"""Host-side sandbox driver.

Prepares the untrusted artifact (fetched on the host, never executed here),
then detonates it inside a locked-down, disposable container and streams the
observed events back. Containment is enforced by the container flags, not by
trusting the code:

  --network none        code execution jobs get NO route out; every egress
                        attempt fails and is recorded (the containment moment)
  --read-only root      plus tmpfs for the few writable paths
  --cap-drop ALL        only SYS_PTRACE added back, for strace
  --pids/--memory/--cpus/--security-opt no-new-privileges
  --runtime runsc       gVisor when present, for kernel isolation

URL jobs run with a bridge network (a browser needs to reach the page) but the
same disposable, capability-stripped container, torn down immediately after.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shlex
import shutil
import tempfile
from pathlib import Path
from typing import AsyncIterator

from . import agent
from .models import Target

SANDBOX_IMAGE = "dc-sandbox:latest"
# When the app itself runs in a container (Docker-out-of-Docker), artifact dirs
# must live at a path that is identical on host and in the app container, so the
# host Docker daemon can bind-mount them. Compose sets DC_WORK_DIR to such a path.
WORK_ROOT = os.environ.get("DC_WORK_DIR") or None
_runtime_cache: str | None = None


async def _run(*args: str, timeout: int = 180) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return -1, "", "timeout"
    return proc.returncode or 0, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


async def docker_available() -> bool:
    rc, _, _ = await _run("docker", "version", "--format", "{{.Server.Version}}", timeout=10)
    return rc == 0


async def gvisor_runtime() -> str:
    """Return 'runsc' if gVisor is registered with Docker, else '' (default)."""
    global _runtime_cache
    if _runtime_cache is not None:
        return _runtime_cache
    rc, out, _ = await _run("docker", "info", "--format", "{{json .Runtimes}}", timeout=10)
    _runtime_cache = "runsc" if (rc == 0 and "runsc" in out) else ""
    return _runtime_cache


async def image_present() -> bool:
    rc, out, _ = await _run("docker", "images", "-q", SANDBOX_IMAGE, timeout=10)
    return rc == 0 and bool(out.strip())


# --- host-side artifact fetch (no execution) --------------------------------
async def _prepare(target: Target, artifact_dir: Path) -> list[dict]:
    """Fetch the artifact onto the host. Returns prep events."""
    evs: list[dict] = []

    def note(msg: str, sev: int = 0, **detail):
        evs.append({"kind": "system", "op": "note", "target": msg,
                    "result": "ok", "severity": sev, "detail": detail})

    if target.type == "npm":
        spec = target.name + (("@" + target.version) if target.version else "")
        note(f"fetching npm tarball for {spec} on host (not executed)")
        rc, out, err = await _run("npm", "pack", spec, "--silent",
                                  "--pack-destination", str(artifact_dir),
                                  timeout=120)
        if rc != 0:
            note(f"npm pack failed: {err.strip()[:200]}", sev=2)
    elif target.type == "pypi":
        spec = target.name + (("==" + target.version) if target.version else "")
        note(f"downloading PyPI sdist for {spec} on host (not executed)")
        rc, out, err = await _run("pip", "download", "--no-deps", "--no-binary",
                                  ":all:", "-d", str(artifact_dir), spec,
                                  timeout=120)
        if rc != 0:
            await _run("pip", "download", "--no-deps", "-d",
                       str(artifact_dir), spec, timeout=120)
    elif target.type == "github":
        url = f"https://github.com/{target.name}.git"
        note(f"cloning {url} on host (not executed)")
        rc, out, err = await _run("git", "clone", "--depth", "1", url,
                                  str(artifact_dir / "repo"), timeout=120)
        if rc != 0:
            note(f"git clone failed: {err.strip()[:200]}", sev=2)
    elif target.type == "url":
        note("url job: browsing happens inside the sandbox, nothing fetched on host")
    return evs


def _docker_cmd(target: Target, artifact_dir: Path, runtime: str,
                timeout: int) -> list[str]:
    net = "bridge" if target.type == "url" else "none"
    art_mount = artifact_dir
    if target.type == "github":
        art_mount = artifact_dir / "repo"
    cmd = [
        "docker", "run", "--rm", "-i",
        "--network", net,
        "--read-only",
        "--tmpfs", "/tmp:rw,exec,size=256m,mode=1777",
        "--tmpfs", "/work:rw,exec,size=512m,mode=1777",
        "--tmpfs", "/home/sandbox:rw,exec,size=512m,mode=1777",
        "--cap-drop", "ALL", "--cap-add", "SYS_PTRACE",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "512",
        "--memory", "1g", "--memory-swap", "1g",
        "--cpus", "1.5",
        "-e", f"DC_TYPE={target.type}",
        "-e", f"DC_NAME={target.name}",
        "-e", f"DC_VERSION={target.version}",
        "-e", f"DC_TIMEOUT={timeout}",
    ]
    if runtime:
        cmd[2:2] = ["--runtime", runtime]  # insert after 'docker run'
    if target.type != "url" and art_mount.exists():
        cmd += ["-v", f"{art_mount}:/artifact:ro"]
    cmd += [SANDBOX_IMAGE]
    return cmd


_SAFE_ARG = re.compile(r"^[A-Za-z0-9 ._/()\-:+@|]{0,200}$")
# High-signal only: patterns that rarely appear in benign package source, so a
# hit is worth surfacing without false-positiving normal libraries.
_DANGER = [
    "child_process", "eval(", "base64", "atob(", "new function(", "os.system",
    "subprocess.", "/etc/shadow", ".aws/credentials", "id_rsa", ".ssh/id",
    "crontab", "chmod +x", "/dev/tcp/", "powershell", "bash -i", "nc -e",
    "mkfifo", "curl http", "wget http",
]


def _extract_sources(art_dir: Path) -> None:
    """Unpack fetched npm/PyPI archives into art_dir/src so the agent can read
    the real source. Extraction is host-side into a temp dir we delete; the
    `data` filter blocks path traversal where the runtime supports it."""
    import tarfile
    import zipfile
    dest = art_dir / "src"
    archives = (list(art_dir.glob("*.tgz")) + list(art_dir.glob("*.tar.gz"))
                + list(art_dir.glob("*.whl")) + list(art_dir.glob("*.zip")))
    for arch in archives:
        try:
            dest.mkdir(exist_ok=True)
            if arch.suffix in (".whl", ".zip"):
                with zipfile.ZipFile(arch) as z:
                    z.extractall(dest)
            else:
                with tarfile.open(arch) as tf:
                    try:
                        tf.extractall(dest, filter="data")
                    except TypeError:
                        tf.extractall(dest)
        except Exception:  # noqa: BLE001
            pass


async def _probe_cmd(tool: str, arg: str, art_dir: Path, runtime: str) -> str:
    """Run one read-only inspection command on the fetched artifact inside a
    locked, network-free container and return its output. The model only picks
    tool+arg from a fixed menu; we build the command, so no shell reaches it."""
    arg = (arg or "").strip()
    if tool in ("read_file", "list_dir"):
        if not arg:
            arg = "/artifact"
        if not arg.startswith("/artifact"):
            arg = "/artifact/" + arg.lstrip("/")
        if not _SAFE_ARG.match(arg):
            return "(refused: unsafe path)"
    if tool == "list_dir":
        inner = f"ls -la -- {shlex.quote(arg)} 2>&1 | head -80"
    elif tool == "read_file":
        inner = f"head -c 4096 -- {shlex.quote(arg)} 2>&1"
    elif tool == "grep":
        if not arg or not _SAFE_ARG.match(arg):
            return "(refused: unsafe pattern)"
        inner = f"grep -rIEn -e {shlex.quote(arg)} /artifact 2>/dev/null | head -60"
    else:
        return ""
    cmd = ["docker", "run", "--rm", "--network", "none", "--read-only",
           "--tmpfs", "/tmp:rw,size=64m", "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges", "--pids-limit", "128",
           "--memory", "512m", "--entrypoint", "bash"]
    if runtime:
        cmd[2:2] = ["--runtime", runtime]
    if art_dir and Path(art_dir).exists():
        cmd += ["-v", f"{art_dir}:/artifact:ro"]
    cmd += [SANDBOX_IMAGE, "-lc", inner]
    rc, out, err = await _run(*cmd, timeout=30)
    return (out or err or "").strip()[:2000]


async def _investigate(target: Target, art_dir: Path, observed: list[dict],
                       runtime: str, max_steps: int = 4) -> AsyncIterator[dict]:
    """Agentic triage: the model decides which files to read and what to grep
    for, one step at a time, based on what it has seen. Decisions and findings
    stream as events; the verdict scorer stays deterministic."""
    files = sum(1 for e in observed if e.get("kind") == "file")
    blocked = sum(1 for e in observed if e.get("kind") == "blocked")
    procs = sum(1 for e in observed if e.get("kind") == "process")
    summary = f"{procs} processes spawned, {files} sensitive file accesses, {blocked} blocked outbound connections"

    yield {"kind": "agent", "op": "note", "target": "agent investigating package source",
           "result": "ok", "severity": 0, "detail": {}}
    listing = await _probe_cmd("list_dir", "/artifact", art_dir, runtime)
    transcript = [{"action": "list_dir /artifact", "result": listing}]

    for _ in range(max_steps):
        action = await agent.next_probe(target, summary, transcript)
        if not action or action.get("tool") == "finish":
            why = (action or {}).get("why", "no further leads")
            yield {"kind": "agent", "op": "note", "target": f"investigation complete: {why}",
                   "result": "ok", "severity": 0, "detail": {}}
            return
        tool, arg = action.get("tool"), action.get("arg", "")
        yield {"kind": "agent", "op": "probe", "target": f"{tool}({arg})",
               "result": "ok", "severity": 0, "detail": {"why": action.get("why", "")[:200]}}
        out = await _probe_cmd(tool, arg, art_dir, runtime)
        transcript.append({"action": f"{tool} {arg}", "result": out[:1200]})
        low = out.lower()
        hits = [p for p in _DANGER if p.lower() in low]
        if hits and "refused" not in low:
            yield {"kind": "process", "op": "static", "target": f"{arg or tool}: {', '.join(hits[:5])}",
                   "result": "ok", "severity": 2,
                   "detail": {"static_risk": True, "patterns": hits[:8]}}
        else:
            yield {"kind": "agent", "op": "result",
                   "target": f"{tool}({arg}) → {len(out)} bytes, no high-risk patterns",
                   "result": "ok", "severity": 0, "detail": {}}


async def detonate(target: Target, timeout: int = 120) -> AsyncIterator[dict]:
    """Yield raw event dicts from a real sandboxed detonation."""
    runtime = await gvisor_runtime()
    if WORK_ROOT:
        Path(WORK_ROOT).mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="dc-", dir=WORK_ROOT))
    artifact_dir = work / "artifact"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    try:
        yield {"kind": "system", "op": "note",
               "target": f"sandbox runtime: {'gVisor (runsc)' if runtime else 'runc (default)'}"
                         f" · network: {'bridge/isolated' if target.type=='url' else 'none (fail-closed)'}",
               "result": "ok", "severity": 0, "detail": {}}

        collected: list[dict] = []
        for e in await _prepare(target, artifact_dir):
            collected.append(e)
            yield e

        cmd = _docker_cmd(target, artifact_dir, runtime, timeout)
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)

        assert proc.stdout is not None
        done_detail: dict | None = None
        try:
            while True:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=timeout + 30)
                if not line:
                    break
                text = line.decode("utf-8", "replace").strip()
                if not text:
                    continue
                try:
                    obj = json.loads(text)
                except json.JSONDecodeError:
                    continue
                if "ev" in obj:
                    collected.append(obj["ev"])
                    yield obj["ev"]
                elif "done" in obj:
                    done_detail = obj["done"]
                    break
        except asyncio.TimeoutError:
            proc.kill()
            yield {"kind": "blocked", "op": "note", "target": "run timed out, container killed",
                   "result": "blocked", "severity": 2, "detail": {}}
        finally:
            if proc.returncode is None:
                proc.kill()
            await proc.wait()

        # Agentic investigation of the package source (LLM-directed, read-only).
        invest_dir = artifact_dir / "repo" if target.type == "github" else artifact_dir
        if target.type in ("npm", "pypi") and agent.available():
            _extract_sources(artifact_dir)
        if target.type in ("npm", "pypi", "github") and agent.available():
            try:
                async for pe in _investigate(target, invest_dir, collected, runtime):
                    yield pe
            except Exception as exc:  # noqa: BLE001  (investigation is best-effort)
                yield {"kind": "agent", "op": "note",
                       "target": f"investigation skipped: {exc}",
                       "result": "ok", "severity": 0, "detail": {}}

        yield {"kind": "system", "op": "done", "target": "detonation complete",
               "result": "ok", "severity": 0, "detail": done_detail or {"rc": None}}
    finally:
        shutil.rmtree(work, ignore_errors=True)
