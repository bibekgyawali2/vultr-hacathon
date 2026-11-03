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
import shutil
import tempfile
from pathlib import Path
from typing import AsyncIterator

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

        for e in await _prepare(target, artifact_dir):
            yield e

        cmd = _docker_cmd(target, artifact_dir, runtime, timeout)
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)

        assert proc.stdout is not None
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
                    yield obj["ev"]
                elif "done" in obj:
                    yield {"kind": "system", "op": "done",
                           "target": "detonation complete",
                           "result": "ok", "severity": 0, "detail": obj["done"]}
        except asyncio.TimeoutError:
            proc.kill()
            yield {"kind": "blocked", "op": "note", "target": "run timed out, container killed",
                   "result": "blocked", "severity": 2, "detail": {}}
        finally:
            if proc.returncode is None:
                proc.kill()
            await proc.wait()
    finally:
        shutil.rmtree(work, ignore_errors=True)
