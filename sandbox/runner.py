#!/usr/bin/env python3
"""Runs INSIDE the sandbox container. Observes, never trusts.

Plants canary credentials, executes the submitted artifact under strace with
no network route out, and emits one JSON line per observed syscall of
interest to stdout. The host streams these lines to the browser.

Contract with the host:
  env  DC_TYPE     npm | pypi | github | exec
  env  DC_NAME     package / repo name
  env  DC_VERSION  optional
  /artifact        read-only mount with any pre-fetched tarball / source
  stdout           JSON lines: {"ev": {...}} ... then {"done": {...}}

The container is started with --network none, so every connect() to a
non-local address fails. That failure IS the containment evidence: we see
what the code tried to reach and confirm it never left.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

HOME = Path(os.environ.get("HOME", "/home/sandbox"))
START = time.time()
_seq = 0
_lock = threading.Lock()

# --- canary credentials -----------------------------------------------------
# Fake, inert values. Nothing here is a real secret. Reading or exfiltrating
# any of these is a strong signal, because benign installers never touch them.
# Note: ~/.npmrc and ~/.pypirc are deliberately NOT canaries — npm and pip read
# them on every legitimate install, so they would false-positive. These paths
# are ones a normal installer never opens.
CANARIES: dict[str, str] = {
    str(HOME / ".aws" / "credentials"):
        "[default]\naws_access_key_id = AKIA_CANARY_000000000000\n"
        "aws_secret_access_key = canary/not+a+real+secret/0000000000000000\n",
    str(HOME / ".ssh" / "id_rsa"):
        "-----BEGIN OPENSSH PRIVATE KEY-----\nCANARY-INERT-KEY-DO-NOT-USE\n"
        "-----END OPENSSH PRIVATE KEY-----\n",
    str(HOME / ".config" / "dc_wallet.txt"):
        "seed: canary inert words only never real do not use\n",
    str(HOME / ".git-credentials"):
        "https://canary:inert0000@github.com\n",
    str(HOME / ".env"):
        "STRIPE_SECRET_KEY=sk_canary_inert_0000\nGITHUB_TOKEN=ghp_canaryInert0000\n",
}
CANARY_PATHS = set(CANARIES)


def emit(obj: dict) -> None:
    with _lock:
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()


def ev(kind: str, op: str, target: str, result: str = "ok",
       severity: int = 0, duration: float = 0.0, **detail) -> None:
    global _seq
    nested = detail.pop("detail", None)
    if isinstance(nested, dict):
        detail.update(nested)
    _seq += 1
    emit({"ev": {
        "seq": _seq,
        "ts": round(time.time() - START, 4),
        "kind": kind, "op": op, "target": target,
        "result": result, "severity": severity,
        "duration": round(duration, 4), "detail": detail,
    }})


def plant_canaries() -> None:
    for path, body in CANARIES.items():
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
        p.chmod(0o600)
    os.environ["AWS_SECRET_ACCESS_KEY"] = "canary/not+a+real+secret/0000"
    os.environ["DC_CANARY_TOKEN"] = "dc_canary_inert_0000"
    ev("system", "note", f"planted {len(CANARIES)} canary credentials in {HOME}",
       detail={"paths": list(CANARY_PATHS)})


# --- strace parsing ---------------------------------------------------------
RE_OPENAT = re.compile(r'openat\([^,]+,\s*"([^"]+)"')
RE_OPEN = re.compile(r'\bopen\(\s*"([^"]+)"')
RE_CONNECT = re.compile(
    r'connect\(\d+,\s*\{sa_family=AF_INET6?,\s*sin6?_port=htons\((\d+)\),'
    r'.*?(?:inet_addr\("([^"]+)"\)|inet_pton\([^,]+,\s*"([^"]+)")')
RE_CONNECT_UNIX = re.compile(r'connect\(\d+,\s*\{sa_family=AF_UNIX')
RE_EXECVE = re.compile(r'execve\("([^"]+)",\s*\[([^\]]*)\]')
RE_RET = re.compile(r'=\s*(-?\d+)(?:\s+(\w+))?')

# Noise: the toolchain reads thousands of its own files. Keep signal paths.
NOISE_PREFIXES = (
    "/usr/", "/lib", "/proc", "/sys", "/etc/ld", "/dev/", "/tmp/npm",
    "/opt/", "/root/.npm/_cacache", str(HOME / ".npm"),
)


def interesting_path(path: str) -> bool:
    if path in CANARY_PATHS:
        return True
    # The work dir and tmp are the package's own sandbox scratch; expected.
    if path.startswith(("/work", "/tmp", "/var/tmp")):
        return False
    if any(path.startswith(p) for p in NOISE_PREFIXES):
        return False
    # Sensitive home dotfiles and anything outside the work dir.
    sensitive = (".aws", ".ssh", ".config", ".netrc", ".git-credentials",
                 ".docker", ".kube", ".gnupg", "credentials", "wallet",
                 "id_rsa", "id_ed25519", ".env", ".npmrc", ".pypirc")
    low = path.lower()
    if any(s in low for s in sensitive):
        return True
    if path.startswith("/home") and "/work" not in path:
        return True
    return False


def parse_line(line: str) -> None:
    # Filesystem opens
    m = RE_OPENAT.search(line) or RE_OPEN.search(line)
    if m:
        path = m.group(1)
        if path in CANARY_PATHS:
            ev("file", "read", path, result="ok", severity=3,
               canary=True)
            return
        if interesting_path(path):
            op = "write" if ("O_WRONLY" in line or "O_RDWR" in line or
                             "O_CREAT" in line) else "read"
            ev("file", op, path, severity=1)
        return
    # Network connect attempts
    m = RE_CONNECT.search(line)
    if m:
        port = m.group(1)
        addr = m.group(2) or m.group(3) or "?"
        if addr.startswith("127.") or addr == "::1":
            return  # loopback is local, not egress
        ret = RE_RET.search(line)
        errno = ret.group(2) if ret and ret.group(1).startswith("-") else ""
        blocked = bool(errno)  # ENETUNREACH / EHOSTUNREACH under --network none
        ev("network" if not blocked else "blocked",
           "connect", f"{addr}:{port}",
           result="blocked" if blocked else "ok",
           severity=3 if blocked else 2, errno=errno)
        return
    # Process spawns
    m = RE_EXECVE.search(line)
    if m:
        binpath = m.group(1)
        argv = m.group(2)
        if binpath.startswith(("/usr/lib", "/lib")):
            return
        ev("process", "exec", binpath, severity=1, argv=argv[:200])
        return


def tail_trace(path: str, stop: threading.Event) -> None:
    while not Path(path).exists() and not stop.is_set():
        time.sleep(0.05)
    try:
        with open(path, "r", errors="replace") as fh:
            while not stop.is_set():
                line = fh.readline()
                if not line:
                    time.sleep(0.05)
                    continue
                try:
                    parse_line(line)
                except Exception:
                    pass
            for line in fh:  # drain remainder
                try:
                    parse_line(line)
                except Exception:
                    pass
    except FileNotFoundError:
        pass


# --- command construction ---------------------------------------------------
def build_command() -> list[str]:
    t = os.environ.get("DC_TYPE", "npm")
    name = os.environ.get("DC_NAME", "")
    work = Path("/work")
    work.mkdir(exist_ok=True)
    os.chdir(work)

    if t == "npm":
        # --offline stops npm's own registry/DNS chatter (which has no route out
        # anyway) so the run doesn't hang on retries; any egress from the
        # package's own install scripts is still observed and blocked.
        base = ["npm", "install", "--no-audit", "--no-fund", "--offline",
                "--fetch-retries=0", "--foreground-scripts"]
        tarball = next(Path("/artifact").glob("*.tgz"), None)
        if tarball:
            return base + [str(tarball)]
        return base + [name]
    if t == "pypi":
        src = next(Path("/artifact").glob("*"), None)
        if src:
            return ["pip", "install", "--no-index",
                    "--find-links", "/artifact", "--no-build-isolation", name]
        return ["pip", "install", name]
    if t == "github":
        repo = Path("/artifact")
        if (repo / "package.json").exists():
            return ["npm", "install", "--no-audit", "--no-fund"]
        if (repo / "setup.py").exists() or (repo / "pyproject.toml").exists():
            return ["pip", "install", "--no-build-isolation", "."]
        return ["bash", "-lc", "ls -la"]
    if t == "exec":
        name = os.environ.get("DC_NAME", "")
        if name == "egress":
            # Honest live containment test: try to reach real hosts. With
            # --network none every connect() fails and strace records it.
            return ["python3", "-c",
                    "import socket\n"
                    "for h in [('1.1.1.1',443),('8.8.8.8',53),('93.184.216.34',80)]:\n"
                    "    try: socket.create_connection(h,3)\n"
                    "    except Exception: pass\n"]
        if name == "secrets":
            # Live canary test: read the planted (inert) credential files so the
            # file-access detector fires on real syscalls.
            return ["bash", "-lc",
                    f"cat {HOME}/.aws/credentials {HOME}/.ssh/id_rsa {HOME}/.env "
                    f">/dev/null 2>&1; echo probe-done"]
        return ["bash", "-lc", os.environ.get("DC_CMD", "true")]
    return ["true"]


def analyze_url() -> None:
    """Browse a URL from inside the disposable container. GET only, never
    submits anything, follows a bounded redirect chain, and reports every
    host it touches plus any credential-harvesting form it finds."""
    import ipaddress
    import socket
    import urllib.error
    import urllib.request
    import urllib.parse
    from html.parser import HTMLParser

    url = os.environ.get("DC_NAME", "")
    ev("system", "note", f"opening {url} in isolated fetcher (GET only)")

    def host_is_public(netloc: str):
        """SSRF guard: refuse loopback, private, link-local (incl. cloud
        metadata 169.254.169.254), reserved, and multicast targets. Every A/AAAA
        record must be public."""
        host = netloc.split("@")[-1].rsplit(":", 1)[0].strip("[]")
        try:
            infos = socket.getaddrinfo(host, None)
        except Exception:  # noqa: BLE001
            return False, "dns-resolution-failed"
        for info in infos:
            ip = info[4][0].split("%")[0]
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if (addr.is_private or addr.is_loopback or addr.is_link_local
                    or addr.is_reserved or addr.is_multicast
                    or addr.is_unspecified):
                return False, f"non-public address {ip}"
        return True, ""

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):  # don't auto-follow; we validate each hop
            return None

    opener = urllib.request.build_opener(_NoRedirect)

    class Scan(HTMLParser):
        def __init__(self):
            super().__init__()
            self.forms: list[dict] = []
            self._cur: dict | None = None
            self.ext_scripts: list[str] = []
            self.meta_refresh = ""

        def handle_starttag(self, tag, attrs):
            a = dict(attrs)
            if tag == "form":
                self._cur = {"action": a.get("action", ""), "pw": False,
                             "inputs": []}
            elif tag == "input" and self._cur is not None:
                self._cur["inputs"].append(a.get("type", "text"))
                if a.get("type") == "password":
                    self._cur["pw"] = True
            elif tag == "script" and a.get("src"):
                self.ext_scripts.append(a["src"])
            elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
                self.meta_refresh = a.get("content", "")

        def handle_endtag(self, tag):
            if tag == "form" and self._cur is not None:
                self.forms.append(self._cur)
                self._cur = None

    chain: list[str] = []
    cur = url
    final = url
    body = ""
    for hop in range(6):
        parts = urllib.parse.urlparse(cur)
        if parts.scheme not in ("http", "https"):
            ev("blocked", "fetch", cur[:120], result="blocked", severity=3,
               detail={"refused": f"non-http scheme '{parts.scheme}'"})
            break
        ok, why = host_is_public(parts.netloc)
        if not ok:
            ev("blocked", "connect", parts.netloc, result="blocked", severity=3,
               detail={"ssrf_refused": why})
            break
        ev("network", "fetch", parts.netloc, severity=1, detail={"GET": cur})
        try:
            req = urllib.request.Request(
                cur, headers={"User-Agent": "DetonationChamber/1.0"}, method="GET")
            resp = opener.open(req, timeout=20)
            code = resp.getcode()
            if code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("Location", "")
                nxt = urllib.parse.urljoin(cur, loc)
                ev("network", "connect", urllib.parse.urlparse(nxt).netloc or nxt,
                   severity=2, detail={"redirected_to": nxt, "status": code})
                chain.append(nxt)
                cur = nxt
                final = nxt
                continue
            final = resp.geturl() or cur
            body = resp.read(600_000).decode("utf-8", "replace")
            break
        except urllib.error.HTTPError as he:  # 4xx/5xx still has a body to scan
            final = cur
            try:
                body = he.read(600_000).decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                pass
            break
        except Exception as exc:  # noqa: BLE001
            ev("blocked", "fetch", parts.netloc, result="error", severity=2,
               detail={"error": str(exc)[:200]})
            break

    scan = Scan()
    try:
        scan.feed(body)
    except Exception:
        pass

    page_host = urllib.parse.urlparse(final).netloc
    for form in scan.forms:
        action_host = urllib.parse.urlparse(
            urllib.parse.urljoin(final, form["action"])).netloc
        cross = action_host and action_host != page_host
        if form["pw"]:
            ev("file", "note", f"credential form -> {action_host or '(self)'}",
               severity=3 if cross else 2,
               detail={"posts_to": action_host, "cross_origin": cross,
                       "inputs": form["inputs"]})
    for src in scan.ext_scripts[:20]:
        shost = urllib.parse.urlparse(urllib.parse.urljoin(final, src)).netloc
        if shost and shost != page_host:
            ev("network", "connect", shost, severity=1,
               detail={"external_script": src[:160]})
    if scan.meta_refresh:
        ev("process", "note", f"meta-refresh redirect: {scan.meta_refresh[:120]}",
           severity=2)

    ev("system", "note", "fetcher closed without submitting any form")
    emit({"done": {"rc": 0, "elapsed": 0.0, "final_url": final,
                   "forms": len(scan.forms)}})


def main() -> None:
    plant_canaries()
    if os.environ.get("DC_TYPE") == "url":
        analyze_url()
        return
    cmd = build_command()
    if os.environ.get("DC_TYPE") == "github":
        # run inside the cloned source
        src = Path("/artifact")
        if src.exists():
            os.chdir(src)

    ev("system", "note", "executing under strace with network isolation",
       detail={"cmd": " ".join(cmd)})

    trace_path = "/tmp/dc_strace.log"
    stop = threading.Event()
    reader = threading.Thread(target=tail_trace, args=(trace_path, stop),
                              daemon=True)
    reader.start()

    strace = [
        "strace", "-f", "-qq", "-ttt", "-s", "256",
        "-e", "trace=openat,open,connect,execve",
        "-o", trace_path, "--",
    ] + cmd

    t0 = time.time()
    try:
        proc = subprocess.run(strace, capture_output=True, text=True,
                              timeout=int(os.environ.get("DC_TIMEOUT", "120")))
        rc = proc.returncode
        tail = (proc.stdout or "")[-800:] + (proc.stderr or "")[-800:]
    except subprocess.TimeoutExpired:
        rc = -1
        tail = "timed out"
    except FileNotFoundError:
        # strace missing: run without it (still contained by --network none)
        proc = subprocess.run(cmd, capture_output=True, text=True)
        rc = proc.returncode
        tail = (proc.stdout or "")[-800:] + (proc.stderr or "")[-800:]

    time.sleep(0.3)
    stop.set()
    reader.join(timeout=2)

    ev("system", "note", f"process exited rc={rc} in {time.time()-t0:.1f}s",
       detail={"tail": tail})
    emit({"done": {"rc": rc, "elapsed": round(time.time() - t0, 2)}})


if __name__ == "__main__":
    main()
