"""Labelled synthetic traces for the stage demo.

These are NOT real packages and NOT real malware. They are hand-authored
event scripts that replay through the exact same UI and scorer as a live run,
so the containment moment is reproducible on stage without shipping anything
that behaves like malware. Every demo event carries detail.synthetic = true,
and the UI shows a "SYNTHETIC REPLAY" banner for these jobs.

Submit one of:  demo:clean   demo:exfil   demo:phish
"""
from __future__ import annotations

HOME = "/home/sandbox"

SCENARIOS: dict[str, dict] = {
    "clean": {
        "title": "demo:clean — a well-behaved utility package",
        "type": "npm",
        "events": [
            ("system", "note", "sandbox runtime: gVisor (runsc) · network: none (fail-closed)", "ok", 0, 0.0),
            ("system", "note", "fetching npm tarball for left-pad-ish@1.0.0 on host (not executed)", "ok", 0, 0.4),
            ("system", "note", "planted 5 canary credentials in " + HOME, "ok", 0, 0.1),
            ("process", "exec", "/usr/local/bin/node", "ok", 1, 0.2),
            ("file", "write", "/work/node_modules/.package-lock.json", "ok", 0, 0.1),
            ("file", "read", "/work/package.json", "ok", 0, 0.1),
            ("process", "exec", "/usr/bin/npm", "ok", 1, 0.3),
            ("system", "note", "process exited rc=0 in 3.1s", "ok", 0, 0.1),
            ("system", "done", "detonation complete", "ok", 0, 0.0),
        ],
    },
    "exfil": {
        "title": "demo:exfil — postinstall script reaches for secrets (contained)",
        "type": "npm",
        "events": [
            ("system", "note", "sandbox runtime: gVisor (runsc) · network: none (fail-closed)", "ok", 0, 0.0),
            ("system", "note", "fetching npm tarball for reqeusts-helper@2.1.4 on host (not executed)", "ok", 0, 0.4),
            ("system", "note", "planted 5 canary credentials in " + HOME, "ok", 0, 0.1),
            ("process", "exec", "/usr/local/bin/node", "ok", 1, 0.2),
            ("process", "exec", "/bin/sh -c node postinstall.js", "ok", 1, 0.2),
            ("file", "read", "/work/node_modules/reqeusts-helper/postinstall.js", "ok", 0, 0.1),
            ("file", "read", f"{HOME}/.aws/credentials", "ok", 3, 0.1, {"canary": True}),
            ("file", "read", f"{HOME}/.env", "ok", 3, 0.1, {"canary": True}),
            ("file", "read", f"{HOME}/.ssh/id_rsa", "ok", 3, 0.1, {"canary": True}),
            ("blocked", "connect", "185.220.101.44:443", "blocked", 3, 0.3, {"errno": "ENETUNREACH"}),
            ("blocked", "connect", "collector.exfil-demo.invalid:443", "blocked", 3, 0.3, {"errno": "EAI_AGAIN"}),
            ("system", "note", "process exited rc=1 in 4.6s", "ok", 0, 0.1),
            ("system", "done", "detonation complete", "ok", 0, 0.0),
        ],
    },
    "apt": {
        "title": "demo:apt — a staged supply-chain implant (contained end to end)",
        "type": "npm",
        "events": [
            ("system", "note", "sandbox runtime: gVisor (runsc) · network: none (fail-closed)", "ok", 0, 0.0),
            ("system", "note", "fetching npm tarball for ui-theme-helper@4.7.2 on host (not executed)", "ok", 0, 0.4),
            ("system", "note", "planted 5 canary credentials in " + HOME, "ok", 0, 0.1),
            ("process", "exec", "/usr/local/bin/node", "ok", 1, 0.2),
            ("process", "exec", "/bin/sh -c node scripts/postinstall.js", "ok", 1, 0.2),
            ("file", "read", "/work/node_modules/ui-theme-helper/scripts/postinstall.js", "ok", 0, 0.1),
            # --- host recon ---
            ("process", "exec", "/usr/bin/uname -a", "ok", 1, 0.2),
            ("process", "exec", "/usr/bin/whoami", "ok", 1, 0.1),
            ("process", "exec", "/usr/bin/id", "ok", 1, 0.1),
            ("file", "read", "/etc/passwd", "ok", 1, 0.1),
            ("file", "read", "/etc/hostname", "ok", 1, 0.1),
            # --- mass secret harvest (canaries) ---
            ("file", "read", f"{HOME}/.aws/credentials", "ok", 3, 0.1, {"canary": True}),
            ("file", "read", f"{HOME}/.ssh/id_rsa", "ok", 3, 0.1, {"canary": True}),
            ("file", "read", f"{HOME}/.ssh/known_hosts", "ok", 1, 0.1),
            ("file", "read", f"{HOME}/.env", "ok", 3, 0.1, {"canary": True}),
            ("file", "read", f"{HOME}/.git-credentials", "ok", 3, 0.1, {"canary": True}),
            ("file", "read", f"{HOME}/.config/dc_wallet.txt", "ok", 3, 0.1, {"canary": True}),
            ("file", "read", f"{HOME}/.docker/config.json", "ok", 1, 0.1),
            # --- persistence attempts ---
            ("file", "write", f"{HOME}/.bashrc", "ok", 2, 0.1, {"persistence": "shell rc append"}),
            ("file", "write", f"{HOME}/.config/autostart/update.desktop", "ok", 2, 0.1, {"persistence": "autostart entry"}),
            ("process", "exec", "/usr/bin/crontab -l", "ok", 1, 0.1),
            # --- command & control / exfil, all contained ---
            ("process", "exec", "/usr/bin/curl", "ok", 1, 0.2),
            ("blocked", "connect", "8.8.8.8:53", "blocked", 3, 0.2, {"errno": "ENETUNREACH", "note": "DNS to resolve C2"}),
            ("blocked", "connect", "185.220.101.44:443", "blocked", 3, 0.3, {"errno": "ENETUNREACH", "note": "primary C2"}),
            ("blocked", "connect", "data.collect-metrics.invalid:443", "blocked", 3, 0.3, {"errno": "EAI_AGAIN", "note": "exfil endpoint"}),
            ("blocked", "connect", "x7f3a2.dns-tunnel.invalid:443", "blocked", 3, 0.3, {"errno": "EAI_AGAIN", "note": "DNS-tunnel fallback"}),
            ("blocked", "connect", "91.219.236.12:4444", "blocked", 3, 0.3, {"errno": "ENETUNREACH", "note": "reverse shell"}),
            ("system", "note", "process exited rc=1 in 7.8s", "ok", 0, 0.1),
            ("system", "done", "detonation complete", "ok", 0, 0.0),
        ],
    },
    "miner": {
        "title": "demo:miner — a cryptominer dropper (resource abuse + pool C2, contained)",
        "type": "pypi",
        "events": [
            ("system", "note", "sandbox runtime: gVisor (runsc) · network: none (fail-closed)", "ok", 0, 0.0),
            ("system", "note", "downloading PyPI sdist for fast-json-tools==1.3.1 on host (not executed)", "ok", 0, 0.4),
            ("system", "note", "planted 5 canary credentials in " + HOME, "ok", 0, 0.1),
            ("process", "exec", "/usr/bin/python3 setup.py install", "ok", 1, 0.3),
            ("file", "read", "/proc/cpuinfo", "ok", 1, 0.1),
            ("process", "exec", "/bin/sh -c ./xmr --donate 0", "ok", 2, 0.2),
            ("process", "exec", "worker-0", "ok", 1, 0.1),
            ("process", "exec", "worker-1", "ok", 1, 0.1),
            ("process", "exec", "worker-2", "ok", 1, 0.1),
            ("process", "exec", "worker-3", "ok", 1, 0.1),
            ("system", "note", "pid limit reached (512): further forks denied", "blocked", 2, 0.2),
            ("blocked", "connect", "pool.supportxmr.invalid:3333", "blocked", 3, 0.3, {"errno": "EAI_AGAIN", "note": "mining pool"}),
            ("blocked", "connect", "pool2.minexmr.invalid:5555", "blocked", 3, 0.3, {"errno": "EAI_AGAIN", "note": "backup pool"}),
            ("system", "note", "cpu quota throttled runaway worker", "ok", 1, 0.2),
            ("system", "note", "process exited rc=137 (killed) in 6.1s", "ok", 0, 0.1),
            ("system", "done", "detonation complete", "ok", 0, 0.0),
        ],
    },
    "phish": {
        "title": "demo:phish — credential-harvesting page (never submitted)",
        "type": "url",
        "events": [
            ("system", "note", "sandbox runtime: gVisor (runsc) · network: bridge/isolated", "ok", 0, 0.0),
            ("system", "note", "opening https://account-verify.phish-demo.invalid/login in isolated fetcher (GET only)", "ok", 0, 0.2),
            ("network", "fetch", "account-verify.phish-demo.invalid", "ok", 1, 0.4),
            ("network", "connect", "login-cdn.phish-demo.invalid", "ok", 2, 0.2, {"redirected_to": "https://account-verify.phish-demo.invalid/login"}),
            ("file", "note", "credential form -> harvest.phish-demo.invalid", "ok", 3, 0.1,
             {"posts_to": "harvest.phish-demo.invalid", "cross_origin": True, "inputs": ["text", "password"]}),
            ("network", "connect", "track.phish-demo.invalid", "ok", 1, 0.1, {"external_script": "/t.js"}),
            ("system", "note", "fetcher closed without submitting any form", "ok", 0, 0.1),
            ("system", "done", "detonation complete", "ok", 0, 0.0),
        ],
    },
}


def scenario(name: str) -> dict | None:
    return SCENARIOS.get(name.strip().lower())


def event_dicts(name: str) -> list[dict]:
    sc = scenario(name)
    if not sc:
        return []
    out: list[dict] = []
    for row in sc["events"]:
        kind, op, target, result, severity, duration = row[:6]
        detail = dict(row[6]) if len(row) > 6 else {}
        detail["synthetic"] = True
        out.append({"kind": kind, "op": op, "target": target,
                    "result": result, "severity": severity,
                    "duration": duration, "detail": detail})
    return out
