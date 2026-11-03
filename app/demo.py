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
