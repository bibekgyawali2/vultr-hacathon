"""Threat-intelligence layer: the signals competitors surface, added alongside
our behavioural verdict so the product reasons on five axes, not one.

- capabilities(): Socket-style capability badges, derived from observed events.
- attack_mapping(): MITRE ATT&CK techniques, mapped from behaviour.
- registry_metadata() + reputation_flags(): npm/PyPI reputation signals.
- osv_vulns(): known CVEs from OSV.dev (the vuln axis).
- typosquat(): name-similarity to popular packages.

All network lookups are host-side metadata (never executing the artifact), run
in parallel, and fail soft so a run never hangs on them.
"""
from __future__ import annotations

import datetime

import httpx

from .models import Kind, Target

# --- small popularity lists for typosquat detection ------------------------
TOP_NPM = {
    "react", "react-dom", "lodash", "express", "chalk", "axios", "request",
    "debug", "commander", "async", "moment", "vue", "webpack", "typescript",
    "next", "eslint", "jest", "dotenv", "uuid", "left-pad", "colors",
    "node-fetch", "prettier", "rxjs", "bluebird", "yargs", "glob", "socket.io",
    "mongoose", "body-parser", "cors", "jsonwebtoken", "bcrypt", "redux",
    "classnames", "styled-components", "tailwindcss", "vite", "rollup", "babel",
    "cross-env", "nodemon", "ws", "ioredis", "pg", "mysql", "dayjs", "zod",
    "node-gyp", "fs-extra", "semver", "minimist", "qs", "form-data", "undici",
}
TOP_PYPI = {
    "requests", "numpy", "pandas", "flask", "django", "boto3", "urllib3",
    "setuptools", "pip", "six", "python-dateutil", "pyyaml", "certifi", "idna",
    "wheel", "click", "jinja2", "scipy", "matplotlib", "pytest", "cryptography",
    "beautifulsoup4", "sqlalchemy", "fastapi", "pydantic", "aiohttp", "pillow",
    "scikit-learn", "redis", "celery", "tqdm", "rich", "httpx", "uvicorn",
    "typing-extensions", "packaging", "attrs", "colorama", "werkzeug",
}


def _lev(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def typosquat(target: Target) -> dict | None:
    if target.type not in ("npm", "pypi"):
        return None
    name = target.name.lower().split("/")[-1]
    pop = TOP_NPM if target.type == "npm" else TOP_PYPI
    if name in pop:
        return None
    best, bd = None, 99
    for p in pop:
        d = _lev(name, p)
        if d < bd:
            bd, best = d, p
    if best and 1 <= bd <= 2 and abs(len(name) - len(best)) <= 2:
        return {"suspect": name, "similar_to": best, "distance": bd}
    return None


# --- registry reputation ---------------------------------------------------
async def registry_metadata(target: Target) -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=8, follow_redirects=True) as c:
            if target.type == "npm":
                r = await c.get(f"https://registry.npmjs.org/{target.name}")
                if r.status_code != 200:
                    return None
                d = r.json()
                times = d.get("time", {}) or {}
                repo = d.get("repository")
                repo = repo.get("url") if isinstance(repo, dict) else repo
                latest = (d.get("dist-tags", {}) or {}).get("latest", "")
                dl = None
                try:
                    rd = await c.get(
                        f"https://api.npmjs.org/downloads/point/last-month/{target.name}")
                    if rd.status_code == 200:
                        dl = rd.json().get("downloads")
                except Exception:
                    pass
                meta = {
                    "ecosystem": "npm",
                    "created": times.get("created"),
                    "modified": times.get("modified"),
                    "versions": len(d.get("versions", {}) or {}),
                    "repository": repo,
                    "maintainers": [m.get("name") for m in (d.get("maintainers") or [])][:5],
                    "downloads_last_month": dl,
                    "latest": latest,
                }
                return meta
            if target.type == "pypi":
                r = await c.get(f"https://pypi.org/pypi/{target.name}/json")
                if r.status_code != 200:
                    return None
                d = r.json()
                info = d.get("info", {}) or {}
                releases = d.get("releases", {}) or {}
                times = [f["upload_time_iso_8601"]
                         for rs in releases.values() for f in rs
                         if f.get("upload_time_iso_8601")]
                urls = info.get("project_urls") or {}
                repo = (info.get("home_page") or urls.get("Source")
                        or urls.get("Homepage") or urls.get("Repository"))
                return {
                    "ecosystem": "pypi",
                    "created": min(times) if times else None,
                    "modified": max(times) if times else None,
                    "versions": len(releases),
                    "repository": repo,
                    "maintainers": [info.get("author")] if info.get("author") else [],
                    "downloads_last_month": None,
                    "latest": info.get("version", ""),
                }
    except Exception:
        return None
    return None


def reputation_flags(meta: dict | None) -> list[str]:
    flags: list[str] = []
    if not meta:
        return flags
    created = meta.get("created")
    if created:
        try:
            dt = datetime.datetime.fromisoformat(created.replace("Z", "+00:00"))
            age = (datetime.datetime.now(datetime.timezone.utc) - dt).days
            meta["age_days"] = age
            if age < 30:
                flags.append(f"published only {age} day(s) ago")
        except Exception:
            pass
    dl = meta.get("downloads_last_month")
    if isinstance(dl, int) and dl < 1000:
        flags.append(f"low adoption ({dl} downloads/mo)")
    if not meta.get("repository"):
        flags.append("no source repository linked")
    return flags


async def osv_vulns(target: Target) -> list[dict]:
    eco = {"npm": "npm", "pypi": "PyPI"}.get(target.type)
    if not eco:
        return []
    q: dict = {"package": {"name": target.name, "ecosystem": eco}}
    if target.version:
        q["version"] = target.version
    try:
        async with httpx.AsyncClient(timeout=8) as c:
            r = await c.post("https://api.osv.dev/v1/query", json=q)
            if r.status_code != 200:
                return []
            out = []
            for v in (r.json().get("vulns") or [])[:8]:
                sev = ""
                for s in v.get("severity", []) or []:
                    sev = s.get("score", "") or sev
                out.append({"id": v.get("id"),
                            "summary": (v.get("summary") or "")[:140],
                            "severity": sev})
            return out
    except Exception:
        return []


# --- behaviour-derived signals (work for live and demo runs) ---------------
def capabilities(target: Target, events: list) -> list[dict]:
    has = {"file": False, "proc": False, "net": False, "blocked": False,
           "canary": False, "obf": False, "persist": False}
    for e in events:
        k = e.kind
        d = e.detail or {}
        if k == Kind.FILE:
            has["file"] = True
            if d.get("canary"):
                has["canary"] = True
        elif k == Kind.PROCESS:
            has["proc"] = True
            if d.get("static_risk") and any(
                    p in ("base64", "atob(", "eval(", "new function(")
                    for p in d.get("patterns", [])):
                has["obf"] = True
        elif k in (Kind.NETWORK,):
            has["net"] = True
        elif k == Kind.BLOCKED:
            has["blocked"] = True
        if d.get("persistence"):
            has["persist"] = True
    caps = []
    if target.type in ("npm", "pypi") and has["proc"]:
        caps.append({"label": "runs install scripts", "level": "warn"})
    if has["canary"]:
        caps.append({"label": "reads credentials", "level": "bad"})
    if has["blocked"]:
        caps.append({"label": "attempts network egress", "level": "bad"})
    elif has["net"]:
        caps.append({"label": "uses network", "level": "warn"})
    if has["persist"]:
        caps.append({"label": "persistence", "level": "bad"})
    if has["obf"]:
        caps.append({"label": "obfuscated code", "level": "bad"})
    if has["proc"]:
        caps.append({"label": "spawns processes", "level": "warn"})
    if has["file"]:
        caps.append({"label": "filesystem access", "level": "info"})
    return caps


_ATTACK = []  # populated below via mapping


def attack_mapping(events: list) -> list[dict]:
    seen: dict[str, dict] = {}

    def add(tid, name, evidence):
        if tid not in seen:
            seen[tid] = {"id": tid, "name": name, "evidence": evidence}

    for e in events:
        k, op, tgt = e.kind, e.op, (e.target or "")
        d = e.detail or {}
        low = tgt.lower()
        if k == Kind.FILE and d.get("canary"):
            add("T1552.001", "Credentials In Files", "read planted credential files")
        if k == Kind.BLOCKED and op == "connect":
            add("T1041", "Exfiltration Over C2 Channel", "attempted outbound connection to external host")
        if k == Kind.NETWORK and op in ("connect", "fetch"):
            add("T1071", "Application Layer Protocol", "network communication")
        if k == Kind.PROCESS and any(s in low for s in ("/sh", "bash", "node", "python", "/bin/")):
            add("T1059", "Command and Scripting Interpreter", "spawned an interpreter/shell")
        if d.get("persistence"):
            add("T1547", "Boot or Logon Autostart Execution", "wrote a persistence entry")
        if "crontab" in low:
            add("T1053.003", "Scheduled Task/Job: Cron", "touched cron")
        if d.get("static_risk") and any(p in ("base64", "atob(", "eval(", "new function(")
                                        for p in d.get("patterns", [])):
            add("T1027", "Obfuscated Files or Information", "obfuscation/encoding in source")
        if any(s in low for s in ("uname", "whoami", "/etc/passwd", "/etc/hostname", " id")):
            add("T1082", "System Information Discovery", "host reconnaissance")
        if "169.254" in low or d.get("ssrf_refused"):
            add("T1552.005", "Cloud Instance Metadata API", "reached for cloud metadata endpoint")
    return list(seen.values())
