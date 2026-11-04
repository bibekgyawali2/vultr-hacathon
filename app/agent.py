"""The analyst's voice, powered by Vultr Serverless Inference.

The deterministic scorer (analysis.py) owns the verdict. This layer adds the
reasoning a human analyst would write: a plan before the run and a plain-English
summary after it. It is grounded in the observed events and is instructed never
to overturn the evidence-based label. With no API key configured it falls back
to deterministic prose, so the product runs fully offline for the demo.

Vultr Serverless Inference is OpenAI-compatible:
  base  https://api.vultrinference.com/v1
  auth  Authorization: Bearer $VULTR_INFERENCE_API_KEY
"""
from __future__ import annotations

import os

import httpx

BASE = os.environ.get("VULTR_INFERENCE_BASE", "https://api.vultrinference.com/v1")
API_KEY = os.environ.get("VULTR_INFERENCE_API_KEY", "")
MODEL = os.environ.get("VULTR_INFERENCE_MODEL", "deepseek-v4.1-flash-1017")

SYSTEM = (
    "You are the reasoning layer of Detonation Chamber, a malware-analysis "
    "sandbox. You are shown events observed while running an untrusted artifact "
    "in isolation. Be precise, calm, and forensic. Never invent events that are "
    "not in the evidence. Never contradict the provided verdict label. Keep "
    "replies to the requested length."
)


def available() -> bool:
    return bool(API_KEY)


async def _chat(prompt: str, max_tokens: int = 220) -> str:
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{BASE}/chat/completions",
            headers={"Authorization": f"Bearer {API_KEY}"},
            json={
                "model": MODEL,
                "messages": [
                    {"role": "system", "content": SYSTEM},
                    {"role": "user", "content": prompt},
                ],
                "max_tokens": max_tokens,
                "temperature": 0.2,
            },
        )
        resp.raise_for_status()
        data = resp.json()
        msg = data["choices"][0]["message"]
        # Some models place prose in reasoning_content and leave content empty.
        text = (msg.get("content") or msg.get("reasoning_content") or "").strip()
        if not text:
            raise ValueError("empty completion")  # -> caller falls back
        return text


async def plan(target) -> str:
    desc = f"{target.type} artifact '{target.name}'" + (
        f" version {target.version}" if target.version else "")
    if not available():
        plans = {
            "npm": "Fetch the tarball on the host, then run npm install with "
                   "scripts enabled inside a network-isolated container. Watch "
                   "install/postinstall for secret access and egress attempts.",
            "pypi": "Download the sdist, run pip install and import under strace "
                    "with no network route. Watch setup.py and import-time code.",
            "github": "Clone shallow on the host, run the project's install "
                      "inside the sandbox, observe scripts and file access.",
            "url": "Open the page in a disposable isolated fetcher (GET only), "
                   "follow redirects, and inspect for credential-harvesting "
                   "forms and cross-origin posts. Never submit anything.",
            "demo": "Replay a labelled synthetic trace through the live pipeline.",
        }
        return plans.get(target.type, "Detonate in the sandbox and observe behaviour.")
    try:
        return await _chat(
            f"In 1-2 sentences, state the analysis plan for a {desc}. "
            f"Describe what you will run in the sandbox and what behaviours you "
            f"will watch for. No preamble.", max_tokens=256)
    except Exception:
        return "Detonate in the sandbox and observe file, process, and network behaviour."


PROBE_TOOLS = (
    "list_dir(path)  — list a directory under /artifact\n"
    "read_file(path) — show the first 4 KB of a file under /artifact\n"
    "grep(pattern)   — search every file under /artifact for a string\n"
    "finish()        — stop; you have enough to judge"
)


async def next_probe(target, summary: str, transcript: list[dict]) -> dict | None:
    """Agentic step: given what dynamic analysis saw and the investigation so
    far, the model chooses the single most useful next probe. Returns a parsed
    action dict, or None to finish. The verdict stays deterministic; the agent
    only decides *what to look at*."""
    if not available():
        return None
    import json as _json
    import re as _re
    tr = "\n\n".join(
        f"$ {t['action']}\n{(t['result'] or '(empty)')[:500]}"
        for t in transcript[-4:])
    prompt = (
        f"Triaging a {target.type} artifact '{target.name}'.\n"
        f"Dynamic analysis in the sandbox already observed: {summary}.\n\n"
        f"You can now statically investigate the package contents with these "
        f"read-only, sandboxed tools:\n{PROBE_TOOLS}\n\n"
        f"Investigation so far:\n{tr}\n\n"
        f"Pick the single most useful next action to decide if this artifact is "
        f"malicious. Run at least one grep for a dangerous API (child_process, "
        f"eval, base64, os.system, curl, crontab, chmod +x) before you finish, "
        f"and read_file to confirm a hit. Finish once you can judge.\n"
        f'Respond with ONLY one JSON object, e.g. '
        f'{{"tool":"grep","arg":"child_process","why":"look for shell-outs"}} '
        f'or {{"tool":"finish","why":"nothing suspicious in the source"}}.')
    raw = ""
    for _ in range(2):  # the reasoning model occasionally returns an empty turn
        try:
            raw = await _chat(prompt, max_tokens=220)
            break
        except Exception:
            continue
    if not raw:
        return None
    m = _re.search(r"\{.*\}", raw, _re.S)
    if not m:
        return None
    try:
        obj = _json.loads(m.group(0))
    except Exception:
        return None
    if obj.get("tool") not in ("list_dir", "read_file", "grep", "finish"):
        return None
    return obj


async def summarize(target, verdict, top_events: list[str]) -> str:
    if not available():
        return verdict.headline + " " + " ".join(verdict.reasons[:2])
    evidence = "\n".join(f"- {e}" for e in top_events[:12]) or "- (no notable events)"
    prompt = (
        f"Artifact: {target.type} '{target.name}'.\n"
        f"Verdict (fixed, do not change): {verdict.label.value.upper()}, "
        f"risk {verdict.score}/100.\n"
        f"Observed evidence:\n{evidence}\n\n"
        f"Write a 2-3 sentence analyst summary for a ticket. Lead with what the "
        f"artifact did, then what the sandbox did about it. Plain English.")
    try:
        return await _chat(prompt, max_tokens=200)
    except Exception:
        return verdict.headline + " " + " ".join(verdict.reasons[:2])
