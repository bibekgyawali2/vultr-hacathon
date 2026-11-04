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
