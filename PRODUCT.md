# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

FastAPI (Python) backend serving plain HTML/CSS/JS, no frontend build step. Live updates over Server-Sent Events. Sandboxes are Docker containers using the gVisor (`runsc`) runtime when available. Deployed to a Vultr Cloud Compute VM. LLM calls go to Vultr Serverless Inference (OpenAI-compatible, `https://api.vultrinference.com/v1`).

## Users

Primary: AppSec / SOC analysts triaging suspicious packages and links reported by others. They need evidence and a defensible verdict they can paste into a ticket.
Secondary: developers vetting a dependency before installing it. They need a verdict they can read in two seconds.
Analyst-first: the evidence is the product; the verdict summarizes it.

## Product Purpose

Detonation Chamber lets someone hand an untrusted artifact (npm package, PyPI package, GitHub repo, or URL) to an AI agent. The agent detonates it inside a disposable, locked-down sandbox, watches what it actually does, and returns a verdict backed by observed behavior. Success: a malicious artifact gets caught by what it *did* (touched a planted secret, tried to call home), the attempt is contained, and the analyst gets a report with the evidence and the indicators.

## Positioning

Behavioral, not static. Other scanners read the code or check reputation lists. This one runs the artifact under containment, plants fake secrets (canary credentials) to bait it, and has an agent decide what to probe next. The containment event is the evidence.

## Operating Context

- Built for the Vultr "Agent Rush" hackathon (Nov 3–8 2026), track "Blast Radius Zero". The demo video must show at least one containment moment.
- Judged on Application of Technology, Presentation, Business Value, Originality.
- Typical session: paste an identifier → watch a live run (agent reasoning, sandbox terminal output, network and file events) → read the verdict → copy the indicators.

## Capabilities and Constraints

- Inputs: `npm:<name>[@ver]`, `pypi:<name>[==ver]`, `https://github.com/<owner>/<repo>`, any `http(s)` URL.
- Each job runs in a fresh container: read-only root, dropped capabilities, cpu/mem/pids limits, wall-clock timeout, egress forced through a logging proxy that blocks by default except package registries.
- Canary credentials (fake AWS keys, SSH key, `.npmrc` token, env vars) are planted in the sandbox home directory; reading or sending them is flagged.
- URL analysis uses a headless browser inside the sandbox; it never submits forms.
- Verdict scale: benign / suspicious / malicious, with a 0–100 risk score and indicators of compromise (IOCs).
- No Vultr GPUs are available; all model calls go to Vultr Serverless Inference.
- Demo samples that behave maliciously are authored by us and are harmless: they only target the planted canaries and a blocked domain.

## Evidence on Hand

None yet. No real customers, benchmarks, or detection-rate numbers exist. Never fabricate them.

## Product Principles

1. Show the evidence, then the verdict. Every claim in a report traces to an observed event.
2. Containment is visible. When something gets blocked, the user sees exactly what was attempted and what stopped it.
3. Nothing escapes. The sandbox fails closed: if isolation can't be set up, the job doesn't run.
4. Two-second answer, ten-minute depth: the verdict reads at a glance, and the full trace is one scroll away.
