"""Job orchestration: one detonation from submission to verdict.

Runs the sandbox (or a labelled synthetic replay), accumulates events, scores a
verdict, and asks the agent for a plan and a closing summary. Everything is
pushed onto a per-job async queue that the SSE endpoint drains to the browser.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import time
import uuid
from datetime import datetime, timezone

from . import agent, analysis, demo, sandbox, store
from .models import Event, Kind, Result, parse_target


class Job:
    def __init__(self, raw: str):
        self.id = uuid.uuid4().hex[:12]
        self.raw = raw
        self.target = parse_target(raw)
        self.created = time.time()
        self.events: list[Event] = []
        self.verdict = None
        self.summary = ""
        self.plan = ""
        self.status = "queued"          # queued | running | done | error
        self.synthetic = self.target.type == "demo"
        self.sandbox_destroyed = False
        self.runtime = ""
        self.queue: asyncio.Queue = asyncio.Queue()
        self._seq = 0

    def _mk_event(self, d: dict) -> Event:
        self._seq += 1
        return Event(
            seq=self._seq,
            ts=round(d.get("ts", time.time() - self.created), 4),
            kind=Kind(d.get("kind", "system")),
            op=d.get("op", "note"),
            target=d.get("target", ""),
            result=Result(d.get("result", "ok")),
            severity=int(d.get("severity", 0)),
            duration=float(d.get("duration", 0.0)),
            detail=d.get("detail", {}) or {},
        )

    async def push(self, kind: str, payload: dict):
        await self.queue.put({"type": kind, **payload})

    async def push_event(self, d: dict):
        tgt = d.get("target", "")
        if d.get("kind") == "system" and "sandbox runtime:" in tgt:
            self.runtime = tgt.split("sandbox runtime:")[1].split("·")[0].strip()
        e = self._mk_event(d)
        self.events.append(e)
        await self.push("event", {"event": e.to_dict()})

    async def run(self):
        self.status = "running"
        await self.push("status", {"status": "running",
                                   "target": self.target.__dict__,
                                   "synthetic": self.synthetic})

        self.plan = await agent.plan(self.target)
        await self.push("plan", {"plan": self.plan,
                                 "agent": "vultr" if agent.available() else "offline"})

        try:
            if self.target.type == "demo":
                await self._run_demo()
            else:
                async for d in sandbox.detonate(self.target):
                    await self._handle(d)
        except Exception as exc:  # noqa: BLE001
            await self.push_event({"kind": "blocked", "op": "note",
                                   "target": f"driver error: {exc}",
                                   "result": "error", "severity": 2})

        self.verdict = analysis.score(self.events)
        top = [f"{e.kind.value}:{e.op} {e.target}"
               for e in self.events if e.severity >= 1][:12]
        self.summary = await agent.summarize(self.target, self.verdict, top)

        # Live containers run with --rm, so the sandbox is gone once the run ends.
        self.sandbox_destroyed = self.target.type != "demo"
        self.status = "done"

        try:
            store.record(self)
        except Exception:  # noqa: BLE001  (telemetry must never fail a run)
            pass

        await self.push("verdict", {"verdict": self.verdict.to_dict(),
                                    "summary": self.summary})
        await self.push("status", {"status": "done",
                                   "sandbox_destroyed": self.sandbox_destroyed,
                                   "report_url": f"/api/report/{self.id}"})
        await self.queue.put(None)  # sentinel: stream complete

    def report(self) -> dict:
        """A verifiable run record: the full evidence plus a SHA-256 over the
        canonical event sequence, so a report can't be silently edited."""
        events = [e.to_dict() for e in self.events]
        canon = json.dumps(events, sort_keys=True, separators=(",", ":")).encode()
        return {
            "tool": "Detonation Chamber",
            "schema": 1,
            "job_id": self.id,
            "submitted": self.raw,
            "target": self.target.__dict__,
            "synthetic": self.synthetic,
            "created_utc": datetime.fromtimestamp(self.created, timezone.utc)
                .isoformat().replace("+00:00", "Z"),
            "generated_utc": datetime.now(timezone.utc)
                .isoformat().replace("+00:00", "Z"),
            "status": self.status,
            "sandbox_runtime": self.runtime or "unknown",
            "sandbox_destroyed": self.sandbox_destroyed,
            "plan": self.plan,
            "verdict": self.verdict.to_dict() if self.verdict else None,
            "summary": self.summary,
            "event_count": len(events),
            "evidence_sha256": hashlib.sha256(canon).hexdigest(),
            "events": events,
        }

    async def _handle(self, d: dict):
        await self.push_event(d)

    async def _run_demo(self):
        rows = demo.event_dicts(self.target.name)
        if not rows:
            await self.push_event({"kind": "system", "op": "note",
                                   "target": f"unknown demo scenario '{self.target.name}'"
                                             f" — try demo:clean, demo:exfil, demo:phish",
                                   "severity": 1})
            return
        sc = demo.scenario(self.target.name)
        await self.push_event({"kind": "system", "op": "note",
                               "target": sc["title"], "severity": 0,
                               "detail": {"synthetic": True}})
        for d in rows:
            # pace the replay so the strip fills visibly on stage
            await asyncio.sleep(0.45)
            await self.push_event(d)


class JobManager:
    def __init__(self):
        self.jobs: dict[str, Job] = {}

    def create(self, raw: str) -> Job:
        job = Job(raw)
        self.jobs[job.id] = job
        asyncio.create_task(job.run())
        return job

    def get(self, job_id: str) -> Job | None:
        return self.jobs.get(job_id)


manager = JobManager()
