"""Detonation Chamber API.

- POST /api/detonate  {target}            -> {job_id}
- GET  /api/stream/{job_id}  (SSE)        -> status, plan, event, verdict
- GET  /api/health                        -> environment readiness
- static UI served from /web
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import agent, sandbox
from .jobs import manager

WEB = Path(__file__).resolve().parent.parent / "web"
app = FastAPI(title="Detonation Chamber", version="1.0")


class DetonateReq(BaseModel):
    target: str


@app.get("/api/health")
async def health():
    docker_ok = await sandbox.docker_available()
    runtime = await sandbox.gvisor_runtime() if docker_ok else ""
    img = await sandbox.image_present() if docker_ok else False
    return {
        "docker": docker_ok,
        "runtime": "runsc" if runtime else ("runc" if docker_ok else "none"),
        "sandbox_image": img,
        "inference": "vultr" if agent.available() else "offline",
        "model": agent.MODEL if agent.available() else None,
    }


@app.post("/api/detonate")
async def detonate(req: DetonateReq):
    target = (req.target or "").strip()
    if not target:
        raise HTTPException(400, "target is required")
    job = manager.create(target)
    return {"job_id": job.id, "target": job.target.__dict__,
            "synthetic": job.synthetic}


@app.get("/api/report/{job_id}")
async def report(job_id: str):
    job = manager.get(job_id)
    if not job:
        raise HTTPException(404, "unknown job")
    from fastapi.responses import JSONResponse
    return JSONResponse(
        job.report(),
        headers={"Content-Disposition":
                 f'attachment; filename="detonation-{job_id}.json"'})


@app.get("/api/stream/{job_id}")
async def stream(job_id: str):
    job = manager.get(job_id)
    if not job:
        raise HTTPException(404, "unknown job")

    async def gen():
        # Replay anything already emitted before the client connected.
        yield _sse("hello", {"job_id": job.id})
        while True:
            try:
                item = await asyncio.wait_for(job.queue.get(), timeout=30)
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"
                continue
            if item is None:
                yield _sse("end", {})
                break
            yield _sse(item.get("type", "message"), item)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


@app.get("/")
async def index():
    return FileResponse(WEB / "index.html")


app.mount("/", StaticFiles(directory=WEB), name="web")
