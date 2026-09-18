"""Hardline web app. One page in, one report out. Nothing stored.

Configs are parsed in memory and discarded when the response is sent. The only
thing written anywhere is a scan counter — the demand metric — and it holds
no configuration data.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware

from . import __version__
from .ai import summarize
from .parser import ParseError, parse
from .rules import RULES
from .scoring import build_report

log = logging.getLogger("hardline")

MAX_BYTES = 2 * 1024 * 1024
RATE_LIMIT = int(os.environ.get("HARDLINE_RATE_PER_MIN", "20"))
COUNTER_PATH = Path(os.environ.get("HARDLINE_COUNTER", Path(__file__).parent.parent / "data" / "scans.json"))

app = FastAPI(title="Hardline", version=__version__, docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")


# ── security headers ────────────────────────────────────────────────────────
class Headers(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Frame-Options"] = "DENY"
        if not request.url.path.startswith("/static/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp


app.add_middleware(Headers)


# ── rate limit (per IP, sliding minute) ─────────────────────────────────────
_hits: dict[str, deque] = defaultdict(deque)
_hits_lock = threading.Lock()


def _allow(ip: str) -> bool:
    now = time.time()
    with _hits_lock:
        q = _hits[ip]
        while q and q[0] < now - 60:
            q.popleft()
        if len(q) >= RATE_LIMIT:
            return False
        q.append(now)
        return True


# ── scan counter (the metric) ───────────────────────────────────────────────
_counter_lock = threading.Lock()


def _count(grade: str, critical: int, mikrotrick: bool) -> None:
    try:
        COUNTER_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _counter_lock:
            data = json.loads(COUNTER_PATH.read_text()) if COUNTER_PATH.exists() else {}
            day = time.strftime("%Y-%m-%d")
            d = data.setdefault(day, {"scans": 0, "grades": {}, "with_critical": 0, "mikrotrick": 0})
            d["scans"] += 1
            d["grades"][grade] = d["grades"].get(grade, 0) + 1
            d["with_critical"] += 1 if critical else 0
            d["mikrotrick"] += 1 if mikrotrick else 0
            COUNTER_PATH.write_text(json.dumps(data, indent=1))
    except Exception:
        log.exception("counter write failed")


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    return (fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "?"))


# ── routes ──────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {"rules": len(RULES), "version": __version__})


async def _read_input(export_text: str, file: UploadFile | None) -> str:
    if file is not None and file.filename:
        raw = await file.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ParseError("That file is over 2 MB. A RouterOS export is normally under 200 KB.")
        return raw.decode("utf-8", errors="replace")
    if len(export_text.encode("utf-8", errors="replace")) > MAX_BYTES:
        raise ParseError("That paste is over 2 MB. A RouterOS export is normally under 200 KB.")
    return export_text


async def _scan(text: str, want_ai: bool):
    cfg = await run_in_threadpool(parse, text)
    report = await run_in_threadpool(build_report, cfg)
    if want_ai:
        try:
            report.ai_summary = await asyncio.wait_for(run_in_threadpool(summarize, report), timeout=15)
        except asyncio.TimeoutError:
            report.ai_summary = None
    _count(report.grade, report.counts["critical"], report.mikrotrick_exposed)
    return report


@app.post("/scan", response_class=HTMLResponse)
async def scan(request: Request, export_text: str = Form(""), file: UploadFile | None = File(None),
               ai: str = Form("1"), client_redacted: str = Form("")):
    if not _allow(_client_ip(request)):
        return templates.TemplateResponse(request, "index.html",
                                          {"rules": len(RULES), "version": __version__,
                                           "error": "Too many scans from this address. Try again in a minute."},
                                          status_code=429)
    try:
        text = await _read_input(export_text, file)
        report = await _scan(text, want_ai=(ai == "1"))
    except ParseError as e:
        return templates.TemplateResponse(request, "index.html",
                                          {"rules": len(RULES), "version": __version__, "error": str(e)},
                                          status_code=400)
    return templates.TemplateResponse(request, "report.html",
                                      {"r": report, "rules": report.rules_run, "version": __version__,
                                       "client_redacted": client_redacted if client_redacted.isdigit() else None})


@app.post("/api/scan")
async def api_scan(request: Request):
    """JSON in, JSON out. Body: {"export": "<text>", "ai": false}"""
    if not _allow(_client_ip(request)):
        return JSONResponse({"error": "rate limited"}, status_code=429)
    body = await request.body()
    if len(body) > MAX_BYTES:
        return JSONResponse({"error": "payload over 2 MB"}, status_code=413)
    try:
        data = json.loads(body or b"{}")
        report = await _scan(str(data.get("export", "")), want_ai=bool(data.get("ai", False)))
    except (ParseError, ValueError) as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    return JSONResponse(report.to_dict())


@app.get("/stats")
async def stats():
    """Aggregate counts only. No configs, no IPs."""
    if not COUNTER_PATH.exists():
        return {"days": {}}
    return {"days": json.loads(COUNTER_PATH.read_text())}


@app.get("/healthz")
async def healthz():
    return {"ok": True, "rules": len(RULES), "version": __version__}
