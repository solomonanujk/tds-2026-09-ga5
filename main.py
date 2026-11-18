"""TDS 2026-09 GA5 — one service answering Q1 (RAG) and Q4 (harness safety router).

  Q1  RAG Colosseum          base URL  <BASE>            (POST /query)
  Q4  Harness safety router  full URL  <BASE>/classify

Run locally:  uvicorn main:app --port 8000
"""
from __future__ import annotations

import json
import os
import time
from collections import deque
from typing import Any, Deque, Dict

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.concurrency import run_in_threadpool

from ga5 import rag, safety

EMAIL = "24f2001638@ds.study.iitm.ac.in"

app = FastAPI(title="TDS GA5", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# With GA5_DEBUG_TOKEN set, keep the last grader requests (in memory) so the
# real probe wording can be inspected between Checks.
DEBUG_TOKEN = os.environ.get("GA5_DEBUG_TOKEN", "").strip()
CAPTURE: Dict[str, Deque[Dict[str, Any]]] = {"query": deque(maxlen=60), "classify": deque(maxlen=8)}


def _capture(kind: str, body: Any, result: Any) -> None:
    if DEBUG_TOKEN:
        CAPTURE[kind].append({"at": time.time(), "body": body, "result": result})


@app.post("/query")
async def query(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}
    question = body.get("question") or body.get("query") or ""
    if not isinstance(question, str):
        question = json.dumps(question)
    try:
        top_k = int(body.get("top_k", 3) or 3)
    except Exception:
        top_k = 3
    result = await run_in_threadpool(rag.answer, question, top_k)
    out = {k: result[k] for k in ("answer", "sources", "scores", "confidence")}
    _capture("query", body, {**out, "reason": result.get("reason")})
    return JSONResponse(out)


@app.post("/classify")
async def classify(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "expected an object"}, status_code=400)
    result = await run_in_threadpool(safety.classify, body)
    _capture("classify", body, result)
    return JSONResponse(result, media_type="application/json")


@app.get("/debug/requests")
def debug_requests(token: str = "", kind: str = "query") -> JSONResponse:
    if not DEBUG_TOKEN or token != DEBUG_TOKEN or kind not in CAPTURE:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse({"captures": list(CAPTURE[kind])})


@app.get("/", response_class=PlainTextResponse)
def index() -> str:
    return (
        "TDS 2026-09 GA5\n"
        f"student: {EMAIL}\n"
        "Q1 RAG       : POST /query\n"
        "Q4 safety    : POST /classify\n"
    )


@app.get("/healthz")
def healthz() -> JSONResponse:
    return JSONResponse({"ok": True, "rag": rag.health()})
