"""
POST /chat — KI-Chat über den aktuellen Analysebericht.
Streamt die Antwort via Server-Sent Events.
"""
from __future__ import annotations

import json
import os
from typing import AsyncIterator

import httpx
from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from database.db import get_analysis, get_ai_review

router = APIRouter()

FEATHERLESS_API_URL = "https://api.featherless.ai/v1/chat/completions"
FEATHERLESS_API_KEY = os.environ.get("FEATHERLESS_API_KEY", "")
FEATHERLESS_MODEL = "deepseek-ai/DeepSeek-V3-0324"

_SYSTEM_BASE = """\
Du bist ein forensischer PDF-Analyst-Assistent. Du hilfst dabei, Analyseergebnisse zu erklären
und Fragen zum forensischen Befund zu beantworten.

Antworte präzise, verständlich und hilfreich. Wenn ein Analysebericht vorliegt,
beziehe dich konkret auf dessen Befunde.

WICHTIG: Antworte IMMER in der Sprache in der der Nutzer schreibt. \
Schreibt er Deutsch, antworte auf Deutsch. Schreibt er Englisch, antworte auf Englisch. \
Passe dich automatisch an — auch wenn die Sprache mid-conversation wechselt.
"""


class ChatRequest(BaseModel):
    message: str
    analysis_id: str | None = None
    lang: str = "de"
    history: list[dict] | None = None  # [{role, content}, ...]


def _build_context(result, ai_review: dict | None, lang: str) -> str:
    """Baut einen kompakten Kontext-String aus dem Analysebericht."""
    if result is None:
        return ""

    lines = []
    lines.append(f"=== FORENSISCHER ANALYSEBERICHT ===")
    lines.append(f"Datei: {result.filename}")
    lines.append(f"Risiko-Level: {result.risk_level}")
    lines.append(f"Anomalien: HIGH={result.anomaly_count_high}, MEDIUM={result.anomaly_count_medium}, LOW={result.anomaly_count_low}")

    if result.all_anomalies:
        lines.append("\nTop-Anomalien:")
        for a in result.all_anomalies[:10]:
            lines.append(f"  [{a.severity}] {a.category}: {a.message}")

    if ai_review:
        v = ai_review.get("verdict", "?")
        c = ai_review.get("confidence", "?")
        lines.append(f"\nKI-Verdict: {v} (Konfidenz: {c}%)")
        if ai_review.get("zusammenfassung"):
            lines.append(f"KI-Zusammenfassung: {ai_review['zusammenfassung'][:400]}")
        if ai_review.get("laien_erklaerung"):
            lines.append(f"Laien-Erklärung: {ai_review['laien_erklaerung']}")

    return "\n".join(lines)


async def _stream_chat(messages: list[dict]) -> AsyncIterator[str]:
    """Streamt die DeepSeek-Antwort als SSE-Events."""
    payload = {
        "model": FEATHERLESS_MODEL,
        "messages": messages,
        "stream": True,
        "max_tokens": 1024,
        "temperature": 0.7,
    }
    headers = {
        "Authorization": f"Bearer {FEATHERLESS_API_KEY}",
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
    }

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            async with client.stream("POST", FEATHERLESS_API_URL, json=payload, headers=headers) as resp:
                async for line in resp.aiter_lines():
                    if not line.startswith("data: "):
                        continue
                    data = line[6:]
                    if data == "[DONE]":
                        yield "data: [DONE]\n\n"
                        return
                    try:
                        chunk = json.loads(data)
                        delta = chunk["choices"][0]["delta"].get("content", "")
                        if delta:
                            yield f"data: {json.dumps({'content': delta})}\n\n"
                    except Exception:
                        continue
    except Exception as e:
        yield f"data: {json.dumps({'error': str(e)})}\n\n"
        yield "data: [DONE]\n\n"


@router.post("/chat")
async def chat_endpoint(req: ChatRequest):
    """Chat mit DeepSeek über den aktuellen Analysebericht."""
    lang = req.lang if req.lang in ("de", "en") else "de"
    system_prompt = _SYSTEM_BASE

    # Kontext aus Analysebericht laden wenn analysis_id vorhanden
    if req.analysis_id:
        result = await get_analysis(req.analysis_id)
        ai_review = await get_ai_review(req.analysis_id, lang) if result else None
        context = _build_context(result, ai_review, lang)
        if context:
            system_prompt += f"\n\n{context}"

    # Messages zusammenbauen
    messages = [{"role": "system", "content": system_prompt}]

    # Bisherige Chat-History
    if req.history:
        for msg in req.history[-10:]:  # max. 10 Messages History
            if msg.get("role") in ("user", "assistant") and msg.get("content"):
                messages.append({"role": msg["role"], "content": msg["content"]})

    # Neue Nachricht
    messages.append({"role": "user", "content": req.message})

    return StreamingResponse(
        _stream_chat(messages),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
