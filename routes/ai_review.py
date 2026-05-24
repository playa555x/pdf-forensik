"""
POST /ai-review/{analysis_id} — KI-forensische Bewertung (Cache-first).
GET  /ai-review/{analysis_id} — Gecachtes KI-Review abrufen (ohne neu zu generieren).
GET  /ai-review/{analysis_id}/stream — SSE-Stream: erst Quick-Impression (8B),
     dann Tiefen-Gutachten (26B).
"""
from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse

from database.db import (
    get_analysis, save_ai_review, get_ai_review,
    save_ai_balanced, get_ai_balanced,
)
import os
from analyzers.ai_review import (
    run_ai_review, stream_quick_impression, run_balanced_findings_review,
)
from analyzers.ai_claude_cli import (
    run_ai_review_via_claude, run_balanced_findings_review_via_claude,
)

# Backend-Switch: AI_BACKEND=claude (Default: ollama)
_AI_BACKEND = os.environ.get("AI_BACKEND", "ollama").strip().lower()


async def _do_ai_review(analysis_data, lang):
    """Dispatcher zum richtigen Backend."""
    if _AI_BACKEND == "claude":
        return await run_ai_review_via_claude(analysis_data, lang=lang)
    return await run_ai_review(analysis_data, lang=lang)


async def _do_balanced(findings, doc_type, workflow, lang):
    if _AI_BACKEND == "claude":
        return await run_balanced_findings_review_via_claude(
            findings=findings, doc_type=doc_type, workflow=workflow, lang=lang,
        )
    return await run_balanced_findings_review(
        findings=findings, doc_type=doc_type, workflow=workflow, lang=lang,
    )

router = APIRouter()

# Pendente Hintergrund-Tasks festhalten, damit der GC sie nicht einkassiert
# wenn der Client die SSE-Verbindung trennt. Werden nach Fertigstellung auto-entfernt.
_pending_deep_tasks: set = set()


def _spawn_background(coro) -> asyncio.Task:
    task = asyncio.create_task(coro)
    _pending_deep_tasks.add(task)
    task.add_done_callback(_pending_deep_tasks.discard)
    return task


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


@router.get("/ai-review/{analysis_id}")
async def get_cached_ai_review(analysis_id: str, lang: str = Query(default="de")):
    """
    Gibt das gespeicherte KI-Review zurück — ohne neuen KI-Call.
    Liefert 404 wenn noch kein Review für diese Sprache gespeichert ist.
    """
    review = await get_ai_review(analysis_id, lang)
    if review is None:
        raise HTTPException(status_code=404, detail="Kein gespeichertes KI-Review vorhanden.")
    return review


@router.post("/ai-review/{analysis_id}")
async def ai_review(analysis_id: str, lang: str = Query(default="de"), force: bool = Query(default=False)):
    """
    Sendet eine gespeicherte Analyse an das lokale Ollama-Modell (Gemma4).
    Cache-first: Wenn bereits ein Review in dieser Sprache existiert, wird es direkt zurückgegeben.
    Mit ?force=true wird immer neu generiert.
    """
    result = await get_analysis(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Analyse nicht gefunden.")

    # Cache prüfen (außer bei force=true)
    if not force:
        cached = await get_ai_review(analysis_id, lang)
        if cached is not None:
            cached["_cached"] = True
            return cached

    # Neu generieren (Backend-abhaengig: ollama oder claude)
    analysis_data = result.model_dump()
    review = await _do_ai_review(analysis_data, lang=lang)

    if not review.get("available", True) and "error" in review:
        raise HTTPException(status_code=502, detail=review["error"])

    # Speichern für spätere Aufrufe
    await save_ai_review(analysis_id, lang, review)

    return review


@router.get("/ai-review/{analysis_id}/stream")
async def stream_ai_review(
    analysis_id: str,
    lang: str = Query(default="de"),
    force: bool = Query(default=False),
):
    """
    Server-Sent-Events Stream:
      event: cached       → {review}                      (wenn Cache-Hit)
      event: prelim_start → {}
      event: prelim       → {delta: "..."}                (stückweise Erst-Einschätzung)
      event: prelim_done  → {}
      event: deep_start   → {eta_seconds: 300}
      event: final        → {review}                      (vollständiges JSON-Gutachten)
      event: error        → {error: "..."}
    """
    result = await get_analysis(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Analyse nicht gefunden.")

    analysis_data = result.model_dump()

    async def _run_and_cache_deep():
        """Tiefen-Review ausführen + cachen. Läuft als detached Task weiter,
        auch wenn der Client die Verbindung trennt."""
        try:
            review = await run_ai_review(analysis_data, lang=lang)
            if review.get("available", True) and "error" not in review:
                await save_ai_review(analysis_id, lang, review)
            return review
        except Exception as e:
            return {"error": f"Deep-Review-Task-Fehler: {e}", "available": False}

    # Harte Obergrenzen damit ein blockierter Modell-Call den Server nicht vergiftet.
    PRELIM_PER_TOKEN_TIMEOUT = 20    # Sekunden zwischen 2 Tokens — sonst Abbruch
    DEEP_MAX_WAIT_SECONDS    = 240   # Stream wartet max 4 Min auf Deep-Result, danach -> pending

    async def gen():
        # Cache-Hit? Dann direkt final ausliefern
        if not force:
            cached = await get_ai_review(analysis_id, lang)
            if cached is not None:
                cached["_cached"] = True
                yield _sse("cached", cached)
                yield _sse("final", cached)
                return

        # Tiefen-Review SOFORT parallel starten (läuft im Hintergrund weiter,
        # auch wenn der Client die Verbindung trennt — wird beim nächsten
        # Laden aus dem Cache bedient).
        deep_task = _spawn_background(_run_and_cache_deep())

        # Stage 1 — Quick Impression (Streaming, mit Per-Token-Timeout)
        yield _sse("prelim_start", {})
        try:
            prelim_iter = stream_quick_impression(analysis_data, lang).__aiter__()
            while True:
                try:
                    delta = await asyncio.wait_for(
                        prelim_iter.__anext__(), timeout=PRELIM_PER_TOKEN_TIMEOUT
                    )
                    yield _sse("prelim", {"delta": delta})
                except StopAsyncIteration:
                    break
                except asyncio.TimeoutError:
                    yield _sse("prelim_error", {
                        "error": f"Quick-Impression haengt (>{PRELIM_PER_TOKEN_TIMEOUT}s kein Token) — abgebrochen"
                    })
                    break
        except Exception as e:
            yield _sse("prelim_error", {"error": str(e)[:300]})
        yield _sse("prelim_done", {})

        # Stage 2 — auf Deep-Review warten mit Hard-Cap
        yield _sse("deep_start", {"eta_seconds": DEEP_MAX_WAIT_SECONDS})

        elapsed = 0
        while not deep_task.done() and elapsed < DEEP_MAX_WAIT_SECONDS:
            await asyncio.sleep(5)
            elapsed += 5
            if not deep_task.done():
                yield _sse("deep_tick", {"elapsed_seconds": elapsed})

        if deep_task.done():
            try:
                review = deep_task.result()
            except Exception as e:
                review = {"error": f"Deep-Task-Fehler: {e}", "available": False}
            yield _sse("final", review)
        else:
            # Hard-Cap erreicht — Task laeuft im Hintergrund weiter und schreibt in Cache.
            # Client kann die Seite in 1-2 Min neu laden -> Cache-Hit liefert das Ergebnis.
            yield _sse("deep_pending", {
                "message": (
                    "Tiefen-Gutachten dauert laenger als erwartet. "
                    "Es laeuft im Hintergrund weiter und wird automatisch im Cache abgelegt. "
                    "Bitte die Seite in 1-2 Minuten neu laden."
                ),
                "elapsed_seconds": elapsed,
            })
            yield _sse("final", {
                "pending": True,
                "available": False,
                "error": "Timeout im SSE-Stream — Ergebnis kommt per Cache nach.",
            })

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ──────────────────────────────────────────────────────────────────────
# Balanced-per-Finding Endpoints
# ──────────────────────────────────────────────────────────────────────

@router.get("/ai-balanced/{analysis_id}")
async def get_cached_ai_balanced(analysis_id: str, lang: str = Query(default="de", pattern="^(de|en)$")):
    """Gibt die gespeicherte balanced-per-Finding-Bewertung zurueck. 404 wenn noch nicht generiert."""
    balanced = await get_ai_balanced(analysis_id, lang)
    if balanced is None:
        raise HTTPException(status_code=404, detail="Keine balanced-Bewertung vorhanden.")
    return balanced


@router.post("/ai-balanced/{analysis_id}")
async def ai_balanced(
    analysis_id: str,
    lang: str = Query(default="de", pattern="^(de|en)$"),
    force: bool = Query(default=False),
):
    """
    Generiert eine ausgewogene Per-Befund-Bewertung (beide Seiten je Finding).
    Cache-first: wenn schon vorhanden, sofortiger Return mit ?_cached=true.
    Mit ?force=true wird neu generiert.
    Filter: nur HIGH+MEDIUM+LOW Anomalien (kein INFO).
    """
    result = await get_analysis(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Analyse nicht gefunden.")

    if not force:
        cached = await get_ai_balanced(analysis_id, lang)
        if cached is not None:
            cached["_cached"] = True
            return cached

    data = result.model_dump()
    all_anoms = data.get("all_anomalies") or []
    # Nur relevante Befunde (kein INFO) — Token-Budget schuetzen
    relevant = []
    for a in all_anoms:
        sev = a.get("severity") if isinstance(a, dict) else getattr(a, "severity", "")
        sev_str = sev if isinstance(sev, str) else str(getattr(sev, "value", sev))
        if (sev_str or "").upper() != "INFO":
            relevant.append(a)

    doc_type = (data.get("doc_type") or {}).get("doc_type", "unknown")
    workflow = (data.get("signature_workflow") or {}).get("workflow", "unknown")

    balanced = await _do_balanced(
        findings=relevant, doc_type=doc_type, workflow=workflow, lang=lang,
    )

    if not balanced.get("available", True) and "error" in balanced:
        # Wir geben den Fehler trotzdem zurueck (HTTP 200), damit Frontend ihn anzeigen kann,
        # ohne dass ein 502 die UI bricht.
        balanced["_cached"] = False
        return balanced

    await save_ai_balanced(analysis_id, lang, balanced)
    balanced["_cached"] = False
    return balanced
