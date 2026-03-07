"""
POST /ai-review/{analysis_id} — KI-forensische Bewertung (Cache-first).
GET  /ai-review/{analysis_id} — Gecachtes KI-Review abrufen (ohne neu zu generieren).
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from database.db import get_analysis, save_ai_review, get_ai_review
from analyzers.ai_review import run_ai_review

router = APIRouter()


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
    Sendet eine gespeicherte Analyse an DeepSeek (via Featherless AI).
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

    # Neu generieren
    analysis_data = result.model_dump()
    review = await run_ai_review(analysis_data, lang=lang)

    if not review.get("available", True) and "error" in review:
        raise HTTPException(status_code=502, detail=review["error"])

    # Speichern für spätere Aufrufe
    await save_ai_review(analysis_id, lang, review)

    return review
