"""
GET /history         — Verlauf aller Analysen.
GET /history/search  — Suche nach Dateiname, Hash, Datumsbereich.
"""
from __future__ import annotations
from typing import Optional

from fastapi import APIRouter, Query

from database.db import list_analyses, search_analyses

router = APIRouter()


@router.get("/history")
async def get_history(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
    """Alle Analysen sortiert nach Datum (neueste zuerst)."""
    rows = await list_analyses(limit=limit, offset=offset)
    return {"analyses": rows, "count": len(rows)}


@router.get("/history/search")
async def search_history(
    q: Optional[str] = Query(None, description="Suche in Dateiname, MD5, SHA256"),
    date_from: Optional[str] = Query(None, description="Von-Datum (YYYY-MM-DD)"),
    date_to: Optional[str] = Query(None, description="Bis-Datum (YYYY-MM-DD)"),
):
    """Analysen suchen."""
    rows = await search_analyses(q=q, date_from=date_from, date_to=date_to)
    return {"analyses": rows, "count": len(rows)}
