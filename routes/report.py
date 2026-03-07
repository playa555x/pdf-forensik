"""
GET /report/{id}            — PDF-Bericht herunterladen.
GET /compare-report/{id}    — Vergleichsbericht herunterladen.
GET /images/{id}/{index}    — Extrahiertes Bild abrufen.
"""
from __future__ import annotations
import traceback
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse

from database.db import get_analysis, get_comparison, update_report_path, update_comparison_report_path, get_ai_review
from reports.pdf_report import generate_analysis_report, generate_comparison_report
from config import IMAGES_DIR, REPORTS_DIR

router = APIRouter()


@router.get("/report/{analysis_id}")
async def download_report(
    analysis_id: str,
    lang: str = Query(default="de", regex="^(de|en)$"),
):
    """PDF-Analysebericht herunterladen — lang=de|en (wird immer frisch generiert)."""
    result = await get_analysis(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Analyse nicht gefunden.")

    # KI-Review aus DB laden (falls vorhanden)
    ai_review = await get_ai_review(analysis_id, lang)

    # Immer neu generieren damit Template-Updates sofort wirksam werden
    report_path = REPORTS_DIR / f"report_{analysis_id}_{lang}.pdf"
    try:
        report_path = generate_analysis_report(result, lang=lang, ai_review=ai_review)
        await update_report_path(analysis_id, str(report_path))
    except Exception as e:
        tb = traceback.format_exc()
        print(f"[ERROR] Report-Generierung fehlgeschlagen:\n{tb}")
        raise HTTPException(status_code=500, detail=f"Report-Generierung fehlgeschlagen: {str(e)}\n\nTraceback:\n{tb}")

    return FileResponse(
        path=str(report_path),
        media_type="application/pdf",
        filename=f"forensik_report_{result.filename}.pdf",
    )


@router.get("/compare-report/{comparison_id}")
async def download_compare_report(
    comparison_id: str,
    lang: str = Query(default="de", regex="^(de|en)$"),
):
    """Vergleichsbericht herunterladen — wird immer frisch generiert."""
    result = await get_comparison(comparison_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Vergleich nicht gefunden.")

    report_path = REPORTS_DIR / f"compare_{comparison_id}_{lang}.pdf"
    try:
        report_path = generate_comparison_report(result, lang=lang)
        await update_comparison_report_path(comparison_id, str(report_path))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Vergleichsbericht-Generierung fehlgeschlagen: {str(e)}")

    return FileResponse(
        path=str(report_path),
        media_type="application/pdf",
        filename=f"forensik_vergleich_{comparison_id[:8]}.pdf",
    )


@router.get("/images/{analysis_id}/{index}")
async def get_extracted_image(analysis_id: str, index: int):
    """Extrahiertes JPEG-Bild abrufen."""
    img_path = IMAGES_DIR / analysis_id / f"image_{index:04d}.jpg"

    if not img_path.exists():
        raise HTTPException(status_code=404, detail="Bild nicht gefunden.")

    return FileResponse(
        path=str(img_path),
        media_type="image/jpeg",
        filename=f"image_{analysis_id[:8]}_{index}.jpg",
    )
