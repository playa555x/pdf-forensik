"""
POST /analyze  — PDF hochladen und analysieren.
GET  /analysis/{id} — Ergebnis abrufen.
DELETE /analysis/{id} — Analyse löschen.
"""
from __future__ import annotations
import shutil
import uuid
from pathlib import Path

from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder

from config import UPLOAD_DIR, MAX_UPLOAD_SIZE_BYTES, IMAGES_DIR
from analyzers.pipeline import run_pipeline
from analyzers.multiformat_pipeline import run_office_pipeline
from analyzers.image_pipeline import run_image_pipeline
from analyzers.format_detector import detect_format, is_supported, is_pdf_format, is_office_format, is_image_format
from database.db import save_analysis, get_analysis, delete_analysis
from models.schemas import AnalysisResult

router = APIRouter()


@router.post("/analyze")
async def analyze_pdf(file: UploadFile = File(...), profile: str = "standard"):
    """Dokument hochladen und vollständige forensische Analyse starten (PDF, DOCX, XLSX, PPTX, DOC, ODT, JPEG, PNG)."""

    filename = file.filename or ""

    # Dateiformat-Check
    if not is_supported(filename):
        raise HTTPException(
            status_code=400,
            detail="Nicht unterstütztes Dateiformat. Erlaubt: PDF, DOCX, XLSX, PPTX, DOC, XLS, PPT, ODT, ODS, ODP, JPEG, PNG.",
        )

    content = await file.read()
    if len(content) > MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Datei zu groß (max. {MAX_UPLOAD_SIZE_BYTES // 1024 // 1024} MB).",
        )

    # Format per Magic-Bytes + Extension bestimmen
    upload_id = str(uuid.uuid4())
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else 'bin'
    tmp_path = UPLOAD_DIR / f"{upload_id}.{ext}"
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    try:
        tmp_path.write_bytes(content)
        fmt = detect_format(tmp_path, filename)

        if is_pdf_format(fmt):
            # PDF-Magic-Bytes prüfen
            if not content.startswith(b"%PDF"):
                raise HTTPException(status_code=400, detail="Datei ist kein gültiges PDF (fehlendes %PDF-Header).")
            result: AnalysisResult = run_pipeline(tmp_path, filename, profile=profile if profile in ("lite","standard","deep") else "standard")
        elif is_office_format(fmt):
            result = run_office_pipeline(tmp_path, filename)
        elif is_image_format(fmt):
            result = run_image_pipeline(tmp_path, filename)
        else:
            raise HTTPException(status_code=400, detail=f"Format '{fmt}' wird nicht unterstützt.")

        await save_analysis(result)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analyse fehlgeschlagen: {str(e)}")
    finally:
        if tmp_path.exists():
            tmp_path.unlink()

    return jsonable_encoder(result)


@router.get("/analysis/{analysis_id}")
async def get_analysis_result(analysis_id: str):
    """Gespeicherte Analyse-Ergebnisse abrufen."""
    result = await get_analysis(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Analyse nicht gefunden.")
    return jsonable_encoder(result)


@router.delete("/analysis/{analysis_id}")
async def delete_analysis_result(analysis_id: str):
    """Analyse + extrahierte Bilder löschen."""
    found = await delete_analysis(analysis_id)
    if not found:
        raise HTTPException(status_code=404, detail="Analyse nicht gefunden.")

    # Extrahierte Bilder löschen
    img_dir = IMAGES_DIR / analysis_id
    if img_dir.exists():
        shutil.rmtree(img_dir)

    return {"status": "deleted", "analysis_id": analysis_id}
