"""
POST /batch/analyze — Mehrere Dateien gleichzeitig analysieren (max 20).
Verarbeitet sequentiell, gibt Queue-Status zurück.
"""
from __future__ import annotations
import uuid
import shutil
from pathlib import Path
from typing import List

from fastapi import APIRouter, UploadFile, File, HTTPException

from config import UPLOAD_DIR, MAX_UPLOAD_SIZE_BYTES
from analyzers.pipeline import run_pipeline
from analyzers.multiformat_pipeline import run_office_pipeline
from analyzers.image_pipeline import run_image_pipeline
from analyzers.format_detector import detect_format, is_pdf_format, is_office_format, is_image_format
from database.db import save_analysis

router = APIRouter()

MAX_BATCH_SIZE = 20


@router.post("/batch/analyze")
async def batch_analyze(files: List[UploadFile] = File(...)):
    """
    Analysiert mehrere Dateien sequentiell.
    Gibt Batch-Ergebnis mit Status pro Datei zurück.
    """
    if not files:
        raise HTTPException(status_code=400, detail="Keine Dateien übergeben.")
    if len(files) > MAX_BATCH_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"Maximal {MAX_BATCH_SIZE} Dateien pro Batch erlaubt.",
        )

    batch_id = str(uuid.uuid4())
    results = []

    for upload in files:
        filename = upload.filename or "unknown.pdf"
        try:
            # Größencheck
            content = await upload.read()
            if len(content) > MAX_UPLOAD_SIZE_BYTES:
                results.append({
                    "filename": filename,
                    "status": "error",
                    "error": f"Datei zu groß ({len(content) // 1024 // 1024} MB > 200 MB)",
                })
                continue

            # Speichern
            file_path = UPLOAD_DIR / f"batch_{uuid.uuid4()}_{filename}"
            file_path.write_bytes(content)

            # Analyse — Format-abhängig
            fmt = detect_format(file_path)
            try:
                if is_office_format(fmt):
                    analysis = run_office_pipeline(file_path, filename)
                elif is_image_format(fmt):
                    analysis = run_image_pipeline(file_path, filename)
                else:
                    analysis = run_pipeline(file_path, filename)
            except Exception:
                analysis = run_pipeline(file_path, filename)

            await save_analysis(analysis)

            results.append({
                "filename": filename,
                "analysis_id": analysis.analysis_id,
                "risk_level": analysis.risk_level.value,
                "anomaly_count_high": analysis.anomaly_count_high,
                "anomaly_count_medium": analysis.anomaly_count_medium,
                "anomaly_count_low": analysis.anomaly_count_low,
                "status": "ok",
            })

        except Exception as e:
            results.append({
                "filename": filename,
                "status": "error",
                "error": str(e)[:200],
            })
        finally:
            try:
                await upload.seek(0)
            except Exception:
                pass

    ok_count = sum(1 for r in results if r.get("status") == "ok")
    err_count = len(results) - ok_count

    return {
        "batch_id": batch_id,
        "total": len(results),
        "ok": ok_count,
        "errors": err_count,
        "results": results,
    }
