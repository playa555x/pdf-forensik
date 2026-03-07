"""
Seitengeometrie: MediaBox/CropBox, A4-Check, gemischte Größen.
"""
from __future__ import annotations
from pathlib import Path
from typing import List

import pikepdf

from models.schemas import PageGeometry, PageGeometryResult, Anomaly, AnomalySeverity
from config import A4_WIDTH_PT, A4_HEIGHT_PT, A4_TOLERANCE_PT


def _is_a4(w: float, h: float) -> bool:
    """Prüft ob Seite A4-Format (Hoch- oder Querformat)."""
    portrait  = (abs(w - A4_WIDTH_PT)  < A4_TOLERANCE_PT and abs(h - A4_HEIGHT_PT) < A4_TOLERANCE_PT)
    landscape = (abs(w - A4_HEIGHT_PT) < A4_TOLERANCE_PT and abs(h - A4_WIDTH_PT)  < A4_TOLERANCE_PT)
    return portrait or landscape


def _orientation(w: float, h: float) -> str:
    if w < h:
        return "portrait"
    if w > h:
        return "landscape"
    return "square"


def analyze_page_geometry(pdf_path: Path) -> PageGeometryResult:
    anomalies: list[Anomaly] = []

    try:
        pdf = pikepdf.open(pdf_path)
    except Exception as e:
        return PageGeometryResult(anomalies=[
            Anomaly(severity=AnomalySeverity.HIGH, category="geometry",
                    message="PDF konnte nicht geöffnet werden", detail=str(e))
        ])

    pages: List[PageGeometry] = []
    unique_sizes: set[str] = set()

    with pdf:
        for page in pdf.pages:
            try:
                mediabox = page.mediabox
                w = float(mediabox[2]) - float(mediabox[0])
                h = float(mediabox[3]) - float(mediabox[1])
                if w < 0:
                    w = -w
                if h < 0:
                    h = -h
                is_a4 = _is_a4(w, h)
                orient = _orientation(w, h)
                size_key = f"{w:.1f}x{h:.1f}"
                unique_sizes.add(size_key)
                pages.append(PageGeometry(
                    width_pt=round(w, 2),
                    height_pt=round(h, 2),
                    is_a4=is_a4,
                    orientation=orient,
                ))
            except Exception:
                continue

    mixed_sizes = len(unique_sizes) > 1

    if mixed_sizes:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.LOW,
            category="geometry",
            message=f"Gemischte Seitengrößen im Dokument ({len(unique_sizes)} verschiedene Formate)",
            detail=", ".join(sorted(unique_sizes)),
        ))

    return PageGeometryResult(
        pages=pages,
        mixed_sizes=mixed_sizes,
        unique_sizes=sorted(unique_sizes),
        anomalies=anomalies,
    )
