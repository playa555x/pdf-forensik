"""
JPEG-Extraktion aus PDFs.
Primär: pikepdf XObject-Traversal (sauber, ohne Doppelkompression).
Fallback: Binär-Scan nach JPEG-SOI/EOI-Marker.
"""
from __future__ import annotations
import uuid
from pathlib import Path
from typing import List

import pikepdf

from models.schemas import JpegExtractorResult, ExtractedImage, Anomaly, AnomalySeverity
from config import IMAGES_DIR

# JPEG-Marker
_JPEG_SOI = b"\xff\xd8\xff"
_JPEG_EOI = b"\xff\xd9"


def _save_image_data(data: bytes, analysis_id: str, index: int) -> Path:
    out_dir = IMAGES_DIR / analysis_id
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"image_{index:04d}.jpg"
    out_path.write_bytes(data)
    return out_path


def _extract_xobjects(pdf: pikepdf.Pdf, analysis_id: str) -> List[ExtractedImage]:
    """Traversiert alle XObjects und extrahiert DCTDecode-Images."""
    images = []
    index = 0

    for page_num, page in enumerate(pdf.pages):
        resources = page.get("/Resources", {})
        xobjects = resources.get("/XObject", {})

        for name, xobj in xobjects.items():
            try:
                xobj_resolved = xobj
                subtype = str(xobj_resolved.get("/Subtype", ""))
                if subtype != "/Image":
                    continue

                filters = xobj_resolved.get("/Filter", None)
                if filters is None:
                    continue

                filter_str = str(filters)
                if "/DCTDecode" not in filter_str and "/DCTD" not in filter_str:
                    continue

                # Rohbytes extrahieren (pikepdf behält JPEG-Kompression bei)
                raw = bytes(xobj_resolved.read_raw_bytes())

                if len(raw) < 3:
                    continue

                out_path = _save_image_data(raw, analysis_id, index)
                images.append(ExtractedImage(
                    index=index,
                    filename=out_path.name,
                    page=page_num + 1,
                    extraction_method="xobject",
                    file_size_bytes=len(raw),
                ))
                index += 1

            except Exception:
                continue

    return images


def _extract_binary_scan(pdf_path: Path, analysis_id: str, start_index: int) -> List[ExtractedImage]:
    """Fallback: Binär-Scan nach JPEG-Markern."""
    images = []
    index = start_index

    try:
        data = pdf_path.read_bytes()
    except Exception:
        return []

    pos = 0
    while True:
        soi = data.find(_JPEG_SOI, pos)
        if soi == -1:
            break

        eoi = data.find(_JPEG_EOI, soi + 2)
        if eoi == -1:
            break

        jpeg_data = data[soi:eoi + 2]

        # Mindestgröße (< 512 bytes = wahrscheinlich kein echtes Bild)
        if len(jpeg_data) >= 512:
            out_path = _save_image_data(jpeg_data, analysis_id, index)
            images.append(ExtractedImage(
                index=index,
                filename=out_path.name,
                page=None,
                extraction_method="binary_scan",
                file_size_bytes=len(jpeg_data),
            ))
            index += 1

        pos = eoi + 2

    return images


def extract_jpegs(pdf_path: Path, analysis_id: str) -> JpegExtractorResult:
    anomalies: list[Anomaly] = []
    all_images: List[ExtractedImage] = []

    try:
        pdf = pikepdf.open(pdf_path)
    except Exception as e:
        return JpegExtractorResult(anomalies=[
            Anomaly(severity=AnomalySeverity.HIGH, category="jpeg_extractor",
                    message="PDF konnte nicht geöffnet werden", detail=str(e))
        ])

    with pdf:
        xobj_images = _extract_xobjects(pdf, analysis_id)
        all_images.extend(xobj_images)

    # Fallback nur wenn XObject nichts gefunden hat
    if not xobj_images:
        binary_images = _extract_binary_scan(pdf_path, analysis_id, len(all_images))
        if binary_images:
            all_images.extend(binary_images)
            anomalies.append(Anomaly(
                severity=AnomalySeverity.INFO,
                category="jpeg_extractor",
                message=f"{len(binary_images)} Bild(er) per Binär-Scan gefunden (keine XObject-Einbettung)",
            ))

    return JpegExtractorResult(
        total_images=len(all_images),
        images=all_images,
        anomalies=anomalies,
    )
