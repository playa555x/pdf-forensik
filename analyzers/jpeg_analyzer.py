"""
JPEG-Analyse: Dimensionen, Farbraum, EXIF, XMP, DPI, Hashes.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from typing import List, Optional, Dict, Any

from PIL import Image
from PIL.ExifTags import TAGS

from models.schemas import (
    JpegAnalyzerResult, ImageAnalysisDetail, ExtractedImage, Anomaly, AnomalySeverity
)
from config import IMAGES_DIR


def _compute_hashes(data: bytes) -> tuple[str, str]:
    return (
        hashlib.md5(data).hexdigest(),
        hashlib.sha256(data).hexdigest(),
    )


def _parse_exif(img: Image.Image) -> tuple[Dict[str, Any], bool]:
    exif_data = {}
    has_exif = False
    try:
        raw_exif = img._getexif()  # type: ignore[attr-defined]
        if raw_exif:
            has_exif = True
            for tag_id, value in raw_exif.items():
                tag = TAGS.get(tag_id, str(tag_id))
                if isinstance(value, bytes):
                    try:
                        value = value.decode("utf-8", errors="replace")
                    except Exception:
                        value = value.hex()
                exif_data[tag] = str(value)
    except Exception:
        pass
    return exif_data, has_exif


def _get_xmp(img: Image.Image) -> Optional[str]:
    try:
        xmp = img.info.get("xmp")
        if xmp:
            if isinstance(xmp, bytes):
                return xmp.decode("utf-8", errors="replace")
            return str(xmp)
    except Exception:
        pass
    return None


def _get_gps(exif: Dict[str, Any]) -> Optional[str]:
    """Versucht GPS-Koordinaten aus EXIF zu extrahieren."""
    try:
        gps_info = exif.get("GPSInfo")
        if not gps_info:
            return None
        # Einfache Darstellung
        return str(gps_info)[:200]
    except Exception:
        return None


def analyze_jpegs(images: List[ExtractedImage], analysis_id: str) -> JpegAnalyzerResult:
    anomalies: list[Anomaly] = []
    analyzed: List[ImageAnalysisDetail] = []

    img_dir = IMAGES_DIR / analysis_id

    for img_meta in images:
        img_path = img_dir / img_meta.filename
        if not img_path.exists():
            continue

        data = img_path.read_bytes()
        md5, sha256 = _compute_hashes(data)

        detail = ImageAnalysisDetail(
            index=img_meta.index,
            filename=img_meta.filename,
            md5=md5,
            sha256=sha256,
        )

        try:
            with Image.open(img_path) as img:
                detail.width = img.width
                detail.height = img.height
                detail.color_mode = img.mode

                # DPI
                dpi = img.info.get("dpi")
                if dpi:
                    try:
                        detail.dpi_x = float(dpi[0])
                        detail.dpi_y = float(dpi[1])
                    except Exception:
                        pass

                # EXIF
                exif, has_exif = _parse_exif(img)
                detail.exif = exif
                detail.has_exif = has_exif

                if has_exif:
                    detail.camera_make  = exif.get("Make")
                    detail.camera_model = exif.get("Model")
                    detail.original_datetime = exif.get("DateTimeOriginal") or exif.get("DateTime")
                    detail.gps_coords = _get_gps(exif)

                    if detail.gps_coords:
                        anomalies.append(Anomaly(
                            severity=AnomalySeverity.MEDIUM,
                            category="jpeg_analyzer",
                            message=f"Bild {img_meta.index} enthält GPS-Koordinaten in EXIF",
                            detail=f"GPS: {detail.gps_coords[:100]}",
                        ))

                    if detail.camera_make or detail.camera_model:
                        anomalies.append(Anomaly(
                            severity=AnomalySeverity.INFO,
                            category="jpeg_analyzer",
                            message=f"Bild {img_meta.index}: Kamera-Metadaten vorhanden",
                            detail=f"{detail.camera_make or ''} {detail.camera_model or ''}".strip(),
                        ))

                # XMP
                xmp = _get_xmp(img)
                detail.xmp = xmp
                detail.has_xmp = xmp is not None

        except Exception as e:
            anomalies.append(Anomaly(
                severity=AnomalySeverity.LOW,
                category="jpeg_analyzer",
                message=f"Bild {img_meta.index} konnte nicht analysiert werden",
                detail=str(e),
            ))

        analyzed.append(detail)

    return JpegAnalyzerResult(
        analyzed=analyzed,
        anomalies=anomalies,
    )
