"""
Quantisierungstabellen-Fingerprint.
Erkennt Ghostscript-typische Quantisierungstabellen in eingebetteten JPEGs.
"""
from __future__ import annotations
import struct
from pathlib import Path
from typing import List, Dict, Any

from models.schemas import QuantFingerprintResult, ExtractedImage, Anomaly, AnomalySeverity
from config import IMAGES_DIR, GHOSTSCRIPT_LUMA_QUANT_SIGNATURE

# JPEG-Marker
_MARKER_SOI  = b"\xff\xd8"
_MARKER_DQT  = b"\xff\xdb"
_MARKER_SOS  = b"\xff\xda"


def _read_jpeg_quant_tables(data: bytes) -> List[List[int]]:
    """Alle Quantisierungstabellen aus JPEG-Rohdaten extrahieren."""
    tables = []
    pos = 0

    # SOI überspringen
    if data[:2] != _MARKER_SOI:
        return tables

    pos = 2

    while pos < len(data) - 3:
        if data[pos] != 0xFF:
            break

        marker = data[pos:pos+2]
        pos += 2

        if marker == _MARKER_SOS:
            break

        if len(data) < pos + 2:
            break

        segment_len = struct.unpack(">H", data[pos:pos+2])[0]

        if marker == _MARKER_DQT:
            # DQT kann mehrere Tabellen enthalten
            seg_data = data[pos+2:pos+segment_len]
            seg_pos = 0

            while seg_pos < len(seg_data) - 64:
                pq_tq = seg_data[seg_pos]
                precision = (pq_tq >> 4) & 0x0F  # 0=8bit, 1=16bit
                table_id  = pq_tq & 0x0F
                seg_pos += 1

                if precision == 0:
                    table = list(seg_data[seg_pos:seg_pos+64])
                    seg_pos += 64
                else:
                    table = []
                    for _ in range(64):
                        if seg_pos + 2 <= len(seg_data):
                            val = struct.unpack(">H", seg_data[seg_pos:seg_pos+2])[0]
                            table.append(val)
                            seg_pos += 2
                    seg_pos += 128  # Fallback

                if len(table) == 64:
                    tables.append(table)

        pos += segment_len

    return tables


def _match_score(table: List[int], reference: List[int]) -> float:
    """Übereinstimmungs-Score zwischen 0.0 und 1.0."""
    if len(table) != 64 or len(reference) != 64:
        return 0.0
    matches = sum(1 for a, b in zip(table, reference) if a == b)
    return matches / 64.0


def analyze_quant_fingerprint(images: List[ExtractedImage], analysis_id: str) -> QuantFingerprintResult:
    anomalies: list[Anomaly] = []
    matches: List[Dict[str, Any]] = []
    ghostscript_detected = False
    images_checked = 0

    img_dir = IMAGES_DIR / analysis_id

    for img_meta in images:
        img_path = img_dir / img_meta.filename
        if not img_path.exists():
            continue

        images_checked += 1

        try:
            data = img_path.read_bytes()
            tables = _read_jpeg_quant_tables(data)

            for tbl_idx, table in enumerate(tables):
                score = _match_score(table, GHOSTSCRIPT_LUMA_QUANT_SIGNATURE)
                table_type = "Luminanz" if tbl_idx == 0 else "Chrominanz"

                if score >= 0.90:
                    ghostscript_detected = True
                    matches.append({
                        "image_index": img_meta.index,
                        "table_type": table_type,
                        "match_score": round(score, 3),
                        "table_id": tbl_idx,
                    })

        except Exception:
            continue

    if ghostscript_detected:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category="quant_fingerprint",
            message=f"Ghostscript-Quantisierungstabelle in {len(matches)} Bild(ern) erkannt",
            detail=f"Bilder: {[m['image_index'] for m in matches]}",
        ))

    return QuantFingerprintResult(
        images_checked=images_checked,
        ghostscript_detected=ghostscript_detected,
        matches=matches,
        anomalies=anomalies,
    )
