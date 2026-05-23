"""
DCT-basierter Copy-Move Forensik-Detektor.

Klassischer Algorithmus (Fridrich 2003 - "Detection of Copy-Move Forgery"):
1. PDF-Seite via PyMuPDF rendern (200 DPI, Graustufen).
2. Bild in 16x16 Bloecke mit Stride 8 zerlegen.
3. DCT pro Block, untere 8 Koeffizienten quantisieren -> Feature-Vektor.
4. Lexikografische Sortierung -> identische Features liegen benachbart.
5. Bei N benachbarten Bloecken mit gleichem Feature: pruefe Shift-Vektor.
6. Wenn >= MIN_MATCHES Bloecke denselben Shift haben -> Copy-Move-Region.

Erkennt:
- Geklonte Stempel/Unterschriften/Seitenzahlen.
- Verschobene Felder (z.B. Buyer-Name doppelt eingefuegt).
- Gefaelschte Dokumenten-Header.

Implementierung mit numpy + scipy DCT - keine externe ML-Lib noetig.
"""
from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List, Tuple

from models.schemas import Anomaly, AnomalySeverity, CopyMoveResult


BLOCK_SIZE = 16
STRIDE = 8
DCT_COEFFS = 8           # Anzahl der unteren DCT-Koeffizienten als Feature
QUANT_STEP = 4           # Quantisierungs-Step
MIN_SHIFT = 32           # Bloecke mit Shift < MIN_SHIFT ignorieren (Eigenschaft)
MIN_MATCHES_PER_SHIFT = 6  # mindestens N Bloecke mit selbem Shift -> Match
MAX_BLOCKS_PER_PAGE = 10000  # Performance-Cap


def _dct2(block):
    """2D DCT via separable 1D-DCTs (scipy)."""
    from scipy.fftpack import dct
    return dct(dct(block.T, norm="ortho").T, norm="ortho")


def _zigzag_indices(n: int):
    """Erste n Indizes im Zigzag-Pattern aus der oberen linken Ecke."""
    coords = []
    for s in range(BLOCK_SIZE * 2 - 1):
        if s % 2 == 0:
            coords.extend((s - i, i) for i in range(s + 1) if i <= s and (s - i) < BLOCK_SIZE and i < BLOCK_SIZE)
        else:
            coords.extend((i, s - i) for i in range(s + 1) if i <= s and i < BLOCK_SIZE and (s - i) < BLOCK_SIZE)
        if len(coords) >= n:
            break
    return coords[:n]


def _analyze_page(arr) -> Tuple[List[Dict[str, Any]], int]:
    """Returns (matches, blocks_processed)."""
    import numpy as np

    h, w = arr.shape
    if h < BLOCK_SIZE or w < BLOCK_SIZE:
        return [], 0

    zz = _zigzag_indices(DCT_COEFFS)
    features: List[Tuple[Tuple[int, ...], Tuple[int, int]]] = []
    blocks_processed = 0

    for y in range(0, h - BLOCK_SIZE + 1, STRIDE):
        for x in range(0, w - BLOCK_SIZE + 1, STRIDE):
            if blocks_processed >= MAX_BLOCKS_PER_PAGE:
                break
            block = arr[y:y + BLOCK_SIZE, x:x + BLOCK_SIZE].astype("float32")
            # skip uniform blocks (whitespace) - kein forensischer Wert
            if block.std() < 5.0:
                continue
            d = _dct2(block)
            feat = tuple(int(round(d[i, j] / QUANT_STEP)) for i, j in zz)
            features.append((feat, (x, y)))
            blocks_processed += 1
        if blocks_processed >= MAX_BLOCKS_PER_PAGE:
            break

    if len(features) < 2:
        return [], blocks_processed

    # Lexikografische Sortierung
    features.sort(key=lambda t: t[0])

    # Shift-Histogram
    shifts: Dict[Tuple[int, int], List[Tuple[Tuple[int, int], Tuple[int, int]]]] = {}
    for i in range(len(features) - 1):
        if features[i][0] != features[i + 1][0]:
            continue
        x1, y1 = features[i][1]
        x2, y2 = features[i + 1][1]
        dx, dy = x2 - x1, y2 - y1
        # Distanz-Filter: zu nahe = Block-Eigenschaft, ignorieren
        if abs(dx) < MIN_SHIFT and abs(dy) < MIN_SHIFT:
            continue
        # Normalize shift to positive direction
        key = (abs(dx), abs(dy))
        shifts.setdefault(key, []).append(((x1, y1), (x2, y2)))

    matches = []
    for shift, pairs in shifts.items():
        if len(pairs) >= MIN_MATCHES_PER_SHIFT:
            # Bounding box of all source blocks
            xs1 = [p[0][0] for p in pairs]
            ys1 = [p[0][1] for p in pairs]
            xs2 = [p[1][0] for p in pairs]
            ys2 = [p[1][1] for p in pairs]
            matches.append({
                "shift": list(shift),
                "match_count": len(pairs),
                "source_bbox": [min(xs1), min(ys1), max(xs1) + BLOCK_SIZE, max(ys1) + BLOCK_SIZE],
                "target_bbox": [min(xs2), min(ys2), max(xs2) + BLOCK_SIZE, max(ys2) + BLOCK_SIZE],
            })
    matches.sort(key=lambda m: -m["match_count"])
    return matches[:10], blocks_processed


def analyze_copy_move(pdf_path: Path) -> CopyMoveResult:
    anomalies: List[Anomaly] = []
    try:
        import fitz
        import numpy as np
    except ImportError as e:
        return CopyMoveResult(error=f"missing dep: {e}", anomalies=[])

    pages_out: List[Dict[str, Any]] = []
    total_matches = 0

    try:
        doc = fitz.open(str(pdf_path))
        for i, page in enumerate(doc):
            try:
                pix = page.get_pixmap(dpi=150, colorspace=fitz.csGRAY)
                arr = np.frombuffer(pix.samples, dtype=np.uint8).reshape(pix.height, pix.width)
                matches, blocks = _analyze_page(arr)
                total_matches += len(matches)
                pages_out.append({
                    "page": i + 1,
                    "blocks_processed": blocks,
                    "matches_found": len(matches),
                    "matches": matches,
                    "image_size": [pix.width, pix.height],
                })
                if matches:
                    biggest = matches[0]
                    # Tabellen/Layout-Heuristik: regelmaessige Shifts (Vielfache von 8/16/32)
                    # mit horizontaler ODER vertikaler Komponente = wahrscheinlich Tabelle
                    shift = biggest["shift"]
                    is_axis_aligned = (shift[0] == 0 or shift[1] == 0)
                    is_grid_multiple = (shift[0] % 8 == 0 and shift[1] % 8 == 0)
                    is_likely_table = is_axis_aligned and is_grid_multiple and biggest['match_count'] < 50
                    if is_likely_table:
                        sev = AnomalySeverity.LOW
                        msg_suffix = " -- vermutlich Tabelle/Layout-Wiederholung"
                    elif biggest["match_count"] >= 30:
                        sev = AnomalySeverity.HIGH
                        msg_suffix = " -- starker Klon-Verdacht"
                    elif biggest["match_count"] >= 15:
                        sev = AnomalySeverity.MEDIUM
                        msg_suffix = " -- moeglicherweise Klon"
                    else:
                        sev = AnomalySeverity.LOW
                        msg_suffix = " -- kleine Wiederholung, oft natuerlich"
                    anomalies.append(Anomaly(
                        severity=sev,
                        category="copy_move_forgery",
                        message=f"Seite {i+1}: {len(matches)} wiederholte Bildbereich(e) gefunden ({biggest['match_count']} Bloecke){msg_suffix}",
                        detail=f"shift={shift} src_bbox={biggest['source_bbox']} tgt_bbox={biggest['target_bbox']}. Bei Tabellen/Listen sind regelmaessige Wiederholungen normal.",
                    ))
            except Exception as e:
                pages_out.append({"page": i + 1, "error": str(e)})
        doc.close()
    except Exception as e:
        return CopyMoveResult(error=str(e), anomalies=[])

    return CopyMoveResult(
        pages=pages_out,
        total_match_clusters=total_matches,
        anomalies=anomalies,
    )
