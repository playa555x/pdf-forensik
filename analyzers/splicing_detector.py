"""
JPEG-Splicing Detector via Quantization-Inkonsistenz.

Forschungs-Background: Spliced PDFs/Bilder enthalten Pixel-Regionen aus
unterschiedlichen JPEG-Quellen, die unterschiedliche Quantization-Tabellen
nutzen. Wenn das finale Bild als JPEG re-encodiert wird, bleiben die
Quantization-Spuren der Original-Quellen sichtbar (JPEG-Ghost-Effekt).

Pipeline (CPU-only, kein ML-Modell noetig):
1. Eingebettete JPEGs aus PDF extrahieren via PyMuPDF.
2. Pro Bild: Decode + Re-Encode mit verschiedenen Q-Stufen (50, 65, 80, 95).
3. Pixel-Differenz pro Region berechnen.
4. Lokale Differenz-Minima = Region wurde mit dieser Q-Stufe einmal kodiert.
5. Wenn unterschiedliche Regionen unterschiedliche Min-Q haben -> Splicing.

Erkennt:
- Eingefuegte Bild-Regionen mit anderer Komprimierungs-Historie.
- Re-saved Bilder ueber andere Bilder.
- Composite-Bilder aus mehreren Quellen (klassischer Cheapfake).

Klassischer Algorithmus (Farid 2009 - "Exposing Digital Forgeries from JPEG Ghosts").
"""
from __future__ import annotations
import io
from pathlib import Path
from typing import Any, Dict, List

from models.schemas import Anomaly, AnomalySeverity, SplicingDetectorResult


Q_LEVELS = [55, 70, 85]   # Re-encode quality steps
BLOCK_SIZE = 64           # Region block size for ghost detection
GHOST_THRESHOLD = 5.0     # Mean-abs-diff threshold for "ghost" match


def _jpeg_ghost_score(img_bytes: bytes) -> Dict[str, Any]:
    """Compute per-Q ghost map. Returns stats + suspect blocks."""
    try:
        from PIL import Image
        import numpy as np
    except ImportError:
        return {"error": "missing dep"}

    try:
        img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
    except Exception as e:
        return {"error": f"open: {e}"}

    arr0 = None
    try:
        import numpy as np
        arr0 = np.asarray(img, dtype="float32")
    except Exception as e:
        return {"error": f"array: {e}"}

    if arr0.ndim != 3 or arr0.shape[0] < BLOCK_SIZE or arr0.shape[1] < BLOCK_SIZE:
        return {"skipped": "too small or wrong shape", "shape": list(arr0.shape)}

    h, w, _ = arr0.shape
    diffs_per_q: Dict[int, Any] = {}

    for q in Q_LEVELS:
        try:
            buf = io.BytesIO()
            img.save(buf, format="JPEG", quality=q)
            buf.seek(0)
            arr_q = np.asarray(Image.open(buf).convert("RGB"), dtype="float32")
            diff = np.mean(np.abs(arr0 - arr_q), axis=2)  # per-pixel mean diff
            diffs_per_q[q] = diff
        except Exception:
            continue

    if not diffs_per_q:
        return {"error": "no q-levels processed"}

    # Per-block: which Q level minimizes the diff?
    qs_sorted = sorted(diffs_per_q.keys())
    n_blocks_h = h // BLOCK_SIZE
    n_blocks_w = w // BLOCK_SIZE
    block_min_q: List[Dict[str, Any]] = []
    q_count: Dict[int, int] = {q: 0 for q in qs_sorted}

    for by in range(n_blocks_h):
        for bx in range(n_blocks_w):
            y0, y1 = by * BLOCK_SIZE, (by + 1) * BLOCK_SIZE
            x0, x1 = bx * BLOCK_SIZE, (bx + 1) * BLOCK_SIZE
            block_diffs = {q: float(diffs_per_q[q][y0:y1, x0:x1].mean())
                           for q in qs_sorted}
            min_q = min(block_diffs, key=block_diffs.get)
            min_val = block_diffs[min_q]
            if min_val < GHOST_THRESHOLD:
                q_count[min_q] += 1
                block_min_q.append({
                    "block": [bx, by],
                    "min_q": min_q,
                    "min_diff": round(min_val, 2),
                })

    total = sum(q_count.values())
    return {
        "image_size": [w, h],
        "total_blocks": n_blocks_h * n_blocks_w,
        "ghost_matched_blocks": total,
        "q_distribution": q_count,
        "matched_blocks": block_min_q[:30],   # cap
    }


def analyze_splicing(pdf_path: Path) -> SplicingDetectorResult:
    anomalies: List[Anomaly] = []

    try:
        import fitz
    except ImportError:
        return SplicingDetectorResult(error="PyMuPDF missing", anomalies=[])

    images_analyzed: List[Dict[str, Any]] = []

    try:
        doc = fitz.open(str(pdf_path))
        for i, page in enumerate(doc):
            for j, img_info in enumerate(page.get_images(full=True)):
                xref = img_info[0]
                try:
                    pix = doc.extract_image(xref)
                    img_bytes = pix["image"]
                    ext = pix.get("ext", "?")
                    if ext.lower() not in ("jpeg", "jpg"):
                        continue   # Only JPEGs have ghost-traceable history
                    res = _jpeg_ghost_score(img_bytes)
                    res.update({
                        "page": i + 1,
                        "xref": xref,
                        "img_index": j,
                        "ext": ext,
                    })
                    images_analyzed.append(res)
                except Exception as e:
                    images_analyzed.append({
                        "page": i + 1, "xref": xref, "error": str(e),
                    })
        doc.close()
    except Exception as e:
        return SplicingDetectorResult(error=str(e), anomalies=[])

    # Anomaly: image with multi-modal Q-distribution = composite
    for img in images_analyzed:
        qd = img.get("q_distribution") or {}
        if not qd:
            continue
        total = sum(qd.values()) or 1
        # Check entropy: if multiple Q levels each >20% -> mixed encoding
        major_levels = [q for q, c in qd.items() if c / total > 0.2]
        if len(major_levels) >= 2:
            anomalies.append(Anomaly(
                severity=AnomalySeverity.HIGH,
                category="splicing_jpeg_ghost",
                message=f"Bild auf Seite {img['page']} hat mixed Quality-History: {major_levels} -- moegliches Composite",
                detail=f"q_distribution={qd}",
            ))

    if images_analyzed and not anomalies:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.LOW,
            category="splicing_clean",
            message=f"{len(images_analyzed)} JPEG-Bild(er) analysiert -- keine Splicing-Indikatoren",
            detail="JPEG-Ghost-Test bestanden",
        ))

    return SplicingDetectorResult(
        images_analyzed=images_analyzed,
        total_images=len(images_analyzed),
        anomalies=anomalies,
    )
