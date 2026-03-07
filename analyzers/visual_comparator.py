"""
Visual Render Comparison — Rendert PDF-Seiten und vergleicht Pixel für Pixel.
Erkennt visuelle Unterschiede zwischen Rendering-Engines.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional
import logging
import hashlib

logger = logging.getLogger(__name__)


def analyze_visual_render(pdf_path: Path, reference_path: Optional[Path] = None) -> Dict[str, Any]:
    """Rendert PDF-Seiten und erzeugt Page-Hashes für Vergleich."""
    result = {
        "available": False,
        "renderer": None,
        "pages_rendered": 0,
        "page_hashes": [],
        "resolution_dpi": 72,
        "total_pixels": 0,
        "blank_pages": [],
        "visual_anomalies": [],
        "comparison": None,
        "anomalies": [],
    }

    try:
        import fitz  # PyMuPDF
        result["available"] = True
        result["renderer"] = f"PyMuPDF {fitz.version[0]}"
    except ImportError:
        result["error"] = "PyMuPDF nicht installiert"
        return result

    try:
        doc = fitz.open(str(pdf_path))
        result["pages_rendered"] = len(doc)
        dpi = 72
        result["resolution_dpi"] = dpi

        for page_num in range(min(len(doc), 50)):  # Max 50 Seiten
            page = doc[page_num]

            # Seite rendern
            mat = fitz.Matrix(dpi / 72, dpi / 72)
            pix = page.get_pixmap(matrix=mat, alpha=False)

            # Pixel-Daten
            pixel_data = pix.samples
            width, height = pix.width, pix.height
            total_px = width * height
            result["total_pixels"] += total_px

            # Hash der gerenderten Seite
            page_hash = hashlib.sha256(pixel_data).hexdigest()

            # Blank-Page-Erkennung: Prüfe ob fast alle Pixel weiß sind
            white_threshold = 250
            white_pixels = 0
            step = max(1, len(pixel_data) // 10000)  # Sampling für Performance
            for i in range(0, len(pixel_data), step * 3):
                if i + 2 < len(pixel_data):
                    r, g, b = pixel_data[i], pixel_data[i + 1], pixel_data[i + 2]
                    if r > white_threshold and g > white_threshold and b > white_threshold:
                        white_pixels += 1

            sample_count = len(range(0, len(pixel_data), step * 3))
            white_ratio = white_pixels / max(sample_count, 1)

            is_blank = white_ratio > 0.99

            page_info = {
                "page": page_num + 1,
                "width": width,
                "height": height,
                "hash": page_hash,
                "white_ratio": round(white_ratio, 4),
                "is_blank": is_blank,
            }
            result["page_hashes"].append(page_info)

            if is_blank:
                result["blank_pages"].append(page_num + 1)

            # Visuelle Anomalien erkennen
            # 1. Ungewöhnliche Seitengröße
            if width < 10 or height < 10:
                result["visual_anomalies"].append({
                    "page": page_num + 1,
                    "type": "tiny_page",
                    "detail": f"Seite {page_num + 1} hat extrem kleine Maße: {width}×{height}px",
                })

            # 2. Duplikat-Seiten erkennen
            for prev in result["page_hashes"][:-1]:
                if prev["hash"] == page_hash and not is_blank:
                    result["visual_anomalies"].append({
                        "page": page_num + 1,
                        "type": "duplicate_page",
                        "detail": f"Seite {page_num + 1} ist visuell identisch mit Seite {prev['page']}",
                    })
                    break

        doc.close()

        # Referenz-Vergleich
        if reference_path and reference_path.exists():
            result["comparison"] = _compare_renders(pdf_path, reference_path, dpi)

        # Anomalien zusammenfassen
        if result["blank_pages"]:
            result["anomalies"].append({
                "severity": "LOW",
                "category": "Visual",
                "message": f"{len(result['blank_pages'])} leere Seiten gefunden",
                "detail": f"Seiten: {', '.join(str(p) for p in result['blank_pages'][:10])}",
            })

        dup_pages = [a for a in result["visual_anomalies"] if a["type"] == "duplicate_page"]
        if dup_pages:
            result["anomalies"].append({
                "severity": "MEDIUM",
                "category": "Visual",
                "message": f"{len(dup_pages)} duplizierte Seiten gefunden",
                "detail": "; ".join(a["detail"] for a in dup_pages[:5]),
            })

    except Exception as e:
        logger.error(f"Visual Render fehlgeschlagen: {e}")
        result["error"] = str(e)

    return result


def _compare_renders(pdf_a: Path, pdf_b: Path, dpi: int = 72) -> Dict[str, Any]:
    """Vergleicht zwei PDF-Dateien visuell Seite für Seite."""
    import fitz

    comparison = {
        "identical_pages": 0,
        "different_pages": 0,
        "page_diffs": [],
    }

    try:
        doc_a = fitz.open(str(pdf_a))
        doc_b = fitz.open(str(pdf_b))

        max_pages = min(len(doc_a), len(doc_b), 20)

        for i in range(max_pages):
            mat = fitz.Matrix(dpi / 72, dpi / 72)
            pix_a = doc_a[i].get_pixmap(matrix=mat, alpha=False)
            pix_b = doc_b[i].get_pixmap(matrix=mat, alpha=False)

            hash_a = hashlib.sha256(pix_a.samples).hexdigest()
            hash_b = hashlib.sha256(pix_b.samples).hexdigest()

            if hash_a == hash_b:
                comparison["identical_pages"] += 1
            else:
                comparison["different_pages"] += 1
                # Differenz berechnen
                diff_ratio = 0
                if pix_a.width == pix_b.width and pix_a.height == pix_b.height:
                    data_a = pix_a.samples
                    data_b = pix_b.samples
                    diff_count = sum(1 for a, b in zip(data_a[::100], data_b[::100]) if abs(a - b) > 10)
                    diff_ratio = diff_count / max(len(data_a) // 100, 1)

                comparison["page_diffs"].append({
                    "page": i + 1,
                    "diff_ratio": round(diff_ratio, 4),
                    "size_a": f"{pix_a.width}×{pix_a.height}",
                    "size_b": f"{pix_b.width}×{pix_b.height}",
                })

        doc_a.close()
        doc_b.close()

    except Exception as e:
        comparison["error"] = str(e)

    return comparison
