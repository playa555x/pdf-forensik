"""
LayoutLMv3 Form-Field Consistency Analyzer.

microsoft/layoutlmv3-base extrahiert Tokens + normalisierte Bounding-Boxes
([0..1000]-Skala) pro PDF-Seite. Wir verwenden NICHT die Token-Klassifikation
(braeuchte fine-tuned Modell), sondern nur die Tokenizer + Layout-Embedding
ueber den Image-Encoder, um Outlier in der Layout-Verteilung zu finden.

Forensisch:
- Cluster aller Token-BBoxes pro Seite via Y-Median + IQR.
- Tokens mit BBox-Y-Position > 1.5*IQR vom Median = Outlier
  (haeufig nachtraeglich eingefuegte Felder).
- Cross-Page-Vergleich der BBox-Verteilungen: drastische Abweichungen
  einer Seite gegenueber dem Dokument-Mittel = Verdacht auf nachtraegliche
  Manipulation.

Nutzt nur den Tokenizer + Image-Processor (kein torch.no_grad()-Forward),
laeuft daher auch auf CPU schnell (~2-3s pro Seite).
"""
from __future__ import annotations
import statistics
from pathlib import Path
from typing import Any, Dict, List

from models.schemas import Anomaly, AnomalySeverity, LayoutConsistencyResult


_PROC_CACHE: Dict[str, Any] = {}


def _load_processor():
    if "proc" in _PROC_CACHE:
        return _PROC_CACHE["proc"]
    try:
        from transformers import LayoutLMv3Processor
        proc = LayoutLMv3Processor.from_pretrained(
            "microsoft/layoutlmv3-base",
            apply_ocr=True,
            cache_dir="/var/data/hf_cache",
        )
        _PROC_CACHE["proc"] = proc
        return proc
    except Exception as e:
        _PROC_CACHE["error"] = str(e)
        return None


def _bbox_stats(bboxes: List[List[int]]) -> Dict[str, Any]:
    """LayoutLMv3 bboxes are normalized [0..1000]. Compute layout fingerprint."""
    if not bboxes:
        return {}
    xs = [(b[0] + b[2]) / 2 for b in bboxes]
    ys = [(b[1] + b[3]) / 2 for b in bboxes]
    widths = [b[2] - b[0] for b in bboxes]
    heights = [b[3] - b[1] for b in bboxes]

    def _stats(arr):
        if not arr:
            return {}
        return {
            "median": round(statistics.median(arr), 1),
            "mean": round(statistics.mean(arr), 1),
            "stdev": round(statistics.stdev(arr) if len(arr) > 1 else 0, 1),
            "min": min(arr),
            "max": max(arr),
        }

    return {
        "token_count": len(bboxes),
        "x_center": _stats(xs),
        "y_center": _stats(ys),
        "width": _stats(widths),
        "height": _stats(heights),
    }


def _find_y_outliers(bboxes: List[List[int]], words: List[str]) -> List[Dict[str, Any]]:
    """Tokens whose Y-position deviates strongly from the page median."""
    if len(bboxes) < 8:
        return []
    ys = [(b[1] + b[3]) / 2 for b in bboxes]
    median = statistics.median(ys)
    q1 = statistics.median(sorted(ys)[:len(ys) // 2])
    q3 = statistics.median(sorted(ys)[(len(ys) + 1) // 2:])
    iqr = q3 - q1
    if iqr < 1:
        return []
    threshold = 1.5 * iqr
    outliers = []
    for i, (b, w) in enumerate(zip(bboxes, words)):
        y = (b[1] + b[3]) / 2
        if abs(y - median) > threshold and w.strip():
            outliers.append({
                "word": w[:30],
                "bbox": b,
                "y_center": round(y, 1),
                "deviation": round(abs(y - median), 1),
            })
    return outliers[:20]


def analyze_hf_layout_consistency(pdf_path: Path) -> LayoutConsistencyResult:
    anomalies: List[Anomaly] = []

    try:
        import fitz
    except ImportError:
        return LayoutConsistencyResult(error="PyMuPDF missing", anomalies=[])

    proc = _load_processor()
    if proc is None:
        return LayoutConsistencyResult(
            error=_PROC_CACHE.get("error", "LayoutLMv3 processor load failed"),
            anomalies=[],
        )

    try:
        from PIL import Image
        import io
    except ImportError as e:
        return LayoutConsistencyResult(error=f"missing dep: {e}", anomalies=[])

    pages_out: List[Dict[str, Any]] = []
    page_fingerprints: List[Dict[str, Any]] = []

    try:
        doc = fitz.open(str(pdf_path))
        # Cap to 10 pages for performance
        for i, page in enumerate(doc):
            if i >= 10:
                break
            try:
                pix = page.get_pixmap(dpi=120)
                img = Image.open(io.BytesIO(pix.tobytes("png"))).convert("RGB")
                # apply_ocr=True triggers built-in tesseract for token extraction
                encoded = proc(img, return_tensors="pt", truncation=True, max_length=512)
                # Strict validation -- BatchEncoding may return None or missing keys silently
                if "input_ids" not in encoded:
                    pages_out.append({"page": i + 1, "error": "LayoutLMv3 processor returned no input_ids -- OCR likely failed on page"})
                    continue
                # Bbox extraction (preferred path)
                bboxes: List[List[int]] = []
                if "bbox" in encoded:
                    bboxes_raw = encoded["bbox"]
                    if hasattr(bboxes_raw, "tolist"):
                        bb = bboxes_raw.tolist()
                        if bb and isinstance(bb[0], list):
                            bboxes = bb[0]
                # Words: from processor's internal storage (Tesseract-derived)
                words: List[str] = []
                input_ids = encoded.get("input_ids")
                if input_ids is not None and hasattr(input_ids, "tolist"):
                    try:
                        # Decode token-by-token to reconstruct words
                        ids_list = input_ids.tolist()[0]
                        for tid in ids_list:
                            tok = proc.tokenizer.decode([tid], skip_special_tokens=True).strip()
                            words.append(tok)
                    except Exception:
                        words = []
                # Truncate words/bboxes to same length
                n = min(len(words), len(bboxes))
                words, bboxes = words[:n], bboxes[:n]
                if n == 0:
                    pages_out.append({"page": i + 1, "error": "no tokens/bboxes extracted -- empty page or OCR failure"})
                    continue

                fingerprint = _bbox_stats(bboxes)
                outliers = _find_y_outliers(bboxes, words) if words else []

                page_fingerprints.append(fingerprint)
                pages_out.append({
                    "page": i + 1,
                    "tokens": fingerprint.get("token_count", 0),
                    "y_outliers": outliers,
                    "fingerprint": fingerprint,
                })
            except Exception as e:
                pages_out.append({"page": i + 1, "error": str(e)})

        doc.close()
    except Exception as e:
        return LayoutConsistencyResult(error=str(e), anomalies=[])

    # Anomaly: any page with significant outliers
    for p in pages_out:
        outs = p.get("y_outliers", [])
        if len(outs) >= 3:
            anomalies.append(Anomaly(
                severity=AnomalySeverity.MEDIUM,
                category="layout_y_outlier",
                message=f"Seite {p['page']}: {len(outs)} Token mit ungewoehnlicher Y-Position (moegliches eingefuegtes Feld)",
                detail=f"first_outliers={[o['word'] for o in outs[:5]]}",
            ))

    # Anomaly: page-to-page layout fingerprint divergence
    if len(page_fingerprints) >= 2:
        token_counts = [p.get("token_count", 0) for p in page_fingerprints]
        if max(token_counts) > 0 and min(token_counts) > 0:
            ratio = max(token_counts) / max(min(token_counts), 1)
            if ratio > 5:
                anomalies.append(Anomaly(
                    severity=AnomalySeverity.LOW,
                    category="layout_token_imbalance",
                    message=f"Seitenuebergreifende Token-Verteilung stark asymmetrisch (max/min = {ratio:.1f}x)",
                    detail=f"token_counts={token_counts}",
                ))

    return LayoutConsistencyResult(
        pages=pages_out,
        page_count=len(pages_out),
        anomalies=anomalies,
    )
