"""
OCR Text-Discrepancy Analyzer.

Pipeline:
1. Render jede PDF-Seite via PyMuPDF zu PNG (300 DPI).
2. Tesseract 5 OCR auf das Rendering (deu + eng).
3. Embedded Text-Layer via PyMuPDF.get_text("text").
4. Vergleich Token-by-Token:
   - Hoch ueberlappend  -> normal
   - Embedded leer aber OCR voll -> reine Scan-PDF (info)
   - Embedded voll aber OCR leer -> hidden text (suspicious)
   - Beide voll aber unterschiedlich -> klassische Manipulation
       (z.B. visueller Text "USD" wurde unsichtbar durch "EUR" ersetzt)

Liefert: similarity ratio, fehlende/zusaetzliche Tokens pro Seite.
"""
from __future__ import annotations
import re
import subprocess
import shutil
from pathlib import Path
from typing import Any, Dict, List

from models.schemas import Anomaly, AnomalySeverity, OCRTextDiffResult


_TOKEN_RE = re.compile(r"[A-Za-z0-9äöüÄÖÜß€$%@.,/-]+")


def _tokenize(text: str) -> List[str]:
    return [t.lower() for t in _TOKEN_RE.findall(text or "") if len(t) >= 2]


def _jaccard(a: List[str], b: List[str]) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def _ocr_image(image_bytes: bytes, langs: str = "eng+deu") -> str:
    if not shutil.which("tesseract"):
        return ""
    try:
        proc = subprocess.run(
            ["tesseract", "stdin", "stdout", "-l", langs, "--psm", "6"],
            input=image_bytes, capture_output=True, timeout=120,
        )
        return proc.stdout.decode("utf-8", errors="replace")
    except Exception:
        return ""


def analyze_ocr_text_diff(pdf_path: Path) -> OCRTextDiffResult:
    anomalies: List[Anomaly] = []
    try:
        import fitz
    except ImportError:
        return OCRTextDiffResult(error="PyMuPDF not installed", anomalies=[])

    if not shutil.which("tesseract"):
        return OCRTextDiffResult(error="tesseract not installed", anomalies=[])

    pages: List[Dict[str, Any]] = []
    total_embedded = 0
    total_ocr = 0
    sum_similarity = 0.0
    seen = 0

    try:
        doc = fitz.open(str(pdf_path))
        for i, page in enumerate(doc):
            embedded = page.get_text("text") or ""
            # 150 DPI + JPEG quality 85 spart ~70% Speicher fuer grosse PDFs
            pix = page.get_pixmap(dpi=150)
            try:
                png = pix.tobytes("jpeg", jpg_quality=85)
            except Exception:
                png = pix.tobytes("png")
            ocr = _ocr_image(png)

            emb_tokens = _tokenize(embedded)
            ocr_tokens = _tokenize(ocr)
            sim = _jaccard(emb_tokens, ocr_tokens)
            only_emb = sorted(set(emb_tokens) - set(ocr_tokens))[:30]
            only_ocr = sorted(set(ocr_tokens) - set(emb_tokens))[:30]

            pages.append({
                "page": i + 1,
                "embedded_token_count": len(emb_tokens),
                "ocr_token_count": len(ocr_tokens),
                "similarity_jaccard": round(sim, 3),
                "only_in_embedded": only_emb,
                "only_in_ocr": only_ocr,
                "embedded_chars": len(embedded),
                "ocr_chars": len(ocr),
            })
            total_embedded += len(emb_tokens)
            total_ocr += len(ocr_tokens)
            sum_similarity += sim
            seen += 1
        doc.close()
    except Exception as e:
        return OCRTextDiffResult(error=str(e), anomalies=[])

    avg_sim = sum_similarity / seen if seen else 1.0

    # Anomaly heuristics
    for p in pages:
        emb_n = p["embedded_token_count"]
        ocr_n = p["ocr_token_count"]
        sim = p["similarity_jaccard"]

        if emb_n > 5 and ocr_n == 0:
            anomalies.append(Anomaly(
                severity=AnomalySeverity.MEDIUM,
                category="ocr_hidden_text",
                message=f"Seite {p['page']}: embedded Text vorhanden, OCR liefert nichts -- moeglicherweise unsichtbarer Text",
                detail=f"emb_tokens={emb_n}, ocr_tokens=0",
            ))
        elif emb_n == 0 and ocr_n > 5:
            anomalies.append(Anomaly(
                severity=AnomalySeverity.LOW,
                category="ocr_scan_only",
                message=f"Seite {p['page']}: reine Scan-PDF (kein eingebetteter Text)",
                detail=f"ocr_tokens={ocr_n}",
            ))
        elif emb_n > 10 and ocr_n > 10 and sim < 0.3:
            # < 30% Aehnlichkeit ist deutlich ueber Tesseract-Fehlerrate (~30-50% bei kleinen Schriften)
            anomalies.append(Anomaly(
                severity=AnomalySeverity.HIGH,
                category="ocr_text_mismatch",
                message=f"Seite {p['page']}: embedded Text weicht stark vom OCR ab (Jaccard={sim}) -- Manipulation-Verdacht",
                detail=f"only_embedded={p['only_in_embedded'][:8]} only_ocr={p['only_in_ocr'][:8]}",
            ))
        elif emb_n > 10 and ocr_n > 10 and 0.3 <= sim < 0.6:
            anomalies.append(Anomaly(
                severity=AnomalySeverity.MEDIUM,
                category="ocr_text_partial_mismatch",
                message=f"Seite {p['page']}: teilweise Diskrepanz zwischen embedded Text und OCR (Jaccard={sim})",
                detail=f"emb={emb_n} ocr={ocr_n}",
            ))

    return OCRTextDiffResult(
        pages=pages,
        total_embedded_tokens=total_embedded,
        total_ocr_tokens=total_ocr,
        avg_similarity=round(avg_sim, 3),
        anomalies=anomalies,
    )
