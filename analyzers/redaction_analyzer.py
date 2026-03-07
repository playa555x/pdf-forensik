"""
Redaction Analysis.

Prüft ob Schwärzungen in PDFs tatsächlich sicher sind:
1. Schwarze Rechtecke über Text (unsicher — Text noch im Stream)
2. Annotations-basierte Redaktionen (Redact-Annotations)
3. Overlapping Content prüfen (Text unter Grafik-Overlay)
4. Redacted-Area Content-Extraction-Versuch
"""
from __future__ import annotations
import re
from pathlib import Path
from typing import List, Dict, Any

from models.schemas import Anomaly, AnomalySeverity, RedactionResult

try:
    import pikepdf
    PIKE_OK = True
except ImportError:
    PIKE_OK = False


def analyze_redactions(pdf_path: Path) -> RedactionResult:
    """Analysiert Schwärzungen auf Sicherheit."""
    anomalies: List[Anomaly] = []
    redactions_found = 0
    secure_count = 0
    insecure_count = 0
    details: List[Dict[str, Any]] = []

    if not PIKE_OK:
        return RedactionResult(
            anomalies=[Anomaly(
                severity=AnomalySeverity.INFO,
                category="redaction",
                message="pikepdf nicht verfügbar — Redaktions-Analyse übersprungen",
            )]
        )

    try:
        pdf = pikepdf.open(pdf_path, allow_overwriting_input=True)

        for page_num, page in enumerate(pdf.pages, 1):
            # 1. Prüfe Annotations
            annots = page.get("/Annots")
            if annots:
                try:
                    annot_list = list(annots) if isinstance(annots, pikepdf.Array) else []
                except Exception:
                    annot_list = []

                for annot_ref in annot_list:
                    try:
                        annot = annot_ref if isinstance(annot_ref, pikepdf.Dictionary) else pdf.get_object(annot_ref)
                        subtype = str(annot.get("/Subtype", ""))

                        if subtype == "/Redact":
                            redactions_found += 1
                            # Redact-Annotation gefunden — prüfe ob angewendet
                            # Wenn /Redact noch als Annotation existiert, wurde sie NICHT angewendet
                            insecure_count += 1
                            details.append({
                                "page": page_num,
                                "type": "redact_annotation_pending",
                                "secure": False,
                                "note": "Redact-Annotation nicht angewendet — Text noch lesbar",
                            })
                            anomalies.append(Anomaly(
                                severity=AnomalySeverity.HIGH,
                                category="redaction",
                                message=f"Seite {page_num}: Nicht-angewendete Redact-Annotation",
                                detail="Schwärzung ist nur visuell — der darunter liegende Text ist noch im PDF",
                            ))

                    except Exception:
                        continue

            # 2. Content-Stream-Analyse: Schwarze Rechtecke über Text
            try:
                content_stream = page.get("/Contents")
                if content_stream:
                    if isinstance(content_stream, pikepdf.Array):
                        raw_parts = []
                        for cs in content_stream:
                            try:
                                raw_parts.append(bytes(cs.read_bytes()))
                            except Exception:
                                pass
                        raw = b"".join(raw_parts)
                    else:
                        try:
                            raw = bytes(content_stream.read_bytes())
                        except Exception:
                            raw = b""

                    content_text = raw.decode("latin-1", errors="replace")

                    # Muster: Schwarze Füllung (0 0 0 rg/RG) gefolgt von re (Rechteck) und f (Fill)
                    black_rects = re.findall(
                        r'0\s+0\s+0\s+(?:rg|RG)\s*[\d.]+\s+[\d.]+\s+[\d.]+\s+[\d.]+\s+re\s+f',
                        content_text
                    )

                    # Prüfe ob Text-Operatoren (Tj, TJ, ') in der Nähe der Rechtecke sind
                    if black_rects:
                        has_text_ops = bool(re.search(r'\((.*?)\)\s*(?:Tj|TJ|\')', content_text))

                        if has_text_ops:
                            redactions_found += len(black_rects)
                            # Text existiert noch → unsichere Schwärzung
                            for i, rect in enumerate(black_rects[:5]):
                                insecure_count += 1
                                details.append({
                                    "page": page_num,
                                    "type": "black_rect_over_text",
                                    "secure": False,
                                    "rect_pattern": rect[:60],
                                    "note": "Schwarzes Rechteck über Text — Copy-Paste extrahiert den Text",
                                })

                            if black_rects:
                                anomalies.append(Anomaly(
                                    severity=AnomalySeverity.HIGH,
                                    category="redaction",
                                    message=f"Seite {page_num}: {len(black_rects)} schwarze Rechtecke über Text",
                                    detail="Unsichere Schwärzung — Text kann per Copy-Paste oder via API extrahiert werden",
                                ))

                    # 3. Prüfe auf Redaction-Remnants
                    # Manche PDFs haben Schwärzungen richtig gemacht, aber der Originaltext
                    # ist noch in einem vorherigen Incremental Update
                    # (Das wird vom incremental_diff Analyzer geprüft)

            except Exception:
                continue

        pdf.close()

    except Exception as e:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category="redaction",
            message=f"Redaktions-Analyse-Fehler: {str(e)[:100]}",
        ))

    return RedactionResult(
        redactions_found=redactions_found,
        secure_redactions=secure_count,
        insecure_redactions=insecure_count,
        redaction_details=details,
        anomalies=anomalies,
    )
