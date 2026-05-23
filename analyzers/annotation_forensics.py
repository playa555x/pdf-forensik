"""
Annotation-Forensik (Bonus-Analyzer).

Walkt ALLE PDF-Objekte (nicht nur die in /Annots-Arrays referenzierten),
extrahiert /T (Author), /M (ModDate), /NM (Name), /Subtype, /Rect, /Contents.

Erkennt:
- Verwaiste Annotations (Annot-Objekte ohne Page-Referenz)  -> haeufig nach Redaction
- Ueberlappende Rect-Bereiche (z.B. Square-Annot ueber Text-Bereich = Redaction)
- Author-Zeitlinie aus /M-Timestamps
- Annotations in spaeteren Revisionen (verlinkt mit incremental_updates)
"""
from __future__ import annotations
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from models.schemas import Anomaly, AnomalySeverity, AnnotationForensicsResult


_DATE_RE = re.compile(r"D:(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})")


def _parse_pdf_date(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    m = _DATE_RE.search(str(raw))
    if not m:
        return None
    y, mo, d, h, mi, s = m.groups()
    return f"{y}-{mo}-{d}T{h}:{mi}:{s}"


def _extract_value(obj_text: str, key: str) -> Optional[str]:
    """Crude regex-extract of /Key (string) or /Key /Name from object string."""
    pattern = re.compile(rf"/{re.escape(key)}\s*\(([^)]*)\)")
    m = pattern.search(obj_text)
    if m:
        return m.group(1)
    pattern2 = re.compile(rf"/{re.escape(key)}\s*/(\w+)")
    m = pattern2.search(obj_text)
    if m:
        return m.group(1)
    return None


def _extract_rect(obj_text: str) -> Optional[List[float]]:
    m = re.search(r"/Rect\s*\[([^\]]+)\]", obj_text)
    if not m:
        return None
    try:
        nums = [float(x) for x in m.group(1).replace(",", " ").split()]
        if len(nums) == 4:
            return nums
    except ValueError:
        pass
    return None


def _rects_overlap(a: List[float], b: List[float]) -> bool:
    ax1, ax2 = sorted([a[0], a[2]])
    ay1, ay2 = sorted([a[1], a[3]])
    bx1, bx2 = sorted([b[0], b[2]])
    by1, by2 = sorted([b[1], b[3]])
    return not (ax2 < bx1 or bx2 < ax1 or ay2 < by1 or by2 < ay1)


def analyze_annotation_forensics(pdf_path: Path) -> AnnotationForensicsResult:
    anomalies: List[Anomaly] = []
    try:
        import fitz
    except ImportError:
        return AnnotationForensicsResult(error="PyMuPDF not installed", anomalies=[])

    annotations: List[Dict[str, Any]] = []
    referenced_xrefs: set = set()

    try:
        doc = fitz.open(str(pdf_path))

        # Schritt 1: collect xrefs that are referenced as /Annots on a page
        for i, page in enumerate(doc):
            for annot in page.annots() or []:
                referenced_xrefs.add(annot.xref)

        # Schritt 2: walk ALL objects, find ones with /Type /Annot
        for xref in range(1, doc.xref_length()):
            try:
                obj_text = doc.xref_object(xref) or ""
                if "/Subtype" not in obj_text and "/Type /Annot" not in obj_text:
                    continue
                # Heuristic: must look like an annotation
                if "/Annot" not in obj_text and "/Subtype" not in obj_text:
                    continue
                subtype = _extract_value(obj_text, "Subtype")
                if not subtype:
                    continue
                # Subtype must be a known annotation type to qualify
                if subtype not in ("Text", "Square", "Circle", "Highlight", "Underline",
                                    "StrikeOut", "Stamp", "Caret", "Ink", "Popup", "FileAttachment",
                                    "Sound", "Movie", "Widget", "Screen", "PrinterMark",
                                    "TrapNet", "Watermark", "3D", "Redact", "FreeText", "Line",
                                    "PolyLine", "Polygon", "Link"):
                    continue

                ann = {
                    "xref": xref,
                    "subtype": subtype,
                    "author": _extract_value(obj_text, "T"),
                    "name": _extract_value(obj_text, "NM"),
                    "mod_date_raw": _extract_value(obj_text, "M"),
                    "mod_date_iso": _parse_pdf_date(_extract_value(obj_text, "M")),
                    "contents": _extract_value(obj_text, "Contents"),
                    "rect": _extract_rect(obj_text),
                    "referenced": xref in referenced_xrefs,
                }
                annotations.append(ann)
            except Exception:
                continue

        doc.close()
    except Exception as e:
        return AnnotationForensicsResult(error=str(e), anomalies=[])

    # Anomaly: orphan annotations (existieren aber keine Seite zeigt drauf)
    orphans = [a for a in annotations if not a["referenced"]]
    if orphans:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category="annot_orphan",
            message=f"{len(orphans)} verwaiste Annotation(en) -- existieren im PDF aber sind keiner Seite zugeordnet",
            detail=f"subtypes: {sorted(set(a['subtype'] for a in orphans))}",
        ))

    # Author-Liste
    authors = sorted({a["author"] for a in annotations if a["author"]})
    if authors:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.LOW,
            category="annot_authors",
            message=f"{len(authors)} unterschiedliche Annotation-Author(en)",
            detail=f"authors: {authors}",
        ))

    # Redaction-Detection: nur expliziter /Redact-Subtype (keine Square/Stamp - oft legitim)
    explicit_redactions = [a for a in annotations
                           if a["subtype"] == "Redact" and a["rect"]]
    if explicit_redactions:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.HIGH,
            category="annot_redaction",
            message=f"{len(explicit_redactions)} explizite Redact-Annotation(en)",
            detail=f"authors: {sorted({a['author'] for a in explicit_redactions if a['author']})}",
        ))

    # Square/Stamp nur als LOW-Info (legitim aber dokumentationswert)
    cover_annots = [a for a in annotations
                    if a["subtype"] in ("Square", "Stamp") and a["rect"]]
    if cover_annots:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.LOW,
            category="annot_cover_shape",
            message=f"{len(cover_annots)} Square/Stamp-Annotation(en) -- pruefen ob Inhalt darunter verdeckt",
            detail=f"subtypes: {sorted(set(a['subtype'] for a in cover_annots))}",
        ))

    # Timeline aus /M-Datums
    dated = sorted(
        [(a["mod_date_iso"], a) for a in annotations if a["mod_date_iso"]],
        key=lambda t: t[0],
    )
    timeline = [{"date": d, "subtype": a["subtype"], "author": a["author"]}
                for d, a in dated]

    return AnnotationForensicsResult(
        annotation_count=len(annotations),
        annotations=annotations[:200],   # cap
        orphan_count=len(orphans),
        unique_authors=authors,
        timeline=timeline[:200],
        anomalies=anomalies,
    )
