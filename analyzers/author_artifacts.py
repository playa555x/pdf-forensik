"""
Author-Artifacts-Analyzer: Extrahiert versteckte Autorhinweise aus PDF-Strukturen.

Quellen:
- Font-Subset-Präfixe (z.B. "ABCDEF+Arial" → Präfix = Geräte-/Session-Fingerprint)
- XMP xmpMM:History (Speicherpfade, Autorennamen, Anwendungs-IDs)
- Annotations: /T (Autor), /Contents
- Formularfelder: /T (Feldname), /V (Wert), /TU (Tooltip)
- Kommentare im Revisions-History-Stream
- /ViewerPreferences /PrinterName (falls gesetzt)
- Thumbnail-Kommentar (manchmal Softwarename)
"""
from __future__ import annotations
import re
from pathlib import Path
from typing import List, Dict, Any, Set

import pikepdf

from models.schemas import Anomaly, AnomalySeverity


# Regex: 6-Buchstaben-Großbuchstaben-Präfix vor "+"
_FONT_PREFIX_RE = re.compile(r"^([A-Z]{6})\+(.+)$")

# XMP-Keys die Benutzernamen/Pfade enthalten können
_XMP_AUTHOR_KEYS = [
    "xmpMM:History",
    "xmpMM:DerivedFrom",
    "xmpMM:OriginalDocumentID",
    "dc:creator",
    "xmp:CreatorTool",
    "xmpMM:InstanceID",
    "pdf:Producer",
]

# Windows/macOS Pfad-Muster (enthält häufig Benutzernamen)
_PATH_RE = re.compile(
    r"(?:[A-Za-z]:\\|/home/|/Users/|/var/|C:/)"
    r"(?:[^\s\"'<>:*?|/\\]+[/\\])*[^\s\"'<>:*?|/\\]+",
    re.IGNORECASE,
)

# E-Mail-Muster
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


def _extract_font_prefixes(pdf: pikepdf.Pdf) -> List[Dict[str, Any]]:
    """Extrahiert 6-Buchstaben-Font-Subset-Präfixe aus allen Seiten und Ressourcen."""
    prefixes: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    def _scan_fonts(obj, page_num: int):
        try:
            if isinstance(obj, pikepdf.Dictionary):
                for key in obj.keys():
                    val = obj[key]
                    if str(key) == "/BaseFont":
                        name = str(val).lstrip("/")
                        m = _FONT_PREFIX_RE.match(name)
                        if m and m.group(1) not in seen:
                            seen.add(m.group(1))
                            prefixes.append({
                                "prefix":    m.group(1),
                                "font_name": m.group(2),
                                "page":      page_num,
                                "note":      "Font-Subset-Präfix (6-Zeichen): einmalig je Dokument/Session generiert",
                            })
                    try:
                        _scan_fonts(val, page_num)
                    except Exception:
                        pass
        except Exception:
            pass

    try:
        for i, page in enumerate(pdf.pages):
            try:
                res = page.get("/Resources")
                if res:
                    fonts = res.get("/Font")
                    if fonts:
                        _scan_fonts(fonts, i + 1)
            except Exception:
                continue
    except Exception:
        pass

    return prefixes


def _extract_xmp_authors(pdf: pikepdf.Pdf) -> List[Dict[str, Any]]:
    """Extrahiert Autorinformationen aus XMP-Metadaten."""
    results = []
    try:
        with pdf.open_metadata() as meta:
            for key in _XMP_AUTHOR_KEYS:
                try:
                    val = meta.get(key)
                    if val:
                        s = str(val)
                        results.append({"source": f"XMP:{key}", "value": s})
                except Exception:
                    continue

            # Alle Felder nach Pfaden und E-Mails scannen
            for key in meta:
                try:
                    val = str(meta[key])
                    paths = _PATH_RE.findall(val)
                    emails = _EMAIL_RE.findall(val)
                    for p in paths:
                        results.append({"source": f"XMP:{key}[path]", "value": p})
                    for e in emails:
                        results.append({"source": f"XMP:{key}[email]", "value": e})
                except Exception:
                    continue
    except Exception:
        pass
    return results


def _extract_annotation_authors(pdf: pikepdf.Pdf) -> List[Dict[str, Any]]:
    """Extrahiert Autoren aus Annotations (/T = Author-Feld)."""
    results = []
    try:
        for i, page in enumerate(pdf.pages):
            try:
                annots = page.get("/Annots")
                if not annots:
                    continue
                for annot in annots:
                    try:
                        if isinstance(annot, pikepdf.Dictionary):
                            author = annot.get("/T")
                            if author:
                                results.append({
                                    "source":  f"Annotation/T (Seite {i+1})",
                                    "value":   str(author),
                                    "type":    str(annot.get("/Subtype", "")),
                                })
                            # Inhalt (kann E-Mail/Name enthalten)
                            contents = annot.get("/Contents")
                            if contents:
                                s = str(contents)
                                emails = _EMAIL_RE.findall(s)
                                for e in emails:
                                    results.append({
                                        "source": f"Annotation/Contents/email (Seite {i+1})",
                                        "value":  e,
                                    })
                    except Exception:
                        continue
            except Exception:
                continue
    except Exception:
        pass
    return results


def _extract_form_field_hints(pdf: pikepdf.Pdf) -> List[Dict[str, Any]]:
    """Extrahiert Formularfeld-Namen die Benutzerhinweise enthalten können."""
    results = []
    try:
        acroform = pdf.Root.get("/AcroForm")
        if not acroform:
            return results
        fields = acroform.get("/Fields")
        if not fields:
            return results

        def _scan_fields(field_list):
            for field in field_list:
                try:
                    if not isinstance(field, pikepdf.Dictionary):
                        field = field.get_object()
                    name  = field.get("/T")
                    value = field.get("/V")
                    tip   = field.get("/TU")
                    if name:
                        results.append({"source": "AcroForm/Field/T", "value": str(name)})
                    if value and str(value).strip():
                        s = str(value)
                        emails = _EMAIL_RE.findall(s)
                        paths  = _PATH_RE.findall(s)
                        for e in emails:
                            results.append({"source": "AcroForm/Field/V[email]", "value": e})
                        for p in paths:
                            results.append({"source": "AcroForm/Field/V[path]", "value": p})
                    if tip:
                        results.append({"source": "AcroForm/Field/TU", "value": str(tip)})
                    kids = field.get("/Kids")
                    if kids:
                        _scan_fields(kids)
                except Exception:
                    continue

        _scan_fields(fields)
    except Exception:
        pass
    return results


def _extract_printer_name(pdf: pikepdf.Pdf) -> List[Dict[str, Any]]:
    """Extrahiert /PrinterName aus ViewerPreferences — enthält manchmal Gerätename."""
    results = []
    try:
        vp = pdf.Root.get("/ViewerPreferences")
        if vp:
            pn = vp.get("/PrinterName")
            if pn:
                results.append({"source": "ViewerPreferences/PrinterName", "value": str(pn)})
    except Exception:
        pass
    return results


def analyze_author_artifacts(pdf_path: Path) -> Dict[str, Any]:
    """Hauptfunktion: aggregiert alle versteckten Autorenhinweise."""
    anomalies: List[Anomaly] = []

    try:
        pdf = pikepdf.open(pdf_path)
    except Exception as e:
        return {
            "font_prefixes":      [],
            "xmp_authors":        [],
            "annotation_authors": [],
            "form_field_hints":   [],
            "printer_name":       [],
            "all_artifacts":      [],
            "anomalies": [Anomaly(
                severity=AnomalySeverity.HIGH,
                category="author_artifacts",
                message="PDF konnte nicht für Author-Artifact-Analyse geöffnet werden",
                detail=str(e),
            )],
        }

    with pdf:
        font_prefixes      = _extract_font_prefixes(pdf)
        xmp_authors        = _extract_xmp_authors(pdf)
        annotation_authors = _extract_annotation_authors(pdf)
        form_hints         = _extract_form_field_hints(pdf)
        printer            = _extract_printer_name(pdf)

    all_artifacts = font_prefixes + xmp_authors + annotation_authors + form_hints + printer

    # Anomalien
    if font_prefixes:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.INFO,
            category="author_artifacts",
            message=f"{len(font_prefixes)} Font-Subset-Präfix(e) gefunden — einmalige Session-Fingerprints",
            detail=", ".join(f"{p['prefix']}+{p['font_name']}" for p in font_prefixes[:5]),
        ))

    paths_found = [a for a in all_artifacts if "[path]" in a.get("source", "")]
    if paths_found:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category="author_artifacts",
            message=f"{len(paths_found)} Dateipfad(e) gefunden — können Benutzernamen enthalten",
            detail="; ".join(p["value"] for p in paths_found[:3]),
        ))

    emails_found = [a for a in all_artifacts if "[email]" in a.get("source", "")]
    if emails_found:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category="author_artifacts",
            message=f"{len(emails_found)} E-Mail-Adresse(n) im Dokument eingebettet",
            detail="; ".join(e["value"] for e in emails_found[:3]),
        ))

    annot_authors = [a for a in annotation_authors if "Annotation/T" in a.get("source", "")]
    if annot_authors:
        names = list({a["value"] for a in annot_authors})
        anomalies.append(Anomaly(
            severity=AnomalySeverity.INFO,
            category="author_artifacts",
            message=f"Annotations-Autoren gefunden: {', '.join(names[:5])}",
            detail=f"{len(annot_authors)} Annotation(en) mit Autorenfeld",
        ))

    return {
        "font_prefixes":      font_prefixes,
        "xmp_authors":        xmp_authors,
        "annotation_authors": annotation_authors,
        "form_field_hints":   form_hints,
        "printer_name":       printer,
        "all_artifacts":      all_artifacts,
        "anomalies":          anomalies,
    }
