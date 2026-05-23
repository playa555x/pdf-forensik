"""
Doc-Type-Klassifikator — heuristische Einordnung des PDFs in eine
Dokumentkategorie, die als Eingabe fuer Doc-Typ-bewusste Severity-Profile
genutzt wird (siehe analyzers/severity_profiles.py).

Kategorien:
- office_letter        — kurzer Office-Brief/Memo
- office_document      — laengeres Office-Dokument (Bericht, Vertrag)
- design_brochure      — CorelDRAW/InDesign/Illustrator/Scribus -> Marketingmaterial
- scan                 — Dokument ist eingescannt (Printer-Forensik detected)
- form                 — AcroForm dominiert (ausfuellbares Formular)
- technical_document   — LaTeX/pdfTeX-Quelle (akademisch/technisch)
- online_converted     — Online-Konverter (Smallpdf, iLovePDF, ...)
- unknown              — keine eindeutigen Indikatoren

Ist absichtlich heuristisch und einfach. Wer es spaeter ersetzen will,
kann z.B. ein DocLayout-Modell von HuggingFace anschliessen — die Schnittstelle
(DocTypeResult) bleibt gleich.
"""
from __future__ import annotations
from typing import Optional

from models.schemas import (
    SoftwareFingerprint, MetadataResult, SignatureInfo,
    PrinterForensicsResult, DocTypeResult,
)


# Tool-Listen — case-insensitive Substring-Matches
_DESIGN_TOOLS = (
    "CorelDRAW", "InDesign", "Adobe Illustrator", "Scribus",
    "QuarkXPress", "Adobe FrameMaker", "Affinity Publisher", "Affinity Designer",
)
_OFFICE_TOOLS = (
    "Microsoft Word", "Microsoft® Word", "Word for Mac",
    "LibreOffice", "OpenOffice", "Apple Pages",
)
_TECHNICAL_TOOLS = (
    "pdfTeX", "LaTeX", "TeX Live", "MiKTeX", "XeTeX", "LuaTeX",
)
_ONLINE_SERVICES = (
    "Smallpdf", "iLovePDF", "Sejda", "PDF2Go", "pdfforge", "wkhtmltopdf",
    "PDF24", "doPDF",
)


def _matches_any(haystack: str, needles: tuple) -> Optional[str]:
    if not haystack:
        return None
    h = haystack.lower()
    for n in needles:
        if n.lower() in h:
            return n
    return None


def classify_doc_type(
    software_fingerprint: Optional[SoftwareFingerprint] = None,
    metadata: Optional[MetadataResult] = None,
    signature: Optional[SignatureInfo] = None,
    printer_forensics: Optional[PrinterForensicsResult] = None,
) -> DocTypeResult:
    """
    Klassifiziert das PDF heuristisch. Reihenfolge der Pruefungen ist
    bewusst gewaehlt — Scan-Erkennung hat hoechste Prioritaet, dann
    Tool-Match, dann Form-Indikator.
    """
    reasoning: list[str] = []

    sf = software_fingerprint
    tool     = (sf.identified_tool if sf else "") or ""
    producer = (sf.producer_raw    if sf else "") or ""
    creator  = (sf.creator_raw     if sf else "") or ""
    combined = f"{tool} {producer} {creator}".strip()

    page_count   = (metadata.page_count if metadata else 0) or 0
    is_scan      = bool(printer_forensics and printer_forensics.is_scanned_document)
    has_acroform = bool(signature and signature.has_acroform)

    inputs = {
        "identified_tool": tool,
        "producer_raw":    producer,
        "creator_raw":     creator,
        "page_count":      page_count,
        "is_scan":         is_scan,
        "has_acroform":    has_acroform,
    }

    # 1) Scan-Erkennung — Printer-Forensik hat schon entschieden
    if is_scan:
        reasoning.append("PrinterForensics meldet is_scanned_document=True")
        return DocTypeResult(
            doc_type="scan",
            confidence=0.92,
            reasoning=reasoning,
            inputs=inputs,
        )

    # 2) Design-Tool im Producer/Creator -> Marketingmaterial
    m = _matches_any(combined, _DESIGN_TOOLS)
    if m:
        reasoning.append(f"Design-Tool '{m}' im Producer/Creator")
        return DocTypeResult(
            doc_type="design_brochure",
            confidence=0.90,
            reasoning=reasoning,
            inputs=inputs,
        )

    # 3) Office-Tool — Laenge entscheidet Brief vs. Dokument
    m = _matches_any(combined, _OFFICE_TOOLS)
    if m:
        if page_count > 20:
            reasoning.append(f"Office-Tool '{m}' + {page_count} Seiten -> langes Dokument")
            return DocTypeResult(
                doc_type="office_document",
                confidence=0.85,
                reasoning=reasoning,
                inputs=inputs,
            )
        reasoning.append(f"Office-Tool '{m}' + {page_count} Seiten -> Brief/Memo")
        return DocTypeResult(
            doc_type="office_letter",
            confidence=0.85,
            reasoning=reasoning,
            inputs=inputs,
        )

    # 4) AcroForm dominant + kein Office-Match -> Formular
    if has_acroform and page_count <= 10:
        reasoning.append(f"AcroForm + nur {page_count} Seiten -> Formular")
        return DocTypeResult(
            doc_type="form",
            confidence=0.78,
            reasoning=reasoning,
            inputs=inputs,
        )

    # 5) LaTeX/pdfTeX -> Technisches Dokument
    m = _matches_any(combined, _TECHNICAL_TOOLS)
    if m:
        reasoning.append(f"LaTeX-Toolchain '{m}' im Producer")
        return DocTypeResult(
            doc_type="technical_document",
            confidence=0.82,
            reasoning=reasoning,
            inputs=inputs,
        )

    # 6) Online-Konverter — wahrscheinlich aus anderem Format konvertiert
    m = _matches_any(combined, _ONLINE_SERVICES)
    if m:
        reasoning.append(f"Online-Konverter '{m}' — Quellformat unbekannt")
        return DocTypeResult(
            doc_type="online_converted",
            confidence=0.72,
            reasoning=reasoning,
            inputs=inputs,
        )

    # 7) Form als Fallback wenn AcroForm aber alle anderen Indikatoren fehlen
    if has_acroform:
        reasoning.append("AcroForm trotz unbekanntem Producer")
        return DocTypeResult(
            doc_type="form",
            confidence=0.60,
            reasoning=reasoning,
            inputs=inputs,
        )

    # 8) Default
    reasoning.append("Keine eindeutigen Indikatoren — generischer Fallback")
    return DocTypeResult(
        doc_type="unknown",
        confidence=0.30,
        reasoning=reasoning,
        inputs=inputs,
    )
