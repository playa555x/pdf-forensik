"""
Software-Fingerprint: Producer-String → bekanntes Tool identifizieren.
"""
from __future__ import annotations
import re
from typing import Optional

from models.schemas import SoftwareFingerprint, Anomaly, AnomalySeverity
from config import KNOWN_PRODUCERS

_ONLINE_KEYWORDS = {"online", "smallpdf", "ilovepdf", "sejda", "pdf2go", "pdfforge", "pdf24"}
_OCR_KEYWORDS = {"abbyy", "omnipage", "tesseract", "ocr"}
_LIBRARY_KEYWORDS = {"fpdf", "itextsharp", "itext", "pdfsharp", "reportlab", "pikepdf", "pdfium", "pypdf"}


def _extract_version(raw: str) -> Optional[str]:
    m = re.search(r"(\d+[\.\d]+)", raw)
    return m.group(1) if m else None


def _classify_tool(identified: str) -> str:
    lower = identified.lower()
    if any(k in lower for k in _ONLINE_KEYWORDS):
        return "Online-Dienst"
    if any(k in lower for k in _OCR_KEYWORDS):
        return "OCR-Software"
    if any(k in lower for k in _LIBRARY_KEYWORDS):
        return "Programm-Bibliothek"
    if "word" in lower or "libreoffice" in lower or "openoffice" in lower or "indesign" in lower:
        return "Desktop-Anwendung"
    if "ghostscript" in lower or "distiller" in lower or "pdfTeX" in lower or "latex" in lower:
        return "Konverter/Renderer"
    return "PDF-Software"


def analyze_software_fingerprint(
    producer_raw: Optional[str],
    creator_raw: Optional[str],
) -> SoftwareFingerprint:
    anomalies: list[Anomaly] = []

    identified_tool = None
    tool_category = None
    version_hint = None

    for source in [producer_raw or "", creator_raw or ""]:
        if not source:
            continue
        for key, name in KNOWN_PRODUCERS.items():
            if key.lower() in source.lower():
                identified_tool = name
                version_hint = _extract_version(source)
                tool_category = _classify_tool(name)
                break
        if identified_tool:
            break

    # Unbekanntes Tool → INFO
    if not identified_tool:
        if producer_raw or creator_raw:
            identified_tool = producer_raw or creator_raw
            tool_category = "Unbekannt"
            anomalies.append(Anomaly(
                severity=AnomalySeverity.INFO,
                category="software",
                message="Producer/Creator nicht in bekannter Tool-Tabelle gefunden",
                detail=f"Producer: {producer_raw!r} | Creator: {creator_raw!r}",
            ))
        else:
            anomalies.append(Anomaly(
                severity=AnomalySeverity.LOW,
                category="software",
                message="Weder Producer noch Creator im PDF vorhanden",
            ))

    # Mismatch: Creator ≠ Producer (verschiedene Tools)
    if producer_raw and creator_raw and producer_raw != creator_raw:
        prod_id = None
        crea_id = None
        for key, name in KNOWN_PRODUCERS.items():
            if key.lower() in producer_raw.lower():
                prod_id = name
            if key.lower() in creator_raw.lower():
                crea_id = name

        if prod_id and crea_id and prod_id != crea_id:
            anomalies.append(Anomaly(
                severity=AnomalySeverity.INFO,
                category="software",
                message=f"Dokument wurde mit '{crea_id}' erstellt und mit '{prod_id}' konvertiert",
                detail=f"Creator: {creator_raw!r} | Producer: {producer_raw!r}",
            ))

    return SoftwareFingerprint(
        producer_raw=producer_raw,
        creator_raw=creator_raw,
        identified_tool=identified_tool,
        tool_category=tool_category,
        version_hint=version_hint,
        anomalies=anomalies,
    )
