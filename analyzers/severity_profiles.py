"""
Severity-Profile pro Dokumenttyp.

Hintergrund:
Viele Befunde sind in bestimmten Dokumenttypen *erwartet* und KEIN
Manipulationshinweis. Beispiele:

- OCR-Text-Mismatch in einer CorelDRAW-Broschuere -> OCR scheitert an
  stylized text. Kein Manipulationsverdacht.
- "Layer 1" OCG-Layer in einer Broschuere -> Default-Layer-Name von
  CorelDRAW, nichts versteckt.
- Wiederholtes Bild ("signature_reuse" per phash) auf vielen Seiten ->
  Logo/Fusszeile, keine missbraeuchte Signatur.

Diese Heuristiken wurden vorher pauschal als HIGH gewertet -> jede Broschuere
landete auf "100/100 Manipulations-Score". Mit Doc-Typ-bewussten Downgrades
landen sie auf INFO/LOW, der Score bleibt vernuenftig.

Wichtig: HARD_HIGH_CATEGORIES sind echte Security-Befunde, die NIE
heruntergesetzt werden — egal in welchem Dokumenttyp.
"""
from __future__ import annotations
from typing import Optional, Tuple

from models.schemas import Anomaly, AnomalySeverity


# Hard-HIGH: NIE durch Doc-Typ-Profile downgraden.
# Diese Befunde sind echte Sicherheitsindikatoren — auch in einer harmlosen
# Marketingbroschuere sind sie HIGH.
HARD_HIGH_CATEGORIES = frozenset({
    "javascript",      # /JS, /OpenAction, /Launch — Auto-Execute
    "shadow_attack",   # Signature Shadow Attack (Wiener Krypto-Bug)
    "yara",            # YARA-Regel matched (Malware-Signature)
    "virus_scan",      # ClamAV oder VirusTotal Treffer
    "malware",         # generic malware
    "embedded_executable",  # .exe/.dll/.bat in PDF
    "redaction",       # bypassable Schwaerzung (sensible Daten extrahierbar)
})


# Downgrade-Regeln pro Doc-Typ.
# Format:  doc_type -> [(category, keyword_or_None, new_severity), ...]
# - keyword=None  matcht alle Anomalien dieser Kategorie
# - keyword=str   matcht nur wenn das keyword (case-insensitive) in
#                 message+detail vorkommt
# Reihenfolge: erste passende Regel gewinnt.
_DOWNGRADE_RULES: dict[str, list[Tuple[str, Optional[str], AnomalySeverity]]] = {
    "design_brochure": [
        # OCR scheitert bei stylized text — erwartbar
        ("ocr_text_mismatch",         None,      AnomalySeverity.INFO),
        ("ocr_text_partial_mismatch", None,      AnomalySeverity.INFO),
        ("trocr_duplicate_text",      None,      AnomalySeverity.INFO),
        # "signature_reuse" via phash auf eine Broschuere = wiederholtes Logo
        ("signature_reuse",           "phash",   AnomalySeverity.INFO),
        ("signature_reuse",           "logo",    AnomalySeverity.INFO),
        ("signature",                 "phash",   AnomalySeverity.INFO),
        # CorelDRAW-Standard-Layer
        ("ocg_layers",                "Layer 1", AnomalySeverity.INFO),
        ("ocg",                       "Layer 1", AnomalySeverity.INFO),
        # JPEG-Mixed-Quality entsteht bei Broschueren-Aggregation von Fotos
        ("splicing_jpeg_ghost",       None,      AnomalySeverity.LOW),
        ("deep_jpeg",                 "mixed",   AnomalySeverity.LOW),
        # Design-Software laesst mehr verwaiste Objekte zurueck
        ("residual_objects",          None,      AnomalySeverity.LOW),
        ("annot_orphan",              None,      AnomalySeverity.LOW),
        # Hybrid-XRef ist seit PDF 1.5 normal — nicht verdaechtig
        ("xref",                      "Hybrid",  AnomalySeverity.INFO),
        ("xref_validation",           "Hybrid",  AnomalySeverity.INFO),
        # pdfid-Keyword /JS in XFA-Schema ist kein echtes JavaScript
        # (NICHT generell pdfid_keyword runter — nur wenn der eigentliche
        #  javascript-Analyzer KEINEN echten JS-Befund hat. Das pruefen wir
        #  konservativ ueber keyword "/JS")
        # (Bewusst NICHT in HARD_HIGH-Liste, weil das keyword "javascript" ist)
    ],
    "scan": [
        # Scans haben keinen echten Embedding-Text-Layer -> Mismatch ist normal
        ("ocr_text_mismatch",         None, AnomalySeverity.LOW),
        ("ocr_text_partial_mismatch", None, AnomalySeverity.LOW),
        # Scans haben keine echten Fonts
        ("font_forensics",            None, AnomalySeverity.INFO),
        # Yellow Dots sind in gedrucktem Scan-Output normal
        ("yellow_dots",               None, AnomalySeverity.INFO),
        # Printer-Forensik meldet "Scan" — das wussten wir schon
        ("printer_forensics",         None, AnomalySeverity.LOW),
    ],
    "form": [
        # Form-spezifisches: AcroForm vorhanden = das ist der Zweck
        ("acroform",                  None, AnomalySeverity.INFO),
        # JS in Form ist haeufig Field-Validation -> nicht gleich HIGH
        # (NICHT der "javascript"-Auto-Execute, das ist HARD_HIGH)
    ],
    "technical_document": [
        # LaTeX baut viele Fonts ein -> Font-Auffaelligkeiten sind technisch
        ("font_forensics",            "Subset", AnomalySeverity.LOW),
    ],
    "online_converted": [
        # Online-Konverter erzeugen oft "Hybrid-XRef" und "Residual-Objects"
        ("xref",                      "Hybrid", AnomalySeverity.LOW),
        ("residual_objects",          None,     AnomalySeverity.LOW),
    ],
    # office_letter / office_document / unknown -> keine Downgrades (Baseline)
}


_SEVERITY_RANK = {
    AnomalySeverity.INFO:   0,
    AnomalySeverity.LOW:    1,
    AnomalySeverity.MEDIUM: 2,
    AnomalySeverity.HIGH:   3,
}


def _rank(sev: AnomalySeverity) -> int:
    return _SEVERITY_RANK.get(sev, 0)


def is_hard_high(anomaly: Anomaly) -> bool:
    """Echter Security-Befund? Wird nie heruntergesetzt."""
    return anomaly.category in HARD_HIGH_CATEGORIES


def apply_doc_type_profile(
    anomalies: list[Anomaly],
    doc_type: Optional[str],
) -> list[Anomaly]:
    """
    Wendet die Doc-Typ-spezifischen Downgrades an. Liefert eine NEUE Liste —
    die Originalanomalien bleiben unveraendert (Pydantic-Modelle sind frozen
    in pydantic v2 sowieso de-facto immutable).

    - Hard-HIGH-Kategorien werden nie downgegraded.
    - Pro Anomalie wird die erste passende Regel angewendet.
    - Eine Regel kann nur NACH UNTEN downgraden (nie aufwerten).
    - Im detail-Text wird vermerkt, warum heruntergesetzt wurde.
    """
    if not doc_type or doc_type not in _DOWNGRADE_RULES:
        return list(anomalies)

    rules = _DOWNGRADE_RULES[doc_type]
    out: list[Anomaly] = []

    for a in anomalies:
        if is_hard_high(a):
            out.append(a)
            continue

        new_sev: Optional[AnomalySeverity] = None
        for cat, kw, target_sev in rules:
            if a.category != cat:
                continue
            if kw is None:
                new_sev = target_sev
                break
            hay = f"{a.message or ''} {a.detail or ''}".lower()
            if kw.lower() in hay:
                new_sev = target_sev
                break

        if new_sev is not None and _rank(new_sev) < _rank(a.severity):
            note = (
                f"  [Doc-Typ '{doc_type}': Severity heruntergesetzt von "
                f"{a.severity.value} -> {new_sev.value}, "
                f"da dieser Befund fuer diesen Dokumenttyp typisch/erwartet ist.]"
            )
            out.append(Anomaly(
                severity=new_sev,
                category=a.category,
                message=a.message,
                detail=((a.detail or "") + note).strip(),
            ))
        else:
            out.append(a)

    return out


def count_by_class(anomalies: list[Anomaly]) -> dict:
    """
    Zaehlt Anomalien aufgeteilt nach Hard-HIGH / Soft-HIGH / MEDIUM / LOW / INFO.

    Returns dict mit Keys: hard_high, soft_high, medium, low, info, total_high
    """
    hh = sh = m = l = i = 0
    for a in anomalies:
        if a.severity == AnomalySeverity.HIGH:
            if is_hard_high(a):
                hh += 1
            else:
                sh += 1
        elif a.severity == AnomalySeverity.MEDIUM:
            m += 1
        elif a.severity == AnomalySeverity.LOW:
            l += 1
        elif a.severity == AnomalySeverity.INFO:
            i += 1
    return {
        "hard_high":  hh,
        "soft_high":  sh,
        "medium":     m,
        "low":        l,
        "info":       i,
        "total_high": hh + sh,
    }
