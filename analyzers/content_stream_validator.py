"""
Content Stream Operator Validation.

Validiert PDF-Content-Stream-Operatoren nach ISO 32000:
1. Erkennt ungültige/unbekannte Operatoren
2. Identifiziert verdächtige Muster (z.B. Stack-Manipulation)
3. Statistik über Operator-Verwendung
"""
from __future__ import annotations
import re
from pathlib import Path
from typing import List, Dict, Any

from models.schemas import Anomaly, AnomalySeverity, ContentStreamResult

try:
    import pikepdf
    PIKE_OK = True
except ImportError:
    PIKE_OK = False


# Alle gültigen PDF-Operatoren (ISO 32000-1:2008)
VALID_OPERATORS = {
    # General graphics state
    "w", "J", "j", "M", "d", "ri", "i", "gs",
    # Special graphics state
    "q", "Q", "cm",
    # Path construction
    "m", "l", "c", "v", "y", "h", "re",
    # Path painting
    "S", "s", "f", "F", "f*", "B", "B*", "b", "b*", "n",
    # Clipping paths
    "W", "W*",
    # Text objects
    "BT", "ET",
    # Text state
    "Tc", "Tw", "Tz", "TL", "Tf", "Tr", "Ts",
    # Text positioning
    "Td", "TD", "Tm", "T*",
    # Text showing
    "Tj", "TJ", "'", '"',
    # Type 3 fonts
    "d0", "d1",
    # Color
    "CS", "cs", "SC", "SCN", "sc", "scn", "G", "g", "RG", "rg", "K", "k",
    # Shading
    "sh",
    # External objects
    "Do",
    # Inline images
    "BI", "ID", "EI",
    # XObject
    # Marked content
    "MP", "DP", "BMC", "BDC", "EMC",
    # Compatibility
    "BX", "EX",
}

# Verdächtige Muster
SUSPICIOUS_PATTERNS = [
    (re.compile(rb'(?:q\s+){10,}'), "Excessive q (save-state) — Stack-Overflow-Versuch"),
    (re.compile(rb'(?:Q\s+){10,}'), "Excessive Q (restore-state) — Stack-Underflow-Versuch"),
    (re.compile(rb'/JavaScript\s'), "JavaScript-Referenz im Content-Stream"),
    (re.compile(rb'/Launch\s'), "Launch-Action im Content-Stream"),
    (re.compile(rb'/URI\s'), "URI-Action im Content-Stream"),
    (re.compile(rb'/GoTo\w*\s'), "GoTo-Action im Content-Stream"),
    (re.compile(rb'\\x[0-9a-fA-F]{2}'), "Hex-Escape-Sequenzen"),
]


def _extract_operators(content: bytes) -> List[str]:
    """Extrahiert Operatoren aus einem Content-Stream."""
    text = content.decode("latin-1", errors="replace")

    # Operatoren sind Wörter die nicht mit / oder ( anfangen und nicht numerisch sind
    # Vereinfachte Extraktion: Alles was nach einem Zeilenende oder Leerzeichen kommt
    # und aus Buchstaben besteht
    operators = []
    # Regex für Operatoren (alphabetische Token die keine Argumente sind)
    tokens = re.findall(r'(?:^|\s)([a-zA-Z\*\'\"]{1,4})(?:\s|$)', text)

    for t in tokens:
        # Filtere offensichtliche Nicht-Operatoren
        if t in VALID_OPERATORS:
            operators.append(t)
        elif len(t) <= 3 and t.isalpha():
            operators.append(t)  # Möglicherweise ungültig

    return operators


def analyze_content_streams(pdf_path: Path) -> ContentStreamResult:
    """Validiert Content-Stream-Operatoren im PDF."""
    anomalies: List[Anomaly] = []
    pages_checked = 0
    invalid_operators: List[Dict[str, Any]] = []
    suspicious_patterns: List[Dict[str, Any]] = []
    operator_stats: Dict[str, int] = {}

    if not PIKE_OK:
        return ContentStreamResult(
            anomalies=[Anomaly(
                severity=AnomalySeverity.INFO,
                category="content_stream",
                message="pikepdf nicht verfügbar — Content-Stream-Validierung übersprungen",
            )]
        )

    try:
        pdf = pikepdf.open(pdf_path, allow_overwriting_input=True)

        for page_num, page in enumerate(pdf.pages, 1):
            pages_checked += 1

            try:
                contents = page.get("/Contents")
                if not contents:
                    continue

                # Content zusammenbauen
                if isinstance(contents, pikepdf.Array):
                    raw_parts = []
                    for cs in contents:
                        try:
                            raw_parts.append(bytes(cs.read_bytes()))
                        except Exception:
                            pass
                    raw = b"".join(raw_parts)
                else:
                    try:
                        raw = bytes(contents.read_bytes())
                    except Exception:
                        continue

                # Operatoren extrahieren
                ops = _extract_operators(raw)
                for op in ops:
                    operator_stats[op] = operator_stats.get(op, 0) + 1

                # Ungültige Operatoren finden
                for op in ops:
                    if op not in VALID_OPERATORS and len(op) <= 3:
                        invalid_operators.append({
                            "page": page_num,
                            "operator": op,
                        })

                # Verdächtige Muster
                for pattern, desc in SUSPICIOUS_PATTERNS:
                    matches = pattern.findall(raw[:100_000])
                    if matches:
                        suspicious_patterns.append({
                            "page": page_num,
                            "pattern": desc,
                            "count": len(matches),
                        })

                # BT/ET Balance prüfen
                bt_count = raw.count(b"BT")
                et_count = raw.count(b"ET")
                if bt_count != et_count:
                    suspicious_patterns.append({
                        "page": page_num,
                        "pattern": f"BT/ET-Unbalance: {bt_count} BT vs {et_count} ET",
                        "count": 1,
                    })

                # q/Q Balance prüfen
                q_save = len(re.findall(rb'\bq\b', raw))
                q_restore = len(re.findall(rb'\bQ\b', raw))
                if abs(q_save - q_restore) > 2:
                    suspicious_patterns.append({
                        "page": page_num,
                        "pattern": f"q/Q-Unbalance: {q_save} q vs {q_restore} Q",
                        "count": 1,
                    })

            except Exception:
                continue

        pdf.close()

    except Exception as e:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category="content_stream",
            message=f"Content-Stream-Analyse-Fehler: {str(e)[:100]}",
        ))

    # Anomalien generieren
    unique_invalid = list({inv["operator"] for inv in invalid_operators})
    if unique_invalid:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category="content_stream",
            message=f"{len(unique_invalid)} ungültige Operatoren: {', '.join(unique_invalid[:10])}",
            detail="Ungültige Operatoren können auf manipulierte Streams oder spezifische Software hinweisen",
        ))

    for sp in suspicious_patterns:
        sev = AnomalySeverity.HIGH if "JavaScript" in sp["pattern"] or "Launch" in sp["pattern"] else AnomalySeverity.MEDIUM
        anomalies.append(Anomaly(
            severity=sev,
            category="content_stream",
            message=f"Seite {sp['page']}: {sp['pattern']}",
        ))

    return ContentStreamResult(
        pages_checked=pages_checked,
        invalid_operators=invalid_operators[:50],
        suspicious_patterns=suspicious_patterns[:20],
        operator_stats=dict(sorted(operator_stats.items(), key=lambda x: -x[1])[:30]),
        anomalies=anomalies,
    )
