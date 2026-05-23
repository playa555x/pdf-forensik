"""
Linearization Analyzer — Prüft ob PDF für Web-Optimierung linearisiert wurde.
Linearisierte PDFs haben eine spezielle Struktur für "fast web view".
"""

from pathlib import Path
from typing import Dict, Any
import logging
import re

logger = logging.getLogger(__name__)


def analyze_linearization(pdf_path: Path) -> Dict[str, Any]:
    """Analysiert Linearisierungs-Status und -Details."""
    result = {
        "is_linearized": False,
        "linearization_version": None,
        "file_length_declared": None,
        "file_length_actual": None,
        "length_mismatch": False,
        "hint_table_present": False,
        "first_page_obj": None,
        "first_page_end_offset": None,
        "page_count_declared": None,
        "primary_hint_offset": None,
        "primary_hint_length": None,
        "overflow_hint_offset": None,
        "xref_offset": None,
        "details": {},
        "anomalies": [],
    }

    try:
        data = pdf_path.read_bytes()
        result["file_length_actual"] = len(data)

        # Suche nach Linearization-Dictionary in den ersten 4KB
        head = data[:4096].decode("latin-1", errors="replace")

        # Pattern: obj << /Linearized 1 /L ... /H [...] /O ... /E ... /N ... /T ... >>
        # Bounded quantifiers gegen catastrophic backtracking
        lin_match = re.search(
            r'\b(\d{1,7}[\t ]{1,4}\d{1,5}[\t ]{1,4}obj\s{0,10}<<[^>]{0,2000}?/Linearized\s{0,5}[\d.]{1,10}[^>]{0,2000}?>>)',
            head, re.DOTALL
        )

        if lin_match:
            result["is_linearized"] = True
            lin_dict = lin_match.group(1)

            # Version
            ver_match = re.search(r'/Linearized\s+([\d.]+)', lin_dict)
            if ver_match:
                result["linearization_version"] = ver_match.group(1)

            # /L — Gesamtlänge der Datei
            l_match = re.search(r'/L\s+(\d+)', lin_dict)
            if l_match:
                result["file_length_declared"] = int(l_match.group(1))
                if result["file_length_declared"] != result["file_length_actual"]:
                    result["length_mismatch"] = True
                    result["anomalies"].append({
                        "severity": "HIGH",
                        "category": "Linearization",
                        "message": "Deklarierte Dateigröße stimmt nicht mit tatsächlicher überein",
                        "detail": f"Deklariert: {result['file_length_declared']}, Tatsächlich: {result['file_length_actual']} — Datei wurde nach Linearisierung modifiziert",
                    })

            # /O — Objekt-Nr der ersten Seite
            o_match = re.search(r'/O\s+(\d+)', lin_dict)
            if o_match:
                result["first_page_obj"] = int(o_match.group(1))

            # /E — End-Offset der ersten Seite
            e_match = re.search(r'/E\s+(\d+)', lin_dict)
            if e_match:
                result["first_page_end_offset"] = int(e_match.group(1))

            # /N — Seitenanzahl
            n_match = re.search(r'/N\s+(\d+)', lin_dict)
            if n_match:
                result["page_count_declared"] = int(n_match.group(1))

            # /T — XRef Offset
            t_match = re.search(r'/T\s+(\d+)', lin_dict)
            if t_match:
                result["xref_offset"] = int(t_match.group(1))

            # /H — Hint Table [offset length] oder [offset length overflow_offset overflow_length]
            h_match = re.search(r'/H\s*\[\s*(\d+)\s+(\d+)(?:\s+(\d+)\s+(\d+))?\s*\]', lin_dict)
            if h_match:
                result["hint_table_present"] = True
                result["primary_hint_offset"] = int(h_match.group(1))
                result["primary_hint_length"] = int(h_match.group(2))
                if h_match.group(3):
                    result["overflow_hint_offset"] = int(h_match.group(3))

            result["details"] = {
                "linearized_version": result["linearization_version"],
                "file_length": result["file_length_declared"],
                "first_page_object": result["first_page_obj"],
                "first_page_end": result["first_page_end_offset"],
                "pages": result["page_count_declared"],
                "hint_table": result["hint_table_present"],
                "xref_offset": result["xref_offset"],
            }

        else:
            result["is_linearized"] = False

        # Prüfe auf hybride Strukturen
        xref_count = len(re.findall(rb'(?:xref|startxref)', data))
        if xref_count > 2 and result["is_linearized"]:
            result["details"]["xref_sections"] = xref_count
            if xref_count > 4:
                result["anomalies"].append({
                    "severity": "MEDIUM",
                    "category": "Linearization",
                    "message": f"Ungewöhnlich viele XRef-Sektionen ({xref_count}) für linearisiertes PDF",
                    "detail": "Linearisierte PDFs haben normalerweise 2 XRef-Sektionen.",
                })

    except Exception as e:
        logger.error(f"Linearization-Analyse fehlgeschlagen: {e}")
        result["error"] = str(e)

    return result
