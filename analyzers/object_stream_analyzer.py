"""
Object-Stream-Analyzer: Dekomprimiert und analysiert alle ObjStm-Objekte im PDF.

ObjStm (Object Streams, PDF 1.5+) können komprimierte Objekte enthalten,
die von einfachen Viewern und forensischen Tools oft übersehen werden.
Sie sind ein bekannter Ort für:
- Versteckte /Info-Dictionaries
- Doppelte Objekt-Definitionen (Shadow-Technik)
- Verschleierte JavaScript-Objekte
- Versteckte Formulare / Widgets

Zusätzlich wird der xref-Stream analysiert (PDF 1.5+ Cross-Reference-Streams).
"""
from __future__ import annotations
import re
from pathlib import Path
from typing import List, Dict, Any, Set

import pikepdf

from models.schemas import Anomaly, AnomalySeverity


# Verdächtige Schlüssel innerhalb von ObjStm-Objekten
_SUSPICIOUS_KEYS = {
    "/JavaScript", "/JS", "/Launch", "/EmbeddedFile", "/RichMedia",
    "/OpenAction", "/AA", "/URI", "/SubmitForm", "/ImportData",
    "/SetOCGState", "/Sound", "/Movie", "/Hide", "/GoToE",
}

# Bekannte harmlose Objekt-Typen
_HARMLESS_TYPES = {"/Font", "/XObject", "/ExtGState", "/ColorSpace", "/Pattern", "/Shading"}


def _flatten_obj(obj) -> Dict[str, Any]:
    """Konvertiert ein pikepdf-Objekt in ein serialisierbares Dict."""
    result = {}
    try:
        if isinstance(obj, pikepdf.Dictionary):
            for k in obj.keys():
                try:
                    v = obj[k]
                    if isinstance(v, (pikepdf.Dictionary, pikepdf.Array)):
                        result[str(k)] = str(v)
                    else:
                        result[str(k)] = str(v)
                except Exception:
                    result[str(k)] = "<unlesbar>"
        elif isinstance(obj, pikepdf.Array):
            result["_array"] = [str(i) for i in obj]
        else:
            result["_value"] = str(obj)
    except Exception:
        result["_error"] = "Nicht serialisierbar"
    return result


def _analyze_object_stream(pdf: pikepdf.Pdf, obj_id: int) -> Dict[str, Any]:
    """Analysiert einen einzelnen ObjStm."""
    result = {
        "obj_id":         obj_id,
        "sub_objects":    [],
        "suspicious_keys": [],
        "has_info_dict":  False,
        "has_javascript": False,
    }
    try:
        obj = pdf.get_object((obj_id, 0))
        if not isinstance(obj, pikepdf.Dictionary):
            return result

        obj_type = str(obj.get("/Type", ""))
        if obj_type != "/ObjStm":
            return result

        # N = Anzahl der enthaltenen Objekte
        n = int(obj.get("/N", 0))
        result["n_objects"] = n

        # Rohdaten des Streams lesen
        try:
            raw = obj.read_bytes()
            stream_text = raw.decode("latin-1", errors="replace")
            result["stream_length"] = len(raw)

            # Nach verdächtigen Schlüsselwörtern suchen
            for key in _SUSPICIOUS_KEYS:
                if key.lower() in stream_text.lower():
                    result["suspicious_keys"].append(key)

            if "/Info" in stream_text or "/Title" in stream_text or "/Author" in stream_text:
                result["has_info_dict"] = True

            if "/JavaScript" in stream_text or "/JS" in stream_text:
                result["has_javascript"] = True

        except Exception as e:
            result["stream_error"] = str(e)

    except Exception as e:
        result["error"] = str(e)

    return result


def _find_all_obj_streams(pdf: pikepdf.Pdf) -> List[int]:
    """Findet alle ObjStm-Objekte im PDF."""
    obj_stream_ids = []
    try:
        for obj_id in pdf.objects:
            try:
                obj = pdf.get_object((obj_id, 0))
                if isinstance(obj, pikepdf.Dictionary):
                    if str(obj.get("/Type", "")) == "/ObjStm":
                        obj_stream_ids.append(obj_id)
            except Exception:
                continue
    except Exception:
        pass
    return obj_stream_ids


def _check_xref_stream(pdf_path: Path) -> Dict[str, Any]:
    """Prüft ob PDF einen Cross-Reference-Stream (PDF 1.5+) statt xref-Tabelle verwendet."""
    result = {
        "has_xref_stream":   False,
        "has_hybrid_xref":   False,
        "linearized":        False,
        "note":              "",
    }
    try:
        with open(pdf_path, "rb") as f:
            content = f.read(2048)  # Nur Header scannen
            content_str = content.decode("latin-1", errors="replace")

        if b"xref" in content[:512]:
            result["note"] = "Traditionelle xref-Tabelle"
        else:
            # Kein xref am Start → wahrscheinlich xref-Stream
            result["has_xref_stream"] = True
            result["note"] = "PDF verwendet Cross-Reference-Streams (PDF 1.5+)"

        # Hybrid-xref (beides)
        if b"xref" in content and b"/XRef" in content:
            result["has_hybrid_xref"] = True
            result["note"] = "Hybrid xref — traditionelle Tabelle + XRef-Stream (Manipulations-Risiko)"

        if b"/Linearized" in content:
            result["linearized"] = True

    except Exception as e:
        result["error"] = str(e)

    return result


def _check_duplicate_object_numbers(pdf_path: Path) -> List[Dict[str, Any]]:
    """
    Sucht nach mehrfach definierten Objekt-Nummern im raw PDF-Byte-Stream.
    Eine Objekt-Nummer die mehrfach vorkommt = mögliche Shadow-Technik.
    """
    duplicates = []
    try:
        with open(pdf_path, "rb") as f:
            content = f.read()

        # Muster: "N 0 obj" (Objekt-Nummer N, Generation 0)
        # Bounded quantifiers verhindern catastrophic backtracking auf binary
        # Streams (JPEG/PNG-Bilder etc.). Vorher konnte \d+\s+0\s+obj bei
        # bestimmten PDFs minutenlang die CPU blockieren (engineless run_pipeline).
        # Objekt-Nummern sind in der Praxis <7-stellig, Whitespace nur Tab/Space.
        pattern = re.compile(rb"\b(\d{1,7})[\t ]{1,4}0[\t ]{1,4}obj\b")
        matches = pattern.findall(content)

        counts: Dict[int, int] = {}
        for m in matches:
            num = int(m)
            counts[num] = counts.get(num, 0) + 1

        for obj_num, count in counts.items():
            if count > 1:
                duplicates.append({
                    "obj_num":     obj_num,
                    "occurrences": count,
                    "note":        f"Objekt {obj_num} ist {count}x definiert — mögliche Shadow/Override-Technik",
                })

    except Exception as e:
        duplicates.append({"error": str(e)})

    return duplicates


def analyze_object_streams(pdf_path: Path) -> Dict[str, Any]:
    """Hauptfunktion: Analysiert alle ObjStm-Objekte und xref-Struktur."""
    anomalies: List[Anomaly] = []

    try:
        pdf = pikepdf.open(pdf_path)
    except Exception as e:
        return {
            "obj_stream_count": 0,
            "obj_streams":      [],
            "xref_info":        {},
            "duplicate_objs":   [],
            "anomalies": [Anomaly(
                severity=AnomalySeverity.HIGH,
                category="object_streams",
                message="PDF konnte nicht für ObjStm-Analyse geöffnet werden",
                detail=str(e),
            )],
        }

    with pdf:
        obj_stream_ids = _find_all_obj_streams(pdf)
        stream_results = [_analyze_object_stream(pdf, oid) for oid in obj_stream_ids]

    xref_info     = _check_xref_stream(pdf_path)
    duplicate_objs = _check_duplicate_object_numbers(pdf_path)

    # Anomalien
    suspicious_streams = [s for s in stream_results if s.get("suspicious_keys") or s.get("has_javascript")]
    if suspicious_streams:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.HIGH,
            category="object_streams",
            message=f"{len(suspicious_streams)} ObjStm mit verdächtigen Inhalten",
            detail=f"Verdächtige Keys: {', '.join(k for s in suspicious_streams for k in s.get('suspicious_keys', [])[:3])}",
        ))

    info_streams = [s for s in stream_results if s.get("has_info_dict")]
    if info_streams:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category="object_streams",
            message=f"{len(info_streams)} ObjStm enthält /Info-ähnliche Metadaten",
            detail="Metadaten in Object Streams können von simplen Analyzern übersehen werden",
        ))

    if duplicate_objs:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.HIGH,
            category="object_streams",
            message=f"{len(duplicate_objs)} doppelt definierte Objekt-Nummer(n) gefunden",
            detail="; ".join(d.get("note", "") for d in duplicate_objs[:3]),
        ))

    if xref_info.get("has_hybrid_xref"):
        anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category="object_streams",
            message="Hybrid xref-Struktur — traditionell + Stream (PDF 1.5-Manipulations-Technik)",
            detail=xref_info.get("note", ""),
        ))

    return {
        "obj_stream_count": len(stream_results),
        "obj_streams":      stream_results,
        "xref_info":        xref_info,
        "duplicate_objs":   duplicate_objs,
        "anomalies":        anomalies,
    }
