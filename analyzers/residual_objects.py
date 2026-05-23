"""
Residual-Objects-Analyzer: Carving verwaister/gelöschter Objekte im PDF-Byte-Stream.

Technik:
1. Alle definierten xref-Einträge einlesen (aktive Objekt-Nummern)
2. Im Raw-Byte-Stream nach "N 0 obj ... endobj"-Mustern suchen
3. Objekte die im Stream vorhanden sind, aber NICHT in xref stehen = verwaist/gelöscht
4. Verwaiste Objekte können gelöschten Text, Metadaten, alte Versionen enthalten

Außerdem:
- Erkennung von "%%EOF" ohne Abschluss-xref (trailing garbage)
- Erkennung von Binärdaten nach dem letzten %%EOF
- Suche nach eingebettetem Content nach %%EOF (Steganographie-Technik)
"""
from __future__ import annotations
import re
from pathlib import Path
from typing import List, Dict, Any, Set, Tuple

import pikepdf

from models.schemas import Anomaly, AnomalySeverity


# Bounded quantifiers verhindern catastrophic backtracking auf binary Streams
# (JPEG/Font-Bytes die zufaellig wie Zahlen/Whitespace aussehen). Vorher
# konnte das bei bestimmten PDFs minutenlang die CPU blockieren.
# - Objekt-Nummern in der Praxis <7-stellig
# - Whitespace zwischen Header-Tokens nur Tab/Space, nicht CR/LF
# - Body-Length cap 500 KB pro Objekt (deckt 99,9% der realen PDFs ab)
_OBJ_PATTERN    = re.compile(rb"(\d{1,7})[\t ]{1,4}0[\t ]{1,4}obj\b(.{0,500000}?)\bendobj", re.DOTALL)
_EOF_PATTERN    = re.compile(rb"%%EOF")
_STREAM_PATTERN = re.compile(rb"\bstream\b(.{0,1000000}?)\bendstream\b", re.DOTALL)

_MAX_CONTENT_PREVIEW = 500  # Byte-Vorschau für verwaiste Objekte


def _get_active_xref_objects(pdf: pikepdf.Pdf) -> Set[int]:
    """Gibt alle aktiven (xref-referenzierten) Objekt-Nummern zurück."""
    active = set()
    try:
        for obj_id in pdf.objects:
            active.add(int(obj_id))
    except Exception:
        pass
    return active


def _find_raw_objects(content: bytes) -> List[Tuple[int, int, bytes]]:
    """
    Findet alle "N 0 obj...endobj"-Muster im Raw-Byte-Stream.
    Gibt (obj_num, byte_offset, raw_content) zurück.
    Begrenzt auf erste 50 Treffer für Performance.
    """
    results = []
    for m in _OBJ_PATTERN.finditer(content):
        try:
            obj_num = int(m.group(1))
            offset  = m.start()
            raw     = m.group(2)[:_MAX_CONTENT_PREVIEW]
            results.append((obj_num, offset, raw))
        except Exception:
            continue
        if len(results) >= 50:
            break
    return results


def _classify_obj_content(raw: bytes) -> Dict[str, Any]:
    """Klassifiziert den Inhalt eines verwaisten Objekts."""
    raw_str = raw.decode("latin-1", errors="replace")
    info = {
        "preview":      raw_str[:200].strip(),
        "has_text":     bool(re.search(r"/Type\s*/Page|BT\s|Tj\s|TJ\s", raw_str)),
        "has_metadata": bool(re.search(r"/Author|/Title|/Creator|/Producer", raw_str, re.IGNORECASE)),
        "has_js":       bool(re.search(r"/JavaScript|/JS\s", raw_str, re.IGNORECASE)),
        "has_url":      bool(re.search(r"https?://|/URI\s", raw_str, re.IGNORECASE)),
        "has_stream":   b"stream" in raw,
        "type_hint":    None,
    }
    # Typ-Erkennung
    if "/Page" in raw_str:
        info["type_hint"] = "Page"
    elif "/Metadata" in raw_str or "/Author" in raw_str:
        info["type_hint"] = "Metadata"
    elif "/EmbeddedFile" in raw_str:
        info["type_hint"] = "EmbeddedFile"
    elif "/JavaScript" in raw_str:
        info["type_hint"] = "JavaScript"
    elif "/Font" in raw_str:
        info["type_hint"] = "Font"
    elif "/XObject" in raw_str:
        info["type_hint"] = "XObject"
    return info


def _find_trailing_data(content: bytes) -> Dict[str, Any]:
    """
    Sucht nach Daten nach dem letzten %%EOF-Marker.
    Trailing data nach %%EOF = Auffüllung, Steganographie oder Manipulations-Artefakt.
    """
    eof_positions = [m.start() for m in _EOF_PATTERN.finditer(content)]
    if not eof_positions:
        return {"found": False, "note": "Kein %%EOF gefunden — kein gültiges PDF?"}

    last_eof = eof_positions[-1]
    trailing = content[last_eof + 5:]  # Nach "%%EOF"
    trailing = trailing.strip()

    if len(trailing) == 0:
        return {"found": False, "last_eof_offset": last_eof, "note": "Kein Trailing Data"}

    # Prüfen ob es nur Whitespace/CR/LF ist
    if trailing.strip(b"\r\n \t") == b"":
        return {"found": False, "last_eof_offset": last_eof, "note": "Nur Leerzeichen nach %%EOF"}

    return {
        "found":           True,
        "last_eof_offset": last_eof,
        "trailing_bytes":  len(trailing),
        "preview_hex":     trailing[:64].hex(),
        "preview_text":    trailing[:64].decode("latin-1", errors="replace"),
        "note":            f"{len(trailing)} Bytes nach dem letzten %%EOF",
    }


def _find_multiple_eof(content: bytes) -> Dict[str, Any]:
    """Erkennt mehrere %%EOF-Marker (Indiz für Incremental Updates oder Manipulation)."""
    positions = [m.start() for m in _EOF_PATTERN.finditer(content)]
    return {
        "count":     len(positions),
        "offsets":   positions[:10],
        "note":      f"{len(positions)} %%EOF-Marker gefunden" if len(positions) > 1 else "Einfaches EOF",
    }


def analyze_residual_objects(pdf_path: Path) -> Dict[str, Any]:
    """Hauptfunktion: Carving verwaister Objekte + Trailing-Data-Analyse."""
    anomalies: List[Anomaly] = []

    try:
        pdf = pikepdf.open(pdf_path)
        active_objs = _get_active_xref_objects(pdf)
        pdf.close()
    except Exception as e:
        return {
            "orphaned_count":   0,
            "orphaned_objects": [],
            "trailing_data":    {},
            "eof_info":         {},
            "anomalies": [Anomaly(
                severity=AnomalySeverity.HIGH,
                category="residual_objects",
                message="PDF konnte nicht für Residual-Object-Analyse geöffnet werden",
                detail=str(e),
            )],
        }

    try:
        with open(pdf_path, "rb") as f:
            content = f.read()
    except Exception as e:
        return {
            "orphaned_count":   0,
            "orphaned_objects": [],
            "trailing_data":    {},
            "eof_info":         {},
            "anomalies": [Anomaly(
                severity=AnomalySeverity.HIGH,
                category="residual_objects",
                message="PDF-Datei konnte nicht gelesen werden",
                detail=str(e),
            )],
        }

    raw_objects = _find_raw_objects(content)
    trailing    = _find_trailing_data(content)
    eof_info    = _find_multiple_eof(content)

    # Verwaiste Objekte = im Raw-Stream vorhanden, aber nicht in aktiver xref
    orphaned = []
    for (obj_num, offset, raw) in raw_objects:
        if obj_num not in active_objs:
            classification = _classify_obj_content(raw)
            orphaned.append({
                "obj_num":  obj_num,
                "offset":   offset,
                "content":  classification,
            })

    # Anomalien
    high_risk_orphans = [o for o in orphaned if o["content"].get("has_js") or
                         o["content"].get("type_hint") in ("JavaScript", "EmbeddedFile")]
    if high_risk_orphans:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.HIGH,
            category="residual_objects",
            message=f"{len(high_risk_orphans)} verwaiste Objekte mit JavaScript/EmbeddedFile",
            detail=f"Objekt-IDs: {', '.join(str(o['obj_num']) for o in high_risk_orphans[:5])}",
        ))

    metadata_orphans = [o for o in orphaned if o["content"].get("has_metadata")]
    if metadata_orphans:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category="residual_objects",
            message=f"{len(metadata_orphans)} verwaiste Objekte mit Metadaten-Inhalten",
            detail="Können gelöschte Autorenangaben, Titel etc. enthalten",
        ))

    if orphaned:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.LOW,
            category="residual_objects",
            message=f"{len(orphaned)} verwaiste Objekte gefunden (nicht in xref referenziert)",
            detail="Können Überreste gelöschter oder ersetzter Inhalte sein",
        ))

    if trailing.get("found"):
        sev = AnomalySeverity.HIGH if trailing["trailing_bytes"] > 1000 else AnomalySeverity.MEDIUM
        anomalies.append(Anomaly(
            severity=sev,
            category="residual_objects",
            message=f"Trailing Data nach %%EOF: {trailing['trailing_bytes']} Bytes",
            detail=trailing.get("note", ""),
        ))

    if eof_info["count"] > 2:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.INFO,
            category="residual_objects",
            message=f"Mehrere %%EOF-Marker: {eof_info['count']} (normal bei Incremental Updates)",
            detail=f"Offsets: {eof_info['offsets'][:5]}",
        ))

    return {
        "orphaned_count":   len(orphaned),
        "orphaned_objects": orphaned,
        "trailing_data":    trailing,
        "eof_info":         eof_info,
        "anomalies":        anomalies,
    }
