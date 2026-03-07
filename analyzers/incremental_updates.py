"""
Incremental Updates Analyzer.
Erkennt mehrfache PDF-Revisionen via %%EOF-Scan.
Incremental Updates sind die häufigste Methode zur PDF-Manipulation:
Originaldokument bleibt erhalten, neue Version wird angehängt.
"""
from __future__ import annotations
from pathlib import Path
from typing import List, Dict, Any

from models.schemas import IncrementalUpdatesResult, Anomaly, AnomalySeverity

_EOF_MARKER  = b"%%EOF"
_XREF_MARKER = b"xref"
_STARTXREF   = b"startxref"


def analyze_incremental_updates(pdf_path: Path) -> IncrementalUpdatesResult:
    anomalies: list[Anomaly] = []

    try:
        data = pdf_path.read_bytes()
    except Exception as e:
        return IncrementalUpdatesResult(anomalies=[
            Anomaly(severity=AnomalySeverity.HIGH, category="incremental_updates",
                    message="Datei konnte nicht gelesen werden", detail=str(e))
        ])

    # Alle %%EOF-Positionen finden
    eof_positions: List[int] = []
    pos = 0
    while True:
        idx = data.find(_EOF_MARKER, pos)
        if idx == -1:
            break
        eof_positions.append(idx)
        pos = idx + len(_EOF_MARKER)

    revision_count = len(eof_positions)

    # Revisionen analysieren
    revisions: List[Dict[str, Any]] = []
    prev_end = 0

    for i, eof_pos in enumerate(eof_positions):
        revision_end   = eof_pos + len(_EOF_MARKER)
        revision_start = prev_end
        revision_size  = revision_end - revision_start

        # startxref-Wert dieser Revision finden
        segment = data[revision_start:revision_end]
        xref_offset = None
        sx_idx = segment.rfind(_STARTXREF)
        if sx_idx != -1:
            try:
                after = segment[sx_idx + len(_STARTXREF):].strip()
                xref_offset = int(after.split()[0])
            except Exception:
                pass

        # Xref-Typ: klassisch oder Stream?
        xref_type = "unbekannt"
        if xref_offset is not None:
            try:
                obj_start = data[revision_start + xref_offset: revision_start + xref_offset + 20]
                if obj_start.lstrip().startswith(b"xref"):
                    xref_type = "klassische Tabelle"
                else:
                    xref_type = "xref-Stream (komprimiert)"
            except Exception:
                pass

        # Neues Objekte zählen (grob via "obj" + "endobj")
        obj_count = segment.count(b" obj\n") + segment.count(b" obj\r")

        revisions.append({
            "revision":    i + 1,
            "start_byte":  revision_start,
            "end_byte":    revision_end,
            "size_bytes":  revision_size,
            "xref_offset": xref_offset,
            "xref_type":   xref_type,
            "obj_count":   obj_count,
        })

        prev_end = revision_end

    # Bytes nach letztem %%EOF (verdächtig)
    trailing_bytes = len(data) - eof_positions[-1] - len(_EOF_MARKER) if eof_positions else 0
    has_trailing_data = trailing_bytes > 20  # > 20 Bytes = verdächtig

    # Anomalien
    if revision_count > 1:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.HIGH,
            category="incremental_updates",
            message=f"Dokument enthält {revision_count} Revisionen — Inhalt wurde nach Erstellung verändert",
            detail=f"Revisions-Größen: {[r['size_bytes'] for r in revisions]} Bytes",
        ))

        # Wenn letzte Revision sehr klein ist → wahrscheinlich nur Metadaten geändert
        if revisions[-1]["size_bytes"] < 1024:
            anomalies.append(Anomaly(
                severity=AnomalySeverity.MEDIUM,
                category="incremental_updates",
                message="Letzte Revision sehr klein (<1KB) — könnte nur Metadaten-Änderung sein",
                detail=f"Größe: {revisions[-1]['size_bytes']} Bytes",
            ))

    if has_trailing_data:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category="incremental_updates",
            message=f"{trailing_bytes} Bytes Daten nach letztem %%EOF — versteckte Daten möglich",
        ))

    return IncrementalUpdatesResult(
        revision_count=revision_count,
        revisions=revisions,
        has_trailing_data=has_trailing_data,
        trailing_bytes=trailing_bytes,
        anomalies=anomalies,
    )
