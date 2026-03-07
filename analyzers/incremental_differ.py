"""
Incremental Update Diffing.

Zeigt konkret was sich zwischen PDF-Revisionen geändert hat:
1. Findet alle %%EOF Marker (= Revisionsgrenzen)
2. Extrahiert Objekte pro Revision
3. Vergleicht Objekte zwischen Revisionen
4. Identifiziert hinzugefügte, geänderte, gelöschte Objekte
"""
from __future__ import annotations
import re
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Set, Tuple

from models.schemas import Anomaly, AnomalySeverity, IncrementalDiffResult

try:
    import pikepdf
    PIKE_OK = True
except ImportError:
    PIKE_OK = False


def _find_eof_markers(content: bytes) -> List[int]:
    """Findet alle %%EOF Positionen im PDF."""
    positions = []
    pos = 0
    while True:
        idx = content.find(b"%%EOF", pos)
        if idx == -1:
            break
        positions.append(idx)
        pos = idx + 5
    return positions


def _extract_obj_ids_from_xref(content: bytes, xref_pos: int) -> Set[int]:
    """Extrahiert Objekt-IDs aus einer XRef-Tabelle ab xref_pos."""
    obj_ids = set()
    chunk = content[xref_pos:xref_pos + 50_000].decode("latin-1", errors="replace")
    lines = chunk.split("\n")

    i = 1  # Skip 'xref' line
    while i < len(lines):
        line = lines[i].strip()
        if line.startswith("trailer") or not line:
            break

        parts = line.split()
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            start_obj = int(parts[0])
            count = int(parts[1])
            for j in range(count):
                i += 1
                if i >= len(lines):
                    break
                entry = lines[i].strip().split()
                if len(entry) >= 3 and entry[2] == "n":
                    obj_ids.add(start_obj + j)
        i += 1

    return obj_ids


def _extract_revision_bytes(content: bytes, eof_positions: List[int], rev_index: int) -> bytes:
    """Extrahiert die Bytes einer bestimmten Revision."""
    end = eof_positions[rev_index] + 5
    if rev_index == 0:
        return content[:end]
    else:
        start = eof_positions[rev_index - 1] + 5
        return content[start:end]


def analyze_incremental_diff(pdf_path: Path) -> IncrementalDiffResult:
    """Analysiert Unterschiede zwischen inkrementellen Updates."""
    anomalies: List[Anomaly] = []
    diffs: List[Dict[str, Any]] = []

    try:
        with open(pdf_path, "rb") as f:
            content = f.read()
    except Exception as e:
        return IncrementalDiffResult(
            anomalies=[Anomaly(
                severity=AnomalySeverity.MEDIUM,
                category="incremental_diff",
                message=f"Datei konnte nicht gelesen werden: {str(e)[:80]}",
            )]
        )

    eof_positions = _find_eof_markers(content)
    revision_count = len(eof_positions)

    if revision_count <= 1:
        return IncrementalDiffResult(revision_count=revision_count, anomalies=anomalies)

    # Für jede Revision: XRef-Tabelle finden und Objekte extrahieren
    revision_objects: List[Set[int]] = []

    for i, eof_pos in enumerate(eof_positions):
        rev_bytes = content[:eof_pos + 5]  # Kumulativ bis zu dieser Revision

        # Letzte XRef vor diesem EOF finden
        xref_search_start = max(0, eof_pos - 100_000)
        xref_chunk = rev_bytes[xref_search_start:]
        xref_matches = list(re.finditer(rb'\bxref\b', xref_chunk))

        if xref_matches:
            last_xref = xref_search_start + xref_matches[-1].start()
            obj_ids = _extract_obj_ids_from_xref(rev_bytes, last_xref)
        else:
            # XRef-Stream: Objekte über Regex finden
            obj_ids = set()
            for m in re.finditer(rb'(\d+)\s+\d+\s+obj\b', xref_chunk):
                obj_ids.add(int(m.group(1)))

        revision_objects.append(obj_ids)

    # Diffs berechnen
    for i in range(1, len(revision_objects)):
        prev = revision_objects[i - 1]
        curr = revision_objects[i]

        added = curr - prev
        removed = prev - curr
        # Geänderte Objekte: In beiden vorhanden, aber wir können den Inhalt vergleichen
        common = curr & prev

        # Inhalt der geänderten Objekte vergleichen
        modified = set()
        rev_chunk = _extract_revision_bytes(content, eof_positions, i)

        # Objekte in dieser Revision (nur das Delta)
        delta_objs = set()
        for m in re.finditer(rb'(\d+)\s+\d+\s+obj\b', rev_chunk):
            delta_objs.add(int(m.group(1)))

        # Objekte die in der Revision neu geschrieben wurden und auch vorher existierten
        modified = delta_objs & common

        # Summary
        summary_parts = []
        if added:
            summary_parts.append(f"{len(added)} hinzugefügt")
        if modified:
            summary_parts.append(f"{len(modified)} geändert")
        if removed:
            summary_parts.append(f"{len(removed)} entfernt")

        # Detail: Was wurde geändert?
        change_details = []
        for obj_id in list(modified)[:10]:
            # Versuche den Objekt-Typ zu bestimmen
            pattern = re.compile(
                rf'{obj_id}\s+\d+\s+obj\s*(.*?)endobj'.encode(),
                re.DOTALL
            )
            match = pattern.search(rev_chunk[:500_000])
            if match:
                obj_content = match.group(1)[:200].decode("latin-1", errors="replace")
                obj_type = "unknown"
                if "/Type" in obj_content:
                    type_match = re.search(r'/Type\s*/(\w+)', obj_content)
                    if type_match:
                        obj_type = type_match.group(1)
                elif "/Subtype" in obj_content:
                    type_match = re.search(r'/Subtype\s*/(\w+)', obj_content)
                    if type_match:
                        obj_type = type_match.group(1)

                change_details.append({
                    "object": obj_id,
                    "type": obj_type,
                    "snippet": obj_content[:100],
                })

        diff_entry = {
            "revision": i + 1,
            "added_count": len(added),
            "modified_count": len(modified),
            "removed_count": len(removed),
            "added_objects": sorted(list(added))[:20],
            "modified_objects": sorted(list(modified))[:20],
            "removed_objects": sorted(list(removed))[:20],
            "change_details": change_details,
            "summary": ", ".join(summary_parts) if summary_parts else "Keine Änderungen erkannt",
            "revision_size_bytes": len(rev_chunk),
        }
        diffs.append(diff_entry)

    # Anomalien
    for d in diffs:
        if d["added_count"] + d["modified_count"] > 20:
            anomalies.append(Anomaly(
                severity=AnomalySeverity.MEDIUM,
                category="incremental_diff",
                message=f"Revision {d['revision']}: Umfangreiche Änderungen ({d['summary']})",
                detail=f"Revisionsgrößeö: {d['revision_size_bytes']:,} Bytes",
            ))

        # Prüfe ob Metadata/Info-Objekte geändert wurden
        for cd in d.get("change_details", []):
            if cd.get("type") in ("Catalog", "Info", "Metadata"):
                anomalies.append(Anomaly(
                    severity=AnomalySeverity.HIGH,
                    category="incremental_diff",
                    message=f"Revision {d['revision']}: {cd['type']}-Objekt geändert",
                    detail=f"Objekt {cd['object']}: {cd.get('snippet', '')[:60]}",
                ))

    if revision_count > 5:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category="incremental_diff",
            message=f"{revision_count} Revisionen — ungewöhnlich viele Updates",
            detail="Viele Revisionen können auf nachträgliche Manipulation hinweisen",
        ))

    return IncrementalDiffResult(
        revision_count=revision_count,
        diffs=diffs,
        anomalies=anomalies,
    )
