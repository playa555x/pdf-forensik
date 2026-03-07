"""
XRef Deep Validation.

Validiert die Cross-Reference-Tabelle eines PDF:
- Konsistenz der Offsets
- Subsection-Validierung
- Free-Object-Chain-Verifikation
- Duplikat-Offsets
- Orphan-Referenzen
"""
from __future__ import annotations
import re
from pathlib import Path
from typing import List, Dict, Any

from models.schemas import Anomaly, AnomalySeverity, XRefValidationResult

try:
    import pikepdf
    PIKE_OK = True
except ImportError:
    PIKE_OK = False


def analyze_xref_deep(pdf_path: Path) -> XRefValidationResult:
    """Tiefe XRef-Validierung."""
    anomalies: List[Anomaly] = []

    if not PIKE_OK:
        return XRefValidationResult(
            anomalies=[Anomaly(
                severity=AnomalySeverity.INFO,
                category="xref",
                message="pikepdf nicht verfügbar — XRef-Validierung übersprungen",
            )]
        )

    total_entries = 0
    subsection_count = 0
    free_chain_valid = True
    free_chain_length = 0
    consistency_errors: List[Dict[str, Any]] = []
    duplicate_offsets: List[Dict[str, Any]] = []
    orphan_refs: List[Dict[str, Any]] = []
    xref_type = "table"

    try:
        # Raw-Datei lesen für XRef-Tabellen-Analyse
        with open(pdf_path, "rb") as f:
            content = f.read()

        # XRef-Typ bestimmen
        if b"/Type /XRef" in content:
            xref_type = "stream"

        # Hybrid-Check
        if b"xref" in content and b"/Type /XRef" in content:
            xref_type = "hybrid"
            anomalies.append(Anomaly(
                severity=AnomalySeverity.MEDIUM,
                category="xref",
                message="Hybrid-XRef erkannt (Tabelle + Stream)",
                detail="Hybride XRef-Strukturen können Inkonsistenzen verbergen",
            ))

        # XRef-Tabelle(n) parsen
        xref_positions = [m.start() for m in re.finditer(rb'\bxref\b', content)]

        offset_map: Dict[int, List[int]] = {}  # offset → [obj_numbers]
        free_objects: List[int] = []  # Objekt-Nummern
        in_use_objects: Dict[int, int] = {}  # obj_num → offset

        for xref_pos in xref_positions:
            # Zeilen nach 'xref' lesen
            chunk = content[xref_pos:xref_pos + 100_000].decode("latin-1", errors="replace")
            lines = chunk.split("\n")

            i = 1  # Erste Zeile ist 'xref'
            while i < len(lines):
                line = lines[i].strip()
                if line.startswith("trailer") or not line:
                    break

                # Subsection-Header: start_obj count
                parts = line.split()
                if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                    start_obj = int(parts[0])
                    count = int(parts[1])
                    subsection_count += 1

                    for j in range(count):
                        i += 1
                        if i >= len(lines):
                            break
                        entry = lines[i].strip()
                        eparts = entry.split()
                        if len(eparts) >= 3:
                            offset = int(eparts[0])
                            gen = int(eparts[1])
                            flag = eparts[2]
                            obj_num = start_obj + j
                            total_entries += 1

                            if flag == "f":
                                free_objects.append(obj_num)
                            else:
                                in_use_objects[obj_num] = offset
                                if offset not in offset_map:
                                    offset_map[offset] = []
                                offset_map[offset].append(obj_num)

                i += 1

        # Duplikat-Offsets prüfen
        for offset, obj_nums in offset_map.items():
            if len(obj_nums) > 1 and offset != 0:
                duplicate_offsets.append({
                    "offset": offset,
                    "objects": obj_nums,
                })
                anomalies.append(Anomaly(
                    severity=AnomalySeverity.HIGH,
                    category="xref",
                    message=f"Duplikat-Offset {offset}: Objekte {obj_nums}",
                    detail="Mehrere Objekte am selben Offset — mögliche Manipulation",
                ))

        # Free-Chain validieren
        if free_objects:
            free_chain_length = len(free_objects)
            # Obj 0 sollte immer frei sein
            if 0 not in free_objects:
                free_chain_valid = False
                anomalies.append(Anomaly(
                    severity=AnomalySeverity.MEDIUM,
                    category="xref",
                    message="Objekt 0 ist nicht in der Free-Chain",
                    detail="PDF-Standard verlangt Obj 0 als Head der Free-Chain",
                ))

        # Offset-Konsistenz prüfen mit pikepdf
        try:
            pdf = pikepdf.open(pdf_path, allow_overwriting_input=True)
            pike_obj_count = len(list(pdf.objects))

            # Prüfe ob Objekte tatsächlich am angegebenen Offset existieren
            for obj_num, offset in list(in_use_objects.items())[:500]:
                if offset > len(content):
                    consistency_errors.append({
                        "object": obj_num,
                        "offset": offset,
                        "error": "Offset außerhalb der Datei",
                    })
                elif offset > 0:
                    # Prüfe ob an diesem Offset ein Objekt beginnt
                    snippet = content[offset:offset+30].decode("latin-1", errors="replace")
                    if not re.match(r'\d+\s+\d+\s+obj\b', snippet):
                        consistency_errors.append({
                            "object": obj_num,
                            "offset": offset,
                            "error": f"Kein Objekt-Start am Offset: {snippet[:20]}",
                        })

            # Orphan-Refs: Objekte die in keiner XRef referenziert werden
            for obj_key in pdf.objects:
                obj_n = int(str(obj_key))
                if obj_n not in in_use_objects and obj_n not in free_objects and obj_n != 0:
                    orphan_refs.append({"object": obj_n})

            pdf.close()
        except Exception:
            pass

        if consistency_errors:
            anomalies.append(Anomaly(
                severity=AnomalySeverity.HIGH,
                category="xref",
                message=f"{len(consistency_errors)} XRef-Konsistenzfehler",
                detail=f"Erste: {consistency_errors[0]}",
            ))

        if len(orphan_refs) > 5:
            anomalies.append(Anomaly(
                severity=AnomalySeverity.MEDIUM,
                category="xref",
                message=f"{len(orphan_refs)} Objekte ohne XRef-Eintrag",
                detail="Orphan-Objekte können versteckte Inhalte enthalten",
            ))

    except Exception as e:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category="xref",
            message=f"XRef-Analyse-Fehler: {str(e)[:100]}",
        ))

    return XRefValidationResult(
        xref_type=xref_type,
        total_entries=total_entries,
        subsection_count=subsection_count,
        free_chain_valid=free_chain_valid,
        free_chain_length=free_chain_length,
        consistency_errors=consistency_errors[:20],
        duplicate_offsets=duplicate_offsets,
        orphan_refs=orphan_refs[:50],
        anomalies=anomalies,
    )
