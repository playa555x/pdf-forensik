"""
ExifTool Wrapper — Tiefer Metadaten-Extraktor (1000+ proprietaere Tags).

Wraps `exiftool -j -G -s -a -e -api LargeFileSupport=1 file.pdf` und liefert:
- ALLE Adobe-spezifische History (xmpMM:History, photoshop:History)
- Lightroom/Photoshop Edit-Spuren
- IPTC, GPS, ICC-Profil-Header, JFIF
- Mehrere /Info-Eintraege bei manipulierten PDFs (history of duplicates)

Forensisch wertvoll: Adobe XMP History laesst sich nicht einfach loeschen
ohne den Hash zu zerstoeren — also klares Zeichen wenn ein Dokument editiert
und re-saved wurde.
"""
from __future__ import annotations
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List

from models.schemas import Anomaly, AnomalySeverity, ExifToolResult


# Forensisch hochinteressante Tags - loesen automatisch Anomalien aus
SUSPICIOUS_TAGS = {
    "XMP-xmpMM:History":      ("HIGH",   "exiftool_xmp_history",     "Adobe XMP Edit-History gefunden"),
    "XMP-xmpMM:DerivedFrom":  ("MEDIUM", "exiftool_derived_from",    "Dokument abgeleitet von anderem File"),
    "XMP-photoshop:History":  ("HIGH",   "exiftool_ps_history",      "Photoshop-Edit-History"),
    "XMP-pdf:Trapped":        ("LOW",    "exiftool_trapped",         "Trapping-Information vorhanden"),
    "XMP-xmpMM:DocumentID":   ("LOW",    "exiftool_doc_id",          "Document-ID gesetzt"),
    "XMP-xmpMM:InstanceID":   ("LOW",    "exiftool_instance_id",     "Instance-ID gesetzt"),
    "XMP-xmpMM:OriginalDocumentID": ("MEDIUM", "exiftool_orig_id",   "Original-Document-ID -- Datei wurde dupliziert"),
    # PDF:Linearized entfernt - ist Default fuer Browser-PDFs, kein Manipulationshinweis
}


def _run_exiftool(pdf_path: Path) -> Dict[str, Any]:
    if not shutil.which("exiftool"):
        return {"error": "exiftool not installed"}
    cmd = [
        "exiftool",
        "-j",                       # JSON
        "-G",                       # Group-Names
        "-s",                       # Short tag names
        "-a",                       # All duplicate tags
        "-e",                       # Exclude composite
        "-api", "LargeFileSupport=1",
        str(pdf_path),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if proc.returncode != 0:
            return {"error": proc.stderr[:500] or "exiftool failed", "rc": proc.returncode}
        data = json.loads(proc.stdout)
        return data[0] if data else {}
    except subprocess.TimeoutExpired:
        return {"error": "timeout"}
    except json.JSONDecodeError as e:
        return {"error": f"json parse: {e}", "raw": proc.stdout[:500]}
    except Exception as e:
        return {"error": str(e)}


def analyze_exiftool(pdf_path: Path) -> ExifToolResult:
    raw = _run_exiftool(pdf_path)
    anomalies: List[Anomaly] = []

    if "error" in raw:
        return ExifToolResult(raw_tags={}, error=raw["error"], anomalies=[])

    # Cleanup: drop noise tags
    drop = {"SourceFile", "ExifTool:ExifToolVersion", "File:FileName",
            "File:Directory", "File:FileSize", "File:FileType",
            "File:FileTypeExtension", "File:MIMEType",
            "File:FileModifyDate", "File:FileAccessDate",
            "File:FileInodeChangeDate", "File:FilePermissions"}
    clean = {k: v for k, v in raw.items() if k not in drop}

    # XMP History special handling
    xmp_history = []
    history_raw = clean.get("XMP-xmpMM:History")
    if history_raw:
        if isinstance(history_raw, list):
            xmp_history = history_raw
        elif isinstance(history_raw, str):
            # Sometimes serialized as string; split semicolons
            xmp_history = [s.strip() for s in history_raw.split(";") if s.strip()]
        else:
            xmp_history = [str(history_raw)]

    # Anomaly: PDF Producer/Creator mismatch with XMP CreatorTool
    pdf_producer = clean.get("PDF:Producer", "")
    xmp_creator = clean.get("XMP-xmp:CreatorTool", "")
    if pdf_producer and xmp_creator:
        if pdf_producer.split()[0].lower() not in xmp_creator.lower() \
           and xmp_creator.split()[0].lower() not in pdf_producer.lower():
            anomalies.append(Anomaly(
                severity=AnomalySeverity.MEDIUM,
                category="exiftool_producer_mismatch",
                message="PDF:Producer weicht von XMP:CreatorTool ab",
                detail=f"Producer={pdf_producer!r} vs CreatorTool={xmp_creator!r}",
            ))

    # Multiple Producer/Creator entries (duplicates -- Anti-Forensics-Smell)
    for k, v in raw.items():
        if isinstance(v, list) and k.endswith((":Producer", ":Creator", ":Author")):
            if len(v) > 1:
                anomalies.append(Anomaly(
                    severity=AnomalySeverity.HIGH,
                    category="exiftool_duplicate_meta",
                    message=f"Mehrere {k} Werte gefunden -- typischer Anti-Forensik-Trick",
                    detail=f"Werte: {v}",
                ))

    # XMP History laenge
    if xmp_history:
        actions = []
        for item in xmp_history:
            if isinstance(item, dict):
                actions.append(item.get("Action") or item.get("xmpMM:Action") or str(item)[:60])
            else:
                actions.append(str(item)[:60])
        anomalies.append(Anomaly(
            severity=AnomalySeverity.HIGH,
            category="exiftool_xmp_history",
            message=f"XMP Edit-History mit {len(xmp_history)} Eintraegen -- Datei wurde mehrfach editiert",
            detail=f"Actions: {actions[:8]}",
        ))

    # Generic suspicious-tag scan
    for tag, (sev, cat, msg) in SUSPICIOUS_TAGS.items():
        if tag in clean and tag not in ("XMP-xmpMM:History", "XMP-photoshop:History"):
            val = clean[tag]
            if val:
                sev_enum = {"HIGH": AnomalySeverity.HIGH,
                            "MEDIUM": AnomalySeverity.MEDIUM,
                            "LOW": AnomalySeverity.LOW}[sev]
                anomalies.append(Anomaly(
                    severity=sev_enum,
                    category=cat,
                    message=msg,
                    detail=f"{tag}={str(val)[:200]}",
                ))

    return ExifToolResult(
        raw_tags=clean,
        xmp_history=xmp_history,
        producer=pdf_producer or None,
        creator_tool=xmp_creator or None,
        document_id=clean.get("XMP-xmpMM:DocumentID"),
        instance_id=clean.get("XMP-xmpMM:InstanceID"),
        original_document_id=clean.get("XMP-xmpMM:OriginalDocumentID"),
        derived_from=clean.get("XMP-xmpMM:DerivedFrom"),
        tag_count=len(clean),
        anomalies=anomalies,
    )
