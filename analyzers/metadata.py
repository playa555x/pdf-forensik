"""
PDF-Metadaten via pikepdf.
Parst /Info-Dictionary + XMP-Metadata-Stream (via defusedxml).
"""
from __future__ import annotations
import re
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime, timezone

import pikepdf

from models.schemas import MetadataResult, Anomaly, AnomalySeverity


_PDF_DATE_RE = re.compile(
    r"D:(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})"
    r"(?:([+-Z])(\d{2})?'?(\d{2})?'?)?",
    re.IGNORECASE,
)


def _parse_pdf_date(raw: str) -> Optional[str]:
    if not raw:
        return None
    raw = raw.strip()
    m = _PDF_DATE_RE.match(raw)
    if not m:
        return None
    try:
        year, month, day = int(m.group(1)), int(m.group(2)), int(m.group(3))
        hour, minute, second = int(m.group(4)), int(m.group(5)), int(m.group(6))
        tz_sign = m.group(7) or "Z"
        tz_h = int(m.group(8) or 0)
        tz_m = int(m.group(9) or 0)

        if tz_sign.upper() == "Z":
            offset_min = 0
        elif tz_sign == "+":
            offset_min = tz_h * 60 + tz_m
        else:
            offset_min = -(tz_h * 60 + tz_m)

        dt = datetime(year, month, day, hour, minute, second)
        return dt.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError):
        return None


def _str(v) -> Optional[str]:
    if v is None:
        return None
    try:
        return str(v)
    except Exception:
        return None


def _parse_xmp(pdf: pikepdf.Pdf) -> Dict[str, Any]:
    """XMP-Metadata-Stream aus PDF extrahieren und strukturiert parsen."""
    result: Dict[str, Any] = {}
    try:
        with pdf.open_metadata() as meta:
            # pikepdf gibt uns schon strukturierten Zugriff
            xmp_fields = {}
            for key in meta:
                try:
                    val = meta[key]
                    xmp_fields[key] = str(val)
                except Exception:
                    continue
            if xmp_fields:
                result["fields"] = xmp_fields

            # Rohdaten zusätzlich
            raw = meta.to_xml()
            if raw:
                result["raw_length"] = len(raw)

                # Konflikt-Erkennung: XMP vs /Info
                xmp_creator    = xmp_fields.get("dc:creator", xmp_fields.get("xmp:CreatorTool", ""))
                xmp_create_date= xmp_fields.get("xmp:CreateDate", "")
                xmp_mod_date   = xmp_fields.get("xmp:ModifyDate", "")
                result["xmp_creator"]     = xmp_creator or None
                result["xmp_create_date"] = xmp_create_date or None
                result["xmp_mod_date"]    = xmp_mod_date or None

    except Exception as e:
        result["parse_error"] = str(e)
    return result


def analyze_metadata(pdf_path: Path) -> MetadataResult:
    anomalies: list[Anomaly] = []

    try:
        pdf = pikepdf.open(pdf_path)
    except Exception as e:
        return MetadataResult(anomalies=[
            Anomaly(severity=AnomalySeverity.HIGH,
                    category="metadata",
                    message="PDF konnte nicht geöffnet werden",
                    detail=str(e))
        ])

    with pdf:
        info = pdf.docinfo
        page_count  = len(pdf.pages)
        pdf_version = pdf.pdf_version

        title    = _str(info.get("/Title"))
        author   = _str(info.get("/Author"))
        subject  = _str(info.get("/Subject"))
        keywords = _str(info.get("/Keywords"))
        creator  = _str(info.get("/Creator"))
        producer = _str(info.get("/Producer"))
        creation_date_raw = _str(info.get("/CreationDate"))
        mod_date_raw      = _str(info.get("/ModDate"))

        # XMP parsen
        xmp_data = _parse_xmp(pdf)

    creation_date_parsed = _parse_pdf_date(creation_date_raw or "")
    mod_date_parsed      = _parse_pdf_date(mod_date_raw or "")
    now_iso = datetime.now(timezone.utc).isoformat()

    # Anomalie: ModDate < CreationDate
    if creation_date_parsed and mod_date_parsed:
        if mod_date_parsed < creation_date_parsed:
            anomalies.append(Anomaly(
                severity=AnomalySeverity.HIGH,
                category="metadata",
                message="ModDate liegt vor CreationDate — mögliche Manipulation",
                detail=f"CreationDate: {creation_date_parsed} | ModDate: {mod_date_parsed}",
            ))

    # CreationDate in der Zukunft
    if creation_date_parsed and creation_date_parsed > now_iso:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.HIGH,
            category="metadata",
            message="CreationDate liegt in der Zukunft",
            detail=f"CreationDate: {creation_date_parsed}",
        ))

    # ModDate in der Zukunft
    if mod_date_parsed and mod_date_parsed > now_iso:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category="metadata",
            message="ModDate liegt in der Zukunft",
            detail=f"ModDate: {mod_date_parsed}",
        ))

    # XMP vs /Info Konflikt-Erkennung
    if xmp_data:
        xmp_create = xmp_data.get("xmp_create_date")
        xmp_mod    = xmp_data.get("xmp_mod_date")

        if xmp_create and creation_date_parsed:
            # Grob vergleichen (erste 10 Zeichen = Datum)
            xmp_date_short  = str(xmp_create)[:10].replace("-", "")
            info_date_short = creation_date_parsed[:10].replace("-", "")
            if xmp_date_short and info_date_short and xmp_date_short != info_date_short:
                anomalies.append(Anomaly(
                    severity=AnomalySeverity.MEDIUM,
                    category="metadata",
                    message="XMP-CreateDate weicht vom /Info-CreationDate ab — mögliche Manipulation",
                    detail=f"XMP: {xmp_create} | /Info: {creation_date_parsed}",
                ))

        if xmp_mod and mod_date_parsed:
            xmp_mod_short  = str(xmp_mod)[:10].replace("-", "")
            info_mod_short = mod_date_parsed[:10].replace("-", "")
            if xmp_mod_short and info_mod_short and xmp_mod_short != info_mod_short:
                anomalies.append(Anomaly(
                    severity=AnomalySeverity.MEDIUM,
                    category="metadata",
                    message="XMP-ModifyDate weicht vom /Info-ModDate ab — mögliche Manipulation",
                    detail=f"XMP: {xmp_mod} | /Info: {mod_date_parsed}",
                ))

    return MetadataResult(
        title=title,
        author=author,
        subject=subject,
        keywords=keywords,
        creator=creator,
        producer=producer,
        creation_date_raw=creation_date_raw,
        mod_date_raw=mod_date_raw,
        creation_date_parsed=creation_date_parsed,
        mod_date_parsed=mod_date_parsed,
        pdf_version=pdf_version,
        page_count=page_count,
        xmp_data=xmp_data if xmp_data else None,
        anomalies=anomalies,
    )
