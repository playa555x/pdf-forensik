"""
Timezone-Analyzer: Extrahiert alle Datumsangaben aus PDF-Metadaten und XMP,
analysiert Zeitzonenmuster, erkennt DST-Anomalien und leitet geografische
Region aus dem UTC-Offset ab.
"""
from __future__ import annotations
import re
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone, timedelta

import pikepdf

from models.schemas import Anomaly, AnomalySeverity


# UTC-Offset → mögliche Regionen (grobe Zuordnung)
_OFFSET_REGIONS: Dict[int, str] = {
    -720: "UTC-12 (Baker Island)",
    -660: "UTC-11 (Samoa)",
    -600: "UTC-10 (Hawaii)",
    -570: "UTC-9:30 (Marquesas)",
    -540: "UTC-9 (Alaska)",
    -480: "UTC-8 (USA Pacific / Los Angeles)",
    -420: "UTC-7 (USA Mountain / Denver)",
    -360: "UTC-6 (USA Central / Chicago)",
    -300: "UTC-5 (USA Eastern / New York, Brasilien)",
    -240: "UTC-4 (Atlantik, Venezuela)",
    -210: "UTC-3:30 (Neufundland)",
    -180: "UTC-3 (Argentinien, Brasília)",
    -120: "UTC-2 (Südatlantik)",
    -60:  "UTC-1 (Azoren, Kap Verde)",
    0:    "UTC+0 (UK, Irland, Portugal, West-Afrika)",
    60:   "UTC+1 (Mitteleuropa: DE, FR, IT, ES, PL)",
    120:  "UTC+2 (Osteuropa: GR, RO, FI; Israel; Südafrika)",
    180:  "UTC+3 (Russland/Moskau, Ostafrika, Saudi-Arabien)",
    210:  "UTC+3:30 (Iran)",
    240:  "UTC+4 (Russland/Samara, UAE, Pakistan-Westrand)",
    270:  "UTC+4:30 (Afghanistan)",
    300:  "UTC+5 (Pakistan, Usbekistan)",
    330:  "UTC+5:30 (Indien, Sri Lanka)",
    345:  "UTC+5:45 (Nepal)",
    360:  "UTC+6 (Bangladesch, Kasachstan)",
    390:  "UTC+6:30 (Myanmar)",
    420:  "UTC+7 (Thailand, Vietnam, Russland/Krasnojarsk)",
    480:  "UTC+8 (China, Australien/Perth, Singapur)",
    525:  "UTC+8:45 (Australien/Eucla)",
    540:  "UTC+9 (Japan, Südkorea, Russland/Jakutsk)",
    570:  "UTC+9:30 (Australien/Darwin, Adelaide-Normalzeit)",
    600:  "UTC+10 (Australien/Sydney, Papua-Neuguinea)",
    630:  "UTC+10:30 (Australien/Lord Howe Island)",
    660:  "UTC+11 (Salomonen, Russland/Magadan)",
    720:  "UTC+12 (Neuseeland, Russland/Kamtschatka)",
    765:  "UTC+12:45 (Neuseeland/Chatham)",
    780:  "UTC+13 (Tonga, Samoa-Sommerzeit)",
    840:  "UTC+14 (Kiribati/Linieninseln)",
}

_PDF_DATE_RE = re.compile(
    r"D:(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})"
    r"(?:([+-Z])(\d{2})?'?(\d{2})?'?)?",
    re.IGNORECASE,
)


def _parse_pdf_date_full(raw: str) -> Optional[Dict[str, Any]]:
    """Parst ein PDF-Datum und gibt alle Bestandteile zurück."""
    if not raw:
        return None
    raw = raw.strip()
    m = _PDF_DATE_RE.match(raw)
    if not m:
        return None
    try:
        year   = int(m.group(1))
        month  = int(m.group(2))
        day    = int(m.group(3))
        hour   = int(m.group(4))
        minute = int(m.group(5))
        second = int(m.group(6))
        tz_sign = m.group(7) or "Z"
        tz_h    = int(m.group(8) or 0)
        tz_m    = int(m.group(9) or 0)

        if tz_sign.upper() == "Z":
            offset_min = 0
            tz_str = "Z (UTC)"
        elif tz_sign == "+":
            offset_min = tz_h * 60 + tz_m
            tz_str = f"+{tz_h:02d}:{tz_m:02d}"
        else:
            offset_min = -(tz_h * 60 + tz_m)
            tz_str = f"-{tz_h:02d}:{tz_m:02d}"

        tz_offset = timedelta(minutes=offset_min)
        dt_local  = datetime(year, month, day, hour, minute, second)
        dt_utc    = dt_local - tz_offset

        region = _OFFSET_REGIONS.get(offset_min, f"UTC{tz_str} — unbekannte Region")

        return {
            "raw":        raw,
            "iso_local":  dt_local.isoformat(),
            "iso_utc":    dt_utc.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"),
            "tz_string":  tz_str,
            "offset_min": offset_min,
            "region":     region,
        }
    except (ValueError, OverflowError):
        return None


def _extract_xmp_dates(pdf: pikepdf.Pdf) -> List[Dict[str, Any]]:
    """Extrahiert alle Datums-Felder aus dem XMP-Stream."""
    results = []
    try:
        with pdf.open_metadata() as meta:
            date_keys = [k for k in meta if "date" in k.lower() or "Date" in k]
            for key in date_keys:
                try:
                    val = str(meta[key])
                    results.append({"source": f"XMP:{key}", "raw": val})
                except Exception:
                    continue
    except Exception:
        pass
    return results


def analyze_timezones(pdf_path: Path) -> Dict[str, Any]:
    """
    Analysiert alle Zeitstempel im PDF und leitet daraus:
    - UTC-Offsets aller Datumsfelder
    - Wahrscheinliche geografische Region
    - Inkonsistenzen zwischen verschiedenen Zeitstempeln
    - DST-Auffälligkeiten (Halbe-Stunden-Offsets)
    """
    anomalies: List[Anomaly] = []
    dates: List[Dict[str, Any]] = []

    try:
        pdf = pikepdf.open(pdf_path)
    except Exception as e:
        return {
            "dates": [],
            "region_hint": None,
            "offset_consistent": True,
            "anomalies": [Anomaly(
                severity=AnomalySeverity.HIGH,
                category="timezone",
                message="PDF konnte nicht für Timezone-Analyse geöffnet werden",
                detail=str(e),
            )],
        }

    with pdf:
        info = pdf.docinfo
        for field_name in ["/CreationDate", "/ModDate"]:
            raw = None
            try:
                raw = str(info.get(field_name) or "")
            except Exception:
                pass
            if raw:
                parsed = _parse_pdf_date_full(raw)
                if parsed:
                    parsed["source"] = f"/Info{field_name}"
                    dates.append(parsed)

        # XMP-Daten
        xmp_dates = _extract_xmp_dates(pdf)
        for xd in xmp_dates:
            parsed = _parse_pdf_date_full(xd["raw"])
            if parsed:
                parsed["source"] = xd["source"]
                dates.append(parsed)
            else:
                # XMP-Datum in ISO-Format, kein D:-Prefix
                raw_xmp = xd["raw"]
                dates.append({
                    "raw":        raw_xmp,
                    "iso_local":  raw_xmp,
                    "iso_utc":    raw_xmp,
                    "tz_string":  "unbekannt",
                    "offset_min": None,
                    "region":     "unbekannt",
                    "source":     xd["source"],
                })

    # Anomalie-Erkennung
    offsets = [d["offset_min"] for d in dates if d.get("offset_min") is not None]
    unique_offsets = list(set(offsets))

    # Inkonsistente Zeitzonen zwischen CreationDate und ModDate
    if len(unique_offsets) > 1:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category="timezone",
            message="Inkonsistente Zeitzonen zwischen verschiedenen Datumsfeldern",
            detail=f"Gefundene UTC-Offsets: {[f'{o//60:+d}:{abs(o)%60:02d}' for o in unique_offsets]}",
        ))

    # Halbe-Stunden-Offsets (ungewöhnlich für DE/EU, interessant für forensische Herkunft)
    for offset in unique_offsets:
        if offset is not None and offset % 60 != 0:
            region = _OFFSET_REGIONS.get(offset, "unbekannt")
            anomalies.append(Anomaly(
                severity=AnomalySeverity.INFO,
                category="timezone",
                message=f"Ungewöhnlicher Halbstunden-Offset: {offset//60:+d}:{abs(offset)%60:02d}",
                detail=f"Deutet auf Region hin: {region}",
            ))

    # UTC+0 mit Z — könnte manuell gesetzt worden sein
    z_count = sum(1 for d in dates if d.get("tz_string") == "Z (UTC)")
    if z_count > 0 and len(dates) > 1:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.INFO,
            category="timezone",
            message="Einige Datumsfelder verwenden UTC/Z — könnte normalisiert worden sein",
            detail=f"{z_count} von {len(dates)} Feldern haben UTC+0",
        ))

    # Region-Hinweis (häufigster Offset)
    region_hint = None
    if offsets:
        most_common_offset = max(set(offsets), key=offsets.count)
        region_hint = _OFFSET_REGIONS.get(most_common_offset)

    return {
        "dates":              dates,
        "region_hint":        region_hint,
        "offset_consistent":  len(unique_offsets) <= 1,
        "unique_offsets":     unique_offsets,
        "anomalies":          anomalies,
    }
