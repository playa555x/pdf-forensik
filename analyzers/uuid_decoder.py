"""
UUID v1 → Zeitstempel-Decoder.
Sucht UUIDs im gesamten PDF-Byte-Stream und vergleicht Zeitstempel mit CreationDate.
"""
from __future__ import annotations
import re
import uuid as uuid_module
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

from models.schemas import UUIDDecodeResult, Anomaly, AnomalySeverity
from config import UUID_TIMESTAMP_HIGH_DELTA_SECONDS, UUID_TIMESTAMP_MEDIUM_DELTA_SECONDS

_UUID_RE = re.compile(
    rb"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-1[0-9a-fA-F]{3}-"
    rb"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}"
)

# UUID v1 Epoch: 15. Oktober 1582 00:00:00 UTC
_UUID_EPOCH_DELTA = 122192928000000000  # 100-ns-Ticks zwischen UUID-Epoch und Unix-Epoch


def _uuid1_to_datetime(u: str) -> Optional[datetime]:
    try:
        parsed = uuid_module.UUID(u)
        if parsed.version != 1:
            return None
        ns100 = parsed.time - _UUID_EPOCH_DELTA
        unix_seconds = ns100 / 1e7
        return datetime.fromtimestamp(unix_seconds, tz=timezone.utc)
    except Exception:
        return None


def analyze_uuids(pdf_path: Path, creation_date_iso: Optional[str] = None) -> UUIDDecodeResult:
    anomalies: list[Anomaly] = []
    decoded_list = []

    try:
        data = pdf_path.read_bytes()
    except Exception as e:
        return UUIDDecodeResult(anomalies=[
            Anomaly(severity=AnomalySeverity.HIGH, category="uuid", message="Datei konnte nicht gelesen werden", detail=str(e))
        ])

    raw_uuids = _UUID_RE.findall(data)
    seen = set()
    found_uuids = []

    for raw in raw_uuids:
        u_str = raw.decode("ascii").lower()
        if u_str not in seen:
            seen.add(u_str)
            found_uuids.append(u_str)

    for u_str in found_uuids:
        ts = _uuid1_to_datetime(u_str)
        if ts is None:
            continue

        ts_iso = ts.isoformat().replace("+00:00", "Z")
        delta = None

        if creation_date_iso:
            try:
                cd = datetime.fromisoformat(creation_date_iso.replace("Z", "+00:00"))
                delta = abs((ts - cd).total_seconds())

                if delta > UUID_TIMESTAMP_HIGH_DELTA_SECONDS:
                    anomalies.append(Anomaly(
                        severity=AnomalySeverity.HIGH,
                        category="uuid",
                        message=f"UUID-Zeitstempel weicht um {delta:.0f}s von CreationDate ab (>{UUID_TIMESTAMP_HIGH_DELTA_SECONDS}s)",
                        detail=f"UUID: {u_str} | UUID-Zeit: {ts_iso} | CreationDate: {creation_date_iso}",
                    ))
                elif delta > UUID_TIMESTAMP_MEDIUM_DELTA_SECONDS:
                    anomalies.append(Anomaly(
                        severity=AnomalySeverity.MEDIUM,
                        category="uuid",
                        message=f"UUID-Zeitstempel weicht um {delta:.0f}s von CreationDate ab (>{UUID_TIMESTAMP_MEDIUM_DELTA_SECONDS}s)",
                        detail=f"UUID: {u_str} | UUID-Zeit: {ts_iso} | CreationDate: {creation_date_iso}",
                    ))
            except Exception:
                pass

        decoded_list.append({
            "uuid": u_str,
            "version": 1,
            "timestamp_utc": ts_iso,
            "delta_seconds": delta,
            "creation_date_iso": creation_date_iso,
        })

    return UUIDDecodeResult(
        found_uuids=found_uuids,
        decoded=decoded_list,
        anomalies=anomalies,
    )
