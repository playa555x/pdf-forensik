"""
Fuzzy Hashing (ssdeep / TLSH).

Erzeugt fuzzy Hashes zum Finden ähnlicher (nicht identischer) Dokumente:
1. ppdeep (Python-Reimplementierung von ssdeep)
2. TLSH (Trend Micro Locality Sensitive Hash)
"""
from __future__ import annotations
from pathlib import Path
from typing import Optional

from models.schemas import Anomaly, AnomalySeverity, FuzzyHashResult

# ppdeep (ssdeep-kompatibel)
try:
    import ppdeep
    PPDEEP_OK = True
except ImportError:
    PPDEEP_OK = False

# TLSH
try:
    import tlsh
    TLSH_OK = True
except ImportError:
    TLSH_OK = False


def compute_fuzzy_hashes(pdf_path: Path) -> FuzzyHashResult:
    """Berechnet Fuzzy-Hashes für ein PDF."""
    anomalies = []
    ssdeep_hash: Optional[str] = None
    tlsh_hash: Optional[str] = None

    try:
        with open(pdf_path, "rb") as f:
            data = f.read()
    except Exception as e:
        return FuzzyHashResult(
            available=False,
            anomalies=[Anomaly(
                severity=AnomalySeverity.INFO,
                category="fuzzy_hash",
                message=f"Datei nicht lesbar: {str(e)[:80]}",
            )]
        )

    # ssdeep via ppdeep
    if PPDEEP_OK:
        try:
            ssdeep_hash = ppdeep.hash(data)
        except Exception as e:
            anomalies.append(Anomaly(
                severity=AnomalySeverity.INFO,
                category="fuzzy_hash",
                message=f"ssdeep-Hash-Fehler: {str(e)[:80]}",
            ))

    # TLSH
    if TLSH_OK:
        try:
            tlsh_hash = tlsh.hash(data)
            if tlsh_hash == "" or tlsh_hash == "TNULL":
                tlsh_hash = None
                anomalies.append(Anomaly(
                    severity=AnomalySeverity.INFO,
                    category="fuzzy_hash",
                    message="TLSH konnte keinen Hash erzeugen (Datei zu klein oder zu uniform)",
                ))
        except Exception as e:
            anomalies.append(Anomaly(
                severity=AnomalySeverity.INFO,
                category="fuzzy_hash",
                message=f"TLSH-Hash-Fehler: {str(e)[:80]}",
            ))

    available = PPDEEP_OK or TLSH_OK

    return FuzzyHashResult(
        ssdeep_hash=ssdeep_hash,
        tlsh_hash=tlsh_hash,
        available=available,
        anomalies=anomalies,
    )
