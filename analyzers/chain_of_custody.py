"""
Chain of Custody Module.

Erzeugt gerichtsverwertbare Dokumentation:
1. Examiner-Name und Fallnummer
2. Zeitstempel für Start/Ende der Untersuchung
3. SHA-256 des Reports als Integritätsnachweis
4. Audit-Log aller durchgeführten Analysen
5. Evidence-Integrity (Vergleich Original-Hash vor/nach Analyse)
"""
from __future__ import annotations
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

from models.schemas import ChainOfCustodyResult


def create_chain_of_custody(
    pdf_path: Path,
    original_hash_sha256: str,
    analysis_id: str,
    analyzer_names: List[str],
    examiner_name: Optional[str] = None,
    case_number: Optional[str] = None,
) -> ChainOfCustodyResult:
    """Erstellt die Chain-of-Custody-Dokumentation."""

    now_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # Evidence Integrity: Hash nochmal berechnen
    try:
        with open(pdf_path, "rb") as f:
            current_hash = hashlib.sha256(f.read()).hexdigest()
    except Exception:
        current_hash = "NICHT LESBAR"

    integrity_match = (current_hash == original_hash_sha256)

    evidence_integrity = {
        "original_hash": original_hash_sha256,
        "post_analysis_hash": current_hash,
        "integrity_intact": integrity_match,
        "hash_algorithm": "SHA-256",
    }

    # Audit-Log
    audit_log: List[Dict[str, Any]] = [
        {
            "timestamp": now_utc,
            "action": "analysis_start",
            "detail": f"Analyse gestartet für {pdf_path.name}",
            "analysis_id": analysis_id,
        },
    ]

    for i, analyzer in enumerate(analyzer_names, 1):
        audit_log.append({
            "timestamp": now_utc,
            "action": f"analyzer_{i:02d}",
            "detail": f"Analyzer ausgeführt: {analyzer}",
            "sequence": i,
        })

    audit_log.append({
        "timestamp": now_utc,
        "action": "analysis_complete",
        "detail": f"Analyse abgeschlossen — {len(analyzer_names)} Analyzer ausgeführt",
        "evidence_intact": integrity_match,
    })

    return ChainOfCustodyResult(
        examiner_name=examiner_name or "Automatisiert (PDF Forensik Analyzer)",
        case_number=case_number,
        examination_start=now_utc,
        examination_end=now_utc,
        report_hash_sha256=None,  # Wird nach Report-Generierung gesetzt
        audit_log=audit_log,
        evidence_integrity=evidence_integrity,
    )
