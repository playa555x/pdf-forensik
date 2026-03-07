"""
Encryption Analyzer.
Erkennt /Encrypt Dictionary, Algorithmus, Schlüssellänge, Owner/User-Passwort-Status.
"""
from __future__ import annotations
from pathlib import Path
from typing import Optional, Dict, Any

import pikepdf

from models.schemas import EncryptionResult, Anomaly, AnomalySeverity

# Verschlüsselungs-Algorithmen nach V + R Wert
_ALGO_MAP = {
    (1, 2): "RC4 40-bit (PDF 1.1)",
    (1, 3): "RC4 40-bit (PDF 1.2–1.3)",
    (2, 2): "RC4 variabel (PDF 1.3)",
    (2, 3): "RC4 128-bit (PDF 1.4)",
    (3, 3): "RC4 128-bit + Permissions (PDF 1.4)",
    (4, 4): "AES 128-bit (PDF 1.5)",
    (5, 5): "AES 256-bit (PDF 1.7 Ext. 3)",
    (5, 6): "AES 256-bit (PDF 2.0)",
}

_STRENGTH = {
    "RC4 40-bit":  "SCHWACH",
    "RC4 128-bit": "MITTEL",
    "AES 128-bit": "STARK",
    "AES 256-bit": "SEHR STARK",
}


def analyze_encryption(pdf_path: Path) -> EncryptionResult:
    anomalies: list[Anomaly] = []

    try:
        pdf = pikepdf.open(pdf_path, allow_overwriting_input=True)
    except pikepdf.PasswordError:
        # PDF ist verschlüsselt und braucht Passwort
        return EncryptionResult(
            is_encrypted=True,
            requires_password=True,
            anomalies=[Anomaly(
                severity=AnomalySeverity.HIGH,
                category="encryption",
                message="PDF ist passwortgeschützt — Inhalt kann nicht analysiert werden",
                detail="User-Passwort erforderlich",
            )]
        )
    except Exception as e:
        return EncryptionResult(anomalies=[
            Anomaly(severity=AnomalySeverity.HIGH, category="encryption",
                    message="PDF konnte nicht geöffnet werden", detail=str(e))
        ])

    with pdf:
        trailer = pdf.trailer

        if "/Encrypt" not in trailer:
            return EncryptionResult(is_encrypted=False, anomalies=anomalies)

        enc = trailer["/Encrypt"]
        is_encrypted = True
        requires_password = False

        # Algorithmus-Parameter
        v = int(enc.get("/V", 0))
        r = int(enc.get("/R", 0))
        length = int(enc.get("/Length", 40))

        algorithm = _ALGO_MAP.get((v, r), f"Unbekannt (V={v}, R={r})")

        # Stärke bestimmen
        strength = "UNBEKANNT"
        for key, val in _STRENGTH.items():
            if key.lower() in algorithm.lower():
                strength = val
                break

        # Permissions-Flags (P-Wert)
        p_value = int(enc.get("/P", -1))
        permissions = _decode_permissions(p_value) if p_value != -1 else None

        # O und U Hash (Owner/User Password Hash)
        owner_hash = _hex(enc.get("/O"))
        user_hash  = _hex(enc.get("/U"))

        # Metadata encrypted?
        encrypt_metadata = bool(enc.get("/EncryptMetadata", True))

        # Anomalien
        if "RC4" in algorithm:
            severity = AnomalySeverity.HIGH if "40-bit" in algorithm else AnomalySeverity.MEDIUM
            anomalies.append(Anomaly(
                severity=severity,
                category="encryption",
                message=f"Veralteter Verschlüsselungsalgorithmus: {algorithm}",
                detail="RC4 gilt als unsicher — AES sollte verwendet werden",
            ))

        if permissions and not permissions.get("print"):
            anomalies.append(Anomaly(
                severity=AnomalySeverity.INFO,
                category="encryption",
                message="Drucken ist im Dokument deaktiviert",
            ))

        if permissions and not permissions.get("copy"):
            anomalies.append(Anomaly(
                severity=AnomalySeverity.INFO,
                category="encryption",
                message="Kopieren von Text ist im Dokument deaktiviert",
            ))

        if not encrypt_metadata:
            anomalies.append(Anomaly(
                severity=AnomalySeverity.LOW,
                category="encryption",
                message="Metadaten sind NICHT verschlüsselt — XMP lesbar trotz Verschlüsselung",
            ))

    return EncryptionResult(
        is_encrypted=is_encrypted,
        requires_password=requires_password,
        algorithm=algorithm,
        key_length_bits=length,
        strength=strength,
        v_value=v,
        r_value=r,
        p_value=p_value,
        permissions=permissions,
        owner_hash=owner_hash,
        user_hash=user_hash,
        encrypt_metadata=encrypt_metadata,
        anomalies=anomalies,
    )


def _hex(val) -> Optional[str]:
    if val is None:
        return None
    try:
        return bytes(val).hex()
    except Exception:
        return str(val)


def _decode_permissions(p: int) -> Dict[str, bool]:
    """PDF /P Permissions-Bitmask dekodieren."""
    return {
        "print":            bool(p & (1 << 2)),
        "modify":           bool(p & (1 << 3)),
        "copy":             bool(p & (1 << 4)),
        "annotate":         bool(p & (1 << 5)),
        "fill_forms":       bool(p & (1 << 8)),
        "extract":          bool(p & (1 << 9)),
        "assemble":         bool(p & (1 << 10)),
        "print_highres":    bool(p & (1 << 11)),
    }
