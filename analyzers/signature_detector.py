"""
Digitale Signaturen erkennen: /AcroForm, /Sig, /DocMDP.
Zertifikat-Details via pyhanko (Aussteller, Gültigkeit, Fingerprint).
"""
from __future__ import annotations
from pathlib import Path
from typing import List, Optional, Dict, Any

import pikepdf

from models.schemas import SignatureInfo, Anomaly, AnomalySeverity


def _extract_cert_info(pdf_path: Path) -> Optional[Dict[str, Any]]:
    """Versucht Zertifikat-Details aus /Sig-Feldern via pyhanko zu lesen."""
    try:
        from pyhanko.pdf_utils.reader import PdfFileReader
        from pyhanko.sign.validation import validate_pdf_signature
        from pyhanko_certvalidator import CertificateValidator
        import io

        with open(pdf_path, "rb") as f:
            reader = PdfFileReader(f)
            sigs = reader.embedded_signatures
            if not sigs:
                return None

            results = []
            for sig in sigs:
                try:
                    info: Dict[str, Any] = {}
                    sd = sig.signed_data
                    cert = sd.cert
                    info["subject"] = str(cert.subject.human_friendly) if hasattr(cert.subject, "human_friendly") else str(cert.subject)
                    info["issuer"]  = str(cert.issuer.human_friendly)  if hasattr(cert.issuer, "human_friendly")  else str(cert.issuer)
                    info["serial"]  = str(cert.serial_number)
                    info["not_valid_before"] = str(cert["tbs_certificate"]["validity"]["not_before"].native)
                    info["not_valid_after"]  = str(cert["tbs_certificate"]["validity"]["not_after"].native)
                    # SHA-1 Fingerprint
                    import hashlib
                    info["fingerprint_sha1"] = hashlib.sha1(cert.dump()).hexdigest()
                    info["sig_field_name"] = sig.field_name
                    results.append(info)
                except Exception:
                    continue

            return {"certificates": results} if results else None
    except Exception:
        return None


def analyze_signatures(pdf_path: Path) -> SignatureInfo:
    anomalies: list[Anomaly] = []

    try:
        pdf = pikepdf.open(pdf_path)
    except Exception as e:
        return SignatureInfo(anomalies=[
            Anomaly(severity=AnomalySeverity.HIGH, category="signature",
                    message="PDF konnte nicht geöffnet werden", detail=str(e))
        ])

    with pdf:
        has_acroform = False
        has_sig_field = False
        has_doc_mdp = False
        sig_field_names: List[str] = []

        catalog = pdf.Root
        if "/AcroForm" in catalog:
            has_acroform = True
            acroform = catalog["/AcroForm"]
            fields = acroform.get("/Fields", [])
            for field_ref in fields:
                try:
                    field = field_ref
                    ft = str(field.get("/FT", ""))
                    t  = str(field.get("/T", ""))
                    if ft == "/Sig":
                        has_sig_field = True
                        sig_field_names.append(t)
                except Exception:
                    continue

        if "/Perms" in catalog:
            perms = catalog["/Perms"]
            if "/DocMDP" in perms:
                has_doc_mdp = True

        try:
            for obj in pdf.objects:
                try:
                    if hasattr(obj, "keys") and "/DocMDP" in obj:
                        has_doc_mdp = True
                        break
                except Exception:
                    continue
        except Exception:
            pass

        if has_sig_field and not has_acroform:
            anomalies.append(Anomaly(
                severity=AnomalySeverity.HIGH,
                category="signature",
                message="Signatur-Feld gefunden, aber kein /AcroForm vorhanden — inkonsistentes Dokument",
            ))

        if has_doc_mdp and not has_sig_field:
            anomalies.append(Anomaly(
                severity=AnomalySeverity.MEDIUM,
                category="signature",
                message="/DocMDP vorhanden, aber kein Signatur-Feld — Zertifizierungssignatur möglicherweise entfernt",
            ))

        if has_sig_field:
            anomalies.append(Anomaly(
                severity=AnomalySeverity.INFO,
                category="signature",
                message=f"Dokument enthält {len(sig_field_names)} Signatur-Feld(er)",
                detail=", ".join(sig_field_names) if sig_field_names else None,
            ))

    # Zertifikat-Details via pyhanko
    cert_info = _extract_cert_info(pdf_path)

    if cert_info:
        for cert in cert_info.get("certificates", []):
            # Zertifikat abgelaufen?
            try:
                from datetime import datetime, timezone
                not_after = cert.get("not_valid_after", "")
                if not_after:
                    exp = datetime.fromisoformat(str(not_after).replace("Z", "+00:00"))
                    if exp < datetime.now(timezone.utc):
                        anomalies.append(Anomaly(
                            severity=AnomalySeverity.HIGH,
                            category="signature",
                            message=f"Signatur-Zertifikat abgelaufen: {cert.get('subject', '?')}",
                            detail=f"Gültig bis: {not_after}",
                        ))
            except Exception:
                pass

    return SignatureInfo(
        has_acroform=has_acroform,
        has_sig_field=has_sig_field,
        has_doc_mdp=has_doc_mdp,
        sig_field_names=sig_field_names,
        cert_info=cert_info,
        anomalies=anomalies,
    )
