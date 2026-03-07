"""
Virus-Scan Analyzer — ClamAV (lokal) + VirusTotal API (optional).

ClamAV:   Wird immer versucht. Wenn clamd nicht läuft → available=False, kein Fehler.
VirusTotal: Nur wenn VT_API_KEY in ENV gesetzt. SHA256-Hash wird zuerst geprüft
            (kein neuer Upload wenn Hash bekannt), erst dann hochgeladen.
"""
from __future__ import annotations

import time
import hashlib
import json
from pathlib import Path
from typing import Optional

from models.schemas import VirusScanResult, VirusScanEngine, Anomaly, AnomalySeverity
from config import VIRUSTOTAL_API_KEY, VIRUSTOTAL_API_URL, CLAMAV_SOCKET


# ---- ClamAV -----------------------------------------------------------------

def _scan_clamav(pdf_path: Path) -> VirusScanEngine:
    engine = VirusScanEngine(name="ClamAV")
    try:
        import pyclamd  # type: ignore
        t0 = time.monotonic()
        try:
            cd = pyclamd.ClamdUnixSocket(filename=CLAMAV_SOCKET)
            cd.ping()
        except Exception:
            # Fallback: TCP (Windows / Docker)
            try:
                cd = pyclamd.ClamdNetworkSocket(host="127.0.0.1", port=3310)
                cd.ping()
            except Exception as e:
                engine.available = False
                engine.error = f"clamd nicht erreichbar: {e}"
                return engine

        engine.available = True
        result = cd.scan_file(str(pdf_path))
        elapsed = int((time.monotonic() - t0) * 1000)
        engine.scan_duration_ms = elapsed
        engine.scanned = True

        if result is None:
            engine.clean = True
        else:
            # result = {filepath: ("FOUND", "Eicar-Test-Signature")} or ("ERROR", msg)
            for fpath, verdict in result.items():
                status, name = verdict
                if status == "FOUND":
                    engine.clean = False
                    engine.detections.append({
                        "scanner": "ClamAV",
                        "result":  name,
                        "file":    fpath,
                    })
                elif status == "ERROR":
                    engine.error = name

    except ImportError:
        engine.available = False
        engine.error = "ClamAV nicht installiert"
    except Exception as e:
        engine.available = False
        engine.error = str(e)

    return engine


# ---- VirusTotal -------------------------------------------------------------

def _sha256_file(pdf_path: Path) -> str:
    h = hashlib.sha256()
    with open(pdf_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _scan_virustotal(pdf_path: Path, sha256: str) -> VirusScanEngine:
    engine = VirusScanEngine(name="VirusTotal", available=True)
    if not VIRUSTOTAL_API_KEY:
        engine.available = False
        engine.error = "VT_API_KEY nicht konfiguriert"
        return engine

    try:
        import urllib.request
        import urllib.error

        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        t0 = time.monotonic()

        # 1. Hash-Lookup (keine neue Submission wenn bereits bekannt)
        req = urllib.request.Request(
            f"{VIRUSTOTAL_API_URL}/files/{sha256}",
            headers=headers,
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
            upload_needed = False
        except urllib.error.HTTPError as e:
            if e.code == 404:
                upload_needed = True
                data = None
            else:
                raise

        # 2. Datei hochladen wenn noch nicht bekannt
        if upload_needed:
            file_size = pdf_path.stat().st_size
            # Dateien > 32MB brauchen Upload-URL (nicht im Free-Tier verfügbar)
            if file_size > 32 * 1024 * 1024:
                engine.error = "Datei >32MB: VirusTotal Free-Tier unterstützt keine großen Uploads"
                engine.scanned = False
                return engine

            import email.mime.multipart
            boundary = b"----FormBoundary7MA4YWxk"
            body = (
                b"--" + boundary + b"\r\n"
                b'Content-Disposition: form-data; name="file"; filename="upload.pdf"\r\n'
                b"Content-Type: application/pdf\r\n\r\n" +
                pdf_path.read_bytes() +
                b"\r\n--" + boundary + b"--\r\n"
            )
            upload_req = urllib.request.Request(
                f"{VIRUSTOTAL_API_URL}/files",
                data=body,
                headers={
                    **headers,
                    "Content-Type": f"multipart/form-data; boundary={boundary.decode()}",
                },
                method="POST",
            )
            with urllib.request.urlopen(upload_req, timeout=60) as resp:
                upload_resp = json.loads(resp.read())

            analysis_id = upload_resp.get("data", {}).get("id")
            if not analysis_id:
                engine.error = "Kein analysis_id in VT-Antwort"
                return engine

            # Auf Analyse warten (max 60s, alle 5s pollen)
            for _ in range(12):
                time.sleep(5)
                poll_req = urllib.request.Request(
                    f"{VIRUSTOTAL_API_URL}/analyses/{analysis_id}",
                    headers=headers,
                )
                with urllib.request.urlopen(poll_req, timeout=15) as resp:
                    poll_data = json.loads(resp.read())
                status = poll_data.get("data", {}).get("attributes", {}).get("status")
                if status == "completed":
                    # Jetzt den File-Report holen
                    req2 = urllib.request.Request(
                        f"{VIRUSTOTAL_API_URL}/files/{sha256}",
                        headers=headers,
                    )
                    with urllib.request.urlopen(req2, timeout=15) as resp:
                        data = json.loads(resp.read())
                    break
            else:
                engine.error = "VirusTotal-Analyse Timeout (>60s)"
                engine.scanned = False
                return engine

        # Ergebnis auswerten
        engine.scanned = True
        engine.scan_duration_ms = int((time.monotonic() - t0) * 1000)

        attrs     = data.get("data", {}).get("attributes", {})
        stats     = attrs.get("last_analysis_stats", {})
        results   = attrs.get("last_analysis_results", {})

        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total      = sum(stats.values()) if stats else 0

        engine.clean = (malicious == 0 and suspicious == 0)

        for scanner_name, scan_result in results.items():
            cat = scan_result.get("category", "")
            if cat in ("malicious", "suspicious"):
                engine.detections.append({
                    "scanner": scanner_name,
                    "result":  scan_result.get("result") or cat,
                    "category": cat,
                })

        # Zusammenfassung
        engine.detections.insert(0, {
            "summary": f"{malicious} malicious, {suspicious} suspicious von {total} Engines"
        })

    except Exception as e:
        engine.available = True
        engine.scanned = False
        engine.error = str(e)

    return engine


# ---- Haupt-Funktion ---------------------------------------------------------

def analyze_virus_scan(pdf_path: Path, sha256: Optional[str] = None) -> VirusScanResult:
    if sha256 is None:
        sha256 = _sha256_file(pdf_path)

    anomalies: list[Anomaly] = []
    engines = []

    # ClamAV
    clam = _scan_clamav(pdf_path)
    engines.append(clam)

    # VirusTotal (nur wenn API-Key vorhanden)
    vt: Optional[VirusScanEngine] = None
    if VIRUSTOTAL_API_KEY:
        vt = _scan_virustotal(pdf_path, sha256)
        engines.append(vt)

    # Anomalien aggregieren
    total_detections = 0
    is_clean = True

    for eng in engines:
        if not eng.scanned:
            continue
        det_count = len([d for d in eng.detections if "scanner" in d])
        total_detections += det_count
        if not eng.clean:
            is_clean = False
            anomalies.append(Anomaly(
                severity=AnomalySeverity.HIGH,
                category="virus_scan",
                message=f"{eng.name}: {det_count} Treffer — Datei als schädlich eingestuft!",
                detail=", ".join(
                    d.get("result", d.get("category", "?"))
                    for d in eng.detections
                    if "scanner" in d
                )[:300],
            ))

    # VirusTotal-URL für direkten Link
    vt_url = f"https://www.virustotal.com/gui/file/{sha256}" if VIRUSTOTAL_API_KEY else None

    return VirusScanResult(
        is_clean=is_clean,
        total_detections=total_detections,
        engines=engines,
        sha256=sha256,
        virustotal_url=vt_url,
        anomalies=anomalies,
    )
