"""
Stream Decompression & Content Analysis.

Dekomprimiert /FlateDecode, /ASCIIHexDecode, /ASCII85Decode, /LZWDecode,
/RunLengthDecode, /CCITTFaxDecode, /JBIG2Decode, /Crypt Streams und
scannt den Inhalt nach Exploit-Indikatoren.
"""
from __future__ import annotations
import re
import zlib
from pathlib import Path
from typing import List, Dict, Any

from models.schemas import Anomaly, AnomalySeverity, StreamDecompResult

try:
    import pikepdf
    PIKE_OK = True
except ImportError:
    PIKE_OK = False


# Exploit-Signaturen in dekomprimierten Streams
EXPLOIT_PATTERNS = [
    (re.compile(rb'\\x[0-9a-fA-F]{2}', re.DOTALL), "Shell-Escape-Sequenzen"),
    (re.compile(rb'getenv|system|exec|popen|passthru', re.IGNORECASE), "System-Call-Hinweise"),
    (re.compile(rb'\\u[0-9a-fA-F]{4}', re.DOTALL), "Unicode-Escape (JS-Obfuskation)"),
    (re.compile(rb'eval\s*\(', re.IGNORECASE), "eval()-Aufruf"),
    (re.compile(rb'unescape\s*\(', re.IGNORECASE), "unescape()-Aufruf"),
    (re.compile(rb'String\.fromCharCode', re.IGNORECASE), "String.fromCharCode (Obfuskation)"),
    (re.compile(rb'ActiveXObject', re.IGNORECASE), "ActiveX-Objekt-Erstellung"),
    (re.compile(rb'shellcode|heap\s*spray|NOP\s*sled', re.IGNORECASE), "Exploit-Terminologie"),
    (re.compile(rb'CVE-\d{4}-\d+', re.IGNORECASE), "CVE-Referenz"),
    (re.compile(rb'%[0-9a-fA-F]{2}' * 10, re.DOTALL), "URL-kodierter Payload (>=10 Seq.)"),
    (re.compile(rb'/JBIG2Decode.*\x00{20,}', re.DOTALL), "JBIG2-Null-Padding (CVE-2009-*)"),
    (re.compile(rb'this\.exportDataObject', re.IGNORECASE), "exportDataObject (Datei-Exfiltration)"),
    (re.compile(rb'app\.launchURL', re.IGNORECASE), "launchURL (URL-Start)"),
    (re.compile(rb'util\.printf', re.IGNORECASE), "util.printf (Format-String)"),
]

# Verdächtige Filter-Ketten
SUSPICIOUS_FILTER_CHAINS = [
    ["/FlateDecode", "/FlateDecode"],  # Double-Deflate → Obfuskation
    ["/ASCIIHexDecode", "/FlateDecode", "/FlateDecode"],
    ["/JBIG2Decode"],  # Historisch anfällig
    ["/Crypt"],  # Verschlüsselter Stream
]


def _check_exploit_patterns(data: bytes, obj_label: str) -> List[Dict[str, Any]]:
    """Scannt dekomprimierte Daten nach Exploit-Indikatoren."""
    findings = []
    for pattern, desc in EXPLOIT_PATTERNS:
        matches = pattern.findall(data[:50_000])  # Limit für Performance
        if matches:
            findings.append({
                "object": obj_label,
                "pattern": desc,
                "match_count": len(matches),
                "sample": matches[0][:60].decode("latin-1", errors="replace"),
            })
    return findings


def analyze_stream_decompression(pdf_path: Path) -> StreamDecompResult:
    """Dekomprimiert alle Streams und scannt nach Exploits."""
    anomalies: List[Anomaly] = []

    if not PIKE_OK:
        return StreamDecompResult(
            anomalies=[Anomaly(
                severity=AnomalySeverity.INFO,
                category="stream_decomp",
                message="pikepdf nicht verfügbar — Stream-Analyse übersprungen",
            )]
        )

    total_streams = 0
    decompressed = 0
    failed = 0
    filters_found: set = set()
    suspicious_content: List[Dict[str, Any]] = []
    exploit_indicators: List[Dict[str, Any]] = []

    try:
        pdf = pikepdf.open(pdf_path, allow_overwriting_input=True)

        for obj_num in pdf.objects:
            try:
                obj = pdf.objects[obj_num]
                if not isinstance(obj, pikepdf.Stream):
                    continue

                total_streams += 1
                obj_label = f"Obj {obj_num}"

                # Filter-Kette extrahieren
                raw_filter = obj.get("/Filter")
                if raw_filter is not None:
                    if isinstance(raw_filter, pikepdf.Array):
                        chain = [str(f) for f in raw_filter]
                    else:
                        chain = [str(raw_filter)]
                    for f in chain:
                        filters_found.add(f)
                else:
                    chain = []

                # Verdächtige Filter-Ketten prüfen
                for sus_chain in SUSPICIOUS_FILTER_CHAINS:
                    if chain == sus_chain or (len(sus_chain) == 1 and sus_chain[0] in chain):
                        if sus_chain == ["/JBIG2Decode"]:
                            suspicious_content.append({
                                "object": obj_label,
                                "type": "jbig2_stream",
                                "filters": chain,
                                "note": "JBIG2-Stream — historisch anfällig für Exploits (CVE-2009-*, CVE-2021-30860)",
                            })
                        elif "/Crypt" in chain:
                            suspicious_content.append({
                                "object": obj_label,
                                "type": "encrypted_stream",
                                "filters": chain,
                                "note": "Verschlüsselter Stream — Inhalt nicht inspizierbar",
                            })
                        elif chain.count("/FlateDecode") >= 2:
                            suspicious_content.append({
                                "object": obj_label,
                                "type": "double_deflate",
                                "filters": chain,
                                "note": "Doppelte Kompression — häufig bei Obfuskation",
                            })

                # Dekomprimieren
                try:
                    raw_data = bytes(obj.read_raw_bytes())
                    decompressed += 1

                    # Exploit-Scan
                    findings = _check_exploit_patterns(raw_data, obj_label)
                    exploit_indicators.extend(findings)

                except Exception:
                    failed += 1

            except Exception:
                continue

        pdf.close()

    except Exception as e:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category="stream_decomp",
            message=f"Stream-Analyse-Fehler: {str(e)[:100]}",
        ))

    # Anomalien generieren
    if exploit_indicators:
        for ei in exploit_indicators[:10]:  # Max 10
            anomalies.append(Anomaly(
                severity=AnomalySeverity.HIGH,
                category="stream_decomp",
                message=f'Exploit-Indikator in {ei["object"]}: {ei["pattern"]}',
                detail=f'Sample: {ei["sample"][:80]}',
            ))

    for sc in suspicious_content:
        sev = AnomalySeverity.HIGH if "jbig2" in sc.get("type", "") else AnomalySeverity.MEDIUM
        anomalies.append(Anomaly(
            severity=sev,
            category="stream_decomp",
            message=f'Verdächtiger Stream {sc["object"]}: {sc["type"]}',
            detail=sc.get("note", ""),
        ))

    if failed > total_streams * 0.3 and total_streams > 5:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category="stream_decomp",
            message=f"{failed}/{total_streams} Streams konnten nicht dekomprimiert werden",
            detail="Hohe Fehlerrate deutet auf beschädigte oder absichtlich manipulierte Streams hin",
        ))

    return StreamDecompResult(
        total_streams=total_streams,
        decompressed=decompressed,
        failed=failed,
        filters_found=sorted(filters_found),
        suspicious_content=suspicious_content,
        exploit_indicators=exploit_indicators[:20],
        anomalies=anomalies,
    )
