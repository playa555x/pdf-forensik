"""
mpeepdf Wrapper.

mpeepdf (https://github.com/Tholep/mpeepdf) ist ein aktiver Python-3-Fork
von peepdf mit JSON-Output-Mode und neueren CVE-Signaturen fuer:
- /JBIG2Decode  (CVE-2009-0658, etc.)
- /Launch       (CVE-2010-1240)
- /JS Heap-Spray (CVE-2008-2992)
- /JBIG2 Pattern, /XFA-Forms, /AcroForm-Submit
- Embedded Flash, OLE-in-PDF
- Encryption-Downgrade-Attacks
- Suspicious Filters Pipeline (e.g. /ASCII85Decode/FlateDecode obfuscation)

Output: JSON von `mpeepdf -j file.pdf` -> Vulnerabilities, Suspicious Elements,
Encryption-Indikatoren, Object-Counts.
"""
from __future__ import annotations
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List

from models.schemas import Anomaly, AnomalySeverity, MpeepdfResult


def _run_mpeepdf(pdf_path: Path) -> Dict[str, Any]:
    if shutil.which("peepdf"):
        cmd = ["peepdf", "-j", "-f", str(pdf_path)]
    elif shutil.which("mpeepdf"):
        cmd = ["mpeepdf", "-j", "-f", str(pdf_path)]
    else:
        return {"error": "peepdf/mpeepdf not installed"}

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        out = proc.stdout.strip()
        if not out:
            return {"error": "empty output", "stderr": proc.stderr[:300]}
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return {"raw_output": out[:4000], "stderr": proc.stderr[:300]}
    except subprocess.TimeoutExpired:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)}


def _walk_for_key(obj: Any, key: str) -> List[Any]:
    """Recursively collect all values under a given key in nested dicts/lists."""
    found: List[Any] = []
    if isinstance(obj, dict):
        if key in obj:
            v = obj[key]
            if isinstance(v, list):
                found.extend(v)
            else:
                found.append(v)
        for v in obj.values():
            found.extend(_walk_for_key(v, key))
    elif isinstance(obj, list):
        for v in obj:
            found.extend(_walk_for_key(v, key))
    return found


def analyze_mpeepdf(pdf_path: Path) -> MpeepdfResult:
    """
    Korrektes peepdf-Schema (verifiziert via Live-Run):
      peepdf_analysis.basic.{encrypted, encryption_algorithms, linearized, errors, detection}
      peepdf_analysis.advanced[].version_info.{
          suspicious_elements.{actions, elements, js_vulns, triggers, urls},
          error_objects, decoding_error_streams, js_objects, ...
      }
    """
    raw = _run_mpeepdf(pdf_path)
    anomalies: List[Anomaly] = []

    if "error" in raw and "raw_output" not in raw:
        return MpeepdfResult(raw=raw, error=raw["error"], anomalies=[])

    root = raw.get("peepdf_analysis", {}) or {}
    basic = root.get("basic", {}) or {}
    versions = root.get("advanced", []) or []

    suspicious_actions: List[str] = []
    suspicious_elements_list: List[str] = []
    js_vulns: List[str] = []
    triggers: List[str] = []
    urls: List[str] = []

    for v in versions:
        vi = v.get("version_info", {}) or {}
        se = vi.get("suspicious_elements") or {}

        # actions: dict {"/JS": [5], "/JavaScript": [5]}
        for k, objs in (se.get("actions") or {}).items():
            suspicious_actions.append(f"action {k} -> objs={objs}")

        # elements: list [{"name":"/EmbeddedFile","objects":[7]}]
        for el in (se.get("elements") or []):
            name = el.get("name") if isinstance(el, dict) else str(el)
            objs = el.get("objects") if isinstance(el, dict) else None
            suspicious_elements_list.append(f"{name} obj={objs}")

        # js_vulns: list of CVE-like signatures from peepdf's JS analyzer
        for jv in (se.get("js_vulns") or []):
            js_vulns.append(str(jv))

        # triggers: dict {"/OpenAction": [1], "/AcroForm": [1]}
        for k, objs in (se.get("triggers") or {}).items():
            triggers.append(f"{k} -> objs={objs}")

        for u in (se.get("urls") or []):
            urls.append(str(u))

        # error/decoding streams = anti-forensics smell
        err_objs = vi.get("error_objects") or []
        dec_err = vi.get("decoding_error_streams") or []
        if err_objs or dec_err:
            anomalies.append(Anomaly(
                severity=AnomalySeverity.MEDIUM,
                category="mpeepdf_decode_error",
                message=f"Version {vi.get('version_number','?')}: error/decoding streams gefunden",
                detail=f"errors={err_objs[:8]} decoding_errors={dec_err[:8]}",
            ))

    # Encryption
    encryption_info: List[str] = []
    # peepdf basic.encrypted ist false-positive-anfaellig: oft true bei non-encrypted PDFs
    # Nur melden wenn Encryption-Algorithms tatsaechlich vorhanden
    algos = basic.get("encryption_algorithms") or []
    if basic.get("encrypted") and algos:
        encryption_info.append(f"algorithms={algos}")
        anomalies.append(Anomaly(
            severity=AnomalySeverity.LOW,
            category="mpeepdf_encrypted",
            message=f"PDF ist verschluesselt (algorithms: {algos})",
            detail=f"Verschluesselung: {algos}",
        ))

    if js_vulns:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.HIGH,
            category="mpeepdf_js_cve",
            message=f"{len(js_vulns)} JavaScript-Vulnerability-Signature(n) (peepdf js_vulns)",
            detail=f"{js_vulns[:5]}",
        ))

    if triggers:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.HIGH,
            category="mpeepdf_auto_trigger",
            message=f"Auto-Execute-Trigger: {len(triggers)} gefunden",
            detail=f"{triggers[:5]}",
        ))

    if suspicious_actions:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.HIGH,
            category="mpeepdf_suspicious_action",
            message=f"{len(suspicious_actions)} verdaechtige Action(s) (z.B. /JS, /Launch)",
            detail=f"{suspicious_actions[:5]}",
        ))

    if suspicious_elements_list:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category="mpeepdf_suspicious_element",
            message=f"{len(suspicious_elements_list)} verdaechtige Element(e)",
            detail=f"{suspicious_elements_list[:5]}",
        ))

    return MpeepdfResult(
        raw=raw,
        vulnerabilities=js_vulns[:50],
        suspicious_elements=(suspicious_actions + suspicious_elements_list + triggers)[:50],
        cve_references=js_vulns[:50],   # peepdf's js_vulns ARE CVE identifiers
        encryption_info=encryption_info[:20],
        anomalies=anomalies,
    )
