"""
YARA Rule Scanner — Scannt PDF-Bytes gegen bekannte Malware-/Exploit-Signaturen.
Enthält eingebaute Regeln für PDF-spezifische Bedrohungen.
"""

from pathlib import Path
from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

# ---- Eingebaute YARA-Regeln für PDF-Forensik --------------------------------

BUILTIN_RULES_SOURCE = r"""
rule PDF_JavaScript_Obfuscation {
    meta:
        description = "Obfuscated JavaScript in PDF"
        severity = "HIGH"
        category = "malware"
    strings:
        $eval = "eval(" ascii nocase
        $unescape = "unescape(" ascii nocase
        $fromcharcode = "fromCharCode" ascii nocase
        $settimeout = "setTimeout(" ascii nocase
        $activex = "ActiveXObject" ascii nocase
        $shellexec = "Shell.Execute" ascii nocase
        $wscript = "WScript.Shell" ascii nocase
        $powershell = "powershell" ascii nocase
    condition:
        2 of them
}

rule PDF_Exploit_CVE_Patterns {
    meta:
        description = "Known PDF exploit CVE patterns"
        severity = "CRITICAL"
        category = "exploit"
    strings:
        $cve1 = "collectEmailInfo" ascii nocase
        $cve2 = "getAnnots" ascii nocase
        $cve3 = "getIcon" ascii nocase
        $cve4 = "spell.customDictionaryOpen" ascii nocase
        $cve5 = "media.newPlayer" ascii nocase
        $cve6 = "Collab.collectEmailInfo" ascii nocase
        $cve7 = "util.printf" ascii nocase
        $cve8 = "app.doc.Collab" ascii nocase
    condition:
        any of them
}

rule PDF_Suspicious_Streams {
    meta:
        description = "Suspicious encoded/compressed content"
        severity = "MEDIUM"
        category = "evasion"
    strings:
        $jbig2 = "/JBIG2Decode" ascii
        $crypt = "/Crypt" ascii
        $double_flate = "/FlateDecode/FlateDecode" ascii
        $asciihex = "/ASCIIHexDecode" ascii
        $ascii85 = "/ASCII85Decode" ascii
        $runlen = "/RunLengthDecode" ascii
    condition:
        2 of them
}

rule PDF_Embedded_Executable {
    meta:
        description = "Embedded executable content in PDF"
        severity = "CRITICAL"
        category = "malware"
    strings:
        $mz = { 4D 5A }
        $elf = { 7F 45 4C 46 }
        $pe = "This program cannot be run in DOS mode"
        $bat = "@echo off" ascii nocase
        $ps1 = "-ExecutionPolicy Bypass" ascii nocase
        $vbs = "CreateObject" ascii nocase
    condition:
        any of them
}

rule PDF_Phishing_Indicators {
    meta:
        description = "Phishing indicators in PDF"
        severity = "MEDIUM"
        category = "phishing"
    strings:
        $login = /https?:\/\/[a-z0-9\-\.]+\.(tk|ml|ga|cf|gq|xyz|top|buzz|club)\//
        $shortener1 = "bit.ly/" ascii nocase
        $shortener2 = "tinyurl.com/" ascii nocase
        $shortener3 = "t.co/" ascii nocase
        $form_action = /\/URI\s*\(https?:\/\//
        $submit_form = "/SubmitForm" ascii
    condition:
        2 of them
}

rule PDF_Shellcode_Patterns {
    meta:
        description = "Potential shellcode in PDF streams"
        severity = "CRITICAL"
        category = "exploit"
    strings:
        $nopsled = { 90 90 90 90 90 90 90 90 }
        $heap_spray = { 0C 0C 0C 0C 0C 0C 0C 0C }
        $int80 = { CD 80 }
        $syscall = { 0F 05 }
    condition:
        any of them
}

rule PDF_Suspicious_Launch {
    meta:
        description = "Launch action to execute external program"
        severity = "HIGH"
        category = "malware"
    strings:
        $launch = "/Launch" ascii
        $action = "/Action" ascii
        $cmd = "cmd.exe" ascii nocase
        $open = "/OpenAction" ascii
    condition:
        ($launch and $action) or ($cmd) or ($open and $launch)
}

rule PDF_Data_Exfiltration {
    meta:
        description = "Potential data exfiltration via PDF"
        severity = "HIGH"
        category = "exfiltration"
    strings:
        $submit = "/SubmitForm" ascii
        $uri = "/URI" ascii
        $importdata = "/ImportData" ascii
        $gotor = "/GoToR" ascii
        $launch = "/Launch" ascii
    condition:
        ($submit and $uri) or $importdata or ($gotor and $uri) or ($launch and $uri)
}
"""


def analyze_yara(pdf_path: Path) -> Dict[str, Any]:
    """Scannt PDF mit YARA-Regeln."""
    result = {
        "available": False,
        "rules_loaded": 0,
        "matches": [],
        "total_matches": 0,
        "critical_matches": 0,
        "high_matches": 0,
        "medium_matches": 0,
        "anomalies": [],
    }

    try:
        import yara
    except ImportError:
        logger.warning("yara-python nicht installiert")
        result["error"] = "yara-python not installed"
        return result

    try:
        # Eingebaute Regeln kompilieren
        rules = yara.compile(source=BUILTIN_RULES_SOURCE)
        result["available"] = True
        result["rules_loaded"] = 8  # Anzahl der eingebauten Regeln

        # Externe Regeln laden falls vorhanden
        rules_dir = pdf_path.parent / "yara_rules"
        external_count = 0
        all_rules = [rules]

        if rules_dir.exists():
            for rule_file in rules_dir.glob("*.yar"):
                try:
                    ext_rule = yara.compile(filepath=str(rule_file))
                    all_rules.append(ext_rule)
                    external_count += 1
                except Exception as e:
                    logger.warning(f"YARA-Regel {rule_file.name} fehlerhaft: {e}")

            result["rules_loaded"] += external_count

        # PDF-Datei scannen
        pdf_data = pdf_path.read_bytes()

        for rule_set in all_rules:
            matches = rule_set.match(data=pdf_data)
            for match in matches:
                severity = "MEDIUM"
                category = "unknown"
                description = match.rule

                # Meta-Daten extrahieren
                if hasattr(match, "meta"):
                    severity = match.meta.get("severity", "MEDIUM")
                    category = match.meta.get("category", "unknown")
                    description = match.meta.get("description", match.rule)

                match_strings = []
                for offset, identifier, data in match.strings:
                    try:
                        decoded = data.decode("utf-8", errors="replace")[:100]
                    except Exception:
                        decoded = data.hex()[:100]
                    match_strings.append({
                        "offset": offset,
                        "identifier": identifier if isinstance(identifier, str) else str(identifier),
                        "data_preview": decoded,
                    })

                match_entry = {
                    "rule": match.rule,
                    "description": description,
                    "severity": severity,
                    "category": category,
                    "matched_strings": match_strings[:10],
                    "string_count": len(match_strings),
                }
                result["matches"].append(match_entry)

                if severity == "CRITICAL":
                    result["critical_matches"] += 1
                elif severity == "HIGH":
                    result["high_matches"] += 1
                else:
                    result["medium_matches"] += 1

        result["total_matches"] = len(result["matches"])

        # Anomalien erzeugen
        for m in result["matches"]:
            sev = m["severity"]
            if sev == "CRITICAL":
                anom_sev = "HIGH"
            elif sev == "HIGH":
                anom_sev = "HIGH"
            else:
                anom_sev = "MEDIUM"

            result["anomalies"].append({
                "severity": anom_sev,
                "category": "YARA",
                "message": f"YARA: {m['description']}",
                "detail": f"Rule: {m['rule']}, Category: {m['category']}, Strings: {m['string_count']}",
            })

    except Exception as e:
        logger.error(f"YARA-Scan fehlgeschlagen: {e}")
        result["error"] = str(e)

    return result
