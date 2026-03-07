"""
JavaScript / Action Analyzer.
Erkennt /JS, /OpenAction, /AA, /Launch, /URI, /SubmitForm — Exploit-Vektoren.
"""
from __future__ import annotations
import re
from pathlib import Path
from typing import List, Dict, Any

import pikepdf
from pikepdf import Dictionary, Stream

from models.schemas import JavaScriptResult, Anomaly, AnomalySeverity


def _is_dict_like(obj) -> bool:
    """True wenn das pikepdf-Objekt ein Dictionary oder Stream ist (hat .get())."""
    return isinstance(obj, (Dictionary, Stream))

# Gefährliche Action-Typen
_DANGEROUS_ACTIONS = {
    "/Launch":       ("HIGH",   "Startet externe Anwendungen — klassischer Exploit-Vektor"),
    "/JS":           ("HIGH",   "JavaScript-Code eingebettet"),
    "/JavaScript":   ("HIGH",   "JavaScript-Code eingebettet"),
    "/SubmitForm":   ("MEDIUM", "Sendet Formulardaten an externe URL"),
    "/ImportData":   ("MEDIUM", "Importiert externe Daten in das PDF"),
    "/RichMedia":    ("MEDIUM", "Rich Media (Flash/Video) eingebettet"),
    "/Sound":        ("LOW",    "Audio-Objekt eingebettet"),
    "/Movie":        ("LOW",    "Video-Objekt eingebettet"),
    "/GoToR":        ("LOW",    "Link zu externer Datei"),
    "/URI":          ("INFO",   "Externer URL-Link"),
}

# Regex für obfuskierten JavaScript-Code
_OBFUSCATION_PATTERNS = [
    (rb"eval\s*\(", "eval() — mögliche Code-Obfuskation"),
    (rb"unescape\s*\(", "unescape() — häufig bei Exploit-Code"),
    (rb"String\.fromCharCode", "fromCharCode — Byte-Level-Obfuskation"),
    (rb"\\u[0-9a-fA-F]{4}", "Unicode-Escape-Sequenzen"),
    (rb"%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}", "URL-Encoding in JS"),
]


def _extract_js_content(obj) -> str:
    """Versucht JS-Inhalt aus einem pikepdf-Objekt zu lesen."""
    try:
        if hasattr(obj, "read_bytes"):
            raw = bytes(obj.read_bytes())
            return raw.decode("utf-8", errors="replace")[:2000]
        return str(obj)[:2000]
    except Exception:
        return ""


def analyze_javascript(pdf_path: Path) -> JavaScriptResult:
    anomalies: list[Anomaly] = []
    found_actions: List[Dict[str, Any]] = []
    js_snippets:   List[Dict[str, Any]] = []

    try:
        pdf = pikepdf.open(pdf_path)
    except Exception as e:
        return JavaScriptResult(anomalies=[
            Anomaly(severity=AnomalySeverity.HIGH, category="javascript",
                    message="PDF konnte nicht geöffnet werden", detail=str(e))
        ])

    with pdf:
        # 1. /OpenAction im Catalog prüfen (auto-execute beim Öffnen)
        catalog = pdf.Root
        if "/OpenAction" in catalog:
            action = catalog["/OpenAction"]
            action_type = str(action.get("/S", "unbekannt")) if _is_dict_like(action) else "unbekannt"

            # Rohe Aktion vollständig dumpen für Forensik
            raw_action_dump = _dump_action(action)

            found_actions.append({
                "location": "/Catalog /OpenAction",
                "type": action_type,
                "auto_execute": True,
                "raw_dump": raw_action_dump,
            })

            sev, desc = _DANGEROUS_ACTIONS.get(action_type, ("LOW", "Unbekannte Aktion"))
            detail_msg = "Wird automatisch beim Öffnen des PDFs ausgeführt!"
            if action_type == "unbekannt" and raw_action_dump:
                detail_msg += f" Rohdaten: {raw_action_dump[:300]}"

            anomalies.append(Anomaly(
                severity=AnomalySeverity(sev),
                category="javascript",
                message=f"Auto-Execute beim Öffnen: {action_type} — {desc}",
                detail=detail_msg,
            ))

            # JS-Inhalt extrahieren
            if action_type in ("/JS", "/JavaScript"):
                js_str = _extract_js_str(action)
                if js_str:
                    js_snippets.append({"location": "/OpenAction", "code": js_str[:500]})
                    _check_obfuscation(js_str.encode(), "/OpenAction", anomalies)

        # 2. /AA (Additional Actions) im Catalog
        if "/AA" in catalog:
            aa = catalog["/AA"]
            for trigger in aa.keys():
                found_actions.append({
                    "location": f"/Catalog /AA {trigger}",
                    "type": str(aa[trigger].get("/S", "?")) if _is_dict_like(aa[trigger]) else "?",
                    "auto_execute": True,
                })
                anomalies.append(Anomaly(
                    severity=AnomalySeverity.MEDIUM,
                    category="javascript",
                    message=f"Dokument-Level Additional Action: {trigger}",
                ))

        # 3. Alle Seiten nach /AA und Annotations mit Actions durchsuchen
        for page_num, page in enumerate(pdf.pages):
            # Page-Level /AA
            if "/AA" in page:
                aa = page["/AA"]
                for trigger in aa.keys():
                    found_actions.append({
                        "location": f"Seite {page_num+1} /AA {trigger}",
                        "type": "page_action",
                        "auto_execute": True,
                    })
                    anomalies.append(Anomaly(
                        severity=AnomalySeverity.LOW,
                        category="javascript",
                        message=f"Seiten-Action auf Seite {page_num+1}: {trigger}",
                    ))

            # Annotations
            annots = page.get("/Annots", [])
            for annot in annots:
                try:
                    if "/A" in annot:
                        action = annot["/A"]
                        action_type = str(action.get("/S", "?"))
                        if action_type in _DANGEROUS_ACTIONS:
                            sev, desc = _DANGEROUS_ACTIONS[action_type]
                            found_actions.append({
                                "location": f"Seite {page_num+1} /Annot /A",
                                "type": action_type,
                                "auto_execute": False,
                            })
                            if action_type not in ("/URI", "/GoToR"):
                                anomalies.append(Anomaly(
                                    severity=AnomalySeverity(sev),
                                    category="javascript",
                                    message=f"Gefährliche Annotation-Action auf Seite {page_num+1}: {action_type}",
                                    detail=desc,
                                ))
                except Exception:
                    continue

        # 4. Namen-Dictionary nach JavaScript durchsuchen
        try:
            if "/Names" in catalog:
                names = catalog["/Names"]
                if "/JavaScript" in names:
                    js_names = names["/JavaScript"]
                    _scan_name_tree(js_names, js_snippets, anomalies)
        except Exception:
            pass

        # 5. Alle Objekte nach /Launch und /RichMedia scannen (Bulk-Scan)
        try:
            for obj in pdf.objects:
                try:
                    if not _is_dict_like(obj):
                        continue
                    obj_type = str(obj.get("/S", ""))
                    if obj_type == "/Launch":
                        f = obj.get("/F", obj.get("/Win", {}))
                        fname = str(f.get("/F", "?")) if _is_dict_like(f) else str(f)
                        anomalies.append(Anomaly(
                            severity=AnomalySeverity.HIGH,
                            category="javascript",
                            message=f"Launch-Action gefunden: startet '{fname}'",
                        ))
                    elif "/RichMedia" in obj:
                        anomalies.append(Anomaly(
                            severity=AnomalySeverity.MEDIUM,
                            category="javascript",
                            message="RichMedia-Objekt (Flash/Video) gefunden",
                        ))
                except Exception:
                    continue
        except Exception:
            pass

    has_javascript = any(a["type"] in ("/JS", "/JavaScript") for a in found_actions)
    has_auto_execute = any(a["auto_execute"] for a in found_actions)

    if has_javascript and not any(a.severity == AnomalySeverity.HIGH for a in anomalies):
        anomalies.append(Anomaly(
            severity=AnomalySeverity.HIGH,
            category="javascript",
            message=f"JavaScript-Code gefunden ({len(js_snippets)} Snippet(s))",
        ))

    return JavaScriptResult(
        has_javascript=has_javascript,
        has_auto_execute=has_auto_execute,
        found_actions=found_actions,
        js_snippets=js_snippets,
        anomalies=anomalies,
    )


def _dump_action(action) -> str:
    """Gibt alle Schlüssel und Werte einer PDF-Aktion als lesbaren String zurück."""
    try:
        if not _is_dict_like(action):
            return repr(action)[:500]
        parts = []
        for key in action.keys():
            try:
                val = action[key]
                if hasattr(val, "read_bytes"):
                    raw = bytes(val.read_bytes())
                    val_str = raw.decode("utf-8", errors="replace")[:200]
                elif _is_dict_like(val):
                    # Nested dict — rekursiv eine Ebene tiefer
                    sub = {str(k): str(val[k])[:100] for k in val.keys()}
                    val_str = str(sub)
                else:
                    val_str = str(val)[:200]
                parts.append(f"{key}={val_str}")
            except Exception:
                parts.append(f"{key}=<nicht lesbar>")
        return " | ".join(parts)
    except Exception as e:
        return f"<Dump-Fehler: {e}>"


def _extract_js_str(action) -> str:
    try:
        if "/JS" in action:
            js = action["/JS"]
            if hasattr(js, "read_bytes"):
                return bytes(js.read_bytes()).decode("utf-8", errors="replace")
            return str(js)
    except Exception:
        pass
    return ""


def _check_obfuscation(data: bytes, location: str, anomalies: list):
    for pattern, desc in _OBFUSCATION_PATTERNS:
        if re.search(pattern, data):
            anomalies.append(Anomaly(
                severity=AnomalySeverity.HIGH,
                category="javascript",
                message=f"Obfuskierter JavaScript-Code in {location}: {desc}",
            ))
            break


def _scan_name_tree(node, js_snippets: list, anomalies: list, depth=0):
    if depth > 5:
        return
    try:
        if "/Names" in node:
            names_list = list(node["/Names"])
            for i in range(0, len(names_list) - 1, 2):
                try:
                    name = str(names_list[i])
                    action = names_list[i + 1]
                    js_str = _extract_js_str(action)
                    if js_str:
                        js_snippets.append({"location": f"/Names/JavaScript/{name}", "code": js_str[:500]})
                        anomalies.append(Anomaly(
                            severity=AnomalySeverity.HIGH,
                            category="javascript",
                            message=f"JavaScript im Namen-Dictionary: '{name}'",
                        ))
                        _check_obfuscation(js_str.encode(), f"/Names/{name}", anomalies)
                except Exception:
                    continue
        if "/Kids" in node:
            for kid in node["/Kids"]:
                _scan_name_tree(kid, js_snippets, anomalies, depth + 1)
    except Exception:
        pass
