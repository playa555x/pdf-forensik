"""
PDF/A & PDF/X Compliance Validator — Prüft Konformität mit Archivierungs- und Druckstandards.
"""

from pathlib import Path
from typing import List, Dict, Any, Optional
import logging
import re

logger = logging.getLogger(__name__)


def analyze_pdfa_pdfx(pdf_path: Path) -> Dict[str, Any]:
    """Prüft PDF/A und PDF/X Compliance."""
    result = {
        "pdfa_claimed": None,
        "pdfa_version": None,
        "pdfa_conformance": None,
        "pdfx_claimed": None,
        "pdfx_version": None,
        "compliance_issues": [],
        "total_issues": 0,
        "critical_issues": 0,
        "passes": [],
        "output_intent": None,
        "anomalies": [],
    }

    try:
        import pikepdf
    except ImportError:
        result["error"] = "pikepdf not installed"
        return result

    try:
        pdf = pikepdf.open(pdf_path)
    except Exception as e:
        result["error"] = str(e)
        return result

    try:
        # ---- PDF/A & PDF/X Identifikation aus XMP ----
        root = pdf.Root
        metadata_stream = root.get("/Metadata")
        xmp_text = ""

        if metadata_stream:
            try:
                meta_obj = metadata_stream if isinstance(metadata_stream, pikepdf.Stream) else pdf.get_object(metadata_stream)
                xmp_bytes = meta_obj.read_bytes()
                xmp_text = xmp_bytes.decode("utf-8", errors="replace")
            except Exception:
                pass

        # PDF/A aus XMP erkennen
        pdfa_part_match = re.search(r'pdfaid:part["\s>]*(\d+)', xmp_text, re.IGNORECASE)
        pdfa_conf_match = re.search(r'pdfaid:conformance["\s>]*([ABUabu])', xmp_text, re.IGNORECASE)

        if pdfa_part_match:
            part = pdfa_part_match.group(1)
            conf = pdfa_conf_match.group(1).upper() if pdfa_conf_match else "?"
            result["pdfa_claimed"] = True
            result["pdfa_version"] = f"PDF/A-{part}"
            result["pdfa_conformance"] = conf
        else:
            result["pdfa_claimed"] = False

        # PDF/X aus XMP erkennen
        pdfx_match = re.search(r'pdfxid:GTS_PDFX\w*["\s>]*(PDF/X[^<"]*)', xmp_text, re.IGNORECASE)
        if not pdfx_match:
            pdfx_match = re.search(r'GTS_PDFX\w*["\s>]*(PDF/X[^<"]*)', xmp_text, re.IGNORECASE)

        if pdfx_match:
            result["pdfx_claimed"] = True
            result["pdfx_version"] = pdfx_match.group(1).strip()
        else:
            result["pdfx_claimed"] = False

        # ---- Output Intent prüfen ----
        output_intents = root.get("/OutputIntents")
        if output_intents:
            try:
                oi_list = output_intents if isinstance(output_intents, pikepdf.Array) else [output_intents]
                for oi in oi_list:
                    oi_obj = oi if isinstance(oi, pikepdf.Dictionary) else pdf.get_object(oi)
                    oi_subtype = str(oi_obj.get("/S", ""))
                    oi_condition = str(oi_obj.get("/OutputConditionIdentifier", ""))
                    oi_info = str(oi_obj.get("/Info", ""))
                    result["output_intent"] = {
                        "subtype": oi_subtype.replace("/", ""),
                        "condition": oi_condition,
                        "info": oi_info,
                    }
                    break
            except Exception:
                pass

        # ---- PDF/A Compliance Checks ----
        if result["pdfa_claimed"]:
            _check_pdfa_compliance(pdf, result, xmp_text)

        # ---- PDF/X Compliance Checks ----
        if result["pdfx_claimed"]:
            _check_pdfx_compliance(pdf, result)

        # ---- Allgemeine Checks (auch ohne Claim) ----
        _check_general_compliance(pdf, result)

        result["total_issues"] = len(result["compliance_issues"])
        result["critical_issues"] = sum(1 for i in result["compliance_issues"] if i.get("severity") == "CRITICAL")

        # Anomalien
        if result["pdfa_claimed"] and result["total_issues"] > 0:
            result["anomalies"].append({
                "severity": "MEDIUM",
                "category": "Compliance",
                "message": f"PDF/A-{result['pdfa_version']} beansprucht, aber {result['total_issues']} Compliance-Probleme",
                "detail": f"Kritische Probleme: {result['critical_issues']}",
            })

        if result["pdfx_claimed"] and not result.get("output_intent"):
            result["anomalies"].append({
                "severity": "MEDIUM",
                "category": "Compliance",
                "message": "PDF/X beansprucht ohne OutputIntent",
                "detail": "PDF/X erfordert zwingend ein OutputIntent-Dictionary.",
            })

    except Exception as e:
        logger.error(f"PDF/A-X Analyse fehlgeschlagen: {e}")
        result["error"] = str(e)

    pdf.close()
    return result


def _check_pdfa_compliance(pdf, result: Dict, xmp_text: str):
    """Prüft PDF/A-spezifische Anforderungen."""
    root = pdf.Root
    issues = result["compliance_issues"]
    passes = result["passes"]

    # 1. Metadaten müssen als XMP vorhanden sein
    if not root.get("/Metadata"):
        issues.append({"check": "XMP Metadata", "severity": "CRITICAL",
                       "message": "PDF/A erfordert XMP-Metadaten — nicht gefunden"})
    else:
        passes.append("XMP Metadata vorhanden")

    # 2. Keine JavaScript
    if root.get("/OpenAction") or "/JavaScript" in str(root.get("/Names", {})):
        issues.append({"check": "JavaScript", "severity": "CRITICAL",
                       "message": "PDF/A verbietet JavaScript — gefunden"})
    else:
        passes.append("Kein JavaScript")

    # 3. Keine externen Links/Actions (GoToR, Launch, Sound, Movie)
    forbidden_actions = ["/GoToR", "/Launch", "/Sound", "/Movie", "/ResetForm", "/ImportData"]
    for page in pdf.pages:
        annots = page.get("/Annots", [])
        try:
            for annot in annots:
                annot_obj = annot if isinstance(annot, pikepdf.Dictionary) else pdf.get_object(annot)
                action = annot_obj.get("/A", {})
                if isinstance(action, pikepdf.Dictionary):
                    action_type = str(action.get("/S", ""))
                    if action_type in forbidden_actions:
                        issues.append({"check": "Forbidden Action", "severity": "CRITICAL",
                                       "message": f"PDF/A verbietet {action_type}-Aktionen"})
                        break
        except Exception:
            continue

    # 4. Verschlüsselung verboten
    if pdf.is_encrypted:
        issues.append({"check": "Encryption", "severity": "CRITICAL",
                       "message": "PDF/A verbietet Verschlüsselung"})
    else:
        passes.append("Keine Verschlüsselung")

    # 5. Fonts müssen eingebettet sein
    has_unembedded = False
    for page in pdf.pages:
        resources = page.get("/Resources", pikepdf.Dictionary())
        fonts = resources.get("/Font", pikepdf.Dictionary())
        for fname, fref in fonts.items():
            try:
                fobj = fref if isinstance(fref, pikepdf.Dictionary) else pdf.get_object(fref)
                fdesc = fobj.get("/FontDescriptor")
                if fdesc:
                    fd = fdesc if isinstance(fdesc, pikepdf.Dictionary) else pdf.get_object(fdesc)
                    if not any(fd.get(k) for k in ["/FontFile", "/FontFile2", "/FontFile3"]):
                        has_unembedded = True
                        break
            except Exception:
                continue
        if has_unembedded:
            break

    if has_unembedded:
        issues.append({"check": "Font Embedding", "severity": "CRITICAL",
                       "message": "PDF/A erfordert alle Fonts eingebettet — nicht-eingebettete gefunden"})
    else:
        passes.append("Alle Fonts eingebettet")

    # 6. Transparenz (PDF/A-1 verbietet es)
    if result.get("pdfa_version") == "PDF/A-1":
        for page in pdf.pages:
            resources = page.get("/Resources", pikepdf.Dictionary())
            ext_gs = resources.get("/ExtGState", pikepdf.Dictionary())
            for gs_name, gs_ref in ext_gs.items():
                try:
                    gs = gs_ref if isinstance(gs_ref, pikepdf.Dictionary) else pdf.get_object(gs_ref)
                    if gs.get("/SMask") or gs.get("/CA") or gs.get("/ca"):
                        issues.append({"check": "Transparency", "severity": "CRITICAL",
                                       "message": "PDF/A-1 verbietet Transparenz — ExtGState mit Alpha gefunden"})
                        break
                except Exception:
                    continue


def _check_pdfx_compliance(pdf, result: Dict):
    """Prüft PDF/X-spezifische Anforderungen."""
    issues = result["compliance_issues"]
    passes = result["passes"]

    # OutputIntent ist Pflicht
    if not result.get("output_intent"):
        issues.append({"check": "OutputIntent", "severity": "CRITICAL",
                       "message": "PDF/X erfordert OutputIntent — nicht gefunden"})
    else:
        passes.append("OutputIntent vorhanden")

    # Trapped-Key sollte gesetzt sein
    info = pdf.docinfo
    trapped = str(info.get("/Trapped", "")) if info else ""
    if trapped not in ["/True", "/False", "True", "False"]:
        issues.append({"check": "Trapped Key", "severity": "MEDIUM",
                       "message": "PDF/X erfordert /Trapped-Key in /Info — nicht oder ungültig gesetzt"})
    else:
        passes.append("Trapped-Key gesetzt")


def _check_general_compliance(pdf, result: Dict):
    """Allgemeine Compliance-Checks."""
    passes = result["passes"]

    # PDF-Version
    version = str(pdf.pdf_version)
    passes.append(f"PDF-Version: {version}")

    # Page count
    passes.append(f"Seiten: {len(pdf.pages)}")
