"""
Font Forensics — Analysiert eingebettete Fonts: Subsetting, Herkunft, Typ, Encoding.
"""

from pathlib import Path
from typing import List, Dict, Any, Optional
import logging
import re

logger = logging.getLogger(__name__)


def analyze_fonts(pdf_path: Path) -> Dict[str, Any]:
    """Extrahiert und analysiert alle Font-Informationen aus dem PDF."""
    result = {
        "total_fonts": 0,
        "embedded_count": 0,
        "subset_count": 0,
        "system_fonts": 0,
        "type1_count": 0,
        "truetype_count": 0,
        "type3_count": 0,
        "cid_count": 0,
        "fonts": [],
        "suspicious_fonts": [],
        "font_creators": [],
        "encoding_anomalies": [],
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

    seen_fonts = set()
    all_fonts = []

    try:
        for page_num, page in enumerate(pdf.pages, 1):
            resources = page.get("/Resources", pikepdf.Dictionary())
            font_dict = resources.get("/Font", pikepdf.Dictionary())

            for font_name, font_ref in font_dict.items():
                try:
                    font_obj = font_ref if isinstance(font_ref, pikepdf.Dictionary) else pdf.get_object(font_ref)

                    base_font = str(font_obj.get("/BaseFont", "Unknown"))
                    if base_font.startswith("/"):
                        base_font = base_font[1:]

                    # Deduplizieren
                    font_key = base_font
                    if font_key in seen_fonts:
                        continue
                    seen_fonts.add(font_key)

                    subtype = str(font_obj.get("/Subtype", "Unknown"))
                    if subtype.startswith("/"):
                        subtype = subtype[1:]

                    encoding = str(font_obj.get("/Encoding", "None"))
                    if encoding.startswith("/"):
                        encoding = encoding[1:]

                    # Subset-Erkennung: ABCDEF+FontName
                    is_subset = bool(re.match(r'^[A-Z]{6}\+', base_font))
                    subset_prefix = base_font[:6] if is_subset else None
                    clean_name = base_font[7:] if is_subset else base_font

                    # Eingebettet?
                    font_desc = font_obj.get("/FontDescriptor")
                    is_embedded = False
                    embedded_type = None
                    font_file_size = 0

                    if font_desc:
                        fd = font_desc if isinstance(font_desc, pikepdf.Dictionary) else pdf.get_object(font_desc)
                        for key in ["/FontFile", "/FontFile2", "/FontFile3"]:
                            ff = fd.get(key)
                            if ff:
                                is_embedded = True
                                embedded_type = key[1:]
                                try:
                                    ff_obj = ff if isinstance(ff, pikepdf.Stream) else pdf.get_object(ff)
                                    font_file_size = int(ff_obj.get("/Length", 0))
                                except Exception:
                                    pass
                                break

                    # Typ zählen
                    if "Type1" in subtype:
                        result["type1_count"] += 1
                    elif "TrueType" in subtype:
                        result["truetype_count"] += 1
                    elif "Type3" in subtype:
                        result["type3_count"] += 1
                    elif "CIDFont" in subtype:
                        result["cid_count"] += 1

                    if is_embedded:
                        result["embedded_count"] += 1
                    else:
                        result["system_fonts"] += 1

                    if is_subset:
                        result["subset_count"] += 1

                    font_info = {
                        "name": clean_name,
                        "base_font": base_font,
                        "subtype": subtype,
                        "encoding": encoding,
                        "is_embedded": is_embedded,
                        "embedded_type": embedded_type,
                        "is_subset": is_subset,
                        "subset_prefix": subset_prefix,
                        "font_file_size": font_file_size,
                        "first_page": page_num,
                    }

                    # Herkunftsanalyse
                    origin = _detect_font_origin(clean_name)
                    font_info["origin"] = origin

                    all_fonts.append(font_info)

                    # Verdächtig?
                    if subtype == "Type3":
                        result["suspicious_fonts"].append({
                            "font": base_font,
                            "reason": "Type3 font — kann beliebige Grafiken enthalten",
                            "severity": "MEDIUM",
                        })
                    if not is_embedded and not is_subset:
                        # System-Fonts die nicht eingebettet sind könnten auf verschiedenen Systemen anders aussehen
                        pass

                except Exception as e:
                    logger.debug(f"Font-Analyse fehlgeschlagen für {font_name}: {e}")
                    continue

    except Exception as e:
        logger.error(f"Font-Analyse Fehler: {e}")

    result["total_fonts"] = len(all_fonts)
    result["fonts"] = all_fonts[:50]  # Max 50 für JSON

    # Font-Creator-Statistik
    origins = {}
    for f in all_fonts:
        o = f.get("origin", "Unknown")
        origins[o] = origins.get(o, 0) + 1
    result["font_creators"] = [{"origin": k, "count": v} for k, v in sorted(origins.items(), key=lambda x: -x[1])]

    # Anomalien
    if result["type3_count"] > 0:
        result["anomalies"].append({
            "severity": "MEDIUM",
            "category": "Fonts",
            "message": f"Type3-Fonts gefunden: {result['type3_count']}",
            "detail": "Type3-Fonts definieren eigene Glyphen als Grafik-Operationen — können zum Verschleiern verwendet werden.",
        })

    if result["system_fonts"] > 0 and result["embedded_count"] == 0:
        result["anomalies"].append({
            "severity": "LOW",
            "category": "Fonts",
            "message": f"Keine eingebetteten Fonts — {result['system_fonts']} System-Fonts verwendet",
            "detail": "Dokument ohne eingebettete Fonts kann auf verschiedenen Systemen unterschiedlich aussehen.",
        })

    subset_prefixes = set(f["subset_prefix"] for f in all_fonts if f.get("subset_prefix"))
    if len(subset_prefixes) > 1:
        result["anomalies"].append({
            "severity": "INFO",
            "category": "Fonts",
            "message": f"{len(subset_prefixes)} verschiedene Subset-Präfixe gefunden",
            "detail": f"Präfixe: {', '.join(sorted(subset_prefixes)[:10])} — jedes Präfix stammt aus einer Sitzung.",
        })

    pdf.close()
    return result


def _detect_font_origin(font_name: str) -> str:
    """Erkennt die Herkunft/Familie eines Fonts."""
    name_lower = font_name.lower()

    ms_fonts = ["arial", "times new roman", "calibri", "cambria", "segoe",
                "consolas", "courier new", "verdana", "tahoma", "comic sans",
                "trebuchet", "georgia", "impact", "palatino"]
    for f in ms_fonts:
        if f.replace(" ", "") in name_lower.replace(" ", ""):
            return "Microsoft"

    apple_fonts = ["helvetica", "san francisco", "sf pro", "menlo",
                   "avenir", "optima", "gill sans"]
    for f in apple_fonts:
        if f.replace(" ", "") in name_lower.replace(" ", ""):
            return "Apple/macOS"

    adobe_fonts = ["minionpro", "myriadpro", "adobegaramond", "sourcesan",
                   "sourcecode", "sourceserif", "acaslonpro", "kozuka",
                   "kozgopr", "ryo"]
    for f in adobe_fonts:
        if f in name_lower:
            return "Adobe"

    google_fonts = ["roboto", "open sans", "lato", "montserrat", "noto",
                    "poppins", "raleway", "ubuntu", "playfair", "inter"]
    for f in google_fonts:
        if f.replace(" ", "") in name_lower.replace(" ", ""):
            return "Google Fonts"

    latex_fonts = ["cmbx", "cmr", "cmti", "cmsy", "cmex", "lm", "libertinus",
                   "txsy", "rsfs", "eufm"]
    for f in latex_fonts:
        if name_lower.startswith(f):
            return "LaTeX/TeX"

    libre_fonts = ["liberation", "dejavu", "freesans", "freeserif",
                   "freemono", "nimbus"]
    for f in libre_fonts:
        if f in name_lower:
            return "Open Source/Linux"

    return "Unknown"
