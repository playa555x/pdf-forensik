"""
ICC Color Profile Analyzer — Extrahiert und analysiert eingebettete ICC-Farbprofile.
ICC-Profile können Gerät, Software und Workflows verraten.
"""

from pathlib import Path
from typing import Dict, Any, List
import logging
import struct

logger = logging.getLogger(__name__)


def analyze_icc_profiles(pdf_path: Path) -> Dict[str, Any]:
    """Extrahiert und analysiert ICC-Farbprofile aus dem PDF."""
    result = {
        "profiles_found": 0,
        "profiles": [],
        "color_spaces_used": [],
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

    color_spaces = set()
    profiles = []

    try:
        # OutputIntents (PDF/X, PDF/A)
        oi_list = pdf.Root.get("/OutputIntents", [])
        if oi_list:
            try:
                for oi in oi_list:
                    oi_obj = oi if isinstance(oi, pikepdf.Dictionary) else pdf.get_object(oi)
                    dest_profile = oi_obj.get("/DestOutputProfile")
                    if dest_profile:
                        profile_data = _extract_icc_data(dest_profile, pdf)
                        if profile_data:
                            profile_data["source"] = "OutputIntent"
                            profile_data["condition"] = str(oi_obj.get("/OutputConditionIdentifier", ""))
                            profiles.append(profile_data)
            except Exception as e:
                logger.debug(f"OutputIntent-ICC Fehler: {e}")

        # Alle Seiten nach ICC-basierten ColorSpaces durchsuchen
        for page_num, page in enumerate(pdf.pages, 1):
            resources = page.get("/Resources", pikepdf.Dictionary())

            # ColorSpace-Dictionary
            cs_dict = resources.get("/ColorSpace", pikepdf.Dictionary())
            for cs_name, cs_ref in cs_dict.items():
                try:
                    cs_obj = cs_ref if isinstance(cs_ref, pikepdf.Array) else pdf.get_object(cs_ref) if not isinstance(cs_ref, pikepdf.Name) else None
                    if cs_obj is None:
                        color_spaces.add(str(cs_ref))
                        continue

                    if isinstance(cs_obj, pikepdf.Array) and len(cs_obj) >= 2:
                        cs_type = str(cs_obj[0])
                        if cs_type == "/ICCBased":
                            icc_stream = cs_obj[1]
                            profile_data = _extract_icc_data(icc_stream, pdf)
                            if profile_data:
                                profile_data["source"] = f"Page {page_num}"
                                profile_data["cs_name"] = str(cs_name)
                                profiles.append(profile_data)
                        color_spaces.add(cs_type.replace("/", ""))
                    elif isinstance(cs_obj, pikepdf.Name):
                        color_spaces.add(str(cs_obj).replace("/", ""))
                except Exception:
                    continue

            # XObject Images
            xobjs = resources.get("/XObject", pikepdf.Dictionary())
            for xo_name, xo_ref in xobjs.items():
                try:
                    xo = xo_ref if isinstance(xo_ref, pikepdf.Stream) else pdf.get_object(xo_ref)
                    if str(xo.get("/Subtype", "")) == "/Image":
                        cs = xo.get("/ColorSpace")
                        if isinstance(cs, pikepdf.Array) and len(cs) >= 2:
                            if str(cs[0]) == "/ICCBased":
                                profile_data = _extract_icc_data(cs[1], pdf)
                                if profile_data:
                                    profile_data["source"] = f"Image on Page {page_num}"
                                    # Deduplizieren
                                    if not any(p.get("profile_id") == profile_data.get("profile_id") for p in profiles):
                                        profiles.append(profile_data)
                        elif isinstance(cs, pikepdf.Name):
                            color_spaces.add(str(cs).replace("/", ""))
                except Exception:
                    continue

            if page_num > 20:  # Performance-Limit
                break

    except Exception as e:
        logger.error(f"ICC-Analyse Fehler: {e}")

    # Deduplizieren nach profile_id
    seen_ids = set()
    unique_profiles = []
    for p in profiles:
        pid = p.get("profile_id", id(p))
        if pid not in seen_ids:
            seen_ids.add(pid)
            unique_profiles.append(p)

    result["profiles_found"] = len(unique_profiles)
    result["profiles"] = unique_profiles[:20]
    result["color_spaces_used"] = sorted(color_spaces)

    # Anomalien
    if len(unique_profiles) > 1:
        creators = set(p.get("creator", "") for p in unique_profiles if p.get("creator"))
        if len(creators) > 1:
            result["anomalies"].append({
                "severity": "MEDIUM",
                "category": "ICC",
                "message": f"Verschiedene ICC-Profil-Ersteller: {', '.join(creators)}",
                "detail": "Verschiedene ICC-Profile von verschiedenen Quellen deuten auf zusammengesetzte Dokumente hin.",
            })

    pdf.close()
    return result


def _extract_icc_data(stream_ref, pdf) -> Dict[str, Any]:
    """Extrahiert ICC-Header-Informationen aus einem Stream."""
    try:
        stream = stream_ref if isinstance(stream_ref, pikepdf.Stream) else pdf.get_object(stream_ref)
        raw = stream.read_bytes()

        if len(raw) < 128:
            return None

        # ICC Header ist 128 Bytes
        profile_size = struct.unpack(">I", raw[0:4])[0]
        preferred_cmm = raw[4:8].decode("ascii", errors="replace").strip('\x00')
        version_major = raw[8]
        version_minor = (raw[9] >> 4) & 0x0F
        version_patch = raw[9] & 0x0F
        device_class = raw[12:16].decode("ascii", errors="replace").strip('\x00')
        color_space = raw[16:20].decode("ascii", errors="replace").strip('\x00')
        pcs = raw[20:24].decode("ascii", errors="replace").strip('\x00')

        # Erstellungsdatum
        year = struct.unpack(">H", raw[24:26])[0]
        month = struct.unpack(">H", raw[26:28])[0]
        day = struct.unpack(">H", raw[28:30])[0]
        hour = struct.unpack(">H", raw[30:32])[0]
        minute = struct.unpack(">H", raw[32:34])[0]
        second = struct.unpack(">H", raw[34:36])[0]

        creation_date = None
        if 1990 <= year <= 2030:
            creation_date = f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}"

        # Primary Platform
        platform = raw[40:44].decode("ascii", errors="replace").strip('\x00')
        platform_map = {
            "APPL": "Apple",
            "MSFT": "Microsoft",
            "SGI ": "Silicon Graphics",
            "SUNW": "Sun Microsystems",
            "": "Platform Independent",
        }
        platform_name = platform_map.get(platform, platform)

        # Creator
        creator = raw[80:84].decode("ascii", errors="replace").strip('\x00')

        # Profile ID (MD5, Bytes 84-99)
        profile_id = raw[84:100].hex()
        if profile_id == "0" * 32:
            profile_id = None

        # Device Class Name
        class_map = {
            "scnr": "Scanner/Input",
            "mntr": "Monitor/Display",
            "prtr": "Printer/Output",
            "link": "DeviceLink",
            "spac": "ColorSpace",
            "abst": "Abstract",
            "nmcl": "Named Color",
        }
        device_class_name = class_map.get(device_class.lower(), device_class)

        # Bekannte Profile erkennen
        known_profile = _identify_known_profile(raw, profile_size)

        # Components count from N field in ICCBased stream
        n_components = None
        if isinstance(stream, pikepdf.Stream):
            n_val = stream.get("/N")
            if n_val:
                n_components = int(n_val)

        return {
            "profile_size": profile_size,
            "version": f"{version_major}.{version_minor}.{version_patch}",
            "cmm": preferred_cmm,
            "device_class": device_class_name,
            "color_space": color_space.strip(),
            "pcs": pcs.strip(),
            "creation_date": creation_date,
            "platform": platform_name,
            "creator": creator,
            "profile_id": profile_id,
            "components": n_components,
            "known_profile": known_profile,
        }

    except Exception as e:
        logger.debug(f"ICC-Parsing fehlgeschlagen: {e}")
        return None


def _identify_known_profile(raw: bytes, size: int) -> str:
    """Versucht bekannte ICC-Profile zu identifizieren."""
    # Description Tag suchen (Tag-Signatur 'desc')
    try:
        tag_count = struct.unpack(">I", raw[128:132])[0]
        for i in range(min(tag_count, 50)):
            offset = 132 + i * 12
            sig = raw[offset:offset + 4]
            tag_offset = struct.unpack(">I", raw[offset + 4:offset + 8])[0]
            tag_size = struct.unpack(">I", raw[offset + 8:offset + 12])[0]

            if sig == b'desc' and tag_offset + min(tag_size, 500) <= len(raw):
                desc_data = raw[tag_offset:tag_offset + min(tag_size, 500)]
                # ASCII-Teil extrahieren
                if desc_data[:4] == b'desc':
                    str_len = struct.unpack(">I", desc_data[8:12])[0]
                    desc_str = desc_data[12:12 + min(str_len, 200)].decode("ascii", errors="replace").strip('\x00')
                    return desc_str
                elif desc_data[:4] == b'mluc':
                    # MultiLocalizedUnicode
                    try:
                        rec_count = struct.unpack(">I", desc_data[8:12])[0]
                        if rec_count > 0:
                            str_offset = struct.unpack(">I", desc_data[20:24])[0]
                            str_len = struct.unpack(">I", desc_data[16:20])[0]
                            desc_str = desc_data[str_offset:str_offset + min(str_len, 200)].decode("utf-16-be", errors="replace").strip('\x00')
                            return desc_str
                    except Exception:
                        pass
                break
    except Exception:
        pass

    return "Unknown"
