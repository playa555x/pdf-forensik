"""
Cross-Document Fingerprinting — Erstellt mehrdimensionale Fingerprints
für Ähnlichkeitsvergleiche über große Dokumentenmengen.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional
import logging
import hashlib
import json

logger = logging.getLogger(__name__)


def create_document_fingerprint(pdf_path: Path, analysis_result: Optional[Dict] = None) -> Dict[str, Any]:
    """Erstellt einen mehrdimensionalen Fingerprint des Dokuments."""
    result = {
        "fingerprint_version": "1.0",
        "structural_hash": None,
        "font_hash": None,
        "metadata_hash": None,
        "style_hash": None,
        "content_hash": None,
        "fingerprint_vector": [],
        "similarity_features": {},
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
        # 1. Structural Hash — Objektstruktur
        struct_features = _extract_structural_features(pdf)
        result["structural_hash"] = hashlib.md5(
            json.dumps(struct_features, sort_keys=True).encode()
        ).hexdigest()
        result["similarity_features"]["structure"] = struct_features

        # 2. Font Hash — Font-Kombination und -Eigenschaften
        font_features = _extract_font_features(pdf)
        result["font_hash"] = hashlib.md5(
            json.dumps(font_features, sort_keys=True).encode()
        ).hexdigest()
        result["similarity_features"]["fonts"] = font_features

        # 3. Metadata Hash — Ersteller-Fingerprint
        meta_features = _extract_meta_features(pdf)
        result["metadata_hash"] = hashlib.md5(
            json.dumps(meta_features, sort_keys=True).encode()
        ).hexdigest()
        result["similarity_features"]["metadata"] = meta_features

        # 4. Style Hash — Seitengrößen, Margins, Layout
        style_features = _extract_style_features(pdf)
        result["style_hash"] = hashlib.md5(
            json.dumps(style_features, sort_keys=True).encode()
        ).hexdigest()
        result["similarity_features"]["style"] = style_features

        # 5. Content Hash — Text-basierter Fingerprint
        content_features = _extract_content_features(pdf)
        result["content_hash"] = hashlib.md5(
            json.dumps(content_features, sort_keys=True).encode()
        ).hexdigest()
        result["similarity_features"]["content"] = content_features

        # Fingerprint-Vektor für schnellen Vergleich
        result["fingerprint_vector"] = [
            result["structural_hash"],
            result["font_hash"],
            result["metadata_hash"],
            result["style_hash"],
            result["content_hash"],
        ]

    except Exception as e:
        logger.error(f"Document Fingerprint fehlgeschlagen: {e}")
        result["error"] = str(e)

    pdf.close()
    return result


def compare_fingerprints(fp_a: Dict, fp_b: Dict) -> Dict[str, Any]:
    """Vergleicht zwei Fingerprints und gibt Ähnlichkeitsscore zurück."""
    comparison = {
        "overall_similarity": 0.0,
        "dimension_scores": {},
        "identical_dimensions": [],
        "different_dimensions": [],
    }

    dimensions = ["structural_hash", "font_hash", "metadata_hash", "style_hash", "content_hash"]
    weights = {"structural_hash": 0.2, "font_hash": 0.25, "metadata_hash": 0.2, "style_hash": 0.15, "content_hash": 0.2}

    total_score = 0.0
    for dim in dimensions:
        a_val = fp_a.get(dim)
        b_val = fp_b.get(dim)
        if a_val and b_val:
            if a_val == b_val:
                score = 1.0
                comparison["identical_dimensions"].append(dim.replace("_hash", ""))
            else:
                score = 0.0
                comparison["different_dimensions"].append(dim.replace("_hash", ""))
            comparison["dimension_scores"][dim.replace("_hash", "")] = score
            total_score += score * weights.get(dim, 0.2)

    comparison["overall_similarity"] = round(total_score, 4)
    return comparison


def _extract_structural_features(pdf) -> Dict:
    """Extrahiert strukturelle Merkmale."""
    features = {
        "page_count": len(pdf.pages),
        "has_acroform": bool(pdf.Root.get("/AcroForm")),
        "has_outlines": bool(pdf.Root.get("/Outlines")),
        "has_names": bool(pdf.Root.get("/Names")),
        "has_metadata": bool(pdf.Root.get("/Metadata")),
        "has_ocg": bool(pdf.Root.get("/OCProperties")),
        "has_output_intent": bool(pdf.Root.get("/OutputIntents")),
        "catalog_keys": sorted(str(k) for k in pdf.Root.keys()),
    }

    # Objektanzahl pro Typ
    obj_types = {}
    try:
        for i in range(1, min(len(pdf.objects) + 1, 1000)):
            try:
                obj = pdf.get_object((i, 0))
                if isinstance(obj, pikepdf.Dictionary):
                    t = str(obj.get("/Type", "Dict"))
                    obj_types[t] = obj_types.get(t, 0) + 1
                elif isinstance(obj, pikepdf.Stream):
                    obj_types["Stream"] = obj_types.get("Stream", 0) + 1
            except Exception:
                continue
    except Exception:
        pass
    features["object_type_distribution"] = obj_types

    return features


def _extract_font_features(pdf) -> Dict:
    """Extrahiert Font-basierte Merkmale."""
    fonts = set()
    font_types = {}

    for page in pdf.pages[:20]:
        resources = page.get("/Resources", pikepdf.Dictionary())
        font_dict = resources.get("/Font", pikepdf.Dictionary())
        for fname, fref in font_dict.items():
            try:
                fobj = fref if isinstance(fref, pikepdf.Dictionary) else pdf.get_object(fref)
                base_font = str(fobj.get("/BaseFont", ""))
                subtype = str(fobj.get("/Subtype", ""))
                # Subset-Präfix entfernen für Vergleichbarkeit
                import re
                clean = re.sub(r'^/[A-Z]{6}\+', '/', base_font)
                fonts.add(clean)
                ft = subtype.replace("/", "")
                font_types[ft] = font_types.get(ft, 0) + 1
            except Exception:
                continue

    return {
        "unique_fonts": sorted(fonts),
        "font_count": len(fonts),
        "font_types": font_types,
    }


def _extract_meta_features(pdf) -> Dict:
    """Extrahiert Metadaten-Fingerprint."""
    info = pdf.docinfo if pdf.docinfo else {}
    return {
        "producer": str(info.get("/Producer", "")),
        "creator": str(info.get("/Creator", "")),
        "pdf_version": str(pdf.pdf_version),
    }


def _extract_style_features(pdf) -> Dict:
    """Extrahiert Layout/Style-Merkmale."""
    page_sizes = []
    for page in pdf.pages[:20]:
        mb = page.get("/MediaBox")
        if mb:
            try:
                page_sizes.append([round(float(x), 1) for x in mb])
            except Exception:
                pass

    unique_sizes = list(set(tuple(s) for s in page_sizes))

    return {
        "unique_page_sizes": [list(s) for s in unique_sizes],
        "page_size_count": len(unique_sizes),
        "first_page_size": page_sizes[0] if page_sizes else None,
    }


def _extract_content_features(pdf) -> Dict:
    """Extrahiert inhaltliche Merkmale (nicht den Text selbst)."""
    features = {
        "has_images": False,
        "image_count": 0,
        "has_text": False,
        "has_forms": False,
    }

    for page in pdf.pages[:10]:
        resources = page.get("/Resources", pikepdf.Dictionary())

        # Bilder
        xobjs = resources.get("/XObject", pikepdf.Dictionary())
        for xo_name, xo_ref in xobjs.items():
            try:
                xo = xo_ref if isinstance(xo_ref, pikepdf.Dictionary) else pdf.get_object(xo_ref)
                if str(xo.get("/Subtype", "")) == "/Image":
                    features["has_images"] = True
                    features["image_count"] += 1
            except Exception:
                continue

        # Text-Content
        try:
            content = page.get("/Contents")
            if content:
                features["has_text"] = True
        except Exception:
            pass

    # Forms
    if pdf.Root.get("/AcroForm"):
        features["has_forms"] = True

    return features


# pikepdf import für Type-Checks
try:
    import pikepdf
except ImportError:
    pass
