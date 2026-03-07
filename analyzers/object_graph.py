"""
PDF Object Graph Visualizer — Erstellt eine interaktive Objekt-Graph-Darstellung.
Exportiert als JSON für D3.js/Mermaid-Visualisierung im Frontend.
"""

from pathlib import Path
from typing import Dict, Any, List
import logging
import re

logger = logging.getLogger(__name__)


def analyze_object_graph(pdf_path: Path) -> Dict[str, Any]:
    """Erstellt einen Objekt-Graphen des PDF-Dokuments."""
    result = {
        "total_objects": 0,
        "nodes": [],
        "edges": [],
        "object_types": {},
        "max_depth": 0,
        "root_obj": None,
        "catalog_info": {},
        "page_tree": [],
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
        nodes = {}
        edges = []
        type_counts = {}

        # Catalog (Root)
        root = pdf.Root
        root_id = _obj_id(root)
        result["root_obj"] = root_id

        # Catalog-Info
        catalog_keys = []
        for key in root.keys():
            catalog_keys.append(str(key))
        result["catalog_info"] = {
            "keys": catalog_keys,
            "has_acroform": "/AcroForm" in catalog_keys,
            "has_names": "/Names" in catalog_keys,
            "has_outlines": "/Outlines" in catalog_keys,
            "has_metadata": "/Metadata" in catalog_keys,
            "has_ocproperties": "/OCProperties" in catalog_keys,
        }

        # BFS durch den Objektbaum
        visited = set()
        queue = [(root, "Catalog", 0, None)]
        max_objects = 500  # Performance-Limit

        while queue and len(nodes) < max_objects:
            obj, obj_type, depth, parent_id = queue.pop(0)
            obj_id = _obj_id(obj)

            if obj_id in visited:
                # Edge trotzdem hinzufügen für Zirkel-Erkennung
                if parent_id and obj_id:
                    edges.append({"source": parent_id, "target": obj_id, "type": "reference"})
                continue

            visited.add(obj_id)

            if depth > result["max_depth"]:
                result["max_depth"] = depth

            # Node erstellen (obj_type als String sicherstellen)
            obj_type_str = str(obj_type) if obj_type else "Unknown"
            node = {
                "id": obj_id,
                "type": obj_type_str,
                "depth": depth,
                "size": 0,
            }

            # Typ zählen
            type_counts[obj_type_str] = type_counts.get(obj_type_str, 0) + 1

            # Edge vom Parent
            if parent_id:
                edges.append({"source": parent_id, "target": obj_id, "type": "contains"})

            # Kinder traversieren
            if isinstance(obj, pikepdf.Dictionary):
                node["keys"] = [str(k) for k in list(obj.keys())[:20]]
                for key, val in obj.items():
                    child_type = _classify_obj(key, val)
                    if isinstance(val, (pikepdf.Dictionary, pikepdf.Stream)):
                        queue.append((val, child_type, depth + 1, obj_id))
                    elif isinstance(val, pikepdf.Array):
                        for item in val[:20]:
                            if isinstance(item, (pikepdf.Dictionary, pikepdf.Stream)):
                                queue.append((item, child_type, depth + 1, obj_id))

            elif isinstance(obj, pikepdf.Stream):
                node["has_stream"] = True
                try:
                    node["size"] = int(obj.get("/Length", 0))
                except Exception:
                    pass
                # Stream-Dictionary traversieren
                for key, val in obj.items():
                    if key not in ["/Length", "/Filter", "/DecodeParms"]:
                        child_type = _classify_obj(key, val)
                        if isinstance(val, (pikepdf.Dictionary, pikepdf.Stream)):
                            queue.append((val, child_type, depth + 1, obj_id))

            nodes[obj_id] = node

        # Page Tree extrahieren
        pages_ref = root.get("/Pages")
        if pages_ref:
            page_tree = _extract_page_tree(pages_ref, pdf)
            result["page_tree"] = page_tree[:50]

        result["total_objects"] = len(nodes)
        result["nodes"] = list(nodes.values())[:200]  # Limit für JSON
        result["edges"] = edges[:500]
        result["object_types"] = {str(k): v for k, v in type_counts.items()}

        # Anomalien
        if result["max_depth"] > 20:
            result["anomalies"].append({
                "severity": "MEDIUM",
                "category": "ObjectGraph",
                "message": f"Ungewöhnlich tiefe Objektverschachtelung: {result['max_depth']}",
                "detail": "Tiefe Verschachtelung kann auf Verschleierung oder Exploit-Vektoren hinweisen.",
            })

        # Zirkuläre Referenzen erkennen
        edge_set = set()
        circular_refs = 0
        for edge in edges:
            key = (edge["source"], edge["target"])
            reverse = (edge["target"], edge["source"])
            if reverse in edge_set:
                circular_refs += 1
            edge_set.add(key)

        if circular_refs > 0:
            result["anomalies"].append({
                "severity": "HIGH",
                "category": "ObjectGraph",
                "message": f"Zirkuläre Referenzen gefunden: {circular_refs}",
                "detail": "Zirkuläre Referenzen sind ungewöhnlich und können auf Manipulation hinweisen.",
            })

    except Exception as e:
        logger.error(f"Object-Graph Analyse fehlgeschlagen: {e}")
        result["error"] = str(e)

    pdf.close()
    return result


def _obj_id(obj) -> str:
    """Generiert eine eindeutige ID für ein PDF-Objekt."""
    try:
        if hasattr(obj, 'objgen'):
            return f"obj_{obj.objgen[0]}_{obj.objgen[1]}"
    except Exception:
        pass
    return f"obj_{id(obj)}"


def _classify_obj(key: str, val) -> str:
    """Klassifiziert ein PDF-Objekt anhand seines Keys."""
    key_str = str(key)
    type_map = {
        "/Pages": "PageTree",
        "/Page": "Page",
        "/Font": "Font",
        "/XObject": "XObject",
        "/ExtGState": "GraphicsState",
        "/ColorSpace": "ColorSpace",
        "/Pattern": "Pattern",
        "/Shading": "Shading",
        "/Annots": "Annotations",
        "/AcroForm": "AcroForm",
        "/Metadata": "Metadata",
        "/StructTreeRoot": "StructTree",
        "/Outlines": "Outlines",
        "/Names": "Names",
        "/OCProperties": "OCG",
        "/OutputIntents": "OutputIntent",
        "/FontDescriptor": "FontDescriptor",
    }
    return type_map.get(key_str, "Object")


def _extract_page_tree(pages_ref, pdf) -> List[Dict]:
    """Extrahiert die Page-Tree-Struktur."""
    tree = []
    try:
        pages = pages_ref if isinstance(pages_ref, pikepdf.Dictionary) else pdf.get_object(pages_ref)
        kids = pages.get("/Kids", [])
        for i, kid_ref in enumerate(kids[:50]):
            kid = kid_ref if isinstance(kid_ref, pikepdf.Dictionary) else pdf.get_object(kid_ref)
            kid_type = str(kid.get("/Type", ""))
            entry = {
                "index": i,
                "type": kid_type.replace("/", ""),
                "id": _obj_id(kid),
            }
            if kid_type == "/Page":
                mediabox = kid.get("/MediaBox")
                if mediabox:
                    try:
                        entry["mediabox"] = [float(x) for x in mediabox]
                    except Exception:
                        pass
            tree.append(entry)
    except Exception as e:
        logger.debug(f"Page-Tree-Extraktion: {e}")
    return tree
