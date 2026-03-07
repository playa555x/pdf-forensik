"""
OCG Layer Extraction.

Analysiert Optional Content Groups (Ebenen) im PDF:
1. Extrahiert alle OCG-Layer-Definitionen
2. Identifiziert versteckte Layer (OFF by default)
3. Exportiert Layer-Inhalte
"""
from __future__ import annotations
from pathlib import Path
from typing import List, Dict, Any

from models.schemas import Anomaly, AnomalySeverity, OCGLayerResult

try:
    import pikepdf
    PIKE_OK = True
except ImportError:
    PIKE_OK = False


def analyze_ocg_layers(pdf_path: Path) -> OCGLayerResult:
    """Analysiert OCG-Layer im PDF."""
    anomalies: List[Anomaly] = []
    layers: List[Dict[str, Any]] = []
    hidden_layers: List[Dict[str, Any]] = []

    if not PIKE_OK:
        return OCGLayerResult(
            anomalies=[Anomaly(
                severity=AnomalySeverity.INFO,
                category="ocg",
                message="pikepdf nicht verfügbar — OCG-Analyse übersprungen",
            )]
        )

    try:
        pdf = pikepdf.open(pdf_path, allow_overwriting_input=True)

        # OCProperties im Catalog
        catalog = pdf.Root
        oc_props = catalog.get("/OCProperties")

        if not oc_props:
            pdf.close()
            return OCGLayerResult(layer_count=0, anomalies=anomalies)

        # OCGs auflisten
        ocgs = oc_props.get("/OCGs")
        if ocgs and isinstance(ocgs, pikepdf.Array):
            for ocg_ref in ocgs:
                try:
                    ocg = ocg_ref if isinstance(ocg_ref, pikepdf.Dictionary) else pdf.get_object(ocg_ref)
                    name = str(ocg.get("/Name", "Unnamed"))

                    layer_info = {
                        "name": name,
                        "type": str(ocg.get("/Type", "")),
                    }

                    # Intent prüfen
                    intent = ocg.get("/Intent")
                    if intent:
                        if isinstance(intent, pikepdf.Array):
                            layer_info["intent"] = [str(i) for i in intent]
                        else:
                            layer_info["intent"] = str(intent)

                    # Usage prüfen
                    usage = ocg.get("/Usage")
                    if usage:
                        layer_info["usage"] = {}
                        for key in ["/CreatorInfo", "/Language", "/Export", "/Zoom", "/Print",
                                    "/View", "/User", "/PageElement"]:
                            val = usage.get(key)
                            if val:
                                layer_info["usage"][key] = str(val)

                    layers.append(layer_info)
                except Exception:
                    continue

        # Default-Sichtbarkeit prüfen
        default_d = oc_props.get("/D")
        if default_d:
            # OFF-Array: OCGs die standardmäßig ausgeblendet sind
            off_list = default_d.get("/OFF")
            if off_list and isinstance(off_list, pikepdf.Array):
                for off_ref in off_list:
                    try:
                        off_ocg = off_ref if isinstance(off_ref, pikepdf.Dictionary) else pdf.get_object(off_ref)
                        off_name = str(off_ocg.get("/Name", "Unnamed"))
                        hidden_layers.append({
                            "name": off_name,
                            "reason": "In /D/OFF — standardmäßig ausgeblendet",
                        })
                    except Exception:
                        continue

            # Locked-Array: OCGs die nicht umschaltbar sind
            locked_list = default_d.get("/Locked")
            if locked_list and isinstance(locked_list, pikepdf.Array):
                for locked_ref in locked_list:
                    try:
                        locked_ocg = locked_ref if isinstance(locked_ref, pikepdf.Dictionary) else pdf.get_object(locked_ref)
                        locked_name = str(locked_ocg.get("/Name", "Unnamed"))
                        # Finde in layers und markiere als locked
                        for layer in layers:
                            if layer["name"] == locked_name:
                                layer["locked"] = True
                    except Exception:
                        continue

            # Order: Reihenfolge der OCGs (wie sie in Viewern angezeigt werden)
            order = default_d.get("/Order")
            if order:
                for i, layer in enumerate(layers):
                    layer["display_order"] = i

        # Seiten-OCG-Nutzung analysieren
        ocg_page_usage: Dict[str, List[int]] = {}
        for page_num, page in enumerate(pdf.pages, 1):
            # Resources → Properties → OCGs
            resources = page.get("/Resources")
            if resources:
                props = resources.get("/Properties")
                if props:
                    for key in props.keys():
                        try:
                            prop_obj = props[key]
                            if isinstance(prop_obj, pikepdf.Dictionary):
                                prop_name = str(prop_obj.get("/Name", ""))
                                if prop_name:
                                    if prop_name not in ocg_page_usage:
                                        ocg_page_usage[prop_name] = []
                                    ocg_page_usage[prop_name].append(page_num)
                        except Exception:
                            continue

        for layer in layers:
            layer["pages"] = ocg_page_usage.get(layer["name"], [])

        pdf.close()

        # Anomalien
        if hidden_layers:
            anomalies.append(Anomaly(
                severity=AnomalySeverity.HIGH,
                category="ocg",
                message=f"{len(hidden_layers)} versteckte OCG-Layer gefunden",
                detail=", ".join(h["name"] for h in hidden_layers[:5]),
            ))

        if len(layers) > 10:
            anomalies.append(Anomaly(
                severity=AnomalySeverity.MEDIUM,
                category="ocg",
                message=f"Ungewöhnlich viele OCG-Layer: {len(layers)}",
                detail="Viele Layer können auf komplexe Dokumentmanipulation hinweisen",
            ))

    except Exception as e:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category="ocg",
            message=f"OCG-Analyse-Fehler: {str(e)[:100]}",
        ))

    return OCGLayerResult(
        layer_count=len(layers),
        layers=layers,
        hidden_layers=hidden_layers,
        anomalies=anomalies,
    )
