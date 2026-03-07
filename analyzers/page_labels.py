"""
/PageLabels Anomalie-Erkennung.
Simuliert alle Labels und vergleicht declared_page_count mit tatsächlicher Seitenanzahl.
"""
from __future__ import annotations
from pathlib import Path
from typing import List, Dict, Any, Optional

import pikepdf

from models.schemas import PageLabelsResult, Anomaly, AnomalySeverity


def _decode_label_style(style_str: str) -> str:
    styles = {
        "/D": "Dezimal (1,2,3,...)",
        "/r": "Römisch klein (i,ii,iii,...)",
        "/R": "Römisch groß (I,II,III,...)",
        "/a": "Alpha klein (a,b,c,...)",
        "/A": "Alpha groß (A,B,C,...)",
    }
    return styles.get(style_str, f"Unbekannt ({style_str})")


def _simulate_labels(ranges: List[Dict[str, Any]], actual_page_count: int) -> List[str]:
    """Generiert alle Seiten-Label-Strings für das Dokument."""
    if not ranges:
        return []

    # Sortieren nach start_page
    sorted_ranges = sorted(ranges, key=lambda r: r["start_page"])
    labels = []

    for i, r in enumerate(sorted_ranges):
        start = r["start_page"]
        end   = sorted_ranges[i + 1]["start_page"] if i + 1 < len(sorted_ranges) else actual_page_count
        style  = r.get("raw_style", "/D")
        first  = r.get("first_value", 1)
        prefix = r.get("prefix", "")

        for page_idx in range(start, end):
            num = first + (page_idx - start)
            if style == "/D":
                label = f"{prefix}{num}"
            elif style == "/R":
                label = f"{prefix}{_to_roman(num).upper()}"
            elif style == "/r":
                label = f"{prefix}{_to_roman(num).lower()}"
            elif style == "/A":
                label = f"{prefix}{_to_alpha(num).upper()}"
            elif style == "/a":
                label = f"{prefix}{_to_alpha(num).lower()}"
            else:
                label = f"{prefix}{num}"
            labels.append(label)

    return labels


def _to_roman(n: int) -> str:
    if n <= 0:
        return str(n)
    vals = [1000,900,500,400,100,90,50,40,10,9,5,4,1]
    syms = ["M","CM","D","CD","C","XC","L","XL","X","IX","V","IV","I"]
    result = ""
    for v, s in zip(vals, syms):
        while n >= v:
            result += s
            n -= v
    return result


def _to_alpha(n: int) -> str:
    if n <= 0:
        return "?"
    result = ""
    while n > 0:
        n -= 1
        result = chr(ord('a') + n % 26) + result
        n //= 26
    return result


def analyze_page_labels(pdf_path: Path) -> PageLabelsResult:
    anomalies: list[Anomaly] = []
    label_ranges: List[Dict[str, Any]] = []
    declared_page_count = None

    try:
        pdf = pikepdf.open(pdf_path)
    except Exception as e:
        return PageLabelsResult(anomalies=[
            Anomaly(severity=AnomalySeverity.HIGH, category="page_labels",
                    message="PDF konnte nicht geöffnet werden", detail=str(e))
        ])

    with pdf:
        actual_page_count = len(pdf.pages)
        catalog = pdf.Root

        if "/PageLabels" not in catalog:
            return PageLabelsResult(
                has_page_labels=False,
                actual_page_count=actual_page_count,
                anomalies=anomalies,
            )

        page_labels_obj = catalog["/PageLabels"]

        try:
            nums = page_labels_obj.get("/Nums", [])
            nums_list = list(nums)

            for i in range(0, len(nums_list) - 1, 2):
                try:
                    start_page = int(nums_list[i])
                    label_dict = nums_list[i + 1]

                    raw_style = str(label_dict.get("/S", "/D")) if hasattr(label_dict, "get") else "/D"
                    first     = int(label_dict.get("/St", 1)) if hasattr(label_dict, "get") else 1
                    prefix    = str(label_dict.get("/P", "")) if hasattr(label_dict, "get") else ""

                    label_ranges.append({
                        "start_page": start_page,
                        "style": _decode_label_style(raw_style),
                        "raw_style": raw_style,
                        "first_value": first,
                        "prefix": prefix,
                    })
                except Exception:
                    continue

            # Simulation: tatsächliche Labels generieren
            simulated = _simulate_labels(label_ranges, actual_page_count)
            declared_page_count = len(simulated)

            # Anomalie: declared != actual
            if declared_page_count != actual_page_count:
                anomalies.append(Anomaly(
                    severity=AnomalySeverity.HIGH,
                    category="page_labels",
                    message=f"PageLabels deklarieren {declared_page_count} Seiten, Dokument hat aber {actual_page_count}",
                    detail=f"Simulierte Labels: {simulated[:5]}{'…' if len(simulated) > 5 else ''}",
                ))

            # Anomalie: start_page außerhalb des Dokuments
            for r in label_ranges:
                if r["start_page"] >= actual_page_count:
                    anomalies.append(Anomaly(
                        severity=AnomalySeverity.HIGH,
                        category="page_labels",
                        message=f"PageLabel-Range startet bei Seite {r['start_page']+1}, Dokument hat nur {actual_page_count} Seiten",
                    ))
                    break

            # Anomalie: Mehr Ranges als Seiten
            if len(label_ranges) > actual_page_count:
                anomalies.append(Anomaly(
                    severity=AnomalySeverity.HIGH,
                    category="page_labels",
                    message=f"Mehr PageLabel-Ranges ({len(label_ranges)}) als tatsächliche Seiten ({actual_page_count})",
                ))

            # Info: Seitennummerierung beginnt nicht bei 1
            if label_ranges and label_ranges[0].get("first_value", 1) != 1:
                anomalies.append(Anomaly(
                    severity=AnomalySeverity.LOW,
                    category="page_labels",
                    message=f"Seitennummerierung beginnt bei {label_ranges[0]['first_value']} statt 1",
                ))

        except Exception as e:
            anomalies.append(Anomaly(
                severity=AnomalySeverity.MEDIUM,
                category="page_labels",
                message="PageLabels konnten nicht vollständig geparst werden",
                detail=str(e),
            ))

    return PageLabelsResult(
        has_page_labels=True,
        label_ranges=label_ranges,
        declared_page_count=declared_page_count,
        actual_page_count=actual_page_count,
        anomalies=anomalies,
    )
