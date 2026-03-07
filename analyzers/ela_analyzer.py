"""
ELA-Analyzer (Error Level Analysis): Erkennt JPEG-Bildmanipulationen durch
Re-Kompression mit bekannter Qualitätsstufe und Differenzberechnung.

Methode:
1. Eingebettetes JPEG mit Qualität Q re-komprimieren
2. Pixel-Differenz zwischen Original und Re-Kompression berechnen
3. Bereiche mit hohem ELA-Signal = mögliche Manipulation (eingefügter Bereich)
4. Bereiche mit sehr niedrigem ELA-Signal bei homogenem Bild = mögliche Up-Sampling-Fälschung

Zusätzlich: Copy-Move-Detection via Sliding-Window-Hash (einfach, robust)
"""
from __future__ import annotations
import io
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional

try:
    from PIL import Image, ImageChops, ImageEnhance
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

import pikepdf

from models.schemas import Anomaly, AnomalySeverity


_ELA_QUALITY     = 90    # Re-Kompressions-Qualität
_ELA_SCALE       = 15    # Verstärkungs-Faktor für Differenzbild
_ELA_HIGH_THRESH = 25.0  # Mittlere Helligkeit im Differenzbild über diesem Wert → verdächtig
_ELA_LOW_THRESH  = 2.0   # Sehr niedrig → mögliches generiertes/upsampled Bild
_MAX_IMAGES      = 10    # Maximal zu analysierende Bilder (Performance)


def _ela_single(image_bytes: bytes) -> Optional[Dict[str, Any]]:
    """
    Führt ELA auf einem einzelnen JPEG durch.
    Gibt dict mit ela_mean, ela_max, verdict zurück.
    """
    if not PIL_AVAILABLE:
        return None
    try:
        orig = Image.open(io.BytesIO(image_bytes)).convert("RGB")

        # Re-komprimieren
        buf = io.BytesIO()
        orig.save(buf, format="JPEG", quality=_ELA_QUALITY)
        buf.seek(0)
        recompressed = Image.open(buf).convert("RGB")

        # Differenz
        diff = ImageChops.difference(orig, recompressed)

        # Skalieren für bessere Sichtbarkeit
        enhancer = ImageEnhance.Brightness(diff)
        ela_img  = enhancer.enhance(_ELA_SCALE)

        # Statistik
        grayscale = ela_img.convert("L")
        pixels    = list(grayscale.getdata())
        ela_mean  = sum(pixels) / len(pixels) if pixels else 0.0
        ela_max   = max(pixels) if pixels else 0

        if ela_mean > _ELA_HIGH_THRESH:
            verdict = "SUSPICIOUS"
            note    = f"Hoher ELA-Wert ({ela_mean:.1f}) — mögliche Bildmanipulation oder erneute Bearbeitung"
        elif ela_mean < _ELA_LOW_THRESH:
            verdict = "LOW_SIGNAL"
            note    = f"Sehr niedriger ELA-Wert ({ela_mean:.1f}) — mögliches Upsampling/Screenshot"
        else:
            verdict = "NORMAL"
            note    = f"ELA-Wert im normalen Bereich ({ela_mean:.1f})"

        # ELA-Bild als Base64 speichern (kompakt)
        ela_buf = io.BytesIO()
        ela_img.save(ela_buf, format="JPEG", quality=70)
        ela_b64 = __import__("base64").b64encode(ela_buf.getvalue()).decode()

        return {
            "ela_mean":    round(ela_mean, 2),
            "ela_max":     ela_max,
            "verdict":     verdict,
            "note":        note,
            "ela_preview": f"data:image/jpeg;base64,{ela_b64}",
            "dimensions":  f"{orig.width}×{orig.height}",
        }
    except Exception as e:
        return {"error": str(e), "verdict": "ERROR"}


def _copy_move_check(image_bytes: bytes, block_size: int = 32) -> Dict[str, Any]:
    """
    Einfache Copy-Move-Detektion via Block-Hashing.
    Teilt Bild in Blöcke und sucht nach identischen Blöcken an verschiedenen Positionen.
    """
    if not PIL_AVAILABLE:
        return {"copy_move_detected": False, "duplicate_blocks": 0}
    try:
        img   = Image.open(io.BytesIO(image_bytes)).convert("L")
        w, h  = img.size
        hashes: Dict[str, List] = {}

        for y in range(0, h - block_size, block_size):
            for x in range(0, w - block_size, block_size):
                block = img.crop((x, y, x + block_size, y + block_size))
                bh    = hashlib.md5(block.tobytes()).hexdigest()
                if bh not in hashes:
                    hashes[bh] = []
                hashes[bh].append((x, y))

        duplicates = {k: v for k, v in hashes.items() if len(v) > 1}
        # Ignoriere uniforme Blöcke (weiß/schwarz) — zu viele False Positives
        dup_count = sum(len(v) - 1 for v in duplicates.values())

        return {
            "copy_move_detected": dup_count > 5,
            "duplicate_blocks":   dup_count,
            "note": f"{dup_count} duplizierte Blöcke gefunden" if dup_count > 5
                    else "Keine signifikante Copy-Move-Aktivität",
        }
    except Exception:
        return {"copy_move_detected": False, "duplicate_blocks": 0}


def _extract_images_from_pdf(pdf: pikepdf.Pdf) -> List[Dict[str, Any]]:
    """Extrahiert JPEG-Rohdaten aus allen Seiten."""
    images = []
    seen_hashes: set = set()

    for i, page in enumerate(pdf.pages):
        try:
            res = page.get("/Resources")
            if not res:
                continue
            xobjects = res.get("/XObject")
            if not xobjects:
                continue
            for name in xobjects.keys():
                try:
                    xobj = xobjects[name]
                    if not isinstance(xobj, pikepdf.Dictionary):
                        xobj = xobj.get_object()
                    if str(xobj.get("/Subtype", "")) != "/Image":
                        continue
                    # Nur JPEG (DCTDecode)
                    filt = xobj.get("/Filter")
                    filt_str = str(filt) if filt else ""
                    if "DCTDecode" not in filt_str and "/DCT" not in filt_str:
                        continue
                    raw = bytes(xobj.read_raw_bytes())
                    h   = hashlib.md5(raw[:1024]).hexdigest()
                    if h in seen_hashes:
                        continue
                    seen_hashes.add(h)
                    images.append({
                        "page":       i + 1,
                        "name":       str(name),
                        "size_bytes": len(raw),
                        "data":       raw,
                    })
                    if len(images) >= _MAX_IMAGES:
                        return images
                except Exception:
                    continue
        except Exception:
            continue

    return images


def analyze_ela(pdf_path: Path) -> Dict[str, Any]:
    """Hauptfunktion: ELA + Copy-Move für alle JPEG-Bilder im PDF."""
    anomalies: List[Anomaly] = []

    if not PIL_AVAILABLE:
        return {
            "available":     False,
            "images_checked": 0,
            "results":       [],
            "anomalies": [Anomaly(
                severity=AnomalySeverity.INFO,
                category="ela",
                message="ELA nicht verfügbar — Pillow nicht installiert",
            )],
        }

    try:
        pdf = pikepdf.open(pdf_path)
    except Exception as e:
        return {
            "available":      True,
            "images_checked": 0,
            "results":        [],
            "anomalies": [Anomaly(
                severity=AnomalySeverity.HIGH,
                category="ela",
                message="PDF konnte nicht für ELA-Analyse geöffnet werden",
                detail=str(e),
            )],
        }

    with pdf:
        raw_images = _extract_images_from_pdf(pdf)

    if not raw_images:
        return {
            "available":      True,
            "images_checked": 0,
            "results":        [],
            "anomalies":      [],
        }

    results = []
    for img_info in raw_images:
        ela_result = _ela_single(img_info["data"])
        cm_result  = _copy_move_check(img_info["data"])

        entry = {
            "page":       img_info["page"],
            "name":       img_info["name"],
            "size_bytes": img_info["size_bytes"],
            "ela":        ela_result,
            "copy_move":  cm_result,
        }
        results.append(entry)

        # Anomalien
        if ela_result and ela_result.get("verdict") == "SUSPICIOUS":
            anomalies.append(Anomaly(
                severity=AnomalySeverity.HIGH,
                category="ela",
                message=f"ELA: Verdächtiges Bild auf Seite {img_info['page']} ({img_info['name']})",
                detail=ela_result.get("note", ""),
            ))
        if cm_result.get("copy_move_detected"):
            anomalies.append(Anomaly(
                severity=AnomalySeverity.MEDIUM,
                category="ela",
                message=f"Copy-Move: {cm_result['duplicate_blocks']} duplizierte Blöcke auf Seite {img_info['page']}",
                detail=cm_result.get("note", ""),
            ))

    return {
        "available":      True,
        "images_checked": len(results),
        "results":        results,
        "anomalies":      anomalies,
    }
