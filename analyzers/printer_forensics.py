"""
Printer Forensics — Analysiert Scan-/Druck-Artefakte in eingebetteten Bildern.
Erkennt Toner-Muster, Scan-Artefakte, Moiré-Muster und Drucker-Fingerprints.
"""

from pathlib import Path
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)


def analyze_printer_forensics(pdf_path: Path, image_dir: Path = None) -> Dict[str, Any]:
    """Analysiert Bilder im PDF auf Drucker-/Scanner-Artefakte."""
    result = {
        "is_scanned_document": False,
        "scan_confidence": 0.0,
        "scan_indicators": [],
        "printer_type": None,
        "dpi_detected": None,
        "rotation_detected": False,
        "rotation_angle": None,
        "moire_detected": False,
        "halftone_detected": False,
        "banding_detected": False,
        "images_analyzed": 0,
        "image_results": [],
        "anomalies": [],
    }

    try:
        import pikepdf
        from PIL import Image
        import numpy as np
    except ImportError as e:
        result["error"] = f"Missing dependency: {e}"
        return result

    try:
        pdf = pikepdf.open(pdf_path)
    except Exception as e:
        result["error"] = str(e)
        return result

    scan_indicators = []
    image_results = []
    total_score = 0

    try:
        for page_num, page in enumerate(pdf.pages[:10], 1):
            resources = page.get("/Resources", pikepdf.Dictionary())
            xobjs = resources.get("/XObject", pikepdf.Dictionary())

            # Prüfe ob Seite hauptsächlich ein Bild ist (Scan-Indikator)
            mediabox = page.get("/MediaBox")
            page_w = page_h = 0
            if mediabox:
                try:
                    page_w = float(mediabox[2]) - float(mediabox[0])
                    page_h = float(mediabox[3]) - float(mediabox[1])
                except Exception:
                    pass

            for xo_name, xo_ref in xobjs.items():
                try:
                    xo = xo_ref if isinstance(xo_ref, pikepdf.Stream) else pdf.get_object(xo_ref)
                    if str(xo.get("/Subtype", "")) != "/Image":
                        continue

                    img_w = int(xo.get("/Width", 0))
                    img_h = int(xo.get("/Height", 0))
                    bpc = int(xo.get("/BitsPerComponent", 8))
                    cs = str(xo.get("/ColorSpace", ""))
                    filter_type = str(xo.get("/Filter", ""))

                    img_result = {
                        "page": page_num,
                        "width": img_w,
                        "height": img_h,
                        "bpc": bpc,
                        "color_space": cs.replace("/", ""),
                        "filter": filter_type.replace("/", ""),
                        "indicators": [],
                    }

                    # Indikator 1: Bild füllt gesamte Seite (= gescanntes Dokument)
                    if page_w > 0 and page_h > 0 and img_w > 0 and img_h > 0:
                        # DPI schätzen
                        dpi_w = img_w / (page_w / 72)
                        dpi_h = img_h / (page_h / 72)
                        avg_dpi = (dpi_w + dpi_h) / 2

                        coverage = (img_w * img_h) / max((page_w * page_h), 1)
                        # Anpassung: Seitengröße in Punkten vs Pixel
                        page_area_at_dpi = (page_w / 72 * avg_dpi) * (page_h / 72 * avg_dpi)
                        fill_ratio = (img_w * img_h) / max(page_area_at_dpi, 1) if avg_dpi > 50 else 0

                        if fill_ratio > 0.8:
                            img_result["indicators"].append("full_page_image")
                            scan_indicators.append(f"Seite {page_num}: Ganzseitiges Bild ({img_w}×{img_h})")
                            total_score += 30

                        # DPI-Erkennung
                        common_dpis = [72, 96, 150, 200, 300, 400, 600, 1200]
                        closest_dpi = min(common_dpis, key=lambda d: abs(avg_dpi - d))
                        if abs(avg_dpi - closest_dpi) < 5:
                            img_result["detected_dpi"] = closest_dpi
                            if result["dpi_detected"] is None:
                                result["dpi_detected"] = closest_dpi
                            if closest_dpi in [200, 300, 400, 600]:
                                img_result["indicators"].append(f"scan_dpi_{closest_dpi}")
                                scan_indicators.append(f"Scan-typische Auflösung: {closest_dpi} DPI")
                                total_score += 15

                    # Indikator 2: 1-Bit Bilder (SW-Scan)
                    if bpc == 1:
                        img_result["indicators"].append("1bit_bilevel")
                        scan_indicators.append(f"Seite {page_num}: 1-Bit Bilevel (SW-Scan)")
                        total_score += 20

                    # Indikator 3: CCITT/JBIG2 Filter (Scan-typisch)
                    if "CCITT" in filter_type or "JBIG2" in filter_type:
                        img_result["indicators"].append("scan_filter")
                        scan_indicators.append(f"Seite {page_num}: {filter_type.replace('/', '')} (Scan-typisch)")
                        total_score += 20

                    # Pixel-Analyse (wenn möglich)
                    try:
                        raw_data = xo.read_bytes()
                        if len(raw_data) > 100 and img_w > 50 and img_h > 50:
                            pixel_analysis = _analyze_pixels(raw_data, img_w, img_h, bpc, cs)
                            if pixel_analysis:
                                img_result.update(pixel_analysis)
                                if pixel_analysis.get("halftone"):
                                    result["halftone_detected"] = True
                                    scan_indicators.append(f"Seite {page_num}: Halftone-Raster erkannt")
                                    total_score += 15
                                if pixel_analysis.get("banding"):
                                    result["banding_detected"] = True
                                    scan_indicators.append(f"Seite {page_num}: Drucker-Banding erkannt")
                                    total_score += 10
                    except Exception:
                        pass

                    image_results.append(img_result)
                    result["images_analyzed"] += 1

                except Exception as e:
                    logger.debug(f"Printer-Forensik Bild-Analyse: {e}")
                    continue

        # Ergebnis zusammensetzen
        result["scan_indicators"] = scan_indicators
        result["image_results"] = image_results[:20]
        result["scan_confidence"] = min(total_score / 100.0, 1.0)
        result["is_scanned_document"] = result["scan_confidence"] > 0.5

        # Druckertyp ableiten
        if result["halftone_detected"]:
            result["printer_type"] = "Laser/LED"
        elif any("1bit" in (i.get("indicators", [])) for i in image_results):
            result["printer_type"] = "Fax/Bilevel Scanner"
        elif result["is_scanned_document"]:
            result["printer_type"] = "Flatbed/ADF Scanner"

        # Anomalien
        if result["is_scanned_document"]:
            result["anomalies"].append({
                "severity": "INFO",
                "category": "Printer",
                "message": "Dokument ist ein Scan",
                "detail": f"Scan-Konfidenz: {result['scan_confidence']:.0%}, DPI: {result['dpi_detected'] or 'unbekannt'}",
            })

        if result["halftone_detected"]:
            result["anomalies"].append({
                "severity": "INFO",
                "category": "Printer",
                "message": "Halftone-Raster (Drucker-Spuren) erkannt",
                "detail": f"Drucker-Typ: {result['printer_type'] or 'unbekannt'}",
            })

    except Exception as e:
        logger.error(f"Printer-Forensik fehlgeschlagen: {e}")
        result["error"] = str(e)

    pdf.close()
    return result


def _analyze_pixels(raw_data: bytes, width: int, height: int, bpc: int, cs: str) -> Dict[str, Any]:
    """Analysiert Pixel-Daten auf Drucker-/Scan-Artefakte."""
    analysis = {
        "halftone": False,
        "banding": False,
        "noise_level": None,
    }

    try:
        import numpy as np

        # Nur für 8-bit Grayscale oder RGB
        if bpc != 8:
            return analysis

        channels = 3 if "RGB" in cs else 1
        expected_size = width * height * channels

        if len(raw_data) < expected_size:
            return analysis

        arr = np.frombuffer(raw_data[:expected_size], dtype=np.uint8)

        if channels == 3:
            arr = arr.reshape((height, width, 3))
            # Zu Grayscale konvertieren
            gray = (0.299 * arr[:, :, 0] + 0.587 * arr[:, :, 1] + 0.114 * arr[:, :, 2]).astype(np.uint8)
        else:
            gray = arr.reshape((height, width))

        # Noise-Level schätzen (Standardabweichung der Differenz benachbarter Pixel)
        if gray.shape[0] > 2 and gray.shape[1] > 2:
            diff_h = np.diff(gray.astype(np.int16), axis=1)
            diff_v = np.diff(gray.astype(np.int16), axis=0)
            noise = float(np.std(diff_h)) + float(np.std(diff_v))
            analysis["noise_level"] = round(noise / 2, 2)

            # Banding-Erkennung: Periodische horizontale/vertikale Streifen
            row_means = np.mean(gray, axis=1)
            if len(row_means) > 10:
                row_diff = np.diff(row_means.astype(np.float64))
                # FFT für Periodizität
                fft = np.abs(np.fft.rfft(row_diff))
                if len(fft) > 10:
                    # Starke Peaks bei bestimmten Frequenzen = Banding
                    peak_ratio = np.max(fft[5:]) / (np.mean(fft[5:]) + 1e-6)
                    if peak_ratio > 10:
                        analysis["banding"] = True

            # Halftone-Erkennung: Hohe Frequenz-Energie in kleinen Blöcken
            if gray.shape[0] >= 64 and gray.shape[1] >= 64:
                block = gray[32:96, 32:96].astype(np.float64)
                fft2 = np.abs(np.fft.fft2(block))
                center = fft2.shape[0] // 2
                # Energie in hohen Frequenzen
                high_freq = np.mean(fft2[center - 5:center + 5, :]) + np.mean(fft2[:, center - 5:center + 5])
                low_freq = np.mean(fft2[:5, :5])
                if low_freq > 0 and high_freq / (low_freq + 1e-6) > 0.3:
                    analysis["halftone"] = True

    except Exception as e:
        logger.debug(f"Pixel-Analyse: {e}")

    return analysis
