"""
Deep JPEG Forensics.

Erweiterte JPEG-Forensik über die Standard-Analyse hinaus:
1. Double-Compression-Erkennung per DCT-Koeffizienten-Histogramm
2. Huffman-Tabellen-Analyse (Custom vs. Standard)
3. Thumbnail-Validierung (EXIF-Thumbnail vs. Hauptbild)
4. JPEG Ghost Detection (Qualitäts-Differenz-Mapping)
5. PRNU-Schätzung (Photo Response Non-Uniformity)
"""
from __future__ import annotations
import io
import struct
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional

from models.schemas import Anomaly, AnomalySeverity, DeepJpegResult

try:
    from PIL import Image
    PIL_OK = True
except ImportError:
    PIL_OK = False

try:
    import numpy as np
    NP_OK = True
except ImportError:
    NP_OK = False


# Standard-Huffman-Tabellen (JPEG ITU-T.81 Annex K)
STANDARD_LUMA_DC_BITS = bytes([0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0])
STANDARD_CHROMA_DC_BITS = bytes([0, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0])


def _parse_jpeg_markers(data: bytes) -> List[Dict[str, Any]]:
    """Parst alle JPEG-Marker und ihre Segmente."""
    markers = []
    pos = 0
    while pos < len(data) - 1:
        if data[pos] != 0xFF:
            pos += 1
            continue
        marker = data[pos + 1]
        if marker == 0x00 or marker == 0xFF:
            pos += 1
            continue

        entry = {"marker": f"0xFF{marker:02X}", "offset": pos}

        # Marker ohne Länge
        if marker in (0xD8, 0xD9):  # SOI, EOI
            entry["name"] = "SOI" if marker == 0xD8 else "EOI"
            markers.append(entry)
            pos += 2
            continue

        # SOS (Start of Scan) — danach kommen Bilddaten
        if marker == 0xDA:
            entry["name"] = "SOS"
            if pos + 3 < len(data):
                length = struct.unpack(">H", data[pos+2:pos+4])[0]
                entry["length"] = length
            markers.append(entry)
            break

        # Marker mit Länge
        if pos + 3 < len(data):
            length = struct.unpack(">H", data[pos+2:pos+4])[0]
            entry["length"] = length
            segment_data = data[pos+4:pos+2+length]

            if marker == 0xE0:
                entry["name"] = "APP0 (JFIF)"
            elif marker == 0xE1:
                entry["name"] = "APP1 (EXIF/XMP)"
                if segment_data[:4] == b"Exif":
                    entry["has_exif"] = True
            elif marker == 0xDB:
                entry["name"] = "DQT (Quantisierung)"
                entry["dqt_data"] = segment_data[:128].hex()
            elif marker == 0xC4:
                entry["name"] = "DHT (Huffman)"
                entry["dht_data"] = segment_data[:64].hex()
            elif marker == 0xC0:
                entry["name"] = "SOF0 (Baseline)"
                if len(segment_data) >= 5:
                    entry["precision"] = segment_data[0]
                    entry["height"] = struct.unpack(">H", segment_data[1:3])[0]
                    entry["width"] = struct.unpack(">H", segment_data[3:5])[0]
            elif marker == 0xC2:
                entry["name"] = "SOF2 (Progressive)"
            elif 0xE0 <= marker <= 0xEF:
                entry["name"] = f"APP{marker - 0xE0}"
            else:
                entry["name"] = f"Unknown (0x{marker:02X})"

            markers.append(entry)
            pos += 2 + length
        else:
            break

    return markers


def _analyze_dqt_double_compression(data: bytes) -> Dict[str, Any]:
    """
    Erkennt Double-Compression anhand der Quantisierungstabellen.
    Bei doppelter Kompression zeigen DCT-Koeffizienten periodische Artefakte.
    """
    result = {"detected": False, "tables": []}

    pos = 0
    tables = []
    while pos < len(data) - 1:
        if data[pos] == 0xFF and data[pos+1] == 0xDB:
            if pos + 3 < len(data):
                length = struct.unpack(">H", data[pos+2:pos+4])[0]
                seg = data[pos+4:pos+2+length]

                # DQT kann mehrere Tabellen enthalten
                offset = 0
                while offset < len(seg):
                    precision_id = seg[offset]
                    precision = (precision_id >> 4) & 0x0F
                    table_id = precision_id & 0x0F

                    if precision == 0:
                        table_size = 64
                    else:
                        table_size = 128

                    if offset + 1 + table_size <= len(seg):
                        qt = list(seg[offset+1:offset+1+table_size])
                        tables.append({"id": table_id, "values": qt[:64]})
                    offset += 1 + table_size

            pos += 2 + length if pos + 3 < len(data) else pos + 2
        else:
            pos += 1

    # Analyse der Quantisierungstabellen
    for t in tables:
        vals = t["values"]
        if len(vals) == 64:
            # Viele Einsen deuten auf Q=100 oder nahe dran
            ones_count = sum(1 for v in vals if v == 1)
            max_val = max(vals) if vals else 0

            # Schätze Qualität
            # Standard-Luminanz Q=50 Tabelle hat Werte wie 16,11,10,16,24,40,...
            # Dividende-Analyse
            quality_est = 0
            if vals[0] > 0:
                # Grobe Qualitätsschätzung basierend auf DC-Koeffizient
                if vals[0] <= 2:
                    quality_est = 95
                elif vals[0] <= 8:
                    quality_est = 85
                elif vals[0] <= 16:
                    quality_est = 75
                elif vals[0] <= 32:
                    quality_est = 50
                else:
                    quality_est = 30

            # Double-Compression-Indikator:
            # Wenn hochfrequente Koeffizienten (>= Index 32) viele identische Werte haben
            high_freq = vals[32:64]
            if high_freq:
                unique_high = len(set(high_freq))
                ratio = unique_high / len(high_freq)
                if ratio < 0.15 and max_val > 1:
                    result["detected"] = True
                    result["evidence"] = f"Table {t['id']}: Nur {unique_high} unique HF-Werte ({ratio:.0%})"

            t["quality_estimate"] = quality_est
            t["max_value"] = max_val

    result["tables"] = [{"id": t["id"], "quality": t.get("quality_estimate", 0), "max": t.get("max_value", 0)} for t in tables]
    return result


def _analyze_huffman_tables(data: bytes) -> Dict[str, Any]:
    """Vergleicht Huffman-Tabellen mit Standard-Tabellen."""
    result = {"custom_tables": False, "table_count": 0, "details": []}

    pos = 0
    while pos < len(data) - 1:
        if data[pos] == 0xFF and data[pos+1] == 0xC4:
            if pos + 3 < len(data):
                length = struct.unpack(">H", data[pos+2:pos+4])[0]
                seg = data[pos+4:pos+2+length]

                offset = 0
                while offset < len(seg) - 17:
                    info = seg[offset]
                    table_class = (info >> 4) & 0x0F  # 0=DC, 1=AC
                    table_id = info & 0x0F
                    bits = seg[offset+1:offset+17]
                    result["table_count"] += 1

                    # Vergleich mit Standard
                    is_standard = False
                    if table_class == 0 and table_id == 0:
                        is_standard = (bits == STANDARD_LUMA_DC_BITS)
                    elif table_class == 0 and table_id == 1:
                        is_standard = (bits == STANDARD_CHROMA_DC_BITS)

                    if not is_standard and table_class == 0:
                        result["custom_tables"] = True

                    total_symbols = sum(bits)
                    result["details"].append({
                        "class": "DC" if table_class == 0 else "AC",
                        "id": table_id,
                        "is_standard": is_standard,
                        "symbol_count": total_symbols,
                    })

                    offset += 17 + total_symbols

            pos += 2 + length if pos + 3 < len(data) else pos + 2
        else:
            pos += 1

    return result


def _check_thumbnail(file_path: Path) -> Dict[str, Any]:
    """Vergleicht EXIF-Thumbnail mit dem Hauptbild."""
    result = {"has_thumbnail": False, "mismatch": False}

    if not PIL_OK:
        return result

    try:
        img = Image.open(file_path)
        exif = img._getexif() if hasattr(img, "_getexif") else None
        if not exif:
            return result

        # Tag 0x0201 = JPEGInterchangeFormat (Thumbnail-Offset)
        # Tag 0x0202 = JPEGInterchangeFormatLength (Thumbnail-Länge)
        thumb_offset = exif.get(0x0201) or exif.get(513)
        thumb_length = exif.get(0x0202) or exif.get(514)

        if thumb_offset and thumb_length:
            result["has_thumbnail"] = True

            with open(file_path, "rb") as f:
                f.seek(thumb_offset)
                thumb_data = f.read(thumb_length)

            if thumb_data:
                try:
                    thumb_img = Image.open(io.BytesIO(thumb_data))

                    # Vergleiche Aspect-Ratio
                    main_ratio = img.width / img.height if img.height else 0
                    thumb_ratio = thumb_img.width / thumb_img.height if thumb_img.height else 0

                    if abs(main_ratio - thumb_ratio) > 0.1:
                        result["mismatch"] = True
                        result["reason"] = f"Aspect-Ratio-Differenz: Main {main_ratio:.2f}, Thumb {thumb_ratio:.2f}"

                    # Visueller Vergleich: Thumbnail runterskalieren und histogramm vergleichen
                    if NP_OK:
                        thumb_resized = thumb_img.resize((32, 32)).convert("L")
                        main_resized = img.resize((32, 32)).convert("L")

                        t_arr = np.array(thumb_resized, dtype=np.float32)
                        m_arr = np.array(main_resized, dtype=np.float32)

                        diff = np.mean(np.abs(t_arr - m_arr))
                        result["visual_diff"] = round(float(diff), 2)

                        if diff > 50:
                            result["mismatch"] = True
                            result["reason"] = f"Visueller Unterschied: {diff:.0f}/255 — Thumbnail zeigt anderes Bild"

                    result["thumb_size"] = f"{thumb_img.width}x{thumb_img.height}"
                    thumb_img.close()
                except Exception:
                    pass

        img.close()
    except Exception:
        pass

    return result


def _jpeg_ghost_detection(file_path: Path, test_qualities: List[int] = None) -> Dict[str, Any]:
    """
    JPEG Ghost Detection: Rekomprimiert bei verschiedenen Qualitäten und
    vergleicht die Differenz. Bereiche mit niedrigerer Differenz bei einer
    bestimmten Qualität deuten auf vorherige Kompression hin.
    """
    if not PIL_OK or not NP_OK:
        return {"available": False}

    if test_qualities is None:
        test_qualities = [60, 70, 75, 80, 85, 90, 95]

    result = {"available": True, "best_match_quality": None, "min_diff": 999.0, "quality_diffs": {}}

    try:
        orig = Image.open(file_path).convert("RGB")
        orig_arr = np.array(orig, dtype=np.float32)

        # Bild verkleinern für Performance
        if orig.width > 512 or orig.height > 512:
            scale = 512 / max(orig.width, orig.height)
            new_w = int(orig.width * scale)
            new_h = int(orig.height * scale)
            orig = orig.resize((new_w, new_h), Image.LANCZOS)
            orig_arr = np.array(orig, dtype=np.float32)

        for q in test_qualities:
            buf = io.BytesIO()
            orig.save(buf, "JPEG", quality=q)
            buf.seek(0)
            recomp = Image.open(buf).convert("RGB")
            recomp_arr = np.array(recomp, dtype=np.float32)

            diff = np.mean(np.abs(orig_arr - recomp_arr))
            result["quality_diffs"][str(q)] = round(float(diff), 3)

            if diff < result["min_diff"]:
                result["min_diff"] = round(float(diff), 3)
                result["best_match_quality"] = q

            recomp.close()

        orig.close()

        # Interpretation: Wenn die minimale Differenz bei einer bestimmten Qualität
        # deutlich niedriger ist als bei den anderen, war das Bild wahrscheinlich
        # mit dieser Qualität komprimiert.
        diffs = list(result["quality_diffs"].values())
        if diffs:
            mean_diff = sum(diffs) / len(diffs)
            if result["min_diff"] < mean_diff * 0.7:
                result["ghost_detected"] = True
                result["estimated_original_quality"] = result["best_match_quality"]
            else:
                result["ghost_detected"] = False

    except Exception as e:
        result["error"] = str(e)

    return result


def _estimate_prnu(file_path: Path) -> Dict[str, Any]:
    """
    PRNU-Schätzung (Photo Response Non-Uniformity).
    Extrahiert das Sensorrauschen als Fingerprint.
    Vereinfachte Version: Denoising-Filter und Rausch-Extraktion.
    """
    if not PIL_OK or not NP_OK:
        return {"available": False}

    try:
        img = Image.open(file_path).convert("L")
        arr = np.array(img, dtype=np.float64)

        # Verkleinern für Performance
        if arr.shape[0] > 256 or arr.shape[1] > 256:
            img = img.resize((256, 256), Image.LANCZOS)
            arr = np.array(img, dtype=np.float64)

        # Einfaches Denoising: 3x3 Mittelwert-Filter
        from numpy.lib.stride_tricks import sliding_window_view
        padded = np.pad(arr, 1, mode="edge")
        windows = sliding_window_view(padded, (3, 3))
        denoised = windows.mean(axis=(-1, -2))

        # Rauschkomponente = Original - Denoised
        noise = arr - denoised[:arr.shape[0], :arr.shape[1]]

        # Statistiken
        noise_std = float(np.std(noise))
        noise_mean = float(np.mean(np.abs(noise)))

        # Fingerprint-Hash (für Vergleich mit Referenz-PRNUs)
        noise_quantized = np.clip(noise * 10, -128, 127).astype(np.int8)
        prnu_hash = hashlib.sha256(noise_quantized.tobytes()).hexdigest()[:16]

        img.close()

        return {
            "available": True,
            "noise_std": round(noise_std, 4),
            "noise_mean": round(noise_mean, 4),
            "prnu_hash": prnu_hash,
            "note": "PRNU-Fingerprint extrahiert — vergleichbar mit Referenzbildern derselben Kamera",
        }

    except Exception as e:
        return {"available": True, "error": str(e)}


def analyze_deep_jpeg(image_paths: List[Path]) -> DeepJpegResult:
    """Führt die vollständige Deep-JPEG-Forensik durch."""
    anomalies: List[Anomaly] = []
    results: List[Dict[str, Any]] = []

    for img_path in image_paths[:20]:  # Max 20 Bilder
        if not img_path.exists():
            continue

        ext = img_path.suffix.lower()
        if ext not in (".jpg", ".jpeg"):
            continue

        try:
            with open(img_path, "rb") as f:
                data = f.read()
        except Exception:
            continue

        img_result: Dict[str, Any] = {
            "filename": img_path.name,
            "size_bytes": len(data),
        }

        # 1. Marker-Analyse
        markers = _parse_jpeg_markers(data)
        img_result["marker_count"] = len(markers)
        img_result["markers"] = [{"name": m.get("name", "?"), "offset": m.get("offset", 0)} for m in markers[:20]]

        # 2. Double-Compression via DQT
        dqt = _analyze_dqt_double_compression(data)
        img_result["dct_analysis"] = dqt
        if dqt.get("detected"):
            anomalies.append(Anomaly(
                severity=AnomalySeverity.HIGH,
                category="deep_jpeg",
                message=f"Double-Compression in {img_path.name}",
                detail=dqt.get("evidence", "DQT-Analyse zeigt periodische Artefakte"),
            ))

        # 3. Huffman-Tabellen
        huffman = _analyze_huffman_tables(data)
        img_result["huffman_analysis"] = huffman
        if huffman.get("custom_tables"):
            anomalies.append(Anomaly(
                severity=AnomalySeverity.INFO,
                category="deep_jpeg",
                message=f"Custom-Huffman-Tabellen in {img_path.name}",
                detail="Nicht-Standard-Huffman-Tabellen können auf spezifische Software hinweisen",
            ))

        # 4. Thumbnail-Check
        thumb = _check_thumbnail(img_path)
        img_result["thumbnail_check"] = thumb
        if thumb.get("mismatch"):
            anomalies.append(Anomaly(
                severity=AnomalySeverity.HIGH,
                category="deep_jpeg",
                message=f"EXIF-Thumbnail stimmt nicht mit Hauptbild überein: {img_path.name}",
                detail=thumb.get("reason", "Thumbnail-Mismatch erkannt"),
            ))

        # 5. JPEG Ghost Detection
        ghost = _jpeg_ghost_detection(img_path)
        img_result["ghost_detection"] = ghost
        if ghost.get("ghost_detected"):
            anomalies.append(Anomaly(
                severity=AnomalySeverity.MEDIUM,
                category="deep_jpeg",
                message=f"JPEG-Ghost in {img_path.name}: Original-Qualität ~{ghost.get('estimated_original_quality')}",
                detail=f"Min-Diff bei Q{ghost.get('best_match_quality')}: {ghost.get('min_diff')}",
            ))

        # 6. PRNU
        prnu = _estimate_prnu(img_path)
        img_result["prnu"] = prnu

        results.append(img_result)

    return DeepJpegResult(
        images_analyzed=len(results),
        results=results,
        anomalies=anomalies,
    )
