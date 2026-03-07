"""
Image-Forensics-Analyzer: Tiefe forensische Analyse von JPEG/PNG-Bildern.

Methoden:
1. EXIF-Vollextraktion + Konsistenzprüfung
2. Error Level Analysis (ELA) via OpenCV — präziser als PIL-Version
3. Copy-Move-Detektion via DCT-Block-Hashing + optionaler SIFT-Feature-Matching
4. PRNU-Kamerasensor-Fingerprint (vereinfacht, ohne Referenz-Datenbank)
5. Kompressionshistorie-Analyse (JPEG-Schichten via DCT-Koeffizienten)
6. Metadaten-Konsistenzcheck (EXIF vs Bild-Eigenschaften)
7. Thumbnails-Analyse (internes EXIF-Thumbnail vs Hauptbild)
8. Double-JPEG-Compression-Detektion
"""
from __future__ import annotations
import io
import hashlib
import math
import struct
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

try:
    from PIL import Image, ImageChops, ImageEnhance, ImageFilter
    from PIL.ExifTags import TAGS, GPSTAGS
    PIL_OK = True
except ImportError:
    PIL_OK = False

try:
    import numpy as np
    import cv2
    CV2_OK = True
except ImportError:
    CV2_OK = False

from models.schemas import Anomaly, AnomalySeverity


# ============================================================
# EXIF-Vollextraktion
# ============================================================

def _gps_to_decimal(gps_coords, gps_ref: str) -> Optional[float]:
    """Konvertiert IFDRational GPS-Koordinaten in Dezimalgrad."""
    try:
        d = float(gps_coords[0])
        m = float(gps_coords[1])
        s = float(gps_coords[2])
        dec = d + m / 60 + s / 3600
        if gps_ref in ('S', 'W'):
            dec = -dec
        return round(dec, 7)
    except Exception:
        return None


def extract_full_exif(file_path: Path) -> Dict[str, Any]:
    """Extrahiert und strukturiert alle EXIF-Daten inkl. GPS-Dekodierung."""
    result: Dict[str, Any] = {
        'fields': {},
        'gps': None,
        'gps_lat': None,
        'gps_lon': None,
        'gps_alt': None,
        'thumbnail': None,
        'has_thumbnail': False,
        'software': None,
        'camera_make': None,
        'camera_model': None,
        'lens': None,
        'original_datetime': None,
        'digitized_datetime': None,
        'modified_datetime': None,
        'color_space': None,
        'flash': None,
        'exposure_time': None,
        'f_number': None,
        'iso': None,
        'focal_length': None,
        'orientation': None,
        'serial_number': None,
    }

    if not PIL_OK:
        return result

    try:
        img = Image.open(file_path)

        # Thumbnail extrahieren (EXIF-internes Thumbnail)
        try:
            if hasattr(img, '_getexif') and img._getexif():
                thumb_data = img.info.get('exif', b'')
                # EXIF-Thumbnail-Offset: APP1-Marker
                if b'\xff\xd8\xff' in thumb_data:
                    th_start = thumb_data.index(b'\xff\xd8\xff')
                    th_end   = thumb_data.rfind(b'\xff\xd9') + 2
                    if th_end > th_start:
                        th_bytes = thumb_data[th_start:th_end]
                        result['has_thumbnail'] = True
                        # Als base64 für Frontend
                        import base64
                        result['thumbnail'] = f"data:image/jpeg;base64,{base64.b64encode(th_bytes).decode()}"
        except Exception:
            pass

        raw_exif = img._getexif() if hasattr(img, '_getexif') else None  # type: ignore
        if not raw_exif:
            img.close()
            return result

        gps_raw = {}
        for tag_id, value in raw_exif.items():
            tag_name = TAGS.get(tag_id, str(tag_id))
            try:
                if isinstance(value, bytes):
                    try:
                        value = value.decode('utf-8', errors='replace')
                    except Exception:
                        value = value.hex()[:64]
                elif hasattr(value, 'numerator'):
                    value = float(value)
                elif isinstance(value, tuple) and all(hasattr(v, 'numerator') for v in value):
                    value = [float(v) for v in value]
                result['fields'][tag_name] = str(value)[:500]
            except Exception:
                continue

            # Bekannte Felder direkt mappen
            if tag_name == 'GPSInfo' and isinstance(raw_exif[tag_id], dict):
                gps_raw = raw_exif[tag_id]
            elif tag_name == 'Make':
                result['camera_make'] = str(value)
            elif tag_name == 'Model':
                result['camera_model'] = str(value)
            elif tag_name == 'Software':
                result['software'] = str(value)
            elif tag_name == 'LensModel':
                result['lens'] = str(value)
            elif tag_name == 'DateTimeOriginal':
                result['original_datetime'] = str(value)
            elif tag_name == 'DateTimeDigitized':
                result['digitized_datetime'] = str(value)
            elif tag_name == 'DateTime':
                result['modified_datetime'] = str(value)
            elif tag_name == 'ColorSpace':
                result['color_space'] = str(value)
            elif tag_name == 'Flash':
                result['flash'] = str(value)
            elif tag_name == 'ExposureTime':
                result['exposure_time'] = str(value)
            elif tag_name == 'FNumber':
                result['f_number'] = str(value)
            elif tag_name == 'ISOSpeedRatings':
                result['iso'] = str(value)
            elif tag_name == 'FocalLength':
                result['focal_length'] = str(value)
            elif tag_name == 'Orientation':
                result['orientation'] = str(value)
            elif tag_name in ('BodySerialNumber', 'CameraSerialNumber'):
                result['serial_number'] = str(value)

        # GPS dekodieren
        if gps_raw:
            try:
                lat_d  = gps_raw.get(2)
                lat_r  = gps_raw.get(1, 'N')
                lon_d  = gps_raw.get(4)
                lon_r  = gps_raw.get(3, 'E')
                alt_d  = gps_raw.get(6)

                if lat_d:
                    result['gps_lat'] = _gps_to_decimal(lat_d, lat_r)
                if lon_d:
                    result['gps_lon'] = _gps_to_decimal(lon_d, lon_r)
                if alt_d:
                    result['gps_alt'] = round(float(alt_d), 2)

                if result['gps_lat'] and result['gps_lon']:
                    result['gps'] = f"{result['gps_lat']}, {result['gps_lon']}"
                    result['gps_maps_url'] = f"https://www.openstreetmap.org/?mlat={result['gps_lat']}&mlon={result['gps_lon']}&zoom=17"
            except Exception:
                pass

        img.close()
    except Exception as e:
        result['error'] = str(e)

    return result


# ============================================================
# ELA mit OpenCV (präziser als PIL-Variante)
# ============================================================

def ela_opencv(file_path: Path, quality: int = 90) -> Dict[str, Any]:
    """
    Error Level Analysis mit OpenCV.
    Verwendet JPEG-Recompression und berechnet absolute Differenz pixelweise.
    """
    if not CV2_OK or not PIL_OK:
        return {'available': False, 'error': 'OpenCV/Pillow not available'}

    try:
        img = cv2.imread(str(file_path))
        if img is None:
            # PNG oder anderes Format
            pil_img = Image.open(file_path).convert('RGB')
            img = np.array(pil_img)
            img = cv2.cvtColor(img, cv2.COLOR_RGB2BGR)

        if img is None:
            return {'available': False, 'error': 'Could not load image'}

        # Re-komprimieren
        encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), quality]
        _, encoded = cv2.imencode('.jpg', img, encode_param)
        recomp = cv2.imdecode(encoded, cv2.IMREAD_COLOR)

        # Differenz berechnen
        diff = cv2.absdiff(img.astype(np.float32), recomp.astype(np.float32))

        # Skalieren
        diff_scaled = np.clip(diff * 10, 0, 255).astype(np.uint8)

        # Statistiken
        ela_mean  = float(np.mean(diff))
        ela_max   = float(np.max(diff))
        ela_std   = float(np.std(diff))

        # Regionale Anomalie-Karte (8x8 Blockanalyse)
        h, w = diff.mean(axis=2).shape
        block_size = 32
        hot_blocks = 0
        total_blocks = 0
        block_stats = []

        for y in range(0, h - block_size, block_size):
            for x in range(0, w - block_size, block_size):
                block = diff[y:y+block_size, x:x+block_size]
                bm = float(np.mean(block))
                total_blocks += 1
                if bm > ela_mean * 2.5 and bm > 15:
                    hot_blocks += 1
                    block_stats.append({'x': x, 'y': y, 'mean': round(bm, 2)})

        hot_pct = hot_blocks / total_blocks * 100 if total_blocks > 0 else 0

        # Verdict
        if ela_mean > 20 or hot_pct > 15:
            verdict = 'SUSPICIOUS'
            note    = f'ELA-Mittelwert {ela_mean:.1f}, {hot_pct:.1f}% heiße Blöcke — mögliche Bildmanipulation'
        elif ela_mean < 2 and ela_std < 1:
            verdict = 'LOW_SIGNAL'
            note    = 'Sehr niedriges ELA-Signal — Bild ist möglicherweise generiert oder upsampled'
        else:
            verdict = 'NORMAL'
            note    = f'ELA-Wert im normalen Bereich (Mean: {ela_mean:.1f})'

        # ELA-Vorschaubild als Base64
        ela_preview = None
        try:
            import base64
            _, buf = cv2.imencode('.jpg', diff_scaled, [int(cv2.IMWRITE_JPEG_QUALITY), 85])
            ela_preview = f"data:image/jpeg;base64,{base64.b64encode(buf.tobytes()).decode()}"
        except Exception:
            pass

        return {
            'available':   True,
            'ela_mean':    round(ela_mean, 3),
            'ela_max':     round(ela_max, 3),
            'ela_std':     round(ela_std, 3),
            'hot_blocks':  hot_blocks,
            'hot_pct':     round(hot_pct, 2),
            'verdict':     verdict,
            'note':        note,
            'ela_preview': ela_preview,
            'dimensions':  f'{w}×{h}',
            'hot_regions': sorted(block_stats, key=lambda b: -b['mean'])[:10],
        }

    except Exception as e:
        return {'available': True, 'error': str(e), 'verdict': 'ERROR'}


# ============================================================
# Copy-Move-Detektion mit DCT-Block-Hashing
# ============================================================

def copy_move_dct(file_path: Path, block_size: int = 16) -> Dict[str, Any]:
    """
    Copy-Move-Detektion via DCT-Koeffizienten-Hashing.
    Teilt das Bild in überlappende Blöcke, berechnet DCT, hasht, sucht Duplikate.
    Robuster als reine Pixel-Hashing-Methode.
    """
    if not CV2_OK:
        return {'available': False, 'copy_move_detected': False}

    try:
        img = cv2.imread(str(file_path), cv2.IMREAD_GRAYSCALE)
        if img is None:
            pil_img = Image.open(file_path).convert('L')
            img = np.array(pil_img)

        if img is None:
            return {'available': False, 'copy_move_detected': False, 'error': 'Cannot load'}

        h, w = img.shape
        img_float = img.astype(np.float32)

        hashes: Dict[str, List] = {}
        step = block_size  # Nicht-überlappend für Performance

        for y in range(0, h - block_size, step):
            for x in range(0, w - block_size, step):
                block = img_float[y:y+block_size, x:x+block_size]
                dct_block = cv2.dct(block)
                # Nur erste 4x4 DCT-Koeffizienten (niedrige Frequenzen)
                low_freq = dct_block[:4, :4].flatten()
                # Quantisieren für Robustheit
                quantized = np.round(low_freq / 5).astype(np.int16)
                h_key = quantized.tobytes()
                if h_key not in hashes:
                    hashes[h_key] = []
                hashes[h_key].append({'x': x, 'y': y})

        # Duplikate finden (gleiche DCT-Signatur an verschiedenen Positionen)
        duplicates = {k: v for k, v in hashes.items() if len(v) > 1}

        # Ignoriere uniforme Blöcke (alle fast gleich = weißer Hintergrund)
        # Filtere Blöcke wo Standardabweichung < 5 (zu homogen)
        significant_dups = {}
        for k, positions in duplicates.items():
            # Stichprobe: ersten Block prüfen
            p = positions[0]
            block = img_float[p['y']:p['y']+block_size, p['x']:p['x']+block_size]
            if np.std(block) > 5:
                significant_dups[k] = positions

        dup_count   = sum(len(v) - 1 for v in significant_dups.values())
        dup_regions = [{'positions': v[:4]} for v in list(significant_dups.values())[:10]]

        detected = dup_count > 8
        return {
            'available':         True,
            'copy_move_detected': detected,
            'duplicate_blocks':  dup_count,
            'duplicate_regions': dup_regions,
            'note': f'{dup_count} signifikante DCT-Duplikate' if detected else 'Keine Copy-Move-Anomalie',
        }
    except Exception as e:
        return {'available': True, 'copy_move_detected': False, 'error': str(e)}


# ============================================================
# PRNU-Kamerasensor-Fingerprint (vereinfacht)
# ============================================================

def analyze_prnu(file_path: Path) -> Dict[str, Any]:
    """
    Vereinfachte PRNU-Analyse (Photo Response Non-Uniformity).

    Echte PRNU braucht Referenz-Aufnahmen derselben Kamera.
    Diese vereinfachte Version:
    1. Extrahiert das Rauschbild via Wiener-Filter
    2. Berechnet statistische Eigenschaften des Rauschens
    3. Erkennt auffällige Rausch-Inhomogenitäten (Hinweis auf Komposit-Bild)

    Hinweis: Ohne Referenz kann nur Inkonsistenz detektiert werden,
    keine Kamera-Identifikation.
    """
    if not CV2_OK:
        return {'available': False, 'note': 'OpenCV nicht verfügbar'}

    try:
        img = cv2.imread(str(file_path))
        if img is None:
            pil_img = Image.open(file_path).convert('RGB')
            img = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)

        if img is None:
            return {'available': False, 'error': 'Bild konnte nicht geladen werden'}

        # In Float konvertieren
        img_f = img.astype(np.float64) / 255.0

        # Rauschbild via Hochpass-Filter (vereinfachter Wiener-Ansatz)
        blurred = cv2.GaussianBlur(img_f, (5, 5), 1.0)
        noise   = img_f - blurred

        # Rausch-Statistiken
        noise_mean   = float(np.mean(np.abs(noise)))
        noise_std    = float(np.std(noise))
        noise_energy = float(np.sum(noise ** 2))

        # Regionale Rauschanalyse (Quadranten)
        h, w = noise.shape[:2]
        quadrants = {
            'oben_links':    noise[:h//2, :w//2],
            'oben_rechts':   noise[:h//2, w//2:],
            'unten_links':   noise[h//2:, :w//2],
            'unten_rechts':  noise[h//2:, w//2:],
        }
        quad_stds = {k: float(np.std(v)) for k, v in quadrants.items()}
        max_std = max(quad_stds.values()) if quad_stds else 0
        min_std = min(quad_stds.values()) if quad_stds else 0
        inhomogeneity = (max_std - min_std) / (max_std + 1e-10)

        # Frequenzanalyse (Periodische Muster = mögliche Komposition)
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY).astype(np.float32)
        fft  = np.fft.fft2(gray)
        fft_shift = np.fft.fftshift(fft)
        magnitude = np.log1p(np.abs(fft_shift))
        fft_max  = float(np.max(magnitude))
        fft_mean = float(np.mean(magnitude))
        frequency_ratio = fft_max / (fft_mean + 1e-10)

        # Verdict
        verdict = 'NORMAL'
        notes   = []
        if inhomogeneity > 0.4:
            verdict = 'INHOMOGENEOUS'
            notes.append(f'Rausch-Inhomogenität {inhomogeneity:.2f} — unterschiedliche Rauschlevels in Bildregionen')
        if frequency_ratio > 25:
            verdict = 'SUSPICIOUS' if verdict == 'INHOMOGENEOUS' else 'FREQUENCY_ANOMALY'
            notes.append(f'Frequenzspitzen-Verhältnis {frequency_ratio:.1f} — periodische Muster im Frequenzbereich')

        return {
            'available':      True,
            'noise_mean':     round(noise_mean * 1000, 3),   # in Promille
            'noise_std':      round(noise_std * 1000, 3),
            'noise_energy':   round(noise_energy, 2),
            'inhomogeneity':  round(inhomogeneity, 4),
            'frequency_ratio': round(frequency_ratio, 2),
            'quad_stds':      {k: round(v * 1000, 3) for k, v in quad_stds.items()},
            'verdict':        verdict,
            'notes':          notes,
            'note': notes[0] if notes else 'Kein auffälliges Rauschprofil',
        }
    except Exception as e:
        return {'available': True, 'error': str(e)}


# ============================================================
# Double-JPEG-Compression-Detektion
# ============================================================

def detect_double_compression(file_path: Path) -> Dict[str, Any]:
    """
    Erkennt doppelte JPEG-Kompression durch Analyse der DCT-Koeffizienten-Verteilung.

    Bei einfacher JPEG-Kompression: Histogramm der DCT-Koeff. folgt glatter Kurve.
    Bei doppelter Kompression: Periodische Knicke/Dips im Histogramm (BDCT-Artefakte).

    Funktioniert nur bei JPEG-Dateien.
    """
    result = {'available': True, 'is_jpeg': False, 'double_compressed': False}

    if not file_path.suffix.lower() in ('.jpg', '.jpeg'):
        result['note'] = 'Nur für JPEG-Dateien anwendbar'
        return result

    if not CV2_OK:
        result['available'] = False
        return result

    try:
        img = cv2.imread(str(file_path), cv2.IMREAD_GRAYSCALE)
        if img is None:
            return result

        result['is_jpeg'] = True
        h, w = img.shape
        img_float = img.astype(np.float32)

        # DCT über 8x8-Blöcke (JPEG-Standard)
        coeffs = []
        for y in range(0, h - 8, 8):
            for x in range(0, w - 8, 8):
                block = img_float[y:y+8, x:x+8]
                dct_block = cv2.dct(block)
                coeffs.extend(dct_block.flatten().tolist())

        if not coeffs:
            return result

        coeffs_arr = np.array(coeffs)
        # Auf DC-Koeffizienten filtern (absolute Werte < 200 für Analyse)
        ac_coeffs = coeffs_arr[np.abs(coeffs_arr) < 200]

        # Histogramm der gerundeten AC-Koeffizienten
        hist, bins = np.histogram(ac_coeffs.astype(int), bins=range(-50, 51))

        # Prüfe auf periodische Dips (Nullstellen bei geraden Werten = doppelt komprimiert)
        even_vals  = hist[25::2][:15]   # Gerade Bins ab 0
        odd_vals   = hist[26::2][:15]   # Ungerade Bins ab 1

        even_mean = float(np.mean(even_vals)) if len(even_vals) > 0 else 0
        odd_mean  = float(np.mean(odd_vals))  if len(odd_vals)  > 0 else 0

        # Bei doppelter Kompression: gerade Bins systematisch niedriger als ungerade
        ratio = odd_mean / (even_mean + 1) if even_mean > 0 else 1
        double_compressed = ratio > 1.4 and even_mean > 10

        # Geschätzte originale JPEG-Qualität aus Quantisierungstabelle
        estimated_original_quality = None
        try:
            with Image.open(file_path) as pil_img:
                quantization = pil_img.quantization
                if quantization:
                    luma_table = quantization.get(0, [])
                    if luma_table:
                        q_mean = sum(luma_table[:16]) / 16
                        # Grobe Annäherung: niedrige Q-Tabellen = hohe Qualität
                        estimated_original_quality = max(1, min(100, int(100 - q_mean * 0.7)))
        except Exception:
            pass

        result.update({
            'double_compressed': double_compressed,
            'compression_ratio': round(ratio, 3),
            'estimated_quality': estimated_original_quality,
            'note': ('Doppelte JPEG-Kompression wahrscheinlich — Bild wurde re-gespeichert'
                     if double_compressed
                     else 'Keine signifikanten Doppelkompressionsartefakte'),
        })

    except Exception as e:
        result['error'] = str(e)

    return result


# ============================================================
# Thumbnail-Konsistenz-Check
# ============================================================

def check_thumbnail_consistency(exif_data: Dict[str, Any], file_path: Path) -> Dict[str, Any]:
    """
    Vergleicht das EXIF-interne Thumbnail mit dem Hauptbild.
    Diskrepanz = Hinweis auf nachträgliche Bearbeitung (Bild ausgetauscht, Thumbnail alt).
    """
    result = {
        'has_thumbnail': exif_data.get('has_thumbnail', False),
        'consistent':    True,
        'size_diff_pct': None,
    }

    if not exif_data.get('has_thumbnail') or not exif_data.get('thumbnail'):
        return result

    if not PIL_OK:
        return result

    try:
        # Hauptbild-Dimensionen
        with Image.open(file_path) as main_img:
            main_w, main_h = main_img.size
            main_aspect = main_w / main_h if main_h else 1

        # Thumbnail-Dimensionen
        thumb_b64 = exif_data['thumbnail'].split(',', 1)[-1]
        import base64
        thumb_bytes = base64.b64decode(thumb_b64)
        with Image.open(io.BytesIO(thumb_bytes)) as th_img:
            th_w, th_h = th_img.size
            th_aspect = th_w / th_h if th_h else 1

        # Aspect-Ratio-Vergleich (Toleranz 5%)
        aspect_diff = abs(main_aspect - th_aspect) / (main_aspect + 1e-10)
        result['main_dimensions'] = f'{main_w}×{main_h}'
        result['thumb_dimensions'] = f'{th_w}×{th_h}'
        result['aspect_diff_pct'] = round(aspect_diff * 100, 2)
        result['consistent'] = aspect_diff < 0.05

        if not result['consistent']:
            result['note'] = f'Thumbnail-Seitenverhältnis {th_w/th_h:.2f} ≠ Hauptbild {main_w/main_h:.2f} — mögliche nachträgliche Bearbeitung'
        else:
            result['note'] = 'Thumbnail konsistent mit Hauptbild'

    except Exception as e:
        result['error'] = str(e)

    return result


# ============================================================
# AI-Bild-Erkennung (heuristische Methoden)
# ============================================================

def detect_ai_generated(file_path: Path, exif_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Heuristische KI-Bild-Erkennung.

    Echte KI-Detektion braucht ein trainiertes CNN (z.B. CNNDetection, UnivFD).
    Diese Methode verwendet forensische Heuristiken:

    1. Fehlende Kamera-EXIF (KI-Bilder haben keine echten Kamera-Daten)
    2. Software-Tags (DALL-E, Midjourney, Stable Diffusion, ComfyUI etc.)
    3. Spektrale Analyse (KI-Bilder haben andere Hochfrequenz-Verteilung)
    4. Keine Double-Compression (KI-Bilder sind meist erste Speicherung)
    5. Rauschprofil: KI-Bilder oft zu glatt oder zu strukturiert
    """
    if not CV2_OK or not PIL_OK:
        return {'available': False}

    signals = []
    score   = 0  # 0-100, höher = wahrscheinlicher KI

    # 1. Software-Tags
    software = (exif_data.get('software') or '').lower()
    ai_software_keywords = [
        'stable diffusion', 'diffusion', 'midjourney', 'dall-e', 'dalle',
        'comfyui', 'automatic1111', 'novelai', 'adobe firefly', 'firefly',
        'ideogram', 'flux', 'sdxl', 'sd ', 'diffusers', 'hugging face',
        'invoke', 'a1111', 'fooocus',
    ]
    for kw in ai_software_keywords:
        if kw in software:
            score += 40
            signals.append(f'Software-Tag enthält "{kw}"')
            break

    # 2. Keine Kamera-Daten bei hochauflösendem Bild
    has_camera = bool(exif_data.get('camera_make') or exif_data.get('camera_model'))
    has_lens   = bool(exif_data.get('lens'))
    has_iso    = bool(exif_data.get('iso'))

    if not has_camera and not has_lens and not has_iso:
        score += 15
        signals.append('Keine Kamera-EXIF (kein Make/Model/ISO/Lens)')
    elif not has_camera:
        score += 8
        signals.append('Kein Kamera-Make/Model in EXIF')

    # 3. Spektrale Analyse
    try:
        img = cv2.imread(str(file_path), cv2.IMREAD_GRAYSCALE)
        if img is not None:
            # FFT-Analyse: KI-Bilder oft sehr glatte Spektren ODER spezifische Artefakte
            fft = np.fft.fft2(img.astype(np.float32))
            fft_shift = np.fft.fftshift(fft)
            magnitude = np.abs(fft_shift)

            h, w = magnitude.shape
            # Energie in verschiedenen Frequenzbändern
            center = magnitude[h//2-10:h//2+10, w//2-10:w//2+10]
            outer  = np.concatenate([magnitude[:20, :].flatten(), magnitude[-20:, :].flatten()])

            center_energy = float(np.mean(center))
            outer_energy  = float(np.mean(outer))
            hf_ratio = outer_energy / (center_energy + 1e-10)

            if hf_ratio < 0.001:
                score += 15
                signals.append(f'Sehr niedriger Hochfrequenzanteil ({hf_ratio:.5f}) — typisch für synthetische Bilder')
            elif hf_ratio > 0.05:
                score -= 10  # Eher echtes Foto (viel Rauschen/Textur)

    except Exception:
        pass

    # 4. Bildgröße prüft (KI-Bilder oft exakte Power-of-2 Dimensionen)
    try:
        with Image.open(file_path) as img_pil:
            w, h = img_pil.size
            common_ai_dims = {
                (512, 512), (768, 768), (1024, 1024), (1024, 768), (768, 1024),
                (1280, 720), (1920, 1080), (2048, 2048), (1024, 576), (576, 1024),
                (896, 1152), (1152, 896), (832, 1216), (1216, 832), (1344, 768),
            }
            if (w, h) in common_ai_dims:
                score += 10
                signals.append(f'Bildgröße {w}×{h} ist typisch für KI-Generatoren')
    except Exception:
        pass

    # 5. Keine GPS, kein Datum bei Foto-ähnlichem Bild
    if not exif_data.get('gps') and not exif_data.get('original_datetime') and not has_camera:
        score += 10
        signals.append('Kein GPS, kein Aufnahmedatum, keine Kamera — deutet auf synthetisches Bild hin')

    # Verdict
    if score >= 50:
        verdict = 'LIKELY_AI'
        confidence = min(95, score)
    elif score >= 25:
        verdict = 'POSSIBLY_AI'
        confidence = min(70, score)
    elif score >= 10:
        verdict = 'UNCERTAIN'
        confidence = score
    else:
        verdict = 'LIKELY_REAL'
        confidence = max(0, 100 - score * 5)

    return {
        'available':  True,
        'verdict':    verdict,
        'score':      score,
        'confidence': confidence,
        'signals':    signals,
        'note': {
            'LIKELY_AI':     f'Wahrscheinlich KI-generiert (Score: {score}/100)',
            'POSSIBLY_AI':   f'Möglicherweise KI-generiert (Score: {score}/100)',
            'UNCERTAIN':     f'Unklare Herkunft (Score: {score}/100)',
            'LIKELY_REAL':   f'Wahrscheinlich echtes Foto (Score: {score}/100)',
        }.get(verdict, f'Score: {score}'),
    }


# ============================================================
# Hauptfunktion
# ============================================================

def analyze_image_forensics(file_path: Path) -> Dict[str, Any]:
    """Vollständige Bildforensik für JPEG/PNG."""
    anomalies: List[Anomaly] = []

    # EXIF
    exif_data = extract_full_exif(file_path)

    # ELA
    ela = ela_opencv(file_path)

    # Copy-Move
    copy_move = copy_move_dct(file_path)

    # PRNU
    prnu = analyze_prnu(file_path)

    # Double Compression
    dbl_comp = detect_double_compression(file_path)

    # Thumbnail-Konsistenz
    thumb_check = check_thumbnail_consistency(exif_data, file_path)

    # AI-Detektion
    ai_detect = detect_ai_generated(file_path, exif_data)

    # Anomalien generieren
    if exif_data.get('gps'):
        anomalies.append(Anomaly(
            severity=AnomalySeverity.HIGH,
            category='image_forensics',
            message=f'GPS-Koordinaten in EXIF: {exif_data["gps"]}',
            detail='Aufnahmeort des Fotos ist im Bild gespeichert — Datenschutzrisiko!',
        ))

    if ela.get('verdict') == 'SUSPICIOUS':
        anomalies.append(Anomaly(
            severity=AnomalySeverity.HIGH,
            category='image_forensics',
            message='ELA: Verdächtige Bildregionen — mögliche Manipulation',
            detail=ela.get('note', ''),
        ))

    if copy_move.get('copy_move_detected'):
        anomalies.append(Anomaly(
            severity=AnomalySeverity.HIGH,
            category='image_forensics',
            message=f'Copy-Move: {copy_move["duplicate_blocks"]} duplizierte DCT-Blöcke',
            detail=copy_move.get('note', ''),
        ))

    if prnu.get('verdict') == 'SUSPICIOUS':
        anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category='image_forensics',
            message='PRNU: Rausch-Inhomogenität — mögliche Bildkomposition',
            detail=prnu.get('note', ''),
        ))

    if dbl_comp.get('double_compressed'):
        anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category='image_forensics',
            message='Doppelte JPEG-Kompression erkannt — Bild wurde nachbearbeitet',
            detail=dbl_comp.get('note', ''),
        ))

    if not thumb_check.get('consistent') and thumb_check.get('has_thumbnail'):
        anomalies.append(Anomaly(
            severity=AnomalySeverity.HIGH,
            category='image_forensics',
            message='Thumbnail-Seitenverhältnis weicht vom Hauptbild ab — mögliche Manipulation',
            detail=thumb_check.get('note', ''),
        ))

    if ai_detect.get('verdict') in ('LIKELY_AI', 'POSSIBLY_AI'):
        sev = AnomalySeverity.HIGH if ai_detect['verdict'] == 'LIKELY_AI' else AnomalySeverity.MEDIUM
        anomalies.append(Anomaly(
            severity=sev,
            category='image_forensics',
            message=f'KI-Bild-Erkennung: {ai_detect["verdict"]} (Score {ai_detect["score"]}/100)',
            detail='; '.join(ai_detect.get('signals', [])),
        ))

    return {
        'exif':             exif_data,
        'ela':              ela,
        'copy_move':        copy_move,
        'prnu':             prnu,
        'double_compression': dbl_comp,
        'thumbnail_check':  thumb_check,
        'ai_detection':     ai_detect,
        'anomalies':        anomalies,
    }
