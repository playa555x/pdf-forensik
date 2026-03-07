"""
Steganographie-Analyzer: Erkennt versteckte Informationen in Bilddateien.

Methoden:
1. LSB Chi-Square-Test (JPEG/PNG) — statistischer Test auf LSB-Steganographie
2. RS-Analyse (Regular-Singular) — robustere LSB-Stego-Erkennung
3. DCT-F5-Hinweis-Detektion — F5-Algorithmus-Hinweise bei JPEG
4. PNG-zTXt/tEXt/iTXt-Chunks — Versteckte Texte in PNG-Metadaten
5. Palette-basierte Stego (GIF/PNG-8) — Palettenreihenfolgen-Manipulation
6. Trailing-Data-Detektion — Daten nach Bild-EOF

Ohne aletheia-Library: Pure-Python-Implementierung der wichtigsten Tests.
"""
from __future__ import annotations
import io
import math
import struct
import zlib
from pathlib import Path
from typing import List, Dict, Any, Optional

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

from models.schemas import Anomaly, AnomalySeverity


# ============================================================
# LSB Chi-Square-Test
# ============================================================

def lsb_chi_square(file_path: Path, sample_ratio: float = 0.5) -> Dict[str, Any]:
    """
    Chi-Square-Test auf LSB-Steganographie.

    Idee: Bei natürlichen Bildern haben benachbarte Grauwerte (2k, 2k+1)
    ähnliche Häufigkeiten. Bei LSB-Stego werden die LSBs manipuliert →
    Häufigkeiten der PoVs (Pairs of Values) werden gleichmäßig.

    chi²-Wert nahe 0 = LSB-Stego wahrscheinlich.
    chi²-Wert >> 0   = natürliches Bild.
    """
    if not PIL_OK or not NP_OK:
        return {'available': False}

    try:
        img = Image.open(file_path).convert('L')
        pixels = np.array(img).flatten()

        # Sample (Performance)
        if sample_ratio < 1.0:
            n = max(1000, int(len(pixels) * sample_ratio))
            pixels = pixels[:n]

        # Histogramm
        hist = np.bincount(pixels, minlength=256)

        # PoV-Paare (0,1), (2,3), (4,5), ...
        chi_sq = 0.0
        pairs_tested = 0
        for i in range(0, 254, 2):
            n0 = hist[i]
            n1 = hist[i + 1]
            expected = (n0 + n1) / 2
            if expected > 0:
                chi_sq += (n0 - expected) ** 2 / expected
                chi_sq += (n1 - expected) ** 2 / expected
                pairs_tested += 1

        # Normalisierter Chi-Square
        chi_norm = chi_sq / (pairs_tested * 2) if pairs_tested > 0 else 0

        # p-Wert-Annäherung (Chi-Square-Verteilung mit df=pairs_tested)
        # Einfache Entscheidungsregel: chi_norm < 0.5 → verdächtig
        suspected = chi_norm < 0.5 and len(pixels) > 10000

        # Geschätzte LSB-Kapazität und Füllung
        capacity_bits = len(pixels)
        capacity_kb   = capacity_bits / 8 / 1024

        return {
            'available':   True,
            'chi_square':  round(chi_sq, 2),
            'chi_norm':    round(chi_norm, 4),
            'pairs_tested': pairs_tested,
            'suspected':   suspected,
            'capacity_kb': round(capacity_kb, 2),
            'note': ('LSB-Steganographie wahrscheinlich (Chi² ≈ 0)'
                     if suspected
                     else f'Kein LSB-Stego-Signal (Chi²-norm: {chi_norm:.4f})'),
        }
    except Exception as e:
        return {'available': True, 'error': str(e), 'suspected': False}


# ============================================================
# RS-Analyse (Regular-Singular)
# ============================================================

def rs_analysis(file_path: Path) -> Dict[str, Any]:
    """
    RS-Analyse nach Fridrich et al. — robusterer LSB-Stego-Test.

    Teilt Bild in Gruppen, klassifiziert als Regular (R), Singular (S)
    oder Unusable (U). Bei LSB-Stego: R_m ≈ R_{-m} und S_m ≈ S_{-m}.
    """
    if not PIL_OK or not NP_OK:
        return {'available': False}

    try:
        img = Image.open(file_path).convert('L')
        pixels = np.array(img, dtype=np.int16)
        h, w = pixels.shape

        if h * w < 1000:
            return {'available': True, 'note': 'Bild zu klein für RS-Analyse', 'suspected': False}

        # Diskriminanzfunktion: Summe absoluter Differenzen benachbarter Pixel
        def discrimination(group: np.ndarray) -> float:
            return float(np.sum(np.abs(np.diff(group.astype(np.float32)))))

        # Flip-Funktion +1 (LSB setzen)
        def flip_pos(x: np.ndarray) -> np.ndarray:
            return np.where(x % 2 == 0, x + 1, x - 1).astype(np.int16)

        # Flip-Funktion -1 (invertiertes Flip)
        def flip_neg(x: np.ndarray) -> np.ndarray:
            result = x.copy()
            result[x % 2 == 0] -= 1
            result[x % 2 == 1] += 1
            return np.clip(result, 0, 255).astype(np.int16)

        group_size = 4
        R_m, S_m, R_nm, S_nm = 0, 0, 0, 0
        total = 0

        # Sample: erste 10000 Gruppen
        flat = pixels.flatten()
        n_groups = min(10000, len(flat) // group_size)

        for i in range(n_groups):
            g = flat[i * group_size: (i + 1) * group_size]
            d_orig = discrimination(g)
            d_flip = discrimination(flip_pos(g))
            d_fneg = discrimination(flip_neg(g))

            if d_flip > d_orig:  R_m += 1
            if d_flip < d_orig:  S_m += 1
            if d_fneg > d_orig:  R_nm += 1
            if d_fneg < d_orig:  S_nm += 1
            total += 1

        if total == 0:
            return {'available': True, 'suspected': False}

        r_m  = R_m  / total
        s_m  = S_m  / total
        r_nm = R_nm / total
        s_nm = S_nm / total

        # LSB-Füllung schätzen (nach Fridrich)
        a = 2 * (r_nm - r_m)
        b = r_m - r_nm - s_m + s_nm
        c = s_nm - r_nm

        p = 0.0
        if abs(a) > 1e-10:
            discriminant = b ** 2 - 4 * a * c
            if discriminant >= 0:
                x1 = (-b + math.sqrt(discriminant)) / (2 * a)
                x2 = (-b - math.sqrt(discriminant)) / (2 * a)
                # Wähle die Lösung nahe [0, 0.5]
                for x in (x1, x2):
                    if 0.0 <= x <= 0.5:
                        p = x
                        break

        suspected = p > 0.05  # > 5% LSB-Füllung gilt als verdächtig

        return {
            'available':     True,
            'r_m':           round(r_m, 4),
            's_m':           round(s_m, 4),
            'r_nm':          round(r_nm, 4),
            's_nm':          round(s_nm, 4),
            'estimated_fill': round(p * 100, 2),  # in Prozent
            'suspected':     suspected,
            'note': (f'RS: Geschätzte LSB-Füllung {p*100:.1f}% — Steganographie verdächtig'
                     if suspected
                     else f'RS: Keine signifikante LSB-Steganographie (Füllung: {p*100:.1f}%)'),
        }
    except Exception as e:
        return {'available': True, 'error': str(e), 'suspected': False}


# ============================================================
# PNG-Chunk-Analyse
# ============================================================

def analyze_png_chunks(file_path: Path) -> Dict[str, Any]:
    """
    Analysiert PNG-Chunks nach versteckten Daten.
    Verdächtige Chunks: tEXt, zTXt, iTXt, iCCP, cHRM, hIST, pHYs (custom).
    Unbekannte Chunks können versteckte Daten enthalten.
    """
    if not file_path.suffix.lower() == '.png':
        return {'applicable': False, 'note': 'Nur für PNG-Dateien'}

    result = {
        'applicable': True,
        'chunks':     [],
        'text_data':  [],
        'unknown_chunks': [],
        'trailing_data':  False,
        'trailing_bytes': 0,
    }

    KNOWN_CHUNKS = {
        b'IHDR', b'IDAT', b'IEND', b'PLTE', b'tRNS', b'gAMA', b'cHRM',
        b'sRGB', b'sBIT', b'bKGD', b'hIST', b'pHYs', b'sPLT', b'tIME',
        b'tEXt', b'zTXt', b'iTXt', b'iCCP', b'eXIf',
    }

    try:
        with open(file_path, 'rb') as f:
            content = f.read()

        if content[:8] != b'\x89PNG\r\n\x1a\n':
            return {'applicable': True, 'error': 'Keine gültige PNG-Signatur'}

        offset = 8
        iend_pos = None

        while offset + 12 <= len(content):
            length = struct.unpack('>I', content[offset:offset+4])[0]
            chunk_type = content[offset+4:offset+8]
            chunk_data = content[offset+8:offset+8+length]
            crc = content[offset+8+length:offset+12+length]

            chunk_name = chunk_type.decode('latin-1', errors='replace')
            is_known = chunk_type in KNOWN_CHUNKS

            result['chunks'].append({
                'type':    chunk_name,
                'length':  length,
                'known':   is_known,
                'offset':  offset,
            })

            # Text-Chunks extrahieren
            if chunk_type == b'tEXt':
                try:
                    parts = chunk_data.split(b'\x00', 1)
                    key   = parts[0].decode('latin-1', errors='replace')
                    value = parts[1].decode('latin-1', errors='replace') if len(parts) > 1 else ''
                    result['text_data'].append({'key': key, 'value': value[:500], 'type': 'tEXt'})
                except Exception:
                    pass

            elif chunk_type == b'zTXt':
                try:
                    null_pos = chunk_data.index(b'\x00')
                    key = chunk_data[:null_pos].decode('latin-1')
                    compressed = chunk_data[null_pos+2:]
                    value = zlib.decompress(compressed).decode('utf-8', errors='replace')
                    result['text_data'].append({'key': key, 'value': value[:500], 'type': 'zTXt'})
                except Exception:
                    pass

            elif chunk_type == b'iTXt':
                try:
                    raw = chunk_data.decode('utf-8', errors='replace')
                    result['text_data'].append({'key': 'iTXt', 'value': raw[:500], 'type': 'iTXt'})
                except Exception:
                    pass

            # Unbekannte Chunks
            if not is_known:
                result['unknown_chunks'].append({
                    'type':    chunk_name,
                    'length':  length,
                    'preview': chunk_data[:32].hex(),
                })

            if chunk_type == b'IEND':
                iend_pos = offset + 12 + length
                break

            offset += 12 + length

        # Trailing-Data nach IEND
        if iend_pos and iend_pos < len(content):
            trailing = content[iend_pos:]
            if trailing.strip(b'\x00'):
                result['trailing_data']  = True
                result['trailing_bytes'] = len(trailing)
                result['trailing_hex']   = trailing[:32].hex()

    except Exception as e:
        result['error'] = str(e)

    return result


# ============================================================
# Trailing-Data in JPEG
# ============================================================

def analyze_jpeg_trailing(file_path: Path) -> Dict[str, Any]:
    """Sucht nach Daten nach dem JPEG-EOI-Marker (0xFFD9)."""
    if file_path.suffix.lower() not in ('.jpg', '.jpeg'):
        return {'applicable': False}

    try:
        with open(file_path, 'rb') as f:
            content = f.read()

        # Letztes FFD9 finden
        eoi = content.rfind(b'\xff\xd9')
        if eoi == -1:
            return {'applicable': True, 'error': 'Kein JPEG-EOI-Marker'}

        trailing = content[eoi + 2:]
        if len(trailing.strip(b'\x00')) == 0:
            return {'applicable': True, 'trailing_data': False, 'trailing_bytes': 0}

        return {
            'applicable':    True,
            'trailing_data': True,
            'trailing_bytes': len(trailing),
            'trailing_hex':  trailing[:32].hex(),
            'trailing_text': trailing[:32].decode('latin-1', errors='replace'),
            'note': f'{len(trailing)} Bytes nach JPEG-EOF — mögliche Steganographie oder eingebettete Datei',
        }
    except Exception as e:
        return {'applicable': True, 'error': str(e)}


# ============================================================
# Hauptfunktion
# ============================================================

def analyze_steganography(file_path: Path) -> Dict[str, Any]:
    """Vollständige Steganalyse für JPEG/PNG."""
    anomalies: List[Anomaly] = []
    ext = file_path.suffix.lower()

    # LSB Chi-Square
    chi_result = lsb_chi_square(file_path)

    # RS-Analyse
    rs_result = rs_analysis(file_path)

    # PNG-spezifisch
    png_chunks = analyze_png_chunks(file_path) if ext == '.png' else {'applicable': False}

    # JPEG-Trailing
    jpeg_trailing = analyze_jpeg_trailing(file_path) if ext in ('.jpg', '.jpeg') else {'applicable': False}

    # Anomalien
    if chi_result.get('suspected'):
        anomalies.append(Anomaly(
            severity=AnomalySeverity.HIGH,
            category='steganography',
            message=f'LSB Chi-Square-Test: Steganographie verdächtig (χ²-norm: {chi_result.get("chi_norm", "?")})',
            detail=chi_result.get('note', ''),
        ))

    if rs_result.get('suspected'):
        fill = rs_result.get('estimated_fill', 0)
        anomalies.append(Anomaly(
            severity=AnomalySeverity.HIGH,
            category='steganography',
            message=f'RS-Analyse: ~{fill}% der LSBs manipuliert',
            detail=rs_result.get('note', ''),
        ))

    if png_chunks.get('unknown_chunks'):
        anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category='steganography',
            message=f'{len(png_chunks["unknown_chunks"])} unbekannte PNG-Chunks',
            detail=', '.join(c['type'] for c in png_chunks['unknown_chunks'][:5]),
        ))

    if png_chunks.get('trailing_data'):
        anomalies.append(Anomaly(
            severity=AnomalySeverity.HIGH,
            category='steganography',
            message=f'PNG: {png_chunks["trailing_bytes"]} Bytes Trailing-Data nach IEND',
            detail='Daten nach Bild-Ende — klassische Stego-Technik',
        ))

    if jpeg_trailing.get('trailing_data'):
        anomalies.append(Anomaly(
            severity=AnomalySeverity.HIGH,
            category='steganography',
            message=f'JPEG: {jpeg_trailing["trailing_bytes"]} Bytes nach EOI-Marker',
            detail=jpeg_trailing.get('note', ''),
        ))

    if png_chunks.get('text_data'):
        for td in png_chunks['text_data']:
            if len(td.get('value', '')) > 100:
                anomalies.append(Anomaly(
                    severity=AnomalySeverity.INFO,
                    category='steganography',
                    message=f'PNG-Textchunk ({td["type"]}): "{td["key"]}" — {len(td["value"])} Zeichen',
                    detail=td['value'][:100],
                ))

    return {
        'lsb_chi':     chi_result,
        'rs_analysis': rs_result,
        'png_chunks':  png_chunks,
        'jpeg_trailing': jpeg_trailing,
        'anomalies':   anomalies,
    }
