"""
Yellow Dots / MIC Detector — Druckerfingerprint.
Erkennt Machine Identification Code (MIC) in eingebetteten Bildern.
Methode 1: Pixel-Scan (immer verfügbar, PIL)
Methode 2: poppler/pdftoppm (optional)
"""
from __future__ import annotations
import os
import math
import tempfile
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

try:
    from PIL import Image
    PIL_OK = True
except ImportError:
    PIL_OK = False

try:
    import pikepdf
    PIKEPDF_OK = True
except ImportError:
    PIKEPDF_OK = False

from models.schemas import YellowDotsResult, Anomaly, AnomalySeverity


# Gelbe Pixel: R>180 & G>180 & B<100
_Y_R_MIN = 180
_Y_G_MIN = 180
_Y_B_MAX = 100

# Minimale Clustergröße
_MIN_CLUSTER_SIZE = 3

# Raster-Toleranz (px)
_GRID_TOLERANCE = 8

# Xerox MIC Pattern: 8 Zeilen × 15 Spalten, ~1/300 inch Abstand bei 600dpi ≈ 2px
_XEROX_ROWS = 8
_XEROX_COLS = 15


def _is_yellow(r: int, g: int, b: int) -> bool:
    return r > _Y_R_MIN and g > _Y_G_MIN and b < _Y_B_MAX


def _scan_image_for_dots(img: "Image.Image") -> List[Tuple[int, int]]:
    """Gibt Liste aller gelben Pixel-Koordinaten zurück."""
    dots: List[Tuple[int, int]] = []
    try:
        rgb = img.convert('RGB')
        pixels = rgb.load()
        w, h = rgb.size
        # Bei sehr großen Bildern: Sampling alle 2px
        step = 2 if (w * h) > 4_000_000 else 1
        for y in range(0, h, step):
            for x in range(0, w, step):
                r, g, b = pixels[x, y]
                if _is_yellow(r, g, b):
                    dots.append((x, y))
    except Exception:
        pass
    return dots


def _cluster_dots(dots: List[Tuple[int, int]], radius: int = 10) -> List[List[Tuple[int, int]]]:
    """Gruppiert nahe Punkte zu Clustern (einfaches Grid-basiertes Clustering)."""
    if not dots:
        return []

    clusters: List[List[Tuple[int, int]]] = []
    used = [False] * len(dots)

    for i, (x1, y1) in enumerate(dots):
        if used[i]:
            continue
        cluster = [(x1, y1)]
        used[i] = True
        for j, (x2, y2) in enumerate(dots):
            if used[j]:
                continue
            if abs(x1 - x2) <= radius and abs(y1 - y2) <= radius:
                cluster.append((x2, y2))
                used[j] = True
        clusters.append(cluster)

    return clusters


def _centroid(cluster: List[Tuple[int, int]]) -> Tuple[float, float]:
    xs = [p[0] for p in cluster]
    ys = [p[1] for p in cluster]
    return sum(xs) / len(xs), sum(ys) / len(ys)


def _check_regular_grid(centroids: List[Tuple[float, float]]) -> Optional[Dict[str, Any]]:
    """
    Prüft ob Cluster-Zentroide ein regelmäßiges Raster bilden.
    Gibt {'spacing_x', 'spacing_y', 'rows', 'cols'} zurück oder None.
    """
    if len(centroids) < 6:
        return None

    # Sortiere nach Y dann X
    by_y = sorted(centroids, key=lambda c: c[1])

    # Berechne Y-Abstände
    y_diffs = []
    for k in range(1, min(10, len(by_y))):
        d = abs(by_y[k][1] - by_y[k-1][1])
        if d > 2:
            y_diffs.append(d)

    if not y_diffs:
        return None

    median_y = sorted(y_diffs)[len(y_diffs) // 2]
    if median_y < 2:
        return None

    # Prüfe Konsistenz
    consistent = sum(1 for d in y_diffs if abs(d - median_y) <= _GRID_TOLERANCE)
    if consistent / len(y_diffs) < 0.5:
        return None

    return {
        "spacing_y_px": round(median_y, 1),
        "spacing_x_px": round(median_y, 1),  # Annäherung
        "dot_count": len(centroids),
    }


def _try_decode_xerox(centroids: List[Tuple[float, float]]) -> Dict[str, Any]:
    """
    Versucht Xerox MIC zu dekodieren (vereinfachtes Schema).
    Gibt Datums-/Serieninformation zurück wenn erfolgreich.
    """
    # Nur Platzhalter — echte Dekodierung benötigt kalibrierte Bilder
    return {}


def _extract_embedded_images(file_path: Path) -> List["Image.Image"]:
    """Lädt alle eingebetteten Bilder aus dem PDF via pikepdf."""
    images: List["Image.Image"] = []
    if not PIKEPDF_OK or not PIL_OK:
        return images

    try:
        with pikepdf.open(file_path, suppress_warnings=True) as pdf:
            for page in pdf.pages:
                for name, xobj in page.resources.get('/XObject', {}).items():
                    try:
                        if xobj.get('/Subtype') == '/Image':
                            img_data = xobj.read_bytes()
                            import io
                            img = Image.open(io.BytesIO(img_data))
                            img.load()
                            images.append(img)
                    except Exception:
                        pass
    except Exception:
        pass

    return images


def _scan_with_poppler(file_path: Path) -> Tuple[bool, int, Optional[str]]:
    """
    Optionale Methode: Rendert PDF mit pdftoppm und scannt gerenderte Seiten.
    Gibt (dots_found, dot_count, pattern_type) zurück.
    """
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            prefix = os.path.join(tmpdir, "page")
            result = subprocess.run(
                ['pdftoppm', '-r', '300', '-png', str(file_path), prefix],
                capture_output=True,
                timeout=30,
            )
            if result.returncode != 0:
                return False, 0, None

            total_dots = 0
            all_centroids: List[Tuple[float, float]] = []

            for png_file in Path(tmpdir).glob("*.png"):
                try:
                    img = Image.open(png_file)
                    dots = _scan_image_for_dots(img)
                    if dots:
                        clusters = _cluster_dots(dots)
                        sig_clusters = [c for c in clusters if len(c) >= _MIN_CLUSTER_SIZE]
                        total_dots += len(sig_clusters)
                        all_centroids.extend(_centroid(c) for c in sig_clusters)
                except Exception:
                    pass

            if total_dots > 0:
                grid_info = _check_regular_grid(all_centroids)
                pattern = "xerox_mic" if grid_info and total_dots >= 50 else "generic"
                return True, total_dots, pattern

    except FileNotFoundError:
        pass  # pdftoppm nicht installiert
    except Exception:
        pass

    return False, 0, None


def detect_yellow_dots(file_path: Path) -> YellowDotsResult:
    """Hauptfunktion — erkennt Machine Identification Code."""
    if not PIL_OK:
        return YellowDotsResult(
            available=False,
            method_used="none",
            anomalies=[Anomaly(
                severity=AnomalySeverity.INFO,
                category="yellow_dots",
                message="PIL/Pillow nicht verfügbar — Yellow-Dots-Analyse übersprungen",
            )],
        )

    anomalies: List[Anomaly] = []
    method_used = "none"
    dots_found = False
    dot_count = 0
    pattern_type: Optional[str] = None
    decoded_info: Dict[str, Any] = {}
    found_page: Optional[int] = None

    # Methode 1: Pixel-Scan eingebetteter Bilder
    embedded_images = _extract_embedded_images(file_path)

    if embedded_images:
        method_used = "pixel_scan"
        all_centroids: List[Tuple[float, float]] = []

        for img_idx, img in enumerate(embedded_images[:10]):  # Max 10 Bilder
            try:
                # Nur größere Bilder (kleine Icons überspringen)
                if img.width < 200 or img.height < 200:
                    continue

                dots = _scan_image_for_dots(img)
                if not dots:
                    continue

                clusters = _cluster_dots(dots)
                sig_clusters = [c for c in clusters if len(c) >= _MIN_CLUSTER_SIZE]

                if sig_clusters:
                    dot_count += len(sig_clusters)
                    centroids = [_centroid(c) for c in sig_clusters]
                    all_centroids.extend(centroids)
                    found_page = img_idx + 1

            except Exception:
                pass

        if dot_count > 0:
            dots_found = True
            grid_info = _check_regular_grid(all_centroids)

            if grid_info and dot_count >= 30:
                pattern_type = "xerox_mic"
                decoded_info = _try_decode_xerox(all_centroids)
                decoded_info.update(grid_info)
                anomalies.append(Anomaly(
                    severity=AnomalySeverity.HIGH,
                    category="yellow_dots",
                    message=f"Machine Identification Code (Xerox MIC) erkannt: {dot_count} Punkte in regelmäßigem Raster",
                    detail=f"Drucker-Fingerprint identifiziert. Muster: {grid_info}. Druckserie rückverfolgbar.",
                ))
            elif dot_count > 0:
                pattern_type = "generic"
                anomalies.append(Anomaly(
                    severity=AnomalySeverity.MEDIUM,
                    category="yellow_dots",
                    message=f"Gelbe Punkte in eingebetteten Bildern: {dot_count} Cluster",
                    detail="Mögliche Drucker-Fingerprints. Kein bekanntes MIC-Muster erkannt.",
                ))

    # Methode 2: poppler (optional, bessere Qualität)
    if not dots_found:
        pop_found, pop_count, pop_pattern = _scan_with_poppler(file_path)
        if pop_found:
            method_used = "poppler"
            dots_found = True
            dot_count = pop_count
            pattern_type = pop_pattern
            if pop_pattern == "xerox_mic":
                anomalies.append(Anomaly(
                    severity=AnomalySeverity.HIGH,
                    category="yellow_dots",
                    message=f"MIC erkannt (via poppler-Rendering): {pop_count} Punkte",
                    detail="Xerox-MIC-Muster in gerenderten Seiten gefunden.",
                ))

    return YellowDotsResult(
        available=True,
        method_used=method_used,
        dots_found=dots_found,
        dot_count=dot_count,
        pattern_type=pattern_type,
        decoded_info=decoded_info,
        page=found_page,
        anomalies=anomalies,
    )
