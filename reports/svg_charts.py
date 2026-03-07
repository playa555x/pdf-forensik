"""
SVG-Chart-Generator für den PDF-Forensik-Report.
Erzeugt einbettbare SVG-Strings für:
  - Risk Gauge (Halbkreis-Gauge)
  - Radar Chart (Analyzer-Übersicht)
  - Donut Chart (Anomalie-Verteilung)
  - Mini-Bar (kompakte Balken)
"""
from __future__ import annotations
import math
from typing import List, Tuple, Optional


# ── Farben ────────────────────────────────────────────────────────────────
COLORS = {
    "high":    "#ef4444",
    "medium":  "#f59e0b",
    "low":     "#3b82f6",
    "clean":   "#22c55e",
    "unknown": "#6b7280",
    "bg":      "#0f172a",
    "surface": "#1e293b",
    "border":  "#334155",
    "text":    "#e2e8f0",
    "muted":   "#94a3b8",
    "accent":  "#3b82f6",
}

RISK_COLORS = {
    "HIGH":    "#ef4444",
    "MEDIUM":  "#f59e0b",
    "LOW":     "#3b82f6",
    "CLEAN":   "#22c55e",
    "UNKNOWN": "#6b7280",
}


# ── Risk Gauge ────────────────────────────────────────────────────────────

def svg_risk_gauge(risk_level: str, width: int = 200, height: int = 120) -> str:
    """Erzeugt einen Halbkreis-Gauge für das Risiko-Level.

    risk_level: HIGH, MEDIUM, LOW, CLEAN, UNKNOWN
    """
    cx, cy = width / 2, height - 10
    r = min(width / 2 - 15, height - 25)

    # Risiko-Wert als Winkel (0=CLEAN, 180=HIGH)
    risk_map = {"CLEAN": 0.05, "LOW": 0.30, "MEDIUM": 0.60, "HIGH": 0.90, "UNKNOWN": 0.50}
    ratio = risk_map.get(risk_level, 0.5)

    color = RISK_COLORS.get(risk_level, "#6b7280")

    # Hintergrund-Arc (voller Halbkreis)
    bg_path = _arc_path(cx, cy, r, 180, 360)

    # Gefüllter Arc
    end_angle = 180 + ratio * 180
    fill_path = _arc_path(cx, cy, r, 180, end_angle)

    # Nadel
    needle_angle = math.radians(180 + ratio * 180)
    nx = cx + (r - 8) * math.cos(needle_angle)
    ny = cy + (r - 8) * math.sin(needle_angle)

    # Tick-Marks
    ticks = ""
    for i in range(5):
        a = math.radians(180 + i * 45)
        x1 = cx + (r + 3) * math.cos(a)
        y1 = cy + (r + 3) * math.sin(a)
        x2 = cx + (r - 3) * math.cos(a)
        y2 = cy + (r - 3) * math.sin(a)
        ticks += f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{COLORS["muted"]}" stroke-width="1.5"/>'

    # Glow-Effekt
    glow_id = f"gauge-glow-{id(risk_level) % 10000}"

    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}">
  <defs>
    <filter id="{glow_id}" x="-20%" y="-20%" width="140%" height="140%">
      <feGaussianBlur stdDeviation="3" result="blur"/>
      <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
    <linearGradient id="gauge-grad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#22c55e"/>
      <stop offset="33%" stop-color="#3b82f6"/>
      <stop offset="66%" stop-color="#f59e0b"/>
      <stop offset="100%" stop-color="#ef4444"/>
    </linearGradient>
  </defs>
  <!-- Background arc -->
  <path d="{bg_path}" fill="none" stroke="{COLORS['border']}" stroke-width="12" stroke-linecap="round"/>
  <!-- Gradient arc -->
  <path d="{bg_path}" fill="none" stroke="url(#gauge-grad)" stroke-width="10" stroke-linecap="round" opacity="0.3"/>
  <!-- Active arc -->
  <path d="{fill_path}" fill="none" stroke="{color}" stroke-width="10" stroke-linecap="round" filter="url(#{glow_id})"/>
  <!-- Ticks -->
  {ticks}
  <!-- Needle -->
  <line x1="{cx}" y1="{cy}" x2="{nx:.1f}" y2="{ny:.1f}" stroke="{color}" stroke-width="2.5" stroke-linecap="round"/>
  <circle cx="{cx}" cy="{cy}" r="4" fill="{color}"/>
  <circle cx="{cx}" cy="{cy}" r="2" fill="{COLORS['bg']}"/>
  <!-- Label -->
  <text x="{cx}" y="{cy + 14}" text-anchor="middle" font-family="Helvetica, Arial, sans-serif" font-size="11" font-weight="bold" fill="{color}">{risk_level}</text>
</svg>'''


# ── Radar Chart ───────────────────────────────────────────────────────────

def svg_radar_chart(
    items: List[Tuple[str, str, int]],  # [(name, status_class, anomaly_count), ...]
    width: int = 300,
    height: int = 300,
) -> str:
    """Erzeugt einen Radar-Chart für die Analyzer-Übersicht.

    status_class: 'ok', 'high', 'medium', 'low'
    """
    if not items:
        return ""

    cx, cy = width / 2, height / 2
    r_max = min(width, height) / 2 - 40
    n = len(items)

    # Status zu Wert (0-1, wobei 1 = schlecht)
    status_values = {"ok": 0.1, "low": 0.4, "medium": 0.7, "high": 1.0}

    # Konzentrischen Ringe
    rings = ""
    for level in [0.25, 0.5, 0.75, 1.0]:
        r = r_max * level
        rings += f'<circle cx="{cx}" cy="{cy}" r="{r:.1f}" fill="none" stroke="{COLORS["border"]}" stroke-width="0.5" stroke-dasharray="2,3"/>'

    # Achsen + Labels
    axes = ""
    labels = ""
    points = []

    for i, (name, status, count) in enumerate(items):
        angle = math.radians(-90 + (360 / n) * i)

        # Achse
        ax = cx + r_max * math.cos(angle)
        ay = cy + r_max * math.sin(angle)
        axes += f'<line x1="{cx}" y1="{cy}" x2="{ax:.1f}" y2="{ay:.1f}" stroke="{COLORS["border"]}" stroke-width="0.5"/>'

        # Datenpunkt
        val = status_values.get(status, 0.1)
        px = cx + r_max * val * math.cos(angle)
        py = cy + r_max * val * math.sin(angle)
        points.append((px, py, status))

        # Label
        lx = cx + (r_max + 18) * math.cos(angle)
        ly = cy + (r_max + 18) * math.sin(angle)
        anchor = "start" if math.cos(angle) > 0.1 else ("end" if math.cos(angle) < -0.1 else "middle")

        # Farbzuordnung
        label_color = RISK_COLORS.get(status.upper(), COLORS["text"]) if status != "ok" else COLORS["clean"]
        short_name = name[:12] + "…" if len(name) > 12 else name
        labels += f'<text x="{lx:.1f}" y="{ly:.1f}" text-anchor="{anchor}" font-family="Helvetica, Arial, sans-serif" font-size="7" fill="{label_color}" dominant-baseline="central">{short_name}</text>'

    # Polygon
    poly_points = " ".join(f"{p[0]:.1f},{p[1]:.1f}" for p in points)

    # Farbe des Polygons basierend auf dem schlimmsten Status
    statuses = [s for _, s, _ in items]
    if "high" in statuses:
        poly_color = COLORS["high"]
    elif "medium" in statuses:
        poly_color = COLORS["medium"]
    elif "low" in statuses:
        poly_color = COLORS["low"]
    else:
        poly_color = COLORS["clean"]

    # Datenpunkte als Dots
    dots = ""
    for px, py, status in points:
        dot_color = RISK_COLORS.get(status.upper(), COLORS["clean"]) if status != "ok" else COLORS["clean"]
        dots += f'<circle cx="{px:.1f}" cy="{py:.1f}" r="3" fill="{dot_color}" stroke="{COLORS["bg"]}" stroke-width="1.5"/>'

    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}">
  <!-- Rings -->
  {rings}
  <!-- Axes -->
  {axes}
  <!-- Polygon -->
  <polygon points="{poly_points}" fill="{poly_color}" fill-opacity="0.15" stroke="{poly_color}" stroke-width="1.5"/>
  <!-- Dots -->
  {dots}
  <!-- Labels -->
  {labels}
</svg>'''


# ── Donut Chart ───────────────────────────────────────────────────────────

def svg_donut_chart(
    high: int, medium: int, low: int,
    width: int = 160, height: int = 160,
) -> str:
    """Erzeugt einen Donut-Chart für die Anomalie-Verteilung."""
    total = high + medium + low
    if total == 0:
        # Leerer Donut = alles clean
        cx, cy, r = width / 2, height / 2, 55
        return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}">
  <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{COLORS['clean']}" stroke-width="18" opacity="0.3"/>
  <text x="{cx}" y="{cy - 4}" text-anchor="middle" font-family="Helvetica, Arial, sans-serif" font-size="22" font-weight="bold" fill="{COLORS['clean']}">0</text>
  <text x="{cx}" y="{cy + 12}" text-anchor="middle" font-family="Helvetica, Arial, sans-serif" font-size="8" fill="{COLORS['muted']}">CLEAN</text>
</svg>'''

    cx, cy, r = width / 2, height / 2, 55
    stroke_w = 18
    circumference = 2 * math.pi * r

    segments = [
        (high, COLORS["high"]),
        (medium, COLORS["medium"]),
        (low, COLORS["low"]),
    ]

    arcs = ""
    offset = 0
    for count, color in segments:
        if count == 0:
            continue
        dash = (count / total) * circumference
        gap = circumference - dash
        arcs += f'''<circle cx="{cx}" cy="{cy}" r="{r}" fill="none"
    stroke="{color}" stroke-width="{stroke_w}"
    stroke-dasharray="{dash:.1f} {gap:.1f}"
    stroke-dashoffset="{-offset:.1f}"
    transform="rotate(-90 {cx} {cy})"/>
'''
        offset += dash

    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}">
  <!-- Background ring -->
  <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{COLORS['border']}" stroke-width="{stroke_w}" opacity="0.3"/>
  <!-- Segments -->
  {arcs}
  <!-- Center text -->
  <text x="{cx}" y="{cy - 4}" text-anchor="middle" font-family="Helvetica, Arial, sans-serif" font-size="24" font-weight="bold" fill="{COLORS['text']}">{total}</text>
  <text x="{cx}" y="{cy + 12}" text-anchor="middle" font-family="Helvetica, Arial, sans-serif" font-size="7" fill="{COLORS['muted']}" letter-spacing="1.5">ANOMALIES</text>
</svg>'''


# ── Mini Status Bar ───────────────────────────────────────────────────────

def svg_status_indicator(status: str, label: str, width: int = 120, height: int = 24) -> str:
    """Kompakter Status-Indikator für Tabellen/Listen."""
    colors = {
        "ok": COLORS["clean"],
        "high": COLORS["high"],
        "medium": COLORS["medium"],
        "low": COLORS["low"],
    }
    color = colors.get(status, COLORS["muted"])

    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}">
  <rect x="0" y="4" width="{width}" height="16" rx="8" fill="{COLORS['surface']}" stroke="{COLORS['border']}" stroke-width="0.5"/>
  <circle cx="12" cy="12" r="4" fill="{color}"/>
  <text x="22" y="16" font-family="Helvetica, Arial, sans-serif" font-size="9" fill="{COLORS['text']}">{label}</text>
</svg>'''


# ── Horizontaler Balken (z.B. für Anomaly-Counts) ────────────────────────

def svg_horizontal_bar(
    values: List[Tuple[str, int, str]],  # [(label, count, color), ...]
    width: int = 300, height: int = 80,
) -> str:
    """Horizontale gestapelte Balken."""
    total = sum(v[1] for v in values) or 1
    bar_h = 16
    bar_y = 10

    bars = ""
    x = 30
    bar_width = width - 40

    for label, count, color in values:
        w = (count / total) * bar_width
        if w > 0:
            bars += f'<rect x="{x:.1f}" y="{bar_y}" width="{w:.1f}" height="{bar_h}" fill="{color}" rx="2"/>'
        x += w

    # Labels darunter
    legend = ""
    lx = 30
    for label, count, color in values:
        legend += f'<circle cx="{lx + 5}" cy="{bar_y + bar_h + 18}" r="4" fill="{color}"/>'
        legend += f'<text x="{lx + 13}" y="{bar_y + bar_h + 21}" font-family="Helvetica, Arial, sans-serif" font-size="8" fill="{COLORS["muted"]}">{label}: {count}</text>'
        lx += 80

    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}">
  <!-- Track -->
  <rect x="30" y="{bar_y}" width="{bar_width}" height="{bar_h}" rx="3" fill="{COLORS['border']}" opacity="0.4"/>
  <!-- Bars -->
  {bars}
  <!-- Legend -->
  {legend}
</svg>'''


# ── Timeline ─────────────────────────────────────────────────────────────

def svg_timeline(
    events: List[Tuple[str, str, str]],  # [(date_str, label, color), ...]
    width: int = 500, height: int = 60,
) -> str:
    """Horizontale Timeline für Zeitstempel-Vergleiche."""
    if not events:
        return ""

    n = len(events)
    margin = 50
    usable = width - 2 * margin
    spacing = usable / max(n - 1, 1) if n > 1 else 0

    line_y = 22

    # Hauptlinie
    svg_content = f'<line x1="{margin}" y1="{line_y}" x2="{width - margin}" y2="{line_y}" stroke="{COLORS["border"]}" stroke-width="2"/>'

    for i, (date_str, label, color) in enumerate(events):
        x = margin + i * spacing if n > 1 else width / 2

        # Punkt
        svg_content += f'<circle cx="{x:.1f}" cy="{line_y}" r="5" fill="{color}" stroke="{COLORS["bg"]}" stroke-width="2"/>'

        # Label oben/unten alternierend
        if i % 2 == 0:
            svg_content += f'<text x="{x:.1f}" y="{line_y - 12}" text-anchor="middle" font-family="Helvetica, Arial, sans-serif" font-size="7" fill="{COLORS["text"]}">{label}</text>'
            svg_content += f'<text x="{x:.1f}" y="{line_y + 18}" text-anchor="middle" font-family="Courier, monospace" font-size="6" fill="{COLORS["muted"]}">{date_str}</text>'
        else:
            svg_content += f'<text x="{x:.1f}" y="{line_y + 18}" text-anchor="middle" font-family="Helvetica, Arial, sans-serif" font-size="7" fill="{COLORS["text"]}">{label}</text>'
            svg_content += f'<text x="{x:.1f}" y="{line_y + 30}" text-anchor="middle" font-family="Courier, monospace" font-size="6" fill="{COLORS["muted"]}">{date_str}</text>'

    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}">
  {svg_content}
</svg>'''


# ── Hilfsfunktion: Arc Path ──────────────────────────────────────────────

def _arc_path(cx: float, cy: float, r: float, start_deg: float, end_deg: float) -> str:
    """SVG Arc Path von start_deg bis end_deg (Grad, 0=rechts, 90=unten)."""
    start_rad = math.radians(start_deg)
    end_rad = math.radians(end_deg)

    x1 = cx + r * math.cos(start_rad)
    y1 = cy + r * math.sin(start_rad)
    x2 = cx + r * math.cos(end_rad)
    y2 = cy + r * math.sin(end_rad)

    large_arc = 1 if (end_deg - start_deg) > 180 else 0

    return f"M {x1:.1f} {y1:.1f} A {r:.1f} {r:.1f} 0 {large_arc} 1 {x2:.1f} {y2:.1f}"


# ── Analyzer Status Grid (als SVG-Tabelle) ───────────────────────────────

def svg_analyzer_grid(
    items: List[Tuple[str, str, str, int]],  # [(name, css_class, label, count), ...]
    width: int = 500,
) -> str:
    """Kompaktes Analyzer-Status-Grid als SVG."""
    if not items:
        return ""

    cols = 3
    rows = math.ceil(len(items) / cols)
    cell_w = width / cols
    cell_h = 28
    height = rows * cell_h + 4

    status_colors = {
        "ok":     (COLORS["clean"],  "#052e16"),
        "high":   (COLORS["high"],   "#450a0a"),
        "medium": (COLORS["medium"], "#451a03"),
        "low":    (COLORS["low"],    "#172554"),
    }

    cells = ""
    for i, (name, cls, label, count) in enumerate(items):
        col = i % cols
        row = i // cols
        x = col * cell_w + 2
        y = row * cell_h + 2

        fg, bg = status_colors.get(cls, (COLORS["muted"], COLORS["surface"]))

        # Cell background
        cells += f'<rect x="{x:.1f}" y="{y:.1f}" width="{cell_w - 4:.1f}" height="{cell_h - 4:.1f}" rx="4" fill="{bg}" stroke="{fg}" stroke-width="0.5" opacity="0.8"/>'

        # Status dot
        cells += f'<circle cx="{x + 10:.1f}" cy="{y + cell_h / 2 - 2:.1f}" r="3.5" fill="{fg}"/>'

        # Name
        short = name[:14]
        cells += f'<text x="{x + 18:.1f}" y="{y + cell_h / 2 + 1:.1f}" font-family="Helvetica, Arial, sans-serif" font-size="7.5" fill="{fg}" font-weight="bold">{short}</text>'

        # Count (right-aligned)
        if count > 0:
            cells += f'<text x="{x + cell_w - 12:.1f}" y="{y + cell_h / 2 + 1:.1f}" text-anchor="end" font-family="Helvetica, Arial, sans-serif" font-size="7" fill="{fg}">{count}</text>'

    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height:.0f}">
  {cells}
</svg>'''
