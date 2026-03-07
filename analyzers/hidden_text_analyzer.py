"""
Hidden Text Analyzer — Content-Stream-Analyse.
Erkennt: weißer/unsichtbarer/0pt Text, OCG-Ebenen, Rendering Mode 3.
"""
from __future__ import annotations
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

try:
    import pikepdf
    PIKEPDF_OK = True
except ImportError:
    PIKEPDF_OK = False

from models.schemas import HiddenTextResult, Anomaly, AnomalySeverity


# Farbe die "fast weiß" ist (alle Kanäle > 0.92)
_WHITE_THRESHOLD = 0.92


def _parse_content_stream(stream_bytes: bytes, page_num: int, page_width: float, page_height: float) -> List[Dict[str, Any]]:
    """
    Einfacher PDF-Operator-Parser.
    Verfolgt Zustand: Farbe, Schriftgröße, Rendering Mode, Textposition.
    Gibt verdächtige Textblöcke zurück.
    """
    try:
        text = stream_bytes.decode('latin-1', errors='replace')
    except Exception:
        return []

    findings: List[Dict[str, Any]] = []

    # Zustand
    state = {
        'fill_r': 0.0, 'fill_g': 0.0, 'fill_b': 0.0,
        'font_size': 12.0,
        'render_mode': 0,
        'in_text': False,
        'tx': 0.0, 'ty': 0.0,
    }

    # Alle Token extrahieren
    tokens = re.split(r'\s+', text)
    i = 0
    operand_stack: List[str] = []

    while i < len(tokens):
        tok = tokens[i]
        i += 1

        if not tok:
            continue

        # Operatoren
        if tok == 'BT':
            state['in_text'] = True
            operand_stack = []

        elif tok == 'ET':
            state['in_text'] = False
            operand_stack = []

        elif tok == 'Tf':
            # <font_name> <size> Tf
            if len(operand_stack) >= 2:
                try:
                    state['font_size'] = float(operand_stack[-1])
                except ValueError:
                    pass
            operand_stack = []

        elif tok == 'rg':
            # r g b rg  (0..1 floats)
            if len(operand_stack) >= 3:
                try:
                    state['fill_r'] = float(operand_stack[-3])
                    state['fill_g'] = float(operand_stack[-2])
                    state['fill_b'] = float(operand_stack[-1])
                except ValueError:
                    pass
            operand_stack = []

        elif tok == 'RG':
            # Stroke color — ignorieren für unsere Zwecke
            operand_stack = []

        elif tok == 'g':
            # Graustufen-Füllfarbe
            if operand_stack:
                try:
                    gray = float(operand_stack[-1])
                    state['fill_r'] = gray
                    state['fill_g'] = gray
                    state['fill_b'] = gray
                except ValueError:
                    pass
            operand_stack = []

        elif tok == 'k':
            # CMYK — konvertiere grob zu RGB
            if len(operand_stack) >= 4:
                try:
                    c = float(operand_stack[-4])
                    m = float(operand_stack[-3])
                    y = float(operand_stack[-2])
                    k = float(operand_stack[-1])
                    state['fill_r'] = (1 - c) * (1 - k)
                    state['fill_g'] = (1 - m) * (1 - k)
                    state['fill_b'] = (1 - y) * (1 - k)
                except ValueError:
                    pass
            operand_stack = []

        elif tok == 'Tr':
            # Rendering Mode
            if operand_stack:
                try:
                    state['render_mode'] = int(float(operand_stack[-1]))
                except ValueError:
                    pass
            operand_stack = []

        elif tok in ('Td', 'TD'):
            if len(operand_stack) >= 2:
                try:
                    state['tx'] += float(operand_stack[-2])
                    state['ty'] += float(operand_stack[-1])
                except ValueError:
                    pass
            operand_stack = []

        elif tok == 'Tm':
            if len(operand_stack) >= 6:
                try:
                    state['tx'] = float(operand_stack[-2])
                    state['ty'] = float(operand_stack[-1])
                except ValueError:
                    pass
            operand_stack = []

        elif tok in ('Tj', "'", '"'):
            # Text-Zeige-Operator — extrahiere Text aus letztem String-Operanden
            if operand_stack:
                raw_text = operand_stack[-1]
                # Entferne (...)
                extracted = _extract_string(raw_text)
                if extracted and len(extracted.strip()) > 0:
                    _check_and_add(extracted, state, page_num, page_width, page_height, findings)
            operand_stack = []

        elif tok == 'TJ':
            # Array-Text
            # Sammle alles in operand_stack als Array-Inhalt
            joined = " ".join(operand_stack)
            parts = re.findall(r'\(([^)]*)\)', joined)
            if parts:
                extracted = "".join(parts)
                if extracted.strip():
                    _check_and_add(extracted, state, page_num, page_width, page_height, findings)
            operand_stack = []

        else:
            # Als Operand auf Stack legen
            operand_stack.append(tok)
            # Stack begrenzen
            if len(operand_stack) > 20:
                operand_stack = operand_stack[-20:]

    return findings


def _extract_string(raw: str) -> str:
    """Extrahiert Rohtext aus PDF-String-Notation (...)."""
    # Entferne führende/abschließende Klammern wenn vorhanden
    raw = raw.strip()
    if raw.startswith('(') and raw.endswith(')'):
        raw = raw[1:-1]
    # Escape-Sequenzen
    raw = raw.replace('\\n', ' ').replace('\\r', ' ').replace('\\t', ' ')
    raw = re.sub(r'\\[0-7]{1,3}', '', raw)
    return raw


def _check_and_add(text: str, state: dict, page_num: int, pw: float, ph: float, findings: List[Dict]):
    """Prüft ob Text versteckt ist und fügt zur Fundliste hinzu."""
    reason = None

    r, g, b = state['fill_r'], state['fill_g'], state['fill_b']
    font_size = state['font_size']
    render_mode = state['render_mode']

    if render_mode == 3:
        reason = "invisible_text"  # Rendering Mode 3 = unsichtbar
    elif r > _WHITE_THRESHOLD and g > _WHITE_THRESHOLD and b > _WHITE_THRESHOLD:
        reason = "white_text"
    elif font_size < 1.0 and font_size > 0:
        reason = "tiny_text"
    elif pw > 0 and ph > 0:
        # Off-page check
        tx, ty = state['tx'], state['ty']
        if tx < -50 or ty < -50 or tx > pw + 50 or ty > ph + 50:
            reason = "off_page"

    if reason and len(text.strip()) >= 2:
        findings.append({
            "page": page_num,
            "text": text[:100].strip(),
            "reason": reason,
            "font_size": font_size,
            "render_mode": render_mode,
            "color": f"rgb({r:.2f},{g:.2f},{b:.2f})",
            "x": state['tx'],
            "y": state['ty'],
        })


def _get_ocg_layers(pdf) -> List[Dict[str, Any]]:
    """Extrahiert OCG-Ebenen aus dem Catalog."""
    layers = []
    try:
        catalog = pdf.Root
        if '/OCProperties' in catalog:
            oc = catalog['/OCProperties']
            if '/OCGs' in oc:
                for ocg in oc['/OCGs']:
                    try:
                        name = str(ocg.get('/Name', 'unnamed'))
                        usage = {}
                        if '/Usage' in ocg:
                            u = ocg['/Usage']
                            if '/Print' in u:
                                usage['print'] = str(u['/Print'].get('/PrintState', '?'))
                            if '/View' in u:
                                usage['view'] = str(u['/View'].get('/ViewState', '?'))
                        layers.append({"name": name, "usage": usage})
                    except Exception:
                        pass
    except Exception:
        pass
    return layers


def analyze_hidden_text(file_path: Path) -> HiddenTextResult:
    """Hauptfunktion — analysiert alle Seiten auf versteckten Text."""
    if not PIKEPDF_OK:
        return HiddenTextResult(
            anomalies=[Anomaly(
                severity=AnomalySeverity.INFO,
                category="hidden_text",
                message="pikepdf nicht verfügbar — Hidden-Text-Analyse übersprungen",
            )]
        )

    all_findings: List[Dict[str, Any]] = []
    ocg_layers: List[Dict[str, Any]] = []
    render_mode_3_count = 0

    try:
        with pikepdf.open(file_path, suppress_warnings=True) as pdf:
            # OCG-Ebenen
            ocg_layers = _get_ocg_layers(pdf)

            for page_num, page in enumerate(pdf.pages, start=1):
                # Seitenmaße
                try:
                    mb = page['/MediaBox']
                    pw = float(mb[2])
                    ph = float(mb[3])
                except Exception:
                    pw, ph = 595.28, 841.89

                # /Contents lesen
                if '/Contents' not in page:
                    continue

                contents = page['/Contents']
                stream_bytes = b''

                if isinstance(contents, pikepdf.Array):
                    for c in contents:
                        try:
                            stream_bytes += c.read_bytes()
                        except Exception:
                            pass
                elif isinstance(contents, pikepdf.Stream):
                    try:
                        stream_bytes = contents.read_bytes()
                    except Exception:
                        pass

                if stream_bytes:
                    page_findings = _parse_content_stream(stream_bytes, page_num, pw, ph)
                    all_findings.extend(page_findings)

    except Exception as e:
        return HiddenTextResult(
            anomalies=[Anomaly(
                severity=AnomalySeverity.INFO,
                category="hidden_text",
                message=f"Hidden-Text-Analyse fehlgeschlagen: {e}",
            )]
        )

    # Zähler
    invisible_count = sum(1 for f in all_findings if f['reason'] == 'invisible_text')
    white_count = sum(1 for f in all_findings if f['reason'] == 'white_text')
    tiny_count = sum(1 for f in all_findings if f['reason'] == 'tiny_text')

    # Anomalien
    anomalies: List[Anomaly] = []

    if invisible_count > 0:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.HIGH,
            category="hidden_text",
            message=f"Unsichtbarer Text (Rendering Mode 3) auf {invisible_count} Block(s) gefunden",
            detail="Rendering Mode 3 macht Text für Betrachter vollständig unsichtbar — klassische Steganographie-Technik.",
        ))

    if white_count > 0:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category="hidden_text",
            message=f"Weißer Text (auf weißem Hintergrund) gefunden: {white_count} Block(s)",
            detail="Text mit weißer Füllfarbe ist für Betrachter unsichtbar, aber durchsuchbar.",
        ))

    if tiny_count > 0:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.LOW,
            category="hidden_text",
            message=f"Miniatur-Text (<1pt) gefunden: {tiny_count} Block(s)",
            detail="Text mit Schriftgröße unter 1 Punkt ist für das menschliche Auge nicht lesbar.",
        ))

    if ocg_layers:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.INFO,
            category="hidden_text",
            message=f"OCG-Ebenen (Optional Content Groups) vorhanden: {len(ocg_layers)}",
            detail=", ".join(l['name'] for l in ocg_layers[:5]),
        ))

    return HiddenTextResult(
        hidden_blocks=all_findings[:200],
        invisible_text_count=invisible_count,
        white_text_count=white_count,
        tiny_text_count=tiny_count,
        ocg_layers=ocg_layers,
        rendering_mode_3_count=invisible_count,
        anomalies=anomalies,
    )
