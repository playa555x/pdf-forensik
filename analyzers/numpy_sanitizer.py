"""
numpy_sanitizer.py — Konvertiert numpy-Typen in native Python-Typen.
Wird in allen Pipelines aufgerufen bevor das AnalysisResult zurückgegeben wird.
"""
from __future__ import annotations
import json


def sanitize_result(result):
    """
    Bereinigt alle numpy-Typen im AnalysisResult via JSON round-trip.
    Sicher gegen fehlende numpy-Installation.
    """
    try:
        import numpy as np
    except ImportError:
        return result  # numpy nicht installiert — nichts zu tun

    class _NpEncoder(json.JSONEncoder):
        def default(self, o):
            if isinstance(o, np.bool_):
                return bool(o)
            if isinstance(o, np.integer):
                return int(o)
            if isinstance(o, np.floating):
                return float(o)
            if isinstance(o, np.ndarray):
                return o.tolist()
            return super().default(o)

    try:
        raw = result.model_dump()
        clean = json.loads(json.dumps(raw, cls=_NpEncoder))
        return result.__class__(**clean)
    except Exception:
        return result
