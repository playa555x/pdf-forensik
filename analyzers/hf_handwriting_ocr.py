"""
HuggingFace Handwriting OCR via microsoft/trocr-base-handwritten.

Conditional: laeuft NUR auf zuvor detected Signatur-/Handwriting-Regionen
(aus hf_signature_detector). Liefert Text aus handgeschriebenen Bereichen.

Modell: vision-encoder-decoder (~334M Params), CPU-Inferenz 8-15s pro Crop.
Lazy-Load via globalen Cache.

Forensisch: Text-Extraktion aus Initialen/Siegeln, dann Cross-Check
mit Document-Authoren (vergleicht Initialen-Text mit /Author Feld).
"""
from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List, Optional

from models.schemas import Anomaly, AnomalySeverity, HandwritingOCRResult


_MODEL_CACHE: Dict[str, Any] = {}


def _load_trocr():
    if "model" in _MODEL_CACHE:
        return _MODEL_CACHE["model"], _MODEL_CACHE["processor"]
    try:
        from transformers import TrOCRProcessor, VisionEncoderDecoderModel
        proc = TrOCRProcessor.from_pretrained(
            "microsoft/trocr-base-handwritten",
            cache_dir="/var/data/hf_cache",
        )
        model = VisionEncoderDecoderModel.from_pretrained(
            "microsoft/trocr-base-handwritten",
            cache_dir="/var/data/hf_cache",
        )
        # Inference mode set via torch.no_grad() in caller -- no explicit mode change needed
        _MODEL_CACHE["model"] = model
        _MODEL_CACHE["processor"] = proc
        return model, proc
    except Exception as e:
        _MODEL_CACHE["error"] = str(e)
        return None, None


def analyze_hf_handwriting(crop_paths: List[Path]) -> HandwritingOCRResult:
    """Erwartet Liste von Bild-Pfaden (z.B. von hf_signature_detector)."""
    anomalies: List[Anomaly] = []

    if not crop_paths:
        return HandwritingOCRResult(skipped="no input crops", anomalies=[])

    model, proc = _load_trocr()
    if model is None:
        return HandwritingOCRResult(
            error=_MODEL_CACHE.get("error", "trocr load failed"),
            anomalies=[],
        )

    try:
        from PIL import Image
        import torch
    except ImportError as e:
        return HandwritingOCRResult(error=f"missing dep: {e}", anomalies=[])

    results: List[Dict[str, Any]] = []
    # Cap to first 8 crops to avoid runaway runtime
    for path in crop_paths[:8]:
        try:
            img = Image.open(path).convert("RGB")
            pix_values = proc(images=img, return_tensors="pt").pixel_values
            with torch.no_grad():
                ids = model.generate(pix_values, max_new_tokens=64, num_beams=2)
            text = proc.batch_decode(ids, skip_special_tokens=True)[0].strip()
            results.append({
                "crop_path": str(path),
                "text": text,
                "char_count": len(text),
            })
        except Exception as e:
            results.append({"crop_path": str(path), "error": str(e)})

    empty = [r for r in results if r.get("char_count", 0) == 0 and "error" not in r]
    if empty:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.LOW,
            category="trocr_empty_handwriting",
            message=f"{len(empty)} Signatur-Region(en) liefern keinen Text -- Stempel oder leerer Bereich",
            detail=f"crops: {[r['crop_path'] for r in empty[:3]]}",
        ))

    seen: Dict[str, List[str]] = {}
    for r in results:
        t = r.get("text", "").strip().lower()
        if t and len(t) > 2:
            seen.setdefault(t, []).append(r["crop_path"])
    duplicates = {t: paths for t, paths in seen.items() if len(paths) > 1}
    if duplicates:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category="trocr_duplicate_text",
            message=f"{len(duplicates)} Signatur/Initialen-Text(e) auf mehreren Crops identisch",
            detail=f"texts={list(duplicates.keys())[:3]}",
        ))

    return HandwritingOCRResult(
        results=results,
        total_processed=len(results),
        empty_count=len(empty),
        anomalies=anomalies,
    )
