"""
HuggingFace Signature Detector via Mels22/Signature-Detection-Verification (YOLO11n).

Pipeline:
1. Render jede PDF-Seite via PyMuPDF zu PNG (200 DPI).
2. YOLO11n-Inferenz auf jeder Seite -> Bounding Boxes + Confidence.
3. Sammle alle Signatur-Regionen, exportiere als Bilder ins out_dir.
4. Cross-Page-Vergleich: Hash + perceptual-Hash der Signatur-Crops.
   Identische Signaturen auf verschiedenen Seiten == Wiederverwendung.

Modell: Ultralytics YOLO11 (HF: Mels22/Signature-Detection-Verification).
Lazy-Load via globalen Cache, ~6MB, CPU-Inferenz <2s pro Seite.
"""
from __future__ import annotations
import hashlib
import io
from pathlib import Path
from typing import Any, Dict, List, Optional

from models.schemas import Anomaly, AnomalySeverity, SignatureDetectorResult


_MODEL_CACHE: Dict[str, Any] = {}


def _load_model():
    """Lazy-load YOLO11n signature model (cached)."""
    if "model" in _MODEL_CACHE:
        return _MODEL_CACHE["model"]
    try:
        from ultralytics import YOLO
        from huggingface_hub import hf_hub_download
        # Mels22 hostet das Model als best.pt im Repo
        model_path = hf_hub_download(
            repo_id="Mels22/Signature-Detection-Verification",
            filename="detector_yolo_1cls.pt",
            cache_dir="/var/data/hf_cache",
        )
        m = YOLO(model_path)
        _MODEL_CACHE["model"] = m
        return m
    except Exception as e:
        _MODEL_CACHE["error"] = str(e)
        return None


def _phash(image_bytes: bytes) -> str:
    """Simple average-hash for crop similarity (no extra deps)."""
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(image_bytes)).convert("L").resize((16, 16))
        pixels = list(img.getdata())
        avg = sum(pixels) / len(pixels)
        bits = "".join("1" if p > avg else "0" for p in pixels)
        return f"{int(bits, 2):064x}"
    except Exception:
        return ""


def analyze_hf_signatures(pdf_path: Path, out_dir: Optional[Path] = None) -> SignatureDetectorResult:
    out_dir = out_dir or pdf_path.parent / "signatures"
    out_dir.mkdir(parents=True, exist_ok=True)
    anomalies: List[Anomaly] = []

    try:
        import fitz
    except ImportError:
        return SignatureDetectorResult(error="PyMuPDF missing", anomalies=[])

    model = _load_model()
    if model is None:
        return SignatureDetectorResult(
            error=_MODEL_CACHE.get("error", "model load failed"),
            anomalies=[],
        )

    detections: List[Dict[str, Any]] = []
    crop_hashes: Dict[str, List[Dict[str, Any]]] = {}

    try:
        doc = fitz.open(str(pdf_path))
        for i, page in enumerate(doc):
            try:
                pix = page.get_pixmap(dpi=200)
                png_bytes = pix.tobytes("png")
                from PIL import Image as _Img
                page_img = _Img.open(io.BytesIO(png_bytes)).convert("RGB")
                # YOLO inference (PIL.Image is supported, raw bytes are not)
                results = model.predict(
                    source=page_img,
                    imgsz=640,
                    conf=0.35,
                    verbose=False,
                    device="cpu",
                )
                if not results:
                    continue
                r = results[0]
                if r.boxes is None or len(r.boxes) == 0:
                    continue

                from PIL import Image
                img_full = Image.open(io.BytesIO(png_bytes))

                for j, box in enumerate(r.boxes):
                    xyxy = box.xyxy.cpu().numpy().tolist()[0]
                    conf = float(box.conf.cpu().numpy()[0])
                    cls = int(box.cls.cpu().numpy()[0])
                    label = r.names.get(cls, str(cls))

                    crop = img_full.crop(xyxy)
                    crop_buf = io.BytesIO()
                    crop.save(crop_buf, format="PNG")
                    crop_bytes = crop_buf.getvalue()
                    crop_path = out_dir / f"page{i+1}_sig{j+1}.png"
                    crop_path.write_bytes(crop_bytes)

                    sha = hashlib.sha256(crop_bytes).hexdigest()[:16]
                    ph = _phash(crop_bytes)

                    det = {
                        "page": i + 1,
                        "label": label,
                        "confidence": round(conf, 3),
                        "bbox": [round(x, 1) for x in xyxy],
                        "crop_path": str(crop_path),
                        "sha256_short": sha,
                        "phash": ph,
                    }
                    detections.append(det)
                    crop_hashes.setdefault(ph, []).append(det)
            except Exception as e:
                detections.append({"page": i + 1, "error": str(e)})

        doc.close()
    except Exception as e:
        return SignatureDetectorResult(error=str(e), anomalies=[])

    # Anomaly: same signature on multiple pages
    duplicates = []
    for ph, group in crop_hashes.items():
        if len(group) > 1 and ph:
            pages = sorted({g["page"] for g in group})
            duplicates.append({"phash": ph, "pages": pages, "count": len(group)})

    if duplicates:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.HIGH,
            category="signature_reuse",
            message=f"{len(duplicates)} Signatur(en) auf mehreren Seiten verwendet -- Hinweis auf Copy/Paste",
            detail=f"duplicates={duplicates[:3]}",
        ))

    if detections and not any("error" in d for d in detections):
        sig_pages = sorted({d["page"] for d in detections if "page" in d and "error" not in d})
        anomalies.append(Anomaly(
            severity=AnomalySeverity.LOW,
            category="signature_detected",
            message=f"{len(detections)} Signatur-Region(en) auf Seite(n) {sig_pages} detektiert",
            detail=f"min_conf={min(d['confidence'] for d in detections if 'confidence' in d):.2f}",
        ))

    return SignatureDetectorResult(
        detections=detections,
        duplicates=duplicates,
        total_signatures=sum(1 for d in detections if "error" not in d),
        anomalies=anomalies,
    )
