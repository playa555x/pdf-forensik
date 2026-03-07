"""
Image-Pipeline: Forensische Analyse für direkte JPEG/PNG-Uploads.
"""
from __future__ import annotations
import uuid
from datetime import datetime, timezone
from pathlib import Path

from analyzers.image_forensics import analyze_image_forensics
from analyzers.steg_analyzer import analyze_steganography
from models.schemas import (
    AnalysisResult, HashResult, MetadataResult, UUIDDecodeResult,
    SoftwareFingerprint, SignatureInfo, PageGeometryResult, PageLabelsResult,
    JpegExtractorResult, JpegAnalyzerResult, QuantFingerprintResult,
    EncryptionResult, IncrementalUpdatesResult, JavaScriptResult,
    EmbeddedFilesResult, VirusScanResult, RiskLevel, Anomaly, AnomalySeverity,
    ImageForensicsResult, StegResult,
)
import hashlib


def _compute_hashes(file_path: Path) -> HashResult:
    content = file_path.read_bytes()
    return HashResult(
        md5=hashlib.md5(content).hexdigest(),
        sha1=hashlib.sha1(content).hexdigest(),
        sha256=hashlib.sha256(content).hexdigest(),
        sha512=hashlib.sha512(content).hexdigest(),
        file_size_bytes=len(content),
    )


def _empty_stubs(filename: str) -> dict:
    """Leere Pflicht-Felder für nicht-anwendbare Analyzer."""
    return dict(
        uuid_decode=UUIDDecodeResult(),
        signature=SignatureInfo(),
        page_geometry=PageGeometryResult(),
        page_labels=PageLabelsResult(),
        jpeg_extractor=JpegExtractorResult(),
        jpeg_analyzer=JpegAnalyzerResult(),
        quant_fingerprint=QuantFingerprintResult(),
        encryption=EncryptionResult(),
        incremental_updates=IncrementalUpdatesResult(),
        javascript=JavaScriptResult(),
        embedded_files=EmbeddedFilesResult(),
        virus_scan=VirusScanResult(),
    )


def run_image_pipeline(file_path: Path, original_filename: str) -> AnalysisResult:
    """Vollständige Forensik-Pipeline für JPEG/PNG-Bilddateien."""
    fmt = Path(original_filename).suffix.upper().lstrip('.')  # JPEG | PNG
    analysis_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    # Hashes
    hashes = _compute_hashes(file_path)

    # Image Forensics
    img_data = analyze_image_forensics(file_path)
    img_anomalies = img_data.get('anomalies', [])

    # Steganography
    steg_data = analyze_steganography(file_path)
    steg_anomalies = steg_data.get('anomalies', [])

    # Pydantic-Modelle
    image_forensics = ImageForensicsResult(
        available=img_data.get('available', True),
        format=fmt,
        exif=img_data.get('exif', {}),
        ela=img_data.get('ela', {}),
        copy_move=img_data.get('copy_move', {}),
        prnu=img_data.get('prnu', {}),
        double_compression=img_data.get('double_compression', {}),
        thumbnail_check=img_data.get('thumbnail_check', {}),
        ai_detection=img_data.get('ai_detection', {}),
        anomalies=img_anomalies,
    )

    steganography = StegResult(
        lsb_chi=steg_data.get('lsb_chi', {}),
        rs_analysis=steg_data.get('rs_analysis', {}),
        png_chunks=steg_data.get('png_chunks', {'applicable': False}),
        jpeg_trailing=steg_data.get('jpeg_trailing', {'applicable': False}),
        anomalies=steg_anomalies,
    )

    # Metadaten aus EXIF befüllen
    exif = img_data.get('exif', {})
    software = exif.get('software') or exif.get('Software', '')
    make = exif.get('make') or exif.get('Make', '')
    model_cam = exif.get('model') or exif.get('Model', '')
    dt_orig = exif.get('datetime_original') or exif.get('DateTimeOriginal', '')

    metadata = MetadataResult(
        creator=f"{make} {model_cam}".strip() or None,
        producer=software or None,
        creation_date_raw=dt_orig or None,
        pdf_version=None,
        page_count=1,
    )
    sw_fp = SoftwareFingerprint(
        producer_raw=software or None,
        creator_raw=f"{make} {model_cam}".strip() or None,
        identified_tool=software or (f"{make} {model_cam}".strip() or None),
        tool_category='Camera' if make else ('Software' if software else None),
    )

    # Alle Anomalien aggregieren
    all_anomalies = img_anomalies + steg_anomalies
    high = sum(1 for a in all_anomalies if a.severity == AnomalySeverity.HIGH)
    med  = sum(1 for a in all_anomalies if a.severity == AnomalySeverity.MEDIUM)
    low  = sum(1 for a in all_anomalies if a.severity == AnomalySeverity.LOW)

    risk = RiskLevel.CLEAN
    if high > 0:
        risk = RiskLevel.HIGH
    elif med > 0:
        risk = RiskLevel.MEDIUM
    elif low > 0:
        risk = RiskLevel.LOW

    result = AnalysisResult(
        analysis_id=analysis_id,
        filename=original_filename,
        file_size_bytes=hashes.file_size_bytes,
        analyzed_at=now,
        risk_level=risk,
        anomaly_count_high=high,
        anomaly_count_medium=med,
        anomaly_count_low=low,
        all_anomalies=all_anomalies,
        hashes=hashes,
        metadata=metadata,
        software_fingerprint=sw_fp,
        original_format=fmt,
        image_forensics=image_forensics,
        steganography=steganography,
        **_empty_stubs(original_filename),
    )
    from analyzers.numpy_sanitizer import sanitize_result
    return sanitize_result(result)
