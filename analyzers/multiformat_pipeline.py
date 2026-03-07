"""
Multi-Format-Pipeline: Orchestriert forensische Analyse für DOCX, XLSX, PPTX, DOC, XLS, PPT.

Für Office-Dokumente werden nur die Format-spezifischen Analyzer ausgeführt
plus die universellen Analyzer (Hashes, Virus-Scan, grundlegende Metadaten via Strings).
"""
from __future__ import annotations
import uuid
from pathlib import Path
from datetime import datetime, timezone
from typing import List

from models.schemas import (
    AnalysisResult, HashResult, Anomaly, AnomalySeverity, RiskLevel,
    MetadataResult, UUIDDecodeResult, SoftwareFingerprint, SignatureInfo,
    PageGeometryResult, PageLabelsResult, JpegExtractorResult, JpegAnalyzerResult,
    QuantFingerprintResult, EncryptionResult, IncrementalUpdatesResult,
    JavaScriptResult, EmbeddedFilesResult, VirusScanResult,
    OOXMLResult, OLEResult,
)
from analyzers.hashing import compute_hashes
from analyzers.virus_scan import analyze_virus_scan
from analyzers.format_detector import detect_format, is_office_format
from analyzers.ooxml_analyzer import analyze_ooxml
from analyzers.ole_analyzer import analyze_ole


def _compute_risk_level(anomalies: List[Anomaly]) -> RiskLevel:
    high   = sum(1 for a in anomalies if a.severity == AnomalySeverity.HIGH)
    medium = sum(1 for a in anomalies if a.severity == AnomalySeverity.MEDIUM)
    if high > 0:   return RiskLevel.HIGH
    if medium > 0: return RiskLevel.MEDIUM
    if anomalies:  return RiskLevel.LOW
    return RiskLevel.CLEAN


def _empty_metadata(filename: str) -> MetadataResult:
    return MetadataResult(page_count=0)


def _empty_uuid()        -> UUIDDecodeResult:        return UUIDDecodeResult()
def _empty_software()    -> SoftwareFingerprint:      return SoftwareFingerprint()
def _empty_signature()   -> SignatureInfo:             return SignatureInfo()
def _empty_geometry()    -> PageGeometryResult:        return PageGeometryResult()
def _empty_labels()      -> PageLabelsResult:          return PageLabelsResult()
def _empty_jpeg_ext()    -> JpegExtractorResult:       return JpegExtractorResult()
def _empty_jpeg_anal()   -> JpegAnalyzerResult:        return JpegAnalyzerResult()
def _empty_quant()       -> QuantFingerprintResult:    return QuantFingerprintResult()
def _empty_encryption()  -> EncryptionResult:          return EncryptionResult()
def _empty_incremental() -> IncrementalUpdatesResult:  return IncrementalUpdatesResult()
def _empty_javascript()  -> JavaScriptResult:          return JavaScriptResult()
def _empty_embedded()    -> EmbeddedFilesResult:       return EmbeddedFilesResult()


def run_office_pipeline(file_path: Path, original_filename: str) -> AnalysisResult:
    """Forensik-Pipeline für Office-Dokumente (DOCX/XLSX/PPTX/DOC/XLS/PPT)."""
    analysis_id  = str(uuid.uuid4())
    analyzed_at  = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    fmt          = detect_format(file_path, original_filename)
    all_anomalies: List[Anomaly] = []

    # 1. Hashes (universell)
    hashes = compute_hashes(file_path)

    # 2. Virus-Scan (universell)
    virus_scan = analyze_virus_scan(file_path, sha256=hashes.sha256)
    all_anomalies.extend(virus_scan.anomalies)

    # 3. Format-spezifische Analyse
    ooxml_result: OOXMLResult | None = None
    ole_result:   OLEResult   | None = None

    if fmt in ('DOCX', 'XLSX', 'PPTX', 'ODT', 'ODS', 'ODP', 'OOXML'):
        raw = analyze_ooxml(file_path, fmt)
        ooxml_result = OOXMLResult(
            format=raw['format'],
            core_props=raw.get('core_props', {}),
            app_props=raw.get('app_props', {}),
            rsids=raw.get('rsids', []),
            rsid_count=raw.get('rsid_count', 0),
            track_changes=raw.get('track_changes', []),
            tc_author_count=raw.get('tc_author_count', 0),
            relationships=raw.get('relationships', []),
            external_links=raw.get('external_links', []),
            media=raw.get('media', []),
            macros=raw.get('macros', {}),
            custom_props=raw.get('custom_props', []),
            anomalies=raw.get('anomalies', []),
        )
        all_anomalies.extend(ooxml_result.anomalies)

        # Metadaten aus OOXML in MetadataResult mappen (für Risk-Banner)
        cp = raw.get('core_props', {})
        ap = raw.get('app_props', {})
        metadata = MetadataResult(
            title=cp.get('title'),
            author=cp.get('creator'),
            subject=cp.get('subject'),
            keywords=cp.get('keywords'),
            creator=ap.get('application'),
            producer=ap.get('appversion'),
            creation_date_parsed=cp.get('created'),
            mod_date_parsed=cp.get('modified'),
            page_count=int(ap.get('pages', 0)) if ap.get('pages', '').isdigit() else 0,
        )
        # Software-Fingerprint aus App Properties
        software_fp = SoftwareFingerprint(
            producer_raw=ap.get('application'),
            creator_raw=ap.get('application'),
            identified_tool=ap.get('application'),
            tool_category='Office',
            version_hint=ap.get('appversion'),
        )

    elif fmt in ('DOC', 'XLS', 'PPT', 'OLE'):
        raw = analyze_ole(file_path, fmt)
        ole_result = OLEResult(
            format=raw['format'],
            summary=raw.get('summary', {}),
            doc_summary=raw.get('doc_summary', {}),
            has_macros=raw.get('has_macros', False),
            strings=raw.get('strings', []),
            anomalies=raw.get('anomalies', []),
        )
        all_anomalies.extend(ole_result.anomalies)

        # Metadaten aus OLE-Summary mappen
        s = raw.get('summary', {})
        metadata = MetadataResult(
            title=s.get('title'),
            author=s.get('author'),
            subject=s.get('subject'),
            keywords=s.get('keywords'),
            creator=s.get('app_name'),
            creation_date_parsed=s.get('created'),
            mod_date_parsed=s.get('last_saved'),
            page_count=int(s.get('page_count', 0)) if isinstance(s.get('page_count'), int) else 0,
        )
        software_fp = SoftwareFingerprint(
            producer_raw=s.get('app_name'),
            identified_tool=s.get('app_name'),
            tool_category='Office (Legacy)',
        )
    else:
        metadata    = _empty_metadata(original_filename)
        software_fp = _empty_software()

    risk_level   = _compute_risk_level(all_anomalies)
    high_count   = sum(1 for a in all_anomalies if a.severity == AnomalySeverity.HIGH)
    medium_count = sum(1 for a in all_anomalies if a.severity == AnomalySeverity.MEDIUM)
    low_count    = sum(1 for a in all_anomalies if a.severity == AnomalySeverity.LOW)

    result = AnalysisResult(
        analysis_id=analysis_id,
        filename=original_filename,
        file_size_bytes=hashes.file_size_bytes,
        analyzed_at=analyzed_at,
        risk_level=risk_level,
        anomaly_count_high=high_count,
        anomaly_count_medium=medium_count,
        anomaly_count_low=low_count,
        all_anomalies=all_anomalies,
        hashes=hashes,
        metadata=metadata,
        uuid_decode=_empty_uuid(),
        software_fingerprint=software_fp,
        signature=_empty_signature(),
        page_geometry=_empty_geometry(),
        page_labels=_empty_labels(),
        jpeg_extractor=_empty_jpeg_ext(),
        jpeg_analyzer=_empty_jpeg_anal(),
        quant_fingerprint=_empty_quant(),
        encryption=_empty_encryption(),
        incremental_updates=_empty_incremental(),
        javascript=_empty_javascript(),
        embedded_files=_empty_embedded(),
        virus_scan=virus_scan,
        ooxml=ooxml_result,
        ole=ole_result,
        original_format=fmt,
    )
    from analyzers.numpy_sanitizer import sanitize_result
    return sanitize_result(result)
