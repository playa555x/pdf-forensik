"""
Pydantic-Modelle für alle Analyse-Ergebnisse.
Diese Modelle sind der Vertrag zwischen Analyzern, Datenbank und API.
"""
from __future__ import annotations
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum


class AnomalySeverity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RiskLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    CLEAN = "CLEAN"
    UNKNOWN = "UNKNOWN"


class Anomaly(BaseModel):
    severity: AnomalySeverity
    category: str
    message: str
    detail: Optional[str] = None


class DocTypeResult(BaseModel):
    """
    Heuristische Dokumenttyp-Klassifikation. Wird frueh in der Pipeline
    bestimmt und an Cross-Analyzer + Risk-Berechnung durchgereicht, damit
    Severity-Profile pro Dokumenttyp angewendet werden koennen.
    """
    doc_type: str = "unknown"
    confidence: float = 0.0
    reasoning: List[str] = Field(default_factory=list)
    inputs: Dict[str, Any] = Field(default_factory=dict)


class SignatureWorkflowResult(BaseModel):
    """
    Klassifiziert das Signatur-Setup (Multi-Sig vs. Shadow-Attack vs. ...).
    Wird wie DocTypeResult an severity_profiles durchgereicht damit
    Shadow-Attack-Findings bei legitimer Multi-Sig nicht falsch HIGH bleiben.
    """
    workflow: str = "unknown"
    reasoning: List[str] = Field(default_factory=list)
    eof_count: int = 0
    byterange_count: int = 0
    byteranges: List[Dict[str, Any]] = Field(default_factory=list)
    signatures: List[Dict[str, Any]] = Field(default_factory=list)
    anomalies: List[Anomaly] = Field(default_factory=list)
    error: Optional[str] = None


# ---- Hashing ----------------------------------------------------------------

class HashResult(BaseModel):
    md5: str
    sha1: str
    sha256: str
    sha512: str
    file_size_bytes: int


# ---- Metadaten --------------------------------------------------------------

class MetadataResult(BaseModel):
    title: Optional[str] = None
    author: Optional[str] = None
    subject: Optional[str] = None
    keywords: Optional[str] = None
    creator: Optional[str] = None       # Anwendung die das Quelldokument erstellt hat
    producer: Optional[str] = None      # PDF-Export-Engine
    creation_date_raw: Optional[str] = None
    mod_date_raw: Optional[str] = None
    creation_date_parsed: Optional[str] = None   # ISO 8601
    mod_date_parsed: Optional[str] = None        # ISO 8601
    pdf_version: Optional[str] = None
    page_count: int = 0
    xmp_data: Optional[Dict[str, Any]] = None    # strukturierte XMP-Felder
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- UUID-Decoder -----------------------------------------------------------

class UUIDDecodeResult(BaseModel):
    found_uuids: List[str] = Field(default_factory=list)
    decoded: List[Dict[str, Any]] = Field(default_factory=list)
    # decoded[i] = {"uuid": str, "version": int, "timestamp_utc": str,
    #               "delta_seconds": float, "creation_date_iso": str}
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- Software-Fingerprint ---------------------------------------------------

class SoftwareFingerprint(BaseModel):
    producer_raw: Optional[str] = None
    creator_raw: Optional[str] = None
    identified_tool: Optional[str] = None
    tool_category: Optional[str] = None   # "Desktop", "Online", "Library", "OCR", ...
    version_hint: Optional[str] = None
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- Signaturen -------------------------------------------------------------

class SignatureInfo(BaseModel):
    has_acroform: bool = False
    has_sig_field: bool = False
    has_doc_mdp: bool = False
    sig_field_names: List[str] = Field(default_factory=list)
    cert_info: Optional[Dict[str, Any]] = None
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- Seitengeometrie --------------------------------------------------------

class PageGeometry(BaseModel):
    width_pt: float
    height_pt: float
    is_a4: bool
    orientation: str   # "portrait" | "landscape" | "square"


class PageGeometryResult(BaseModel):
    pages: List[PageGeometry] = Field(default_factory=list)
    mixed_sizes: bool = False
    unique_sizes: List[str] = Field(default_factory=list)
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- PageLabels -------------------------------------------------------------

class PageLabelsResult(BaseModel):
    has_page_labels: bool = False
    label_ranges: List[Dict[str, Any]] = Field(default_factory=list)
    declared_page_count: Optional[int] = None
    actual_page_count: int = 0
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- JPEG-Extraktion --------------------------------------------------------

class ExtractedImage(BaseModel):
    index: int
    filename: str
    page: Optional[int] = None
    extraction_method: str   # "xobject" | "binary_scan"
    file_size_bytes: int


class JpegExtractorResult(BaseModel):
    total_images: int = 0
    images: List[ExtractedImage] = Field(default_factory=list)
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- JPEG-Analyse -----------------------------------------------------------

class ImageAnalysisDetail(BaseModel):
    index: int
    filename: str
    width: Optional[int] = None
    height: Optional[int] = None
    color_mode: Optional[str] = None        # "RGB", "CMYK", "L", ...
    dpi_x: Optional[float] = None
    dpi_y: Optional[float] = None
    exif: Optional[Dict[str, Any]] = None
    xmp: Optional[str] = None
    has_exif: bool = False
    has_xmp: bool = False
    camera_make: Optional[str] = None
    camera_model: Optional[str] = None
    original_datetime: Optional[str] = None
    gps_coords: Optional[str] = None
    md5: Optional[str] = None
    sha256: Optional[str] = None
    anomalies: List[Anomaly] = Field(default_factory=list)


class JpegAnalyzerResult(BaseModel):
    analyzed: List[ImageAnalysisDetail] = Field(default_factory=list)
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- Quantisierungs-Fingerprint ---------------------------------------------

class QuantFingerprintResult(BaseModel):
    images_checked: int = 0
    ghostscript_detected: bool = False
    matches: List[Dict[str, Any]] = Field(default_factory=list)
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- Encryption -------------------------------------------------------------

class EncryptionResult(BaseModel):
    is_encrypted: bool = False
    requires_password: bool = False
    algorithm: Optional[str] = None
    key_length_bits: Optional[int] = None
    strength: Optional[str] = None        # "SCHWACH" | "MITTEL" | "STARK" | "SEHR STARK"
    v_value: Optional[int] = None
    r_value: Optional[int] = None
    p_value: Optional[int] = None
    permissions: Optional[Dict[str, Any]] = None
    owner_hash: Optional[str] = None
    user_hash: Optional[str] = None
    encrypt_metadata: bool = True
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- Incremental Updates ----------------------------------------------------

class IncrementalUpdatesResult(BaseModel):
    revision_count: int = 1
    revisions: List[Dict[str, Any]] = Field(default_factory=list)
    has_trailing_data: bool = False
    trailing_bytes: int = 0
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- JavaScript / Actions ---------------------------------------------------

class JavaScriptResult(BaseModel):
    has_javascript: bool = False
    has_auto_execute: bool = False
    found_actions: List[Dict[str, Any]] = Field(default_factory=list)
    js_snippets: List[Dict[str, Any]] = Field(default_factory=list)
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- Virus-Scan -------------------------------------------------------------

class VirusScanEngine(BaseModel):
    name: str                           # "ClamAV" | "VirusTotal"
    available: bool = False
    scanned: bool = False
    clean: bool = True
    detections: List[Dict[str, Any]] = Field(default_factory=list)
    error: Optional[str] = None
    scan_duration_ms: Optional[int] = None


class VirusScanResult(BaseModel):
    is_clean: bool = True
    total_detections: int = 0
    engines: List[VirusScanEngine] = Field(default_factory=list)
    sha256: Optional[str] = None        # für VirusTotal-Link
    virustotal_url: Optional[str] = None
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- Embedded Files + Annotations + Object Streams -------------------------

class EmbeddedFilesResult(BaseModel):
    embedded_file_count: int = 0
    embedded_files: List[Dict[str, Any]] = Field(default_factory=list)
    annotation_count: int = 0
    annotations: List[Dict[str, Any]] = Field(default_factory=list)
    hidden_annotation_count: int = 0
    obj_stream_count: int = 0
    obj_streams: List[Dict[str, Any]] = Field(default_factory=list)
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- OOXML (DOCX / XLSX / PPTX) --------------------------------------------

class OOXMLResult(BaseModel):
    format: str = "DOCX"
    core_props: Dict[str, Any] = Field(default_factory=dict)
    app_props: Dict[str, Any] = Field(default_factory=dict)
    rsids: List[str] = Field(default_factory=list)
    rsid_count: int = 0
    track_changes: List[Dict[str, Any]] = Field(default_factory=list)
    tc_author_count: int = 0
    relationships: List[Dict[str, Any]] = Field(default_factory=list)
    external_links: List[Dict[str, Any]] = Field(default_factory=list)
    media: List[Dict[str, Any]] = Field(default_factory=list)
    macros: Dict[str, Any] = Field(default_factory=dict)
    custom_props: List[Dict[str, Any]] = Field(default_factory=list)
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- OLE2 (DOC / XLS / PPT) ------------------------------------------------

class OLEResult(BaseModel):
    format: str = "DOC"
    summary: Dict[str, Any] = Field(default_factory=dict)
    doc_summary: Dict[str, Any] = Field(default_factory=dict)
    has_macros: bool = False
    strings: List[str] = Field(default_factory=list)
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- Timezone-Analyse -------------------------------------------------------

class TimezoneResult(BaseModel):
    dates: List[Dict[str, Any]] = Field(default_factory=list)
    region_hint: Optional[str] = None
    offset_consistent: bool = True
    unique_offsets: List[int] = Field(default_factory=list)
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- Author-Artifacts -------------------------------------------------------

class AuthorArtifactsResult(BaseModel):
    font_prefixes: List[Dict[str, Any]] = Field(default_factory=list)
    xmp_authors: List[Dict[str, Any]] = Field(default_factory=list)
    annotation_authors: List[Dict[str, Any]] = Field(default_factory=list)
    form_field_hints: List[Dict[str, Any]] = Field(default_factory=list)
    printer_name: List[Dict[str, Any]] = Field(default_factory=list)
    all_artifacts: List[Dict[str, Any]] = Field(default_factory=list)
    anomalies: List[Anomaly] = Field(default_factory=list)

    @property
    def local_paths(self) -> List[Dict[str, Any]]:
        """Rückwärtskompatibilität — gibt Pfad-Artefakte aus all_artifacts zurück."""
        return [a for a in self.all_artifacts if "[path]" in a.get("source", "")]


# ---- ELA (Error Level Analysis) --------------------------------------------

class ELAResult(BaseModel):
    available: bool = True
    images_checked: int = 0
    results: List[Dict[str, Any]] = Field(default_factory=list)
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- Object Stream Analysis ------------------------------------------------

class ObjectStreamResult(BaseModel):
    obj_stream_count: int = 0
    obj_streams: List[Dict[str, Any]] = Field(default_factory=list)
    xref_info: Dict[str, Any] = Field(default_factory=dict)
    duplicate_objs: List[Dict[str, Any]] = Field(default_factory=list)
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- Residual Objects -------------------------------------------------------

class ResidualObjectsResult(BaseModel):
    orphaned_count: int = 0
    orphaned_objects: List[Dict[str, Any]] = Field(default_factory=list)
    trailing_data: Dict[str, Any] = Field(default_factory=dict)
    eof_info: Dict[str, Any] = Field(default_factory=dict)
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- Shadow Attack Detection -----------------------------------------------

class ShadowAttackResult(BaseModel):
    has_signature: bool = False
    signature_count: int = 0
    shadow_analysis: List[Dict[str, Any]] = Field(default_factory=list)
    isa_analysis: List[Dict[str, Any]] = Field(default_factory=list)
    wrapping_check: Dict[str, Any] = Field(default_factory=dict)
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- IOC-Extraktion (Phase 4) -----------------------------------------------

class IocResult(BaseModel):
    urls: List[Dict[str, Any]] = Field(default_factory=list)        # {url, source, suspicious}
    ips: List[Dict[str, Any]] = Field(default_factory=list)         # {ip, type: internal|external, source}
    emails: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    suspicious_iocs: List[Dict[str, Any]] = Field(default_factory=list)
    total_count: int = 0
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- Hidden Text Analyzer (Phase 4) -----------------------------------------

class HiddenTextResult(BaseModel):
    hidden_blocks: List[Dict[str, Any]] = Field(default_factory=list)  # {page, text, reason, coords}
    invisible_text_count: int = 0
    white_text_count: int = 0
    tiny_text_count: int = 0
    ocg_layers: List[Dict[str, Any]] = Field(default_factory=list)
    rendering_mode_3_count: int = 0
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- Yellow Dots / MIC Detector (Phase 4) -----------------------------------

class YellowDotsResult(BaseModel):
    available: bool = True
    method_used: str = "none"           # "pixel_scan" | "poppler" | "none"
    dots_found: bool = False
    dot_count: int = 0
    pattern_type: Optional[str] = None  # "xerox_mic" | "generic"
    decoded_info: Dict[str, Any] = Field(default_factory=dict)
    page: Optional[int] = None
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- Image Forensics (Phase 3) ----------------------------------------------

class ImageForensicsResult(BaseModel):
    available: bool = True
    format: str = "JPEG"
    exif: Dict[str, Any] = Field(default_factory=dict)
    ela: Dict[str, Any] = Field(default_factory=dict)
    copy_move: Dict[str, Any] = Field(default_factory=dict)
    prnu: Dict[str, Any] = Field(default_factory=dict)
    double_compression: Dict[str, Any] = Field(default_factory=dict)
    thumbnail_check: Dict[str, Any] = Field(default_factory=dict)
    ai_detection: Dict[str, Any] = Field(default_factory=dict)
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- Steganography (Phase 3) ------------------------------------------------

class StegResult(BaseModel):
    lsb_chi: Dict[str, Any] = Field(default_factory=dict)
    rs_analysis: Dict[str, Any] = Field(default_factory=dict)
    png_chunks: Dict[str, Any] = Field(default_factory=dict)
    jpeg_trailing: Dict[str, Any] = Field(default_factory=dict)
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- Stream Decompression (Phase 5) ----------------------------------------

class StreamDecompResult(BaseModel):
    total_streams: int = 0
    decompressed: int = 0
    failed: int = 0
    filters_found: List[str] = Field(default_factory=list)
    suspicious_content: List[Dict[str, Any]] = Field(default_factory=list)
    exploit_indicators: List[Dict[str, Any]] = Field(default_factory=list)
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- XRef Deep Validation (Phase 5) ----------------------------------------

class XRefValidationResult(BaseModel):
    xref_type: str = "table"  # "table" | "stream" | "hybrid"
    total_entries: int = 0
    subsection_count: int = 0
    free_chain_valid: bool = True
    free_chain_length: int = 0
    consistency_errors: List[Dict[str, Any]] = Field(default_factory=list)
    duplicate_offsets: List[Dict[str, Any]] = Field(default_factory=list)
    orphan_refs: List[Dict[str, Any]] = Field(default_factory=list)
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- Deep JPEG Forensics (Phase 5) -----------------------------------------

class DeepJpegResult(BaseModel):
    images_analyzed: int = 0
    results: List[Dict[str, Any]] = Field(default_factory=list)
    # Per image: dct_analysis, huffman_analysis, thumbnail_check, ghost_map, prnu
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- Redaction Analysis (Phase 5) ------------------------------------------

class RedactionResult(BaseModel):
    redactions_found: int = 0
    secure_redactions: int = 0
    insecure_redactions: int = 0
    redaction_details: List[Dict[str, Any]] = Field(default_factory=list)
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- OCG Layer Extraction (Phase 5) ----------------------------------------

class OCGLayerResult(BaseModel):
    layer_count: int = 0
    layers: List[Dict[str, Any]] = Field(default_factory=list)
    hidden_layers: List[Dict[str, Any]] = Field(default_factory=list)
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- Content Stream Validation (Phase 5) -----------------------------------

class ContentStreamResult(BaseModel):
    pages_checked: int = 0
    invalid_operators: List[Dict[str, Any]] = Field(default_factory=list)
    suspicious_patterns: List[Dict[str, Any]] = Field(default_factory=list)
    operator_stats: Dict[str, int] = Field(default_factory=dict)
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- Incremental Update Diffing (Phase 5) ----------------------------------

class IncrementalDiffResult(BaseModel):
    revision_count: int = 0
    diffs: List[Dict[str, Any]] = Field(default_factory=list)
    # Per diff: {revision, added_objects, modified_objects, deleted_objects, summary}
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- Fuzzy Hashing (Phase 5) -----------------------------------------------

class FuzzyHashResult(BaseModel):
    ssdeep_hash: Optional[str] = None
    tlsh_hash: Optional[str] = None
    available: bool = True
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- Cross-Analyzer Intelligence (Phase 5) ---------------------------------

class CorrelationFinding(BaseModel):
    title: str
    severity: AnomalySeverity
    analyzers_involved: List[str] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)
    conclusion: str = ""


class CrossAnalyzerResult(BaseModel):
    correlations: List[CorrelationFinding] = Field(default_factory=list)
    timeline_reconstruction: List[Dict[str, Any]] = Field(default_factory=list)
    creator_profile: Dict[str, Any] = Field(default_factory=dict)
    manipulation_score: float = 0.0  # 0-100
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- Chain of Custody (Phase 5) --------------------------------------------

class ChainOfCustodyResult(BaseModel):
    examiner_name: Optional[str] = None
    case_number: Optional[str] = None
    examination_start: Optional[str] = None
    examination_end: Optional[str] = None
    report_hash_sha256: Optional[str] = None
    audit_log: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_integrity: Dict[str, Any] = Field(default_factory=dict)


# ---- YARA Scanner (Phase 6) -----------------------------------------------

class YaraResult(BaseModel):
    available: bool = True
    rules_loaded: int = 0
    matches: List[Dict[str, Any]] = Field(default_factory=list)
    total_matches: int = 0
    critical_matches: int = 0
    high_matches: int = 0
    medium_matches: int = 0
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- Font Forensics (Phase 6) ---------------------------------------------

class FontForensicsResult(BaseModel):
    total_fonts: int = 0
    embedded_count: int = 0
    subset_count: int = 0
    system_fonts: int = 0
    type1_count: int = 0
    truetype_count: int = 0
    type3_count: int = 0
    cid_count: int = 0
    fonts: List[Dict[str, Any]] = Field(default_factory=list)
    suspicious_fonts: List[Dict[str, Any]] = Field(default_factory=list)
    encoding_anomalies: List[Dict[str, Any]] = Field(default_factory=list)
    font_creators: List[str] = Field(default_factory=list)
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- PDF/A & PDF/X Compliance (Phase 6) -----------------------------------

class PdfaComplianceResult(BaseModel):
    pdfa_claimed: bool = False
    pdfa_version: Optional[str] = None
    pdfa_conformance: Optional[str] = None
    pdfx_claimed: bool = False
    pdfx_version: Optional[str] = None
    compliance_issues: List[Any] = Field(default_factory=list)
    passes: List[Any] = Field(default_factory=list)
    output_intent: Optional[Any] = None
    total_issues: int = 0
    critical_issues: int = 0
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- Linearization Analysis (Phase 6) -------------------------------------

class LinearizationResult(BaseModel):
    is_linearized: bool = False
    linearization_version: Optional[str] = None
    file_length_declared: Optional[int] = None
    file_length_actual: Optional[int] = None
    length_mismatch: bool = False
    hint_table_present: bool = False
    first_page_obj: Optional[int] = None
    first_page_end_offset: Optional[int] = None
    page_count_declared: Optional[int] = None
    primary_hint_offset: Optional[int] = None
    primary_hint_length: Optional[int] = None
    overflow_hint_offset: Optional[int] = None
    xref_offset: Optional[int] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- ICC Color Profile Analysis (Phase 6) ---------------------------------

class IccProfileResult(BaseModel):
    profiles_found: int = 0
    profiles: List[Dict[str, Any]] = Field(default_factory=list)
    color_spaces_used: List[str] = Field(default_factory=list)
    output_intent: Optional[Dict[str, Any]] = None
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- Visual Render Comparison (Phase 6) ------------------------------------

class VisualRenderResult(BaseModel):
    available: bool = True
    pages_rendered: int = 0
    page_hashes: List[Dict[str, Any]] = Field(default_factory=list)
    blank_pages: List[int] = Field(default_factory=list)
    duplicate_pages: List[Dict[str, Any]] = Field(default_factory=list)
    renderer: Optional[str] = None
    resolution_dpi: Optional[int] = None
    total_pixels: Optional[int] = None
    visual_anomalies: List[Dict[str, Any]] = Field(default_factory=list)
    comparison: Optional[Dict[str, Any]] = None
    reference_comparison: Optional[Dict[str, Any]] = None
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- Object Graph Visualizer (Phase 6) ------------------------------------

class ObjectGraphResult(BaseModel):
    total_objects: int = 0
    nodes: List[Dict[str, Any]] = Field(default_factory=list)
    edges: List[Dict[str, Any]] = Field(default_factory=list)
    object_types: Dict[str, int] = Field(default_factory=dict)
    max_depth: int = 0
    root_obj: Optional[str] = None
    catalog_info: Dict[str, Any] = Field(default_factory=dict)
    page_tree: List[Dict[str, Any]] = Field(default_factory=list)
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- Cross-Document Fingerprinting (Phase 6) ------------------------------

class CrossDocFingerprintResult(BaseModel):
    fingerprint_version: str = "1.0"
    structural_hash: Optional[str] = None
    font_hash: Optional[str] = None
    metadata_hash: Optional[str] = None
    style_hash: Optional[str] = None
    content_hash: Optional[str] = None
    fingerprint_vector: List[str] = Field(default_factory=list)
    similarity_features: Dict[str, Any] = Field(default_factory=dict)
    anomalies: List[Anomaly] = Field(default_factory=list)


# ---- Printer Forensics (Phase 6) ------------------------------------------

class PrinterForensicsResult(BaseModel):
    is_scanned_document: bool = False
    scan_confidence: float = 0.0
    scan_indicators: List[str] = Field(default_factory=list)
    printer_type: Optional[str] = None
    dpi_detected: Optional[int] = None
    rotation_detected: bool = False
    rotation_angle: Optional[float] = None
    moire_detected: bool = False
    halftone_detected: bool = False
    banding_detected: bool = False
    images_analyzed: int = 0
    image_results: List[Dict[str, Any]] = Field(default_factory=list)
    anomalies: List[Anomaly] = Field(default_factory=list)




# ---- Open-Source Forensics (peepdf/pdfid/pdf-parser/qpdf/binwalk/PyMuPDF) ---

class OpenSourceForensicsResult(BaseModel):
    pdfid: Dict[str, Any] = Field(default_factory=dict)
    pdf_parser_stats: Dict[str, Any] = Field(default_factory=dict)
    pdf_parser_orphans: Dict[str, Any] = Field(default_factory=dict)
    qpdf_qdf: Dict[str, Any] = Field(default_factory=dict)
    binwalk: Dict[str, Any] = Field(default_factory=dict)
    pymupdf_lowlevel: Dict[str, Any] = Field(default_factory=dict)
    anomalies: List[Anomaly] = Field(default_factory=list)



# ---- Tier 1 Erweiterung (ExifTool, OCR, mpeepdf, Copy-Move, Annotation) ----

class ExifToolResult(BaseModel):
    raw_tags: Dict[str, Any] = Field(default_factory=dict)
    xmp_history: List[Any] = Field(default_factory=list)
    producer: Optional[str] = None
    creator_tool: Optional[str] = None
    document_id: Optional[str] = None
    instance_id: Optional[str] = None
    original_document_id: Optional[str] = None
    derived_from: Optional[Any] = None
    tag_count: int = 0
    error: Optional[str] = None
    anomalies: List[Anomaly] = Field(default_factory=list)


class OCRTextDiffResult(BaseModel):
    pages: List[Dict[str, Any]] = Field(default_factory=list)
    total_embedded_tokens: int = 0
    total_ocr_tokens: int = 0
    avg_similarity: float = 1.0
    error: Optional[str] = None
    anomalies: List[Anomaly] = Field(default_factory=list)


class MpeepdfResult(BaseModel):
    raw: Dict[str, Any] = Field(default_factory=dict)
    vulnerabilities: List[str] = Field(default_factory=list)
    suspicious_elements: List[str] = Field(default_factory=list)
    cve_references: List[str] = Field(default_factory=list)
    encryption_info: List[str] = Field(default_factory=list)
    error: Optional[str] = None
    anomalies: List[Anomaly] = Field(default_factory=list)


class CopyMoveResult(BaseModel):
    pages: List[Dict[str, Any]] = Field(default_factory=list)
    total_match_clusters: int = 0
    error: Optional[str] = None
    anomalies: List[Anomaly] = Field(default_factory=list)


class AnnotationForensicsResult(BaseModel):
    annotation_count: int = 0
    annotations: List[Dict[str, Any]] = Field(default_factory=list)
    orphan_count: int = 0
    unique_authors: List[str] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    error: Optional[str] = None
    anomalies: List[Anomaly] = Field(default_factory=list)



# ---- Tier 2 HF Erweiterung (YOLO Signature, TrOCR Handwriting) -----------

class SignatureDetectorResult(BaseModel):
    detections: List[Dict[str, Any]] = Field(default_factory=list)
    duplicates: List[Dict[str, Any]] = Field(default_factory=list)
    total_signatures: int = 0
    error: Optional[str] = None
    anomalies: List[Anomaly] = Field(default_factory=list)


class HandwritingOCRResult(BaseModel):
    results: List[Dict[str, Any]] = Field(default_factory=list)
    total_processed: int = 0
    empty_count: int = 0
    skipped: Optional[str] = None
    error: Optional[str] = None
    anomalies: List[Anomaly] = Field(default_factory=list)



# ---- Tier 3 + 4 (LayoutLMv3, Splicing, MLLM) -----------------------------

class LayoutConsistencyResult(BaseModel):
    pages: List[Dict[str, Any]] = Field(default_factory=list)
    page_count: int = 0
    error: Optional[str] = None
    anomalies: List[Anomaly] = Field(default_factory=list)


class SplicingDetectorResult(BaseModel):
    images_analyzed: List[Dict[str, Any]] = Field(default_factory=list)
    total_images: int = 0
    error: Optional[str] = None
    anomalies: List[Anomaly] = Field(default_factory=list)


class MLLMReasonerResult(BaseModel):
    manipulation_score: int = 0
    verdict: Optional[str] = None
    key_correlations: List[str] = Field(default_factory=list)
    critical_findings: List[str] = Field(default_factory=list)
    recommended_next_steps: List[str] = Field(default_factory=list)
    raw_response: Optional[str] = None
    error: Optional[str] = None
    anomalies: List[Anomaly] = Field(default_factory=list)

# ---- Gesamt-Ergebnis --------------------------------------------------------

class AnalysisResult(BaseModel):
    analysis_id: str
    filename: str
    file_size_bytes: int
    analyzed_at: str
    risk_level: RiskLevel
    anomaly_count_high: int = 0
    anomaly_count_medium: int = 0
    anomaly_count_low: int = 0
    all_anomalies: List[Anomaly] = Field(default_factory=list)

    hashes: HashResult
    metadata: MetadataResult
    uuid_decode: UUIDDecodeResult
    software_fingerprint: SoftwareFingerprint
    signature: SignatureInfo
    page_geometry: PageGeometryResult
    page_labels: PageLabelsResult
    jpeg_extractor: JpegExtractorResult
    jpeg_analyzer: JpegAnalyzerResult
    quant_fingerprint: QuantFingerprintResult
    encryption: EncryptionResult
    incremental_updates: IncrementalUpdatesResult
    javascript: JavaScriptResult
    embedded_files: EmbeddedFilesResult
    virus_scan: VirusScanResult
    # Phase 1 — neue Analyzer
    timezone: Optional[TimezoneResult] = None
    author_artifacts: Optional[AuthorArtifactsResult] = None
    ela: Optional[ELAResult] = None
    object_streams: Optional[ObjectStreamResult] = None
    residual_objects: Optional[ResidualObjectsResult] = None
    shadow_attack: Optional[ShadowAttackResult] = None
    # Phase 2 — Multi-Format
    ooxml: Optional[OOXMLResult] = None
    ole: Optional[OLEResult] = None
    original_format: str = "PDF"
    # Phase 3 — Image Forensics
    image_forensics: Optional[ImageForensicsResult] = None
    steganography: Optional[StegResult] = None
    # Phase 4 — Intelligence Features
    ioc: Optional[IocResult] = None
    hidden_text: Optional[HiddenTextResult] = None
    yellow_dots: Optional[YellowDotsResult] = None
    # Phase 5 — Advanced Forensics
    stream_decomp: Optional[StreamDecompResult] = None
    xref_validation: Optional[XRefValidationResult] = None
    deep_jpeg: Optional[DeepJpegResult] = None
    redaction: Optional[RedactionResult] = None
    ocg_layers: Optional[OCGLayerResult] = None
    content_stream: Optional[ContentStreamResult] = None
    incremental_diff: Optional[IncrementalDiffResult] = None
    fuzzy_hash: Optional[FuzzyHashResult] = None
    cross_analyzer: Optional[CrossAnalyzerResult] = None
    chain_of_custody: Optional[ChainOfCustodyResult] = None
    # Phase 6 — Extended Forensics
    yara: Optional[YaraResult] = None
    font_forensics: Optional[FontForensicsResult] = None
    pdfa_compliance: Optional[PdfaComplianceResult] = None
    linearization: Optional[LinearizationResult] = None
    icc_profiles: Optional[IccProfileResult] = None
    visual_render: Optional[VisualRenderResult] = None
    object_graph: Optional[ObjectGraphResult] = None
    cross_doc_fingerprint: Optional[CrossDocFingerprintResult] = None
    printer_forensics: Optional[PrinterForensicsResult] = None
    opensource_forensics: Optional[OpenSourceForensicsResult] = None
    exiftool: Optional[ExifToolResult] = None
    ocr_text_diff: Optional[OCRTextDiffResult] = None
    mpeepdf: Optional[MpeepdfResult] = None
    copy_move: Optional[CopyMoveResult] = None
    annotation_forensics: Optional[AnnotationForensicsResult] = None
    hf_signatures: Optional[SignatureDetectorResult] = None
    hf_handwriting: Optional[HandwritingOCRResult] = None
    hf_layout: Optional[LayoutConsistencyResult] = None
    splicing: Optional[SplicingDetectorResult] = None
    mllm_reasoning: Optional[MLLMReasonerResult] = None
    profile: Optional[str] = None
    # Phase 7 — Doc-Type-Klassifikation fuer kalibriertes Scoring
    doc_type: Optional[DocTypeResult] = None
    # Phase 7b — Signatur-Workflow-Klassifikation (Multi-Sig vs. Shadow-Attack)
    signature_workflow: Optional[SignatureWorkflowResult] = None


# ---- Verlauf ----------------------------------------------------------------

class AnalysisSummary(BaseModel):
    id: str
    filename: str
    file_size_bytes: int
    analyzed_at: str
    md5: str
    sha256: str
    risk_level: RiskLevel
    anomaly_count_high: int
    anomaly_count_medium: int
    anomaly_count_low: int
    has_report: bool


# ---- Vergleich --------------------------------------------------------------

class CompareDocumentInfo(BaseModel):
    analysis_id: str
    filename: str
    analyzed_at: str
    sha256: str
    risk_level: RiskLevel
    producer: Optional[str] = None
    creator: Optional[str] = None
    creation_date: Optional[str] = None
    mod_date: Optional[str] = None
    page_count: int = 0
    image_count: int = 0
    anomaly_count_high: int = 0
    anomaly_count_medium: int = 0
    has_javascript: bool = False
    is_encrypted: bool = False
    revision_count: int = 1
    uuids: List[str] = Field(default_factory=list)


class CompareResult(BaseModel):
    comparison_id: str
    compared_at: str
    documents: List[CompareDocumentInfo]
    identical_hashes: List[tuple] = Field(default_factory=list)
    time_proximity_flags: List[Dict[str, Any]] = Field(default_factory=list)
    common_anomalies: List[str] = Field(default_factory=list)
    same_software: List[Dict[str, Any]] = Field(default_factory=list)
    same_uuid_cluster: List[Dict[str, Any]] = Field(default_factory=list)
    metadata_diffs: List[Dict[str, Any]] = Field(default_factory=list)
    anomalies: List[Anomaly] = Field(default_factory=list)
