"""
Analyse-Pipeline: Orchestriert alle 34+ Analyzer.
"""
from __future__ import annotations
import uuid
from pathlib import Path
from config import IMAGES_DIR
from datetime import datetime, timezone
from typing import List, Optional

from models.schemas import (
    AnalysisResult, Anomaly, AnomalySeverity, RiskLevel,
    TimezoneResult, AuthorArtifactsResult, ELAResult,
    ObjectStreamResult, ResidualObjectsResult, ShadowAttackResult,
    IocResult, HiddenTextResult, YellowDotsResult,
    StreamDecompResult, XRefValidationResult, DeepJpegResult,
    RedactionResult, OCGLayerResult, ContentStreamResult,
    IncrementalDiffResult, FuzzyHashResult, CrossAnalyzerResult,
    ChainOfCustodyResult,
    YaraResult, FontForensicsResult, PdfaComplianceResult,
    LinearizationResult, IccProfileResult, VisualRenderResult,
    ObjectGraphResult, CrossDocFingerprintResult, PrinterForensicsResult,
)
from analyzers.hashing import compute_hashes
from analyzers.metadata import analyze_metadata
from analyzers.uuid_decoder import analyze_uuids
from analyzers.software_fingerprint import analyze_software_fingerprint
from analyzers.signature_detector import analyze_signatures
from analyzers.page_geometry import analyze_page_geometry
from analyzers.page_labels import analyze_page_labels
from analyzers.jpeg_extractor import extract_jpegs
from analyzers.jpeg_analyzer import analyze_jpegs
from analyzers.quant_fingerprint import analyze_quant_fingerprint
from analyzers.encryption import analyze_encryption
from analyzers.incremental_updates import analyze_incremental_updates
from analyzers.javascript_analyzer import analyze_javascript
from analyzers.embedded_files import analyze_embedded_files
from analyzers.virus_scan import analyze_virus_scan
from analyzers.timezone_analyzer import analyze_timezones
from analyzers.author_artifacts import analyze_author_artifacts
from analyzers.ela_analyzer import analyze_ela
from analyzers.object_stream_analyzer import analyze_object_streams
from analyzers.residual_objects import analyze_residual_objects
from analyzers.shadow_attack_detector import analyze_shadow_attacks

# Phase 5 — Advanced Forensics
from analyzers.stream_decomp import analyze_stream_decompression
from analyzers.xref_validator import analyze_xref_deep
from analyzers.deep_jpeg import analyze_deep_jpeg
from analyzers.redaction_analyzer import analyze_redactions
from analyzers.ocg_layer_analyzer import analyze_ocg_layers
from analyzers.content_stream_validator import analyze_content_streams
from analyzers.incremental_differ import analyze_incremental_diff
from analyzers.fuzzy_hasher import compute_fuzzy_hashes
from analyzers.cross_analyzer import analyze_cross_correlations
from analyzers.chain_of_custody import create_chain_of_custody
from analyzers.doc_type_classifier import classify_doc_type
from analyzers.multi_signature_workflow import analyze_multi_signature_workflow
from analyzers.severity_profiles import apply_doc_type_profile, count_by_class
from config import (
    RISK_HARD_HIGH_THRESHOLD, RISK_SOFT_HIGH_THRESHOLD,
    RISK_MEDIUM_CLUSTER_THRESHOLD,
)

# Phase 6 — Extended Forensics
from analyzers.yara_scanner import analyze_yara
from analyzers.font_forensics import analyze_fonts
from analyzers.pdfa_validator import analyze_pdfa_pdfx
from analyzers.linearization_analyzer import analyze_linearization
from analyzers.icc_analyzer import analyze_icc_profiles
from analyzers.visual_comparator import analyze_visual_render
from analyzers.object_graph import analyze_object_graph
from analyzers.cross_doc_fingerprint import create_document_fingerprint
from analyzers.printer_forensics import analyze_printer_forensics
from analyzers.opensource_forensics import analyze_opensource_forensics
from analyzers.exiftool_wrapper import analyze_exiftool
from analyzers.ocr_text_diff import analyze_ocr_text_diff
from analyzers.mpeepdf_wrapper import analyze_mpeepdf
from analyzers.copy_move_detector import analyze_copy_move
from analyzers.annotation_forensics import analyze_annotation_forensics
from analyzers.hf_signature_detector import analyze_hf_signatures
from analyzers.hf_handwriting_ocr import analyze_hf_handwriting
from analyzers.hf_layout_consistency import analyze_hf_layout_consistency
from analyzers.splicing_detector import analyze_splicing
from analyzers.mllm_forgery_reasoner import analyze_mllm_reasoning


# Vollständige Liste aller Analyzer-Namen (für Chain of Custody)
ANALYZER_NAMES = [
    "hashing", "metadata", "uuid_decoder", "software_fingerprint",
    "signature_detector", "page_geometry", "page_labels",
    "jpeg_extractor", "jpeg_analyzer", "quant_fingerprint",
    "encryption", "incremental_updates", "javascript_analyzer",
    "embedded_files", "virus_scan", "timezone_analyzer",
    "author_artifacts", "ela_analyzer", "object_stream_analyzer",
    "residual_objects", "shadow_attack_detector",
    "ioc_extractor", "hidden_text_analyzer", "yellow_dots_detector",
    # Phase 5
    "stream_decomp", "xref_validator", "deep_jpeg",
    "redaction_analyzer", "ocg_layer_analyzer", "content_stream_validator",
    "incremental_differ", "fuzzy_hasher", "cross_analyzer",
    "steg_analyzer",
    # Phase 6
    "yara_scanner", "font_forensics", "pdfa_validator",
    "linearization_analyzer", "icc_analyzer", "visual_comparator",
    "object_graph", "cross_doc_fingerprint", "printer_forensics",
    "opensource_forensics",
    "exiftool", "ocr_text_diff", "mpeepdf", "copy_move", "annotation_forensics",
    "hf_signatures", "hf_handwriting", "hf_layout", "splicing", "mllm_reasoning",
]


def _compute_risk_level(
    anomalies: List[Anomaly],
    doc_type: Optional[str] = None,
    signature_workflow: Optional[str] = None,
) -> RiskLevel:
    """
    Doc-Typ-bewusste Risk-Level-Berechnung.

    Vorher: 1 HIGH-Finding -> sofort RISK_HIGH, egal wie heuristisch.
    Ergebnis: Marketingbroschueren landeten auf HIGH wegen OCR-Mismatch.

    Jetzt:
    1. Doc-Typ-Profil anwenden (Downgrades fuer typische Befunde)
    2. Hard-HIGH (echte Security: JS-Exec, Malware, Shadow Attack, ...) -> HIGH
    3. Soft-HIGH-Cluster (>= RISK_SOFT_HIGH_THRESHOLD) -> HIGH
    4. Sonst MEDIUM/LOW/CLEAN nach Anzahl
    """
    effective = apply_doc_type_profile(anomalies, doc_type, signature_workflow=signature_workflow)
    c = count_by_class(effective)

    if c["hard_high"] >= RISK_HARD_HIGH_THRESHOLD:
        return RiskLevel.HIGH
    if c["soft_high"] >= RISK_SOFT_HIGH_THRESHOLD:
        return RiskLevel.HIGH
    if c["soft_high"] >= 1:
        return RiskLevel.MEDIUM
    if c["medium"] >= RISK_MEDIUM_CLUSTER_THRESHOLD:
        return RiskLevel.MEDIUM
    if c["medium"] >= 1:
        return RiskLevel.MEDIUM
    if c["low"] >= 1:
        return RiskLevel.LOW
    return RiskLevel.CLEAN


def run_pipeline(pdf_path: Path, original_filename: str, profile: str = "standard") -> AnalysisResult:
    # === Profile-Gating ===
    _PROFILE_LITE_SKIP = profile == "lite"
    _PROFILE_FULL = profile in ("standard", "deep")
    analysis_id = str(uuid.uuid4())
    analyzed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # ================================================================
    # Phase 1-4: Bestehende Analyzer
    # ================================================================

    # 1. Hashing
    hashes = compute_hashes(pdf_path)

    # 2. Metadaten
    metadata = analyze_metadata(pdf_path)

    # 3. UUID-Decoder
    uuid_decode = analyze_uuids(pdf_path, metadata.creation_date_parsed)

    # 4. Software-Fingerprint
    software_fp = analyze_software_fingerprint(metadata.producer, metadata.creator)

    # 5. Signaturen
    signature = analyze_signatures(pdf_path)

    # 6. Seitengeometrie
    page_geometry = analyze_page_geometry(pdf_path)

    # 7. PageLabels
    page_labels = analyze_page_labels(pdf_path)

    # 8. JPEG-Extraktion
    jpeg_extractor = extract_jpegs(pdf_path, analysis_id)

    # 9. JPEG-Analyse
    jpeg_analyzer = analyze_jpegs(jpeg_extractor.images, analysis_id)

    # 10. Quantisierungs-Fingerprint
    quant_fp = analyze_quant_fingerprint(jpeg_extractor.images, analysis_id)

    # 11. Encryption
    encryption = analyze_encryption(pdf_path)

    # 12. Incremental Updates
    incremental = analyze_incremental_updates(pdf_path)

    # 13. JavaScript / Actions
    javascript = analyze_javascript(pdf_path)

    # 14. Embedded Files + Annotations + Object Streams
    embedded = analyze_embedded_files(pdf_path)

    # 15. Virus-Scan (ClamAV + VirusTotal)
    virus_scan = analyze_virus_scan(pdf_path, sha256=hashes.sha256)

    # 16. Timezone-Analyse
    _tz_raw = analyze_timezones(pdf_path)
    timezone_result = TimezoneResult(
        dates=_tz_raw["dates"],
        region_hint=_tz_raw.get("region_hint"),
        offset_consistent=_tz_raw.get("offset_consistent", True),
        unique_offsets=_tz_raw.get("unique_offsets", []),
        anomalies=_tz_raw.get("anomalies", []),
    )

    # 17. Author-Artifacts
    _aa_raw = analyze_author_artifacts(pdf_path)
    author_artifacts_result = AuthorArtifactsResult(
        font_prefixes=_aa_raw.get("font_prefixes", []),
        xmp_authors=_aa_raw.get("xmp_authors", []),
        annotation_authors=_aa_raw.get("annotation_authors", []),
        form_field_hints=_aa_raw.get("form_field_hints", []),
        printer_name=_aa_raw.get("printer_name", []),
        all_artifacts=_aa_raw.get("all_artifacts", []),
        anomalies=_aa_raw.get("anomalies", []),
    )

    # 18. ELA (Error Level Analysis)
    _ela_raw = analyze_ela(pdf_path)
    ela_result = ELAResult(
        available=_ela_raw.get("available", True),
        images_checked=_ela_raw.get("images_checked", 0),
        results=_ela_raw.get("results", []),
        anomalies=_ela_raw.get("anomalies", []),
    )

    # 19. Object Stream Analysis
    _os_raw = analyze_object_streams(pdf_path)
    object_stream_result = ObjectStreamResult(
        obj_stream_count=_os_raw.get("obj_stream_count", 0),
        obj_streams=_os_raw.get("obj_streams", []),
        xref_info=_os_raw.get("xref_info", {}),
        duplicate_objs=_os_raw.get("duplicate_objs", []),
        anomalies=_os_raw.get("anomalies", []),
    )

    # 20. Residual Objects
    _ro_raw = analyze_residual_objects(pdf_path)
    residual_result = ResidualObjectsResult(
        orphaned_count=_ro_raw.get("orphaned_count", 0),
        orphaned_objects=_ro_raw.get("orphaned_objects", []),
        trailing_data=_ro_raw.get("trailing_data", {}),
        eof_info=_ro_raw.get("eof_info", {}),
        anomalies=_ro_raw.get("anomalies", []),
    )

    # 21. Shadow Attack Detection
    _sa_raw = analyze_shadow_attacks(pdf_path)
    shadow_result = ShadowAttackResult(
        has_signature=_sa_raw.get("has_signature", False),
        signature_count=_sa_raw.get("signature_count", 0),
        shadow_analysis=_sa_raw.get("shadow_analysis", []),
        isa_analysis=_sa_raw.get("isa_analysis", []),
        wrapping_check=_sa_raw.get("wrapping_check", {}),
        anomalies=_sa_raw.get("anomalies", []),
    )

    # 22. IOC Extraction
    from analyzers.ioc_extractor import extract_iocs
    ioc_result = extract_iocs(pdf_path)

    # 23. Hidden Text Analysis
    from analyzers.hidden_text_analyzer import analyze_hidden_text
    hidden_text_result = analyze_hidden_text(pdf_path)

    # 24. Yellow Dots / MIC Detection
    from analyzers.yellow_dots_detector import detect_yellow_dots
    yellow_dots_result = detect_yellow_dots(pdf_path)

    # ================================================================
    # Phase 5: Advanced Forensics
    # ================================================================

    # 25. Stream Decompression & Content Analysis
    stream_decomp_result = analyze_stream_decompression(pdf_path)

    # 26. XRef Deep Validation
    xref_result = analyze_xref_deep(pdf_path)

    # 27. Deep JPEG Forensics
    # Sammle alle extrahierten Bild-Pfade
    image_dir = Path("extracted_images") / analysis_id
    image_paths = []
    if image_dir.exists():
        image_paths = sorted(image_dir.glob("*.jpg")) + sorted(image_dir.glob("*.jpeg"))
    deep_jpeg_result = analyze_deep_jpeg(image_paths)

    # 28. Redaction Analysis
    redaction_result = analyze_redactions(pdf_path)

    # 29. OCG Layer Extraction
    ocg_result = analyze_ocg_layers(pdf_path)

    # 30. Content Stream Operator Validation
    content_stream_result = analyze_content_streams(pdf_path)

    # 31. Incremental Update Diffing
    inc_diff_result = analyze_incremental_diff(pdf_path)

    # 32. Fuzzy Hashing (ssdeep + TLSH)
    fuzzy_hash_result = compute_fuzzy_hashes(pdf_path)

    # 33. Steganography (auf extrahierten Bildern)
    steg_result = None
    try:
        from analyzers.steg_analyzer import analyze_steganography
        from models.schemas import StegResult
        if image_paths:
            # Steg auf das erste/größte Bild anwenden
            _steg_raw = analyze_steganography(image_paths[0])
            steg_result = StegResult(
                lsb_chi=_steg_raw.get("lsb_chi", {}),
                rs_analysis=_steg_raw.get("rs_analysis", {}),
                png_chunks=_steg_raw.get("png_chunks", {}),
                jpeg_trailing=_steg_raw.get("jpeg_trailing", {}),
                anomalies=_steg_raw.get("anomalies", []),
            )
    except Exception:
        pass

    # ================================================================
    # Phase 6: Extended Forensics (jeweils mit try/except abgesichert)
    # ================================================================

    # 36. YARA Rule Scanning
    try:
        _yara_raw = analyze_yara(pdf_path)
        yara_result = YaraResult(**{k: v for k, v in _yara_raw.items() if k != "error"})
    except Exception as e:
        print(f"[WARN] YARA-Analyzer fehlgeschlagen: {e}")
        yara_result = YaraResult()

    # 37. Font Forensics
    try:
        _font_raw = analyze_fonts(pdf_path)
        font_forensics_result = FontForensicsResult(**{k: v for k, v in _font_raw.items() if k != "error"})
    except Exception as e:
        print(f"[WARN] Font-Forensik fehlgeschlagen: {e}")
        font_forensics_result = FontForensicsResult()

    # 38. PDF/A & PDF/X Compliance
    try:
        _pdfa_raw = analyze_pdfa_pdfx(pdf_path)
        pdfa_result = PdfaComplianceResult(**{k: v for k, v in _pdfa_raw.items() if k != "error"})
    except Exception as e:
        print(f"[WARN] PDF/A-Validator fehlgeschlagen: {e}")
        pdfa_result = PdfaComplianceResult()

    # 39. Linearization Analysis
    try:
        _lin_raw = analyze_linearization(pdf_path)
        linearization_result = LinearizationResult(**{k: v for k, v in _lin_raw.items() if k != "error"})
    except Exception as e:
        print(f"[WARN] Linearization-Analyzer fehlgeschlagen: {e}")
        linearization_result = LinearizationResult()

    # 40. ICC Color Profile Analysis
    try:
        _icc_raw = analyze_icc_profiles(pdf_path)
        icc_result = IccProfileResult(**{k: v for k, v in _icc_raw.items() if k != "error"})
    except Exception as e:
        print(f"[WARN] ICC-Analyzer fehlgeschlagen: {e}")
        icc_result = IccProfileResult()

    # 41. Visual Render Comparison
    try:
        _vis_raw = analyze_visual_render(pdf_path)
        visual_result = VisualRenderResult(**{k: v for k, v in _vis_raw.items() if k != "error"})
    except Exception as e:
        print(f"[WARN] Visual-Render fehlgeschlagen: {e}")
        visual_result = VisualRenderResult()

    # 42. Object Graph Visualization
    try:
        _graph_raw = analyze_object_graph(pdf_path)
        object_graph_result = ObjectGraphResult(**{k: v for k, v in _graph_raw.items() if k != "error"})
    except Exception as e:
        print(f"[WARN] Object-Graph fehlgeschlagen: {e}")
        object_graph_result = ObjectGraphResult()

    # 43. Cross-Document Fingerprinting
    try:
        _fp_raw = create_document_fingerprint(pdf_path)
        cross_doc_fp_result = CrossDocFingerprintResult(**{k: v for k, v in _fp_raw.items() if k != "error"})
    except Exception as e:
        print(f"[WARN] Cross-Doc-Fingerprint fehlgeschlagen: {e}")
        cross_doc_fp_result = CrossDocFingerprintResult()

    # 44. Printer Forensics
    try:
        _pf_raw = analyze_printer_forensics(pdf_path)
        printer_result = PrinterForensicsResult(**{k: v for k, v in _pf_raw.items() if k != "error"})
    except Exception as e:
        print(f"[WARN] Printer-Forensik fehlgeschlagen: {e}")
        printer_result = PrinterForensicsResult()

    # ================================================================


    # ================================================================
    # 36b. Open-Source Forensik-Tools (pdfid/pdf-parser/qpdf/binwalk/PyMuPDF)
    # ================================================================
    try:
        opensource_result = analyze_opensource_forensics(pdf_path, IMAGES_DIR / analysis_id)
    except Exception as e:
        print(f'[WARN] Open-Source Forensik fehlgeschlagen: {e}')
        from models.schemas import OpenSourceForensicsResult as _OSF
        opensource_result = _OSF()



    # ================================================================
    # Tier 1 Erweiterung: ExifTool / OCR / mpeepdf / Copy-Move / Annotation
    # ================================================================
    try:
        exiftool_result = analyze_exiftool(pdf_path)
    except Exception as e:
        print(f"[WARN] ExifTool fehlgeschlagen: {e}")
        from models.schemas import ExifToolResult as _ET
        exiftool_result = _ET(error=str(e))

    if _PROFILE_LITE_SKIP:
        from models.schemas import OCRTextDiffResult as _OD
        ocr_diff_result = _OD(error='skipped (profile=lite)')
    else:
        try:
            ocr_diff_result = analyze_ocr_text_diff(pdf_path)
        except Exception as e:
            print(f"[WARN] OCR-Diff fehlgeschlagen: {e}")
            from models.schemas import OCRTextDiffResult as _OD
            ocr_diff_result = _OD(error=str(e))

    if _PROFILE_LITE_SKIP:
        from models.schemas import MpeepdfResult as _MP
        mpeepdf_result = _MP(error='skipped (profile=lite)')
    else:
        try:
            mpeepdf_result = analyze_mpeepdf(pdf_path)
        except Exception as e:
            print(f"[WARN] mpeepdf fehlgeschlagen: {e}")
            from models.schemas import MpeepdfResult as _MP
            mpeepdf_result = _MP(error=str(e))

    if _PROFILE_LITE_SKIP:
        from models.schemas import CopyMoveResult as _CM
        copy_move_result = _CM(error='skipped (profile=lite)')
    else:
        try:
            copy_move_result = analyze_copy_move(pdf_path)
        except Exception as e:
            print(f"[WARN] Copy-Move fehlgeschlagen: {e}")
            from models.schemas import CopyMoveResult as _CM
            copy_move_result = _CM(error=str(e))

    try:
        annot_forensics_result = analyze_annotation_forensics(pdf_path)
    except Exception as e:
        print(f"[WARN] Annotation-Forensik fehlgeschlagen: {e}")
        from models.schemas import AnnotationForensicsResult as _AF
        annot_forensics_result = _AF(error=str(e))



    # ================================================================
    # Tier 2 HF: Signature-Detection + Handwriting-OCR
    # ================================================================
    if _PROFILE_LITE_SKIP:
        from models.schemas import SignatureDetectorResult as _SR
        sig_result = _SR(error='skipped (profile=lite)')
    else:
        try:
            sig_result = analyze_hf_signatures(pdf_path, IMAGES_DIR / analysis_id / "signatures")
        except Exception as e:
            print(f"[WARN] HF Signature-Detector fehlgeschlagen: {e}")
            from models.schemas import SignatureDetectorResult as _SR
            sig_result = _SR(error=str(e))

    # Handwriting-OCR conditional auf gefundene Signatur-Crops + profile
    if _PROFILE_LITE_SKIP:
        from models.schemas import HandwritingOCRResult as _HR
        handwriting_result = _HR(skipped='profile=lite')
    else:
        try:
            crop_paths = []
            if sig_result and sig_result.detections:
                for d in sig_result.detections:
                    cp = d.get("crop_path")
                    if cp:
                        from pathlib import Path as _P
                        crop_paths.append(_P(cp))
            if crop_paths:
                handwriting_result = analyze_hf_handwriting(crop_paths)
            else:
                from models.schemas import HandwritingOCRResult as _HR
                handwriting_result = _HR(skipped="no signatures detected")
        except Exception as e:
            print(f"[WARN] HF Handwriting-OCR fehlgeschlagen: {e}")
            from models.schemas import HandwritingOCRResult as _HR
            handwriting_result = _HR(error=str(e))



    # ================================================================
    # Tier 3 + 4: LayoutLMv3 / Splicing / MLLM-Reasoning (profile-gated)
    # ================================================================
    from models.schemas import (
        LayoutConsistencyResult as _LCR,
        SplicingDetectorResult as _SPR,
        MLLMReasonerResult as _MLR,
    )

    layout_result = _LCR(error="skipped (profile=" + profile + ")")
    splicing_result = _SPR(error="skipped (profile=" + profile + ")")
    mllm_result = _MLR(error="skipped (profile=" + profile + ")")

    if profile in ("standard", "deep"):
        try:
            splicing_result = analyze_splicing(pdf_path)
        except Exception as e:
            print(f"[WARN] Splicing fehlgeschlagen: {e}")
            splicing_result = _SPR(error=str(e))

    if profile == "deep":
        try:
            layout_result = analyze_hf_layout_consistency(pdf_path)
        except Exception as e:
            print(f"[WARN] LayoutLMv3 fehlgeschlagen: {e}")
            layout_result = _LCR(error=str(e))

    # Anomalien aggregieren (Phase 1-4 + Phase 5 + Phase 6)
    # ================================================================
    all_anomalies: List[Anomaly] = []
    for result in [
        metadata, uuid_decode, software_fp, signature,
        page_geometry, page_labels, jpeg_extractor, jpeg_analyzer,
        quant_fp, encryption, incremental, javascript, embedded, virus_scan,
        timezone_result, author_artifacts_result, ela_result,
        object_stream_result, residual_result, shadow_result,
        ioc_result, hidden_text_result, yellow_dots_result,
        # Phase 5
        stream_decomp_result, xref_result, deep_jpeg_result,
        redaction_result, ocg_result, content_stream_result,
        inc_diff_result, fuzzy_hash_result,
        # Phase 6
        yara_result, font_forensics_result, pdfa_result,
        linearization_result, icc_result, visual_result,
        object_graph_result, cross_doc_fp_result, printer_result,
        opensource_result,
        exiftool_result, ocr_diff_result, mpeepdf_result, copy_move_result, annot_forensics_result,
        sig_result, handwriting_result, layout_result, splicing_result,
    ]:
        all_anomalies.extend(result.anomalies)

    # Steg-Anomalien
    if steg_result:
        all_anomalies.extend(steg_result.anomalies)

    # ================================================================
    # Doc-Type + Signatur-Workflow-Klassifikation (vor Risk-Level + Cross!)
    # ================================================================
    doc_type_result = classify_doc_type(
        software_fingerprint=software_fp,
        metadata=metadata,
        signature=signature,
        printer_forensics=printer_result,
    )
    _doc_type_key = doc_type_result.doc_type

    # Signatur-Workflow per pyhanko-Validierung
    try:
        from models.schemas import SignatureWorkflowResult as _SWR
        _swf_raw = analyze_multi_signature_workflow(pdf_path)
        signature_workflow_result = _SWR(**{k: v for k, v in _swf_raw.items() if k != "error"})
        if _swf_raw.get("error"):
            signature_workflow_result.error = _swf_raw["error"]
    except Exception as e:
        print(f"[WARN] Multi-Signatur-Workflow-Analyzer fehlgeschlagen: {e}")
        from models.schemas import SignatureWorkflowResult as _SWR
        signature_workflow_result = _SWR(workflow="error", error=str(e))
    _workflow_key = signature_workflow_result.workflow

    # Anomalien aus Signatur-Workflow ins all_anomalies einsammeln
    all_anomalies.extend(signature_workflow_result.anomalies)

    # === Severity-Profil EINMAL auf all_anomalies anwenden ===
    # Damit alle Counts + Risk-Berechnungen + UI-Anzeige konsistent die
    # downgegradet Severities sehen statt der Roh-Severities.
    all_anomalies = apply_doc_type_profile(
        all_anomalies, _doc_type_key, signature_workflow=_workflow_key,
    )

    significant  = [a for a in all_anomalies if a.severity != AnomalySeverity.INFO]
    risk_level   = _compute_risk_level(significant)  # Profile schon angewandt

    high_count   = sum(1 for a in all_anomalies if a.severity == AnomalySeverity.HIGH)
    medium_count = sum(1 for a in all_anomalies if a.severity == AnomalySeverity.MEDIUM)
    low_count    = sum(1 for a in all_anomalies if a.severity == AnomalySeverity.LOW)

    # Vorläufiges Ergebnis (ohne Cross-Analyzer und Chain of Custody)
    analysis_result = AnalysisResult(
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
        uuid_decode=uuid_decode,
        software_fingerprint=software_fp,
        signature=signature,
        page_geometry=page_geometry,
        page_labels=page_labels,
        jpeg_extractor=jpeg_extractor,
        jpeg_analyzer=jpeg_analyzer,
        quant_fingerprint=quant_fp,
        encryption=encryption,
        incremental_updates=incremental,
        javascript=javascript,
        embedded_files=embedded,
        virus_scan=virus_scan,
        timezone=timezone_result,
        author_artifacts=author_artifacts_result,
        ela=ela_result,
        object_streams=object_stream_result,
        residual_objects=residual_result,
        shadow_attack=shadow_result,
        ioc=ioc_result,
        hidden_text=hidden_text_result,
        yellow_dots=yellow_dots_result,
        # Phase 5
        stream_decomp=stream_decomp_result,
        xref_validation=xref_result,
        deep_jpeg=deep_jpeg_result,
        redaction=redaction_result,
        ocg_layers=ocg_result,
        content_stream=content_stream_result,
        incremental_diff=inc_diff_result,
        fuzzy_hash=fuzzy_hash_result,
        steganography=steg_result,
        # Phase 6
        yara=yara_result,
        font_forensics=font_forensics_result,
        pdfa_compliance=pdfa_result,
        linearization=linearization_result,
        icc_profiles=icc_result,
        visual_render=visual_result,
        object_graph=object_graph_result,
        cross_doc_fingerprint=cross_doc_fp_result,
        printer_forensics=printer_result,
        opensource_forensics=opensource_result,
        exiftool=exiftool_result,
        ocr_text_diff=ocr_diff_result,
        mpeepdf=mpeepdf_result,
        copy_move=copy_move_result,
        annotation_forensics=annot_forensics_result,
        hf_signatures=sig_result,
        hf_handwriting=handwriting_result,
        hf_layout=layout_result,
        splicing=splicing_result,
        profile=profile,
        doc_type=doc_type_result,
        signature_workflow=signature_workflow_result,
    )

    # ================================================================
    # 34. Cross-Analyzer Intelligence (braucht das Gesamtergebnis)
    # ================================================================
    cross_result = analyze_cross_correlations(
        analysis_result, doc_type=_doc_type_key, signature_workflow=_workflow_key,
    )
    all_anomalies.extend(cross_result.anomalies)
    analysis_result.cross_analyzer = cross_result

    # 35. Chain of Custody
    coc_result = create_chain_of_custody(
        pdf_path=pdf_path,
        original_hash_sha256=hashes.sha256,
        analysis_id=analysis_id,
        analyzer_names=ANALYZER_NAMES,
    )
    analysis_result.chain_of_custody = coc_result

    # Profile auf nachtraeglich von Cross-Analyzer hinzugefuegte Anomalien anwenden
    all_anomalies = apply_doc_type_profile(
        all_anomalies, _doc_type_key, signature_workflow=_workflow_key,
    )

    # Anomalie-Counts aktualisieren (nach Cross-Analyzer + Profile)
    analysis_result.all_anomalies = all_anomalies
    analysis_result.anomaly_count_high = sum(1 for a in all_anomalies if a.severity == AnomalySeverity.HIGH)
    analysis_result.anomaly_count_medium = sum(1 for a in all_anomalies if a.severity == AnomalySeverity.MEDIUM)
    analysis_result.anomaly_count_low = sum(1 for a in all_anomalies if a.severity == AnomalySeverity.LOW)

    # Risk-Level nochmal berechnen (Profile schon angewandt)
    significant = [a for a in all_anomalies if a.severity != AnomalySeverity.INFO]
    analysis_result.risk_level = _compute_risk_level(significant)


    # ================================================================
    # MLLM Reasoning -- nach allen anderen Analyzern, nutzt das Gesamt-Anomalie-Set
    # ================================================================
    if profile == "deep":
        try:
            from models.schemas import MetadataResult as _MR
            metadata_summary = {
                "title": getattr(metadata, "title", None),
                "creator": getattr(metadata, "creator", None),
                "producer": getattr(metadata, "producer", None),
                "creation_date": getattr(metadata, "creation_date_parsed", None),
                "mod_date": getattr(metadata, "mod_date_parsed", None),
                "page_count": getattr(metadata, "page_count", None),
            }
            exif_tags = getattr(exiftool_result, "raw_tags", {}) or {}
            mllm_result = analyze_mllm_reasoning(all_anomalies, metadata_summary, exif_tags)
        except Exception as e:
            print(f"[WARN] MLLM-Reasoning fehlgeschlagen: {e}")
            mllm_result = _MLR(error=str(e))
        all_anomalies.extend(mllm_result.anomalies)
        analysis_result.mllm_reasoning = mllm_result
    else:
        analysis_result.mllm_reasoning = mllm_result


    # Risk-Level final-recompute nach MLLM
    analysis_result.all_anomalies = all_anomalies
    analysis_result.anomaly_count_high   = sum(1 for a in all_anomalies if a.severity == AnomalySeverity.HIGH)
    analysis_result.anomaly_count_medium = sum(1 for a in all_anomalies if a.severity == AnomalySeverity.MEDIUM)
    analysis_result.anomaly_count_low    = sum(1 for a in all_anomalies if a.severity == AnomalySeverity.LOW)
    significant_final = [a for a in all_anomalies if a.severity != AnomalySeverity.INFO]
    analysis_result.risk_level = _compute_risk_level(significant_final)

    from analyzers.numpy_sanitizer import sanitize_result
    return sanitize_result(analysis_result)
