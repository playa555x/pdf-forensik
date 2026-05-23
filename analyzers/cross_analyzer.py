"""
Cross-Analyzer Intelligence — Korrelations-Engine.

Analysiert Ergebnisse aller Einzelanalyzer und erkennt Zusammenhänge:
1. Zeitlinien-Rekonstruktion (UUID + Metadata + Timezone)
2. Creator-Profiling (Software + Author + Font-Prefixes)
3. Manipulations-Scoring (gewichtete Bewertung aller Anomalien)
4. Automatische Korrelationen zwischen Analyzern
"""
from __future__ import annotations
from datetime import datetime
from typing import List, Dict, Any, Optional

from models.schemas import (
    Anomaly, AnomalySeverity, CorrelationFinding, CrossAnalyzerResult,
    AnalysisResult,
)
from analyzers.severity_profiles import (
    apply_doc_type_profile, count_by_class, is_hard_high,
)
from config import (
    SCORE_HARD_HIGH_WEIGHT, SCORE_SOFT_HIGH_WEIGHT,
    SCORE_MEDIUM_WEIGHT, SCORE_LOW_WEIGHT,
)


def _parse_datetime(dt_str: Optional[str]) -> Optional[datetime]:
    """Versucht verschiedene Datetime-Formate zu parsen."""
    if not dt_str:
        return None
    for fmt in [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ]:
        try:
            return datetime.strptime(dt_str[:19], fmt[:len(dt_str[:19])+2])
        except Exception:
            continue
    return None


def _reconstruct_timeline(result: AnalysisResult) -> List[Dict[str, Any]]:
    """Rekonstruiert eine Zeitlinie aus allen verfügbaren Zeitstempeln."""
    events = []

    # Metadata-Zeitstempel
    if result.metadata:
        if result.metadata.creation_date_parsed:
            events.append({
                "source": "metadata",
                "type": "creation",
                "timestamp": result.metadata.creation_date_parsed,
                "detail": f"PDF erstellt (Creator: {result.metadata.creator or '?'})",
            })
        if result.metadata.mod_date_parsed:
            events.append({
                "source": "metadata",
                "type": "modification",
                "timestamp": result.metadata.mod_date_parsed,
                "detail": f"PDF geändert (Producer: {result.metadata.producer or '?'})",
            })

    # UUID-Zeitstempel
    if result.uuid_decode and result.uuid_decode.decoded:
        for uid in result.uuid_decode.decoded:
            ts = uid.get("timestamp_utc") or uid.get("creation_date_iso")
            if ts:
                events.append({
                    "source": "uuid",
                    "type": "uuid_creation",
                    "timestamp": ts,
                    "detail": f"UUID v{uid.get('version', '?')}: {uid.get('uuid', '?')[:16]}...",
                })

    # Timezone-Informationen
    if result.timezone and result.timezone.dates:
        for tz_date in result.timezone.dates:
            if isinstance(tz_date, dict) and tz_date.get("parsed"):
                events.append({
                    "source": "timezone",
                    "type": "timezone_ref",
                    "timestamp": tz_date["parsed"],
                    "detail": f"TZ-Referenz: Offset {tz_date.get('offset', '?')}",
                })

    # Author-Artifacts Zeitstempel
    if result.author_artifacts:
        for artifact in result.author_artifacts.all_artifacts:
            if isinstance(artifact, dict) and artifact.get("timestamp"):
                events.append({
                    "source": "author_artifacts",
                    "type": "artifact",
                    "timestamp": artifact["timestamp"],
                    "detail": f"Artifact: {artifact.get('source', '?')}",
                })

    # Sortieren
    def sort_key(e):
        dt = _parse_datetime(e.get("timestamp", ""))
        return dt if dt else datetime.min

    events.sort(key=sort_key)
    return events


def _build_creator_profile(result: AnalysisResult) -> Dict[str, Any]:
    """Erstellt ein Profil des Dokument-Erstellers."""
    profile: Dict[str, Any] = {
        "software": {},
        "author_info": {},
        "system_hints": {},
        "confidence": "low",
    }

    # Software-Informationen
    if result.software_fingerprint:
        sf = result.software_fingerprint
        profile["software"] = {
            "identified_tool": sf.identified_tool,
            "tool_category": sf.tool_category,
            "version": sf.version_hint,
            "producer": sf.producer_raw,
            "creator": sf.creator_raw,
        }

    # Metadata-Autor
    if result.metadata:
        if result.metadata.author:
            profile["author_info"]["name"] = result.metadata.author
        if result.metadata.keywords:
            profile["author_info"]["keywords"] = result.metadata.keywords

    # Author-Artifacts
    if result.author_artifacts:
        aa = result.author_artifacts
        if aa.font_prefixes:
            profile["system_hints"]["font_prefixes"] = [
                f.get("prefix", "") for f in aa.font_prefixes[:5]
            ]
        if aa.printer_name:
            profile["system_hints"]["printers"] = [
                p.get("name", "") for p in aa.printer_name[:3]
            ]
        if aa.xmp_authors:
            profile["author_info"]["xmp_authors"] = [
                a.get("name", "") for a in aa.xmp_authors[:3]
            ]

    # Timezone → Region-Hint
    if result.timezone:
        if result.timezone.region_hint:
            profile["system_hints"]["region"] = result.timezone.region_hint
        if result.timezone.unique_offsets:
            profile["system_hints"]["utc_offsets"] = result.timezone.unique_offsets

    # Yellow Dots → Drucker-Info
    if result.yellow_dots and result.yellow_dots.dots_found:
        profile["system_hints"]["yellow_dots"] = result.yellow_dots.decoded_info

    # Confidence berechnen
    info_count = sum(1 for v in [
        profile["software"].get("identified_tool"),
        profile["author_info"].get("name"),
        profile["system_hints"].get("region"),
        profile["system_hints"].get("font_prefixes"),
    ] if v)

    if info_count >= 3:
        profile["confidence"] = "high"
    elif info_count >= 2:
        profile["confidence"] = "medium"

    return profile


def _find_correlations(
    result: AnalysisResult,
    signature_workflow: Optional[str] = None,
) -> List[CorrelationFinding]:
    """Findet automatische Korrelationen zwischen Analyzer-Ergebnissen.

    `signature_workflow`: bei 'multi_sig_intact' wird die Korrelation
    "Signiertes Dokument mit nachtraeglichen Updates" zu INFO degradiert,
    weil sie in einem legitimen Multi-Sig-Workflow erwartbar ist.
    """
    correlations: List[CorrelationFinding] = []
    is_multi_sig_intact = signature_workflow == "multi_sig_intact"

    # 1. Creator/Producer-Mismatch + UUID-Zeitdifferenz
    if result.software_fingerprint and result.uuid_decode:
        sf = result.software_fingerprint
        if sf.creator_raw and sf.producer_raw and sf.creator_raw != sf.producer_raw:
            # Prüfe ob UUID-Zeitstempel die Software-Wechsel bestätigen
            uuid_gaps = []
            for uid in result.uuid_decode.decoded:
                delta = uid.get("delta_seconds")
                if delta and abs(delta) > 3600:
                    uuid_gaps.append(f"{abs(delta)/3600:.1f}h")

            if uuid_gaps:
                correlations.append(CorrelationFinding(
                    title="Software-Wechsel mit UUID-Zeitlücken",
                    severity=AnomalySeverity.HIGH,
                    analyzers_involved=["software_fingerprint", "uuid_decode"],
                    evidence=[
                        f"Creator: {sf.creator_raw}",
                        f"Producer: {sf.producer_raw}",
                        f"UUID-Zeitlücken: {', '.join(uuid_gaps)}",
                    ],
                    conclusion="Dokument wurde mit verschiedenen Tools zu verschiedenen Zeiten bearbeitet — mögliche Manipulation",
                ))

    # 2. Metadata-Zeitstempel vs. UUID-Zeitstempel Inkonsistenz
    if result.metadata and result.uuid_decode:
        creation = _parse_datetime(result.metadata.creation_date_parsed)
        if creation and result.uuid_decode.decoded:
            for uid in result.uuid_decode.decoded:
                uid_ts = _parse_datetime(uid.get("timestamp_utc"))
                if uid_ts and creation:
                    diff_hours = abs((uid_ts - creation).total_seconds()) / 3600
                    if diff_hours > 48:
                        correlations.append(CorrelationFinding(
                            title="Zeitstempel-Inkonsistenz: Metadata vs UUID",
                            severity=AnomalySeverity.HIGH,
                            analyzers_involved=["metadata", "uuid_decode"],
                            evidence=[
                                f"Metadata-Erstellung: {result.metadata.creation_date_parsed}",
                                f"UUID-Zeitstempel: {uid.get('timestamp_utc')}",
                                f"Differenz: {diff_hours:.0f} Stunden",
                            ],
                            conclusion="Erstellungszeit und UUID-Zeitstempel weichen stark ab — Zeitstempel möglicherweise manipuliert",
                        ))
                        break

    # 3. Timezone-Inkonsistenz + Author-Artifacts
    if result.timezone and result.author_artifacts:
        if not result.timezone.offset_consistent and len(result.timezone.unique_offsets) > 1:
            # Prüfe ob verschiedene Autoren verschiedene Zeitzonen haben
            authors = []
            for a in result.author_artifacts.xmp_authors:
                if isinstance(a, dict):
                    authors.append(a.get("name", ""))

            if len(set(authors)) > 1:
                correlations.append(CorrelationFinding(
                    title="Mehrere Autoren mit verschiedenen Zeitzonen",
                    severity=AnomalySeverity.MEDIUM,
                    analyzers_involved=["timezone", "author_artifacts"],
                    evidence=[
                        f"Zeitzonen: UTC{result.timezone.unique_offsets}",
                        f"Autoren: {', '.join(set(authors))}",
                    ],
                    conclusion="Verschiedene Bearbeiter in verschiedenen Zeitzonen — konsistent mit Kollaboration oder Manipulation",
                ))

    # 4. Verschlüsselung + JavaScript
    if result.encryption and result.javascript:
        if result.encryption.is_encrypted and result.javascript.has_javascript:
            correlations.append(CorrelationFinding(
                title="Verschlüsseltes PDF mit JavaScript",
                severity=AnomalySeverity.HIGH,
                analyzers_involved=["encryption", "javascript"],
                evidence=[
                    f"Verschlüsselung: {result.encryption.algorithm or 'unbekannt'}",
                    f"JavaScript: {len(result.javascript.js_snippets)} Snippets",
                ],
                conclusion="Kombination von Verschlüsselung und JavaScript ist hochverdächtig — möglicher Exploit",
            ))

    # 5. Incremental Updates + Signatur
    if result.incremental_updates and result.signature:
        if result.incremental_updates.revision_count > 1 and result.signature.has_sig_field:
            # Bei legitimer Multi-Sig sind genau das die erwarteten Revisionen
            # — pyhanko hat ja bestaetigt, dass alle Sigs intakt sind.
            if is_multi_sig_intact:
                correlations.append(CorrelationFinding(
                    title="Multi-Signatur-Workflow: mehrere Revisionen vorhanden",
                    severity=AnomalySeverity.INFO,
                    analyzers_involved=["incremental_updates", "signature", "signature_workflow"],
                    evidence=[
                        f"Revisionen: {result.incremental_updates.revision_count}",
                        f"Signatur-Felder: {result.signature.sig_field_names}",
                        "pyhanko bestaetigt: alle Signaturen kryptografisch intakt",
                    ],
                    conclusion="Mehrere Revisionen sind in einem Multi-Signatur-Workflow erwartbar — kein Shadow-Attack",
                ))
            else:
                correlations.append(CorrelationFinding(
                    title="Signiertes Dokument mit nachträglichen Updates",
                    severity=AnomalySeverity.HIGH,
                    analyzers_involved=["incremental_updates", "signature"],
                    evidence=[
                        f"Revisionen: {result.incremental_updates.revision_count}",
                        f"Signatur-Felder: {result.signature.sig_field_names}",
                    ],
                    conclusion="Inkrementelle Updates nach Signatur können die Signaturintegrität gefährden (Shadow Attack)",
                ))

    # 6. Hidden Text + Redaction (wenn vorhanden)
    if result.hidden_text and result.hidden_text.hidden_blocks:
        if result.redaction and result.redaction.insecure_redactions > 0:
            correlations.append(CorrelationFinding(
                title="Versteckter Text + unsichere Schwärzung",
                severity=AnomalySeverity.HIGH,
                analyzers_involved=["hidden_text", "redaction"],
                evidence=[
                    f"Versteckte Textblöcke: {len(result.hidden_text.hidden_blocks)}",
                    f"Unsichere Schwärzungen: {result.redaction.insecure_redactions}",
                ],
                conclusion="Kombination aus verstecktem Text und unsicheren Schwärzungen — sensible Daten möglicherweise extrahierbar",
            ))

    # 7. IOC + Embedded Files
    if result.ioc and result.embedded_files:
        suspicious_urls = result.ioc.suspicious_iocs if result.ioc.suspicious_iocs else []
        embedded = result.embedded_files.embedded_files if result.embedded_files.embedded_files else []
        if suspicious_urls and embedded:
            correlations.append(CorrelationFinding(
                title="Verdächtige URLs + eingebettete Dateien",
                severity=AnomalySeverity.HIGH,
                analyzers_involved=["ioc", "embedded_files"],
                evidence=[
                    f"Verdächtige IOCs: {len(suspicious_urls)}",
                    f"Eingebettete Dateien: {len(embedded)}",
                ],
                conclusion="Eingebettete Dateien zusammen mit verdächtigen URLs deuten auf Payload-Delivery hin",
            ))

    # 8. ELA-Anomalien + JPEG Double-Compression
    if result.ela and result.deep_jpeg:
        ela_anomalies = [a for a in (result.ela.anomalies or []) if a.severity in (AnomalySeverity.HIGH, AnomalySeverity.MEDIUM)]
        jpeg_anomalies = [a for a in (result.deep_jpeg.anomalies or []) if "Double" in a.message or "Ghost" in a.message]

        if ela_anomalies and jpeg_anomalies:
            correlations.append(CorrelationFinding(
                title="ELA-Anomalien bestätigt durch JPEG-Forensik",
                severity=AnomalySeverity.HIGH,
                analyzers_involved=["ela", "deep_jpeg"],
                evidence=[
                    f"ELA-Auffälligkeiten: {len(ela_anomalies)}",
                    f"JPEG-Forensik-Befunde: {len(jpeg_anomalies)}",
                ],
                conclusion="Beide unabhängigen Bildanalysen zeigen Manipulationshinweise — sehr wahrscheinlich bearbeitet",
            ))

    return correlations


def _compute_manipulation_score(
    result: AnalysisResult,
    correlations: List[CorrelationFinding],
    doc_type: Optional[str] = None,
    signature_workflow: Optional[str] = None,
) -> float:
    """
    Berechnet einen Manipulations-Score von 0-100, **Doc-Typ-bewusst**.

    Aenderung gegenueber alter Implementierung:
    - Anomalien werden zuerst per `apply_doc_type_profile` an den Dokumenttyp
      angepasst (z.B. OCR-Mismatch in einer Broschuere -> INFO statt HIGH).
    - "Hard-HIGH" (echte Security) und "Soft-HIGH" (Heuristik) werden
      unterschiedlich gewichtet. Damit kippt ein Marketing-PDF nicht mehr auf
      100/100 nur weil OCR an stylized text scheitert, waehrend ein PDF mit
      Malware-Signatur weiterhin sofort einen hohen Score bekommt.
    """
    # Doc-Typ + Signatur-Workflow bewusste Severities anwenden
    effective_anomalies = apply_doc_type_profile(
        result.all_anomalies or [], doc_type, signature_workflow=signature_workflow,
    )
    counts = count_by_class(effective_anomalies)

    score = 0.0
    score += counts["hard_high"] * SCORE_HARD_HIGH_WEIGHT
    score += counts["soft_high"] * SCORE_SOFT_HIGH_WEIGHT
    score += counts["medium"]    * SCORE_MEDIUM_WEIGHT
    score += counts["low"]       * SCORE_LOW_WEIGHT

    # Korrelations-Punkte (Hard-/Soft-HIGH unterscheiden)
    for c in correlations:
        # Korrelation ist Hard-HIGH wenn mindestens ein involvierter Analyzer
        # in HARD_HIGH_CATEGORIES ist
        is_hh = any(a in {"javascript", "shadow_attack", "yara", "virus_scan", "redaction"}
                    for a in (c.analyzers_involved or []))
        if c.severity == AnomalySeverity.HIGH:
            score += 15 if is_hh else 8
        elif c.severity == AnomalySeverity.MEDIUM:
            score += 8 if is_hh else 4
        else:
            score += 3

    # Hard-HIGH-Boni fuer kritische Einzelbefunde — auch wenn die Anomalie
    # vielleicht keine HIGH-Severity hatte, ist das Vorhandensein selbst kritisch
    if result.javascript and getattr(result.javascript, "has_auto_execute", False):
        score += 20
    if result.shadow_attack and result.shadow_attack.anomalies:
        score += 25
    if result.virus_scan:
        try:
            if any(e.threats_found for e in (result.virus_scan.engines or [])):
                score += 30
        except Exception:
            pass

    return min(100.0, score)


def analyze_cross_correlations(
    result: AnalysisResult,
    doc_type: Optional[str] = None,
    signature_workflow: Optional[str] = None,
) -> CrossAnalyzerResult:
    """Fuehrt die vollstaendige Cross-Analyzer-Korrelation durch.

    `doc_type`:           Dokumenttyp aus doc_type_classifier (Broschuere/Scan/...)
    `signature_workflow`: Workflow-Klasse aus multi_signature_workflow
                          (z.B. 'multi_sig_intact' dampft shadow_attack-Findings).
    Beide werden an Severity-Profil + Scoring durchgereicht.
    """
    anomalies: List[Anomaly] = []

    # 1. Zeitlinie rekonstruieren
    timeline = _reconstruct_timeline(result)

    # 2. Creator-Profil erstellen
    creator_profile = _build_creator_profile(result)

    # 3. Korrelationen finden (workflow-bewusst)
    correlations = _find_correlations(result, signature_workflow=signature_workflow)

    # 4. Manipulations-Score (Doc-Typ + Signatur-Workflow-bewusst)
    manip_score = _compute_manipulation_score(
        result, correlations,
        doc_type=doc_type,
        signature_workflow=signature_workflow,
    )

    # Anomalien aus Korrelationen
    for c in correlations:
        anomalies.append(Anomaly(
            severity=c.severity,
            category="cross_analyzer",
            message=c.title,
            detail=c.conclusion,
        ))

    # Score-basierte Anomalie
    if manip_score > 60:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.HIGH,
            category="cross_analyzer",
            message=f"Hoher Manipulations-Score: {manip_score:.0f}/100",
            detail="Mehrere unabhängige Indikatoren deuten auf Dokumentmanipulation hin",
        ))
    elif manip_score > 30:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category="cross_analyzer",
            message=f"Mittlerer Manipulations-Score: {manip_score:.0f}/100",
            detail="Einige Indikatoren erfordern weitere Untersuchung",
        ))

    return CrossAnalyzerResult(
        correlations=correlations,
        timeline_reconstruction=timeline,
        creator_profile=creator_profile,
        manipulation_score=round(manip_score, 1),
        anomalies=anomalies,
    )
