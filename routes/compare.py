"""
POST /compare — 2-4 bereits analysierte Dokumente vergleichen.
Erweitert: Software-Matching, UUID-Cluster, Metadata-Diff, JS/Encryption-Flags.
"""
from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

import json
from database.db import get_analysis, save_comparison, find_font_prefix_matches, find_quant_table_matches
from models.schemas import (
    CompareResult, CompareDocumentInfo, Anomaly, AnomalySeverity
)
from config import COMPARE_MIN_TIME_DIFF_SECONDS

router = APIRouter()


class CompareRequest(BaseModel):
    analysis_ids: List[str]


@router.post("/compare")
async def compare_analyses(req: CompareRequest):
    if len(req.analysis_ids) < 2:
        raise HTTPException(status_code=400, detail="Mindestens 2 Analysen erforderlich.")
    if len(req.analysis_ids) > 4:
        raise HTTPException(status_code=400, detail="Maximal 4 Analysen gleichzeitig.")

    results = []
    for aid in req.analysis_ids:
        r = await get_analysis(aid)
        if r is None:
            raise HTTPException(status_code=404, detail=f"Analyse {aid} nicht gefunden.")
        results.append(r)

    anomalies: list[Anomaly] = []
    identical_hashes = []
    time_proximity_flags = []
    same_software: List[Dict[str, Any]] = []
    same_uuid_cluster: List[Dict[str, Any]] = []
    metadata_diffs: List[Dict[str, Any]] = []

    # Dokument-Infos aufbauen
    doc_infos = []
    for r in results:
        doc_infos.append(CompareDocumentInfo(
            analysis_id=r.analysis_id,
            filename=r.filename,
            analyzed_at=r.analyzed_at,
            sha256=r.hashes.sha256,
            risk_level=r.risk_level,
            producer=r.software_fingerprint.producer_raw,
            creator=r.software_fingerprint.creator_raw,
            creation_date=r.metadata.creation_date_parsed,
            mod_date=r.metadata.mod_date_parsed,
            page_count=r.metadata.page_count,
            image_count=r.jpeg_extractor.total_images,
            anomaly_count_high=r.anomaly_count_high,
            anomaly_count_medium=r.anomaly_count_medium,
            has_javascript=r.javascript.has_javascript,
            is_encrypted=r.encryption.is_encrypted,
            revision_count=r.incremental_updates.revision_count,
            uuids=r.uuid_decode.found_uuids[:10],
        ))

    # 1. Identische SHA256
    for i in range(len(results)):
        for j in range(i + 1, len(results)):
            if results[i].hashes.sha256 == results[j].hashes.sha256:
                identical_hashes.append((results[i].analysis_id, results[j].analysis_id))
                anomalies.append(Anomaly(
                    severity=AnomalySeverity.HIGH,
                    category="compare",
                    message=f"Identische SHA256-Hashes: '{results[i].filename}' und '{results[j].filename}'",
                    detail=f"SHA256: {results[i].hashes.sha256}",
                ))

    # 2. Zeitnähe (CreationDate < 5 Minuten Abstand)
    for i in range(len(results)):
        for j in range(i + 1, len(results)):
            cd_i = results[i].metadata.creation_date_parsed
            cd_j = results[j].metadata.creation_date_parsed
            if cd_i and cd_j:
                try:
                    dt_i = datetime.fromisoformat(cd_i.replace("Z", "+00:00"))
                    dt_j = datetime.fromisoformat(cd_j.replace("Z", "+00:00"))
                    diff = abs((dt_i - dt_j).total_seconds())
                    if diff < COMPARE_MIN_TIME_DIFF_SECONDS:
                        time_proximity_flags.append({
                            "analysis_id_a": results[i].analysis_id,
                            "analysis_id_b": results[j].analysis_id,
                            "filename_a": results[i].filename,
                            "filename_b": results[j].filename,
                            "delta_seconds": diff,
                        })
                        anomalies.append(Anomaly(
                            severity=AnomalySeverity.MEDIUM,
                            category="compare",
                            message=f"Dokumente im Abstand von {diff:.0f}s erstellt (<{COMPARE_MIN_TIME_DIFF_SECONDS}s)",
                            detail=f"'{results[i].filename}' ({cd_i}) vs '{results[j].filename}' ({cd_j})",
                        ))
                except Exception:
                    pass

    # 3. Gleiche Software (Producer identisch)
    for i in range(len(results)):
        for j in range(i + 1, len(results)):
            prod_i = results[i].software_fingerprint.identified_tool
            prod_j = results[j].software_fingerprint.identified_tool
            if prod_i and prod_j and prod_i == prod_j:
                entry = {
                    "analysis_id_a": results[i].analysis_id,
                    "analysis_id_b": results[j].analysis_id,
                    "tool": prod_i,
                }
                if entry not in same_software:
                    same_software.append(entry)

            # Identische Producer-Strings (inkl. Version)
            raw_i = results[i].software_fingerprint.producer_raw or ""
            raw_j = results[j].software_fingerprint.producer_raw or ""
            if raw_i and raw_j and raw_i == raw_j:
                anomalies.append(Anomaly(
                    severity=AnomalySeverity.INFO,
                    category="compare",
                    message=f"Identischer Producer-String bei '{results[i].filename}' und '{results[j].filename}'",
                    detail=f"Producer: {raw_i}",
                ))

    # 4. UUID-Cluster (gleiche UUIDs in verschiedenen Dokumenten → gleiche Maschine/Session)
    for i in range(len(results)):
        for j in range(i + 1, len(results)):
            uuids_i = set(results[i].uuid_decode.found_uuids)
            uuids_j = set(results[j].uuid_decode.found_uuids)
            shared  = uuids_i & uuids_j
            if shared:
                same_uuid_cluster.append({
                    "analysis_id_a": results[i].analysis_id,
                    "analysis_id_b": results[j].analysis_id,
                    "shared_uuids": list(shared)[:5],
                })
                anomalies.append(Anomaly(
                    severity=AnomalySeverity.HIGH,
                    category="compare",
                    message=f"Identische UUIDs in '{results[i].filename}' und '{results[j].filename}' — gleiche Quelle!",
                    detail=f"Geteilte UUIDs: {list(shared)[:3]}",
                ))

    # 5. Metadata-Diff (Autor, Titel, Keywords)
    fields_to_compare = [
        ("author",   "Autor"),
        ("title",    "Titel"),
        ("keywords", "Keywords"),
        ("creator",  "Creator"),
    ]
    for fname, label in fields_to_compare:
        values = [(r.filename, getattr(r.metadata, fname)) for r in results]
        non_null = [(fn, v) for fn, v in values if v]
        if len(non_null) > 1:
            unique_vals = set(v for _, v in non_null)
            if len(unique_vals) > 1:
                metadata_diffs.append({
                    "field": label,
                    "values": {fn: v for fn, v in non_null},
                })

    # 6. JavaScript-Flag
    js_docs = [r for r in results if r.javascript.has_javascript]
    if js_docs and len(js_docs) < len(results):
        anomalies.append(Anomaly(
            severity=AnomalySeverity.HIGH,
            category="compare",
            message=f"Nur {len(js_docs)} von {len(results)} Dokumenten enthalten JavaScript",
            detail=", ".join(r.filename for r in js_docs),
        ))

    # 7. Revisions-Anomalie
    multi_rev = [r for r in results if r.incremental_updates.revision_count > 1]
    if multi_rev:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category="compare",
            message=f"{len(multi_rev)} Dokument(e) haben mehrere Revisionen (mögliche Manipulation)",
            detail=", ".join(f"{r.filename} ({r.incremental_updates.revision_count} Rev.)" for r in multi_rev),
        ))

    # Gemeinsame Anomalie-Kategorien (Bug-Fix: leere Liste behandeln)
    all_cats = [set(a.category for a in r.all_anomalies) for r in results]
    if len(all_cats) >= 2:
        common_anomalies = sorted(set.intersection(*all_cats))
    else:
        common_anomalies = []

    comparison_id = str(uuid.uuid4())
    compared_at   = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    compare_result = CompareResult(
        comparison_id=comparison_id,
        compared_at=compared_at,
        documents=doc_infos,
        identical_hashes=identical_hashes,
        time_proximity_flags=time_proximity_flags,
        common_anomalies=common_anomalies,
        same_software=same_software,
        same_uuid_cluster=same_uuid_cluster,
        metadata_diffs=metadata_diffs,
        anomalies=anomalies,
    )

    await save_comparison(compare_result)
    return compare_result.model_dump()


@router.get("/cross-match/fonts/{analysis_id}")
async def cross_match_fonts(analysis_id: str):
    """Findet Dokumente aus derselben Word-Session (gleiche Font-Präfixe)."""
    result = await get_analysis(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Analyse nicht gefunden.")

    prefixes = [
        fp.get('prefix', fp.get('name', ''))
        for fp in (result.author_artifacts.font_prefixes if result.author_artifacts else [])
    ]
    prefixes = [p for p in prefixes if p]

    matches = await find_font_prefix_matches(prefixes, analysis_id)
    return {
        "analysis_id": analysis_id,
        "filename": result.filename,
        "font_prefixes": prefixes,
        "matches": matches,
        "match_count": len(matches),
    }


@router.get("/cross-match/quant/{analysis_id}")
async def cross_match_quant(analysis_id: str):
    """Findet Dokumente von derselben Kamera/demselben Scanner (gleiche Quant-Tabellen)."""
    result = await get_analysis(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Analyse nicht gefunden.")

    quant_sig = json.dumps(
        result.quant_fingerprint.matches[:3] if result.quant_fingerprint else []
    )

    matches = await find_quant_table_matches(quant_sig, analysis_id)
    return {
        "analysis_id": analysis_id,
        "filename": result.filename,
        "quant_signature": quant_sig,
        "matches": matches,
        "match_count": len(matches),
    }
