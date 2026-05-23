"""
MLLM-basierter Forgery-Reasoner via lokalem Ollama.

Nimmt das gesammelte Anomalien-Set + Annotation-Liste + ExifTool-Tags und
laesst das Sprachmodell eine forensische Bewertung schreiben:
- Welche Anomalien sind kritisch?
- Welche Pattern wurden zusammen gefunden (z.B. JS+EmbeddedFile = Malware-Vektor)?
- Wie wahrscheinlich ist Manipulation auf einer Skala 0-100?
- Welche weitere Untersuchung waere empfohlen?

Anders als der bestehende ai_review.py: dieser Analyzer fokussiert auf
korrelierte Reasoning-Logik, nicht auf Text-Generation.

Kein zusaetzliches Modell-Download -- nutzt die vorhandene Ollama-Instanz.
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from models.schemas import Anomaly, AnomalySeverity, MLLMReasonerResult


SYSTEM_PROMPT = """Du bist ein erfahrener forensischer PDF-Analyst. Du erhaelst die Liste aller Befunde aus einer Multi-Tool-Analyse einer PDF-Datei und sollst eine knappe, technisch praezise Bewertung abgeben.

Antworte AUSSCHLIESSLICH im folgenden JSON-Format (keine Markdown, kein Vorwort):
{
  "manipulation_score": 0-100,
  "key_correlations": ["Korrelation 1", "Korrelation 2", ...],
  "critical_findings": ["Befund 1", "Befund 2"],
  "recommended_next_steps": ["Schritt 1", "Schritt 2"],
  "verdict": "CLEAN" | "SUSPECT" | "MANIPULATED"
}"""


def _call_ollama(prompt: str, system: str = SYSTEM_PROMPT, model: Optional[str] = None) -> Optional[str]:
    import os
    import httpx
    base = os.environ.get("OLLAMA_BASE_URL", "http://host.docker.internal:11434")
    # Prefer faster qwen2.5:3b over dolphin-mistral (3-8 tok/s on CPU = often >180s timeout)
    selected_model = model or os.environ.get("OLLAMA_REASONING_MODEL", "qwen2.5:3b")
    url = f"{base}/v1/chat/completions"
    payload = {
        "model": selected_model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.1,
        "max_tokens": 500,
    }
    try:
        r = httpx.post(url, json=payload, timeout=600.0)
        r.raise_for_status()
        data = r.json()
        return data["choices"][0]["message"]["content"]
    except Exception as e:
        return f"__ERR__: {e}"


def _build_summary(anomalies: List[Dict[str, Any]],
                   metadata_summary: Dict[str, Any],
                   exiftool_tags: Dict[str, Any]) -> str:
    parts = ["FORENSIK-BEFUNDE:\n"]

    if anomalies:
        parts.append(f"Anomalien gesamt: {len(anomalies)}")
        for sev in ("HIGH", "MEDIUM", "LOW"):
            n = sum(1 for a in anomalies if a.get("severity") == sev)
            parts.append(f"  {sev}: {n}")
        parts.append("\nDetails (Top 25):")
        for a in anomalies[:25]:
            parts.append(f"- [{a.get('severity')}] {a.get('category')}: {a.get('message')}")

    parts.append("\nMETADATEN:")
    for k, v in (metadata_summary or {}).items():
        parts.append(f"  {k}: {v}")

    if exiftool_tags:
        parts.append("\nEXIFTOOL TAGS (Auszug):")
        keys = ["PDF:Producer", "XMP-xmp:CreatorTool", "XMP-xmpMM:DocumentID",
                "XMP-xmpMM:OriginalDocumentID", "XMP-xmpMM:DerivedFrom",
                "XMP-xmpMM:History"]
        for k in keys:
            if k in exiftool_tags:
                v = exiftool_tags[k]
                parts.append(f"  {k}: {str(v)[:120]}")

    return "\n".join(parts)


def analyze_mllm_reasoning(anomalies: List[Any],
                            metadata_summary: Dict[str, Any],
                            exiftool_tags: Dict[str, Any]) -> MLLMReasonerResult:
    """Anomalies passed as List of Anomaly-dicts or Anomaly objects."""
    out_anomalies: List[Anomaly] = []

    # Flatten anomalies to dict
    flat: List[Dict[str, Any]] = []
    for a in anomalies or []:
        if isinstance(a, dict):
            flat.append(a)
        else:
            flat.append({
                "severity": getattr(a, "severity", None) or
                            (a.severity.value if hasattr(a.severity, "value") else str(a.severity)),
                "category": getattr(a, "category", "?"),
                "message": getattr(a, "message", ""),
                "detail": getattr(a, "detail", ""),
            })

    summary = _build_summary(flat, metadata_summary, exiftool_tags)
    raw = _call_ollama(summary)

    if not raw:
        return MLLMReasonerResult(error="empty response", anomalies=[])
    if raw.startswith("__ERR__"):
        return MLLMReasonerResult(error=raw.replace("__ERR__: ", "", 1), anomalies=[])

    parsed: Dict[str, Any] = {}
    raw_clean = raw.strip()
    # Strip optional code-fence
    if raw_clean.startswith("```"):
        raw_clean = raw_clean.split("```", 2)[1] if "```" in raw_clean[3:] else raw_clean[3:]
        if raw_clean.lstrip().startswith("json"):
            raw_clean = raw_clean.lstrip()[4:].strip()
    try:
        parsed = json.loads(raw_clean)
    except json.JSONDecodeError:
        # Last-resort: extract first {...} block
        import re
        m = re.search(r"\{.*\}", raw_clean, re.DOTALL)
        if m:
            try:
                parsed = json.loads(m.group(0))
            except json.JSONDecodeError:
                parsed = {}

    if not parsed:
        return MLLMReasonerResult(
            raw_response=raw[:2000],
            error="JSON parse failed",
            anomalies=[],
        )

    score = int(parsed.get("manipulation_score") or 0)
    verdict = str(parsed.get("verdict") or "?")

    if verdict == "MANIPULATED" or score >= 70:
        out_anomalies.append(Anomaly(
            severity=AnomalySeverity.HIGH,
            category="mllm_verdict_manipulated",
            message=f"MLLM-Bewertung: MANIPULATED (Score {score})",
            detail=f"key_correlations: {parsed.get('key_correlations', [])[:3]}",
        ))
    elif verdict == "SUSPECT" or score >= 40:
        out_anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category="mllm_verdict_suspect",
            message=f"MLLM-Bewertung: SUSPECT (Score {score})",
            detail=f"critical: {parsed.get('critical_findings', [])[:3]}",
        ))

    return MLLMReasonerResult(
        manipulation_score=score,
        verdict=verdict,
        key_correlations=parsed.get("key_correlations", [])[:10],
        critical_findings=parsed.get("critical_findings", [])[:10],
        recommended_next_steps=parsed.get("recommended_next_steps", [])[:10],
        raw_response=raw[:2000],
        anomalies=out_anomalies,
    )
