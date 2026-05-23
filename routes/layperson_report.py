"""
GET /report/layperson/{analysis_id} — der Anfaenger-Bericht.

Eine HTML-Seite die einem nicht-technischen Nutzer in 3 klaren Sektionen
zeigt:
  1. Was ist das fuer ein Dokument?
  2. Was haben wir gefunden?
  3. Was bedeutet das?  (Ampel-Verdict + Empfehlung)

Quellen: AnalysisResult (Pipeline-Output) + AIReview (gemma3:4b-Output).
Wenn kein AI-Review im Cache ist, wird die Seite trotzdem gerendert —
ohne den KI-Fliesstext, dafuer mit Hinweis "wird gerade generiert".
"""
from __future__ import annotations
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Request, Query
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape

from database.db import get_analysis, get_ai_review

router = APIRouter()

# Eigene Jinja-Env mit DISABLEM Cache — die Starlette-Jinja2Templates-Caching
# kollidiert in dieser Version mit irgendwas (TypeError: unhashable type: dict
# beim get_template()). cache_size=0 schaltet's aus.
_jinja = Environment(
    loader=FileSystemLoader(str(Path(__file__).parent.parent / "templates")),
    autoescape=select_autoescape(["html", "xml"]),
    cache_size=0,
)


# Mensch-lesbare Labels fuer doc_type-Strings aus dem Classifier
_DOC_TYPE_LABELS = {
    "office_letter":       ("Brief / Memo",                 "Ein kurzes Bueroschreiben (typisch ein Anschreiben oder Memo)."),
    "office_document":     ("Bueroschreiben (laenger)",     "Ein laengeres Office-Dokument (Bericht, Vertrag, Praesentation)."),
    "design_brochure":     ("Marketing-Broschuere",         "Ein gestaltetes Werbe- oder Imagedokument aus einem Design-Programm."),
    "scan":                ("Eingescanntes Dokument",       "Aus Papier eingescanntes Dokument (kein digital erzeugter Text)."),
    "form":                ("Ausfuellbares Formular",       "Ein Formular mit Eingabefeldern."),
    "technical_document":  ("Technisches Dokument",         "Akademisch/technisch (LaTeX/pdfTeX) erzeugt."),
    "online_converted":    ("Online-konvertiert",           "Ueber einen Online-Service (Smallpdf, iLovePDF, ...) erzeugt."),
    "unknown":             ("Unbekannter Typ",              "Keine eindeutigen Indikatoren - keine vertrauliche Aussage moeglich."),
}


_WORKFLOW_LABELS = {
    "no_signature":               ("Nicht signiert",          "Das Dokument enthaelt keine digitale Signatur."),
    "single_sig_intact":          ("1 Signatur (intakt)",     "Ein Unterzeichner, Signatur mathematisch intakt."),
    "single_sig_modified_after":  ("Signatur + Aenderungen",  "Eine Signatur, aber nach dem Signieren wurde noch etwas hinzugefuegt - pruefen ob nur Signatur-Material oder echter Inhalt."),
    "single_sig_broken":          ("Signatur GEBROCHEN",      "Die Signatur ist mathematisch gebrochen - signierter Inhalt wurde manipuliert!"),
    "multi_sig_intact":           ("Multi-Signatur (intakt)", "Mehrere Unterzeichner, alle Signaturen kryptografisch intakt - legitim (z.B. e-imza-Workflow)."),
    "multi_sig_broken":           ("Multi-Sig GEBROCHEN",     "Mehrere Signaturen, mindestens eine ist gebrochen - Inhalt nach Signieren manipuliert!"),
    "multi_byterange_no_validated_sig": ("Sig-Status unklar", "Signatur-Strukturen vorhanden, konnten aber nicht validiert werden."),
    "unknown":                    ("Signatur-Status unklar",  "Signatur-Setup konnte nicht eindeutig klassifiziert werden."),
    "error":                      ("Sig-Pruefung fehlgeschlagen", "Bei der Signatur-Pruefung gab es einen technischen Fehler."),
}


def _classify_overall(risk_level: str, manip_score: Optional[float], workflow: Optional[str]) -> dict:
    """Liefert Ampel-Status + Kurztext fuer Sektion 3."""
    # Harte Sig-Brueche immer rot
    if workflow in ("single_sig_broken", "multi_sig_broken"):
        return {
            "color":      "red",
            "icon":       "\U0001F6D1",  # 🛑
            "label":      "VERDAECHTIG - dieser Datei NICHT vertrauen",
            "short":      "Eine kryptografische Signatur ist gebrochen. Das heisst der Inhalt wurde nach der Unterschrift veraendert.",
        }
    if risk_level == "HIGH":
        return {
            "color":      "red",
            "icon":       "\U0001F6D1",  # 🛑
            "label":      "VERDAECHTIG - dieser Datei NICHT vertrauen",
            "short":      "Mehrere unabhaengige Pruefungen liefern ernste Hinweise auf Manipulation oder Schadcode.",
        }
    if risk_level == "MEDIUM":
        return {
            "color":      "amber",
            "icon":       "⚠️",  # ⚠️
            "label":      "MIT VORSICHT - Nachpruefung empfohlen",
            "short":      "Einige Pruefungen sind aufgefallen, aber kein klarer Manipulationsbeweis. Bei wichtigen Entscheidungen das Original vom Absender holen.",
        }
    # LOW, CLEAN, UNKNOWN
    return {
        "color":      "green",
        "icon":       "✅",  # ✅
        "label":      "UNAUFFAELLIG",
        "short":      "Die forensischen Pruefungen haben nichts Wesentliches gefunden. Das ist KEIN Echtheits-Beweis, nur Abwesenheit von Verdacht.",
    }


def _significant_findings(all_anomalies: list, limit: int = 12) -> list:
    """Filtert die Anomalie-Liste fuer einen Anfaenger:
    - INFO + Downgrades raus
    - Pro Kategorie max. 1 Eintrag, das groebste Severity gewinnt
    - Sortiert: HIGH > MEDIUM > LOW
    """
    if not all_anomalies:
        return []
    sev_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    # Nicht-INFO
    non_info = [a for a in all_anomalies if (a.get("severity") if isinstance(a, dict) else a.severity) != "INFO"]
    # Erste pro Kategorie (mit hoechster severity)
    by_cat: dict = {}
    for a in non_info:
        cat = a.get("category") if isinstance(a, dict) else a.category
        sev = a.get("severity") if isinstance(a, dict) else a.severity
        if cat not in by_cat or sev_rank.get(sev, 0) > sev_rank.get(by_cat[cat].get("severity") if isinstance(by_cat[cat], dict) else by_cat[cat].severity, 0):
            by_cat[cat] = a
    flat = list(by_cat.values())
    flat.sort(key=lambda a: -sev_rank.get((a.get("severity") if isinstance(a, dict) else a.severity), 0))
    return flat[:limit]


def _to_dict(obj):
    """AnalysisResult oder Pydantic-Model in dict konvertieren — robust."""
    if obj is None:
        return None
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if hasattr(obj, "dict"):
        return obj.dict()
    if isinstance(obj, dict):
        return obj
    return None


@router.get("/report/layperson/{analysis_id}", response_class=HTMLResponse)
async def layperson_report(
    request: Request,
    analysis_id: str,
    lang: str = Query(default="de", pattern="^(de|en)$"),
):
    """Anfaenger-freundliche HTML-Seite mit 3-Akt-Struktur."""
    result = await get_analysis(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Analyse nicht gefunden.")
    ai_review = await get_ai_review(analysis_id, lang)

    data = _to_dict(result) or {}
    doc_type = (data.get("doc_type") or {}).get("doc_type", "unknown")
    doc_type_reasoning = (data.get("doc_type") or {}).get("reasoning", [])
    workflow = (data.get("signature_workflow") or {}).get("workflow", "unknown")
    workflow_reasoning = (data.get("signature_workflow") or {}).get("reasoning", [])
    signers = [
        s for s in (data.get("signature_workflow") or {}).get("signatures", [])
        if isinstance(s, dict) and s.get("type") == "signature" and s.get("signer_cn")
    ]

    risk_level = data.get("risk_level", "UNKNOWN")
    manip_score = ((data.get("cross_analyzer") or {}).get("manipulation_score"))
    verdict = _classify_overall(risk_level, manip_score, workflow)

    doc_label, doc_explanation = _DOC_TYPE_LABELS.get(doc_type, _DOC_TYPE_LABELS["unknown"])
    wf_label, wf_explanation = _WORKFLOW_LABELS.get(workflow, _WORKFLOW_LABELS["unknown"])

    findings = _significant_findings(data.get("all_anomalies", []), limit=12)

    meta = data.get("metadata") or {}
    swf = data.get("software_fingerprint") or {}

    ctx = {
        "request":        request,
        "analysis_id":    analysis_id,
        "filename":       data.get("filename", "?"),
        "file_size_mb":   round((data.get("file_size_bytes") or 0) / 1024 / 1024, 2),
        "analyzed_at":    data.get("analyzed_at", ""),

        "doc_type_key":   doc_type,
        "doc_type_label": doc_label,
        "doc_type_explanation": doc_explanation,
        "doc_type_reasoning":   doc_type_reasoning,

        "workflow_key":      workflow,
        "workflow_label":    wf_label,
        "workflow_explanation": wf_explanation,
        "workflow_reasoning":   workflow_reasoning,
        "signers":           signers,

        "verdict":      verdict,
        "risk_level":   risk_level,
        "manip_score":  manip_score,
        "high_count":   data.get("anomaly_count_high", 0),
        "medium_count": data.get("anomaly_count_medium", 0),
        "low_count":    data.get("anomaly_count_low", 0),

        "findings":     findings,

        "creator":      meta.get("creator", "") or swf.get("identified_tool", ""),
        "producer":     meta.get("producer", "") or swf.get("producer_raw", ""),
        "author":       meta.get("author", "") or "—",
        "title":        meta.get("title", "") or "—",
        "created":      meta.get("creation_date_parsed", "") or meta.get("creation_date_raw", "") or "—",
        "modified":     meta.get("mod_date_parsed", "") or meta.get("mod_date_raw", "") or "—",
        "page_count":   meta.get("page_count", 0),

        "ai_review":    ai_review,  # kann None sein
    }
    # request raus — wird im manuellen Render nicht gebraucht (kein url_for o.ä.)
    ctx.pop("request", None)
    template = _jinja.get_template("layperson_report.html")
    return HTMLResponse(content=template.render(**ctx))
