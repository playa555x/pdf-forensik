"""
AI-Review Analyzer — Forensische Bewertung per DeepSeek R1 via Featherless API.

Sendet die aggregierten Analyseergebnisse an das KI-Modell und erhält eine
umfassende forensische Einschätzung mit Verdict, Begründung, Empfehlungen,
Dokumenteninhalt-Bewertung und weiterführenden Analyse-Vorschlägen.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict

import httpx

# Featherless API — OpenAI-kompatibel
FEATHERLESS_API_URL = "https://api.featherless.ai/v1/chat/completions"
FEATHERLESS_API_KEY = os.environ.get(
    "FEATHERLESS_API_KEY",
    "rc_40c0f75a22cd80906e5192e5535d211839e7fe12679a4eacd63adaed90503b57",
)
FEATHERLESS_MODEL = "deepseek-ai/DeepSeek-V3-0324"

_SYSTEM_PROMPT_DE = """\
Du bist ein weltweit führender PDF-Forensik-Gutachter und Sachverständiger für digitale Dokumentenprüfung
mit über 20 Jahren Erfahrung in Strafverfolgung, Wirtschaftsprüfung und IT-Sicherheit.

Du erhältst maschinenlesbare Analysedaten eines forensischen PDF/Dokument-Scanners.
Deine Aufgabe ist eine VOLLSTÄNDIGE, PROFESSIONELLE forensische Bewertung auf Deutsch.

Analysiere JEDEN einzelnen Befund im Detail:
1. Was wurde gefunden? (Konkrete Fakten)
2. Was bedeutet das? (Interpretation)
3. Was lässt sich daraus schließen? (Forensische Schlussfolgerung)
4. Wie sollte man sich verhalten? (Handlungsempfehlung)
5. Welche weiteren Tests sind sinnvoll? — NUR Tests die im Prompt explizit als "NOCH NICHT AUSGEFÜHRT" markiert sind, oder externe/manuelle Maßnahmen (z.B. Original anfordern, Notariat, Laboranalyse). NIEMALS Tests vorschlagen die im Abschnitt "BEREITS AUSGEFÜHRTE ANALYZER" aufgelistet sind.

Bewerte auch den INHALT des Dokuments wenn Metadaten darauf schließen lassen
(Autor, Titel, Betreff, Erstellungssoftware, eingebettete Objekte).

Antworte IMMER als valides JSON-Objekt mit EXAKT dieser Struktur:
{
  "verdict": "ECHT" | "VERDÄCHTIG" | "GEFÄLSCHT" | "UNBEKANNT",
  "confidence": 0..100,
  "legitimitaets_score": 0..100,
  "zusammenfassung": "Ausführliche Gesamtbewertung (4-6 Sätze) die auch für Laien verständlich ist",
  "hauptbefunde": [
    {"befund": "Was wurde gefunden", "bedeutung": "Was es bedeutet", "schweregrad": "HOCH|MITTEL|NIEDRIG"}
  ],
  "manipulation_hinweise": [
    {"hinweis": "Konkreter Manipulationshinweis", "erklaerung": "Warum das verdächtig ist", "schweregrad": "HOCH|MITTEL|NIEDRIG"}
  ],
  "was_wurde_gefunden": "Detaillierte Beschreibung aller gefundenen Auffälligkeiten und was genau der Scanner entdeckt hat",
  "was_laesst_sich_erkennen": "Was lässt sich aus den Befunden erkennen — Muster, Zusammenhänge, Auffälligkeiten",
  "was_laesst_sich_schliessen": "Welche forensischen Schlussfolgerungen kann man ziehen",
  "verhaltensempfehlung": "Wie sollte man sich verhalten — konkreter Rat für den Dokumentenempfänger",
  "weitere_tests": [
    {"test": "Name des Tests", "grund": "Warum dieser Test sinnvoll wäre", "prioritaet": "HOCH|MITTEL|NIEDRIG"}
  ],
  "erweiterungsvorschlaege": [
    {"vorschlag": "Was könnte man noch prüfen/erweitern", "beschreibung": "Details"}
  ],
  "dokument_inhalt_bewertung": {
    "dokumenttyp_vermutung": "Was für ein Dokument ist das vermutlich (Rechnung, Vertrag, Zeugnis, etc.)",
    "inhalt_plausibilitaet": "Wie plausibel erscheint der Inhalt basierend auf den Metadaten",
    "autor_bewertung": "Bewertung des Autors/Erstellers",
    "software_bewertung": "Bewertung der verwendeten Software — normal oder ungewöhnlich",
    "zeitstempel_bewertung": "Bewertung der Zeitstempel — konsistent oder verdächtig",
    "auffaelligkeiten": ["Auffälligkeit 1", "Auffälligkeit 2"]
  },
  "empfehlungen": ["Empfehlung 1", "Empfehlung 2"],
  "technische_details": "Ausführliche technische Analyse mit allen relevanten Details",
  "risiko_erklaerung": "Verständliche Erklärung des Risikoniveaus für Laien — warum ist das Dokument sicher/unsicher",
  "fazit": "Abschließendes Fazit: Wie legitim ist das Dokument, wie hoch ist das Fälschungsrisiko, und was sollte als Nächstes passieren",
  "laien_erklaerung": "Erkläre in 3-5 einfachen Sätzen was das Ergebnis bedeutet — als würdest du es jemandem erklären der keinerlei technisches Wissen hat. Keine Fachbegriffe, keine Abkürzungen. Sag klar ob das Dokument verdächtig ist, warum, und was die Person jetzt tun sollte."
}

WICHTIG:
- Sei GRÜNDLICH und DETAILLIERT — dies ist ein professionelles Gutachten
- Nenne KONKRETE Befunde, nicht vage Aussagen
- Bewerte die Legitimität auf einer Skala (legitimitaets_score: 100 = definitiv echt, 0 = definitiv gefälscht)
- Berücksichtige ALLE vorliegenden Daten
- Verwende nur das JSON-Objekt — kein Text/Markdown davor oder danach"""

_SYSTEM_PROMPT_EN = """\
You are a world-leading PDF forensics expert and certified specialist in digital document examination
with over 20 years of experience in law enforcement, auditing, and IT security.

You receive machine-readable analysis data from a forensic PDF/document scanner.
Your task is to provide a COMPLETE, PROFESSIONAL forensic assessment in English.

Analyze EVERY individual finding in detail:
1. What was found? (Concrete facts)
2. What does it mean? (Interpretation)
3. What can be concluded? (Forensic conclusion)
4. What action should be taken? (Recommendation)
5. What further tests are useful? — ONLY tests that are NOT listed in the "ALREADY EXECUTED ANALYZERS" section of the prompt, or external/manual measures (e.g. request original, notary, laboratory analysis). NEVER suggest tests that are listed as already executed.

Also assess the CONTENT of the document when metadata provides clues
(author, title, subject, creation software, embedded objects).

ALWAYS respond as a valid JSON object with EXACTLY this structure:
{
  "verdict": "GENUINE" | "SUSPICIOUS" | "FORGED" | "UNKNOWN",
  "confidence": 0..100,
  "legitimitaets_score": 0..100,
  "zusammenfassung": "Comprehensive overall assessment (4-6 sentences) understandable for non-experts",
  "hauptbefunde": [
    {"befund": "What was found", "bedeutung": "What it means", "schweregrad": "HIGH|MEDIUM|LOW"}
  ],
  "manipulation_hinweise": [
    {"hinweis": "Specific manipulation indicator", "erklaerung": "Why this is suspicious", "schweregrad": "HIGH|MEDIUM|LOW"}
  ],
  "was_wurde_gefunden": "Detailed description of all anomalies found and what the scanner specifically detected",
  "was_laesst_sich_erkennen": "What can be recognized from the findings — patterns, correlations, anomalies",
  "was_laesst_sich_schliessen": "What forensic conclusions can be drawn",
  "verhaltensempfehlung": "What action should be taken — concrete advice for the document recipient",
  "weitere_tests": [
    {"test": "Name of the test", "grund": "Why this test would be useful", "prioritaet": "HIGH|MEDIUM|LOW"}
  ],
  "erweiterungsvorschlaege": [
    {"vorschlag": "What else could be examined/extended", "beschreibung": "Details"}
  ],
  "dokument_inhalt_bewertung": {
    "dokumenttyp_vermutung": "What type of document this likely is (invoice, contract, certificate, etc.)",
    "inhalt_plausibilitaet": "How plausible the content appears based on metadata",
    "autor_bewertung": "Assessment of the author/creator",
    "software_bewertung": "Assessment of the software used — normal or unusual",
    "zeitstempel_bewertung": "Assessment of timestamps — consistent or suspicious",
    "auffaelligkeiten": ["Anomaly 1", "Anomaly 2"]
  },
  "empfehlungen": ["Recommendation 1", "Recommendation 2"],
  "technische_details": "Detailed technical analysis with all relevant details",
  "risiko_erklaerung": "Clear explanation of the risk level for non-experts — why the document is safe/unsafe",
  "fazit": "Final conclusion: How legitimate is the document, how high is the forgery risk, and what should happen next",
  "laien_erklaerung": "Explain in 3-5 simple sentences what the result means — as if explaining to someone with no technical knowledge. No jargon, no abbreviations. Clearly state whether the document is suspicious, why, and what the person should do now."
}

IMPORTANT:
- Be THOROUGH and DETAILED — this is a professional expert report
- State CONCRETE findings, not vague statements
- Rate legitimacy on a scale (legitimitaets_score: 100 = definitely genuine, 0 = definitely forged)
- Consider ALL available data
- Use only the JSON object — no text/markdown before or after"""


def _get_system_prompt(lang: str) -> str:
    return _SYSTEM_PROMPT_EN if lang == "en" else _SYSTEM_PROMPT_DE


def _build_user_prompt(analysis_data: Dict[str, Any], lang: str = "de") -> str:
    """Komprimierte, relevante Analysedaten für den KI-Prompt aufbereiten."""

    # Nur die forensisch relevanten Felder extrahieren
    relevant = {
        "dateiname": analysis_data.get("filename"),
        "dateigröße_bytes": analysis_data.get("file_size_bytes"),
        "risiko_level": analysis_data.get("risk_level"),
        "anomalien_high": analysis_data.get("anomaly_count_high", 0),
        "anomalien_medium": analysis_data.get("anomaly_count_medium", 0),
        "anomalien_low": analysis_data.get("anomaly_count_low", 0),
        "analysiert_am": analysis_data.get("analyzed_at"),
    }

    # Metadaten
    meta = analysis_data.get("metadata", {})
    relevant["metadaten"] = {
        "erstellt": meta.get("creation_date_parsed"),
        "geändert": meta.get("mod_date_parsed"),
        "autor": meta.get("author"),
        "titel": meta.get("title"),
        "betreff": meta.get("subject"),
        "creator": meta.get("creator"),
        "producer": meta.get("producer"),
        "seiten": meta.get("page_count"),
        "pdf_version": meta.get("pdf_version"),
        "anomalien": meta.get("anomalies", []),
    }

    # Alle Anomalien (alle Schweregrade, max. 50)
    all_anomalies = analysis_data.get("all_anomalies", [])
    relevant["alle_anomalien"] = all_anomalies[:50]

    # Software-Fingerprint
    sw = analysis_data.get("software_fingerprint", {})
    relevant["software"] = {
        "tool": sw.get("identified_tool"),
        "kategorie": sw.get("tool_category"),
        "producer_raw": sw.get("producer_raw"),
        "creator_raw": sw.get("creator_raw"),
        "anomalien": sw.get("anomalies", []),
    }

    # Hashes
    hashes = analysis_data.get("hashes", {})
    relevant["hashes"] = {
        "md5": hashes.get("md5"),
        "sha256": hashes.get("sha256"),
    }

    # Signaturen
    sig = analysis_data.get("signature", {})
    relevant["signatur"] = {
        "hat_acroform": sig.get("has_acroform"),
        "hat_sig_feld": sig.get("has_sig_field"),
        "hat_doc_mdp": sig.get("has_doc_mdp"),
        "anomalien": sig.get("anomalies", []),
    }

    # Verschlüsselung
    enc = analysis_data.get("encryption", {})
    relevant["verschlüsselung"] = {
        "ist_verschlüsselt": enc.get("is_encrypted"),
        "algorithmus": enc.get("algorithm"),
        "stärke": enc.get("strength"),
    }

    # Inkrementelle Updates
    inc = analysis_data.get("incremental_updates", {})
    relevant["inkrementelle_updates"] = {
        "revisionen": inc.get("revision_count"),
        "anomalien": inc.get("anomalies", []),
    }

    # JavaScript
    js = analysis_data.get("javascript", {})
    relevant["javascript"] = {
        "hat_javascript": js.get("has_javascript"),
        "auto_execute": js.get("has_auto_execute"),
        "anomalien": js.get("anomalies", []),
    }

    # Shadow Attack
    shadow = analysis_data.get("shadow_attack", {})
    if shadow:
        relevant["shadow_attack"] = {
            "hat_signatur": shadow.get("has_signature"),
            "anomalien": shadow.get("anomalies", []),
        }

    # Hidden Text
    hidden = analysis_data.get("hidden_text", {})
    if hidden:
        relevant["versteckter_text"] = {
            "blöcke": hidden.get("invisible_text_count", 0),
            "weißer_text": hidden.get("white_text_count", 0),
            "anomalien": hidden.get("anomalies", []),
        }

    # IOC Extraktion
    ioc = analysis_data.get("ioc", {})
    if ioc:
        relevant["ioc"] = {
            "urls": ioc.get("urls", [])[:20],
            "verdächtige_iocs": ioc.get("suspicious_iocs", []),
            "anomalien": ioc.get("anomalies", []),
        }

    # Cross-Analyzer
    cross = analysis_data.get("cross_analyzer", {})
    if cross:
        relevant["cross_analyzer"] = {
            "manipulations_score": cross.get("manipulation_score"),
            "korrelationen": cross.get("correlations", [])[:15],
        }

    # YARA
    yara = analysis_data.get("yara", {})
    if yara and yara.get("total_matches", 0) > 0:
        relevant["yara"] = {
            "matches": yara.get("total_matches"),
            "kritisch": yara.get("critical_matches"),
            "hoch": yara.get("high_matches"),
            "regeln": yara.get("matched_rules", [])[:10],
        }

    # Redaction
    redaction = analysis_data.get("redaction", {})
    if redaction and redaction.get("insecure_redactions", 0) > 0:
        relevant["schwärzungen"] = {
            "unsicher": redaction.get("insecure_redactions"),
            "anomalien": redaction.get("anomalies", []),
        }

    # Font-Forensik
    fonts = analysis_data.get("font_forensics", {})
    if fonts:
        relevant["font_forensik"] = {
            "schriften_anzahl": fonts.get("total_fonts", 0),
            "eingebettete_schriften": fonts.get("embedded_count", 0),
            "anomalien": fonts.get("anomalies", []),
        }

    # Seitengeometrie
    geo = analysis_data.get("page_geometry", {})
    if geo:
        relevant["seitengeometrie"] = {
            "format": geo.get("detected_format"),
            "anomalien": geo.get("anomalies", []),
        }

    # Timezone
    tz = analysis_data.get("timezone", {})
    if tz:
        relevant["zeitzonen"] = {
            "erkannt": tz.get("detected_timezone"),
            "anomalien": tz.get("anomalies", []),
        }

    # Author Artifacts
    author = analysis_data.get("author_artifacts", {})
    if author:
        relevant["autor_artefakte"] = {
            "font_prefixes": author.get("font_prefixes", [])[:10],
            "anomalien": author.get("anomalies", []),
        }

    # Eingebettete Dateien
    embedded = analysis_data.get("embedded_files", {})
    if embedded:
        relevant["eingebettete_dateien"] = {
            "anzahl": embedded.get("file_count", 0),
            "dateien": embedded.get("files", [])[:10],
            "anomalien": embedded.get("anomalies", []),
        }

    # UUID Decode
    uuid = analysis_data.get("uuid_decode", {})
    if uuid:
        relevant["uuid_decode"] = {
            "version": uuid.get("version"),
            "timestamp": uuid.get("timestamp_parsed"),
            "anomalien": uuid.get("anomalies", []),
        }

    # Linearization
    lin = analysis_data.get("linearization", {})
    if lin:
        relevant["linearisierung"] = {
            "ist_linearisiert": lin.get("is_linearized"),
            "anomalien": lin.get("anomalies", []),
        }

    # XRef Validation
    xref = analysis_data.get("xref_validation", {})
    if xref:
        relevant["xref"] = {
            "anomalien": xref.get("anomalies", []),
        }

    # Printer Forensics
    printer = analysis_data.get("printer_forensics", {})
    if printer:
        relevant["drucker_forensik"] = {
            "anomalien": printer.get("anomalies", []),
        }

    # ELA
    ela = analysis_data.get("ela", {})
    if ela:
        relevant["fehlerpegelanalyse"] = {
            "anomalien": ela.get("anomalies", []),
        }

    # Welche Analyzer wurden bereits ausgeführt?
    _ANALYZER_LABELS_DE = {
        "metadata":            "Metadaten-Analyse (Autor, Datum, Software, PDF-Version)",
        "software_fingerprint":"Software-Fingerprinting (Erstellungsprogramm)",
        "signature":           "Digitale Signatur & AcroForm",
        "encryption":          "Verschlüsselungs-Analyse",
        "incremental_updates": "Inkrementelle Updates / Revisions-Analyse",
        "javascript":          "JavaScript & Action-Analyse (OpenAction, Launch, JS-Code)",
        "embedded_files":      "Eingebettete Dateien",
        "uuid_decode":         "UUID-Zeitstempel-Dekodierung",
        "timezone":            "Zeitzonenkonsistenz",
        "page_geometry":       "Seitengeometrie & Formatanalyse",
        "page_labels":         "PageLabels / Seitennummern-Konsistenz",
        "jpeg_analyzer":       "JPEG-Forensik (Double-Compression, JPEG-Ghosts, Qualitätsstufen)",
        "jpeg_extractor":      "JPEG-Extraktion & Bildanalyse",
        "deep_jpeg":           "Deep-JPEG-Forensik (Double-Compression, JPEG-Ghosts, DCT-Analyse)",
        "ela":                 "Error Level Analysis (ELA) — Bildmanipulations-Detektion",
        "image_forensics":     "Bild-Forensik (EXIF, Kamera-Metadaten, Steganografie-Check)",
        "steganography":       "Steganografie-Erkennung",
        "hidden_text":         "Versteckter / unsichtbarer Text",
        "object_streams":      "Object-Stream-Analyse",
        "xref_validation":     "XRef-Tabellen-Validierung",
        "content_stream":      "Content-Stream-Dekompression & Analyse",
        "residual_objects":    "Residual-Objekte / verwaiste PDF-Objekte",
        "shadow_attack":       "Shadow-Attack-Detektion",
        "ioc":                 "IOC-Extraktion (URLs, IPs, verdächtige Inhalte)",
        "yara":                "YARA-Regel-Scan (Malware-Signaturen)",
        "font_forensics":      "Font-Forensik (Schriften, Einbettung, Prefixes)",
        "author_artifacts":    "Autor-Artefakte (Font-Prefixes, Geräte-Signaturen)",
        "pdfa_compliance":     "PDF/A-Konformität",
        "linearization":       "Linearisierungs-Check (Fast Web View)",
        "printer_forensics":   "Drucker-Forensik (Yellow Dots, MIC-Muster)",
        "yellow_dots":         "Yellow Dots / Machine Identification Code (MIC)",
        "redaction":           "Schwärzungs-Analyse (Redaction-Check)",
        "fuzzy_hash":          "Fuzzy-Hash (ssdeep) — Ähnlichkeitsvergleich",
        "cross_analyzer":      "Cross-Analyzer-Korrelation (Befunde übergreifend verknüpft)",
        "chain_of_custody":    "Chain-of-Custody-Tracking",
        "cross_doc_fingerprint":"Cross-Document-Fingerprinting (Dokument-Vergleich DB)",
        "virus_scan":          "Virusscan (ClamAV / VirusTotal)",
        "ocg_layers":          "OCG-Layer-Analyse (Optional Content Groups)",
        "incremental_diff":    "Inkrementeller Diff (was hat sich zwischen Revisionen geändert)",
        "object_graph":        "Objekt-Graph-Analyse",
        "visual_render":       "Visuelles Rendering (Screenshot-Vergleich)",
        "icc_profiles":        "ICC-Farbprofil-Analyse",
    }
    _ANALYZER_LABELS_EN = {
        "metadata":            "Metadata analysis (author, dates, software, PDF version)",
        "software_fingerprint":"Software fingerprinting (creation tool)",
        "signature":           "Digital signature & AcroForm",
        "encryption":          "Encryption analysis",
        "incremental_updates": "Incremental updates / revision analysis",
        "javascript":          "JavaScript & action analysis (OpenAction, Launch, JS code)",
        "embedded_files":      "Embedded files",
        "uuid_decode":         "UUID timestamp decoding",
        "timezone":            "Timezone consistency",
        "page_geometry":       "Page geometry & format analysis",
        "page_labels":         "PageLabels / page number consistency",
        "jpeg_analyzer":       "JPEG forensics (double-compression, JPEG ghosts, quality levels)",
        "jpeg_extractor":      "JPEG extraction & image analysis",
        "deep_jpeg":           "Deep JPEG forensics (double-compression, JPEG ghosts, DCT analysis)",
        "ela":                 "Error Level Analysis (ELA) — image manipulation detection",
        "image_forensics":     "Image forensics (EXIF, camera metadata, steganography check)",
        "steganography":       "Steganography detection",
        "hidden_text":         "Hidden / invisible text",
        "object_streams":      "Object stream analysis",
        "xref_validation":     "XRef table validation",
        "content_stream":      "Content stream decompression & analysis",
        "residual_objects":    "Residual objects / orphaned PDF objects",
        "shadow_attack":       "Shadow attack detection",
        "ioc":                 "IOC extraction (URLs, IPs, suspicious content)",
        "yara":                "YARA rule scan (malware signatures)",
        "font_forensics":      "Font forensics (fonts, embedding, prefixes)",
        "author_artifacts":    "Author artifacts (font prefixes, device signatures)",
        "pdfa_compliance":     "PDF/A compliance",
        "linearization":       "Linearization check (fast web view)",
        "printer_forensics":   "Printer forensics (yellow dots, MIC patterns)",
        "yellow_dots":         "Yellow dots / Machine Identification Code (MIC)",
        "redaction":           "Redaction analysis",
        "fuzzy_hash":          "Fuzzy hash (ssdeep) — similarity comparison",
        "cross_analyzer":      "Cross-analyzer correlation (findings linked across modules)",
        "chain_of_custody":    "Chain of custody tracking",
        "cross_doc_fingerprint":"Cross-document fingerprinting (database comparison)",
        "virus_scan":          "Virus scan (ClamAV / VirusTotal)",
        "ocg_layers":          "OCG layer analysis (optional content groups)",
        "incremental_diff":    "Incremental diff (what changed between revisions)",
        "object_graph":        "Object graph analysis",
        "visual_render":       "Visual rendering (screenshot comparison)",
        "icc_profiles":        "ICC color profile analysis",
    }

    labels = _ANALYZER_LABELS_EN if lang == "en" else _ANALYZER_LABELS_DE
    already_run = []
    for key, label in labels.items():
        if analysis_data.get(key) is not None:
            already_run.append(f"✓ {label}")

    if lang == "en":
        already_block = (
            "\n\nALREADY EXECUTED ANALYZERS (do NOT suggest these as further tests — they were already run):\n"
            + "\n".join(already_run)
            + "\n\nOnly suggest tests that are NOT in this list above, or external/manual tests "
            "that go beyond what an automated scanner can do."
        )
        prompt = (
            "Forensic analysis data of the document:\n\n"
            + json.dumps(relevant, ensure_ascii=False, indent=2)
            + already_block
            + "\n\nProvide a COMPLETE forensic assessment as JSON. "
            "Analyze EVERY finding individually. Assess the legitimacy of the document. "
            "Only suggest further tests that have NOT already been run. "
            "Also assess the suspected content of the document."
        )
    else:
        already_block = (
            "\n\nBEREITS AUSGEFÜHRTE ANALYZER (schlage diese NICHT als weitere Tests vor — sie wurden bereits durchgeführt):\n"
            + "\n".join(already_run)
            + "\n\nSchlage nur Tests vor die NICHT in dieser Liste stehen, oder externe/manuelle Tests "
            "die über das hinausgehen was ein automatisierter Scanner leisten kann."
        )
        prompt = (
            "Forensische Analysedaten des Dokuments:\n\n"
            + json.dumps(relevant, ensure_ascii=False, indent=2)
            + already_block
            + "\n\nErstelle eine VOLLSTÄNDIGE forensische Bewertung als JSON. "
            "Analysiere JEDEN Befund einzeln. Bewerte die Legitimität des Dokuments. "
            "Schlage NUR weiterführende Tests vor die NOCH NICHT ausgeführt wurden. "
            "Bewerte auch den vermuteten Inhalt des Dokuments."
        )
    return prompt


def _extract_json_from_response(content: str) -> dict:
    """Extrahiert JSON aus der KI-Antwort, auch wenn sie in Markdown-Blöcken steht."""
    # Erst versuchen direkt zu parsen
    content = content.strip()

    # DeepSeek R1 kann <think>...</think> Tags haben — entfernen
    content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()

    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    # Markdown-JSON-Block extrahieren
    match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", content, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1).strip())
        except json.JSONDecodeError:
            pass

    # Letzter Versuch: erstes { bis letztes } extrahieren
    start = content.find("{")
    end = content.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(content[start : end + 1])
        except json.JSONDecodeError:
            pass

    raise json.JSONDecodeError("Kein valides JSON in der Antwort gefunden", content, 0)


async def run_ai_review(analysis_data: Dict[str, Any], lang: str = "de") -> Dict[str, Any]:
    """
    Sendet Analysedaten an Featherless/DeepSeek R1 und gibt strukturiertes Review zurück.

    Returns:
        Dict mit keys: verdict, confidence, zusammenfassung, hauptbefunde,
                       manipulation_hinweise, empfehlungen, technische_details,
                       risiko_erklaerung, weitere_tests, dokument_inhalt_bewertung,
                       model, error (nur bei Fehler)
    """
    if not FEATHERLESS_API_KEY:
        return {"error": "Kein FEATHERLESS_API_KEY konfiguriert.", "available": False}

    user_prompt = _build_user_prompt(analysis_data, lang=lang)

    headers = {
        "Authorization": f"Bearer {FEATHERLESS_API_KEY}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": FEATHERLESS_MODEL,
        "messages": [
            {"role": "system", "content": _get_system_prompt(lang)},
            {"role": "user", "content": user_prompt},
        ],
        "max_tokens": 8192,
        "temperature": 0.3,
    }

    content = ""
    max_retries = 3
    last_error = ""

    for attempt in range(max_retries):
        try:
            async with httpx.AsyncClient(timeout=300.0) as client:
                response = await client.post(
                    FEATHERLESS_API_URL, headers=headers, json=payload
                )

                # Bei 429 (Rate-Limit) warten und retry
                if response.status_code == 429 and attempt < max_retries - 1:
                    import asyncio
                    wait = 10 * (attempt + 1)
                    await asyncio.sleep(wait)
                    continue

                response.raise_for_status()

            data = response.json()
            content = data["choices"][0]["message"]["content"]

            # JSON aus Antwort parsen (robust gegen Markdown-Blöcke und <think>-Tags)
            review = _extract_json_from_response(content)
            review["model"] = FEATHERLESS_MODEL
            review["available"] = True
            return review

        except httpx.HTTPStatusError as e:
            last_error = f"API-Fehler {e.response.status_code}: {e.response.text[:500]}"
            if e.response.status_code == 429 and attempt < max_retries - 1:
                import asyncio
                await asyncio.sleep(10 * (attempt + 1))
                continue
            return {"error": last_error, "available": False}
        except json.JSONDecodeError as e:
            return {
                "error": f"KI-Antwort konnte nicht als JSON geparst werden: {e}",
                "raw_response": content[:2000] if content else "",
                "available": False,
            }
        except Exception as e:
            last_error = str(e)
            if attempt < max_retries - 1:
                import asyncio
                await asyncio.sleep(5)
                continue
            return {
                "error": f"Unerwarteter Fehler: {last_error}",
                "available": False,
            }

    return {"error": f"Alle {max_retries} Versuche fehlgeschlagen: {last_error}", "available": False}
