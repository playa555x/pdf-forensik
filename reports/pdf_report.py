"""
PDF-Bericht-Generierung — Playwright Chromium (HTML→PDF).
Vollständig zweisprachig (DE/EN), professionelles Dark-Theme Design
mit eingebetteten SVG-Charts und ELA-Beweisbildern.
"""
from __future__ import annotations
import math
import traceback
from pathlib import Path
from datetime import datetime
from typing import Optional, Any, List

from jinja2 import Environment, FileSystemLoader
from markupsafe import Markup

from models.schemas import AnalysisResult, CompareResult, AnomalySeverity, RiskLevel
from config import REPORTS_DIR
from reports.svg_charts import (
    svg_risk_gauge,
    svg_radar_chart,
    svg_donut_chart,
    svg_timeline,
    svg_analyzer_grid,
    svg_horizontal_bar,
)

# ─── Playwright HTML→PDF ──────────────────────────────────────────────────────

def _html_to_pdf_playwright(html_str: str, out_path: Path) -> None:
    """Rendert HTML zu PDF via Playwright Chromium.
    Läuft in einem separaten Thread mit eigenem asyncio-Loop,
    damit es auch innerhalb von FastAPI (asyncio) funktioniert.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise RuntimeError(
            "Playwright ist nicht installiert. Bitte ausführen:\n"
            "  pip install playwright\n"
            "  playwright install chromium"
        )

    import threading

    exc_holder = []

    def _run():
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch()
                page = browser.new_page()
                page.set_content(html_str, wait_until="networkidle")
                page.pdf(
                    path=str(out_path),
                    format="A4",
                    print_background=True,
                    margin={"top": "0mm", "bottom": "0mm", "left": "0mm", "right": "0mm"},
                )
                browser.close()
        except Exception as e:
            exc_holder.append(e)

    t = threading.Thread(target=_run)
    t.start()
    t.join(timeout=120)

    if t.is_alive():
        raise RuntimeError("PDF-Generierung Timeout (>120s)")
    if exc_holder:
        raise exc_holder[0]


# ─── Templates-Verzeichnis ────────────────────────────────────────────────────
_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"

# ─── Übersetzungen (KOMPLETT DE + EN — kein Key darf fehlen!) ────────────────
_T: dict[str, dict[str, str]] = {
    # ── Allgemein ──
    "report_title":       {"de": "Forensischer Analysebericht", "en": "Forensic Analysis Report"},
    "report_subtitle":    {"de": "Detaillierter PDF-Untersuchungsbericht", "en": "Detailed PDF Examination Report"},
    "confidential":       {"de": "VERTRAULICH — Nur für autorisierte Empfänger", "en": "CONFIDENTIAL — Authorized recipients only"},
    "page_footer":        {"de": "PDF Forensik Analyzer — Vertraulicher Analysebericht", "en": "PDF Forensics Analyzer — Confidential Report"},
    "generated":          {"de": "Erstellt am", "en": "Generated on"},
    "no_data":            {"de": "Keine Daten verfügbar.", "en": "No data available."},
    "yes":                {"de": "Ja", "en": "Yes"},
    "no":                 {"de": "Nein", "en": "No"},
    "page":               {"de": "Seite", "en": "Page"},
    "file":               {"de": "Datei", "en": "File"},
    "analyzed_at":        {"de": "Analysiert am", "en": "Analyzed at"},
    "format":             {"de": "Format", "en": "Format"},
    "analysis_id":        {"de": "Analyse-ID", "en": "Analysis ID"},
    "file_size":          {"de": "Dateigröße", "en": "File size"},
    "anomaly_overview":   {"de": "Anomalie-Übersicht", "en": "Anomaly Overview"},
    "complete_anomalies": {"de": "Vollständige Anomalie-Übersicht", "en": "Complete Anomaly Overview"},
    "total":              {"de": "Gesamt", "en": "Total"},
    "risk_label":         {"de": "RISIKO", "en": "RISK"},
    "found":              {"de": "Gefunden", "en": "Found"},
    "not_found":          {"de": "Nicht gefunden", "en": "Not found"},
    "count":              {"de": "Anzahl", "en": "Count"},
    "source":             {"de": "Quelle", "en": "Source"},
    "severity_col":       {"de": "Schwere", "en": "Severity"},
    "category_col":       {"de": "Kategorie", "en": "Category"},
    "message_col":        {"de": "Meldung", "en": "Message"},
    "size_col":           {"de": "Größe", "en": "Size"},
    "status_col":         {"de": "Status", "en": "Status"},
    "name_col":           {"de": "Name", "en": "Name"},
    "type_col":           {"de": "Typ", "en": "Type"},
    "value_col":          {"de": "Wert", "en": "Value"},

    # ── Executive Summary ──
    "exec_summary":       {"de": "Executive Summary", "en": "Executive Summary"},
    "exec_critical":      {"de": "Kritische Befunde (HIGH)", "en": "Critical Findings (HIGH)"},
    "exec_medium":        {"de": "Wichtige Befunde (MEDIUM)", "en": "Important Findings (MEDIUM)"},
    "exec_clean":         {
        "de": "Keine kritischen Anomalien gefunden. Das Dokument erscheint forensisch unauffällig.",
        "en": "No critical anomalies found. The document appears forensically clean."
    },
    "exec_analyzer_grid": {"de": "Analyzer-Übersicht", "en": "Analyzer Overview"},
    "exec_expl": {
        "de": "Diese Zusammenfassung zeigt auf einen Blick ob das PDF forensisch auffällig ist. Jeder Analyzer prüft einen spezifischen Aspekt — von Metadaten über Signaturen bis hin zu versteckten Inhalten. Grün = unauffällig, Rot = kritischer Befund der näherer Prüfung bedarf.",
        "en": "This summary shows at a glance whether the PDF is forensically suspicious. Each analyzer checks a specific aspect — from metadata and signatures to hidden content. Green = no issues, Red = critical finding requiring closer inspection.",
    },

    # ── Hashes ──
    "sec_hashes":         {"de": "Kryptografische Hashes", "en": "Cryptographic Hashes"},
    "hash_expl": {
        "de": "Kryptografische Hashwerte identifizieren ein Dokument eindeutig. Jede noch so kleine Änderung am Dateiinhalt erzeugt einen völlig anderen Hash. Durch Vergleich mit einem bekannten Referenzwert lässt sich Manipulation zweifelsfrei beweisen oder ausschließen.",
        "en": "Cryptographic hash values uniquely identify a document. Even the smallest change to the file content produces a completely different hash. By comparing with a known reference value, manipulation can be proven or excluded beyond doubt.",
    },
    "hash_good": {
        "de": "Unverändertes Dokument: SHA-256 des erhaltenen Dokuments stimmt mit dem vom Absender mitgeteilten Hash überein — kein Byte wurde geändert.",
        "en": "Unmodified document: SHA-256 of the received document matches the hash provided by the sender — not a single byte was changed.",
    },
    "hash_bad": {
        "de": "Manipuliertes Dokument: Hash weicht vom Referenzwert ab. Der Inhalt wurde nach der Erstellung verändert — z. B. Betrag, Name oder Datum ersetzt.",
        "en": "Tampered document: Hash differs from the reference value. The content was altered after creation — e.g. amount, name or date replaced.",
    },

    # ── Metadaten ──
    "sec_metadata":       {"de": "PDF-Metadaten", "en": "PDF Metadata"},
    "meta_expl": {
        "de": "PDF-Metadaten enthalten Informationen über Autor, Erstellsoftware, Erstelldatum und Änderungsdatum. Diese Felder lassen sich manuell ändern. Widersprüche — z. B. Erstelldatum liegt nach dem Änderungsdatum, oder der angegebene Producer passt nicht zur Software — sind starke Hinweise auf nachträgliche Manipulation.",
        "en": "PDF metadata contains information about the author, creation software, creation date and modification date. These fields can be manually altered. Contradictions — e.g. creation date is later than modification date, or the stated producer doesn't match the software — are strong indicators of subsequent manipulation.",
    },
    "meta_good": {
        "de": "Konsistente Daten: Creator = 'Microsoft Word 16', Producer = 'Microsoft Word 16', Erstelldatum < Änderungsdatum — alle Felder stimmen mit einer legitimen Bürodokument-Erstellung überein.",
        "en": "Consistent data: Creator = 'Microsoft Word 16', Producer = 'Microsoft Word 16', creation date < modification date — all fields match a legitimate office document creation.",
    },
    "meta_bad": {
        "de": "Widersprüchliche Daten: Erstelldatum 15.03.2024, Änderungsdatum 10.03.2024 (unmöglich). Producer = 'iText 5 (Java)', obwohl angeblich aus Word exportiert — deutet auf nachträgliche Bearbeitung mit einem PDF-Toolkit hin.",
        "en": "Contradictory data: Creation date 15.03.2024, modification date 10.03.2024 (impossible). Producer = 'iText 5 (Java)' although supposedly exported from Word — indicates post-processing with a PDF toolkit.",
    },
    "lbl_title":          {"de": "Titel", "en": "Title"},
    "lbl_author":         {"de": "Autor", "en": "Author"},
    "lbl_subject":        {"de": "Betreff", "en": "Subject"},
    "lbl_keywords":       {"de": "Schlüsselwörter", "en": "Keywords"},
    "lbl_creator":        {"de": "Creator", "en": "Creator"},
    "lbl_producer":       {"de": "Producer", "en": "Producer"},
    "lbl_created":        {"de": "Erstellt", "en": "Created"},
    "lbl_modified":       {"de": "Geändert", "en": "Modified"},
    "lbl_pdf_version":    {"de": "PDF-Version", "en": "PDF Version"},
    "lbl_pages":          {"de": "Seitenanzahl", "en": "Page count"},

    # ── Software ──
    "sec_software":       {"de": "Software-Fingerprint", "en": "Software Fingerprint"},
    "sw_expl": {
        "de": "Der Software-Fingerprint verrät, welche Anwendung das PDF ursprünglich erzeugt hat. Die Felder 'Creator' und 'Producer' hinterlassen charakteristische Spuren. Stimmt die identifizierte Software nicht mit der angegebenen Herkunft des Dokuments überein (z. B. angeblich aus Word, aber mit Python-Bibliothek erstellt), ist Manipulation wahrscheinlich.",
        "en": "The software fingerprint reveals which application originally created the PDF. The 'Creator' and 'Producer' fields leave characteristic traces. If the identified software doesn't match the stated origin of the document (e.g. supposedly from Word but created with a Python library), manipulation is likely.",
    },
    "sw_good": {
        "de": "Konsistent: Producer = 'Microsoft Word for Microsoft 365', Creator = 'Microsoft Word' — das Dokument wurde mit gängiger Office-Software erzeugt, keine Anzeichen nachträglicher Bearbeitung.",
        "en": "Consistent: Producer = 'Microsoft Word for Microsoft 365', Creator = 'Microsoft Word' — the document was created with standard office software, no signs of post-processing.",
    },
    "sw_bad": {
        "de": "Widersprüchlich: Angeblich als Word-Dokument versendet, aber Producer = 'iText 7.1.9 (Java)' — deutet auf nachträgliche Erstellung oder Manipulation mit einem Java-PDF-Toolkit hin.",
        "en": "Contradictory: Allegedly sent as a Word document, but Producer = 'iText 7.1.9 (Java)' — indicates subsequent creation or manipulation with a Java PDF toolkit.",
    },
    "lbl_tool":           {"de": "Identifiziertes Tool", "en": "Identified Tool"},
    "lbl_category":       {"de": "Kategorie", "en": "Category"},
    "lbl_version":        {"de": "Version", "en": "Version"},
    "lbl_producer_raw":   {"de": "Producer (roh)", "en": "Producer (raw)"},
    "lbl_creator_raw":    {"de": "Creator (roh)", "en": "Creator (raw)"},

    # ── Signaturen ──
    "sec_signatures":     {"de": "Digitale Signaturen & Shadow-Attack", "en": "Digital Signatures & Shadow Attack"},
    "sig_expl": {
        "de": "Digitale Signaturen sollen die Unversehrtheit und Herkunft eines Dokuments garantieren. Der Shadow-Attack ist eine bekannte Angriffsmethode: Das Dokument erscheint in PDF-Viewern als signiert und gültig, zeigt aber einen anderen Inhalt als zum Zeitpunkt der Signierung — weil nach der Signatur neue Inhalte eingefügt wurden, die den signierten Bereich überlagern.",
        "en": "Digital signatures are intended to guarantee the integrity and origin of a document. The Shadow Attack is a known attack method: The document appears as signed and valid in PDF viewers, but shows different content than at the time of signing — because new content was inserted after the signature that overlays the signed area.",
    },
    "sig_good": {
        "de": "Signatur vorhanden, keine Bytes nach der Signatur, kein neuer XRef-Abschnitt nach der Signatur — das Dokument wurde seit der Signierung nicht verändert.",
        "en": "Signature present, no bytes after the signature, no new XRef section after the signature — the document has not been modified since signing.",
    },
    "sig_bad": {
        "de": "Bytes nach der Signatur (123.456 Bytes) + neuer XRef-Abschnitt: klassisches Shadow-Attack-Muster. Der angezeigte Inhalt (z. B. Betrag 9.999 €) kann vom signierten Inhalt (z. B. 99 €) abweichen.",
        "en": "Bytes after the signature (123,456 bytes) + new XRef section: classic Shadow Attack pattern. The displayed content (e.g. amount €9,999) may differ from the signed content (e.g. €99).",
    },
    "lbl_acroform":       {"de": "AcroForm vorhanden", "en": "AcroForm present"},
    "lbl_sig_field":      {"de": "Signaturfeld vorhanden", "en": "Signature field present"},
    "lbl_doc_mdp":        {"de": "DocMDP (Certified)", "en": "DocMDP (Certified)"},
    "lbl_sig_names":      {"de": "Sig-Feldnamen", "en": "Sig field names"},
    "lbl_shadow_analysis":{"de": "Shadow-Attack-Analyse", "en": "Shadow Attack Analysis"},
    "lbl_sig_count":      {"de": "Signaturen erkannt", "en": "Signatures detected"},
    "lbl_isa_entries":    {"de": "ISA-Einträge", "en": "ISA entries"},
    "no_sig":             {
        "de": "Keine digitale Signatur gefunden. Das Dokument enthält kein Signaturfeld — eine nachträgliche Manipulation kann nicht über Signaturprüfung ausgeschlossen werden.",
        "en": "No digital signature found. The document contains no signature field — subsequent manipulation cannot be ruled out via signature verification.",
    },
    "col_sig_idx":        {"de": "#", "en": "#"},
    "col_bytes_after":    {"de": "Bytes nach Sig", "en": "Bytes after Sig"},
    "col_xref_after":     {"de": "XRef danach", "en": "XRef after"},
    "col_doc_end":        {"de": "Doc-End Offset", "en": "Doc-End Offset"},

    # ── UUID ──
    "sec_uuid":           {"de": "UUID-Analyse", "en": "UUID Analysis"},
    "uuid_expl": {
        "de": "UUID v1 (Universal Unique Identifier, Version 1) enthalten einen genauen Zeitstempel und eine MAC-Adresse des Computers. Microsoft Office bettet solche UUIDs beim Speichern ein. Der dekodierte Zeitstempel kann mit dem Erstelldatum in den Metadaten verglichen werden — eine Abweichung von mehr als einigen Minuten ist ein starkes Indiz dafür, dass die Metadaten nachträglich geändert wurden.",
        "en": "UUID v1 (Universal Unique Identifier, Version 1) contain a precise timestamp and a MAC address of the computer. Microsoft Office embeds such UUIDs when saving. The decoded timestamp can be compared with the creation date in the metadata — a deviation of more than a few minutes is a strong indicator that the metadata was subsequently altered.",
    },
    "uuid_good": {
        "de": "UUID-Zeitstempel stimmt mit Erstelldatum überein (Abweichung < 60 Sekunden) — konsistente Zeitangaben, kein Hinweis auf Manipulation.",
        "en": "UUID timestamp matches creation date (deviation < 60 seconds) — consistent timestamps, no indication of manipulation.",
    },
    "uuid_bad": {
        "de": "UUID-Zeitstempel weicht 2 Tage vom angegebenen Erstelldatum ab — die Metadaten wurden sehr wahrscheinlich nachträglich geändert, um ein früheres Datum vorzutäuschen.",
        "en": "UUID timestamp deviates 2 days from the stated creation date — the metadata was very likely subsequently altered to fake an earlier date.",
    },
    "lbl_found_uuids":    {"de": "Gefundene UUIDs", "en": "Found UUIDs"},
    "lbl_decoded":        {"de": "Dekodierte UUIDs", "en": "Decoded UUIDs"},
    "no_uuid":            {
        "de": "Keine UUID v1 gefunden. UUID v1 werden typischerweise von Microsoft Office generiert. Dokumente aus anderen Quellen (z. B. LaTeX, LibreOffice) enthalten oft keine UUIDs.",
        "en": "No UUID v1 found. UUID v1 are typically generated by Microsoft Office. Documents from other sources (e.g. LaTeX, LibreOffice) often contain no UUIDs.",
    },
    "col_uuid":           {"de": "UUID (gekürzt)", "en": "UUID (shortened)"},
    "col_timestamp":      {"de": "Zeitstempel (UTC)", "en": "Timestamp (UTC)"},
    "col_delta":          {"de": "Δ zum Erstelldatum", "en": "Δ to creation date"},

    # ── Timezone ──
    "sec_timezone":       {"de": "Timezone-Analyse", "en": "Timezone Analysis"},
    "tz_expl": {
        "de": "Die Zeitzone, in der ein Dokument erstellt wurde, hinterlässt Spuren in den Datumsstempeln der PDF-Metadaten (z. B. '+01:00' für Mitteleuropa). Inkonsistente Offsets zwischen Erstelldatum und Änderungsdatum können darauf hinweisen, dass das Dokument in einem anderen Land bearbeitet wurde — oder dass Zeitstempel manuell geändert wurden.",
        "en": "The timezone in which a document was created leaves traces in the date stamps of PDF metadata (e.g. '+01:00' for Central Europe). Inconsistent offsets between creation date and modification date may indicate that the document was edited in a different country — or that timestamps were manually altered.",
    },
    "tz_good": {
        "de": "Alle Zeitstempel konsistent in UTC+1 (Mitteleuropa) — geografisch und zeitlich stimmig, kein Hinweis auf Manipulation.",
        "en": "All timestamps consistently in UTC+1 (Central Europe) — geographically and temporally consistent, no indication of manipulation.",
    },
    "tz_bad": {
        "de": "Erstelldatum mit Offset UTC+8 (Asien/China), Änderungsdatum UTC+1 (Europa) — deutet auf Bearbeitung in einer anderen Region hin, oder auf manuelle Änderung des Zeitstempels.",
        "en": "Creation date with offset UTC+8 (Asia/China), modification date UTC+1 (Europe) — indicates editing in a different region, or manual alteration of the timestamp.",
    },
    "lbl_region_hint":    {"de": "Region-Hinweis", "en": "Region hint"},
    "lbl_tz_consistent":  {"de": "Offsets konsistent", "en": "Offsets consistent"},
    "lbl_unique_offsets": {"de": "Gefundene Offsets", "en": "Found offsets"},
    "lbl_date_fields":    {"de": "Analysierte Datumsfelder", "en": "Analyzed date fields"},

    # ── Author Artifacts ──
    "sec_author":         {"de": "Autor-Artefakte", "en": "Author Artifacts"},
    "author_expl": {
        "de": "Microsoft Office bettet beim Exportieren als PDF charakteristische Font-Präfixe ein, die aus den ersten 6 Zeichen einer zufälligen UUID bestehen. Dokumente, die von demselben Autor in derselben Word-Sitzung erstellt wurden, teilen dieselben Font-Präfixe. Außerdem können lokale Dateipfade, Benutzernamen und E-Mail-Adressen aus den OLE-Metadaten extrahiert werden.",
        "en": "Microsoft Office embeds characteristic font prefixes when exporting as PDF, consisting of the first 6 characters of a random UUID. Documents created by the same author in the same Word session share the same font prefixes. Additionally, local file paths, usernames and email addresses can be extracted from the OLE metadata.",
    },
    "author_good": {
        "de": "Font-Präfixe sind zufällig und einzigartig — kein Bezug zu anderen Dokumenten im System, kein Hinweis auf gemeinsamen Ursprung.",
        "en": "Font prefixes are random and unique — no relation to other documents in the system, no indication of common origin.",
    },
    "author_bad": {
        "de": "Font-Präfix 'ABCDEF' taucht in 3 anderen Dokumenten auf, die angeblich von verschiedenen Personen stammen — alle wurden in derselben Word-Sitzung vom selben Gerät erstellt.",
        "en": "Font prefix 'ABCDEF' appears in 3 other documents allegedly from different people — all were created in the same Word session on the same device.",
    },
    "lbl_font_prefixes":  {"de": "Font-Präfixe", "en": "Font prefixes"},
    "lbl_artifacts":      {"de": "Alle Artefakte", "en": "All artifacts"},

    # ── Encryption ──
    "sec_encryption":     {"de": "Verschlüsselung", "en": "Encryption"},
    "enc_expl": {
        "de": "PDF-Verschlüsselung schützt den Inhalt eines Dokuments. Wichtig für die forensische Analyse ist nicht nur ob, sondern wie ein Dokument verschlüsselt ist: Schwache Verschlüsselung (RC4, kurze Schlüssel) kann gebrochen werden. Ein nachträglich entschlüsseltes und neu verschlüsseltes Dokument zeigt in der Regel andere Metadaten als das Original.",
        "en": "PDF encryption protects the content of a document. Important for forensic analysis is not just whether, but how a document is encrypted: Weak encryption (RC4, short keys) can be broken. A subsequently decrypted and re-encrypted document typically shows different metadata than the original.",
    },
    "enc_good": {
        "de": "Keine Verschlüsselung — das Dokument ist offen lesbar, alle Inhalte können vollständig analysiert werden.",
        "en": "No encryption — the document is openly readable, all contents can be fully analyzed.",
    },
    "enc_bad": {
        "de": "RC4-Verschlüsselung mit 40-Bit-Schlüssel (veraltet, nicht sicher) — Inhalt kann mit bekannten Tools entschlüsselt werden. Oder: AES-256 Verschlüsselung verhindert vollständige Analyse.",
        "en": "RC4 encryption with 40-bit key (outdated, not secure) — content can be decrypted with known tools. Or: AES-256 encryption prevents complete analysis.",
    },
    "lbl_encrypted":      {"de": "Verschlüsselt", "en": "Encrypted"},
    "lbl_enc_method":     {"de": "Methode", "en": "Method"},
    "lbl_key_length":     {"de": "Schlüssellänge", "en": "Key length"},

    # ── Incremental Updates ──
    "sec_incremental":    {"de": "Inkrementelle Updates", "en": "Incremental Updates"},
    "incr_expl": {
        "de": "Das PDF-Format erlaubt es, Änderungen am Ende einer Datei anzuhängen, ohne den ursprünglichen Inhalt zu überschreiben (inkrementelle Updates). Legitim wird dies z. B. beim Ausfüllen von Formularen genutzt. Forensisch bedeutsam ist es, wenn nach einer digitalen Signatur noch Inhalte hinzugefügt wurden — das ist das Grundprinzip des Shadow-Attacks.",
        "en": "The PDF format allows changes to be appended to the end of a file without overwriting the original content (incremental updates). This is legitimately used e.g. when filling in forms. Forensically significant is when content was added after a digital signature — this is the fundamental principle of the Shadow Attack.",
    },
    "incr_good": {
        "de": "Keine inkrementellen Updates — das Dokument wurde seit der Erstellung nicht verändert (außer durch die ursprüngliche Software).",
        "en": "No incremental updates — the document has not been modified since creation (except by the original software).",
    },
    "incr_bad": {
        "de": "3 inkrementelle Updates nach einer Signatur — der Inhalt wurde nach der Unterzeichnung mehrfach verändert. Was der Unterzeichner gesehen hat, und was jetzt angezeigt wird, kann voneinander abweichen.",
        "en": "3 incremental updates after a signature — the content was modified multiple times after signing. What the signer saw and what is displayed now may differ.",
    },
    "lbl_update_count":   {"de": "Anzahl Updates", "en": "Number of updates"},
    "lbl_has_incremental":{"de": "Inkrementelle Updates vorhanden", "en": "Incremental updates present"},

    # ── JavaScript ──
    "sec_javascript":     {"de": "JavaScript & Actions", "en": "JavaScript & Actions"},
    "js_expl": {
        "de": "PDFs können JavaScript-Code enthalten, der beim Öffnen, bei Feldaktionen oder Seitenaktionen ausgeführt wird. In legitimen Dokumenten (Formulare, Präsentationen) ist JavaScript selten. In Schad-PDFs wird JavaScript für Exploits, Datendiebstahl (z. B. Auslesen von Benutzerdaten), oder zum Starten externer Programme genutzt.",
        "en": "PDFs can contain JavaScript code that is executed when opening, on field actions or page actions. In legitimate documents (forms, presentations) JavaScript is rare. In malicious PDFs, JavaScript is used for exploits, data theft (e.g. reading user data), or to launch external programs.",
    },
    "js_good": {
        "de": "Kein JavaScript, keine Launch-Actions, keine verdächtigen URI-Actions — das Dokument ist passiv und führt beim Öffnen keine automatischen Aktionen aus.",
        "en": "No JavaScript, no launch actions, no suspicious URI actions — the document is passive and performs no automatic actions when opened.",
    },
    "js_bad": {
        "de": "JavaScript-Code vorhanden der beim Öffnen ausgeführt wird + eine /Launch-Action die ein externes Programm startet — klassische Merkmale eines Exploit-PDFs.",
        "en": "JavaScript code present that executes on opening + a /Launch action that starts an external program — classic characteristics of an exploit PDF.",
    },
    "lbl_js_count":       {"de": "JS-Objekte", "en": "JS objects"},
    "lbl_js_actions":     {"de": "Aktionen gesamt", "en": "Total actions"},
    "lbl_js_launch":      {"de": "/Launch-Actions", "en": "/Launch actions"},
    "lbl_js_uri":         {"de": "/URI-Actions", "en": "/URI actions"},
    "lbl_js_snippets":    {"de": "JavaScript-Code (Auszug)", "en": "JavaScript code (excerpt)"},

    # ── Embedded Files ──
    "sec_embedded":       {"de": "Eingebettete Dateien", "en": "Embedded Files"},
    "emb_expl": {
        "de": "Das PDF-Format erlaubt es, beliebige Dateien direkt im Dokument einzubetten (ähnlich einem ZIP-Archiv). Legitim wird dies für Anhänge genutzt (z. B. Rechnungs-XML in ZUGFeRD-PDFs). Forensisch verdächtig sind versteckte ausführbare Dateien (.exe, .bat, .vbs), Office-Dokumente mit Makros, oder Dateien mit irreführenden Namen.",
        "en": "The PDF format allows any files to be embedded directly in the document (similar to a ZIP archive). Legitimately used for attachments (e.g. invoice XML in ZUGFeRD PDFs). Forensically suspicious are hidden executable files (.exe, .bat, .vbs), Office documents with macros, or files with misleading names.",
    },
    "emb_good": {
        "de": "Keine eingebetteten Dateien, oder nur legitime Anhänge (z. B. invoice.xml in einem ZUGFeRD-Rechnungs-PDF).",
        "en": "No embedded files, or only legitimate attachments (e.g. invoice.xml in a ZUGFeRD invoice PDF).",
    },
    "emb_bad": {
        "de": "Eingebettete EXE-Datei ('update.exe') die beim Öffnen eines Anhangs automatisch ausgeführt werden kann — klassischer Dropper-Mechanismus für Malware.",
        "en": "Embedded EXE file ('update.exe') that can be automatically executed when opening an attachment — classic dropper mechanism for malware.",
    },
    "no_embedded":        {
        "de": "Keine eingebetteten Dateien vorhanden — das Dokument enthält nur PDF-Standard-Inhalte.",
        "en": "No embedded files found — the document contains only standard PDF content.",
    },

    # ── Object Streams ──
    "sec_objstreams":     {"de": "Objekt-Streams", "en": "Object Streams"},
    "obj_expl": {
        "de": "Komprimierte Objekt-Streams (ObjStm, PDF 1.5+) bündeln mehrere PDF-Objekte in einem komprimierten Datenstrom. Sie werden in modernen PDFs zur Komprimierung genutzt, erschweren aber die forensische Analyse, weil Inhalte erst dekomprimiert werden müssen. Eine ungewöhnlich hohe Anzahl oder unerwartete Objekte in Streams können auf Verschleierungsversuche hinweisen.",
        "en": "Compressed object streams (ObjStm, PDF 1.5+) bundle multiple PDF objects into a compressed data stream. Used in modern PDFs for compression, but complicate forensic analysis because contents must first be decompressed. An unusually high number or unexpected objects in streams may indicate obfuscation attempts.",
    },
    "lbl_objstream_count":{"de": "Object Streams", "en": "Object streams"},
    "lbl_compressed_objs":{"de": "Komprimierte Objekte", "en": "Compressed objects"},

    # ── Residual Objects ──
    "sec_residual":       {"de": "Residual-Objekte", "en": "Residual Objects"},
    "res_expl": {
        "de": "Residual-Objekte sind alte Versionen von PDF-Objekten, die zwar durch inkrementelle Updates überschrieben wurden, aber noch im Dokument vorhanden sind. Sie können gelöschten Text, frühere Dokumentversionen oder sensitive Informationen enthalten. Forensisch lassen sich damit frühere Dokumentzustände rekonstruieren.",
        "en": "Residual objects are old versions of PDF objects that were overwritten by incremental updates but still exist in the document. They may contain deleted text, earlier document versions or sensitive information. Forensically, earlier document states can be reconstructed from them.",
    },
    "lbl_residual_count": {"de": "Residual-Objekte", "en": "Residual objects"},
    "lbl_total_objects":  {"de": "Objekte gesamt", "en": "Total objects"},

    # ── Images / ELA ──
    "sec_images":         {"de": "Bilder & ELA-Analyse", "en": "Images & ELA Analysis"},
    "img_expl": {
        "de": "JPEG-Bilder im PDF enthalten in ihrer Quantisierungstabelle einen digitalen Fingerabdruck der Kamera oder des Scanners. Stammen Bilder in einem scheinbar einheitlichen Dokument von verschiedenen Geräten, kann das auf Bildmanipulation hinweisen. Die Error Level Analysis (ELA) erkennt nachträglich eingefügte oder digital bearbeitete Bildbereiche durch unterschiedliche JPEG-Kompressionsartefakte.",
        "en": "JPEG images in the PDF contain a digital fingerprint of the camera or scanner in their quantization table. If images in an apparently uniform document come from different devices, this may indicate image manipulation. Error Level Analysis (ELA) detects subsequently inserted or digitally edited image areas through different JPEG compression artifacts.",
    },
    "img_good": {
        "de": "Alle Bilder haben identische Quantisierungstabellen — kamen von demselben Gerät oder derselben Software. ELA-Werte gleichmäßig niedrig — keine Anzeichen digitaler Nachbearbeitung.",
        "en": "All images have identical quantization tables — came from the same device or software. ELA values uniformly low — no signs of digital post-processing.",
    },
    "img_bad": {
        "de": "Unterschiedliche Quantisierungstabellen in einem Bild — Teilbereiche stammen von verschiedenen Quellen. ELA-Analyse zeigt hot spots mit mean_ela > 15 in einem Bildbereich — deutet auf eingefügten oder manipulierten Inhalt hin.",
        "en": "Different quantization tables in an image — sub-areas come from different sources. ELA analysis shows hot spots with mean_ela > 15 in an image area — indicates inserted or manipulated content.",
    },
    "lbl_image_count":    {"de": "Bilder gesamt", "en": "Total images"},
    "lbl_quant_tables":   {"de": "Quantisierungstabellen", "en": "Quantization tables"},
    "lbl_multi_source":   {"de": "Mehrere Bildquellen", "en": "Multiple image sources"},
    "lbl_ela_results":    {"de": "ELA-Ergebnisse", "en": "ELA results"},
    "col_ela_img":        {"de": "Bild", "en": "Image"},
    "col_ela_mean":       {"de": "Mean ELA", "en": "Mean ELA"},
    "col_ela_max":        {"de": "Max ELA", "en": "Max ELA"},
    "col_ela_hot":        {"de": "Hot Regions", "en": "Hot regions"},
    "col_ela_susp":       {"de": "Verdächtig", "en": "Suspicious"},
    "no_ela":             {
        "de": "Keine eingebetteten JPEG-Bilder für ELA-Analyse gefunden.",
        "en": "No embedded JPEG images found for ELA analysis.",
    },

    # ── IOC ──
    "sec_ioc":            {"de": "Netzwerk-IOCs", "en": "Network IOCs"},
    "ioc_expl": {
        "de": "Indicators of Compromise (IOCs) sind Netzwerkadressen (URLs, IPs, Domains, E-Mails), die im PDF-Inhalt eingebettet sind — in Metadaten, Links, JavaScript-Code oder direkt im Dokumenttext. Verdächtige IOCs können auf Command-and-Control-Server, Phishing-Domains oder Datenexfiltrations-Endpunkte hinweisen.",
        "en": "Indicators of Compromise (IOCs) are network addresses (URLs, IPs, domains, emails) embedded in the PDF content — in metadata, links, JavaScript code or directly in the document text. Suspicious IOCs may point to command-and-control servers, phishing domains or data exfiltration endpoints.",
    },
    "ioc_good": {
        "de": "Nur bekannte, legitime URLs (z. B. https://www.microsoft.com, mailto-Links zur eigenen Domain) — kein Hinweis auf Kommunikation mit externen Servern.",
        "en": "Only known, legitimate URLs (e.g. https://www.microsoft.com, mailto links to own domain) — no indication of communication with external servers.",
    },
    "ioc_bad": {
        "de": "URL http://185.220.101.x/update.exe (Tor-Exit-Node IP) gefunden — klassischer C&C-Endpunkt für Malware-Downloads. Oder: .onion-Adresse in einem Link-Annotation.",
        "en": "URL http://185.220.101.x/update.exe (Tor exit node IP) found — classic C&C endpoint for malware downloads. Or: .onion address in a link annotation.",
    },
    "lbl_total_iocs":     {"de": "IOCs gesamt", "en": "Total IOCs"},
    "lbl_urls":           {"de": "URLs", "en": "URLs"},
    "lbl_ips":            {"de": "IP-Adressen", "en": "IP addresses"},
    "lbl_emails_ioc":     {"de": "E-Mail-Adressen", "en": "Email addresses"},
    "lbl_domains":        {"de": "Domains", "en": "Domains"},
    "lbl_suspicious_iocs":{"de": "Verdächtige IOCs", "en": "Suspicious IOCs"},
    "lbl_emails_list":    {"de": "E-Mail-Adressen", "en": "Email addresses"},
    "suspicious_iocs_warn":{"de": "Verdächtige IOCs gefunden — externe Netzwerkverbindungen oder Phishing-Indikatoren vorhanden!", "en": "Suspicious IOCs found — external network connections or phishing indicators present!"},
    "col_url":            {"de": "URL", "en": "URL"},
    "col_suspicious":     {"de": "Verdächtig", "en": "Suspicious"},
    "col_ip":             {"de": "IP-Adresse", "en": "IP address"},
    "col_ip_type":        {"de": "Typ", "en": "Type"},

    # ── Hidden Text ──
    "sec_hidden_text":    {"de": "Versteckter Text", "en": "Hidden Text"},
    "ht_expl": {
        "de": "Versteckter Text in PDFs ist ein bekanntes Manipulationswerkzeug: Weißer Text auf weißem Hintergrund, winziger Text (< 1pt Schriftgröße) oder Text mit Rendering Mode 3 (Invisible) ist für den Betrachter unsichtbar, aber für Suchmaschinen und forensische Tools lesbar. Häufig genutzt um Keywords zu verstecken, oder um suchbare Text-Layer über gescannte Bilder zu legen.",
        "en": "Hidden text in PDFs is a known manipulation tool: White text on white background, tiny text (< 1pt font size) or text with Rendering Mode 3 (Invisible) is invisible to the viewer, but readable for search engines and forensic tools. Frequently used to hide keywords, or to place searchable text layers over scanned images.",
    },
    "ht_good": {
        "de": "Kein versteckter Text — alle Textinhalte sind für den Betrachter sichtbar und der angezeigte Inhalt stimmt mit dem tatsächlichen Inhalt überein.",
        "en": "No hidden text — all text content is visible to the viewer and the displayed content matches the actual content.",
    },
    "ht_bad": {
        "de": "Text mit Rendering Mode 3 (invisible) gefunden: 'NICHT GEPRÜFT' auf Seite 1 — dieser Text ist unsichtbar, aber vorhanden. Oder: weißer Text '5000€' über dem sichtbaren '500€'.",
        "en": "Text with Rendering Mode 3 (invisible) found: 'NOT VERIFIED' on page 1 — this text is invisible but present. Or: white text '5000€' over the visible '500€'.",
    },
    "ht_clean":           {"de": "Kein versteckter Text gefunden — das Dokument enthält keine unsichtbaren Textinhalte.", "en": "No hidden text found — the document contains no invisible text content."},
    "ht_warning":         {"de": "Versteckter Text gefunden — unsichtbare Inhalte im Dokument!", "en": "Hidden text found — invisible content in the document!"},
    "lbl_invisible":      {"de": "Invisible-Text-Blöcke (Mode 3)", "en": "Invisible text blocks (Mode 3)"},
    "lbl_white_text":     {"de": "Weißer Text auf weißem Hintergrund", "en": "White text on white background"},
    "lbl_tiny_text":      {"de": "Winziger Text (< 1pt)", "en": "Tiny text (< 1pt)"},
    "lbl_ocg_layers":     {"de": "Optionale Content-Gruppen (Layer)", "en": "Optional content groups (layers)"},
    "col_ht_page":        {"de": "Seite", "en": "Page"},
    "col_ht_reason":      {"de": "Grund", "en": "Reason"},
    "col_ht_text":        {"de": "Text (Auszug)", "en": "Text (excerpt)"},
    "col_ht_size":        {"de": "Schriftgröße", "en": "Font size"},

    # ── Yellow Dots ──
    "sec_yellow_dots":    {"de": "Yellow Dots (MIC-Detektion)", "en": "Yellow Dots (MIC Detection)"},
    "yd_expl": {
        "de": "Viele Farblaserdrucker (besonders von Xerox, HP, Canon, Brother) drucken unsichtbare gelbe Mikroperforationen — sogenannte Machine Identification Codes (MIC) oder Yellow Dots. Diese kodieren Datum, Uhrzeit und Seriennummer des Druckers. Damit lassen sich gedruckte Dokumente auf den genauen Drucker und Druckzeitpunkt zurückverfolgen — relevant für Whistleblower-Identifikation und Strafverfolgung.",
        "en": "Many color laser printers (especially from Xerox, HP, Canon, Brother) print invisible yellow micro-perforations — so-called Machine Identification Codes (MIC) or Yellow Dots. These encode the date, time and serial number of the printer. This allows printed documents to be traced back to the exact printer and print time — relevant for whistleblower identification and law enforcement.",
    },
    "no_yd":              {"de": "Keine Yellow-Dot-Muster in eingebetteten Bildern gefunden.", "en": "No yellow dot patterns found in embedded images."},
    "yd_warning":         {"de": "Yellow-Dot-Muster erkannt — Drucker-Identifikationscode möglicherweise vorhanden.", "en": "Yellow dot pattern detected — printer identification code may be present."},
    "lbl_yd_available":   {"de": "Analyse verfügbar", "en": "Analysis available"},
    "lbl_yd_method":      {"de": "Methode", "en": "Method"},
    "lbl_yd_found":       {"de": "Dots gefunden", "en": "Dots found"},
    "lbl_yd_count":       {"de": "Cluster-Anzahl", "en": "Cluster count"},
    "lbl_yd_pattern":     {"de": "Muster-Typ", "en": "Pattern type"},
    "lbl_yd_page":        {"de": "Seite", "en": "Page"},
    "lbl_mic_decoded":    {"de": "Dekodierte MIC-Information", "en": "Decoded MIC information"},

    # ── Virus Scan ──
    "sec_virusscan":      {"de": "Virus-Scan", "en": "Virus Scan"},

    # ── OOXML/OLE ──
    "sec_ooxml":          {"de": "OOXML-Forensik", "en": "OOXML Forensics"},
    "sec_ole":            {"de": "OLE-Forensik", "en": "OLE Forensics"},
    "lbl_track_changes":  {"de": "Änderungsverfolgung", "en": "Track changes"},
    "lbl_rsid_count":     {"de": "Bearbeitungsschritte (RSIDs)", "en": "Editing steps (RSIDs)"},
    "lbl_ext_links":      {"de": "Externe Links", "en": "External links"},
    "lbl_macros":         {"de": "Makros vorhanden", "en": "Macros present"},

    # ── Quant Fingerprint ──
    "sec_quant":          {"de": "JPEG-Quantisierungs-Fingerprint", "en": "JPEG Quantization Fingerprint"},

    # ══════ Phase 5 — Advanced Forensics ══════

    # ── Stream Decompression ──
    "sec_stream_decomp":  {"de": "Stream-Decompression & Exploit-Scan", "en": "Stream Decompression & Exploit Scan"},
    "stream_expl": {
        "de": "Alle komprimierten Streams im PDF werden dekomprimiert und auf Exploit-Indikatoren gescannt. Verdächtige Filter-Ketten (Double-Deflate, JBIG2, Crypt) werden identifiziert.",
        "en": "All compressed streams in the PDF are decompressed and scanned for exploit indicators. Suspicious filter chains (double-deflate, JBIG2, Crypt) are identified.",
    },
    "lbl_total_streams":    {"de": "Streams gesamt", "en": "Total streams"},
    "lbl_decompressed":     {"de": "Dekomprimiert", "en": "Decompressed"},
    "lbl_decomp_failed":    {"de": "Fehlgeschlagen", "en": "Failed"},
    "lbl_filters_found":    {"de": "Gefundene Filter", "en": "Filters found"},
    "lbl_suspicious_streams": {"de": "Verdächtige Streams", "en": "Suspicious streams"},
    "lbl_exploit_indicators": {"de": "Exploit-Indikatoren", "en": "Exploit indicators"},

    # ── XRef Validation ──
    "sec_xref":           {"de": "XRef Deep Validation", "en": "XRef Deep Validation"},
    "xref_expl": {
        "de": "Die Cross-Reference-Tabelle wird auf Konsistenz, Duplikate, freie Ketten und Orphan-Referenzen geprüft. Inkonsistenzen können auf nachträgliche Manipulation hinweisen.",
        "en": "The cross-reference table is checked for consistency, duplicates, free chains, and orphan references. Inconsistencies may indicate post-hoc manipulation.",
    },
    "lbl_xref_type":        {"de": "XRef-Typ", "en": "XRef type"},
    "lbl_xref_entries":     {"de": "Einträge gesamt", "en": "Total entries"},
    "lbl_subsections":      {"de": "Subsektionen", "en": "Subsections"},
    "lbl_free_chain":       {"de": "Free-Chain gültig", "en": "Free chain valid"},
    "lbl_consistency_errors": {"de": "Konsistenzfehler", "en": "Consistency errors"},
    "lbl_dup_offsets":      {"de": "Duplikat-Offsets", "en": "Duplicate offsets"},

    # ── Deep JPEG ──
    "sec_deep_jpeg":      {"de": "Erweiterte JPEG-Forensik", "en": "Deep JPEG Forensics"},
    "deep_jpeg_expl": {
        "de": "Tiefenanalyse der JPEG-Bilder: DCT-Koeffizienten-Prüfung auf Double-Compression, Huffman-Tabellen-Vergleich mit Standard, EXIF-Thumbnail-Validierung, JPEG-Ghost-Detection und PRNU-Sensorrauschen-Extraktion.",
        "en": "Deep analysis of JPEG images: DCT coefficient checking for double compression, Huffman table comparison with standard, EXIF thumbnail validation, JPEG ghost detection, and PRNU sensor noise extraction.",
    },
    "lbl_dct_analysis":     {"de": "DCT Double-Compression", "en": "DCT Double Compression"},
    "lbl_huffman":          {"de": "Huffman-Tabellen", "en": "Huffman Tables"},
    "lbl_thumbnail":        {"de": "Thumbnail-Prüfung", "en": "Thumbnail Check"},
    "lbl_jpeg_ghost":       {"de": "JPEG Ghost Detection", "en": "JPEG Ghost Detection"},
    "lbl_prnu":             {"de": "PRNU-Fingerprint", "en": "PRNU Fingerprint"},

    # ── Redaction ──
    "sec_redaction":      {"de": "Schwärzungsanalyse", "en": "Redaction Analysis"},
    "redaction_expl": {
        "de": "Prüft ob Schwärzungen im PDF tatsächlich sicher sind. Unsichere Schwärzungen (schwarze Rechtecke über Text, nicht-angewendete Redact-Annotations) ermöglichen das Extrahieren des geschwärzten Textes.",
        "en": "Checks whether redactions in the PDF are actually secure. Insecure redactions (black rectangles over text, unapplied redact annotations) allow extraction of the redacted text.",
    },
    "lbl_redactions_found": {"de": "Schwärzungen gefunden", "en": "Redactions found"},
    "lbl_secure":           {"de": "Sicher", "en": "Secure"},
    "lbl_insecure":         {"de": "Unsicher", "en": "Insecure"},
    "redact_secure_ok":     {"de": "Alle Schwärzungen sind korrekt angewendet.", "en": "All redactions are properly applied."},
    "redact_none":          {"de": "Keine Schwärzungen im Dokument.", "en": "No redactions in document."},

    # ── OCG Layers ──
    "sec_ocg":            {"de": "OCG-Layer (Ebenen)", "en": "OCG Layers"},
    "ocg_expl": {
        "de": "Optional Content Groups (OCG) sind Ebenen im PDF die ein-/ausgeblendet werden können. Versteckte Layer können sensible Inhalte enthalten die bei normaler Ansicht nicht sichtbar sind.",
        "en": "Optional Content Groups (OCG) are layers in the PDF that can be shown/hidden. Hidden layers may contain sensitive content not visible in normal view.",
    },
    "lbl_layer_count":      {"de": "Layer gesamt", "en": "Total layers"},
    "lbl_hidden_layers":    {"de": "Versteckte Layer", "en": "Hidden layers"},
    "ocg_none":             {"de": "Keine OCG-Layer im Dokument.", "en": "No OCG layers in document."},

    # ── Content Stream ──
    "sec_content_stream": {"de": "Content-Stream-Validierung", "en": "Content Stream Validation"},
    "cs_expl": {
        "de": "Prüft PDF-Content-Stream-Operatoren nach ISO 32000. Ungültige oder verdächtige Operatoren können auf manipulierte Streams oder Exploit-Versuche hinweisen.",
        "en": "Validates PDF content stream operators per ISO 32000. Invalid or suspicious operators may indicate manipulated streams or exploit attempts.",
    },
    "lbl_pages_checked":    {"de": "Seiten geprüft", "en": "Pages checked"},
    "lbl_invalid_ops":      {"de": "Ungültige Operatoren", "en": "Invalid operators"},
    "lbl_suspicious_patterns": {"de": "Verdächtige Muster", "en": "Suspicious patterns"},
    "lbl_op_stats":         {"de": "Operator-Statistik (Top 10)", "en": "Operator Statistics (Top 10)"},

    # ── Incremental Diff ──
    "sec_inc_diff":       {"de": "Revisions-Differenzierung", "en": "Revision Diffing"},
    "inc_diff_expl": {
        "de": "Zeigt konkret was sich zwischen PDF-Revisionen geändert hat: hinzugefügte, geänderte und entfernte Objekte pro Revision. Änderungen an Metadata- oder Catalog-Objekten sind besonders verdächtig.",
        "en": "Shows concrete changes between PDF revisions: added, modified, and deleted objects per revision. Changes to metadata or catalog objects are particularly suspicious.",
    },
    "lbl_revision":         {"de": "Revision", "en": "Revision"},
    "lbl_added":            {"de": "Hinzugefügt", "en": "Added"},
    "lbl_modified":         {"de": "Geändert", "en": "Modified"},
    "lbl_removed":          {"de": "Entfernt", "en": "Removed"},
    "lbl_rev_size":         {"de": "Revisionsgröße", "en": "Revision size"},

    # ── Fuzzy Hash ──
    "sec_fuzzy_hash":     {"de": "Fuzzy Hashing", "en": "Fuzzy Hashing"},
    "fuzzy_expl": {
        "de": "Fuzzy Hashes (ssdeep, TLSH) erkennen ähnliche — nicht nur identische — Dokumente. Damit können leicht modifizierte Kopien oder Vorversionen eines Dokuments identifiziert werden.",
        "en": "Fuzzy hashes (ssdeep, TLSH) detect similar — not just identical — documents. This allows identification of slightly modified copies or previous versions of a document.",
    },
    "lbl_ssdeep":           {"de": "ssdeep", "en": "ssdeep"},
    "lbl_tlsh":             {"de": "TLSH", "en": "TLSH"},

    # ── Cross-Analyzer ──
    "sec_cross_analyzer": {"de": "Cross-Analyzer Intelligence", "en": "Cross-Analyzer Intelligence"},
    "cross_expl": {
        "de": "Automatische Korrelation zwischen allen Analyzern: Zeitlinien-Rekonstruktion, Creator-Profiling und gewichteter Manipulations-Score. Einzelbefunde werden zu einem Gesamtbild zusammengeführt.",
        "en": "Automatic correlation across all analyzers: timeline reconstruction, creator profiling, and weighted manipulation score. Individual findings are merged into a comprehensive picture.",
    },
    "lbl_manipulation_score": {"de": "Manipulations-Score", "en": "Manipulation Score"},
    "lbl_correlations":     {"de": "Korrelationen", "en": "Correlations"},
    "lbl_timeline":         {"de": "Rekonstruierte Zeitlinie", "en": "Reconstructed Timeline"},
    "lbl_creator_profile":  {"de": "Creator-Profil", "en": "Creator Profile"},
    "lbl_confidence":       {"de": "Konfidenz", "en": "Confidence"},

    # ── Chain of Custody ──
    "sec_coc":            {"de": "Chain of Custody", "en": "Chain of Custody"},
    "coc_expl": {
        "de": "Dokumentation der Beweiskette für gerichtliche Verwertbarkeit: Wer hat wann welche Analyse durchgeführt? Wurde die Datei während der Analyse verändert?",
        "en": "Chain of custody documentation for court admissibility: Who performed which analysis when? Was the file modified during analysis?",
    },
    "lbl_examiner":         {"de": "Gutachter", "en": "Examiner"},
    "lbl_case_number":      {"de": "Fallnummer", "en": "Case number"},
    "lbl_exam_start":       {"de": "Untersuchungsbeginn", "en": "Examination start"},
    "lbl_exam_end":         {"de": "Untersuchungsende", "en": "Examination end"},
    "lbl_evidence_integrity": {"de": "Beweis-Integrität", "en": "Evidence integrity"},
    "lbl_integrity_ok":     {"de": "Datei unverändert", "en": "File unchanged"},
    "lbl_integrity_fail":   {"de": "Datei verändert!", "en": "File modified!"},
    "lbl_audit_log":        {"de": "Audit-Log", "en": "Audit log"},

    # Phase 6 — Extended Forensics
    "sec_yara":             {"de": "🛡️ YARA Malware-Scan", "en": "🛡️ YARA Malware Scan"},
    "sec_font_forensics":   {"de": "🔤 Font-Forensik", "en": "🔤 Font Forensics"},
    "sec_pdfa_compliance":  {"de": "📜 PDF/A & PDF/X Compliance", "en": "📜 PDF/A & PDF/X Compliance"},
    "sec_linearization":    {"de": "⚡ Linearisierung", "en": "⚡ Linearization"},
    "sec_icc_profiles":     {"de": "🎨 ICC-Farbprofile", "en": "🎨 ICC Color Profiles"},
    "sec_visual_render":    {"de": "🖼️ Visueller Render", "en": "🖼️ Visual Render"},
    "sec_object_graph":     {"de": "🕸️ PDF-Objekt-Graph", "en": "🕸️ PDF Object Graph"},
    "sec_cross_doc_fp":     {"de": "🔗 Cross-Document Fingerprint", "en": "🔗 Cross-Document Fingerprint"},
    "sec_printer_forensics":{"de": "🖨️ Drucker-Forensik", "en": "🖨️ Printer Forensics"},
    "lbl_yara_rules":       {"de": "Geladene Regeln", "en": "Rules Loaded"},
    "lbl_yara_matches":     {"de": "Treffer gesamt", "en": "Total Matches"},
    "lbl_yara_critical":    {"de": "Kritische Treffer", "en": "Critical Matches"},
    "col_yara_rule":        {"de": "Regel", "en": "Rule"},
    "col_yara_severity":    {"de": "Schwere", "en": "Severity"},
    "col_yara_category":    {"de": "Kategorie", "en": "Category"},
    "col_yara_desc":        {"de": "Beschreibung", "en": "Description"},
    "lbl_ff_total":         {"de": "Schriftarten gesamt", "en": "Total Fonts"},
    "lbl_ff_embedded":      {"de": "Eingebettet", "en": "Embedded"},
    "lbl_ff_subset":        {"de": "Subset", "en": "Subset"},
    "lbl_ff_system":        {"de": "System-Fonts", "en": "System Fonts"},
    "lbl_ff_creators":      {"de": "Font-Herkunft", "en": "Font Origins"},
    "lbl_pdfa_claimed":     {"de": "PDF/A beansprucht", "en": "PDF/A Claimed"},
    "lbl_pdfx_claimed":     {"de": "PDF/X beansprucht", "en": "PDF/X Claimed"},
    "lbl_pdfa_issues":      {"de": "Compliance-Probleme", "en": "Compliance Issues"},
    "lbl_pdfa_passes":      {"de": "Bestandene Prüfungen", "en": "Passed Checks"},
    "lbl_lin_linearized":   {"de": "Linearisiert", "en": "Linearized"},
    "lbl_lin_version":      {"de": "Version", "en": "Version"},
    "lbl_lin_mismatch":     {"de": "Größen-Diskrepanz", "en": "Size Mismatch"},
    "lbl_icc_count":        {"de": "Profile gefunden", "en": "Profiles Found"},
    "lbl_icc_colorspaces":  {"de": "Farbräume", "en": "Color Spaces"},
    "col_icc_name":         {"de": "Profilname", "en": "Profile Name"},
    "col_icc_class":        {"de": "Geräteklasse", "en": "Device Class"},
    "col_icc_platform":     {"de": "Plattform", "en": "Platform"},
    "col_icc_source":       {"de": "Quelle", "en": "Source"},
    "lbl_vr_pages":         {"de": "Gerenderte Seiten", "en": "Pages Rendered"},
    "lbl_vr_blank":         {"de": "Leere Seiten", "en": "Blank Pages"},
    "lbl_vr_duplicates":    {"de": "Duplizierte Seiten", "en": "Duplicate Pages"},
    "lbl_og_objects":       {"de": "Objekte gesamt", "en": "Total Objects"},
    "lbl_og_max_depth":     {"de": "Max. Tiefe", "en": "Max Depth"},
    "lbl_cdf_struct":       {"de": "Struktur-Hash", "en": "Structure Hash"},
    "lbl_cdf_font":         {"de": "Font-Hash", "en": "Font Hash"},
    "lbl_cdf_meta":         {"de": "Metadaten-Hash", "en": "Metadata Hash"},
    "lbl_cdf_style":        {"de": "Style-Hash", "en": "Style Hash"},
    "lbl_cdf_content":      {"de": "Content-Hash", "en": "Content Hash"},
    "lbl_pf_scanned":       {"de": "Gescanntes Dokument", "en": "Scanned Document"},
    "lbl_pf_confidence":    {"de": "Scan-Konfidenz", "en": "Scan Confidence"},
    "lbl_pf_printer_type":  {"de": "Druckertyp", "en": "Printer Type"},
    "lbl_pf_dpi":           {"de": "Erkannte DPI", "en": "Detected DPI"},
    "lbl_pf_halftone":      {"de": "Halftone-Raster", "en": "Halftone Pattern"},
    "lbl_pf_banding":       {"de": "Drucker-Banding", "en": "Printer Banding"},
    "lbl_pf_images":        {"de": "Analysierte Bilder", "en": "Images Analyzed"},
}


def _t(key: str, lang: str) -> str:
    """Übersetzung abrufen — fällt auf DE zurück wenn EN-Eintrag fehlt."""
    entry = _T.get(key)
    if not entry:
        return key
    return entry.get(lang) or entry.get("de") or key


def _risk_icon(level) -> str:
    return {
        RiskLevel.HIGH: "🔴", RiskLevel.MEDIUM: "🟡",
        RiskLevel.LOW: "🔵", RiskLevel.CLEAN: "🟢",
    }.get(level, "⚪")


def _safe_anomalies(obj) -> list:
    """Safely extract anomalies from an analyzer result, never raising."""
    if obj is None:
        return []
    try:
        anoms = getattr(obj, 'anomalies', None)
        if anoms is None or anoms is NotImplemented:
            return []
        result = []
        for a in anoms:
            if a is None or a is NotImplemented:
                continue
            # Ensure severity is a proper AnomalySeverity
            sev = getattr(a, 'severity', None)
            if sev is None or sev is NotImplemented:
                continue
            result.append(a)
        return result
    except (TypeError, AttributeError):
        return []


def _sanitize_all_anomalies(result: AnalysisResult) -> None:
    """Pre-process ALL anomalies on the result to guarantee they are safe lists.
    This prevents 'NotImplementedType is not iterable' in the template."""
    # All fields that have .anomalies
    _fields_with_anomalies = [
        'metadata', 'software_fingerprint', 'signature', 'uuid_decode',
        'encryption', 'incremental_updates', 'javascript', 'embedded_files',
        'jpeg_analyzer', 'virus_scan', 'timezone', 'author_artifacts',
        'ela', 'object_streams', 'residual_objects', 'shadow_attack',
        'ioc', 'hidden_text', 'yellow_dots', 'quant_fingerprint',
        'stream_decomp', 'xref_validation', 'deep_jpeg', 'redaction',
        'ocg_layers', 'content_stream', 'incremental_diff', 'fuzzy_hash',
        'cross_analyzer', 'yara', 'font_forensics', 'pdfa_compliance',
        'linearization', 'icc_profiles', 'visual_render', 'object_graph',
        'cross_doc_fingerprint', 'printer_forensics',
    ]
    for field_name in _fields_with_anomalies:
        obj = getattr(result, field_name, None)
        if obj is None:
            continue
        try:
            anoms = getattr(obj, 'anomalies', None)
            if anoms is None or anoms is NotImplemented:
                try:
                    obj.anomalies = []
                except (AttributeError, TypeError):
                    pass
                continue
            # Rebuild as clean list, filtering out bad entries
            clean = []
            for a in anoms:
                if a is None or a is NotImplemented:
                    continue
                sev = getattr(a, 'severity', None)
                if sev is None or sev is NotImplemented:
                    continue
                clean.append(a)
            try:
                obj.anomalies = clean
            except (AttributeError, TypeError):
                pass
        except (TypeError, AttributeError):
            try:
                obj.anomalies = []
            except (AttributeError, TypeError):
                pass

    # Sanitize all_anomalies
    if not isinstance(result.all_anomalies, list):
        try:
            result.all_anomalies = list(result.all_anomalies)
        except (TypeError, ValueError):
            result.all_anomalies = []
    # Filter bad entries from all_anomalies
    clean_all = []
    for a in result.all_anomalies:
        if a is None or a is NotImplemented:
            continue
        sev = getattr(a, 'severity', None)
        if sev is None or sev is NotImplemented:
            continue
        clean_all.append(a)
    result.all_anomalies = clean_all


def _anom_status(anomalies: list) -> tuple[str, str]:
    """Returns (css_class, label)"""
    if not anomalies:
        return "ok", "OK"
    try:
        highs = [a for a in anomalies if getattr(getattr(a, 'severity', None), 'value', None) == "HIGH"]
        meds  = [a for a in anomalies if getattr(getattr(a, 'severity', None), 'value', None) == "MEDIUM"]
        lows  = [a for a in anomalies if getattr(getattr(a, 'severity', None), 'value', None) == "LOW"]
    except (TypeError, AttributeError):
        return "ok", "OK"
    if highs:
        return "high", f"HIGH ({len(highs)})"
    if meds:
        return "medium", f"MEDIUM ({len(meds)})"
    if lows:
        return "low", f"LOW ({len(lows)})"
    return "ok", "OK"


def _build_analyzers(result: AnalysisResult) -> list:
    """Baut die Liste für das Analyzer-Grid (alle Phasen 1-6)."""
    def _entry(name, anomalies):
        safe = _safe_anomalies(anomalies) if not isinstance(anomalies, list) else anomalies
        cls, label = _anom_status(safe)
        return (name, cls, label, len(safe))

    # Phase 1-2: Basis-Analyzer
    items = [
        ("Metadata",        _safe_anomalies(result.metadata)),
        ("Hashes",          []),
        ("Software FP",     _safe_anomalies(result.software_fingerprint)),
        ("Signatures",      _safe_anomalies(result.signature)),
        ("UUID",            _safe_anomalies(result.uuid_decode)),
        ("Encryption",      _safe_anomalies(result.encryption)),
        ("Incr. Updates",   _safe_anomalies(result.incremental_updates)),
        ("JavaScript",      _safe_anomalies(result.javascript)),
        ("Embedded Files",  _safe_anomalies(result.embedded_files)),
        ("JPEG/Images",     _safe_anomalies(result.jpeg_analyzer)),
        ("Virus Scan",      _safe_anomalies(result.virus_scan)),
    ]

    # Phase 3-4: Optional
    _optional_phase34 = [
        ("Timezone",     result.timezone),
        ("Author Art.",  result.author_artifacts),
        ("ELA",          result.ela),
        ("Obj Streams",  result.object_streams),
        ("Residual",     result.residual_objects),
        ("Shadow Atk",   result.shadow_attack),
        ("IOC",          result.ioc),
        ("Hidden Text",  result.hidden_text),
        ("Yellow Dots",  result.yellow_dots),
        ("Quant FP",     result.quant_fingerprint),
    ]
    for name, obj in _optional_phase34:
        if obj is not None:
            items.append((name, _safe_anomalies(obj)))

    # Phase 5: Advanced Forensics
    _optional_phase5 = [
        ("Stream Dec.",   result.stream_decomp),
        ("XRef Valid.",   result.xref_validation),
        ("Deep JPEG",    result.deep_jpeg),
        ("Redaction",    result.redaction),
        ("OCG Layers",   result.ocg_layers),
        ("Content Str.", result.content_stream),
        ("Incr. Diff",   result.incremental_diff),
        ("Fuzzy Hash",   result.fuzzy_hash),
        ("Cross-Anal.",  result.cross_analyzer),
    ]
    for name, obj in _optional_phase5:
        if obj is not None:
            items.append((name, _safe_anomalies(obj)))

    # Phase 6: Extended Forensics
    _optional_phase6 = [
        ("YARA",         result.yara),
        ("Font Foren.",  result.font_forensics),
        ("PDF/A Compl.", result.pdfa_compliance),
        ("Lineariz.",    result.linearization),
        ("ICC Profiles", result.icc_profiles),
        ("Visual Rend.", result.visual_render),
        ("Obj Graph",    result.object_graph),
        ("Cross-Doc",    result.cross_doc_fingerprint),
        ("Printer For.", result.printer_forensics),
    ]
    for name, obj in _optional_phase6:
        if obj is not None:
            items.append((name, _safe_anomalies(obj)))

    return [_entry(name, anom) for name, anom in items]


def _anomaly_table_html(anomalies, lang: str) -> str:
    """Rendert eine Anomalie-Tabelle als HTML-String."""
    if not anomalies or anomalies is NotImplemented:
        return ""
    try:
        anomalies = list(anomalies)
    except TypeError:
        return ""
    if not anomalies:
        return ""
    rows = ""
    for a in anomalies:
        sev = a.severity.value
        detail = f'<br><span style="color:#64748b;font-size:6.5pt">{a.detail[:250]}</span>' if a.detail else ""
        rows += f"""
        <tr>
          <td><span class="sev sev-{sev}">{sev}</span></td>
          <td class="mono" style="font-size:7pt">{a.category}</td>
          <td style="font-size:7.5pt">{a.message}{detail}</td>
        </tr>"""
    return f"""
    <table class="anom-table" style="margin-top:3mm">
      <thead><tr>
        <th style="width:16mm">{_t('severity_col', lang)}</th>
        <th style="width:30mm">{_t('category_col', lang)}</th>
        <th>{_t('message_col', lang)}</th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table>"""


def _build_timeline_events(result: AnalysisResult) -> list:
    """Baut Timeline-Events aus Metadaten + UUID-Zeitstempeln."""
    events = []

    # Erstelldatum
    if result.metadata.creation_date_parsed:
        d = str(result.metadata.creation_date_parsed)[:19]
        events.append((d, "Created", "#3b82f6"))

    # Änderungsdatum
    if result.metadata.mod_date_parsed:
        d = str(result.metadata.mod_date_parsed)[:19]
        events.append((d, "Modified", "#8b5cf6"))

    # UUID-Zeitstempel
    if result.uuid_decode and result.uuid_decode.decoded:
        for i, dec in enumerate(result.uuid_decode.decoded[:2]):
            ts = str(dec.get('timestamp_utc', '?'))[:19] if isinstance(dec, dict) else str(getattr(dec, 'timestamp_utc', '?'))[:19]
            events.append((ts, f"UUID {i+1}", "#f59e0b"))

    return events


# ─── Haupt-Funktion ───────────────────────────────────────────────────────────

def generate_analysis_report(result: AnalysisResult, lang: str = "de", ai_review: dict = None) -> Path:
    """Generiert vollständigen PDF-Bericht via WeasyPrint."""
    out_dir = REPORTS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"report_{result.analysis_id}_{lang}.pdf"

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=True,
    )

    # Jinja2-Filter registrieren
    def _truncate_filter(s, length=50, killwords=False, end="...", leeway=0):
        """Jinja2-kompatibles Truncate."""
        s = str(s) if s is not None else ""
        if len(s) <= length:
            return s
        return s[:length] + end
    env.filters["truncate"] = _truncate_filter

    # Anomalie-Tabelle als Callable für Template
    def anomaly_table_fn(anomalies):
        safe = _safe_anomalies(anomalies) if not isinstance(anomalies, list) else anomalies
        return Markup(_anomaly_table_html(safe, lang))

    # Safe-List Jinja2 Filter: ensures iterable, never raises
    def _safe_list_filter(val):
        if val is None or val is NotImplemented:
            return []
        try:
            return list(val)
        except TypeError:
            return []
    env.filters["safe_list"] = _safe_list_filter

    # Safe-Anomalies filter: ensures anomalies are always a clean iterable list
    def _safe_anoms_filter(val):
        if val is None or val is NotImplemented:
            return []
        try:
            result_list = []
            for a in val:
                if a is None or a is NotImplemented:
                    continue
                sev = getattr(a, 'severity', None)
                if sev is None or sev is NotImplemented:
                    continue
                result_list.append(a)
            return result_list
        except TypeError:
            return []
    env.filters["safe_anoms"] = _safe_anoms_filter

    # Template laden — NUR v2 benutzen
    tmpl = env.get_template("report_template_v2.html")

    # ── Sanitize ALL anomalies before rendering ──
    _sanitize_all_anomalies(result)

    # ── SVG Charts generieren ──
    risk_val = result.risk_level.value if result.risk_level else "UNKNOWN"
    gauge_svg = svg_risk_gauge(risk_val, width=220, height=130)
    donut_svg = svg_donut_chart(
        result.anomaly_count_high,
        result.anomaly_count_medium,
        result.anomaly_count_low,
        width=140, height=140,
    )

    # Radar-Chart
    analyzers = _build_analyzers(result)
    radar_items = [(name, cls, count) for name, cls, label, count in analyzers]
    radar_svg = svg_radar_chart(radar_items, width=280, height=280)

    # Timeline
    timeline_events = _build_timeline_events(result)
    timeline_svg = svg_timeline(timeline_events, width=480, height=55) if timeline_events else ""

    total_anom = max(result.anomaly_count_high + result.anomaly_count_medium + result.anomaly_count_low, 1)

    ctx = {
        "lang":           lang,
        "r":              result,
        "now":            datetime.now().strftime("%d.%m.%Y %H:%M"),
        "risk_icon":      _risk_icon(result.risk_level),
        "total_anom":     total_anom,
        "analyzers":      analyzers,
        "anomaly_table":  anomaly_table_fn,
        "t":              lambda key: _t(key, lang),
        # SVG Charts
        "gauge_svg":      gauge_svg,
        "donut_svg":      donut_svg,
        "radar_svg":      radar_svg,
        "timeline_svg":   timeline_svg,
        # KI-Review
        "ai_review":      ai_review or {},
    }

    try:
        html_str = tmpl.render(**ctx)
    except Exception as e:
        tb = traceback.format_exc()
        print(f"[ERROR] Template rendering failed:\n{tb}")
        raise RuntimeError(f"Template-Rendering fehlgeschlagen: {e}") from e

    # Playwright Chromium: HTML → PDF
    _html_to_pdf_playwright(html_str, out_path)

    return out_path


# ─── Vergleichsbericht ────────────────────────────────────────────────────────

def generate_comparison_report(result: CompareResult, lang: str = "de") -> Path:
    """Generiert einen Vergleichsbericht via WeasyPrint (Dark Theme)."""
    out_dir = REPORTS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"compare_{result.comparison_id}_{lang}.pdf"

    title = "Forensischer Vergleichsbericht" if lang == "de" else "Forensic Comparison Report"
    label_a = "Datei A" if lang == "de" else "File A"
    label_b = "Datei B" if lang == "de" else "File B"
    same_label = "Identisch" if lang == "de" else "Identical"
    same_val = ("Ja" if result.are_identical else "Nein") if lang == "de" else ("Yes" if result.are_identical else "No")
    generated = "Erstellt am" if lang == "de" else "Generated on"
    now = datetime.now().strftime("%d.%m.%Y %H:%M")

    # Differences
    diff_label = "Unterschiede" if lang == "de" else "Differences"
    no_diff = "Keine Unterschiede gefunden." if lang == "de" else "No differences found."

    diff_rows = ""
    if hasattr(result, 'differences') and result.differences:
        for d in result.differences[:30]:
            field = d.get('field', '?')
            val_a = str(d.get('value_a', '—'))[:100]
            val_b = str(d.get('value_b', '—'))[:100]
            diff_rows += f"""
            <tr>
              <td style="font-weight:600; color:#93c5fd">{field}</td>
              <td class="mono">{val_a}</td>
              <td class="mono">{val_b}</td>
            </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="{lang}">
<head><meta charset="UTF-8">
<style>
@page {{
    size: A4;
    margin: 18mm;
    background: #0f172a;
    @bottom-center {{
        content: counter(page) " / " counter(pages);
        font-family: Helvetica, Arial, sans-serif;
        font-size: 7pt;
        color: #475569;
    }}
}}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family: Helvetica, Arial, sans-serif; font-size:9pt; color:#cbd5e1; background:#0f172a; line-height:1.5; }}
.header {{ background: linear-gradient(135deg, #1e3a5f, #172554); border-left: 4pt solid #3b82f6; padding:5mm 6mm; border-radius:0 4pt 4pt 0; margin-bottom:6mm; }}
.header h1 {{ font-size:16pt; color:#e2e8f0; font-weight:800; }}
.header .sub {{ font-size:8pt; color:#64748b; margin-top:1mm; }}
.card {{ background:#1e293b; border:0.5pt solid #334155; border-radius:4pt; padding:4mm 5mm; margin-bottom:4mm; }}
.card-label {{ font-size:6pt; color:#475569; letter-spacing:2pt; margin-bottom:1mm; }}
.card-value {{ font-size:9pt; color:#e2e8f0; font-family: 'Courier New', monospace; word-break:break-all; }}
.row {{ display:flex; gap:4mm; margin-bottom:4mm; }}
.row > .card {{ flex:1; }}
.badge {{ display:inline-block; padding:1.5mm 4mm; border-radius:3pt; font-size:8pt; font-weight:700; }}
.badge-yes {{ background:rgba(34,197,94,0.15); color:#4ade80; border:0.5pt solid #16a34a; }}
.badge-no  {{ background:rgba(239,68,68,0.15); color:#f87171; border:0.5pt solid #dc2626; }}
table {{ width:100%; border-collapse:collapse; margin-top:4mm; }}
th {{ background:#334155; color:#e2e8f0; padding:2.5mm 3mm; text-align:left; font-size:7.5pt; font-weight:600; border:0.5pt solid #475569; }}
td {{ padding:2mm 3mm; border:0.5pt solid #334155; font-size:8pt; color:#cbd5e1; }}
tr:nth-child(odd) td {{ background:#1e293b; }}
tr:nth-child(even) td {{ background:#0f172a; }}
.mono {{ font-family:'Courier New', monospace; font-size:7.5pt; }}
.info {{ background:rgba(59,130,246,0.08); border:0.5pt solid rgba(59,130,246,0.3); border-radius:4pt; padding:3mm 4mm; color:#93c5fd; font-size:8.5pt; }}
</style>
</head>
<body>
<div class="header">
  <h1>{title}</h1>
  <div class="sub">{generated} {now}</div>
</div>

<div class="row">
  <div class="card">
    <div class="card-label">{label_a.upper()}</div>
    <div class="card-value">{result.filename_a}</div>
  </div>
  <div class="card">
    <div class="card-label">{label_b.upper()}</div>
    <div class="card-value">{result.filename_b}</div>
  </div>
</div>

<div class="card" style="text-align:center">
  <div class="card-label">{same_label.upper()}</div>
  <span class="badge {'badge-yes' if result.are_identical else 'badge-no'}">{same_val}</span>
</div>

{"" if not diff_rows else f'''
<div class="header" style="margin-top:6mm">
  <h1 style="font-size:12pt">{diff_label}</h1>
</div>
<table>
  <thead><tr><th>Field</th><th>{label_a}</th><th>{label_b}</th></tr></thead>
  <tbody>{diff_rows}</tbody>
</table>
'''}

{"" if diff_rows else f'<div class="info" style="margin-top:6mm">{no_diff}</div>'}

</body></html>"""

    _html_to_pdf_playwright(html, out_path)
    return out_path
