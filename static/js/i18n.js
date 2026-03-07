/**
 * i18n.js — Deutsch / Englisch Sprachumschaltung
 * Verwendung: t('key') gibt den übersetzten String zurück.
 * Sprache wird in localStorage gespeichert.
 */

const TRANSLATIONS = {
  de: {
    // App
    app_name: "PDF Forensik",

    // Navbar
    nav_analyse:  "Analyse",
    nav_verlauf:  "Verlauf",
    nav_vergleich:"Vergleich",
    nav_lang_btn: "EN",
    nav_lang_title:"Switch to English",

    // Upload
    upload_drop:  "PDF hier ablegen oder",
    upload_btn:   "Datei auswählen",
    upload_hint:  "Maximal 200 MB · Nur PDF-Dateien",
    upload_progress: "Analysiere PDF…",
    step_hash:    "HASH",
    step_meta:    "META",
    step_img:     "IMG",
    step_uuid:    "UUID",
    step_sig:     "SIG",
    step_fp:      "FP",

    // Risk Banner
    btn_download_report: "PDF-Bericht",
    btn_add_compare:     "Vergleich",
    btn_ai_review:       "🤖 KI-Gutachten",

    // KI-Review Panel
    ai_confidence:       "Konfidenz:",
    ai_legit:            "Legitimität:",
    ai_laien_title:      "💬 In einfachen Worten",
    ai_behavior_short:   "Was tun?",
    ai_expert_details:   "Expertenmodus — Alle technischen Details anzeigen",
    ai_summary:          "Zusammenfassung",
    ai_found:            "🔍 Was wurde gefunden",
    ai_recognize:        "💡 Was lässt sich erkennen",
    ai_conclude:         "🧠 Forensische Schlussfolgerungen",
    ai_findings:         "Hauptbefunde",
    ai_manipulation:     "⚠ Manipulationshinweise",
    ai_behavior:         "🛡 Verhaltensempfehlung",
    ai_doc_assessment:   "📄 Dokumenteninhalt-Bewertung",
    ai_further_tests:    "🧪 Vorgeschlagene weitere Tests",
    ai_extensions:       "💡 Erweiterungsvorschläge",
    ai_recommendations:  "Empfehlungen",
    ai_risk_explanation: "Risikoerklärung",
    ai_conclusion:       "✅ Fazit",
    ai_technical_details:"Technische Details",
    ai_model_prefix:     "Modell:",

    // Sections
    sec_virusscan:      "Virus-Scan",
    sec_hashes:         "Kryptografische Hashes",
    sec_metadata:       "PDF-Metadaten",
    sec_software:       "Software-Fingerprint",
    sec_uuid:           "UUID-Analyse",
    sec_signature:      "Digitale Signaturen",
    sec_geometry:       "Seitengeometrie",
    sec_pagelabels:     "PageLabels",
    sec_images:         "Eingebettete Bilder",
    sec_encryption:     "Verschlüsselung",
    sec_incremental:    "Revisionen / Incremental Updates",
    sec_javascript:     "JavaScript & Actions",
    sec_embedded:       "Eingebettete Dateien & Annotations",
    sec_anomalies:      "Anomalien",

    // Virus-Scan
    vs_clean:           "Keine Bedrohung erkannt",
    vs_infected:        "Treffer — Potenziell schädlich!",
    vs_unavailable:     "Nicht verfügbar",
    vs_not_scanned:     "Nicht gescannt",
    vs_clean_status:    "Sauber",
    vs_detections:      "Treffer",
    vs_more:            "… und {n} weitere",
    vs_vt_link:         "Auf VirusTotal ansehen",
    vs_expl: `<b>Was wird geprüft?</b> Die PDF-Datei wird gegen bekannte Malware-Signaturen geprüft.
      <b>ClamAV</b> läuft lokal — kein Upload zu Dritten.
      <b>VirusTotal</b> prüft mit 70+ Antivirenprogrammen (nur wenn API-Key konfiguriert).`,

    // Hashes
    hash_expl: `<b>Was sind Hashes?</b> Kryptografische Prüfsummen des gesamten PDF-Inhalts. Ändert sich auch nur 1 Byte, ändern sich alle Hashes komplett — das macht sie zur zuverlässigen Datei-ID.<br><b>Wie nutze ich das?</b> Kopiere den SHA-256-Hash und vergleiche ihn mit dem Hash einer Vertrauensquelle (z.B. Original-Absender, behördliche Datenbank, VirusTotal). Stimmen die Hashes überein, ist die Datei byte-identisch und wurde nicht manipuliert.`,
    hash_copy: "Hash kopiert!",

    // Metadata
    meta_expl: `<b>Was sind PDF-Metadaten?</b> Jedes PDF enthält ein /Info-Dictionary mit Angaben zu Erstellungssoftware, Datum und Autor. Diese werden häufig bei Fälschungen manipuliert — z.B. durch Rückdatieren oder Entfernen des Autors. Wir prüfen auch XMP-Metadaten auf Widersprüche zum /Info-Dictionary.`,

    // Software
    sw_expl: `<b>Was ist der Software-Fingerprint?</b> Der "Producer"-String verrät die PDF-Export-Engine. Der "Creator" zeigt die Quell-Anwendung. Stimmen Creator und Producer nicht zusammen, wurde das Dokument konvertiert oder nachbearbeitet.`,

    // UUID
    uuid_expl: `<b>Was sind UUID v1-Zeitstempel?</b> UUID Version 1 enthält einen exakten Zeitstempel (100ns-Auflösung). Weicht dieser stark vom CreationDate ab, deutet das auf Manipulation hin — das Dokument wurde zu einem anderen Zeitpunkt erstellt als behauptet.`,

    // Signature
    sig_expl: `<b>Was sind digitale Signaturen?</b> PDFs können kryptografisch signiert sein. /DocMDP legt fest ob nach der Signatur Änderungen erlaubt sind. Ist ein Sig-Feld vorhanden aber kein AcroForm, ist das Dokument inkonsistent — ein Zeichen für Manipulation.`,

    // Geometry
    geo_expl: `<b>Was prüft die Seitengeometrie?</b> MediaBox = Seitengröße in Punkten (1pt = 1/72 Zoll). Standard A4 = 595×842pt. Verschiedene Seitengrößen im selben Dokument können auf zusammengefügte PDFs hinweisen.`,

    // PageLabels
    pl_expl: `<b>Was sind PageLabels?</b> PDFs können eine eigene Seitennummerierung definieren. Stimmt die deklarierte Anzahl nicht mit der tatsächlichen überein, ist das ein Indiz für nachträgliche Seitenmanipulation.`,

    // Images
    img_expl: `<b>Was wird bei Bildern geprüft?</b> EXIF-Daten können Kameramodell, GPS und Aufnahmedatum enthalten — oft vergessen beim Fälschen. Quantisierungstabellen sind ein Software-Fingerprint. Ghostscript-typische Tabellen deuten auf Nachbearbeitung hin.`,

    // Encryption
    enc_expl: `<b>Was prüft die Verschlüsselung?</b> RC4-40bit ist trivial knackbar. RC4-128bit gilt als schwach. AES-128/256 sind sicher. Ein gesperrtes Dokument kann trotzdem manipuliert worden sein wenn die Metadaten unverschlüsselt bleiben.`,

    // Incremental Updates
    inc_expl: `<b>Was sind Incremental Updates?</b> PDFs können ohne vollständige Neuerstellung ergänzt werden — der originale Inhalt bleibt erhalten, neue Objekte werden angehängt. Mehr als 1 Revision = mögliche nachträgliche Änderung, oft mit dem Ziel eine Signatur zu umgehen.`,

    // JavaScript
    js_expl: `<b>Was wird geprüft?</b> /OpenAction wird beim Öffnen automatisch ausgeführt. /Launch startet externe Programme. /JS = eingebetteter JavaScript-Code. In legitimen Dokumenten selten bis nie vorhanden — mögliche Exploit-Vektoren.`,

    // Embedded Files
    ef_expl: `<b>Was wird geprüft?</b> PDFs können Dateien einbetten — darunter ausführbare Dateien (.exe, .dll, .bat). Annotations können versteckte Metadaten oder Links zu externen Servern enthalten. Object Streams können Inhalte verschleiern.`,

    // Upload errors
    err_not_pdf:   "Nur PDF-Dateien werden akzeptiert.",
    err_too_large: "Datei zu groß (max. 200 MB).",
    analysis_done: "Analyse abgeschlossen!",

    // History
    hist_title:       "Analyse-Verlauf",
    hist_subtitle:    "Alle bisherigen PDF-Analysen",
    hist_search_ph:   "Dateiname, Hash oder Risiko suchen…",
    hist_search_btn:  "Suchen",
    hist_empty:       "Noch keine Analysen vorhanden.",
    hist_view:        "Anzeigen",
    hist_delete:      "Löschen",
    hist_confirm_del: "Analyse wirklich löschen?",

    // Compare
    cmp_title:        "Dokument-Vergleich",
    cmp_subtitle:     "2-4 analysierte PDFs nebeneinander vergleichen",
    cmp_select:       "Dokument {n} auswählen",
    cmp_add_slot:     "+ Dokument hinzufügen",
    cmp_run:          "Vergleich starten",
    cmp_running:      "Vergleiche…",
    cmp_summary:      "Vergleichs-Übersicht",
    cmp_timeline:     "Erstellungs-Timeline",
    cmp_table:        "Attribut-Vergleich",
    cmp_anomalies:    "Vergleichs-Anomalien",
    cmp_software:     "Software-Übereinstimmungen",
    cmp_uuid:         "UUID-Cluster (gemeinsame Maschine)",
    cmp_metadiff:     "Metadaten-Unterschiede",
    cmp_report_btn:   "Vergleichsbericht herunterladen",
    cmp_pick_title:   "Analyse auswählen",
    cmp_pick_search:  "Dateiname suchen…",
    cmp_select_docs:  "Dokumente auswählen",
    cmp_select_hint:  "Aus Verlauf wählen oder IDs eingeben",

    // Compare — dynamische Schlüssel (JS-generiert)
    cmp_failed:           "Vergleich fehlgeschlagen",
    cmp_attr_col:         "Attribut",
    cmp_doc_prefix:       "Dok.",
    cmp_attr_risk:        "Risiko",
    cmp_attr_high:        "HIGH-Anomalien",
    cmp_attr_medium:      "MEDIUM-Anomalien",
    cmp_attr_encrypted:   "Verschlüsselt",
    cmp_sum_docs:         "Dokumente",
    cmp_sum_hashes:       "Identische Hashes",
    cmp_sum_time:         "Zeitnähe-Flags",
    cmp_sum_uuid:         "UUID-Cluster",
    cmp_sum_software:     "Software-Übereinstimmungen",
    cmp_sum_metadiff:     "Metadaten-Unterschiede",
    cmp_sum_anomalies:    "Vergleichs-Anomalien",
    cmp_sum_common_cats:  "Gemeinsame Anomalie-Kategorien",
    cmp_hits:             "Treffer",
    cmp_cluster:          "Cluster",
    cmp_found:            "gefunden",
    cmp_fields:           "Felder",
    cmp_uuid_warning:     "Gleiche UUIDs in mehreren Dokumenten — diese Dokumente wurden wahrscheinlich auf derselben Maschine oder in derselben Session erstellt.",
    cmp_metadiff_intro:   "Felder die zwischen den Dokumenten unterschiedliche Werte haben:",
    cmp_no_analyses:      "Keine Analysen vorhanden",
    cmp_doc_id_a:         "Dok-ID A",
    cmp_doc_id_b:         "Dok-ID B",

    // Page titles / subtitles
    page_analyse_title:    "Forensische PDF-Analyse",
    page_analyse_subtitle: "Metadaten · Hashes · Bilder · UUID-Decoder · Signatur-Erkennung · Software-Fingerprint",

    // History extended
    hist_subtitle_full:          "Alle gespeicherten forensischen Analysen",
    hist_loading:                "Lade Verlauf…",
    hist_date_from:              "Von",
    hist_date_to:                "Bis",
    hist_reset_btn:              "Zurücksetzen",
    hist_load_error:             "Verlauf konnte nicht geladen werden",
    hist_search_error:           "Suche fehlgeschlagen",
    hist_analyses_found_plural:  "Analysen gefunden",
    hist_analyses_found_singular:"Analyse gefunden",
    hist_empty_hint:             "Analysiere ein PDF auf der Hauptseite",
    hist_download_report:        "Bericht herunterladen",
    hist_confirm_del_prefix:     "Analyse",
    hist_delete_error:           "Löschen fehlgeschlagen",

    // Loading / generic
    loading:                "Lade…",
    loading_saved_analysis: "Lade gespeicherte Analyse…",
    analysis_not_found:     "Analyse nicht gefunden",
    no_data:                "Keine Daten",

    // Labels — field names in tables
    lbl_filesize:          "Dateigröße",
    lbl_pdf_version:       "PDF-Version",
    lbl_pages:             "Seiten",
    lbl_title:             "Titel",
    lbl_author:            "Autor",
    lbl_subject:           "Betreff",
    lbl_keywords:          "Schlüsselwörter",
    lbl_created_raw:       "Erstellt (raw)",
    lbl_created:           "Erstellt",
    lbl_modified_raw:      "Geändert (raw)",
    lbl_modified:          "Geändert",
    lbl_identified_tool:   "Identifiziertes Tool",
    lbl_category:          "Kategorie",
    lbl_version:           "Version",
    lbl_found_uuid_v1:     "Gefundene UUID v1",
    lbl_acroform:          "AcroForm",
    lbl_sig_field:         "Signatur-Feld",
    lbl_docmdp:            "DocMDP",
    lbl_sig_names:         "Sig-Feld-Namen",
    lbl_signature:         "Signatur",
    lbl_mixed_sizes:       "Gemischte Größen",
    lbl_unique_formats:    "Eindeutige Formate",
    lbl_total_pages:       "Seiten gesamt",
    lbl_extracted_images:  "Extrahierte Bilder",
    lbl_ghostscript_quant: "Ghostscript-Quant.",
    lbl_extraction_method: "Extraktionsmethode",
    lbl_status:            "Status",
    lbl_algorithm:         "Algorithmus",
    lbl_key_length:        "Schlüssellänge",
    lbl_strength:          "Stärke",
    lbl_meta_enc:          "Metadaten enc.",
    lbl_print:             "Drucken",
    lbl_edit:              "Bearbeiten",
    lbl_copy:              "Kopieren",
    lbl_annotate:          "Annotieren",
    lbl_forms:             "Formulare",
    lbl_print_hires:       "Hochaufl. Druck",
    lbl_revisions:         "Revisionen",
    lbl_data_after_eof:    "Daten nach EOF",
    lbl_javascript:        "JavaScript",
    lbl_auto_execute:      "Auto-Execute",
    lbl_total_actions:     "Aktionen gesamt",
    lbl_js_snippets:       "JS-Snippets",
    lbl_embedded_files:    "Eingebettete Dateien",
    lbl_annotations:       "Annotations gesamt",
    lbl_hidden_annotations:"Versteckte Annotations",
    lbl_obj_streams:       "Object Streams",
    lbl_analysiert:        "Analysiert",

    // Column headers
    col_uuid:           "UUID",
    col_uuid_timestamp: "Zeitstempel (aus UUID)",
    col_uuid_delta:     "Δ zum CreationDate",
    col_uuid_verdict:   "Bewertung",
    col_page:           "Seite",
    col_wh_pt:          "Breite × Höhe (pt)",
    col_a4:             "A4",
    col_orientation:    "Ausrichtung",
    col_revision:       "Revision",
    col_size:           "Größe",
    col_xref_type:      "xref-Typ",
    col_new_objects:    "Neue Objekte",
    col_byte_offset:    "Byte-Offset",
    col_location:       "Ort",
    col_type:           "Typ",
    col_auto_execute:   "Auto-Execute",
    col_filename:       "Dateiname",
    col_mime:           "MIME",
    col_sha256:         "SHA256",
    col_cert_field:     "Feld",
    col_cert_subject:   "Inhaber",
    col_cert_issuer:    "Aussteller",
    col_cert_serial:    "Seriennummer",
    col_cert_valid_from:"Gültig von",
    col_cert_valid_until:"Gültig bis",
    col_cert_sha1fp:    "SHA1-Fingerprint",

    // Sub-headers
    sub_xmp_metadata:     "XMP-Metadaten",
    sub_cert_details:     "Zertifikat-Details",
    sub_permissions:      "Berechtigungen",
    sub_revision_details: "Revisions-Details",
    sub_found_actions:    "Gefundene Aktionen",
    sub_js_snippets:      "JavaScript-Snippets (erste 500 Zeichen)",
    sub_embedded_files:   "Eingebettete Dateien",

    // Status / value texts
    enc_not_encrypted:      "Nicht verschlüsselt",
    enc_password_protected: "Passwortgeschützt",
    enc_encrypted_no_pw:    "Verschlüsselt (kein User-Passwort)",
    enc_meta_unencrypted:   "Nein — XMP-Metadaten unverschlüsselt!",
    present_warning:        "VORHANDEN",
    present:                "Vorhanden",
    not_present:            "Nicht vorhanden",
    auto_exec_yes:          "JA — wird beim Öffnen ausgeführt!",
    auto_exec_short:        "JA",
    no_clean:               "Nein",
    yes_clean:              "Ja",
    none_clean:             "Keine",
    rev_one_clean:          "1 (unverändert)",
    revisions_count:        "Revisionen",
    bytes_after_eof:        "Bytes nach %%EOF",
    rev_current:            "aktuell",
    ghostscript_detected:   "Erkannt — Bilder wurden neu-komprimiert",
    not_detected:           "Nicht erkannt",
    geo_mixed_yes:          "Ja — verschiedene Formate!",
    perm_allowed:           "Erlaubt",
    perm_denied:            "Gesperrt",
    file_count_suffix:      "Datei(en)",
    cert_expired:           "Zertifikat abgelaufen!",
    uuid_none_found:        "Keine UUID v1 im Dokument gefunden — kein Word/Office-Fingerprint vorhanden.",
    uuid_consistent:        "Konsistent",
    uuid_strongly_deviating:"Stark abweichend ({delta}s)",
    uuid_slightly_deviating:"Leicht abweichend ({delta}s)",
    no_jpeg_images:         "Keine eingebetteten JPEG-Bilder gefunden.",

    // Tooltip texts
    xmp_tooltip: "XMP ist ein zweiter Metadaten-Speicher im PDF. Widersprüche zwischen XMP und /Info-Dictionary deuten auf Manipulation hin.",
    xmp_what:    "Was ist XMP?",
    cert_tooltip: "Das digitale Zertifikat bestätigt die Identität des Unterzeichners. Abgelaufene oder unbekannte Zertifikate sind ein Warnsignal.",
    cert_what:   "Was bedeutet das?",

    // Allgemeine neue Labels
    upload_hint:        "Maximal 200 MB · PDF, DOCX, XLSX, PPTX, DOC, ODT",
    err_not_supported:  "Dateiformat nicht unterstützt. Erlaubt: PDF, DOCX, XLSX, PPTX, DOC, XLS, PPT, ODT.",
    err_not_pdf:        "Nur PDF-Dateien werden akzeptiert.",

    // Phase 2 — OOXML / OLE (DE)
    sec_ooxml:          "OOXML-Forensik (DOCX/XLSX/PPTX)",
    sec_ole:            "OLE2-Forensik (DOC/XLS/PPT)",

    ooxml_expl: "<b>OOXML-Forensik:</b> Das Open-XML-Format (ZIP-Container) enthält Core Properties, App Properties, Revisions-IDs (RSID), Track-Changes-Autoren und Makros — forensisch hochrelevant.",
    ole_expl:   "<b>OLE2-Forensik:</b> Das ältere Compound-File-Binary-Format enthält SummaryInformation-Streams mit Autor, Zeitstempeln, Revisionsnummern und Company-Daten.",

    lbl_format:         "Format",
    lbl_last_mod_by:    "Zuletzt bearbeitet von",
    lbl_revision:       "Revision",
    lbl_application:    "Anwendung",
    lbl_app_version:    "App-Version",
    lbl_company:        "Firma",
    lbl_template:       "Vorlage",
    lbl_rsid_count:     "RSID-Sitzungen",
    lbl_tc_authors:     "Track-Changes-Autoren",
    lbl_external_links: "Externe Links",
    lbl_media_files:    "Mediendateien",
    lbl_words:          "Wörter",

    sub_track_changes:  "Track-Changes",
    sub_rsids:          "Revisions-IDs (RSID)",
    sub_external_links: "Externe Verknüpfungen",
    sub_custom_props:   "Custom Properties",
    sub_ole_strings:    "Gefundene Strings (Pfade/Namen/Anwendungen)",

    rsid_total:         "gesamt",
    more:               "weitere",
    col_author:         "Autor",
    col_date:           "Datum",
    col_text:           "Inhalt",

    // Phase 1 — neue Sektionen (DE)
    sec_timezone:        "Timezone-Analyse",
    sec_author_artifacts:"Autoren-Artefakte",
    sec_ela:             "ELA & Copy-Move",
    sec_object_streams:  "Object Streams",
    sec_residual:        "Verwaiste Objekte",
    sec_shadow_attack:   "Shadow-Attack",

    // Timezone
    tz_expl: "<b>Was wird analysiert?</b> Alle Datumsangaben im PDF werden extrahiert, UTC-Offsets verglichen und eine wahrscheinliche geografische Region abgeleitet.",
    lbl_tz_region:      "Wahrscheinliche Region",
    lbl_tz_consistent:  "Zeitzonen konsistent",
    lbl_tz_dates_found: "Datums-Felder gefunden",
    no_timezone_data:   "Keine Datumsangaben im PDF gefunden.",
    tz_inconsistent:    "Inkonsistent — verschiedene Offsets",
    col_tz_source:      "Feld",
    col_tz_local:       "Lokalzeit",
    col_tz_utc:         "UTC",
    col_tz_offset:      "Offset",
    col_tz_region:      "Region",

    // Author Artifacts
    aa_expl: "<b>Was wird gesucht?</b> Versteckte Autorenhinweise: Font-Subset-Präfixe (session-einmalig), XMP-Pfade, Annotations-Autoren, Formulardaten, Druckernamen.",
    lbl_font_prefixes:     "Font-Subset-Präfixe",
    lbl_xmp_author_hints:  "XMP-Autorenhinweise",
    lbl_annotation_authors:"Annotations-Autoren",
    lbl_paths_found:       "Dateipfade gefunden",
    lbl_emails_found:      "E-Mail-Adressen gefunden",
    lbl_printer_name:      "Druckername",
    no_author_artifacts:   "Keine Autoren-Artefakte gefunden.",
    sub_font_prefixes:     "Font-Subset-Präfixe",
    sub_author_artifacts:  "Gefundene Artefakte",
    col_prefix:            "Präfix",
    col_font_name:         "Font-Name",
    col_source:            "Quelle",
    col_value:             "Wert",

    // ELA
    ela_expl: "<b>Error Level Analysis:</b> Bilder werden re-komprimiert und die Pixeldifferenz analysiert. Bereiche mit hoher Differenz = mögliche Montage. Copy-Move sucht nach kopierten Bildblöcken.",
    ela_unavailable:       "ELA nicht verfügbar (Pillow nicht installiert).",
    ela_no_images:         "Keine JPEG-Bilder im PDF für ELA-Analyse.",
    lbl_images_checked:    "Bilder analysiert",
    lbl_suspicious_images: "Verdächtige Bilder",
    lbl_copy_move_detected:"Copy-Move-Treffer",
    ela_difference_image:  "ELA-Differenzbild",
    lbl_ela_mean:          "ELA-Mittelwert",
    lbl_ela_max:           "ELA-Maximum",
    lbl_dup_blocks:        "duplizierte Blöcke",
    lbl_image:             "Bild",

    // Object Streams
    os_expl: "<b>Object Streams (ObjStm):</b> PDF 1.5+ kann Objekte komprimiert in Streams verpacken. Versteckte JS-Objekte oder doppelte Objekt-IDs (Shadow-Technik) sind forensisch relevant.",
    lbl_obj_stream_count:  "ObjStm-Objekte",
    lbl_xref_type:         "xref-Typ",
    lbl_hybrid_xref:       "Hybrid xref",
    lbl_duplicate_objects: "Doppelte Objekt-IDs",
    sub_suspicious_streams:"Verdächtige Object Streams",
    sub_duplicate_objs:    "Doppelt definierte Objekte",
    lbl_objstm:            "ObjStm",
    lbl_suspicious_keys:   "Verdächtige Keys",
    has_javascript:        "JavaScript/JS gefunden",
    obj_count_suffix:      "Objekt(e)",
    lbl_obj:               "Objekt",

    // Residual Objects
    ro_expl: "<b>Verwaiste Objekte (Carving):</b> Im PDF-Byte-Stream vorhandene Objekte, die nicht mehr in der xref-Tabelle referenziert werden — können gelöschten Text, alte Metadaten oder versteckten Code enthalten.",
    lbl_orphaned_objects:  "Verwaiste Objekte",
    lbl_trailing_data:     "Daten nach %%EOF",
    lbl_eof_count:         "%%EOF-Marker",
    sub_orphaned_objects:  "Verwaiste Objekte (Details)",
    sub_trailing_data:     "Daten nach %%EOF",
    col_obj_num:           "Objekt #",
    col_type_hint:         "Typ",
    col_flags:             "Inhalts-Flags",
    col_preview:           "Vorschau",
    col_trailing_bytes:    "Bytes",
    col_hex_preview:       "Hex-Vorschau",
    col_text_preview:      "Text-Vorschau",
    bytes_suffix:          "Bytes",

    // Shadow Attack
    sa_expl: "<b>Shadow-Attack:</b> Erkennt ob der ByteRange der Signatur nicht das gesamte Dokument abdeckt (Shadow Attack), ob nach der Signatur Objekte eingefügt wurden (ISA) oder ob der Signatur-Container falsch referenziert wird.",
    shadow_no_signature:   "Kein Signatur-Feld — Shadow-Attack-Analyse nicht anwendbar.",
    lbl_shadow_attack:     "Shadow-Attack",
    lbl_isa_attack:        "ISA (Incremental Saving Attack)",
    lbl_sig_wrapping:      "Signature Wrapping",
    lbl_sig_count:         "Signaturen",
    shadow_suspicious:     "VERDÄCHTIG",
    shadow_clean:          "Sauber",
    isa_suspicious:        "VERDÄCHTIG",
    isa_clean:             "Sauber",
    wrap_suspicious:       "VERDÄCHTIG",
    wrap_clean:            "Sauber",
    sub_byte_range_analysis: "ByteRange-Details",
    sub_isa_analysis:      "ISA-Analyse",
    col_prefix_bytes:      "Bytes vor Signatur",
    col_suffix_bytes:      "Bytes nach Signatur",
    col_covers_full:       "Deckt gesamtes Dokument",
    yes:                   "Ja",
    no:                    "Nein",

    // Phase 3 — Bild-Forensik
    sec_image_forensics:   "Bild-Forensik",
    sec_steganography:     "Steganographie-Analyse",
    img_forensics_expl:    "<b>Bild-Forensik:</b> EXIF-Metadaten-Analyse, Error Level Analysis (ELA), Copy-Move-Erkennung, PRNU-Rauschprofil, Doppelkomprimierungs-Test und KI-Bild-Erkennung.",
    img_no_exif:           "Keine EXIF-Metadaten gefunden.",
    img_ela_title:         "Error Level Analysis (ELA)",
    img_ela_mean:          "Mittlerer ELA-Wert",
    img_ela_max:           "Maximaler ELA-Wert",
    img_ela_hot_regions:   "Verdächtige Regionen",
    img_copymove_title:    "Copy-Move-Erkennung (DCT)",
    img_copymove_blocks:   "Geprüfte Blöcke",
    img_copymove_matches:  "Doppelte Block-Paare",
    img_copymove_suspected:"Verdächtig",
    img_prnu_title:        "PRNU-Rauschprofil",
    img_prnu_noise_std:    "Rausch-Standardabweichung",
    img_prnu_inconsistent: "Inkonsistentes Rauschprofil",
    img_dc_title:          "Doppelkomprimierung (JPEG)",
    img_dc_suspected:      "Doppelkomprimierung erkannt",
    img_dc_est_quality:    "Geschätzte Ausgangsqualität",
    img_thumb_title:       "Thumbnail-Konsistenz",
    img_thumb_mismatch:    "Thumbnail-/Hauptbild-Mismatch",
    img_ai_title:          "KI-Bild-Erkennung",
    img_ai_score:          "KI-Score",
    img_ai_verdict:        "Bewertung",
    steg_expl:             "<b>Steganographie-Analyse:</b> LSB Chi-Square-Test, RS-Analyse (Fridrich et al.), PNG-Chunk-Inspektion und JPEG Trailing-Data-Suche.",
    steg_chi_title:        "LSB Chi-Square-Test",
    steg_capacity_kb:      "LSB-Kapazität",
    steg_suspected:        "Verdächtig",
    steg_rs_title:         "RS-Analyse (Fridrich)",
    steg_rs_fill:          "Geschätzte LSB-Füllung",
    steg_png_title:        "PNG-Chunk-Analyse",
    steg_png_chunks:       "Chunks gesamt",
    steg_png_unknown:      "Unbekannte Chunks",
    steg_png_trailing:     "Trailing-Data nach IEND",
    steg_png_textchunks:   "Text-Chunks",
    steg_jpeg_title:       "JPEG Trailing-Data",
    steg_jpeg_trailing:    "Daten nach EOI-Marker",
    upload_hint:           "Maximal 200 MB · PDF, DOCX, XLSX, PPTX, DOC, ODT, JPEG, PNG",

    // Phase 4 — IOC
    sec_ioc:               "IOC-Extraktion",
    ioc_expl:              "<b>Network Indicators of Compromise:</b> URLs, IP-Adressen, E-Mail-Adressen und Domains aus allen PDF-Bereichen (Streams, Metadaten, JavaScript, Annotations). Verdächtige TLDs und URL-Shortener werden rot markiert.",
    lbl_ioc_total:         "Gesamt IOCs",
    lbl_ioc_urls:          "URLs",
    lbl_ioc_ips:           "IP-Adressen",
    lbl_ioc_emails:        "E-Mail-Adressen",
    lbl_ioc_suspicious:    "Verdächtige IOCs",
    col_ioc_url:           "URL",
    col_ioc_suspicious:    "Verdächtig",
    col_ioc_source:        "Quelle",
    col_ioc_ip:            "IP-Adresse",
    col_ioc_type:          "Typ",
    ioc_internal_ip:       "Intern",
    ioc_external_ip:       "Extern",
    ioc_no_iocs:           "Keine IOCs gefunden.",
    sub_ioc_urls:          "URLs",
    sub_ioc_ips:           "IP-Adressen",
    sub_ioc_emails:        "E-Mail-Adressen",

    // Phase 4 — Hidden Text
    sec_hidden_text:       "Hidden-Text-Analyse",
    ht_expl:               "<b>Versteckter Text:</b> Analysiert alle Seiten auf unsichtbaren Text — weißer Text auf weißem Hintergrund, Schrift < 1pt, Rendering Mode 3 (vollständig transparent) und off-page Text. OCG-Ebenen werden ebenfalls aufgelistet.",
    lbl_ht_invisible:      "Unsichtbarer Text (Mode 3)",
    lbl_ht_white:          "Weißer Text",
    lbl_ht_tiny:           "Miniatur-Text (<1pt)",
    lbl_ht_ocg:            "OCG-Ebenen",
    col_ht_page:           "Seite",
    col_ht_reason:         "Grund",
    col_ht_text:           "Text-Vorschau",
    col_ht_fontsize:       "Schriftgröße",
    ht_no_hidden:          "Kein versteckter Text gefunden.",
    sub_ht_blocks:         "Gefundene Blöcke",
    sub_ht_ocg:            "OCG-Ebenen (Optional Content)",
    ht_reason_invisible:   "Rendering Mode 3",
    ht_reason_white:       "Weißer Text",
    ht_reason_tiny:        "Miniatur (<1pt)",
    ht_reason_off_page:    "Außerhalb Seite",

    // Phase 4 — Yellow Dots
    sec_yellow_dots:       "Yellow Dots / MIC",
    yd_expl:               "<b>Machine Identification Code (MIC):</b> Drucker kodieren versteckte Identifikationsmuster als winzige gelbe Punkte (Steganographie). Erkennt Xerox MIC und generische Muster in eingebetteten Bildern.",
    lbl_yd_available:      "Analyse verfügbar",
    lbl_yd_method:         "Methode",
    lbl_yd_found:          "Punkte gefunden",
    lbl_yd_count:          "Punkt-Cluster",
    lbl_yd_pattern:        "Muster-Typ",
    lbl_yd_page:           "Seite",
    lbl_yd_decoded:        "Dekodierte Information",
    yd_no_dots:            "Keine gelben Punkte gefunden.",
    yd_pattern_xerox:      "Xerox MIC",
    yd_pattern_generic:    "Generisches Muster",

    // Phase 4 — Batch Upload
    batch_title:           "Batch-Analyse",
    batch_queue:           "Warteschlange",
    batch_start:           "Alle analysieren",
    batch_clear:           "Zurücksetzen",
    batch_status_pending:  "Wartend",
    batch_status_analyzing:"Analysiere…",
    batch_status_done:     "Fertig",
    batch_status_error:    "Fehler",
    batch_results_title:   "Batch-Ergebnisse",
    batch_files_selected:  "{n} Dateien ausgewählt",

    // Phase 4 — Cross-Match
    btn_cross_match_fonts: "Font-Cross-Match",
    btn_cross_match_quant: "Quant-Cross-Match",
    cross_match_loading:   "Suche läuft…",
    cross_match_no_results:"Keine Treffer in der Datenbank.",
    cross_match_results:   "{n} Treffer gefunden",
    col_cm_filename:       "Datei",
    col_cm_analyzed:       "Analysiert",
    col_cm_risk:           "Risiko",
    col_cm_shared:         "Gemeinsame Merkmale",

    // Page Labels
    lbl_page_labels:       "Seiten-Beschriftungen",
    lbl_declared_pages:    "Deklarierte Seiten",
    lbl_actual_pages:      "Tatsächliche Seiten",
    sub_page_labels:       "Label-Bereiche",
    col_start_page:        "Startseite",
    col_style:             "Stil",
    col_first_value:       "Erster Wert",

    // Author Artifacts — neue Keys
    sub_xmp_authors:       "XMP-Autoren",
    sub_annotation_authors:"Annotations-Autoren",

    // Object Streams — neue Keys
    col_first_offset:      "Erster Offset",

    // Encryption — neue Keys
    lbl_enc_v:             "Verschl.-Version (V)",
    lbl_enc_r:             "Revision (R)",
    lbl_enc_p:             "Berechtigungs-Flags (P)",
    lbl_owner_hash:        "Owner-Hash",
    lbl_user_hash:         "User-Hash",

    // Images — Gesamtgröße
    lbl_total_img_size:    "Gesamt-Bildgröße",

    // Incremental Updates — neue Spalten
    col_start_byte:        "Start-Byte",
    col_end_byte:          "End-Byte",
    col_xref_offset:       "XRef-Offset",

    // Annotations
    sub_annotations:       "Annotationen Details",
    col_hidden:            "Versteckt",
    col_contents:          "Inhalt",

    // ELA — hot_regions Label (war evtl. schon vorhanden)
    lbl_ela_hot_regions:   "Hot-Regions",

    // IOC — Domains
    lbl_ioc_domains:       "Domains",
    sub_ioc_domains:       "Gefundene Domains",

    // Hidden Text — neue Spalten
    col_ht_render_mode:    "Render-Modus",
    col_ht_color:          "Farbe (RGB)",

    // Timezone — neue Keys
    lbl_tz_unique_offsets: "Eindeutige Offsets",

    // Author Artifacts — neue Keys
    lbl_form_fields:       "Formularfelder",
    sub_form_fields:       "Formularfeld-Hinweise",
    col_field_name:        "Feldname",

    // Images — neue Keys
    sub_image_details:     "Bild-Details (EXIF / Hashes)",
    col_camera:            "Kamera",
    col_datetime:          "Datum/Zeit",
    col_img_index:         "Bild #",
    col_table_type:        "Tabellen-Typ",
    col_match_score:       "Übereinstimmung",
    col_table_id:          "Tabellen-ID",
    sub_quant_matches:     "Quant-Tabellen Treffer",
    lbl_images_checked:    "Bilder geprüft",

    // Object Streams — neue Keys
    sub_obj_streams_list:  "Alle ObjStm-Streams",
    col_stream_len:        "Stream-Länge",
    col_sub_objects:       "Unter-Objekte",
    lbl_occurrences:       "Vorkommen",

    // Residual Objects — neue Keys
    sub_eof_markers:       "EOF-Marker Details",

    // Shadow Attack — neue Keys
    lbl_signed_from:       "Signiert ab",
    lbl_signed_to:         "Signiert bis",
    lbl_bytes_after_sig:   "Bytes nach Signatur",
    lbl_has_xref_after:    "XRef nach Signatur",
    lbl_has_obj_after:     "Objekte nach Signatur",
    lbl_doc_end_offset:    "Dokument-Ende (Offset)",
    lbl_file_size:         "Dateigröße",
    lbl_byte_range_occ:    "ByteRange-Vorkommen",

    // Chart Dashboard
    chart_risk_gauge:      "Risiko-Level",
    chart_severity:        "Befund-Verteilung",
    chart_radar:           "Analyzer-Radar",
    chart_categories:      "Befunde nach Kategorie",
    chart_phase_summary:   "Phasen-Ergebnis",
    chart_security_score:    "Sicherheits-Score",
    chart_file_structure:    "Dateistruktur",
    chart_analyzer_coverage: "Analyzer-Abdeckung",
    chart_timeline:          "Dokument-Timeline",
    charts_radar_empty:    "Zu wenige Kategorien für Radar-Chart",
    charts_timeline_empty: "Nicht genug Zeitstempel für Timeline",
    lbl_findings:          "Befunde",

    // Phase 5 — Advanced Forensics (DE)
    sec_stream_decomp:     "Stream-Dekompressions-Analyse",
    sec_xref_validation:   "XRef-Deep-Validierung",
    sec_deep_jpeg:         "Deep JPEG-Forensik",
    sec_redaction:         "Schwärzungs-Analyse",
    sec_ocg_layers:        "OCG-Ebenen (Optional Content)",
    sec_content_stream:    "Content-Stream-Validierung",
    sec_inc_diff:          "Inkrementelles Update-Diffing",
    sec_fuzzy_hash:        "Fuzzy Hashing",
    sec_cross_analyzer:    "Cross-Analyzer Intelligence",
    sec_chain_of_custody:  "Chain of Custody",

    // Stream Decomp
    sd_expl:               "<b>Stream-Dekompressions-Analyse:</b> Alle PDF-Streams werden dekomprimiert und auf Exploit-Patterns, verdächtige Filter-Ketten und eingebetteten Code untersucht.",
    lbl_sd_total_streams:  "Streams gesamt",
    lbl_sd_decompressed:   "Dekomprimiert",
    lbl_sd_suspicious:     "Verdächtige Streams",
    lbl_sd_filters:        "Filter-Typen",
    sub_sd_suspicious:     "Verdächtige Stream-Inhalte",
    col_sd_obj:            "Objekt",
    col_sd_filter:         "Filter",
    col_sd_size:           "Größe",
    col_sd_pattern:        "Gefundenes Pattern",

    // XRef Validation
    xref_expl:             "<b>XRef-Deep-Validierung:</b> Prüft Konsistenz der Cross-Reference-Tabelle, Subsektionen, Free-Object-Chains und Offset-Validierung.",
    lbl_xref_entries:      "XRef-Einträge",
    lbl_xref_valid:        "Gültige Einträge",
    lbl_xref_invalid:      "Ungültige Einträge",
    lbl_xref_free:         "Free Objects",
    lbl_xref_hybrid:       "Hybrid XRef",
    lbl_xref_subsections:  "Subsektionen",
    sub_xref_issues:       "XRef-Probleme",
    col_xref_issue:        "Problem",
    col_xref_obj:          "Objekt",

    // Deep JPEG
    dj_expl:               "<b>Deep JPEG-Forensik:</b> DCT-Doppelkomprimierung, Huffman-Tabellen-Vergleich, Thumbnail-Validierung, JPEG Ghost Detection und PRNU-Rauschprofil.",
    lbl_dj_images:         "Analysierte Bilder",
    lbl_dj_dct:            "DCT-Doppelkompression",
    lbl_dj_huffman:        "Huffman-Anomalien",
    lbl_dj_thumbnail:      "Thumbnail-Mismatch",
    lbl_dj_ghost:          "JPEG-Ghost erkannt",
    lbl_dj_prnu:           "PRNU-Inkonsistenz",
    sub_dj_results:        "Detaillierte Ergebnisse",

    // Redaction
    red_expl:              "<b>Schwärzungs-Analyse:</b> Prüft ob Schwärzungen sicher sind — schwarze Rechtecke über Text (unsicher), nicht-angewendete Redact-Annotations, extrahierbarer Text unter Overlay.",
    lbl_red_found:         "Schwärzungen gefunden",
    lbl_red_secure:        "Sichere Schwärzungen",
    lbl_red_insecure:      "Unsichere Schwärzungen",
    sub_red_details:       "Schwärzungs-Details",
    col_red_page:          "Seite",
    col_red_type:          "Typ",
    col_red_secure:        "Sicher",
    col_red_note:          "Hinweis",

    // OCG Layers
    ocg_expl:              "<b>OCG-Ebenen:</b> Optional Content Groups können Inhalte verstecken. Versteckte oder gesperrte Ebenen können forensisch relevante Informationen enthalten.",
    lbl_ocg_count:         "OCG-Ebenen gesamt",
    lbl_ocg_hidden:        "Versteckte Ebenen",
    lbl_ocg_locked:        "Gesperrte Ebenen",
    sub_ocg_list:          "Ebenen-Details",
    col_ocg_name:          "Name",
    col_ocg_visible:       "Sichtbar",
    col_ocg_locked:        "Gesperrt",
    col_ocg_pages:         "Seiten",

    // Content Stream
    cs_expl:               "<b>Content-Stream-Validierung:</b> Prüft PDF-Operatoren gegen ISO 32000, erkennt unbekannte Operatoren, q/Q-Ungleichgewicht und verdächtige Patterns.",
    lbl_cs_pages:          "Geprüfte Seiten",
    lbl_cs_operators:      "Operatoren gesamt",
    lbl_cs_unknown:        "Unbekannte Operatoren",
    lbl_cs_suspicious:     "Verdächtige Patterns",
    lbl_cs_balance:        "q/Q-Balance",
    sub_cs_issues:         "Content-Stream-Probleme",

    // Incremental Diff
    id_expl:               "<b>Inkrementelles Diffing:</b> Zeigt konkret welche Objekte zwischen Revisionen hinzugefügt, geändert oder entfernt wurden.",
    lbl_id_revisions:      "Revisionen",
    lbl_id_added:          "Hinzugefügt",
    lbl_id_modified:       "Geändert",
    lbl_id_removed:        "Entfernt",
    sub_id_changes:        "Änderungen pro Revision",
    col_id_rev:            "Rev.",
    col_id_added:          "Hinzugefügt",
    col_id_modified:       "Geändert",
    col_id_removed:        "Entfernt",
    col_id_types:          "Geänderte Typen",

    // Fuzzy Hash
    fh_expl:               "<b>Fuzzy Hashing:</b> ssdeep (CTPH) und TLSH erzeugen Ähnlichkeits-Hashes. Ähnliche Dokumente haben ähnliche Fuzzy-Hashes — auch wenn Bytes verändert wurden.",
    lbl_fh_ssdeep:         "ssdeep-Hash",
    lbl_fh_tlsh:           "TLSH-Hash",
    lbl_fh_available:      "Verfügbar",

    // Cross-Analyzer
    ca_expl:               "<b>Cross-Analyzer Intelligence:</b> Korreliert Ergebnisse aller Analyzer — Zeitlinien-Rekonstruktion, Creator-Profiling, automatische Korrelationen und gewichteter Manipulations-Score.",
    lbl_ca_score:          "Manipulations-Score",
    lbl_ca_correlations:   "Korrelationen",
    lbl_ca_confidence:     "Creator-Profil Konfidenz",
    sub_ca_timeline:       "Rekonstruierte Zeitlinie",
    sub_ca_profile:        "Creator-Profil",
    sub_ca_correlations:   "Gefundene Korrelationen",
    col_ca_time:           "Zeitstempel",
    col_ca_source:         "Quelle",
    col_ca_event:          "Ereignis",
    col_ca_title:          "Befund",
    col_ca_severity:       "Schwere",
    col_ca_analyzers:      "Beteiligte Analyzer",
    col_ca_conclusion:     "Schlussfolgerung",

    // Chain of Custody
    coc_expl:              "<b>Chain of Custody:</b> Dokumentiert Evidenz-Integrität für gerichtliche Verwertbarkeit — Prüfer, Fall-Nr., Hash-Verifikation und Audit-Log aller Analysen.",
    lbl_coc_examiner:      "Prüfer",
    lbl_coc_case:          "Fall-Nr.",
    lbl_coc_integrity:     "Evidenz-Integrität",
    lbl_coc_hash_match:    "Hash-Übereinstimmung",
    lbl_coc_analyzers_run: "Analyzer ausgeführt",
    sub_coc_audit:         "Audit-Log",
    col_coc_analyzer:      "Analyzer",
    col_coc_status:        "Status",
    col_coc_duration:      "Dauer",
    coc_integrity_ok:      "Intakt — Datei unverändert",
    coc_integrity_fail:    "Kompromittiert — Datei wurde verändert!",

    // Phase 6 — Extended Forensics (DE)
    sec_yara:              "YARA Malware-Scan",
    sec_font_forensics:    "Font-Forensik",
    sec_pdfa_compliance:   "PDF/A & PDF/X Compliance",
    sec_linearization:     "Linearisierung (Web-Optimierung)",
    sec_icc_profiles:      "ICC-Farbprofile",
    sec_visual_render:     "Visueller Render-Vergleich",
    sec_object_graph:      "PDF-Objekt-Graph",
    sec_cross_doc_fp:      "Cross-Document Fingerprint",
    sec_printer_forensics: "Drucker-Forensik",

    // YARA
    yara_expl:             "<b>YARA Malware-Scan:</b> Scannt die PDF-Datei mit spezialisierten YARA-Regeln gegen JavaScript-Verschleierung, CVE-Exploits, Shellcode, Phishing und eingebettete Executables.",
    lbl_yara_available:    "YARA verfügbar",
    lbl_yara_rules:        "Geladene Regeln",
    lbl_yara_matches:      "Treffer gesamt",
    lbl_yara_critical:     "Kritische Treffer",
    lbl_yara_high:         "Hohe Treffer",
    sub_yara_matches:      "YARA-Treffer",
    col_yara_rule:         "Regel",
    col_yara_severity:     "Schwere",
    col_yara_category:     "Kategorie",
    col_yara_desc:         "Beschreibung",
    yara_no_matches:       "Keine YARA-Treffer — Datei ist sauber.",

    // Font Forensics
    ff_expl:               "<b>Font-Forensik:</b> Analysiert eingebettete Schriftarten — Subset-Erkennung, Font-Herkunft (Microsoft/Apple/Adobe/Google/LaTeX), Einbettungsstatus und verdächtige Fonts.",
    lbl_ff_total:          "Schriftarten gesamt",
    lbl_ff_embedded:       "Eingebettet",
    lbl_ff_subset:         "Subset (teilweise eingebettet)",
    lbl_ff_system:         "System-Fonts (nicht eingebettet)",
    lbl_ff_type1:          "Type1",
    lbl_ff_truetype:       "TrueType",
    lbl_ff_creators:       "Font-Herkunft",
    sub_ff_fonts:          "Font-Details",
    sub_ff_suspicious:     "Verdächtige Fonts",
    col_ff_name:           "Font-Name",
    col_ff_type:           "Typ",
    col_ff_embedded:       "Eingebettet",
    col_ff_subset:         "Subset",
    col_ff_origin:         "Herkunft",
    col_ff_pages:          "Seiten",

    // PDF/A & PDF/X
    pdfa_expl:             "<b>PDF/A & PDF/X Compliance:</b> Prüft Konformität mit Archivierungs- (PDF/A) und Druckstandards (PDF/X) — XMP-Metadaten, Font-Einbettung, JavaScript-Verbot, Verschlüsselungsverbot.",
    lbl_pdfa_claimed:      "PDF/A beansprucht",
    lbl_pdfa_version:      "PDF/A Version",
    lbl_pdfa_conformance:  "Konformitätsstufe",
    lbl_pdfx_claimed:      "PDF/X beansprucht",
    lbl_pdfx_version:      "PDF/X Version",
    lbl_pdfa_issues:       "Compliance-Probleme",
    lbl_pdfa_passes:       "Bestandene Prüfungen",
    lbl_pdfa_output_intent:"Output Intent",
    sub_pdfa_issues:       "Compliance-Probleme",
    sub_pdfa_passes:       "Bestandene Prüfungen",
    col_pdfa_check:        "Prüfung",
    col_pdfa_status:       "Status",
    col_pdfa_detail:       "Detail",

    // Linearization
    lin_expl:              "<b>Linearisierung:</b> Prüft ob das PDF für Fast Web View optimiert wurde. Dateigröße-Diskrepanzen nach Linearisierung zeigen nachträgliche Modifikation.",
    lbl_lin_linearized:    "Linearisiert",
    lbl_lin_version:       "Linearisierungs-Version",
    lbl_lin_file_declared: "Deklarierte Dateigröße",
    lbl_lin_file_actual:   "Tatsächliche Dateigröße",
    lbl_lin_mismatch:      "Größen-Diskrepanz",
    lbl_lin_hint_table:    "Hint-Tabelle",
    lbl_lin_first_page:    "Erstes Seiten-Objekt",
    lbl_lin_pages:         "Deklarierte Seiten",
    lin_not_linearized:    "Nicht linearisiert",

    // ICC
    icc_expl:              "<b>ICC-Farbprofile:</b> Extrahiert eingebettete ICC-Profile und zeigt Geräte-, Software- und Plattforminformationen — forensisch relevant da sie den Erstellungs-Workflow verraten.",
    lbl_icc_count:         "Profile gefunden",
    lbl_icc_colorspaces:   "Verwendete Farbräume",
    sub_icc_profiles:      "ICC-Profile",
    col_icc_name:          "Profilname",
    col_icc_version:       "Version",
    col_icc_class:         "Geräteklasse",
    col_icc_colorspace:    "Farbraum",
    col_icc_platform:      "Plattform",
    col_icc_creator:       "Ersteller",
    col_icc_date:          "Erstellungsdatum",
    col_icc_source:        "Quelle",
    icc_no_profiles:       "Keine ICC-Profile gefunden.",

    // Visual Render
    vr_expl:               "<b>Visueller Render-Vergleich:</b> Rendert alle Seiten und erstellt SHA256-Hashes des visuellen Inhalts. Erkennt leere Seiten, duplizierte Seiten und visuelle Unterschiede.",
    lbl_vr_available:      "Render verfügbar",
    lbl_vr_pages:          "Gerenderte Seiten",
    lbl_vr_blank:          "Leere Seiten",
    lbl_vr_duplicates:     "Duplizierte Seiten",
    lbl_vr_renderer:       "Renderer",
    lbl_vr_dpi:            "Auflösung (DPI)",
    sub_vr_hashes:         "Seiten-Hashes",
    col_vr_page:           "Seite",
    col_vr_hash:           "Visueller Hash",
    col_vr_blank:          "Leer",

    // Object Graph
    og_expl:               "<b>PDF-Objekt-Graph:</b> Traversiert den PDF-Objektbaum von der Wurzel (Catalog). Erkennt zirkuläre Referenzen und ungewöhnlich tiefe Verschachtelung.",
    lbl_og_objects:        "Objekte gesamt",
    lbl_og_max_depth:      "Max. Tiefe",
    lbl_og_types:          "Objekttypen",
    lbl_og_circular:       "Zirkuläre Referenzen",
    sub_og_types:          "Objekttyp-Verteilung",
    sub_og_catalog:        "Catalog-Info",
    col_og_type:           "Typ",
    col_og_count:          "Anzahl",

    // Cross-Doc Fingerprint
    cdf_expl:              "<b>Cross-Document Fingerprint:</b> Erstellt einen 5-dimensionalen Fingerprint (Struktur, Fonts, Metadaten, Style, Inhalt) für Ähnlichkeitsvergleiche über Dokumentensammlungen.",
    lbl_cdf_version:       "Fingerprint-Version",
    lbl_cdf_struct:        "Struktur-Hash",
    lbl_cdf_font:          "Font-Hash",
    lbl_cdf_meta:          "Metadaten-Hash",
    lbl_cdf_style:         "Style-Hash",
    lbl_cdf_content:       "Content-Hash",

    // Printer Forensics
    pf_expl:               "<b>Drucker-Forensik:</b> Erkennt gescannte Dokumente durch Vollseitenbilder, DPI-Analyse, Halftone-Raster (Laserdrucker), Banding und CCITT/JBIG2-Filter.",
    lbl_pf_scanned:        "Gescanntes Dokument",
    lbl_pf_confidence:     "Scan-Konfidenz",
    lbl_pf_printer_type:   "Druckertyp",
    lbl_pf_dpi:            "Erkannte DPI",
    lbl_pf_halftone:       "Halftone-Raster",
    lbl_pf_banding:        "Drucker-Banding",
    lbl_pf_images:         "Analysierte Bilder",
    sub_pf_indicators:     "Scan-Indikatoren",

    // Charts extra
    charts_no_anomalies:   "Keine Anomalien gefunden",
    charts_no_categories:  "Keine Kategorien",
    charts_no_findings:    "Keine Befunde",
    charts_no_structure:   "Keine Strukturdaten",
    charts_no_analyzer_data: "Keine Analyzer-Daten",
    score_safe:            "SICHER",
    score_warning:         "WARNUNG",
    score_critical:        "KRITISCH",
    phase_basis:           "Basis",
    phase_structure:       "Struktur",
    phase_image:           "Bild",
    phase_ioc_text:        "IOC/Text",
    phase_deep:            "Deep",
    phase_extended:        "Extended",
    lbl_images:            "Bilder",
    err_unknown:           "Unbekannter Fehler",

    // Chat
    nav_chat:              "KI-Chat",
    chat_no_doc:           "Kein Dokument geladen",
    chat_welcome:          "Ich bin dein forensischer Assistent. Lade ein Dokument und stelle mir Fragen dazu.",
    chat_placeholder:      "Frage zum Bericht…",
  },

  en: {
    // App
    app_name: "PDF Forensics",

    // Navbar
    nav_analyse:  "Analyse",
    nav_verlauf:  "History",
    nav_vergleich:"Compare",
    nav_lang_btn: "DE",
    nav_lang_title:"Auf Deutsch wechseln",

    // Upload
    upload_drop:  "Drop PDF here or",
    upload_btn:   "Choose file",
    upload_hint:  "Max 200 MB · PDF files only",
    upload_progress: "Analysing PDF…",
    step_hash:    "HASH",
    step_meta:    "META",
    step_img:     "IMG",
    step_uuid:    "UUID",
    step_sig:     "SIG",
    step_fp:      "FP",

    // Risk Banner
    btn_download_report: "PDF Report",
    btn_add_compare:     "Compare",
    btn_ai_review:       "🤖 AI Assessment",

    // KI-Review Panel
    ai_confidence:       "Confidence:",
    ai_legit:            "Legitimacy:",
    ai_laien_title:      "💬 In simple words",
    ai_behavior_short:   "What to do?",
    ai_expert_details:   "Expert mode — Show all technical details",
    ai_summary:          "Summary",
    ai_found:            "🔍 What was found",
    ai_recognize:        "💡 What can be recognized",
    ai_conclude:         "🧠 Forensic conclusions",
    ai_findings:         "Main findings",
    ai_manipulation:     "⚠ Manipulation indicators",
    ai_behavior:         "🛡 Recommended action",
    ai_doc_assessment:   "📄 Document content assessment",
    ai_further_tests:    "🧪 Suggested further tests",
    ai_extensions:       "💡 Extension suggestions",
    ai_recommendations:  "Recommendations",
    ai_risk_explanation: "Risk explanation",
    ai_conclusion:       "✅ Conclusion",
    ai_technical_details:"Technical details",
    ai_model_prefix:     "Model:",

    // Sections
    sec_virusscan:      "Virus Scan",
    sec_hashes:         "Cryptographic Hashes",
    sec_metadata:       "PDF Metadata",
    sec_software:       "Software Fingerprint",
    sec_uuid:           "UUID Analysis",
    sec_signature:      "Digital Signatures",
    sec_geometry:       "Page Geometry",
    sec_pagelabels:     "Page Labels",
    sec_images:         "Embedded Images",
    sec_encryption:     "Encryption",
    sec_incremental:    "Revisions / Incremental Updates",
    sec_javascript:     "JavaScript & Actions",
    sec_embedded:       "Embedded Files & Annotations",
    sec_anomalies:      "Anomalies",

    // Virus-Scan
    vs_clean:           "No threats detected",
    vs_infected:        "Detections — Potentially malicious!",
    vs_unavailable:     "Not available",
    vs_not_scanned:     "Not scanned",
    vs_clean_status:    "Clean",
    vs_detections:      "detections",
    vs_more:            "… and {n} more",
    vs_vt_link:         "View on VirusTotal",
    vs_expl: `<b>What is checked?</b> The PDF file is scanned against known malware signatures.
      <b>ClamAV</b> runs locally — no upload to third parties.
      <b>VirusTotal</b> checks with 70+ antivirus engines (only if API key is configured).`,

    // Hashes
    hash_expl: `<b>What are hashes?</b> Cryptographic checksums of the entire PDF content. Change even 1 byte and all hashes change completely — making them a reliable file fingerprint.<br><b>How to use:</b> Copy the SHA-256 hash and compare it with the hash from a trusted source (e.g. the original sender, an official database, or VirusTotal). If the hashes match, the file is byte-identical and has not been tampered with.`,
    hash_copy: "Hash copied!",

    // Metadata
    meta_expl: `<b>What is PDF metadata?</b> Every PDF contains an /Info dictionary with creation software, dates, and author. These are frequently manipulated in forged documents — e.g. by backdating or removing the author. We also check XMP metadata for contradictions with the /Info dictionary.`,

    // Software
    sw_expl: `<b>What is the Software Fingerprint?</b> The "Producer" string reveals the PDF export engine. "Creator" shows the source application. If Creator and Producer don't match, the document was converted or post-processed.`,

    // UUID
    uuid_expl: `<b>What are UUID v1 timestamps?</b> UUID version 1 contains an exact timestamp (100ns precision). If this timestamp strongly deviates from the CreationDate, it indicates manipulation — the document was created at a different time than claimed.`,

    // Signature
    sig_expl: `<b>What are digital signatures?</b> PDFs can be cryptographically signed. /DocMDP defines what changes are allowed after signing. If a signature field exists but no AcroForm, the document is inconsistent — a sign of manipulation.`,

    // Geometry
    geo_expl: `<b>What does page geometry check?</b> MediaBox = page size in points (1pt = 1/72 inch). Standard A4 = 595×842pt. Different page sizes within one document may indicate merged PDFs from different sources.`,

    // PageLabels
    pl_expl: `<b>What are PageLabels?</b> PDFs can define custom page numbering. If the declared page count doesn't match the actual one, it's a strong indicator of post-hoc page manipulation.`,

    // Images
    img_expl: `<b>What is checked for images?</b> EXIF data can contain camera model, GPS coordinates and original capture date — often forgotten when forging. Quantization tables are a software fingerprint. Ghostscript-typical tables suggest image recompression.`,

    // Encryption
    enc_expl: `<b>What does encryption analysis check?</b> RC4-40bit is trivially breakable. RC4-128bit is considered weak. AES-128/256 are secure. A locked document may still have been manipulated if metadata remains unencrypted.`,

    // Incremental Updates
    inc_expl: `<b>What are incremental updates?</b> PDFs can be extended without full recreation — the original content is preserved and new objects appended. More than 1 revision = possible post-modification, often to bypass a signature.`,

    // JavaScript
    js_expl: `<b>What is checked?</b> /OpenAction executes automatically when the PDF is opened. /Launch starts external programs. /JS = embedded JavaScript code. Rarely found in legitimate documents — possible exploit vectors.`,

    // Embedded Files
    ef_expl: `<b>What is checked?</b> PDFs can embed other files — including executables (.exe, .dll, .bat). Annotations can contain hidden metadata or links to external servers. Object streams can obfuscate content.`,

    // Upload errors
    err_not_pdf:   "Only PDF files are accepted.",
    err_too_large: "File too large (max 200 MB).",
    analysis_done: "Analysis complete!",

    // History
    hist_title:       "Analysis History",
    hist_subtitle:    "All previous PDF analyses",
    hist_search_ph:   "Search filename, hash or risk level…",
    hist_search_btn:  "Search",
    hist_empty:       "No analyses yet.",
    hist_view:        "View",
    hist_delete:      "Delete",
    hist_confirm_del: "Really delete this analysis?",

    // Compare
    cmp_title:        "Document Compare",
    cmp_subtitle:     "Compare 2-4 analysed PDFs side by side",
    cmp_select:       "Select Document {n}",
    cmp_add_slot:     "+ Add Document",
    cmp_run:          "Start Compare",
    cmp_running:      "Comparing…",
    cmp_summary:      "Comparison Overview",
    cmp_timeline:     "Creation Timeline",
    cmp_table:        "Attribute Comparison",
    cmp_anomalies:    "Comparison Anomalies",
    cmp_software:     "Software Matches",
    cmp_uuid:         "UUID Cluster (same machine)",
    cmp_metadiff:     "Metadata Differences",
    cmp_report_btn:   "Download Comparison Report",
    cmp_pick_title:   "Select Analysis",
    cmp_pick_search:  "Search filename…",
    cmp_select_docs:  "Select Documents",
    cmp_select_hint:  "Choose from history or enter IDs",

    // Compare — dynamically generated keys
    cmp_failed:           "Comparison failed",
    cmp_attr_col:         "Attribute",
    cmp_doc_prefix:       "Doc.",
    cmp_attr_risk:        "Risk",
    cmp_attr_high:        "HIGH Anomalies",
    cmp_attr_medium:      "MEDIUM Anomalies",
    cmp_attr_encrypted:   "Encrypted",
    cmp_sum_docs:         "Documents",
    cmp_sum_hashes:       "Identical Hashes",
    cmp_sum_time:         "Time Proximity Flags",
    cmp_sum_uuid:         "UUID Clusters",
    cmp_sum_software:     "Software Matches",
    cmp_sum_metadiff:     "Metadata Differences",
    cmp_sum_anomalies:    "Comparison Anomalies",
    cmp_sum_common_cats:  "Common Anomaly Categories",
    cmp_hits:             "hits",
    cmp_cluster:          "cluster",
    cmp_found:            "found",
    cmp_fields:           "fields",
    cmp_uuid_warning:     "Same UUIDs found in multiple documents — these documents were likely created on the same machine or in the same session.",
    cmp_metadiff_intro:   "Fields that have different values across the documents:",
    cmp_no_analyses:      "No analyses available",
    cmp_doc_id_a:         "Doc-ID A",
    cmp_doc_id_b:         "Doc-ID B",

    // Page titles / subtitles
    page_analyse_title:    "Forensic PDF Analysis",
    page_analyse_subtitle: "Metadata · Hashes · Images · UUID Decoder · Signature Detection · Software Fingerprint",

    // History extended
    hist_subtitle_full:          "All saved forensic analyses",
    hist_loading:                "Loading history…",
    hist_date_from:              "From",
    hist_date_to:                "To",
    hist_reset_btn:              "Reset",
    hist_load_error:             "Failed to load history",
    hist_search_error:           "Search failed",
    hist_analyses_found_plural:  "analyses found",
    hist_analyses_found_singular:"analysis found",
    hist_empty_hint:             "Analyse a PDF on the main page",
    hist_download_report:        "Download report",
    hist_confirm_del_prefix:     "Really delete analysis",
    hist_delete_error:           "Delete failed",

    // Loading / generic
    loading:                "Loading…",
    loading_saved_analysis: "Loading saved analysis…",
    analysis_not_found:     "Analysis not found",
    no_data:                "No data",

    // Labels — field names in tables
    lbl_filesize:          "File size",
    lbl_pdf_version:       "PDF version",
    lbl_pages:             "Pages",
    lbl_title:             "Title",
    lbl_author:            "Author",
    lbl_subject:           "Subject",
    lbl_keywords:          "Keywords",
    lbl_created_raw:       "Created (raw)",
    lbl_created:           "Created",
    lbl_modified_raw:      "Modified (raw)",
    lbl_modified:          "Modified",
    lbl_identified_tool:   "Identified Tool",
    lbl_category:          "Category",
    lbl_version:           "Version",
    lbl_found_uuid_v1:     "Found UUID v1",
    lbl_acroform:          "AcroForm",
    lbl_sig_field:         "Signature Field",
    lbl_docmdp:            "DocMDP",
    lbl_sig_names:         "Sig Field Names",
    lbl_signature:         "Signature",
    lbl_mixed_sizes:       "Mixed Sizes",
    lbl_unique_formats:    "Unique Formats",
    lbl_total_pages:       "Total Pages",
    lbl_extracted_images:  "Extracted Images",
    lbl_ghostscript_quant: "Ghostscript Quant.",
    lbl_extraction_method: "Extraction Method",
    lbl_status:            "Status",
    lbl_algorithm:         "Algorithm",
    lbl_key_length:        "Key Length",
    lbl_strength:          "Strength",
    lbl_meta_enc:          "Metadata enc.",
    lbl_print:             "Print",
    lbl_edit:              "Edit",
    lbl_copy:              "Copy",
    lbl_annotate:          "Annotate",
    lbl_forms:             "Forms",
    lbl_print_hires:       "High-res Print",
    lbl_revisions:         "Revisions",
    lbl_data_after_eof:    "Data after EOF",
    lbl_javascript:        "JavaScript",
    lbl_auto_execute:      "Auto-Execute",
    lbl_total_actions:     "Total Actions",
    lbl_js_snippets:       "JS Snippets",
    lbl_embedded_files:    "Embedded Files",
    lbl_annotations:       "Total Annotations",
    lbl_hidden_annotations:"Hidden Annotations",
    lbl_obj_streams:       "Object Streams",
    lbl_analysiert:        "Analysed",

    // Column headers
    col_uuid:           "UUID",
    col_uuid_timestamp: "Timestamp (from UUID)",
    col_uuid_delta:     "Δ to CreationDate",
    col_uuid_verdict:   "Verdict",
    col_page:           "Page",
    col_wh_pt:          "Width × Height (pt)",
    col_a4:             "A4",
    col_orientation:    "Orientation",
    col_revision:       "Revision",
    col_size:           "Size",
    col_xref_type:      "xref Type",
    col_new_objects:    "New Objects",
    col_byte_offset:    "Byte Offset",
    col_location:       "Location",
    col_type:           "Type",
    col_auto_execute:   "Auto-Execute",
    col_filename:       "Filename",
    col_mime:           "MIME",
    col_sha256:         "SHA256",
    col_cert_field:     "Field",
    col_cert_subject:   "Subject",
    col_cert_issuer:    "Issuer",
    col_cert_serial:    "Serial Number",
    col_cert_valid_from:"Valid From",
    col_cert_valid_until:"Valid Until",
    col_cert_sha1fp:    "SHA1 Fingerprint",

    // Sub-headers
    sub_xmp_metadata:     "XMP Metadata",
    sub_cert_details:     "Certificate Details",
    sub_permissions:      "Permissions",
    sub_revision_details: "Revision Details",
    sub_found_actions:    "Found Actions",
    sub_js_snippets:      "JavaScript Snippets (first 500 characters)",
    sub_embedded_files:   "Embedded Files",

    // Status / value texts
    enc_not_encrypted:      "Not encrypted",
    enc_password_protected: "Password protected",
    enc_encrypted_no_pw:    "Encrypted (no user password)",
    enc_meta_unencrypted:   "No — XMP metadata unencrypted!",
    present_warning:        "PRESENT",
    present:                "Present",
    not_present:            "Not present",
    auto_exec_yes:          "YES — executes on open!",
    auto_exec_short:        "YES",
    no_clean:               "No",
    yes_clean:              "Yes",
    none_clean:             "None",
    rev_one_clean:          "1 (unchanged)",
    revisions_count:        "Revisions",
    bytes_after_eof:        "bytes after %%EOF",
    rev_current:            "current",
    ghostscript_detected:   "Detected — images were recompressed",
    not_detected:           "Not detected",
    geo_mixed_yes:          "Yes — different formats!",
    perm_allowed:           "Allowed",
    perm_denied:            "Denied",
    file_count_suffix:      "file(s)",
    cert_expired:           "Certificate expired!",
    uuid_none_found:        "No UUID v1 found in document — no Word/Office fingerprint present.",
    uuid_consistent:        "Consistent",
    uuid_strongly_deviating:"Strongly deviating ({delta}s)",
    uuid_slightly_deviating:"Slightly deviating ({delta}s)",
    no_jpeg_images:         "No embedded JPEG images found.",

    // Tooltip texts
    xmp_tooltip: "XMP is a second metadata store in the PDF. Contradictions between XMP and /Info dictionary indicate manipulation.",
    xmp_what:    "What is XMP?",
    cert_tooltip: "The digital certificate confirms the signer's identity. Expired or unknown certificates are a warning sign.",
    cert_what:   "What does this mean?",

    // General new labels (EN)
    upload_hint:        "Max 200 MB · PDF, DOCX, XLSX, PPTX, DOC, ODT",
    err_not_supported:  "Unsupported file format. Allowed: PDF, DOCX, XLSX, PPTX, DOC, XLS, PPT, ODT.",
    err_not_pdf:        "Only PDF files accepted.",

    // Phase 2 — OOXML / OLE (EN)
    sec_ooxml:          "OOXML Forensics (DOCX/XLSX/PPTX)",
    sec_ole:            "OLE2 Forensics (DOC/XLS/PPT)",

    ooxml_expl: "<b>OOXML Forensics:</b> The Open XML format (ZIP container) contains Core Properties, App Properties, Revision IDs (RSID), Track Changes authors, and macros — forensically highly relevant.",
    ole_expl:   "<b>OLE2 Forensics:</b> The older Compound File Binary format contains SummaryInformation streams with author, timestamps, revision numbers, and company data.",

    lbl_format:         "Format",
    lbl_last_mod_by:    "Last Modified By",
    lbl_revision:       "Revision",
    lbl_application:    "Application",
    lbl_app_version:    "App Version",
    lbl_company:        "Company",
    lbl_template:       "Template",
    lbl_rsid_count:     "RSID Sessions",
    lbl_tc_authors:     "Track Changes Authors",
    lbl_external_links: "External Links",
    lbl_media_files:    "Media Files",
    lbl_words:          "Words",

    sub_track_changes:  "Track Changes",
    sub_rsids:          "Revision IDs (RSID)",
    sub_external_links: "External Links",
    sub_custom_props:   "Custom Properties",
    sub_ole_strings:    "Found Strings (Paths/Names/Applications)",

    rsid_total:         "total",
    more:               "more",
    col_author:         "Author",
    col_date:           "Date",
    col_text:           "Content",

    // Phase 1 — new sections (EN)
    sec_timezone:        "Timezone Analysis",
    sec_author_artifacts:"Author Artifacts",
    sec_ela:             "ELA & Copy-Move",
    sec_object_streams:  "Object Streams",
    sec_residual:        "Residual Objects",
    sec_shadow_attack:   "Shadow Attack",

    // Timezone
    tz_expl: "<b>What is analyzed?</b> All date fields in the PDF are extracted, UTC offsets compared, and a probable geographic region is inferred.",
    lbl_tz_region:      "Probable Region",
    lbl_tz_consistent:  "Timezones Consistent",
    lbl_tz_dates_found: "Date Fields Found",
    no_timezone_data:   "No date fields found in PDF.",
    tz_inconsistent:    "Inconsistent — different offsets",
    col_tz_source:      "Field",
    col_tz_local:       "Local Time",
    col_tz_utc:         "UTC",
    col_tz_offset:      "Offset",
    col_tz_region:      "Region",

    // Author Artifacts
    aa_expl: "<b>What is searched?</b> Hidden author hints: font subset prefixes (session-unique), XMP paths, annotation authors, form data, printer names.",
    lbl_font_prefixes:     "Font Subset Prefixes",
    lbl_xmp_author_hints:  "XMP Author Hints",
    lbl_annotation_authors:"Annotation Authors",
    lbl_paths_found:       "File Paths Found",
    lbl_emails_found:      "Email Addresses Found",
    lbl_printer_name:      "Printer Name",
    no_author_artifacts:   "No author artifacts found.",
    sub_font_prefixes:     "Font Subset Prefixes",
    sub_author_artifacts:  "Found Artifacts",
    col_prefix:            "Prefix",
    col_font_name:         "Font Name",
    col_source:            "Source",
    col_value:             "Value",

    // ELA
    ela_expl: "<b>Error Level Analysis:</b> Images are recompressed and the pixel difference analyzed. High-difference areas = possible compositing. Copy-Move detection searches for copied image blocks.",
    ela_unavailable:       "ELA not available (Pillow not installed).",
    ela_no_images:         "No JPEG images in PDF for ELA analysis.",
    lbl_images_checked:    "Images Analyzed",
    lbl_suspicious_images: "Suspicious Images",
    lbl_copy_move_detected:"Copy-Move Hits",
    ela_difference_image:  "ELA Difference Image",
    lbl_ela_mean:          "ELA Mean",
    lbl_ela_max:           "ELA Max",
    lbl_dup_blocks:        "duplicate blocks",
    lbl_image:             "Image",

    // Object Streams
    os_expl: "<b>Object Streams (ObjStm):</b> PDF 1.5+ can pack objects compressed in streams. Hidden JS objects or duplicate object IDs (shadow technique) are forensically relevant.",
    lbl_obj_stream_count:  "ObjStm Objects",
    lbl_xref_type:         "xref Type",
    lbl_hybrid_xref:       "Hybrid xref",
    lbl_duplicate_objects: "Duplicate Object IDs",
    sub_suspicious_streams:"Suspicious Object Streams",
    sub_duplicate_objs:    "Duplicate Object Definitions",
    lbl_objstm:            "ObjStm",
    lbl_suspicious_keys:   "Suspicious Keys",
    has_javascript:        "JavaScript/JS found",
    obj_count_suffix:      "object(s)",
    lbl_obj:               "Object",

    // Residual Objects
    ro_expl: "<b>Residual Objects (Carving):</b> Objects present in the PDF byte stream that are no longer referenced in the xref table — may contain deleted text, old metadata, or hidden code.",
    lbl_orphaned_objects:  "Orphaned Objects",
    lbl_trailing_data:     "Data After %%EOF",
    lbl_eof_count:         "%%EOF Markers",
    sub_orphaned_objects:  "Orphaned Objects (Details)",
    sub_trailing_data:     "Data After %%EOF",
    col_obj_num:           "Object #",
    col_type_hint:         "Type",
    col_flags:             "Content Flags",
    col_preview:           "Preview",
    col_trailing_bytes:    "Bytes",
    col_hex_preview:       "Hex Preview",
    col_text_preview:      "Text Preview",
    bytes_suffix:          "bytes",

    // Shadow Attack
    sa_expl: "<b>Shadow Attack:</b> Detects whether the signature ByteRange does not cover the entire document (Shadow Attack), whether objects were inserted after the signature (ISA), or whether the signature container is incorrectly referenced.",
    shadow_no_signature:   "No signature field — Shadow Attack analysis not applicable.",
    lbl_shadow_attack:     "Shadow Attack",
    lbl_isa_attack:        "ISA (Incremental Saving Attack)",
    lbl_sig_wrapping:      "Signature Wrapping",
    lbl_sig_count:         "Signatures",
    shadow_suspicious:     "SUSPICIOUS",
    shadow_clean:          "Clean",
    isa_suspicious:        "SUSPICIOUS",
    isa_clean:             "Clean",
    wrap_suspicious:       "SUSPICIOUS",
    wrap_clean:            "Clean",
    sub_byte_range_analysis: "ByteRange Details",
    sub_isa_analysis:      "ISA Analysis",
    col_prefix_bytes:      "Bytes Before Signature",
    col_suffix_bytes:      "Bytes After Signature",
    col_covers_full:       "Covers Entire Document",
    yes:                   "Yes",
    no:                    "No",

    // Phase 3 — Image Forensics
    sec_image_forensics:   "Image Forensics",
    sec_steganography:     "Steganography Analysis",
    img_forensics_expl:    "<b>Image Forensics:</b> EXIF metadata analysis, Error Level Analysis (ELA), Copy-Move detection, PRNU noise profile, double-compression test and AI image detection.",
    img_no_exif:           "No EXIF metadata found.",
    img_ela_title:         "Error Level Analysis (ELA)",
    img_ela_mean:          "Mean ELA Value",
    img_ela_max:           "Max ELA Value",
    img_ela_hot_regions:   "Suspicious Regions",
    img_copymove_title:    "Copy-Move Detection (DCT)",
    img_copymove_blocks:   "Blocks Checked",
    img_copymove_matches:  "Duplicate Block Pairs",
    img_copymove_suspected:"Suspected",
    img_prnu_title:        "PRNU Noise Profile",
    img_prnu_noise_std:    "Noise Std Dev",
    img_prnu_inconsistent: "Inconsistent Noise Profile",
    img_dc_title:          "Double Compression (JPEG)",
    img_dc_suspected:      "Double Compression Detected",
    img_dc_est_quality:    "Estimated Original Quality",
    img_thumb_title:       "Thumbnail Consistency",
    img_thumb_mismatch:    "Thumbnail/Main Image Mismatch",
    img_ai_title:          "AI Image Detection",
    img_ai_score:          "AI Score",
    img_ai_verdict:        "Verdict",
    steg_expl:             "<b>Steganography Analysis:</b> LSB Chi-Square test, RS-analysis (Fridrich et al.), PNG chunk inspection and JPEG trailing-data detection.",
    steg_chi_title:        "LSB Chi-Square Test",
    steg_capacity_kb:      "LSB Capacity",
    steg_suspected:        "Suspected",
    steg_rs_title:         "RS-Analysis (Fridrich)",
    steg_rs_fill:          "Estimated LSB Fill",
    steg_png_title:        "PNG Chunk Analysis",
    steg_png_chunks:       "Total Chunks",
    steg_png_unknown:      "Unknown Chunks",
    steg_png_trailing:     "Trailing Data After IEND",
    steg_png_textchunks:   "Text Chunks",
    steg_jpeg_title:       "JPEG Trailing Data",
    steg_jpeg_trailing:    "Data After EOI Marker",
    upload_hint:           "Max 200 MB · PDF, DOCX, XLSX, PPTX, DOC, ODT, JPEG, PNG",

    // Phase 4 — IOC
    sec_ioc:               "IOC Extraction",
    ioc_expl:              "<b>Network Indicators of Compromise:</b> URLs, IP addresses, email addresses and domains from all PDF areas (streams, metadata, JavaScript, annotations). Suspicious TLDs and URL shorteners are highlighted in red.",
    lbl_ioc_total:         "Total IOCs",
    lbl_ioc_urls:          "URLs",
    lbl_ioc_ips:           "IP Addresses",
    lbl_ioc_emails:        "Email Addresses",
    lbl_ioc_suspicious:    "Suspicious IOCs",
    col_ioc_url:           "URL",
    col_ioc_suspicious:    "Suspicious",
    col_ioc_source:        "Source",
    col_ioc_ip:            "IP Address",
    col_ioc_type:          "Type",
    ioc_internal_ip:       "Internal",
    ioc_external_ip:       "External",
    ioc_no_iocs:           "No IOCs found.",
    sub_ioc_urls:          "URLs",
    sub_ioc_ips:           "IP Addresses",
    sub_ioc_emails:        "Email Addresses",

    // Phase 4 — Hidden Text
    sec_hidden_text:       "Hidden Text Analysis",
    ht_expl:               "<b>Hidden Text:</b> Analyzes all pages for invisible text — white text on white background, font size < 1pt, Rendering Mode 3 (fully transparent) and off-page text. OCG layers are also listed.",
    lbl_ht_invisible:      "Invisible Text (Mode 3)",
    lbl_ht_white:          "White Text",
    lbl_ht_tiny:           "Tiny Text (<1pt)",
    lbl_ht_ocg:            "OCG Layers",
    col_ht_page:           "Page",
    col_ht_reason:         "Reason",
    col_ht_text:           "Text Preview",
    col_ht_fontsize:       "Font Size",
    ht_no_hidden:          "No hidden text found.",
    sub_ht_blocks:         "Found Blocks",
    sub_ht_ocg:            "OCG Layers (Optional Content)",
    ht_reason_invisible:   "Rendering Mode 3",
    ht_reason_white:       "White Text",
    ht_reason_tiny:        "Tiny (<1pt)",
    ht_reason_off_page:    "Off-Page",

    // Phase 4 — Yellow Dots
    sec_yellow_dots:       "Yellow Dots / MIC",
    yd_expl:               "<b>Machine Identification Code (MIC):</b> Printers encode hidden identification patterns as tiny yellow dots (steganography). Detects Xerox MIC and generic patterns in embedded images.",
    lbl_yd_available:      "Analysis Available",
    lbl_yd_method:         "Method",
    lbl_yd_found:          "Dots Found",
    lbl_yd_count:          "Dot Clusters",
    lbl_yd_pattern:        "Pattern Type",
    lbl_yd_page:           "Page",
    lbl_yd_decoded:        "Decoded Info",
    yd_no_dots:            "No yellow dots found.",
    yd_pattern_xerox:      "Xerox MIC",
    yd_pattern_generic:    "Generic Pattern",

    // Phase 4 — Batch Upload
    batch_title:           "Batch Analysis",
    batch_queue:           "Queue",
    batch_start:           "Analyze All",
    batch_clear:           "Reset",
    batch_status_pending:  "Pending",
    batch_status_analyzing:"Analyzing…",
    batch_status_done:     "Done",
    batch_status_error:    "Error",
    batch_results_title:   "Batch Results",
    batch_files_selected:  "{n} files selected",

    // Phase 4 — Cross-Match
    btn_cross_match_fonts: "Font Cross-Match",
    btn_cross_match_quant: "Quant Cross-Match",
    cross_match_loading:   "Searching…",
    cross_match_no_results:"No matches found in database.",
    cross_match_results:   "{n} matches found",
    col_cm_filename:       "File",
    col_cm_analyzed:       "Analyzed",
    col_cm_risk:           "Risk",
    col_cm_shared:         "Shared Features",

    // Page Labels
    lbl_page_labels:       "Page Labels",
    lbl_declared_pages:    "Declared Pages",
    lbl_actual_pages:      "Actual Pages",
    sub_page_labels:       "Label Ranges",
    col_start_page:        "Start Page",
    col_style:             "Style",
    col_first_value:       "First Value",

    // Author Artifacts — new keys
    sub_xmp_authors:       "XMP Authors",
    sub_annotation_authors:"Annotation Authors",

    // Object Streams — new keys
    col_first_offset:      "First Offset",

    // Encryption — new keys
    lbl_enc_v:             "Encryption Version (V)",
    lbl_enc_r:             "Revision (R)",
    lbl_enc_p:             "Permission Flags (P)",
    lbl_owner_hash:        "Owner Hash",
    lbl_user_hash:         "User Hash",

    // Images — total size
    lbl_total_img_size:    "Total Image Size",

    // Incremental Updates — new columns
    col_start_byte:        "Start Byte",
    col_end_byte:          "End Byte",
    col_xref_offset:       "XRef Offset",

    // Annotations
    sub_annotations:       "Annotation Details",
    col_hidden:            "Hidden",
    col_contents:          "Contents",

    // ELA
    lbl_ela_hot_regions:   "Hot Regions",

    // IOC — Domains
    lbl_ioc_domains:       "Domains",
    sub_ioc_domains:       "Found Domains",

    // Hidden Text — new columns
    col_ht_render_mode:    "Render Mode",
    col_ht_color:          "Color (RGB)",

    // Timezone — new keys
    lbl_tz_unique_offsets: "Unique Offsets",

    // Author Artifacts — new keys
    lbl_form_fields:       "Form Fields",
    sub_form_fields:       "Form Field Hints",
    col_field_name:        "Field Name",

    // Images — new keys
    sub_image_details:     "Image Details (EXIF / Hashes)",
    col_camera:            "Camera",
    col_datetime:          "Date/Time",
    col_img_index:         "Image #",
    col_table_type:        "Table Type",
    col_match_score:       "Match Score",
    col_table_id:          "Table ID",
    sub_quant_matches:     "Quantization Table Matches",
    lbl_images_checked:    "Images Checked",

    // Object Streams — new keys
    sub_obj_streams_list:  "All ObjStm Streams",
    col_stream_len:        "Stream Length",
    col_sub_objects:       "Sub-Objects",
    lbl_occurrences:       "Occurrences",

    // Residual Objects — new keys
    sub_eof_markers:       "EOF Marker Details",

    // Shadow Attack — new keys
    lbl_signed_from:       "Signed From",
    lbl_signed_to:         "Signed To",
    lbl_bytes_after_sig:   "Bytes After Signature",
    lbl_has_xref_after:    "XRef After Signature",
    lbl_has_obj_after:     "Objects After Signature",
    lbl_doc_end_offset:    "Document End (Offset)",
    lbl_file_size:         "File Size",
    lbl_byte_range_occ:    "ByteRange Occurrences",

    // Chart Dashboard
    chart_risk_gauge:      "Risk Level",
    chart_severity:        "Severity Distribution",
    chart_radar:           "Analyzer Radar",
    chart_categories:      "Findings by Category",
    chart_phase_summary:   "Phase Summary",
    chart_security_score:    "Security Score",
    chart_file_structure:    "File Structure",
    chart_analyzer_coverage: "Analyzer Coverage",
    chart_timeline:          "Document Timeline",
    charts_radar_empty:    "Too few categories for radar chart",
    charts_timeline_empty: "Not enough timestamps for timeline",
    lbl_findings:          "Findings",

    // Phase 5 — Advanced Forensics (EN)
    sec_stream_decomp:     "Stream Decompression Analysis",
    sec_xref_validation:   "XRef Deep Validation",
    sec_deep_jpeg:         "Deep JPEG Forensics",
    sec_redaction:         "Redaction Analysis",
    sec_ocg_layers:        "OCG Layers (Optional Content)",
    sec_content_stream:    "Content Stream Validation",
    sec_inc_diff:          "Incremental Update Diffing",
    sec_fuzzy_hash:        "Fuzzy Hashing",
    sec_cross_analyzer:    "Cross-Analyzer Intelligence",
    sec_chain_of_custody:  "Chain of Custody",

    sd_expl:               "<b>Stream Decompression Analysis:</b> All PDF streams are decompressed and scanned for exploit patterns, suspicious filter chains and embedded code.",
    lbl_sd_total_streams:  "Total Streams",
    lbl_sd_decompressed:   "Decompressed",
    lbl_sd_suspicious:     "Suspicious Streams",
    lbl_sd_filters:        "Filter Types",
    sub_sd_suspicious:     "Suspicious Stream Contents",
    col_sd_obj:            "Object",
    col_sd_filter:         "Filter",
    col_sd_size:           "Size",
    col_sd_pattern:        "Pattern Found",

    xref_expl:             "<b>XRef Deep Validation:</b> Checks cross-reference table consistency, subsections, free-object chains and offset validation.",
    lbl_xref_entries:      "XRef Entries",
    lbl_xref_valid:        "Valid Entries",
    lbl_xref_invalid:      "Invalid Entries",
    lbl_xref_free:         "Free Objects",
    lbl_xref_hybrid:       "Hybrid XRef",
    lbl_xref_subsections:  "Subsections",
    sub_xref_issues:       "XRef Issues",
    col_xref_issue:        "Issue",
    col_xref_obj:          "Object",

    dj_expl:               "<b>Deep JPEG Forensics:</b> DCT double-compression, Huffman table comparison, thumbnail validation, JPEG Ghost Detection and PRNU noise profile.",
    lbl_dj_images:         "Images Analyzed",
    lbl_dj_dct:            "DCT Double-Compression",
    lbl_dj_huffman:        "Huffman Anomalies",
    lbl_dj_thumbnail:      "Thumbnail Mismatch",
    lbl_dj_ghost:          "JPEG Ghost Detected",
    lbl_dj_prnu:           "PRNU Inconsistency",
    sub_dj_results:        "Detailed Results",

    red_expl:              "<b>Redaction Analysis:</b> Checks whether redactions are secure — black rectangles over text (insecure), unapplied Redact annotations, extractable text under overlay.",
    lbl_red_found:         "Redactions Found",
    lbl_red_secure:        "Secure Redactions",
    lbl_red_insecure:      "Insecure Redactions",
    sub_red_details:       "Redaction Details",
    col_red_page:          "Page",
    col_red_type:          "Type",
    col_red_secure:        "Secure",
    col_red_note:          "Note",

    ocg_expl:              "<b>OCG Layers:</b> Optional Content Groups can hide content. Hidden or locked layers may contain forensically relevant information.",
    lbl_ocg_count:         "Total OCG Layers",
    lbl_ocg_hidden:        "Hidden Layers",
    lbl_ocg_locked:        "Locked Layers",
    sub_ocg_list:          "Layer Details",
    col_ocg_name:          "Name",
    col_ocg_visible:       "Visible",
    col_ocg_locked:        "Locked",
    col_ocg_pages:         "Pages",

    cs_expl:               "<b>Content Stream Validation:</b> Validates PDF operators against ISO 32000, detects unknown operators, q/Q imbalance and suspicious patterns.",
    lbl_cs_pages:          "Pages Checked",
    lbl_cs_operators:      "Total Operators",
    lbl_cs_unknown:        "Unknown Operators",
    lbl_cs_suspicious:     "Suspicious Patterns",
    lbl_cs_balance:        "q/Q Balance",
    sub_cs_issues:         "Content Stream Issues",

    id_expl:               "<b>Incremental Diffing:</b> Shows which objects were specifically added, modified, or removed between revisions.",
    lbl_id_revisions:      "Revisions",
    lbl_id_added:          "Added",
    lbl_id_modified:       "Modified",
    lbl_id_removed:        "Removed",
    sub_id_changes:        "Changes per Revision",
    col_id_rev:            "Rev.",
    col_id_added:          "Added",
    col_id_modified:       "Modified",
    col_id_removed:        "Removed",
    col_id_types:          "Changed Types",

    fh_expl:               "<b>Fuzzy Hashing:</b> ssdeep (CTPH) and TLSH generate similarity hashes. Similar documents produce similar fuzzy hashes — even when bytes have been changed.",
    lbl_fh_ssdeep:         "ssdeep Hash",
    lbl_fh_tlsh:           "TLSH Hash",
    lbl_fh_available:      "Available",

    ca_expl:               "<b>Cross-Analyzer Intelligence:</b> Correlates results from all analyzers — timeline reconstruction, creator profiling, automatic correlations and weighted manipulation score.",
    lbl_ca_score:          "Manipulation Score",
    lbl_ca_correlations:   "Correlations",
    lbl_ca_confidence:     "Creator Profile Confidence",
    sub_ca_timeline:       "Reconstructed Timeline",
    sub_ca_profile:        "Creator Profile",
    sub_ca_correlations:   "Found Correlations",
    col_ca_time:           "Timestamp",
    col_ca_source:         "Source",
    col_ca_event:          "Event",
    col_ca_title:          "Finding",
    col_ca_severity:       "Severity",
    col_ca_analyzers:      "Involved Analyzers",
    col_ca_conclusion:     "Conclusion",

    coc_expl:              "<b>Chain of Custody:</b> Documents evidence integrity for court admissibility — examiner, case no., hash verification and audit log of all analyses.",
    lbl_coc_examiner:      "Examiner",
    lbl_coc_case:          "Case No.",
    lbl_coc_integrity:     "Evidence Integrity",
    lbl_coc_hash_match:    "Hash Match",
    lbl_coc_analyzers_run: "Analyzers Executed",
    sub_coc_audit:         "Audit Log",
    col_coc_analyzer:      "Analyzer",
    col_coc_status:        "Status",
    col_coc_duration:      "Duration",
    coc_integrity_ok:      "Intact — file unchanged",
    coc_integrity_fail:    "Compromised — file was modified!",

    // Phase 6 — Extended Forensics (EN)
    sec_yara:              "YARA Malware Scan",
    sec_font_forensics:    "Font Forensics",
    sec_pdfa_compliance:   "PDF/A & PDF/X Compliance",
    sec_linearization:     "Linearization (Web Optimization)",
    sec_icc_profiles:      "ICC Color Profiles",
    sec_visual_render:     "Visual Render Comparison",
    sec_object_graph:      "PDF Object Graph",
    sec_cross_doc_fp:      "Cross-Document Fingerprint",
    sec_printer_forensics: "Printer Forensics",

    yara_expl:             "<b>YARA Malware Scan:</b> Scans the PDF file with specialized YARA rules against JavaScript obfuscation, CVE exploits, shellcode, phishing and embedded executables.",
    lbl_yara_available:    "YARA Available",
    lbl_yara_rules:        "Rules Loaded",
    lbl_yara_matches:      "Total Matches",
    lbl_yara_critical:     "Critical Matches",
    lbl_yara_high:         "High Matches",
    sub_yara_matches:      "YARA Matches",
    col_yara_rule:         "Rule",
    col_yara_severity:     "Severity",
    col_yara_category:     "Category",
    col_yara_desc:         "Description",
    yara_no_matches:       "No YARA matches — file is clean.",

    ff_expl:               "<b>Font Forensics:</b> Analyzes embedded fonts — subset detection, font origin (Microsoft/Apple/Adobe/Google/LaTeX), embedding status and suspicious fonts.",
    lbl_ff_total:          "Total Fonts",
    lbl_ff_embedded:       "Embedded",
    lbl_ff_subset:         "Subset (partially embedded)",
    lbl_ff_system:         "System Fonts (not embedded)",
    lbl_ff_type1:          "Type1",
    lbl_ff_truetype:       "TrueType",
    lbl_ff_creators:       "Font Origins",
    sub_ff_fonts:          "Font Details",
    sub_ff_suspicious:     "Suspicious Fonts",
    col_ff_name:           "Font Name",
    col_ff_type:           "Type",
    col_ff_embedded:       "Embedded",
    col_ff_subset:         "Subset",
    col_ff_origin:         "Origin",
    col_ff_pages:          "Pages",

    pdfa_expl:             "<b>PDF/A & PDF/X Compliance:</b> Validates conformance with archival (PDF/A) and print standards (PDF/X) — XMP metadata, font embedding, JavaScript prohibition, encryption prohibition.",
    lbl_pdfa_claimed:      "PDF/A Claimed",
    lbl_pdfa_version:      "PDF/A Version",
    lbl_pdfa_conformance:  "Conformance Level",
    lbl_pdfx_claimed:      "PDF/X Claimed",
    lbl_pdfx_version:      "PDF/X Version",
    lbl_pdfa_issues:       "Compliance Issues",
    lbl_pdfa_passes:       "Passed Checks",
    lbl_pdfa_output_intent:"Output Intent",
    sub_pdfa_issues:       "Compliance Issues",
    sub_pdfa_passes:       "Passed Checks",
    col_pdfa_check:        "Check",
    col_pdfa_status:       "Status",
    col_pdfa_detail:       "Detail",

    lin_expl:              "<b>Linearization:</b> Checks whether the PDF is optimized for Fast Web View. File size discrepancies after linearization indicate post-modification.",
    lbl_lin_linearized:    "Linearized",
    lbl_lin_version:       "Linearization Version",
    lbl_lin_file_declared: "Declared File Size",
    lbl_lin_file_actual:   "Actual File Size",
    lbl_lin_mismatch:      "Size Mismatch",
    lbl_lin_hint_table:    "Hint Table",
    lbl_lin_first_page:    "First Page Object",
    lbl_lin_pages:         "Declared Pages",
    lin_not_linearized:    "Not linearized",

    icc_expl:              "<b>ICC Color Profiles:</b> Extracts embedded ICC profiles showing device, software and platform information — forensically relevant as they reveal the creation workflow.",
    lbl_icc_count:         "Profiles Found",
    lbl_icc_colorspaces:   "Color Spaces Used",
    sub_icc_profiles:      "ICC Profiles",
    col_icc_name:          "Profile Name",
    col_icc_version:       "Version",
    col_icc_class:         "Device Class",
    col_icc_colorspace:    "Color Space",
    col_icc_platform:      "Platform",
    col_icc_creator:       "Creator",
    col_icc_date:          "Creation Date",
    col_icc_source:        "Source",
    icc_no_profiles:       "No ICC profiles found.",

    vr_expl:               "<b>Visual Render Comparison:</b> Renders all pages and generates SHA256 hashes of visual content. Detects blank pages, duplicate pages and visual differences.",
    lbl_vr_available:      "Render Available",
    lbl_vr_pages:          "Pages Rendered",
    lbl_vr_blank:          "Blank Pages",
    lbl_vr_duplicates:     "Duplicate Pages",
    lbl_vr_renderer:       "Renderer",
    lbl_vr_dpi:            "Resolution (DPI)",
    sub_vr_hashes:         "Page Hashes",
    col_vr_page:           "Page",
    col_vr_hash:           "Visual Hash",
    col_vr_blank:          "Blank",

    og_expl:               "<b>PDF Object Graph:</b> Traverses the PDF object tree from root (Catalog). Detects circular references and unusually deep nesting.",
    lbl_og_objects:        "Total Objects",
    lbl_og_max_depth:      "Max Depth",
    lbl_og_types:          "Object Types",
    lbl_og_circular:       "Circular References",
    sub_og_types:          "Object Type Distribution",
    sub_og_catalog:        "Catalog Info",
    col_og_type:           "Type",
    col_og_count:          "Count",

    cdf_expl:              "<b>Cross-Document Fingerprint:</b> Creates a 5-dimensional fingerprint (structure, fonts, metadata, style, content) for similarity comparison across document collections.",
    lbl_cdf_version:       "Fingerprint Version",
    lbl_cdf_struct:        "Structure Hash",
    lbl_cdf_font:          "Font Hash",
    lbl_cdf_meta:          "Metadata Hash",
    lbl_cdf_style:         "Style Hash",
    lbl_cdf_content:       "Content Hash",

    pf_expl:               "<b>Printer Forensics:</b> Detects scanned documents through full-page images, DPI analysis, halftone patterns (laser printers), banding and CCITT/JBIG2 filters.",
    lbl_pf_scanned:        "Scanned Document",
    lbl_pf_confidence:     "Scan Confidence",
    lbl_pf_printer_type:   "Printer Type",
    lbl_pf_dpi:            "Detected DPI",
    lbl_pf_halftone:       "Halftone Pattern",
    lbl_pf_banding:        "Printer Banding",
    lbl_pf_images:         "Images Analyzed",
    sub_pf_indicators:     "Scan Indicators",

    // Charts extra
    charts_no_anomalies:   "No anomalies found",
    charts_no_categories:  "No categories",
    charts_no_findings:    "No findings",
    charts_no_structure:   "No structure data",
    charts_no_analyzer_data: "No analyzer data",
    score_safe:            "SAFE",
    score_warning:         "WARNING",
    score_critical:        "CRITICAL",
    phase_basis:           "Basic",
    phase_structure:       "Structure",
    phase_image:           "Image",
    phase_ioc_text:        "IOC/Text",
    phase_deep:            "Deep",
    phase_extended:        "Extended",
    lbl_images:            "Images",
    err_unknown:           "Unknown error",

    // Chat
    nav_chat:              "AI Chat",
    chat_no_doc:           "No document loaded",
    chat_welcome:          "I am your forensic assistant. Load a document and ask me questions about it.",
    chat_placeholder:      "Ask about the report…",
  }
};

// ===== Backend-Message-Übersetzung (DE→EN) =====
// Patterns: [RegExp, replacement] — wird nur im EN-Modus angewendet
const _MSG_TRANSLATIONS = [
  // Metadata
  [/^ModDate liegt vor CreationDate/, 'ModDate is before CreationDate — possible manipulation'],
  [/^CreationDate liegt in der Zukunft/, 'CreationDate is in the future'],
  [/^ModDate liegt in der Zukunft/, 'ModDate is in the future'],
  [/^XMP-CreateDate weicht vom/, 'XMP-CreateDate differs from /Info-CreationDate — possible manipulation'],
  [/^XMP-ModifyDate weicht vom/, 'XMP-ModifyDate differs from /Info-ModDate — possible manipulation'],
  [/^Deklarierte Dateigröße stimmt nicht/, 'Declared file size does not match actual size'],
  // Software
  [/^Producer\/Creator nicht in bekannter Tool-Tabelle/, 'Producer/Creator not found in known tool database'],
  [/^Weder Producer noch Creator/, 'Neither Producer nor Creator present in PDF'],
  [/^Dokument wurde mit '(.+)' erstellt und mit '(.+)' konvertiert/, 'Document created with \'$1\' and converted with \'$2\''],
  // Hidden Text
  [/^Unsichtbarer Text.*?(\d+) Block/, 'Invisible text (Rendering Mode 3) found: $1 block(s)'],
  [/^Weißer Text.*?(\d+) Block/, 'White text (on white background) found: $1 block(s)'],
  [/^Miniatur-Text.*?(\d+) Block/, 'Tiny text (<1pt) found: $1 block(s)'],
  [/^OCG-Ebenen.*?(\d+)/, 'OCG layers (Optional Content Groups) present: $1'],
  [/^pikepdf nicht verfügbar.*Hidden/, 'pikepdf not available — hidden text analysis skipped'],
  [/^Hidden-Text-Analyse fehlgeschlagen/, 'Hidden text analysis failed'],
  // Residual
  [/^(\d+) verwaiste Objekte mit JavaScript/, '$1 orphaned objects with JavaScript/EmbeddedFile'],
  [/^(\d+) verwaiste Objekte mit Metadaten/, '$1 orphaned objects with metadata content'],
  [/^(\d+) verwaiste Objekte gefunden/, '$1 orphaned objects found (not referenced in xref)'],
  [/^Trailing Data nach %%EOF.*?(\d+) Bytes/, 'Trailing data after %%EOF: $1 bytes'],
  [/^Mehrere %%EOF-Marker.*?(\d+)/, 'Multiple %%EOF markers: $1 (normal for incremental updates)'],
  // Encryption
  [/^PDF ist passwortgeschützt/, 'PDF is password protected — content cannot be analyzed'],
  [/^Veralteter Verschlüsselungsalgorithmus/, 'Outdated encryption algorithm'],
  [/^Drucken ist im Dokument deaktiviert/, 'Printing is disabled in the document'],
  [/^Kopieren von Text ist.*deaktiviert/, 'Text copying is disabled in the document'],
  [/^Metadaten sind NICHT verschlüsselt/, 'Metadata is NOT encrypted — XMP readable despite encryption'],
  // JavaScript
  [/^Auto-Execute beim Öffnen/, 'Auto-execute on open'],
  [/^Dokument-Level Additional Action/, 'Document-level additional action'],
  [/^Seiten-Action auf Seite (\d+)/, 'Page action on page $1'],
  [/^Gefährliche Annotation-Action.*Seite (\d+)/, 'Dangerous annotation action on page $1'],
  [/^Launch-Action gefunden.*'(.+)'/, 'Launch action found: starts \'$1\''],
  [/^RichMedia-Objekt.*gefunden/, 'RichMedia object (Flash/Video) found'],
  [/^JavaScript-Code gefunden.*?(\d+) Snippet/, 'JavaScript code found ($1 snippet(s))'],
  [/^Obfuskierter JavaScript-Code/, 'Obfuscated JavaScript code'],
  [/^JavaScript im Namen-Dictionary/, 'JavaScript in name dictionary'],
  // IOC
  [/^Darknet-URL.*?(\d+)/, 'Darknet URL(s) found: $1 .onion address(es)'],
  [/^Externe IP-Adressen.*?(\d+)/, 'External IP addresses in document: $1'],
  [/^Interne Netzwerkadressen.*?(\d+)/, 'Internal network addresses found: $1'],
  [/^Verdächtige URLs.*?(\d+)/, 'Suspicious URLs (shorteners/unusual TLD): $1'],
  // Incremental
  [/^Dokument enthält (\d+) Revisionen/, 'Document contains $1 revisions — content modified after creation'],
  [/^Letzte Revision sehr klein/, 'Last revision very small (<1KB) — may be metadata-only change'],
  [/^(\d+) Bytes Daten nach letztem %%EOF/, '$1 bytes of data after last %%EOF — hidden data possible'],
  [/^Datei konnte nicht gelesen werden/, 'File could not be read'],
  [/^Revision (\d+):.*Umfangreiche Änderungen/, 'Revision $1: Extensive changes'],
  [/^(\d+) Revisionen — ungewöhnlich viele/, '$1 revisions — unusually many updates'],
  // Signatures
  [/^Signatur-Feld gefunden.*kein.*AcroForm/, 'Signature field found but no /AcroForm — inconsistent document'],
  [/^\/DocMDP vorhanden.*kein Signatur/, '/DocMDP present but no signature field — certification signature possibly removed'],
  [/^Dokument enthält (\d+) Signatur-Feld/, 'Document contains $1 signature field(s)'],
  [/^Signatur-Zertifikat abgelaufen/, 'Signature certificate expired'],
  [/^Signatur deckt nicht das gesamte Dokument/, 'Signature does not cover entire document — shadow attack possible'],
  [/^ISA: Objekte nach Signatur/, 'ISA: Objects found after signature ByteRange — possible ISA manipulation'],
  [/^ISA:.*?(\d+) Bytes nach signiertem/, 'ISA: $1 bytes after signed range'],
  [/^Signature Wrapping.*Mehrere/, 'Signature wrapping: Multiple /ByteRange definitions in document'],
  // Images / ELA
  [/^Bild (\d+) enthält GPS/, 'Image $1 contains GPS coordinates in EXIF'],
  [/^Bild (\d+):.*Kamera-Metadaten/, 'Image $1: Camera metadata present'],
  [/^Bild (\d+) konnte nicht analysiert/, 'Image $1 could not be analyzed'],
  [/^ELA.*Verdächtiges Bild auf Seite (\d+)/, 'ELA: Suspicious image on page $1'],
  [/^Copy-Move.*?(\d+) duplizierte Blöcke/, 'Copy-move: $1 duplicate blocks'],
  [/^Double-Compression/, 'Double compression'],
  [/^Custom-Huffman/, 'Custom Huffman tables'],
  [/^EXIF-Thumbnail stimmt nicht/, 'EXIF thumbnail does not match main image'],
  [/^JPEG-Ghost/, 'JPEG ghost'],
  [/^Hoher Manipulations-Score.*?(\d+)/, 'High manipulation score: $1/100'],
  [/^Mittlerer Manipulations-Score.*?(\d+)/, 'Medium manipulation score: $1/100'],
  [/^(\d+) Bild\(er\) per Binär-Scan/, '$1 image(s) found via binary scan (no XObject embedding)'],
  // Object Streams
  [/^(\d+) Object-Stream.*?(\d+) komprimierten/, '$1 object stream(s) with $2 compressed objects total'],
  [/^(\d+) ObjStm mit verdächtigen/, '$1 ObjStm with suspicious contents'],
  [/^(\d+) ObjStm enthält.*Info/, '$1 ObjStm contains /Info-like metadata'],
  [/^(\d+) doppelt definierte Objekt/, '$1 duplicate object number(s) found'],
  [/^Hybrid xref-Struktur/, 'Hybrid xref structure — traditional + stream (PDF 1.5 manipulation technique)'],
  [/^Ungewöhnlich tiefe Objektverschachtelung.*?(\d+)/, 'Unusually deep object nesting: $1'],
  [/^Zirkuläre Referenzen gefunden/, 'Circular references found'],
  // Embedded
  [/^(\d+) eingebettete Datei/, '$1 embedded file(s) found'],
  [/^Gefährliche eingebettete Datei.*'(.+)'/, 'Dangerous embedded file: \'$1\''],
  [/^Verdächtiger MIME-Type.*'(.+)'.*'(.+)'/, 'Suspicious MIME type: \'$1\' for file \'$2\''],
  // XRef
  [/^Hybrid-XRef erkannt/, 'Hybrid XRef detected (table + stream)'],
  [/^Duplikat-Offset/, 'Duplicate offset'],
  [/^Objekt 0 ist nicht in der Free-Chain/, 'Object 0 is not in the free chain'],
  [/^(\d+) XRef-Konsistenzfehler/, '$1 XRef consistency errors'],
  [/^(\d+) Objekte ohne XRef-Eintrag/, '$1 objects without XRef entry'],
  [/^XRef-Analyse-Fehler/, 'XRef analysis error'],
  // Content Stream
  [/^(\d+) ungültige Operatoren/, '$1 invalid operators'],
  [/^Seite (\d+):/, 'Page $1:'],
  [/^pikepdf nicht verfügbar.*Content-Stream/, 'pikepdf not available — content stream validation skipped'],
  [/^Content-Stream-Analyse-Fehler/, 'Content stream analysis error'],
  // Timezone
  [/^Inkonsistente Zeitzonen/, 'Inconsistent timezones between different date fields'],
  [/^Ungewöhnlicher Halbstunden-Offset/, 'Unusual half-hour offset'],
  [/^Einige Datumsfelder verwenden UTC/, 'Some date fields use UTC/Z — may have been normalized'],
  // UUID
  [/^UUID-Zeitstempel weicht um (\d+)s von CreationDate ab/, 'UUID timestamp deviates by $1s from CreationDate'],
  // Fonts
  [/^Type3-Fonts gefunden.*?(\d+)/, 'Type3 fonts found: $1'],
  [/^Keine eingebetteten Fonts.*?(\d+) System/, 'No embedded fonts — $1 system fonts used'],
  [/^(\d+) verschiedene Subset-Präfixe/, '$1 different subset prefixes found'],
  [/^(\d+) Font-Subset-Präfix/, '$1 font subset prefix(es) found — unique session fingerprints'],
  // Author Artifacts
  [/^(\d+) Dateipfad\(e\)/, '$1 file path(s) found — may contain usernames'],
  [/^(\d+) E-Mail-Adresse/, '$1 email address(es) embedded in document'],
  [/^Annotations-Autoren gefunden/, 'Annotation authors found'],
  [/^Versteckte Annotation auf Seite (\d+)/, 'Hidden annotation on page $1'],
  // Redaction
  [/^Seite (\d+):.*Nicht-angewendete Redact/, 'Page $1: Unapplied redact annotation'],
  [/^Seite (\d+):.*?(\d+) schwarze Rechtecke/, 'Page $1: $2 black rectangles over text'],
  [/^pikepdf nicht verfügbar.*Redaktions/, 'pikepdf not available — redaction analysis skipped'],
  [/^Redaktions-Analyse-Fehler/, 'Redaction analysis error'],
  // Fuzzy Hash
  [/^ssdeep-Hash-Fehler/, 'ssdeep hash error'],
  [/^TLSH konnte keinen Hash erzeugen/, 'TLSH could not generate hash (file too small or uniform)'],
  [/^TLSH-Hash-Fehler/, 'TLSH hash error'],
  // Steganography / Yellow Dots
  [/^Machine Identification Code.*erkannt.*?(\d+) Punkte/, 'Machine Identification Code (Xerox MIC) detected: $1 dots in regular grid'],
  [/^Gelbe Punkte.*?(\d+) Cluster/, 'Yellow dots in embedded images: $1 clusters'],
  [/^MIC erkannt.*?(\d+) Punkte/, 'MIC detected (via poppler rendering): $1 dots'],
  [/^PIL.*nicht verfügbar.*Yellow/, 'PIL/Pillow not available — yellow dots analysis skipped'],
  // Stream Decomp
  [/^pikepdf nicht verfügbar.*Stream/, 'pikepdf not available — stream analysis skipped'],
  [/^Stream-Analyse-Fehler/, 'Stream analysis error'],
  [/^(\d+)\/(\d+) Streams konnten nicht dekomprimiert/, '$1/$2 streams could not be decompressed'],
  // Printer Forensics
  [/^Ghostscript-Quantisierungstabelle.*?(\d+) Bild/, 'Ghostscript quantization table detected in $1 image(s)'],
  [/^Dokument ist ein Scan/, 'Document is a scan'],
  [/^Halftone-Raster.*erkannt/, 'Halftone pattern (printer traces) detected'],
  // PDF/A
  [/^PDF\/A-(.+) beansprucht.*?(\d+) Compliance/, 'PDF/A-$1 claimed but $2 compliance issues'],
  [/^PDF\/X beansprucht ohne OutputIntent/, 'PDF/X claimed without OutputIntent'],
  [/^PDF\/A erfordert XMP-Metadaten/, 'PDF/A requires XMP metadata — not found'],
  [/^PDF\/A verbietet JavaScript/, 'PDF/A prohibits JavaScript — found'],
  [/^PDF\/A verbietet (.+)-Aktionen/, 'PDF/A prohibits $1 actions'],
  [/^PDF\/A verbietet Verschlüsselung/, 'PDF/A prohibits encryption'],
  [/^PDF\/A erfordert alle Fonts/, 'PDF/A requires all fonts embedded — non-embedded found'],
  [/^PDF\/A-1 verbietet Transparenz/, 'PDF/A-1 prohibits transparency — ExtGState with alpha found'],
  [/^PDF\/X erfordert OutputIntent/, 'PDF/X requires OutputIntent — not found'],
  [/^PDF\/X erfordert.*Trapped/, 'PDF/X requires /Trapped key in /Info — not set or invalid'],
  // Linearization
  [/^Ungewöhnlich viele XRef-Sektionen.*?(\d+)/, 'Unusually many XRef sections ($1) for linearized PDF'],
  // Page Geometry
  [/^Gemischte Seitengrößen.*?(\d+) verschiedene/, 'Mixed page sizes in document ($1 different formats)'],
  [/^PageLabels deklarieren (\d+).*hat aber (\d+)/, 'PageLabels declare $1 pages, but document has $2'],
  [/^PageLabel-Range startet bei Seite (\d+).*nur (\d+)/, 'PageLabel range starts at page $1, document only has $2 pages'],
  [/^Mehr PageLabel-Ranges.*?(\d+).*?(\d+)/, 'More PageLabel ranges ($1) than actual pages ($2)'],
  [/^Seitennummerierung beginnt bei (\d+)/, 'Page numbering starts at $1 instead of 1'],
  [/^PageLabels konnten nicht/, 'PageLabels could not be fully parsed'],
  // OCG
  [/^(\d+) versteckte OCG-Layer/, '$1 hidden OCG layers found'],
  [/^Ungewöhnlich viele OCG-Layer.*?(\d+)/, 'Unusually many OCG layers: $1'],
  [/^OCG-Analyse-Fehler/, 'OCG analysis error'],
  [/^pikepdf nicht verfügbar.*OCG/, 'pikepdf not available — OCG analysis skipped'],
  // Visual Render
  [/^(\d+) leere Seiten gefunden/, '$1 blank pages found'],
  [/^(\d+) duplizierte Seiten/, '$1 duplicate pages found'],
  // Virus
  [/^(.+): (\d+) Treffer.*schädlich/, '$1: $2 hit(s) — file classified as malicious!'],
  // Shadow
  [/^ISA: Objekte nach Signatur-ByteRange/, 'ISA: Objects found after signature ByteRange — possible ISA manipulation'],
  // Generic
  [/^PDF konnte nicht.*geöffnet werden/, 'PDF could not be opened'],
  [/^PDF-Datei konnte nicht gelesen/, 'PDF file could not be read'],
  [/^Datei nicht lesbar/, 'File not readable'],
  [/^Verschiedene ICC-Profil-Ersteller/, 'Different ICC profile creators'],
  // Detail strings
  [/^Text mit weißer Füllfarbe ist für Betrachter unsichtbar/, 'Text with white fill color is invisible to viewers but searchable.'],
  [/^Können gelöschte Autorenangaben/, 'May contain deleted author information, titles, etc.'],
  [/^Können Überreste gelöschter oder ersetzter/, 'May be remnants of deleted or replaced content'],
];

function translateMsg(msg) {
  if (!msg || getLang() !== 'en') return msg;
  for (var i = 0; i < _MSG_TRANSLATIONS.length; i++) {
    if (_MSG_TRANSLATIONS[i][0].test(msg)) {
      return msg.replace(_MSG_TRANSLATIONS[i][0], _MSG_TRANSLATIONS[i][1]);
    }
  }
  return msg;
}

// ===== Core i18n API =====

let _lang = localStorage.getItem('pf_lang') || 'de';

function t(key) {
  return (TRANSLATIONS[_lang] && TRANSLATIONS[_lang][key]) ||
         (TRANSLATIONS['de'][key]) ||
         key;
}

function setLang(lang) {
  _lang = lang;
  localStorage.setItem('pf_lang', lang);
  document.documentElement.lang = lang;
  applyLangToPage();
  // Dynamisch gerenderte Analyse-Sektionen neu rendern (alle Texte kommen aus t())
  if (typeof _lastAnalysisData !== 'undefined' && _lastAnalysisData && typeof renderResult === 'function') {
    renderResult(_lastAnalysisData);
  }
  // Dashboard-Komponenten mit dynamischen Inhalten neu rendern
  if (typeof renderCompareSlots === 'function') renderCompareSlots();
  if (typeof renderSidebarHistory === 'function') {
    const items = typeof allSidebarItems !== 'undefined' ? allSidebarItems : [];
    renderSidebarHistory(items);
  }
  // KI-Review neu laden wenn Panel sichtbar (neue Sprache = neuer API-Call)
  if (typeof refreshAiReviewIfVisible === 'function') refreshAiReviewIfVisible();
}

function getLang() { return _lang; }

// ===== DOM-Elemente mit data-i18n Attribut übersetzen =====

function applyLangToPage() {
  // Alle Elemente mit data-i18n="key" Text ersetzen
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    el.textContent = t(key);
  });

  // Alle Elemente mit data-i18n-placeholder="key" Placeholder setzen
  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
    el.placeholder = t(el.getAttribute('data-i18n-placeholder'));
  });

  // Lang-Toggle Button
  const btn = document.getElementById('langToggle');
  if (btn) {
    btn.textContent = t('nav_lang_btn');
    btn.title = t('nav_lang_title');
  }

  // Aktive Klasse auf korrekten Link setzen (Navbar)
  document.querySelectorAll('[data-i18n-href]').forEach(el => {
    // only update text, href stays the same
  });
}

// Beim Laden sofort anwenden
document.addEventListener('DOMContentLoaded', () => {
  document.documentElement.lang = _lang;
  applyLangToPage();

  const btn = document.getElementById('langToggle');
  if (btn) {
    btn.addEventListener('click', () => {
      setLang(_lang === 'de' ? 'en' : 'de');
    });
  }
});
