/**
 * results.js — Ergebnis-Rendering mit Highlighting + kontextuellen Erklärungen
 */

let currentAnalysisId   = null;
let currentFilename     = null;
let _lastAnalysisData   = null;   // gecachte Daten für Sprach-Re-Render

// ===== Erklärungen — kommen jetzt aus i18n =====
// t() ist in i18n.js definiert (wird in base.html davor geladen)
function sectionExpl(key) { return t(key); }

// Feld-Erklärungen (übersetzbar via Lookup-Table)
const FIELD_EXPLANATIONS_DE = {
  "MD5":      "MD5 ist veraltet (angreifbar), aber für schnelle Duplikat-Prüfung immer noch nützlich.",
  "SHA256":   "SHA-256 ist der forensische Standard. Identische SHA256 = identische Dateien.",
  "SHA512":   "SHA-512 bietet maximale Kollisions-Resistenz.",
  "Creator":  "Die Anwendung die das Quelldokument erstellt hat (z.B. 'Microsoft Word').",
  "Producer": "Die PDF-Export-Engine (z.B. 'Adobe PDF Library'). Unterscheidet sich oft vom Creator.",
  "Erstellt": "Wann das PDF laut /Info-Dictionary erstellt wurde. Kann manuell gesetzt werden.",
  "Geändert": "Wann das PDF zuletzt geändert wurde. Liegt ModDate vor CreationDate → Manipulation.",
  "AcroForm": "Das interaktive Formular-Framework. Signatur-Felder brauchen zwingend AcroForm.",
  "DocMDP":   "Document Modification Permissions — definiert was nach der Signatur geändert werden darf.",
  "Ghostscript-Quant.": "Ghostscript-typische JPEG-Quantisierungstabellen — Hinweis auf Nachbearbeitung.",
};
const FIELD_EXPLANATIONS_EN = {
  "MD5":      "MD5 is outdated (vulnerable), but still useful for quick duplicate checking.",
  "SHA256":   "SHA-256 is the forensic standard. Identical SHA256 = identical files.",
  "SHA512":   "SHA-512 provides maximum collision resistance.",
  "Creator":  "The application that created the source document (e.g. 'Microsoft Word').",
  "Producer": "The PDF export engine (e.g. 'Adobe PDF Library'). Often differs from Creator.",
  "Created": "When the PDF was created according to the /Info dictionary. Can be set manually.",
  "Modified": "When the PDF was last modified. If ModDate is before CreationDate → manipulation.",
  "AcroForm": "The interactive form framework. Signature fields require AcroForm.",
  "DocMDP":   "Document Modification Permissions — defines what changes are allowed after signing.",
  "Ghostscript-Quant.": "Ghostscript-typical JPEG quantization tables — suggests image recompression.",
};
function fieldExpl(key) {
  const dict = getLang() === 'en' ? FIELD_EXPLANATIONS_EN : FIELD_EXPLANATIONS_DE;
  return dict[key] || null;
}

// ===== Laien-Erklärungen für Anomalie-Kategorien =====
// Schlüsselwörter im message/category werden gematcht → einfache Erklärung
const _LAIEN_MAP_DE = [
  { match: ['double.compress','doppel.*kompri','Double-Compression','doppelte Komprimierung'],
    text: 'Das Bild in diesem Dokument wurde zweimal komprimiert — das passiert oft wenn jemand ein Bild aus einem Originaldokument herausnimmt, bearbeitet und wieder einfügt.' },
  { match: ['jpeg.ghost','JPEG-Ghost'],
    text: 'Es gibt Hinweise, dass ein Bild aus einer anderen Quelle stammt als der Rest des Dokuments — möglicherweise wurde es nachträglich eingefügt.' },
  { match: ['ela','Error Level'],
    text: 'Bestimmte Bildbereiche reagieren anders auf Komprimierung als der Rest — das kann ein Zeichen sein, dass diese Bereiche verändert wurden.' },
  { match: ['custom.*huffman','huffman','Huffman'],
    text: 'Das Bild verwendet eine ungewöhnliche Kompressionsmethode — dies kann auf eine spezifische Bildbearbeitungssoftware hinweisen.' },
  { match: ['ungültig.*operator','invalid.*operator','content_stream'],
    text: 'Das Dokument enthält ungewöhnliche Anweisungen im Textbereich — solche Fehler entstehen manchmal beim Bearbeiten mit inkompatibler Software.' },
  { match: ['verwaist','orphan','residual'],
    text: 'Es gibt Datenreste im Dokument, die nicht mehr mit dem Inhalt verknüpft sind — das können Überbleibsel von gelöschten oder ersetzten Inhalten sein.' },
  { match: ['incremental.*update','inkrementell'],
    text: 'Das Dokument wurde nach seiner Erstellung nachträglich verändert — bei offiziellen Dokumenten ist das oft ein Warnsignal.' },
  { match: ['signatur','signature','sign'],
    text: 'Die digitale Unterschrift des Dokuments stimmt nicht vollständig überein — das bedeutet, dass das Dokument nach der Unterzeichnung möglicherweise verändert wurde.' },
  { match: ['metadata','metadaten','Metadaten'],
    text: 'Die internen Informationen des Dokuments (z.B. Erstellungsdatum, Autor) sind widersprüchlich oder wurden verändert.' },
  { match: ['font.*subset','subset.*prefix','font_prefix'],
    text: 'Jedes Dokument enthält einmalige Schrift-Fingerabdrücke — diese können helfen die ursprüngliche Software zu identifizieren.' },
  { match: ['xref','cross.reference','Querverwei'],
    text: 'Die interne Verzeichnisstruktur des Dokuments ist beschädigt oder wurde verändert — das ist bei echten Dokumenten normalerweise nicht der Fall.' },
  { match: ['javascript','js.','script'],
    text: 'Das Dokument enthält automatisch ausführbaren Code — das ist bei normalen Dokumenten ungewöhnlich und kann auf Schadsoftware hinweisen.' },
  { match: ['embed','eingebettet','attachment'],
    text: 'Das Dokument enthält eingebettete Dateien — bei offiziellen Dokumenten ist das selten und sollte geprüft werden.' },
  { match: ['encrypt','verschlüssel'],
    text: 'Das Dokument ist teilweise verschlüsselt — das kann legitim sein, erschwert aber die forensische Prüfung.' },
  { match: ['uri','url','link'],
    text: 'Das Dokument enthält Links zu externen Webseiten oder Servern — beim Öffnen könnten Daten übertragen werden.' },
  { match: ['datum','date','Zeitstempel','timestamp','ModDate','CreationDate'],
    text: 'Das Erstellungs- oder Änderungsdatum im Dokument ist widersprüchlich — echte Dokumente haben konsistente Zeitstempel.' },
  { match: ['seite','page','pages'],
    text: 'Die angegebene Seitenzahl stimmt nicht mit dem tatsächlichen Inhalt überein — ein mögliches Zeichen für Manipulation.' },
  { match: ['quant','Quantisierung','quantization'],
    text: 'Die Bildqualitäts-Einstellungen weisen auf eine Nachbearbeitung mit anderer Software hin.' },
  { match: ['acroform','formular','form'],
    text: 'Das Dokument enthält interaktive Formularfelder — diese können manipuliert oder missbraucht werden.' },
];

const _LAIEN_MAP_EN = [
  { match: ['double.compress','Double-Compression'],
    text: 'The image in this document was compressed twice — this often happens when someone extracts an image from an original document, edits it, and reinserts it.' },
  { match: ['jpeg.ghost','JPEG-Ghost'],
    text: 'There are signs that an image comes from a different source than the rest of the document — it may have been inserted afterwards.' },
  { match: ['ela','Error Level'],
    text: 'Certain image areas respond differently to compression than the rest — this can be a sign that these areas have been altered.' },
  { match: ['custom.*huffman','huffman'],
    text: 'The image uses an unusual compression method — this may indicate specific image editing software.' },
  { match: ['invalid.*operator','content_stream'],
    text: 'The document contains unusual instructions in the text area — such errors sometimes occur when editing with incompatible software.' },
  { match: ['orphan','residual'],
    text: 'There are data remnants in the document no longer linked to the content — these can be leftovers from deleted or replaced content.' },
  { match: ['incremental.*update'],
    text: 'The document was modified after its creation — for official documents, this is often a warning sign.' },
  { match: ['signature','sign'],
    text: 'The digital signature of the document does not fully match — the document may have been altered after signing.' },
  { match: ['metadata'],
    text: 'The internal information of the document (e.g. creation date, author) is contradictory or has been altered.' },
  { match: ['font.*subset','subset.*prefix'],
    text: 'Each document contains unique font fingerprints — these can help identify the original software.' },
  { match: ['xref','cross.reference'],
    text: 'The internal directory structure of the document is damaged or altered — this is normally not the case in genuine documents.' },
  { match: ['javascript','script'],
    text: 'The document contains automatically executable code — this is unusual in normal documents and may indicate malware.' },
  { match: ['embed','attachment'],
    text: 'The document contains embedded files — this is rare in official documents and should be checked.' },
  { match: ['encrypt'],
    text: 'The document is partially encrypted — this can be legitimate but makes forensic examination more difficult.' },
  { match: ['uri','url','link'],
    text: 'The document contains links to external websites or servers — data may be transmitted when opened.' },
  { match: ['date','timestamp','ModDate','CreationDate'],
    text: 'The creation or modification date in the document is contradictory — genuine documents have consistent timestamps.' },
  { match: ['page','pages'],
    text: 'The stated page count does not match the actual content — a possible sign of manipulation.' },
  { match: ['quant','quantization'],
    text: 'Image quality settings indicate post-processing with different software.' },
  { match: ['acroform','form'],
    text: 'The document contains interactive form fields — these can be manipulated or misused.' },
];

function _getLaienText(category, message) {
  var isEn = getLang() === 'en';
  var map = isEn ? _LAIEN_MAP_EN : _LAIEN_MAP_DE;
  var combined = ((category || '') + ' ' + (message || '')).toLowerCase();
  for (var i = 0; i < map.length; i++) {
    var entry = map[i];
    for (var j = 0; j < entry.match.length; j++) {
      try {
        if (new RegExp(entry.match[j], 'i').test(combined)) return entry.text;
      } catch(e) { }
    }
  }
  return null;
}

// ===== Verdächtige Werte die geHighlighted werden =====
function _isHighValue(key, val) {
  if (!val || val === "—") return false;
  const v = String(val).toLowerCase();
  if ((key === "Geändert" || key === "Modified" || key === t('lbl_modified')) && v.includes("vor creationdate")) return true;
  return false;
}

// ===== Entry Point =====

function renderResult(data) {
  currentAnalysisId = data.analysis_id;
  currentFilename   = data.filename;
  _lastAnalysisData = data;   // für Sprach-Re-Render cachen

  // Chat-Kontext setzen (damit KI-Chat das aktuelle Dokument kennt)
  if (typeof window.chatSetContext === 'function') {
    window.chatSetContext(data.analysis_id, data.filename);
  }

  // KI-Review Panel zurücksetzen — wird nach dem Laden neu befüllt
  var _aiPanel = document.getElementById('aiReviewPanel');
  if (_aiPanel) {
    _aiPanel.style.display = 'none';
    var _aiContent = document.getElementById('aiReviewContent');
    if (_aiContent) _aiContent.style.display = 'none';
    var _aiLoading = document.getElementById('aiReviewLoading');
    if (_aiLoading) _aiLoading.style.display = 'none';
  }

  const container = document.getElementById('resultContainer');
  container.style.display = 'block';
  container.scrollIntoView({ behavior: 'smooth', block: 'start' });

  // Jeder render-Aufruf einzeln geschützt — ein Fehler darf nicht alles stoppen
  var _renders = [
    function() { renderRiskBanner(data); },
    function() { if (typeof renderChartDashboard === 'function') renderChartDashboard(data); },
    function() { renderAnomalies(data.all_anomalies || []); },
    function() { renderHashes(data.hashes); },
    function() { renderMetadata(data.metadata); },
    function() { renderSoftware(data.software_fingerprint); },
    function() { renderUUID(data.uuid_decode); },
    function() { renderSignature(data.signature); },
    function() { renderGeometry(data.page_geometry); },
    function() { renderPageLabels(data.page_labels); },
    function() { renderImages(data.jpeg_extractor, data.jpeg_analyzer, data.quant_fingerprint, data.analysis_id); },
    function() { renderVirusScan(data.virus_scan); },
    function() { renderEncryption(data.encryption); },
    function() { renderIncrementalUpdates(data.incremental_updates); },
    function() { renderJavaScript(data.javascript); },
    function() { renderEmbeddedFiles(data.embedded_files); },
    // Phase 2 — Office-Formate
    function() { renderOOXML(data.ooxml); },
    function() { renderOLE(data.ole); },
    function() {
      var isImage = !!data.image_forensics;
      _togglePdfOnlySections(!data.ooxml && !data.ole && !isImage);
    },
    // Phase 1 — neue Sektionen
    function() { renderTimezone(data.timezone); },
    function() { renderAuthorArtifacts(data.author_artifacts); },
    function() { renderELA(data.ela); },
    function() { renderObjectStreams(data.object_streams); },
    function() { renderResidualObjects(data.residual_objects); },
    function() { renderShadowAttack(data.shadow_attack); },
    // Phase 3 — Bild-Forensik
    function() { renderImageForensics(data.image_forensics); },
    function() { renderSteganography(data.steganography); },
    // Phase 4 — Intelligence Features
    function() { renderIOC(data.ioc); },
    function() { renderHiddenText(data.hidden_text); },
    function() { renderYellowDots(data.yellow_dots); },
    // Phase 5 — Advanced Forensics
    function() { renderStreamDecomp(data.stream_decomp); },
    function() { renderXRefValidation(data.xref_validation); },
    function() { renderDeepJpeg(data.deep_jpeg); },
    function() { renderRedaction(data.redaction); },
    function() { renderOCGLayers(data.ocg_layers); },
    function() { renderContentStream(data.content_stream); },
    function() { renderIncDiff(data.incremental_diff); },
    function() { renderFuzzyHash(data.fuzzy_hash); },
    function() { renderCrossAnalyzer(data.cross_analyzer); },
    function() { renderChainOfCustody(data.chain_of_custody); },
    // Phase 6 — Extended Forensics
    function() { renderYara(data.yara); },
    function() { renderFontForensics(data.font_forensics); },
    function() { renderPdfaCompliance(data.pdfa_compliance); },
    function() { renderLinearization(data.linearization); },
    function() { renderIccProfiles(data.icc_profiles); },
    function() { renderVisualRender(data.visual_render); },
    function() { renderObjectGraph(data.object_graph); },
    function() { renderCrossDocFp(data.cross_doc_fingerprint); },
    function() { renderPrinterForensics(data.printer_forensics); },
  ];
  _renders.forEach(function(fn, i) {
    try { fn(); } catch(e) { console.error('[renderResult] Render-Schritt ' + i + ' fehlgeschlagen:', e); }
  });

  // === Gecachtes KI-Review laden falls vorhanden ===
  _loadCachedAiReview(data.analysis_id);

  // === Alle Cards öffnen nach Analyse ===
  var allBodies = document.querySelectorAll('#resultContainer .card-body.collapsed');
  allBodies.forEach(function(body) {
    body.classList.remove('collapsed');
    var header = body.previousElementSibling || body.parentElement.querySelector('.collapsible');
    if (header) {
      var arrow = header.querySelector('.collapse-arrow');
      if (arrow) arrow.classList.add('open');
    }
  });

  // === Status-Badges pro Sektion setzen ===
  try { _applyStatusBadges(data); } catch(e) { console.error('[StatusBadges]', e); }

  // GSAP animate result cards
  if (window.gsap) {
    gsap.from('#resultContainer .card', {
      y: 20,
      opacity: 0,
      duration: 0.4,
      stagger: 0.04,
      ease: 'power2.out',
      delay: 0.15,
    });
    gsap.from('#riskBanner', {
      scale: 0.97,
      opacity: 0,
      duration: 0.4,
      ease: 'back.out(1.3)',
    });
  }

  document.getElementById('btnDownloadReport').onclick = () => {
    showReportLangModal(currentAnalysisId);
  };

  document.getElementById('btnAddToCompare').onclick = () => {
    const ids = JSON.parse(localStorage.getItem('compareIds') || '[]');
    if (!ids.includes(currentAnalysisId)) {
      if (ids.length >= 4) ids.shift();
      ids.push(currentAnalysisId);
      localStorage.setItem('compareIds', JSON.stringify(ids));
    }
    window.location.href = '/compare';
  };
}

// ===== Risiko-Banner =====

function renderRiskBanner(data) {
  const badge = document.getElementById('riskBadge');
  badge.textContent = data.risk_level;
  badge.className   = 'risk-badge ' + data.risk_level;

  document.getElementById('riskFilename').textContent = data.filename;

  const high   = data.anomaly_count_high   || 0;
  const medium = data.anomaly_count_medium || 0;
  const low    = data.anomaly_count_low    || 0;

  document.getElementById('riskCounts').innerHTML =
    `<span class="text-high">${high}× HIGH</span> · ` +
    `<span class="text-medium">${medium}× MEDIUM</span> · ` +
    `<span class="text-low">${low}× LOW</span> · ` +
    `${formatBytes(data.file_size_bytes)} · ${t('lbl_analysiert')}: ${formatDate(data.analyzed_at)}`;
}

// ===== Anomalien =====

function renderAnomalies(anomalies) {
  const card  = document.getElementById('anomaliesCard');
  const list  = document.getElementById('anomaliesList');
  const badge = document.getElementById('anomalyTotalBadge');

  const significant = anomalies.filter(a => a.severity !== 'INFO');
  if (!significant.length) { card.style.display = 'none'; return; }

  card.style.display = 'block';
  badge.textContent = significant.length;

  const order  = { HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3 };
  const sorted = [...anomalies].sort((a, b) => (order[a.severity] ?? 4) - (order[b.severity] ?? 4));

  list.innerHTML = sorted.map(a => {
    var msg = typeof translateMsg === 'function' ? translateMsg(a.message) : a.message;
    var det = a.detail && typeof translateMsg === 'function' ? translateMsg(a.detail) : a.detail;
    var laien = _getLaienText(a.category, msg);
    var isEn = getLang() === 'en';
    var detailsLabel = isEn ? 'Technical details' : 'Technische Details';
    return `<div class="anomaly-item anomaly-item-layered">
      <div>${severityBadgeHtml(a.severity)}</div>
      <div class="anomaly-category">${escapeHtml(a.category)}</div>
      <div>
        ${laien ? `<div class="anomaly-laien">${escapeHtml(laien)}</div>` : ''}
        <details class="anomaly-tech-details"${laien ? '' : ' open'}>
          <summary>${detailsLabel}</summary>
          <div class="anomaly-message">${escapeHtml(msg)}</div>
          ${det ? `<div class="anomaly-detail">${escapeHtml(det)}</div>` : ''}
        </details>
      </div>
    </div>`;
  }).join('');

  // Aufklappen
  const body  = document.getElementById('anomaliesBody');
  const arrow = document.querySelector('[data-target="anomaliesBody"] .collapse-arrow');
  body.classList.remove('collapsed');
  if (arrow) arrow.classList.add('open');
}

// ===== Hashes =====

function _hashRow(label, value, explainKey) {
  if (!value) return [label, '—', explainKey];
  const safe = escapeHtml(value);
  const btn = `<button onclick="navigator.clipboard.writeText(this.dataset.hash).then(()=>{this.textContent='';setTimeout(()=>this.textContent='⧉',1400)})"
    data-hash="${safe}"
    title="${escapeHtml(t('hash_copy'))}"
    style="margin-left:8px;padding:1px 7px;font-size:0.72rem;border:1px solid var(--border);border-radius:4px;background:var(--surface2);cursor:pointer;color:var(--muted);vertical-align:middle;line-height:1.4">⧉</button>`;
  const html = `<span style="font-family:monospace;font-size:0.82rem;word-break:break-all">${safe}</span>${btn}`;
  return [label, {__html: html}, explainKey];
}

function renderHashes(h) {
  const el = document.getElementById('hashesContent');
  if (!h) { el.innerHTML = emptyState(t('no_data')); return; }
  var html = sectionExplanation('hash_expl') +
    kvTable([
      [t('lbl_filesize'), formatBytes(h.file_size_bytes)],
      _hashRow('MD5',    h.md5,    'MD5'),
      _hashRow('SHA1',   h.sha1),
      _hashRow('SHA256', h.sha256, 'SHA256'),
      _hashRow('SHA512', h.sha512, 'SHA512'),
    ]);
  if (typeof interpHashes === 'function') html += interpHashes(h);
  el.innerHTML = html;
}

// ===== Metadaten =====

function renderMetadata(m) {
  const el = document.getElementById('metaContent');
  if (!m) { el.innerHTML = emptyState(t('no_data')); return; }

  const rows = [
    [t('lbl_pdf_version'),    m.pdf_version],
    [t('lbl_pages'),          m.page_count],
    [t('lbl_title'),          m.title],
    [t('lbl_author'),         m.author],
    [t('lbl_subject'),        m.subject],
    [t('lbl_keywords'),       m.keywords],
    ['Creator',               m.creator,  'Creator'],
    ['Producer',              m.producer, 'Producer'],
    [t('lbl_created_raw'),    m.creation_date_raw],
    [t('lbl_created'),        formatDate(m.creation_date_parsed), getLang() === 'en' ? 'Created' : 'Erstellt'],
    [t('lbl_modified_raw'),   m.mod_date_raw],
    [t('lbl_modified'),       formatDate(m.mod_date_parsed), getLang() === 'en' ? 'Modified' : 'Geändert'],
  ];

  // Anomalie-Highlighting für diese Zeilen
  const anomalyFields = new Set((m.anomalies || []).map(a => {
    if (a.message.includes('ModDate')) return t('lbl_modified');
    if (a.message.includes('CreationDate')) return t('lbl_created');
    return null;
  }).filter(Boolean));

  let html = sectionExplanation('meta_expl') + kvTableHighlight(rows, anomalyFields);

  // XMP-Daten anzeigen
  if (m.xmp_data && m.xmp_data.fields && Object.keys(m.xmp_data.fields).length > 0) {
    html += `<div class="section-sub-header">
      <span>${t('sub_xmp_metadata')}</span>
      <span class="explain-badge" title="${escapeHtml(t('xmp_tooltip'))}">ℹ${t('xmp_what')}</span>
    </div>`;
    const xmpRows = Object.entries(m.xmp_data.fields).slice(0, 30).map(([k, v]) => [k, v]);
    html += kvTable(xmpRows);
  }

  if (m.anomalies && m.anomalies.length) html += anomalyMiniList(m.anomalies);
  if (typeof interpMetadata === 'function') html += interpMetadata(m);
  el.innerHTML = html;
}

// ===== Software-Fingerprint =====

function renderSoftware(fp) {
  const el = document.getElementById('softwareContent');
  if (!fp) { el.innerHTML = emptyState(t('no_data')); return; }

  var cat = fp.tool_category || '—';
  if (getLang() === 'en' && cat === 'Unbekannt') cat = 'Unknown';
  const rows = [
    [t('lbl_identified_tool'), fp.identified_tool || '—'],
    [t('lbl_category'),        cat],
    [t('lbl_version'),         fp.version_hint    || '—'],
    ['Producer (raw)',         fp.producer_raw    || '—', 'Producer'],
    ['Creator (raw)',          fp.creator_raw     || '—', 'Creator'],
  ];

  let html = sectionExplanation('sw_expl') + kvTable(rows);
  if (fp.anomalies && fp.anomalies.length) html += anomalyMiniList(fp.anomalies);
  if (typeof interpSoftware === 'function') html += interpSoftware(fp);
  el.innerHTML = html;
}

// ===== UUID =====

function renderUUID(u) {
  const card = document.getElementById('uuidCard');
  const el   = document.getElementById('uuidContent');

  if (!u || u.found_uuids.length === 0) {
    card.style.display = 'block';
    el.innerHTML = emptyState(t('uuid_none_found'));
    return;
  }

  card.style.display = 'block';

  let html = sectionExplanation('uuid_expl');
  html += kvTable([[t('lbl_found_uuid_v1'), u.found_uuids.length]]);

  if (u.decoded && u.decoded.length) {
    html += `<div style="margin-top:12px;overflow-x:auto">
      <table class="kv-table">
        <tr>
          <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_uuid')}</th>
          <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_uuid_timestamp')}</th>
          <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_uuid_delta')}</th>
          <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_uuid_verdict')}</th>
        </tr>`;

    u.decoded.slice(0, 10).forEach(d => {
      const delta = d.delta_seconds != null ? Math.round(d.delta_seconds) : null;
      let verdict = `<span class="text-clean">${t('uuid_consistent')}</span>`;
      let rowClass = '';
      if (delta != null) {
        if (delta > 3600) {
          verdict  = `<span class="text-high">${t('uuid_strongly_deviating').replace('{delta}', delta)}</span>`;
          rowClass = 'highlight-high';
        } else if (delta > 60) {
          verdict  = `<span class="text-medium">${t('uuid_slightly_deviating').replace('{delta}', delta)}</span>`;
          rowClass = 'highlight-medium';
        }
      }
      html += `<tr class="${rowClass}">
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.75rem;font-family:monospace;color:var(--text)">${escapeHtml(d.uuid)}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">${escapeHtml(d.timestamp_utc)}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">${delta != null ? delta + 's' : '—'}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem">${verdict}</td>
      </tr>`;
    });
    html += '</table></div>';
  }

  if (u.anomalies && u.anomalies.length) html += anomalyMiniList(u.anomalies);
  if (typeof interpUUID === 'function') html += interpUUID(u);
  el.innerHTML = html;
}

// ===== Signaturen =====

function renderSignature(sig) {
  const el = document.getElementById('sigContent');
  if (!sig) { el.innerHTML = emptyState(t('no_data')); return; }

  const acroIcon = sig.has_acroform ? '' : '';
  const sigIcon  = sig.has_sig_field ? '' : '';
  const mdpIcon  = sig.has_doc_mdp  ? '' : '';

  const anomalyCats = new Set((sig.anomalies || []).map(a => a.message));
  const acroHighlight = !sig.has_acroform && sig.has_sig_field;

  const presentText    = t('present');
  const notPresentText = t('not_present');

  const rows = [
    [t('lbl_acroform'),     acroIcon + ' ' + (sig.has_acroform ? presentText : notPresentText), 'AcroForm'],
    [t('lbl_sig_field'),    sigIcon  + ' ' + (sig.has_sig_field ? presentText : notPresentText)],
    [t('lbl_docmdp'),       mdpIcon  + ' ' + (sig.has_doc_mdp  ? presentText : notPresentText), 'DocMDP'],
    [t('lbl_sig_names'),    sig.sig_field_names.length ? sig.sig_field_names.join(', ') : '—'],
  ];

  const highlightFields = new Set();
  if (acroHighlight) highlightFields.add(t('lbl_acroform'));

  let html = sectionExplanation('sig_expl') + kvTableHighlight(rows, highlightFields);

  // Zertifikat-Details
  if (sig.cert_info && sig.cert_info.certificates && sig.cert_info.certificates.length) {
    html += `<div class="section-sub-header">
      <span>${t('sub_cert_details')}</span>
      <span class="explain-badge" title="${escapeHtml(t('cert_tooltip'))}">ℹ${t('cert_what')}</span>
    </div>`;
    sig.cert_info.certificates.forEach((cert, i) => {
      const expired = cert.not_valid_after && new Date(cert.not_valid_after) < new Date();
      html += `<div class="cert-box${expired ? ' cert-expired' : ''}">`;
      if (expired) html += `<div class="cert-warning">${t('cert_expired')}</div>`;
      html += kvTable([
        [t('col_cert_field'),       cert.sig_field_name || `${t('lbl_signature')} ${i+1}`],
        [t('col_cert_subject'),     cert.subject],
        [t('col_cert_issuer'),      cert.issuer],
        [t('col_cert_serial'),      cert.serial],
        [t('col_cert_valid_from'),  cert.not_valid_before],
        [t('col_cert_valid_until'), cert.not_valid_after],
        [t('col_cert_sha1fp'),      cert.fingerprint_sha1],
      ]);
      html += '</div>';
    });
  }

  if (sig.anomalies && sig.anomalies.length) html += anomalyMiniList(sig.anomalies);
  if (typeof interpSignature === 'function') html += interpSignature(sig);
  el.innerHTML = html;
}

// ===== Seitengeometrie =====

function renderGeometry(geo) {
  const el = document.getElementById('geoContent');
  if (!geo) { el.innerHTML = emptyState(t('no_data')); return; }

  const mixedKey = t('lbl_mixed_sizes');
  const highlightFields = geo.mixed_sizes ? new Set([mixedKey]) : new Set();

  const rows = [
    [mixedKey,              geo.mixed_sizes ? t('geo_mixed_yes') : t('no_clean'), mixedKey],
    [t('lbl_unique_formats'), geo.unique_sizes.join(', ') || '—'],
    [t('lbl_total_pages'),  geo.pages.length],
  ];

  let html = sectionExplanation('geo_expl') + kvTableHighlight(rows, highlightFields);

  if (geo.pages.length > 0) {
    html += `<div style="margin-top:12px;overflow-x:auto"><table class="kv-table">
      <tr>
        <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_page')}</th>
        <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_wh_pt')}</th>
        <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_a4')}</th>
        <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_orientation')}</th>
      </tr>`;
    geo.pages.slice(0, 30).forEach((p, i) => {
      const notA4 = !p.is_a4;
      html += `<tr class="${notA4 && geo.pages.length > 1 ? 'highlight-low' : ''}">
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">${i+1}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;font-family:monospace;color:var(--text)">${p.width_pt} × ${p.height_pt}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:${p.is_a4 ? 'var(--clean)' : 'var(--muted)'}">${p.is_a4 ? '' : '—'}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">${p.orientation}</td>
      </tr>`;
    });
    html += '</table></div>';
  }

  if (geo.anomalies && geo.anomalies.length) html += anomalyMiniList(geo.anomalies);
  el.innerHTML = html;
}

// ===== PageLabels =====

function renderPageLabels(pl) {
  if (!pl || !pl.has_page_labels) return;
  const el = document.getElementById('geoContent');
  if (!el) return;

  // Append page labels info to the geometry card content
  let html = '';
  if (pl.declared_page_count !== pl.actual_page_count) {
    html += `<div class="anomaly-item" style="margin-top:8px">
      ${severityBadgeHtml('MEDIUM')}
      <div class="anomaly-category">${t('lbl_page_labels')}</div>
      <div><div class="anomaly-message">${t('lbl_declared_pages')}: ${pl.declared_page_count} vs ${t('lbl_actual_pages')}: ${pl.actual_page_count}</div></div>
    </div>`;
  }
  if (pl.label_ranges && pl.label_ranges.length > 0) {
    html += `<div class="section-sub-header" style="margin-top:8px"><span>${t('sub_page_labels')}</span></div>
      <div style="overflow-x:auto"><table class="kv-table"><tr>
        <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_start_page')}</th>
        <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_style')}</th>
        <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_prefix')}</th>
        <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_first_value')}</th>
      </tr>`;
    pl.label_ranges.forEach(r => {
      html += `<tr>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">${r.start_page ?? '—'}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">${escapeHtml(r.style || r.raw_style || '—')}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;font-family:monospace;color:var(--accent)">${escapeHtml(r.prefix || '—')}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--muted)">${r.first_value ?? '—'}</td>
      </tr>`;
    });
    html += '</table></div>';
  }
  if (html) el.innerHTML += html;
}

// ===== Bilder =====

function renderImages(extractor, analyzer, quant, analysisId) {
  const card = document.getElementById('imagesCard');
  const el   = document.getElementById('imagesContent');

  if (!extractor || extractor.total_images === 0) {
    el.innerHTML = emptyState(t('no_jpeg_images'));
    return;
  }

  const gsDetected = quant?.ghostscript_detected;

  const gsKey = t('lbl_ghostscript_quant');
  const totalImgBytes = (extractor.images || []).reduce((s, i) => s + (i.file_size_bytes || 0), 0);
  const rows = [
    [t('lbl_extracted_images'), extractor.total_images],
    [gsKey,                     gsDetected ? t('ghostscript_detected') : t('not_detected'), 'Ghostscript-Quant.'],
    [t('lbl_extraction_method'), extractor.images[0]?.extraction_method || '—'],
    [t('lbl_images_checked'),   quant?.images_checked ?? '—'],
    ...(totalImgBytes > 0 ? [[t('lbl_total_img_size'), formatBytes(totalImgBytes)]] : []),
  ];

  const hlFields = gsDetected ? new Set([gsKey]) : new Set();

  let html = sectionExplanation('img_expl') + kvTableHighlight(rows, hlFields);

  if (analyzer && analyzer.analyzed && analyzer.analyzed.length) {
    html += '<div class="image-grid" style="margin-top:16px">';
    analyzer.analyzed.slice(0, 24).forEach(img => {
      const size = img.width && img.height ? `${img.width}×${img.height}` : '?×?';
      const hasGps  = img.gps_coords;
      const hasExif = img.has_exif;
      const hasCam  = img.camera_make || img.camera_model;
      const flags   = [];
      if (hasGps)  flags.push(`<span class="img-flag flag-high" title="GPS-Koordinaten in EXIF!">GPS</span>`);
      if (hasCam)  flags.push(`<span class="img-flag flag-info" title="${escapeHtml((img.camera_make||'')+' '+(img.camera_model||''))}">Kamera</span>`);
      if (hasExif && !hasCam && !hasGps) flags.push(`<span class="img-flag flag-info">EXIF</span>`);
      if (img.has_xmp) flags.push(`<span class="img-flag flag-info">XMP</span>`);

      html += `
        <div class="image-card${hasGps ? ' image-card-alert' : ''}">
          <img src="/images/${analysisId}/${img.index}" alt="Bild ${img.index}" loading="lazy"
               onerror="this.style.display='none'">
          <div class="image-card-info">
            <div>#${img.index} · ${size} · ${img.color_mode || '?'}</div>
            ${img.dpi_x ? `<div class="text-muted">${img.dpi_x}×${img.dpi_y} DPI</div>` : ''}
            ${hasCam ? `<div class="text-muted" style="font-size:0.7rem">${escapeHtml((img.camera_make||'') + ' ' + (img.camera_model||''))}</div>` : ''}
            ${img.original_datetime ? `<div class="text-muted" style="font-size:0.7rem">${escapeHtml(img.original_datetime)}</div>` : ''}
            ${img.md5 ? `<div class="text-muted" style="font-size:0.65rem;font-family:monospace">MD5: ${escapeHtml(img.md5.slice(0,16))}…</div>` : ''}
            <div class="img-flags">${flags.join('')}</div>
          </div>
        </div>`;
    });
    html += '</div>';

    // Detail-Tabelle für EXIF/Hashes
    const imgsWithDetails = analyzer.analyzed.filter(img => img.has_exif || img.md5 || img.camera_make);
    if (imgsWithDetails.length > 0) {
      html += `<div class="section-sub-header" style="margin-top:16px"><span>${t('sub_image_details')}</span></div>`;
      html += '<div style="overflow-x:auto"><table class="kv-table"><tr>' +
        `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">#</th>` +
        `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_camera')}</th>` +
        `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_datetime')}</th>` +
        `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">MD5</th>` +
        `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">SHA256</th>` +
        `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">GPS</th></tr>`;
      imgsWithDetails.slice(0, 20).forEach(img => {
        const camStr = [img.camera_make, img.camera_model].filter(Boolean).join(' ') || '—';
        html += `<tr class="${img.gps_coords ? 'highlight-high' : ''}">
          <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">#${img.index}</td>
          <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">${escapeHtml(camStr)}</td>
          <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">${escapeHtml(img.original_datetime || '—')}</td>
          <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.72rem;font-family:monospace;color:var(--muted)">${img.md5 ? escapeHtml(img.md5.slice(0,12)) + '…' : '—'}</td>
          <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.72rem;font-family:monospace;color:var(--muted)">${img.sha256 ? escapeHtml(img.sha256.slice(0,12)) + '…' : '—'}</td>
          <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:${img.gps_coords ? 'var(--high)' : 'var(--muted)'}">${escapeHtml(img.gps_coords || '—')}</td>
        </tr>`;
      });
      html += '</table></div>';
    }
  }

  // Quant matches detail
  if (quant && quant.matches && quant.matches.length > 0) {
    html += `<div class="section-sub-header"><span>${t('sub_quant_matches')}</span></div>`;
    html += '<div style="overflow-x:auto"><table class="kv-table"><tr>' +
      `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_img_index')}</th>` +
      `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_table_type')}</th>` +
      `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_match_score')}</th>` +
      `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_table_id')}</th></tr>`;
    quant.matches.slice(0, 20).forEach(m => {
      html += `<tr class="highlight-medium">
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">#${m.image_index ?? '—'}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">${escapeHtml(m.table_type || '—')}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--medium)">${m.match_score != null ? (m.match_score * 100).toFixed(0) + '%' : '—'}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.75rem;font-family:monospace;color:var(--muted)">${escapeHtml(m.table_id || '—')}</td>
      </tr>`;
    });
    html += '</table></div>';
  }

  const allAnom = [
    ...(extractor.anomalies || []),
    ...(analyzer?.anomalies || []),
    ...(quant?.anomalies || []),
  ];
  if (allAnom.length) html += anomalyMiniList(allAnom);
  el.innerHTML = html;
}

// ===== Helfer =====

function sectionExplanation(i18nKey) {
  const text = t(i18nKey);
  if (!text || text === i18nKey) return '';
  return `<div class="section-explanation">${text}</div>`;
}

function kvTable(rows) {
  let html = '<table class="kv-table">';
  rows.forEach(([k, v, explainKey]) => {
    const tip = explainKey && fieldExpl(explainKey);
    const explain = tip ? `<span class="field-tooltip" title="${escapeHtml(tip)}">ℹ</span>` : '';
    const val = v == null || v === ''
      ? '<span class="text-muted">—</span>'
      : (v && typeof v === 'object' && v.__html)
        ? v.__html
        : escapeHtml(String(v));
    html += `<tr><td>${escapeHtml(k)}${explain}</td><td>${val}</td></tr>`;
  });
  html += '</table>';
  return html;
}

function kvTableHighlight(rows, highlightSet) {
  let html = '<table class="kv-table">';
  rows.forEach(([k, v, explainKey]) => {
    const isHighlighted = highlightSet && highlightSet.has(k);
    const tip = explainKey && fieldExpl(explainKey);
    const explain = tip ? `<span class="field-tooltip" title="${escapeHtml(tip)}">ℹ</span>` : '';
    const val = v == null || v === '' ? '<span class="text-muted">—</span>' : escapeHtml(String(v));
    const rowClass = isHighlighted ? ' class="highlight-row"' : '';
    html += `<tr${rowClass}><td>${escapeHtml(k)}${explain}</td><td>${val}</td></tr>`;
  });
  html += '</table>';
  return html;
}

function anomalyMiniList(anomalies) {
  if (!anomalies || !anomalies.length) return '';
  var isEn = getLang() === 'en';
  var detailsLabel = isEn ? 'Technical details' : 'Technische Details';
  let html = '<div style="margin-top:12px;border-top:1px solid var(--border);padding-top:10px">';
  anomalies.forEach(a => {
    var msg = typeof translateMsg === 'function' ? translateMsg(a.message) : a.message;
    var det = a.detail && typeof translateMsg === 'function' ? translateMsg(a.detail) : a.detail;
    var laien = _getLaienText(a.category, msg);
    html += `<div class="anomaly-item anomaly-item-layered">
      ${severityBadgeHtml(a.severity)}
      <div class="anomaly-category">${escapeHtml(a.category)}</div>
      <div>
        ${laien ? `<div class="anomaly-laien">${escapeHtml(laien)}</div>` : ''}
        <details class="anomaly-tech-details"${laien ? '' : ' open'}>
          <summary>${detailsLabel}</summary>
          <div class="anomaly-message">${escapeHtml(msg)}</div>
          ${det ? `<div class="anomaly-detail">${escapeHtml(det)}</div>` : ''}
        </details>
      </div>
    </div>`;
  });
  html += '</div>';
  return html;
}

function emptyState(msg) {
  return `<p class="text-muted" style="padding:8px 0">${escapeHtml(msg)}</p>`;
}

// ===== Verschlüsselung =====

function renderEncryption(enc) {
  const el = document.getElementById('encContent');
  if (!enc) { el.innerHTML = emptyState(t('no_data')); return; }

  const EXPL = t('enc_expl');

  if (!enc.is_encrypted) {
    el.innerHTML = `<div class="section-explanation">${EXPL}</div>` +
      kvTable([[t('lbl_status'), t('enc_not_encrypted')]]);
    return;
  }

  const strengthColor = {
    'SCHWACH': 'var(--high)', 'MITTEL': 'var(--medium)',
    'STARK': 'var(--clean)', 'SEHR STARK': 'var(--clean)'
  }[enc.strength] || 'var(--muted)';

  const strengthKey = t('lbl_strength');
  const hlFields = new Set();
  if (enc.strength === 'SCHWACH') hlFields.add(strengthKey);

  const rows = [
    [t('lbl_status'),      enc.requires_password ? t('enc_password_protected') : t('enc_encrypted_no_pw')],
    [t('lbl_algorithm'),   enc.algorithm],
    [t('lbl_key_length'),  enc.key_length_bits ? enc.key_length_bits + ' Bit' : '—'],
    [strengthKey,          enc.strength ? `<span style="color:${strengthColor};font-weight:600">${enc.strength}</span>` : '—'],
    [t('lbl_meta_enc'),    enc.encrypt_metadata ? t('yes_clean') : t('enc_meta_unencrypted')],
    ...(enc.v_value != null ? [[t('lbl_enc_v'), enc.v_value + ` (V${enc.v_value})`]] : []),
    ...(enc.r_value != null ? [[t('lbl_enc_r'), enc.r_value + ` (R${enc.r_value})`]] : []),
    ...(enc.p_value != null ? [[t('lbl_enc_p'), '0x' + (enc.p_value >>> 0).toString(16).toUpperCase()]] : []),
    ...(enc.owner_hash ? [[t('lbl_owner_hash'), enc.owner_hash.slice(0, 32) + '…']] : []),
    ...(enc.user_hash  ? [[t('lbl_user_hash'),  enc.user_hash.slice(0, 32)  + '…']] : []),
  ];

  let html = `<div class="section-explanation">${EXPL}</div>` + kvTableHighlight(rows, hlFields);

  if (enc.permissions) {
    const perms = enc.permissions;
    html += `<div class="section-sub-header"><span>${t('sub_permissions')}</span></div>`;
    html += kvTable([
      [t('lbl_print'),        perms.print       ? t('perm_allowed') : t('perm_denied')],
      [t('lbl_edit'),         perms.modify      ? t('perm_allowed') : t('perm_denied')],
      [t('lbl_copy'),         perms.copy        ? t('perm_allowed') : t('perm_denied')],
      [t('lbl_annotate'),     perms.annotate    ? t('perm_allowed') : t('perm_denied')],
      [t('lbl_forms'),        perms.fill_forms  ? t('perm_allowed') : t('perm_denied')],
      [t('lbl_print_hires'), perms.print_highres ? t('perm_allowed') : t('perm_denied')],
    ]);
  }

  if (enc.anomalies && enc.anomalies.length) html += anomalyMiniList(enc.anomalies);
  if (typeof interpEncryption === 'function') html += interpEncryption(enc);
  el.innerHTML = html;
}

// ===== Virus-Scan =====

function renderVirusScan(vs) {
  const el = document.getElementById('virusScanContent');
  if (!vs) { el.innerHTML = emptyState(t('no_data')); return; }

  const EXPL = t('vs_expl');

  const isClean = vs.is_clean !== false;
  const total   = vs.total_detections || 0;

  // Gesamt-Status
  const statusHtml = isClean
    ? `<div class="virus-status virus-clean">${t('vs_clean')}</div>`
    : `<div class="virus-status virus-infected">${total} ${t('vs_infected')}</div>`;

  let html = `<div class="section-explanation">${EXPL}</div>${statusHtml}`;

  // Engines
  const engines = vs.engines || [];
  engines.forEach(eng => {
    const statusIcon = !eng.available  ? ''
                     : !eng.scanned   ? '⏸'
                     : eng.clean      ? ''
                     : '';

    const statusText = !eng.available ? t('vs_unavailable')
                     : !eng.scanned   ? `${t('vs_not_scanned')}${eng.error ? ': ' + eng.error : ''}`
                     : eng.clean      ? t('vs_clean_status')
                     : `${eng.detections.filter(d => d.scanner).length} ${t('vs_detections')}`;

    const durationText = eng.scan_duration_ms != null
      ? `<span style="color:var(--muted);font-size:0.72rem;margin-left:8px">${eng.scan_duration_ms}ms</span>`
      : '';

    html += `<div class="engine-card ${eng.clean === false ? 'engine-infected' : eng.available && eng.scanned ? 'engine-clean' : 'engine-unavailable'}">
      <div class="engine-header">
        <span class="engine-icon">${statusIcon}</span>
        <span class="engine-name">${escapeHtml(eng.name)}</span>
        <span class="engine-status">${escapeHtml(statusText)}</span>
        ${durationText}
      </div>`;

    // Detektionen anzeigen
    const realDetections = (eng.detections || []).filter(d => d.scanner);
    if (realDetections.length > 0) {
      html += `<div class="engine-detections">`;
      realDetections.slice(0, 10).forEach(d => {
        html += `<div class="engine-detection-row">
          <span class="detection-scanner">${escapeHtml(d.scanner)}</span>
          <span class="detection-result ${d.category === 'malicious' ? 'detection-malicious' : 'detection-suspicious'}">${escapeHtml(d.result || d.category)}</span>
        </div>`;
      });
      if (realDetections.length > 10) {
        html += `<div style="font-size:0.75rem;color:var(--muted);padding:4px 0">${t('vs_more').replace('{n}', realDetections.length - 10)}</div>`;
      }
      html += `</div>`;
    }

    // Summary-Zeile (VirusTotal Gesamtstatistik)
    const summary = (eng.detections || []).find(d => d.summary);
    if (summary) {
      html += `<div style="font-size:0.78rem;color:var(--muted);padding:6px 12px 4px">${escapeHtml(summary.summary)}</div>`;
    }

    html += `</div>`;
  });

  // VirusTotal-Link
  if (vs.virustotal_url) {
    html += `<div style="margin-top:12px;font-size:0.83rem">
      <a href="${escapeHtml(vs.virustotal_url)}" target="_blank" rel="noopener"
         style="color:var(--accent)">${t('vs_vt_link')} (${(vs.sha256||'').slice(0,16)}…)</a>
    </div>`;
  }

  if (vs.anomalies && vs.anomalies.length) html += anomalyMiniList(vs.anomalies);
  if (typeof interpVirusScan === 'function') html += interpVirusScan(vs);
  el.innerHTML = html;
}

// ===== Incremental Updates =====

function renderIncrementalUpdates(inc) {
  const el = document.getElementById('incContent');
  if (!inc) { el.innerHTML = emptyState(t('no_data')); return; }

  const EXPL = t('inc_expl');

  const revKey     = t('lbl_revisions');
  const eofKey     = t('lbl_data_after_eof');

  const hlFields = new Set();
  if (inc.revision_count > 1) hlFields.add(revKey);
  if (inc.has_trailing_data)  hlFields.add(eofKey);

  const rows = [
    [revKey, inc.revision_count === 1 ? t('rev_one_clean') : `${inc.revision_count} ${t('revisions_count')}`, revKey],
    [eofKey, inc.has_trailing_data ? `${inc.trailing_bytes} ${t('bytes_after_eof')}` : t('none_clean'), eofKey],
  ];

  let html = `<div class="section-explanation">${EXPL}</div>` + kvTableHighlight(rows, hlFields);

  if (inc.revisions && inc.revisions.length > 1) {
    html += `<div class="section-sub-header"><span>${t('sub_revision_details')}</span></div>
      <div style="overflow-x:auto"><table class="kv-table">
        <tr>
          <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_revision')}</th>
          <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_size')}</th>
          <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_xref_type')}</th>
          <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_new_objects')}</th>
          <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_start_byte')}</th>
          <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_end_byte')}</th>
          <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_xref_offset')}</th>
        </tr>`;
    inc.revisions.forEach(r => {
      const isLast = r.revision === inc.revisions.length;
      html += `<tr class="${r.revision > 1 ? 'highlight-medium' : ''}">
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">${r.revision}${isLast && inc.revision_count > 1 ? ` (${t('rev_current')})` : ''}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">${formatBytes(r.size_bytes)}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">${escapeHtml(r.xref_type)}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">${r.obj_count}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;font-family:monospace;color:var(--text)">${r.start_byte ?? '—'}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;font-family:monospace;color:var(--muted)">${r.end_byte ?? '—'}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;font-family:monospace;color:var(--muted)">${r.xref_offset ?? '—'}</td>
      </tr>`;
    });
    html += '</table></div>';
  }

  if (inc.anomalies && inc.anomalies.length) html += anomalyMiniList(inc.anomalies);
  if (typeof interpIncrementalUpdates === 'function') html += interpIncrementalUpdates(inc);
  el.innerHTML = html;
}

// ===== JavaScript / Actions =====

function renderJavaScript(js) {
  const el = document.getElementById('jsContent');
  if (!js) { el.innerHTML = emptyState(t('no_data')); return; }

  const EXPL = t('js_expl');

  const jsKey        = t('lbl_javascript');
  const autoExecKey  = t('lbl_auto_execute');

  const hlFields = new Set();
  if (js.has_javascript)   hlFields.add(jsKey);
  if (js.has_auto_execute) hlFields.add(autoExecKey);

  const rows = [
    [jsKey,                 js.has_javascript   ? t('present_warning') : t('not_present'), jsKey],
    [autoExecKey,           js.has_auto_execute ? t('auto_exec_yes')   : t('no_clean'),    autoExecKey],
    [t('lbl_total_actions'), js.found_actions.length],
    [t('lbl_js_snippets'),  js.js_snippets.length],
  ];

  let html = `<div class="section-explanation">${EXPL}</div>` + kvTableHighlight(rows, hlFields);

  if (js.found_actions.length > 0) {
    const hasRawDump = js.found_actions.some(a => a.raw_dump);
    html += `<div class="section-sub-header"><span>${t('sub_found_actions')}</span></div>
      <div style="overflow-x:auto"><table class="kv-table">
        <tr>
          <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_location')}</th>
          <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_type')}</th>
          <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_auto_execute')}</th>
          ${hasRawDump ? `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">Rohdaten / Aktionsinhalt</th>` : ''}
        </tr>`;
    js.found_actions.slice(0, 20).forEach(a => {
      const isDangerous = ['/JS', '/JavaScript', '/Launch', '/SubmitForm'].includes(a.type);
      const rawCell = hasRawDump
        ? `<td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.72rem;font-family:monospace;color:var(--muted);max-width:420px;word-break:break-all">${a.raw_dump ? escapeHtml(a.raw_dump) : '—'}</td>`
        : '';
      html += `<tr class="${isDangerous ? 'highlight-high' : a.auto_execute ? 'highlight-medium' : ''}">
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;font-family:monospace;color:var(--text)">${escapeHtml(a.location)}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:${isDangerous ? 'var(--high)' : 'var(--text)'};font-weight:${isDangerous ? '600' : '400'}">${escapeHtml(a.type)}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:${a.auto_execute ? 'var(--high)' : 'var(--clean)'}">${a.auto_execute ? t('auto_exec_short') : t('no_clean')}</td>
        ${rawCell}
      </tr>`;
    });
    html += '</table></div>';
  }

  if (js.js_snippets.length > 0) {
    html += `<div class="section-sub-header"><span>${t('sub_js_snippets')}</span></div>`;
    js.js_snippets.slice(0, 3).forEach(s => {
      html += `<div class="js-snippet">
        <div class="js-snippet-loc">${escapeHtml(s.location)}</div>
        <pre class="js-snippet-code">${escapeHtml(s.code)}</pre>
      </div>`;
    });
  }

  if (js.anomalies && js.anomalies.length) html += anomalyMiniList(js.anomalies);
  if (typeof interpJavaScript === 'function') html += interpJavaScript(js);
  el.innerHTML = html;
}

// ===== Embedded Files + Annotations =====

function renderEmbeddedFiles(ef) {
  const el = document.getElementById('efContent');
  if (!ef) { el.innerHTML = emptyState(t('no_data')); return; }

  const EXPL = t('ef_expl');

  const embKey    = t('lbl_embedded_files');
  const hiddenKey = t('lbl_hidden_annotations');

  const hlFields = new Set();
  if (ef.embedded_file_count > 0)       hlFields.add(embKey);
  if (ef.hidden_annotation_count > 0)   hlFields.add(hiddenKey);

  const rows = [
    [embKey,                ef.embedded_file_count > 0 ? `${ef.embedded_file_count} ${t('file_count_suffix')}` : t('none_clean'), embKey],
    [t('lbl_annotations'),  ef.annotation_count],
    [hiddenKey,             ef.hidden_annotation_count > 0 ? `${ef.hidden_annotation_count}` : t('none_clean'), hiddenKey],
    [t('lbl_obj_streams'),  ef.obj_stream_count || '—'],
  ];

  let html = `<div class="section-explanation">${EXPL}</div>` + kvTableHighlight(rows, hlFields);

  if (ef.embedded_files.length > 0) {
    html += `<div class="section-sub-header"><span>${t('sub_embedded_files')}</span></div>
      <div style="overflow-x:auto"><table class="kv-table">
        <tr>
          <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_filename')}</th>
          <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_size')}</th>
          <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_mime')}</th>
          <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_sha256')}</th>
        </tr>`;
    ef.embedded_files.forEach(f => {
      const dangerous = /\.(exe|dll|bat|cmd|ps1|vbs|js|jar|scr)$/i.test(f.filename);
      html += `<tr class="${dangerous ? 'highlight-high' : ''}">
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:${dangerous ? 'var(--high)' : 'var(--text)'};font-weight:${dangerous ? '600' : '400'}">${escapeHtml(f.filename)}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">${formatBytes(f.size_bytes)}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">${escapeHtml(f.mime_type)}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.75rem;font-family:monospace;color:var(--text)">${(f.sha256||'').slice(0,16)}…</td>
      </tr>`;
    });
    html += '</table></div>';
  }

  // Annotations Detail
  if (ef.annotations && ef.annotations.length > 0) {
    const hiddenAnns = ef.annotations.filter(a => a.is_hidden);
    html += `<div class="section-sub-header"><span>${hiddenAnns.length > 0 ? '' : ''}${t('sub_annotations')} (${ef.annotations.length})</span></div>
      <div style="overflow-x:auto"><table class="kv-table">
        <tr>
          <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_page')}</th>
          <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_type')}</th>
          <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_hidden')}</th>
          <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_contents')}</th>
          <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">URI</th>
        </tr>`;
    ef.annotations.slice(0, 30).forEach(a => {
      html += `<tr class="${a.is_hidden ? 'highlight-high' : ''}">
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">${a.page ?? '—'}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">${escapeHtml(a.type || '—')}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:${a.is_hidden ? 'var(--high)' : 'var(--clean)'}">${a.is_hidden ? '' + t('yes') : t('no')}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.75rem;color:var(--muted);max-width:200px;overflow:hidden;text-overflow:ellipsis">${escapeHtml((a.contents || '').slice(0, 100))}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.72rem;font-family:monospace;color:var(--accent);word-break:break-all;max-width:160px">${escapeHtml((a.uri || '').slice(0, 80))}</td>
      </tr>`;
    });
    html += '</table></div>';
  }

  if (ef.anomalies && ef.anomalies.length) html += anomalyMiniList(ef.anomalies);
  if (typeof interpEmbeddedFiles === 'function') html += interpEmbeddedFiles(ef);
  el.innerHTML = html;
}

// ===== PDF-Only Sektionen toggle =====

function _togglePdfOnlySections(show) {
  // Sektionen die nur für PDFs relevant sind
  const pdfOnlyIds = [
    'uuidCard', 'imagesCard', 'jsCard',
  ];
  // Cards die immer sichtbar sind (Hashes, Metadaten, Virus-Scan etc.) bleiben.
  // Wir blenden nur die reinen PDF-Analyzer-Sektionen aus bei Office-Docs.
  pdfOnlyIds.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.display = show ? '' : 'none';
  });
  // OOXML/OLE-Cards
  const ooxmlCard = document.getElementById('ooxmlCard');
  const oleCard   = document.getElementById('oleCard');
  if (ooxmlCard) ooxmlCard.style.display = show ? 'none' : '';
  if (oleCard)   oleCard.style.display   = show ? 'none' : '';
}

// ===== OOXML (DOCX / XLSX / PPTX) =====

function renderOOXML(ooxml) {
  const card = document.getElementById('ooxmlCard');
  const el   = document.getElementById('ooxmlContent');
  if (!el) return;
  if (!ooxml) { if (card) card.style.display = 'none'; return; }
  if (card) card.style.display = '';

  const cp = ooxml.core_props || {};
  const ap = ooxml.app_props  || {};
  const mac = ooxml.macros    || {};

  const rows = [
    [t('lbl_format'),        ooxml.format || '—'],
    [t('lbl_title'),         cp.title || '—'],
    [t('lbl_author'),        cp.creator || '—'],
    [t('lbl_last_mod_by'),   cp.last_modified_by || '—'],
    [t('lbl_created'),       formatDate(cp.created)],
    [t('lbl_modified'),      formatDate(cp.modified)],
    [t('lbl_revision'),      cp.revision || '—'],
    [t('lbl_application'),   ap.application || '—'],
    [t('lbl_app_version'),   ap.appversion || '—'],
    [t('lbl_company'),       ap.company || '—'],
    [t('lbl_template'),      cp.template || ap.template || '—'],
    [t('lbl_rsid_count'),    ooxml.rsid_count || 0],
    [t('lbl_tc_authors'),    ooxml.tc_author_count || 0],
    [t('lbl_external_links'), ooxml.external_links?.length || 0],
    [t('lbl_media_files'),   ooxml.media?.length || 0],
    [t('lbl_macros'),        mac.has_macros ? `${t('yes')}` : `${t('no')}`],
  ];

  const hlFields = new Set();
  if (mac.has_macros)              hlFields.add(t('lbl_macros'));
  if (ooxml.external_links?.length) hlFields.add(t('lbl_external_links'));

  let html = sectionExplanation('ooxml_expl') + kvTableHighlight(rows, hlFields);

  // Track-Changes
  if (ooxml.track_changes && ooxml.track_changes.length > 0) {
    html += `<div class="section-sub-header"><span>${t('sub_track_changes')} (${ooxml.track_changes.length})</span></div>
      <div style="overflow-x:auto"><table class="kv-table"><tr>
        <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_type')}</th>
        <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_author')}</th>
        <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_date')}</th>
        <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_text')}</th>
      </tr>`;
    ooxml.track_changes.slice(0, 20).forEach(c => {
      html += `<tr>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">${escapeHtml(c.type || '—')}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;font-weight:500;color:var(--accent)">${escapeHtml(c.author || '—')}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--muted)">${escapeHtml(c.date || '—')}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.72rem;color:var(--muted);max-width:200px;overflow:hidden;text-overflow:ellipsis">${escapeHtml(c.text || '—')}</td>
      </tr>`;
    });
    html += '</table></div>';
  }

  // RSIDs (erste 20)
  if (ooxml.rsids && ooxml.rsids.length > 0) {
    html += `<div class="section-sub-header"><span>${t('sub_rsids')} (${ooxml.rsid_count} ${t('rsid_total')})</span></div>`;
    html += `<div style="font-family:monospace;font-size:0.72rem;color:var(--muted);line-height:1.8;padding:8px 0">`;
    html += ooxml.rsids.slice(0, 40).map(r => escapeHtml(r)).join(' · ');
    if (ooxml.rsids.length > 40) html += ` <em>… +${ooxml.rsids.length - 40} ${t('more')}</em>`;
    html += '</div>';
  }

  // Externe Links
  if (ooxml.external_links && ooxml.external_links.length > 0) {
    html += `<div class="section-sub-header"><span>${t('sub_external_links')}</span></div>`;
    ooxml.external_links.forEach(r => {
      html += `<div class="anomaly-item">
        ${severityBadgeHtml('MEDIUM')}
        <div class="anomaly-category">${escapeHtml(r.type || '')}</div>
        <div><div class="anomaly-message" style="word-break:break-all">${escapeHtml(r.target || '')}</div></div>
      </div>`;
    });
  }

  // Custom Properties
  if (ooxml.custom_props && ooxml.custom_props.length > 0) {
    html += `<div class="section-sub-header"><span>${t('sub_custom_props')}</span></div>`;
    html += kvTable(ooxml.custom_props.map(p => [p.name, p.value]));
  }

  if (ooxml.anomalies && ooxml.anomalies.length) html += anomalyMiniList(ooxml.anomalies);
  el.innerHTML = html;
}

// ===== OLE2 (DOC / XLS / PPT) =====

function renderOLE(ole) {
  const card = document.getElementById('oleCard');
  const el   = document.getElementById('oleContent');
  if (!el) return;
  if (!ole) { if (card) card.style.display = 'none'; return; }
  if (card) card.style.display = '';

  const s  = ole.summary     || {};
  const ds = ole.doc_summary || {};

  const rows = [
    [t('lbl_format'),       ole.format || '—'],
    [t('lbl_title'),        s.title || '—'],
    [t('lbl_author'),       s.author || '—'],
    [t('lbl_last_mod_by'),  s.last_author || '—'],
    [t('lbl_created'),      formatDate(s.created)],
    [t('lbl_modified'),     formatDate(s.last_saved)],
    [t('lbl_revision'),     s.revision != null ? s.revision : '—'],
    [t('lbl_application'),  s.app_name || '—'],
    [t('lbl_company'),      ds.company || '—'],
    [t('lbl_template'),     s.template || '—'],
    [t('lbl_pages'),        s.page_count != null ? s.page_count : '—'],
    [t('lbl_words'),        s.word_count != null ? s.word_count : '—'],
    [t('lbl_macros'),       ole.has_macros ? `${t('yes')}` : `${t('no')}`],
  ];

  const hlFields = new Set();
  if (ole.has_macros) hlFields.add(t('lbl_macros'));

  let html = sectionExplanation('ole_expl') + kvTableHighlight(rows, hlFields);

  // Gefundene Strings (Pfade, E-Mails, Namen)
  if (ole.strings && ole.strings.length > 0) {
    html += `<div class="section-sub-header"><span>${t('sub_ole_strings')}</span></div>`;
    html += '<div style="overflow-x:auto"><table class="kv-table">';
    ole.strings.forEach((s, i) => {
      html += `<tr><td style="padding:6px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;font-family:monospace;color:var(--text)">${escapeHtml(s)}</td></tr>`;
    });
    html += '</table></div>';
  }

  if (ole.anomalies && ole.anomalies.length) html += anomalyMiniList(ole.anomalies);
  el.innerHTML = html;
}

// ===== Timezone-Analyse =====

function renderTimezone(tz) {
  const el = document.getElementById('timezoneContent');
  if (!el) return;
  if (!tz || !tz.dates || tz.dates.length === 0) {
    el.innerHTML = emptyState(t('no_timezone_data'));
    return;
  }

  const uniqueOffsetsStr = (tz.unique_offsets && tz.unique_offsets.length)
    ? tz.unique_offsets.map(o => (o >= 0 ? '+' : '') + o + ' min').join(', ')
    : '—';

  const rows = [
    [t('lbl_tz_region'),     tz.region_hint || '—'],
    [t('lbl_tz_consistent'), tz.offset_consistent ? t('yes_clean') : `${t('tz_inconsistent')}`],
    [t('lbl_tz_dates_found'), tz.dates.length],
    [t('lbl_tz_unique_offsets'), uniqueOffsetsStr],
  ];

  const hlFields = tz.offset_consistent ? new Set() : new Set([t('lbl_tz_consistent')]);
  let html = sectionExplanation('tz_expl') + kvTableHighlight(rows, hlFields);

  // Datums-Tabelle
  html += `<div style="margin-top:12px;overflow-x:auto"><table class="kv-table">
    <tr>
      <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_tz_source')}</th>
      <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_tz_local')}</th>
      <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_tz_utc')}</th>
      <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_tz_offset')}</th>
      <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_tz_region')}</th>
    </tr>`;
  tz.dates.slice(0, 15).forEach(d => {
    html += `<tr>
      <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.75rem;font-family:monospace;color:var(--text)">${escapeHtml(d.source || '—')}</td>
      <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">${escapeHtml(d.iso_local || '—')}</td>
      <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">${escapeHtml(d.iso_utc || '—')}</td>
      <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;font-family:monospace;color:var(--text)">${escapeHtml(d.tz_string || '—')}</td>
      <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--muted)">${escapeHtml(d.region || '—')}</td>
    </tr>`;
  });
  html += '</table></div>';

  if (tz.anomalies && tz.anomalies.length) html += anomalyMiniList(tz.anomalies);
  el.innerHTML = html;
}

// ===== Author-Artifacts =====

function renderAuthorArtifacts(aa) {
  const el = document.getElementById('authorContent');
  if (!el) return;
  if (!aa || aa.all_artifacts.length === 0) {
    el.innerHTML = emptyState(t('no_author_artifacts'));
    return;
  }

  const rows = [
    [t('lbl_font_prefixes'),      aa.font_prefixes.length || 0],
    [t('lbl_xmp_author_hints'),   aa.xmp_authors.length || 0],
    [t('lbl_annotation_authors'), aa.annotation_authors.length || 0],
    [t('lbl_paths_found'),        aa.all_artifacts.filter(a => a.source && a.source.includes('[path]')).length],
    [t('lbl_emails_found'),       aa.all_artifacts.filter(a => a.source && a.source.includes('[email]')).length],
    [t('lbl_printer_name'),       aa.printer_name.length ? aa.printer_name.map(p => p.value || '').join(', ') : '—'],
    [t('lbl_form_fields'),        aa.form_field_hints.length || 0],
  ];

  let html = sectionExplanation('aa_expl') + kvTable(rows);

  // Font-Präfixe
  if (aa.font_prefixes.length > 0) {
    html += `<div class="section-sub-header"><span>${t('sub_font_prefixes')}</span></div>`;
    html += '<div style="overflow-x:auto"><table class="kv-table"><tr>' +
      `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_prefix')}</th>` +
      `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_font_name')}</th>` +
      `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_page')}</th>` +
      `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('lbl_note')}</th></tr>`;
    aa.font_prefixes.forEach(p => {
      html += `<tr>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-family:monospace;font-size:0.78rem;color:var(--accent)">${escapeHtml(p.prefix)}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">${escapeHtml(p.font_name)}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">${p.page}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.75rem;color:var(--muted)">${escapeHtml(p.note || '—')}</td>
      </tr>`;
    });
    html += '</table></div>';
  }

  // Form Field Hints
  if (aa.form_field_hints && aa.form_field_hints.length > 0) {
    html += `<div class="section-sub-header"><span>${t('sub_form_fields')}</span></div>`;
    html += '<div style="overflow-x:auto"><table class="kv-table"><tr>' +
      `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_field_name')}</th>` +
      `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_value')}</th>` +
      `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_source')}</th></tr>`;
    aa.form_field_hints.slice(0, 20).forEach(f => {
      html += `<tr class="highlight-low">
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">${escapeHtml(f.field_name || '—')}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;font-family:monospace;color:var(--text);word-break:break-all">${escapeHtml(f.value || '—')}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.75rem;color:var(--muted)">${escapeHtml(f.source || '—')}</td>
      </tr>`;
    });
    html += '</table></div>';
  }

  // XMP-Autoren
  if (aa.xmp_authors && aa.xmp_authors.length > 0) {
    html += `<div class="section-sub-header"><span>${t('sub_xmp_authors')}</span></div>`;
    html += '<div style="overflow-x:auto"><table class="kv-table"><tr>' +
      `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_source')}</th>` +
      `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_value')}</th></tr>`;
    aa.xmp_authors.slice(0, 15).forEach(a => {
      html += `<tr><td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.75rem;color:var(--muted)">${escapeHtml(a.source || '—')}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;font-family:monospace;color:var(--text)">${escapeHtml(a.value || '—')}</td></tr>`;
    });
    html += '</table></div>';
  }

  // Annotation-Autoren
  if (aa.annotation_authors && aa.annotation_authors.length > 0) {
    html += `<div class="section-sub-header"><span>${t('sub_annotation_authors')}</span></div>`;
    html += '<div style="overflow-x:auto"><table class="kv-table"><tr>' +
      `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_source')}</th>` +
      `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_value')}</th>` +
      `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_type')}</th></tr>`;
    aa.annotation_authors.slice(0, 15).forEach(a => {
      html += `<tr><td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.75rem;color:var(--muted)">${escapeHtml(a.source || '—')}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;font-family:monospace;color:var(--accent)">${escapeHtml(a.value || '—')}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--muted)">${escapeHtml(a.type || '—')}</td></tr>`;
    });
    html += '</table></div>';
  }

  // Alle Artefakte (paths, emails, xmp)
  const interesting = aa.all_artifacts.filter(a => a.source && (a.source.includes('[path]') || a.source.includes('[email]') || a.source.startsWith('Annotation')));
  if (interesting.length > 0) {
    html += `<div class="section-sub-header"><span>${t('sub_author_artifacts')}</span></div>`;
    html += '<div style="overflow-x:auto"><table class="kv-table"><tr>' +
      `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_source')}</th>` +
      `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_value')}</th></tr>`;
    interesting.slice(0, 20).forEach(a => {
      const isPath  = a.source && a.source.includes('[path]');
      const isEmail = a.source && a.source.includes('[email]');
      html += `<tr class="${isPath || isEmail ? 'highlight-medium' : ''}">
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.75rem;color:var(--muted)">${escapeHtml(a.source)}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;font-family:monospace;color:var(--text);word-break:break-all">${escapeHtml(a.value)}</td>
      </tr>`;
    });
    html += '</table></div>';
  }

  if (aa.anomalies && aa.anomalies.length) html += anomalyMiniList(aa.anomalies);
  if (typeof interpAuthorArtifacts === 'function') html += interpAuthorArtifacts(aa);
  el.innerHTML = html;
}

// ===== ELA (Error Level Analysis) =====

function renderELA(ela) {
  const el = document.getElementById('elaContent');
  if (!el) return;

  if (!ela || !ela.available) {
    el.innerHTML = sectionExplanation('ela_expl') +
      `<div class="anomaly-item" style="margin-top:8px">
        ${severityBadgeHtml('LOW')}
        <div class="anomaly-category">ELA</div>
        <div><div class="anomaly-message">${t('ela_unavailable')}</div></div>
      </div>`;
    return;
  }
  if (ela.images_checked === 0) {
    el.innerHTML = sectionExplanation('ela_expl') +
      `<div style="padding:12px;background:var(--surface2);border-radius:6px;margin-top:8px;font-size:0.85rem;color:var(--muted)">
        ${t('ela_no_images')}
      </div>`;
    return;
  }

  let html = sectionExplanation('ela_expl') + kvTable([
    [t('lbl_images_checked'), ela.images_checked],
    [t('lbl_suspicious_images'), ela.results.filter(r => r.ela && r.ela.verdict === 'SUSPICIOUS').length],
    [t('lbl_copy_move_detected'), ela.results.filter(r => r.copy_move && r.copy_move.copy_move_detected).length],
  ]);

  // Einzelne Bild-Ergebnisse
  ela.results.forEach(r => {
    if (!r.ela) return;
    const verdict      = r.ela.verdict || 'NORMAL';
    const verdictClass = verdict === 'SUSPICIOUS' ? 'highlight-high' : verdict === 'LOW_SIGNAL' ? 'highlight-low' : '';
    const verdictIcon  = verdict === 'SUSPICIOUS' ? '' : verdict === 'LOW_SIGNAL' ? '' : '';

    html += `<div class="card" style="margin-top:10px;padding:12px">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
        <span>${verdictIcon}</span>
        <strong>${t('lbl_image')} ${r.name} (${t('col_page')} ${r.page})</strong>
        ${r.size_bytes ? `<span style="font-size:0.72rem;color:var(--muted)">${formatBytes(r.size_bytes)}</span>` : ''}
        ${r.ela.dimensions ? `<span style="font-size:0.72rem;color:var(--muted)">${escapeHtml(r.ela.dimensions)}</span>` : ''}
        <span class="explain-badge ${verdictClass}" style="margin-left:auto">${verdict}</span>
      </div>`;

    if (r.ela.ela_preview) {
      html += `<div style="display:flex;gap:12px;flex-wrap:wrap">
        <div>
          <div style="font-size:0.72rem;color:var(--muted);margin-bottom:4px">${t('ela_difference_image')}</div>
          <img src="${r.ela.ela_preview}" style="max-width:220px;border-radius:4px;border:1px solid var(--border)" title="ELA Mean: ${r.ela.ela_mean}">
        </div>
        <div style="font-size:0.82rem;color:var(--muted)">
          <div>${t('lbl_ela_mean')}: <strong style="color:var(--text)">${r.ela.ela_mean}</strong></div>
          <div>${t('lbl_ela_max')}: <strong style="color:var(--text)">${r.ela.ela_max}</strong></div>
          ${r.ela.hot_regions && r.ela.hot_regions.length ? `<div>${t('lbl_ela_hot_regions')}: <strong style="color:var(--medium)">${r.ela.hot_regions.length}</strong></div>` : ''}
          <div style="margin-top:6px;font-size:0.78rem">${escapeHtml(r.ela.note || '')}</div>
          ${r.copy_move ? `<div style="margin-top:6px">Copy-Move: <strong style="color:${r.copy_move.copy_move_detected ? 'var(--high)' : 'var(--clean)'}">${r.copy_move.duplicate_blocks} ${t('lbl_dup_blocks')}</strong></div>` : ''}
        </div>
      </div>`;
    }
    html += '</div>';
  });

  if (ela.anomalies && ela.anomalies.length) html += anomalyMiniList(ela.anomalies);
  el.innerHTML = html;
}

// ===== Object Streams =====

function renderObjectStreams(os) {
  const el = document.getElementById('objstreamsContent');
  if (!el) return;
  if (!os) { el.innerHTML = emptyState(t('no_data')); return; }

  const xref     = os.xref_info || {};
  const dupObjs  = os.duplicate_objs || [];
  const streams  = os.obj_streams || [];

  const dupKey  = t('lbl_duplicate_objects');
  const hybKey  = t('lbl_hybrid_xref');
  const hlFields = new Set();
  if (dupObjs.length)             hlFields.add(dupKey);
  if (xref.has_hybrid_xref)       hlFields.add(hybKey);

  const rows = [
    [t('lbl_obj_stream_count'), os.obj_stream_count || 0],
    [t('lbl_xref_type'),        xref.note || '—'],
    [hybKey,                    xref.has_hybrid_xref ? `${t('yes')}` : t('no_clean'), hybKey],
    [dupKey,                    dupObjs.length ? `${dupObjs.length} ${t('obj_count_suffix')}` : t('none_clean'), dupKey],
  ];

  let html = sectionExplanation('os_expl') + kvTableHighlight(rows, hlFields);

  // Alle Streams Tabelle
  if (streams.length > 0) {
    html += `<div class="section-sub-header"><span>${t('sub_obj_streams_list')}</span></div>`;
    html += '<div style="overflow-x:auto"><table class="kv-table"><tr>' +
      `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_obj_num')}</th>` +
      `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_stream_len')}</th>` +
      `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_sub_objects')}</th>` +
      `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_first_offset')}</th>` +
      `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">Linearized</th>` +
      `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_flags')}</th></tr>`;
    streams.slice(0, 20).forEach(s => {
      const isDangerous = (s.suspicious_keys && s.suspicious_keys.length) || s.has_javascript;
      const subObjCount = s.sub_objects ? s.sub_objects.length : (s.n_objects || s.n || 0);
      const flags = [
        s.has_javascript ? 'JS' : '',
        s.has_info_dict  ? '/Info' : '',
        s.linearized ? 'Linearized' : '',
        s.suspicious_keys && s.suspicious_keys.length ? `${escapeHtml(s.suspicious_keys.join(', '))}` : '',
      ].filter(Boolean).join(' · ');
      html += `<tr class="${isDangerous ? 'highlight-high' : ''}">
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-family:monospace;font-size:0.78rem;color:${isDangerous ? 'var(--high)' : 'var(--text)'}">#${s.obj_id}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">${s.stream_length != null ? formatBytes(s.stream_length) : (s.size_bytes != null ? formatBytes(s.size_bytes) : '—')}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">${subObjCount}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;font-family:monospace;color:var(--muted)">${s.first_offset ?? '—'}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:${s.linearized ? 'var(--accent)' : 'var(--muted)'}">${s.linearized ? t('yes') : t('no')}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.75rem;color:var(--text)">${flags || '—'}</td>
      </tr>`;
    });
    html += '</table></div>';
  }

  // Doppelte Objekte
  if (dupObjs.length > 0) {
    html += `<div class="section-sub-header"><span>${t('sub_duplicate_objs')}</span></div>`;
    html += '<div style="overflow-x:auto"><table class="kv-table"><tr>' +
      `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_obj_num')}</th>` +
      `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('lbl_occurrences')}</th>` +
      `<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('lbl_note')}</th></tr>`;
    dupObjs.forEach(d => {
      html += `<tr class="highlight-high">
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-family:monospace;font-size:0.78rem;color:var(--high)">#${d.obj_num}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">${d.count || '—'}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--muted)">${escapeHtml(d.note || '')}</td>
      </tr>`;
    });
    html += '</table></div>';
  }

  if (os.anomalies && os.anomalies.length) html += anomalyMiniList(os.anomalies);
  if (typeof interpObjectStreams === 'function') html += interpObjectStreams(os);
  el.innerHTML = html;
}

// ===== Residual Objects =====

function renderResidualObjects(ro) {
  const el = document.getElementById('residualContent');
  if (!el) return;
  if (!ro) { el.innerHTML = emptyState(t('no_data')); return; }

  const trailing = ro.trailing_data || {};
  const eof      = ro.eof_info || {};

  const orphKey  = t('lbl_orphaned_objects');
  const trailKey = t('lbl_trailing_data');
  const hlFields = new Set();
  if (ro.orphaned_count > 0)  hlFields.add(orphKey);
  if (trailing.found)         hlFields.add(trailKey);

  const rows = [
    [orphKey,     ro.orphaned_count > 0 ? `${ro.orphaned_count} ${t('obj_count_suffix')}` : t('none_clean'), orphKey],
    [trailKey,    trailing.found ? `${trailing.trailing_bytes} ${t('bytes_suffix')}` : t('none_clean'), trailKey],
    [t('lbl_eof_count'), eof.count || 1],
  ];

  let html = sectionExplanation('ro_expl') + kvTableHighlight(rows, hlFields);

  // Verwaiste Objekte Details
  if (ro.orphaned_objects && ro.orphaned_objects.length > 0) {
    html += `<div class="section-sub-header"><span>${t('sub_orphaned_objects')}</span></div>
      <div style="overflow-x:auto"><table class="kv-table"><tr>
        <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_obj_num')}</th>
        <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_byte_offset')}</th>
        <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_type_hint')}</th>
        <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_flags')}</th>
        <th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">${t('col_preview')}</th>
      </tr>`;
    ro.orphaned_objects.slice(0, 15).forEach(o => {
      const c   = o.content || {};
      const sev = c.has_js ? 'high' : c.has_metadata ? 'medium' : '';
      const flags = [
        c.has_text     ? 'Text' : '',
        c.has_metadata ? 'Metadata' : '',
        c.has_js       ? 'JS' : '',
        c.has_url      ? 'URL' : '',
        c.has_stream   ? 'Stream' : '',
      ].filter(Boolean).join(' · ');
      html += `<tr class="${sev ? 'highlight-' + sev : ''}">
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-family:monospace;font-size:0.78rem;color:var(--text)">#${o.obj_num}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;font-family:monospace;color:var(--muted)">${o.offset != null ? o.offset : '—'}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">${escapeHtml(c.type_hint || '—')}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">${escapeHtml(flags || '—')}</td>
        <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.72rem;font-family:monospace;color:var(--muted);max-width:300px;overflow:hidden;text-overflow:ellipsis">${escapeHtml((c.preview || '').slice(0, 80))}</td>
      </tr>`;
    });
    html += '</table></div>';
  }

  // EOF Info
  if (eof && (eof.count > 1 || (eof.offsets && eof.offsets.length > 1))) {
    html += `<div class="section-sub-header"><span>${t('sub_eof_markers')}</span></div>`;
    const eofRows = [
      [t('lbl_eof_count'), eof.count || 1],
    ];
    if (eof.offsets && eof.offsets.length > 0) {
      eofRows.push([t('col_byte_offset'), eof.offsets.map(String).join(', ')]);
    }
    html += kvTable(eofRows);
  }

  if (trailing.found) {
    html += `<div class="section-sub-header"><span>${t('sub_trailing_data')}</span></div>`;
    html += kvTable([
      [t('col_trailing_bytes'), trailing.trailing_bytes],
      [t('col_hex_preview'),    trailing.preview_hex || '—'],
      [t('col_text_preview'),   trailing.preview_text || '—'],
    ]);
  }

  if (ro.anomalies && ro.anomalies.length) html += anomalyMiniList(ro.anomalies);
  if (typeof interpResidualObjects === 'function') html += interpResidualObjects(ro);
  el.innerHTML = html;
}

// ===== Shadow Attack Detection =====

function renderShadowAttack(sa) {
  const el = document.getElementById('shadowContent');
  if (!el) return;
  if (!sa || !sa.has_signature) {
    el.innerHTML = sectionExplanation('sa_expl') +
      `<div style="padding:12px;background:var(--surface2);border-radius:6px;margin-top:8px;font-size:0.85rem;color:var(--muted)">
        ${t('shadow_no_signature')}
      </div>`;
    return;
  }

  const shadowSuspicious = sa.shadow_analysis.some(s => !s.covers_full);
  const isaSuspicious    = sa.isa_analysis.some(i => i.isa_detected);
  const wrapSuspicious   = sa.wrapping_check && sa.wrapping_check.suspicious;

  const shadowKey = t('lbl_shadow_attack');
  const isaKey    = t('lbl_isa_attack');
  const wrapKey   = t('lbl_sig_wrapping');
  const hlFields  = new Set();
  if (shadowSuspicious) hlFields.add(shadowKey);
  if (isaSuspicious)    hlFields.add(isaKey);
  if (wrapSuspicious)   hlFields.add(wrapKey);

  const wrapOccurrences = sa.wrapping_check?.byte_range_occurrences;
  const rows = [
    [t('lbl_sig_count'),  sa.signature_count || 0],
    [shadowKey,           shadowSuspicious ? `${t('shadow_suspicious')}` : `${t('shadow_clean')}`, shadowKey],
    [isaKey,              isaSuspicious    ? `${t('isa_suspicious')}`    : `${t('isa_clean')}`,    isaKey],
    [wrapKey,             wrapSuspicious   ? `${t('wrap_suspicious')}`   : `${t('wrap_clean')}`,   wrapKey],
    ...(wrapOccurrences != null ? [[t('lbl_byte_range_occ'), wrapOccurrences]] : []),
  ];

  let html = sectionExplanation('sa_expl') + kvTableHighlight(rows, hlFields);

  // ByteRange-Details
  if (sa.shadow_analysis.length > 0) {
    html += `<div class="section-sub-header"><span>${t('sub_byte_range_analysis')}</span></div>`;
    sa.shadow_analysis.forEach((s, i) => {
      const suspicious = !s.covers_full;
      html += `<div style="background:${suspicious ? 'rgba(239,68,68,0.07)' : 'var(--surface2)'};border:1px solid ${suspicious ? 'var(--high)' : 'var(--border)'};border-radius:6px;padding:10px;margin-bottom:6px">
        <div style="font-size:0.82rem;font-weight:600;margin-bottom:6px;color:${suspicious ? 'var(--high)' : 'var(--text)'}">${t('lbl_signature')} ${i+1} · ${escapeHtml(s.sub_filter || '')}</div>
        ${kvTable([
          ['ByteRange',                 `[${(s.byte_range || []).join(', ')}]`],
          [t('col_prefix_bytes'),       s.prefix_bytes],
          [t('col_suffix_bytes'),       s.suffix_bytes],
          [t('col_covers_full'),        s.covers_full ? `${t('yes')}` : `${t('no')}`],
          [t('lbl_signed_from'),        s.signed_from != null ? s.signed_from + ' B' : '—'],
          [t('lbl_signed_to'),          s.signed_to   != null ? s.signed_to   + ' B' : '—'],
        ])}
      </div>`;
    });
  }

  // ISA-Details
  if (sa.isa_analysis.length > 0) {
    html += `<div class="section-sub-header"><span>${t('sub_isa_analysis')}</span></div>`;
    sa.isa_analysis.forEach((isa, i) => {
      html += `<div style="background:${isa.isa_detected ? 'rgba(239,68,68,0.07)' : 'var(--surface2)'};border:1px solid ${isa.isa_detected ? 'var(--high)' : 'var(--border)'};border-radius:6px;padding:10px;margin-bottom:6px">
        <div style="font-size:0.82rem;font-weight:600;color:${isa.isa_detected ? 'var(--high)' : 'var(--text)'}">${t('lbl_signature')} ${i+1}: ${isa.isa_detected ? 'ISA detected' : 'OK'}</div>
        ${kvTable([
          [t('lbl_bytes_after_sig'),  isa.bytes_after_sig != null ? isa.bytes_after_sig + ' B' : '—'],
          [t('lbl_has_xref_after'),   isa.has_xref_after  ? `${t('yes')}` : `${t('no')}`],
          [t('lbl_has_obj_after'),    isa.has_obj_after   ? `${t('yes')}` : `${t('no')}`],
          [t('lbl_doc_end_offset'),   isa.doc_end_offset != null ? isa.doc_end_offset + ' B' : '—'],
          [t('lbl_file_size'),        isa.file_size != null ? formatBytes(isa.file_size) : '—'],
        ])}
        <div style="font-size:0.78rem;color:var(--muted);margin-top:6px">${escapeHtml(isa.note || '')}</div>
      </div>`;
    });
  }

  if (sa.anomalies && sa.anomalies.length) html += anomalyMiniList(sa.anomalies);
  if (typeof interpShadowAttack === 'function') html += interpShadowAttack(sa);
  el.innerHTML = html;
}

// ===== History-Direktlink: ?analysis_id=xyz =====

document.addEventListener('DOMContentLoaded', async () => {
  const params = new URLSearchParams(window.location.search);
  const id = params.get('analysis_id');
  if (!id) return;

  const progressContainer = document.getElementById('progressContainer');
  const uploadZone        = document.getElementById('uploadZone');
  const errorAlert        = document.getElementById('errorAlert');
  const errorMessage      = document.getElementById('errorMessage');

  if (uploadZone) uploadZone.style.display = 'none';
  if (progressContainer) {
    progressContainer.style.display = 'block';
    document.getElementById('progressLabel').textContent = t('loading_saved_analysis');
    document.getElementById('progressFill').style.width = '60%';
  }

  try {
    const resp = await fetch(`/analysis/${id}`);
    if (!resp.ok) throw new Error(t('analysis_not_found'));
    const data = await resp.json();

    if (progressContainer) progressContainer.style.display = 'none';
    if (uploadZone) uploadZone.style.display = 'flex';

    renderResult(data);
  } catch (err) {
    if (progressContainer) progressContainer.style.display = 'none';
    if (uploadZone) uploadZone.style.display = 'flex';
    if (errorAlert && errorMessage) {
      errorMessage.textContent = err.message;
      errorAlert.style.display = 'flex';
    }
  }
});

// ============================================================
// Phase 3 — Image Forensics
// ============================================================

function renderImageForensics(data) {
  const card = document.getElementById('imageForensicsCard');
  const body = document.getElementById('imageForensicsContent');
  if (!data) { if (card) card.style.display = 'none'; return; }
  card.style.display = 'block';

  const exif = data.exif || {};
  const ela  = data.ela  || {};
  const cm   = data.copy_move || {};
  const prnu = data.prnu || {};
  const dc   = data.double_compression || {};
  const thumb= data.thumbnail_check || {};
  const ai   = data.ai_detection || {};

  // Helper — badge für score
  const scoreBadge = (s) => {
    const cls = s >= 70 ? 'text-high' : s >= 40 ? 'text-medium' : 'text-low';
    return `<span class="${cls}" style="font-weight:700">${s}/100</span>`;
  };

  let html = `<p class="section-expl">${t('img_forensics_expl')}</p>`;

  // --- EXIF ---
  html += `<h4 style="margin:12px 0 6px">EXIF</h4>`;
  const exifFields = [
    ['Make',          exif.make || exif.Make],
    ['Model',         exif.model || exif.Model],
    ['Software',      exif.software || exif.Software],
    ['DateTimeOriginal', exif.datetime_original || exif.DateTimeOriginal],
    ['GPS',           exif.gps_decimal ? `${exif.gps_decimal[0].toFixed(5)}, ${exif.gps_decimal[1].toFixed(5)}` : null],
    ['Flash',         exif.flash !== undefined ? String(exif.flash) : null],
    ['FocalLength',   exif.focal_length],
    ['ISO',           exif.iso !== undefined ? String(exif.iso) : null],
    ['Thumbnail',     exif.thumbnail_base64 ? `<img src="${exif.thumbnail_base64}" style="max-height:60px;border-radius:4px;margin-top:4px">` : null],
  ];
  const exifRows = exifFields.filter(([,v]) => v != null);
  if (exifRows.length) {
    html += `<table class="meta-table"><tbody>` +
      exifRows.map(([k,v]) => `<tr><td class="meta-key">${k}</td><td>${v}</td></tr>`).join('') +
      `</tbody></table>`;
  } else {
    html += `<p class="muted">${t('img_no_exif')}</p>`;
  }

  // --- ELA ---
  if (ela.available !== false) {
    html += `<h4 style="margin:12px 0 6px">${t('img_ela_title')}</h4>`;
    if (ela.ela_preview) {
      html += `<div style="display:flex;gap:16px;align-items:flex-start;flex-wrap:wrap">
        <img src="${ela.ela_preview}" alt="ELA" style="max-width:320px;border-radius:6px;border:1px solid var(--border)">
        <div>`;
    }
    html += `<table class="meta-table"><tbody>
      <tr><td class="meta-key">${t('img_ela_mean')}</td><td>${ela.mean_ela != null ? ela.mean_ela.toFixed(2) : '—'}</td></tr>
      <tr><td class="meta-key">${t('img_ela_max')}</td><td>${ela.max_ela != null ? ela.max_ela.toFixed(2) : '—'}</td></tr>
      <tr><td class="meta-key">${t('img_ela_hot_regions')}</td><td>${ela.hot_regions ? ela.hot_regions.length : 0}</td></tr>
    </tbody></table>`;
    if (ela.ela_preview) html += `</div></div>`;
  }

  // --- Copy-Move ---
  if (cm.available !== false) {
    html += `<h4 style="margin:12px 0 6px">${t('img_copymove_title')}</h4>`;
    html += `<table class="meta-table"><tbody>
      <tr><td class="meta-key">${t('img_copymove_blocks')}</td><td>${cm.blocks_checked ?? '—'}</td></tr>
      <tr><td class="meta-key">${t('img_copymove_matches')}</td><td>${cm.duplicate_pairs ?? 0}</td></tr>
      <tr><td class="meta-key">${t('img_copymove_suspected')}</td><td class="${cm.suspected ? 'text-high' : ''}">${cm.suspected ? t('yes') : t('no')}</td></tr>
    </tbody></table>`;
  }

  // --- PRNU ---
  if (prnu.available !== false) {
    html += `<h4 style="margin:12px 0 6px">${t('img_prnu_title')}</h4>`;
    html += `<table class="meta-table"><tbody>
      <tr><td class="meta-key">${t('img_prnu_noise_std')}</td><td>${prnu.noise_std != null ? prnu.noise_std.toFixed(4) : '—'}</td></tr>
      <tr><td class="meta-key">${t('img_prnu_inconsistent')}</td><td class="${prnu.inconsistent ? 'text-high' : ''}">${prnu.inconsistent ? t('yes') : t('no')}</td></tr>
    </tbody></table>`;
  }

  // --- Double Compression ---
  if (dc.available !== false) {
    html += `<h4 style="margin:12px 0 6px">${t('img_dc_title')}</h4>`;
    html += `<table class="meta-table"><tbody>
      <tr><td class="meta-key">${t('img_dc_suspected')}</td><td class="${dc.suspected ? 'text-high' : ''}">${dc.suspected ? t('yes') : t('no')}</td></tr>
      ${dc.estimated_quality ? `<tr><td class="meta-key">${t('img_dc_est_quality')}</td><td>${dc.estimated_quality}</td></tr>` : ''}
    </tbody></table>`;
  }

  // --- Thumbnail ---
  if (thumb.checked) {
    html += `<h4 style="margin:12px 0 6px">${t('img_thumb_title')}</h4>`;
    html += `<table class="meta-table"><tbody>
      <tr><td class="meta-key">${t('img_thumb_mismatch')}</td><td class="${thumb.mismatch ? 'text-high' : ''}">${thumb.mismatch ? t('yes') : t('no')}</td></tr>
      ${thumb.note ? `<tr><td class="meta-key">${t('lbl_note')}</td><td>${thumb.note}</td></tr>` : ''}
    </tbody></table>`;
  }

  // --- AI Detection ---
  html += `<h4 style="margin:12px 0 6px">${t('img_ai_title')}</h4>`;
  html += `<table class="meta-table"><tbody>
    <tr><td class="meta-key">${t('img_ai_score')}</td><td>${scoreBadge(ai.score ?? 0)}</td></tr>
    <tr><td class="meta-key">${t('img_ai_verdict')}</td><td class="${(ai.score ?? 0) >= 60 ? 'text-high' : ''}">${ai.verdict || '—'}</td></tr>
  </tbody></table>`;
  if (ai.signals && ai.signals.length) {
    html += `<ul style="margin:6px 0 0 16px;font-size:0.8rem;color:var(--muted)">` +
      ai.signals.map(s => `<li>${s}</li>`).join('') + `</ul>`;
  }

  body.innerHTML = html;
}


// ============================================================
// Phase 3 — Steganography
// ============================================================

function renderSteganography(data) {
  const card = document.getElementById('steganographyCard');
  const body = document.getElementById('steganographyContent');
  if (!data) { if (card) card.style.display = 'none'; return; }
  card.style.display = 'block';

  const chi  = data.lsb_chi    || {};
  const rs   = data.rs_analysis || {};
  const png  = data.png_chunks  || {};
  const jpeg = data.jpeg_trailing || {};

  let html = `<p class="section-expl">${t('steg_expl')}</p>`;

  // --- LSB Chi-Square ---
  if (chi.available !== false) {
    html += `<h4 style="margin:12px 0 6px">${t('steg_chi_title')}</h4>`;
    html += `<table class="meta-table"><tbody>
      <tr><td class="meta-key">χ²-norm</td><td>${chi.chi_norm != null ? chi.chi_norm : '—'}</td></tr>
      <tr><td class="meta-key">${t('steg_capacity_kb')}</td><td>${chi.capacity_kb != null ? chi.capacity_kb + ' KB' : '—'}</td></tr>
      <tr><td class="meta-key">${t('steg_suspected')}</td><td class="${chi.suspected ? 'text-high' : ''}">${chi.suspected ? t('yes') : t('no')}</td></tr>
      ${chi.note ? `<tr><td class="meta-key">${t('lbl_note')}</td><td>${chi.note}</td></tr>` : ''}
    </tbody></table>`;
  }

  // --- RS-Analyse ---
  if (rs.available !== false) {
    html += `<h4 style="margin:12px 0 6px">${t('steg_rs_title')}</h4>`;
    html += `<table class="meta-table"><tbody>
      <tr><td class="meta-key">${t('steg_rs_fill')}</td><td>${rs.estimated_fill != null ? rs.estimated_fill + '%' : '—'}</td></tr>
      <tr><td class="meta-key">${t('steg_suspected')}</td><td class="${rs.suspected ? 'text-high' : ''}">${rs.suspected ? t('yes') : t('no')}</td></tr>
      ${rs.note ? `<tr><td class="meta-key">${t('lbl_note')}</td><td>${rs.note}</td></tr>` : ''}
    </tbody></table>`;
  }

  // --- PNG-Chunks ---
  if (png.applicable !== false) {
    html += `<h4 style="margin:12px 0 6px">${t('steg_png_title')}</h4>`;
    html += `<table class="meta-table"><tbody>
      <tr><td class="meta-key">${t('steg_png_chunks')}</td><td>${(png.chunks || []).length}</td></tr>
      <tr><td class="meta-key">${t('steg_png_unknown')}</td><td class="${(png.unknown_chunks || []).length > 0 ? 'text-medium' : ''}">${(png.unknown_chunks || []).length}</td></tr>
      <tr><td class="meta-key">${t('steg_png_trailing')}</td><td class="${png.trailing_data ? 'text-high' : ''}">${png.trailing_data ? `${png.trailing_bytes} Bytes` : t('no')}</td></tr>
    </tbody></table>`;
    if (png.text_data && png.text_data.length) {
      html += `<div style="margin-top:8px"><strong>${t('steg_png_textchunks')}</strong>`;
      html += `<table class="meta-table" style="margin-top:4px"><tbody>` +
        png.text_data.slice(0, 10).map(td =>
          `<tr><td class="meta-key">${td.type}: ${_esc(td.key)}</td><td style="font-size:0.75rem;word-break:break-all">${_esc(td.value.slice(0,200))}</td></tr>`
        ).join('') +
        `</tbody></table></div>`;
    }
  }

  // --- JPEG Trailing ---
  if (jpeg.applicable !== false) {
    html += `<h4 style="margin:12px 0 6px">${t('steg_jpeg_title')}</h4>`;
    html += `<table class="meta-table"><tbody>
      <tr><td class="meta-key">${t('steg_jpeg_trailing')}</td><td class="${jpeg.trailing_data ? 'text-high' : ''}">${jpeg.trailing_data ? `${jpeg.trailing_bytes} Bytes` : t('no')}</td></tr>
      ${jpeg.trailing_hex ? `<tr><td class="meta-key">HEX-Vorschau</td><td style="font-family:monospace;font-size:0.75rem">${_esc(jpeg.trailing_hex)}</td></tr>` : ''}
      ${jpeg.note ? `<tr><td class="meta-key">${t('lbl_note')}</td><td>${_esc(jpeg.note)}</td></tr>` : ''}
    </tbody></table>`;
  }

  body.innerHTML = html;
}

// ============================================================
// Phase 4 — IOC Extraction
// ============================================================

function renderIOC(ioc) {
  const card = document.getElementById('iocCard');
  const el   = document.getElementById('iocContent');
  if (!el) return;
  if (!ioc) { if (card) card.style.display = 'none'; return; }
  if (card) card.style.display = '';

  let html = '<div class="section-explanation">' + t('ioc_expl') + '</div>';

  html += kvTable([
    [t('lbl_ioc_total'),    ioc.total_count || 0],
    [t('lbl_ioc_urls'),     (ioc.urls || []).length],
    [t('lbl_ioc_ips'),      (ioc.ips || []).length],
    [t('lbl_ioc_emails'),   (ioc.emails || []).length],
    [t('lbl_ioc_domains'),  (ioc.domains || []).length],
    [t('lbl_ioc_suspicious'), (ioc.suspicious_iocs || []).length],
  ]);

  if (ioc.urls && ioc.urls.length) {
    html += '<div class="section-sub-header"><span>' + t('sub_ioc_urls') + '</span></div>';
    html += '<div style="overflow-x:auto"><table class="kv-table">';
    html += '<tr>';
    html += '<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">' + t('col_ioc_url') + '</th>';
    html += '<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">' + t('col_ioc_suspicious') + '</th>';
    html += '<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">' + t('col_ioc_source') + '</th>';
    html += '</tr>';
    ioc.urls.slice(0, 30).forEach(function(u) {
      var susp = u.suspicious;
      html += '<tr class="' + (susp ? 'highlight-high' : '') + '">';
      html += '<td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.74rem;font-family:monospace;color:' + (susp ? 'var(--high)' : 'var(--text)') + ';word-break:break-all">' + escapeHtml(u.url) + '</td>';
      html += '<td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:' + (susp ? 'var(--high)' : 'var(--clean)') + ';font-weight:600">' + (susp ? '&#9888; ' + t('yes').toUpperCase() : '&#10003; ' + t('no')) + '</td>';
      html += '<td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--muted)">' + escapeHtml(u.source || '?') + '</td>';
      html += '</tr>';
    });
    html += '</table></div>';
  }

  if (ioc.ips && ioc.ips.length) {
    html += '<div class="section-sub-header"><span>' + t('sub_ioc_ips') + '</span></div>';
    html += '<div style="overflow-x:auto"><table class="kv-table">';
    html += '<tr>';
    html += '<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">' + t('col_ioc_ip') + '</th>';
    html += '<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">' + t('col_ioc_type') + '</th>';
    html += '</tr>';
    ioc.ips.slice(0, 20).forEach(function(ip) {
      var isExt = ip.type === 'external';
      html += '<tr class="' + (isExt ? 'highlight-medium' : '') + '">';
      html += '<td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;font-family:monospace;color:var(--text)">' + escapeHtml(ip.ip) + '</td>';
      html += '<td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:' + (isExt ? 'var(--medium)' : 'var(--muted)') + '">' + (isExt ? t('ioc_external_ip') : t('ioc_internal_ip')) + '</td>';
      html += '</tr>';
    });
    html += '</table></div>';
  }

  if (ioc.emails && ioc.emails.length) {
    html += '<div class="section-sub-header"><span>' + t('sub_ioc_emails') + '</span></div>';
    html += '<div style="padding:8px 12px;font-size:0.8rem;color:var(--text);font-family:monospace;line-height:1.8">';
    html += ioc.emails.slice(0, 20).map(function(e) { return escapeHtml(e); }).join(' &nbsp;&middot;&nbsp; ');
    html += '</div>';
  }

  if (ioc.domains && ioc.domains.length) {
    html += '<div class="section-sub-header"><span>' + t('sub_ioc_domains') + '</span></div>';
    html += '<div style="padding:8px 12px;font-size:0.8rem;color:var(--text);font-family:monospace;line-height:1.8">';
    html += ioc.domains.slice(0, 30).map(function(d) { return escapeHtml(d); }).join(' &nbsp;&middot;&nbsp; ');
    html += '</div>';
  }

  if (!ioc.total_count) {
    html += '<div style="color:var(--muted);padding:8px 0;font-size:0.85rem">' + t('ioc_no_iocs') + '</div>';
  }

  if (ioc.anomalies && ioc.anomalies.length) html += anomalyMiniList(ioc.anomalies);
  if (typeof interpIOC === 'function') html += interpIOC(ioc);
  el.innerHTML = html;
}

// ============================================================
// Phase 4 — Hidden Text Analysis
// ============================================================

function renderHiddenText(ht) {
  const card = document.getElementById('hiddenTextCard');
  const el   = document.getElementById('hiddenTextContent');
  if (!el) return;
  if (!ht) { if (card) card.style.display = 'none'; return; }
  if (card) card.style.display = '';

  const hasFindings = ht.invisible_text_count > 0 || ht.white_text_count > 0 || ht.tiny_text_count > 0;

  let html = '<div class="section-explanation">' + t('ht_expl') + '</div>';

  html += kvTable([
    [t('lbl_ht_invisible'), ht.invisible_text_count || 0],
    [t('lbl_ht_white'),     ht.white_text_count || 0],
    [t('lbl_ht_tiny'),      ht.tiny_text_count || 0],
    [t('lbl_ht_ocg'),       (ht.ocg_layers || []).length],
  ]);

  if (ht.hidden_blocks && ht.hidden_blocks.length) {
    html += '<div class="section-sub-header"><span>' + t('sub_ht_blocks') + '</span></div>';
    html += '<div style="overflow-x:auto"><table class="kv-table">';
    html += '<tr>';
    html += '<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">' + t('col_ht_page') + '</th>';
    html += '<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">' + t('col_ht_reason') + '</th>';
    html += '<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">' + t('col_ht_text') + '</th>';
    html += '<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">' + t('col_ht_fontsize') + '</th>';
    html += '<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">' + t('col_ht_render_mode') + '</th>';
    html += '<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">' + t('col_ht_color') + '</th>';
    html += '<th style="color:var(--muted);padding:8px 12px;font-size:0.78rem;background:var(--surface2)">X / Y</th>';
    html += '</tr>';
    ht.hidden_blocks.slice(0, 30).forEach(function(b) {
      var isHigh = b.reason === 'invisible_text';
      var isMed  = b.reason === 'white_text';
      var colorStr = b.color ? (typeof b.color === 'string' ? b.color : '(' + (b.color[0] != null ? b.color[0].toFixed(2) : '?') + ',' + (b.color[1] != null ? b.color[1].toFixed(2) : '?') + ',' + (b.color[2] != null ? b.color[2].toFixed(2) : '?') + ')') : '—';
      var coordStr = (b.x != null || b.y != null) ? (typeof b.x === 'number' ? b.x.toFixed(0) : '?') + ' / ' + (typeof b.y === 'number' ? b.y.toFixed(0) : '?') : '—';
      html += '<tr class="' + (isHigh ? 'highlight-high' : isMed ? 'highlight-medium' : '') + '">';
      html += '<td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">' + (b.page || '?') + '</td>';
      html += '<td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:' + (isHigh ? 'var(--high)' : isMed ? 'var(--medium)' : 'var(--text)') + ';font-weight:' + (isHigh || isMed ? '600' : '400') + '">' + escapeHtml(b.reason || '?') + '</td>';
      html += '<td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.75rem;font-family:monospace;color:var(--text);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + escapeHtml(b.text || '') + '</td>';
      html += '<td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--muted)">' + (typeof b.font_size === 'number' ? b.font_size.toFixed(1) + 'pt' : '?') + '</td>';
      html += '<td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--muted)">' + (b.render_mode != null ? 'Tr' + b.render_mode : '—') + '</td>';
      html += '<td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.72rem;font-family:monospace;color:var(--muted)">' + escapeHtml(colorStr) + '</td>';
      html += '<td style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.72rem;font-family:monospace;color:var(--muted)">' + escapeHtml(coordStr) + '</td>';
      html += '</tr>';
    });
    html += '</table></div>';
  }

  if (ht.ocg_layers && ht.ocg_layers.length) {
    html += '<div class="section-sub-header"><span>' + t('sub_ht_ocg') + '</span></div>';
    html += '<div style="display:flex;gap:8px;flex-wrap:wrap;padding:8px 0">';
    ht.ocg_layers.forEach(function(l) {
      html += '<span class="explain-badge">' + escapeHtml(l.name || '?') + '</span>';
    });
    html += '</div>';
  }

  if (!hasFindings && !(ht.ocg_layers && ht.ocg_layers.length)) {
    html += '<div style="color:var(--muted);padding:8px 0;font-size:0.85rem">' + t('ht_no_hidden') + '</div>';
  }

  if (ht.anomalies && ht.anomalies.length) html += anomalyMiniList(ht.anomalies);
  if (typeof interpHiddenText === 'function') html += interpHiddenText(ht);
  el.innerHTML = html;
}

// ============================================================
// Phase 4 — Yellow Dots / MIC Detector
// ============================================================

function renderYellowDots(yd) {
  const card = document.getElementById('yellowDotsCard');
  const el   = document.getElementById('yellowDotsContent');
  if (!el) return;
  if (!yd) { if (card) card.style.display = 'none'; return; }
  if (card) card.style.display = '';

  let html = '<div class="section-explanation">' + t('yd_expl') + '</div>';

  html += kvTable([
    [t('lbl_yd_available'), yd.available ? t('yes') : t('no')],
    [t('lbl_yd_method'),    yd.method_used || 'none'],
    [t('lbl_yd_found'),     yd.dots_found ? '<span class="text-high">' + t('yes').toUpperCase() + '</span>' : '<span class="text-clean">' + t('no') + '</span>'],
    [t('lbl_yd_count'),     yd.dot_count || 0],
    [t('lbl_yd_pattern'),   yd.pattern_type === 'xerox_mic' ? t('yd_pattern_xerox') : yd.pattern_type === 'generic' ? t('yd_pattern_generic') : '&#8212;'],
    [t('lbl_yd_page'),      yd.page || '&#8212;'],
  ]);

  if (yd.decoded_info && Object.keys(yd.decoded_info).length) {
    html += '<div class="section-sub-header"><span>' + t('lbl_yd_decoded') + '</span></div>';
    var infoRows = Object.entries(yd.decoded_info).slice(0, 10).map(function(kv) { return [kv[0], String(kv[1])]; });
    html += kvTable(infoRows);
  }

  if (!yd.dots_found) {
    html += '<div style="color:var(--muted);padding:8px 0;font-size:0.85rem">' + t('yd_no_dots') + '</div>';
  }

  if (yd.anomalies && yd.anomalies.length) html += anomalyMiniList(yd.anomalies);
  if (typeof interpYellowDots === 'function') html += interpYellowDots(yd);
  el.innerHTML = html;
}

// ============================================================
// Phase 5 — Advanced Forensics
// ============================================================

function renderStreamDecomp(data) {
  var card = document.getElementById('streamDecompCard');
  var el = document.getElementById('streamDecompContent');
  if (!el) return;
  if (!data) { if (card) card.style.display = 'none'; return; }
  if (card) card.style.display = '';

  var html = '<div class="section-explanation">' + t('sd_expl') + '</div>';
  html += kvTable([
    [t('lbl_sd_total_streams'), data.total_streams || 0],
    [t('lbl_sd_decompressed'), data.decompressed_count || 0],
    [t('lbl_sd_suspicious'), data.suspicious_count || 0, null, data.suspicious_count > 0 ? 'high' : null],
    [t('lbl_sd_filters'), (data.filter_types || []).join(', ') || '—'],
  ]);

  if (data.suspicious_contents && data.suspicious_contents.length) {
    html += '<div class="section-sub-header"><span>' + t('sub_sd_suspicious') + '</span></div>';
    html += '<table class="kv-table" style="width:100%"><tr>';
    [t('col_sd_obj'), t('col_sd_filter'), t('col_sd_size'), t('col_sd_pattern')].forEach(function(h) {
      html += '<th style="padding:6px 10px;color:var(--muted);background:var(--surface2);font-size:0.72rem">' + h + '</th>';
    });
    html += '</tr>';
    data.suspicious_contents.slice(0, 20).forEach(function(s) {
      html += '<tr>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.78rem;font-family:monospace">' + escapeHtml(String(s.obj_id || s.object || '')) + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.78rem">' + escapeHtml(String(s.filter || '')) + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.78rem">' + (s.size || '—') + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--high)">' + escapeHtml(String(s.pattern || s.match || '')) + '</td>';
      html += '</tr>';
    });
    html += '</table>';
  }

  if (data.anomalies && data.anomalies.length) html += anomalyMiniList(data.anomalies);
  el.innerHTML = html;
}

function renderXRefValidation(data) {
  var card = document.getElementById('xrefValidationCard');
  var el = document.getElementById('xrefValidationContent');
  if (!el) return;
  if (!data) { if (card) card.style.display = 'none'; return; }
  if (card) card.style.display = '';

  var html = '<div class="section-explanation">' + t('xref_expl') + '</div>';
  html += kvTable([
    [t('lbl_xref_entries'), data.total_entries || 0],
    [t('lbl_xref_valid'), data.valid_entries || 0],
    [t('lbl_xref_invalid'), data.invalid_entries || 0, null, (data.invalid_entries || 0) > 0 ? 'high' : null],
    [t('lbl_xref_free'), data.free_count || 0],
    [t('lbl_xref_hybrid'), data.is_hybrid ? t('yes') : t('no')],
    [t('lbl_xref_subsections'), data.subsection_count || 0],
  ]);

  if (data.issues && data.issues.length) {
    html += '<div class="section-sub-header"><span>' + t('sub_xref_issues') + '</span></div>';
    data.issues.slice(0, 15).forEach(function(issue) {
      html += '<div style="padding:4px 0;font-size:0.8rem;color:var(--high)">' + escapeHtml(String(issue.message || issue)) + '</div>';
    });
  }

  if (data.anomalies && data.anomalies.length) html += anomalyMiniList(data.anomalies);
  el.innerHTML = html;
}

function renderDeepJpeg(data) {
  var card = document.getElementById('deepJpegCard');
  var el = document.getElementById('deepJpegContent');
  if (!el) return;
  if (!data) { if (card) card.style.display = 'none'; return; }
  if (card) card.style.display = '';

  var html = '<div class="section-explanation">' + t('dj_expl') + '</div>';
  html += kvTable([
    [t('lbl_dj_images'), data.images_analyzed || 0],
    [t('lbl_dj_dct'), data.dct_double_compression ? '<span class="text-high">' + t('yes') + '</span>' : '<span class="text-clean">' + t('no') + '</span>'],
    [t('lbl_dj_huffman'), data.huffman_anomalies || 0],
    [t('lbl_dj_thumbnail'), data.thumbnail_mismatch ? '<span class="text-high">' + t('yes') + '</span>' : '<span class="text-clean">' + t('no') + '</span>'],
    [t('lbl_dj_ghost'), data.jpeg_ghost_detected ? '<span class="text-high">' + t('yes') + '</span>' : '<span class="text-clean">' + t('no') + '</span>'],
    [t('lbl_dj_prnu'), data.prnu_inconsistency ? '<span class="text-high">' + t('yes') + '</span>' : '<span class="text-clean">' + t('no') + '</span>'],
  ]);

  if (data.details && data.details.length) {
    html += '<div class="section-sub-header"><span>' + t('sub_dj_results') + '</span></div>';
    data.details.slice(0, 10).forEach(function(d) {
      html += '<div style="padding:4px 0;font-size:0.8rem;border-bottom:1px solid var(--border)">';
      html += '<span style="font-weight:600">' + escapeHtml(String(d.test || d.type || '')) + ':</span> ';
      html += escapeHtml(String(d.result || d.detail || ''));
      html += '</div>';
    });
  }

  if (data.anomalies && data.anomalies.length) html += anomalyMiniList(data.anomalies);
  el.innerHTML = html;
}

function renderRedaction(data) {
  var card = document.getElementById('redactionCard');
  var el = document.getElementById('redactionContent');
  if (!el) return;
  if (!data) { if (card) card.style.display = 'none'; return; }
  if (card) card.style.display = '';

  var html = '<div class="section-explanation">' + t('red_expl') + '</div>';
  html += kvTable([
    [t('lbl_red_found'), data.redactions_found || 0],
    [t('lbl_red_secure'), data.secure_redactions || 0],
    [t('lbl_red_insecure'), data.insecure_redactions || 0, null, (data.insecure_redactions || 0) > 0 ? 'high' : null],
  ]);

  if (data.redaction_details && data.redaction_details.length) {
    html += '<div class="section-sub-header"><span>' + t('sub_red_details') + '</span></div>';
    html += '<table class="kv-table" style="width:100%"><tr>';
    [t('col_red_page'), t('col_red_type'), t('col_red_secure'), t('col_red_note')].forEach(function(h) {
      html += '<th style="padding:6px 10px;color:var(--muted);background:var(--surface2);font-size:0.72rem">' + h + '</th>';
    });
    html += '</tr>';
    data.redaction_details.slice(0, 20).forEach(function(r) {
      html += '<tr>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.78rem">' + (r.page || '—') + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.78rem">' + escapeHtml(String(r.type || '')) + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.78rem">' + (r.secure ? '<span class="text-clean"></span>' : '<span class="text-high"></span>') + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.78rem">' + escapeHtml(String(r.note || '')) + '</td>';
      html += '</tr>';
    });
    html += '</table>';
  }

  if (data.anomalies && data.anomalies.length) html += anomalyMiniList(data.anomalies);
  el.innerHTML = html;
}

function renderOCGLayers(data) {
  var card = document.getElementById('ocgLayersCard');
  var el = document.getElementById('ocgLayersContent');
  if (!el) return;
  if (!data) { if (card) card.style.display = 'none'; return; }
  if (card) card.style.display = '';

  var html = '<div class="section-explanation">' + t('ocg_expl') + '</div>';
  html += kvTable([
    [t('lbl_ocg_count'), data.layer_count || 0],
    [t('lbl_ocg_hidden'), data.hidden_count || 0, null, (data.hidden_count || 0) > 0 ? 'medium' : null],
    [t('lbl_ocg_locked'), data.locked_count || 0],
  ]);

  if (data.layers && data.layers.length) {
    html += '<div class="section-sub-header"><span>' + t('sub_ocg_list') + '</span></div>';
    html += '<table class="kv-table" style="width:100%"><tr>';
    [t('col_ocg_name'), t('col_ocg_visible'), t('col_ocg_locked'), t('col_ocg_pages')].forEach(function(h) {
      html += '<th style="padding:6px 10px;color:var(--muted);background:var(--surface2);font-size:0.72rem">' + h + '</th>';
    });
    html += '</tr>';
    data.layers.slice(0, 20).forEach(function(l) {
      html += '<tr>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.78rem;font-weight:600">' + escapeHtml(String(l.name || '')) + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.78rem">' + (l.visible !== false ? '<span class="text-clean"></span>' : '<span class="text-high"></span>') + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.78rem">' + (l.locked ? '<span class="text-medium"></span>' : '—') + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.78rem">' + (Array.isArray(l.pages) ? l.pages.join(', ') : (l.pages || '—')) + '</td>';
      html += '</tr>';
    });
    html += '</table>';
  }

  if (data.anomalies && data.anomalies.length) html += anomalyMiniList(data.anomalies);
  el.innerHTML = html;
}

function renderContentStream(data) {
  var card = document.getElementById('contentStreamCard');
  var el = document.getElementById('contentStreamContent');
  if (!el) return;
  if (!data) { if (card) card.style.display = 'none'; return; }
  if (card) card.style.display = '';

  var html = '<div class="section-explanation">' + t('cs_expl') + '</div>';
  html += kvTable([
    [t('lbl_cs_pages'), data.pages_checked || 0],
    [t('lbl_cs_operators'), data.total_operators || 0],
    [t('lbl_cs_unknown'), data.unknown_operators || 0, null, (data.unknown_operators || 0) > 0 ? 'medium' : null],
    [t('lbl_cs_suspicious'), data.suspicious_patterns || 0, null, (data.suspicious_patterns || 0) > 0 ? 'high' : null],
    [t('lbl_cs_balance'), data.q_balanced ? '<span class="text-clean">Balanced</span>' : '<span class="text-high">Unbalanced</span>'],
  ]);

  if (data.issues && data.issues.length) {
    html += '<div class="section-sub-header"><span>' + t('sub_cs_issues') + '</span></div>';
    data.issues.slice(0, 15).forEach(function(issue) {
      html += '<div style="padding:4px 0;font-size:0.8rem;color:var(--medium)">' + escapeHtml(String(issue.message || issue)) + '</div>';
    });
  }

  if (data.anomalies && data.anomalies.length) html += anomalyMiniList(data.anomalies);
  el.innerHTML = html;
}

function renderIncDiff(data) {
  var card = document.getElementById('incDiffCard');
  var el = document.getElementById('incDiffContent');
  if (!el) return;
  if (!data) { if (card) card.style.display = 'none'; return; }
  if (card) card.style.display = '';

  var html = '<div class="section-explanation">' + t('id_expl') + '</div>';
  html += kvTable([
    [t('lbl_id_revisions'), data.revision_count || 0],
    [t('lbl_id_added'), data.total_added || 0],
    [t('lbl_id_modified'), data.total_modified || 0],
    [t('lbl_id_removed'), data.total_removed || 0],
  ]);

  if (data.diffs && data.diffs.length) {
    html += '<div class="section-sub-header"><span>' + t('sub_id_changes') + '</span></div>';
    html += '<table class="kv-table" style="width:100%"><tr>';
    [t('col_id_rev'), t('col_id_added'), t('col_id_modified'), t('col_id_removed'), t('col_id_types')].forEach(function(h) {
      html += '<th style="padding:6px 10px;color:var(--muted);background:var(--surface2);font-size:0.72rem">' + h + '</th>';
    });
    html += '</tr>';
    data.diffs.forEach(function(d) {
      html += '<tr>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.78rem;font-weight:600">' + (d.revision || d.rev || '') + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--clean)">' + (d.added || 0) + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--medium)">' + (d.modified || 0) + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--high)">' + (d.removed || 0) + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.75rem;font-family:monospace;color:var(--muted)">' + escapeHtml(String((d.changed_types || []).join(', '))) + '</td>';
      html += '</tr>';
    });
    html += '</table>';
  }

  if (data.anomalies && data.anomalies.length) html += anomalyMiniList(data.anomalies);
  el.innerHTML = html;
}

function renderFuzzyHash(data) {
  var card = document.getElementById('fuzzyHashCard');
  var el = document.getElementById('fuzzyHashContent');
  if (!el) return;
  if (!data) { if (card) card.style.display = 'none'; return; }
  if (card) card.style.display = '';

  var html = '<div class="section-explanation">' + t('fh_expl') + '</div>';
  html += kvTable([
    [t('lbl_fh_available'), data.available ? t('yes') : t('no')],
    [t('lbl_fh_ssdeep'), data.ssdeep_hash ? '<span style="font-family:monospace;font-size:0.78rem;word-break:break-all">' + escapeHtml(data.ssdeep_hash) + '</span>' : '—'],
    [t('lbl_fh_tlsh'), data.tlsh_hash ? '<span style="font-family:monospace;font-size:0.78rem;word-break:break-all">' + escapeHtml(data.tlsh_hash) + '</span>' : '—'],
  ]);

  if (data.anomalies && data.anomalies.length) html += anomalyMiniList(data.anomalies);
  el.innerHTML = html;
}

function renderCrossAnalyzer(data) {
  var card = document.getElementById('crossAnalyzerCard');
  var el = document.getElementById('crossAnalyzerContent');
  if (!el) return;
  if (!data) { if (card) card.style.display = 'none'; return; }
  if (card) card.style.display = '';

  var html = '<div class="section-explanation">' + t('ca_expl') + '</div>';

  // Manipulation Score gauge
  var score = data.manipulation_score || 0;
  var scoreColor = score > 60 ? 'var(--high)' : score > 30 ? 'var(--medium)' : 'var(--clean)';
  html += '<div style="text-align:center;padding:16px 0">';
  html += '<div style="font-size:2.4rem;font-weight:800;color:' + scoreColor + '">' + score + '<span style="font-size:1rem;color:var(--muted)">/100</span></div>';
  html += '<div style="font-size:0.85rem;color:var(--muted);margin-top:4px">' + t('lbl_ca_score') + '</div>';
  html += '<div style="margin:10px auto;width:200px;height:8px;background:var(--surface2);border-radius:4px;overflow:hidden">';
  html += '<div style="width:' + score + '%;height:100%;background:' + scoreColor + ';border-radius:4px;transition:width 0.6s ease"></div>';
  html += '</div></div>';

  // Creator Profile
  if (data.creator_profile) {
    html += '<div class="section-sub-header"><span>' + t('sub_ca_profile') + '</span></div>';
    var cp = data.creator_profile;
    var profileRows = [];
    if (cp.software && cp.software.identified_tool) profileRows.push([t('lbl_identified_tool'), cp.software.identified_tool]);
    if (cp.software && cp.software.version) profileRows.push([t('lbl_version'), cp.software.version]);
    if (cp.author_info && cp.author_info.name) profileRows.push([t('lbl_author'), cp.author_info.name]);
    if (cp.system_hints && cp.system_hints.region) profileRows.push([t('lbl_tz_region'), cp.system_hints.region]);
    if (cp.confidence) profileRows.push([t('lbl_ca_confidence'), cp.confidence]);
    if (profileRows.length) html += kvTable(profileRows);
  }

  // Timeline
  if (data.timeline_reconstruction && data.timeline_reconstruction.length) {
    html += '<div class="section-sub-header"><span>' + t('sub_ca_timeline') + '</span></div>';
    html += '<table class="kv-table" style="width:100%"><tr>';
    [t('col_ca_time'), t('col_ca_source'), t('col_ca_event')].forEach(function(h) {
      html += '<th style="padding:6px 10px;color:var(--muted);background:var(--surface2);font-size:0.72rem">' + h + '</th>';
    });
    html += '</tr>';
    data.timeline_reconstruction.slice(0, 20).forEach(function(e) {
      html += '<tr>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.75rem;font-family:monospace">' + escapeHtml(String(e.timestamp || '')) + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.78rem">' + escapeHtml(String(e.source || '')) + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.78rem">' + escapeHtml(String(e.detail || e.type || '')) + '</td>';
      html += '</tr>';
    });
    html += '</table>';
  }

  // Correlations
  if (data.correlations && data.correlations.length) {
    html += '<div class="section-sub-header"><span>' + t('sub_ca_correlations') + '</span></div>';
    data.correlations.forEach(function(c) {
      var sev = c.severity || 'MEDIUM';
      html += '<div style="padding:10px;margin:6px 0;border-radius:8px;border-left:4px solid var(--' + sev.toLowerCase() + ');background:var(--surface2)">';
      html += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">';
      html += severityBadgeHtml(sev);
      html += '<span style="font-weight:700;font-size:0.88rem">' + escapeHtml(String(c.title || '')) + '</span>';
      html += '</div>';
      if (c.analyzers_involved) {
        html += '<div style="font-size:0.75rem;color:var(--muted);margin-bottom:4px">' + t('col_ca_analyzers') + ': ' + c.analyzers_involved.join(', ') + '</div>';
      }
      if (c.evidence && c.evidence.length) {
        c.evidence.forEach(function(ev) {
          html += '<div style="font-size:0.78rem;color:var(--text);padding-left:12px">• ' + escapeHtml(String(ev)) + '</div>';
        });
      }
      if (c.conclusion) {
        html += '<div style="font-size:0.8rem;font-weight:600;color:var(--text);margin-top:6px;font-style:italic">' + escapeHtml(c.conclusion) + '</div>';
      }
      html += '</div>';
    });
  }

  if (data.anomalies && data.anomalies.length) html += anomalyMiniList(data.anomalies);
  if (typeof interpCrossAnalyzer === 'function') html += interpCrossAnalyzer(data);
  el.innerHTML = html;
}

function renderChainOfCustody(data) {
  var card = document.getElementById('chainOfCustodyCard');
  var el = document.getElementById('chainOfCustodyContent');
  if (!el) return;
  if (!data) { if (card) card.style.display = 'none'; return; }
  if (card) card.style.display = '';

  var html = '<div class="section-explanation">' + t('coc_expl') + '</div>';

  var integrityOk = data.evidence_integrity === true || data.hash_verified === true;
  html += kvTable([
    [t('lbl_coc_examiner'), data.examiner_name || '—'],
    [t('lbl_coc_case'), data.case_number || '—'],
    [t('lbl_coc_integrity'), integrityOk ? t('coc_integrity_ok') : t('coc_integrity_fail')],
    [t('lbl_coc_hash_match'), data.hash_verified ? '<span class="text-clean"></span>' : '<span class="text-high"></span>'],
    [t('lbl_coc_analyzers_run'), data.analyzers_executed || 0],
  ]);

  if (data.audit_log && data.audit_log.length) {
    html += '<div class="section-sub-header"><span>' + t('sub_coc_audit') + '</span></div>';
    html += '<table class="kv-table" style="width:100%"><tr>';
    [t('col_coc_analyzer'), t('col_coc_status'), t('col_coc_duration')].forEach(function(h) {
      html += '<th style="padding:6px 10px;color:var(--muted);background:var(--surface2);font-size:0.72rem">' + h + '</th>';
    });
    html += '</tr>';
    data.audit_log.forEach(function(entry) {
      var statusColor = entry.status === 'completed' || entry.status === 'success' ? 'var(--clean)' : entry.status === 'error' ? 'var(--high)' : 'var(--muted)';
      html += '<tr>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.78rem;font-family:monospace">' + escapeHtml(String(entry.analyzer || entry.name || '')) + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.78rem;color:' + statusColor + '">' + escapeHtml(String(entry.status || '')) + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.78rem">' + (entry.duration_ms ? entry.duration_ms + 'ms' : '—') + '</td>';
      html += '</tr>';
    });
    html += '</table>';
  }

  if (data.anomalies && data.anomalies.length) html += anomalyMiniList(data.anomalies);
  el.innerHTML = html;
}

// ============================================================
// Phase 6 — Extended Forensics
// ============================================================

function renderYara(data) {
  var card = document.getElementById('yaraCard');
  var el = document.getElementById('yaraContent');
  if (!el) return;
  if (!data) { if (card) card.style.display = 'none'; return; }
  if (card) card.style.display = '';
  var html = '<div class="section-explanation">' + t('yara_expl') + '</div>';
  html += kvTable([
    [t('lbl_yara_available'), data.available ? '<span class="text-clean"></span>' : '<span class="text-high"></span>'],
    [t('lbl_yara_rules'), data.rules_loaded || 0],
    [t('lbl_yara_matches'), data.total_matches || 0],
    [t('lbl_yara_critical'), data.critical_matches ? '<span class="text-high">' + data.critical_matches + '</span>' : '0'],
    [t('lbl_yara_high'), data.high_matches ? '<span class="text-medium">' + data.high_matches + '</span>' : '0'],
  ]);
  if (data.matches && data.matches.length) {
    html += '<div class="section-sub-header"><span>' + t('sub_yara_matches') + '</span></div>';
    html += '<table class="kv-table" style="width:100%"><tr>';
    [t('col_yara_rule'), t('col_yara_severity'), t('col_yara_category'), t('col_yara_desc')].forEach(function(h) {
      html += '<th style="padding:6px 10px;color:var(--muted);background:var(--surface2);font-size:0.72rem">' + h + '</th>';
    });
    html += '</tr>';
    data.matches.forEach(function(m) {
      var sev = (m.severity || 'MEDIUM').toUpperCase();
      html += '<tr>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.78rem;font-family:monospace">' + escapeHtml(String(m.rule || '')) + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.78rem" class="text-' + sev.toLowerCase() + '">' + sev + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.78rem">' + escapeHtml(String(m.category || '')) + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.75rem">' + escapeHtml(String(m.description || '')) + '</td>';
      html += '</tr>';
    });
    html += '</table>';
  } else {
    html += '<div style="color:var(--clean);font-size:0.82rem;margin-top:8px">' + t('yara_no_matches') + '</div>';
  }
  if (data.anomalies && data.anomalies.length) html += anomalyMiniList(data.anomalies);
  el.innerHTML = html;
}

function renderFontForensics(data) {
  var card = document.getElementById('fontForensicsCard');
  var el = document.getElementById('fontForensicsContent');
  if (!el) return;
  if (!data) { if (card) card.style.display = 'none'; return; }
  if (card) card.style.display = '';
  var html = '<div class="section-explanation">' + t('ff_expl') + '</div>';
  html += kvTable([
    [t('lbl_ff_total'), data.total_fonts || 0],
    [t('lbl_ff_embedded'), data.embedded_count || 0],
    [t('lbl_ff_subset'), data.subset_count || 0],
    [t('lbl_ff_system'), data.system_fonts ? '<span class="text-medium">' + data.system_fonts + '</span>' : '0'],
    [t('lbl_ff_type1'), data.type1_count || 0],
    [t('lbl_ff_truetype'), data.truetype_count || 0],
    [t('lbl_ff_creators'), (data.font_creators || []).join(', ') || '—'],
  ]);
  if (data.fonts && data.fonts.length) {
    html += '<div class="section-sub-header"><span>' + t('sub_ff_fonts') + '</span></div>';
    html += '<table class="kv-table" style="width:100%"><tr>';
    [t('col_ff_name'), t('col_ff_type'), t('col_ff_embedded'), t('col_ff_subset'), t('col_ff_origin')].forEach(function(h) {
      html += '<th style="padding:6px 10px;color:var(--muted);background:var(--surface2);font-size:0.72rem">' + h + '</th>';
    });
    html += '</tr>';
    data.fonts.slice(0, 30).forEach(function(f) {
      html += '<tr>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.75rem;font-family:monospace">' + escapeHtml(String(f.name || f.base_font || '')) + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.75rem">' + escapeHtml(String(f.subtype || '')) + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.75rem">' + (f.is_embedded ? '' : '') + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.75rem">' + (f.is_subset ? '' : '—') + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.75rem">' + escapeHtml(String(f.origin || '')) + '</td>';
      html += '</tr>';
    });
    html += '</table>';
  }
  if (data.anomalies && data.anomalies.length) html += anomalyMiniList(data.anomalies);
  el.innerHTML = html;
}

function renderPdfaCompliance(data) {
  var card = document.getElementById('pdfaComplianceCard');
  var el = document.getElementById('pdfaComplianceContent');
  if (!el) return;
  if (!data) { if (card) card.style.display = 'none'; return; }
  if (card) card.style.display = '';
  var html = '<div class="section-explanation">' + t('pdfa_expl') + '</div>';
  html += kvTable([
    [t('lbl_pdfa_claimed'), data.pdfa_claimed ? '<span class="text-clean">PDF/A-' + (data.pdfa_version || '?') + (data.pdfa_conformance || '') + '</span>' : t('no_clean')],
    [t('lbl_pdfx_claimed'), data.pdfx_claimed ? '<span class="text-clean">' + (data.pdfx_version || 'PDF/X') + '</span>' : t('no_clean')],
    [t('lbl_pdfa_issues'), (data.compliance_issues || []).length],
    [t('lbl_pdfa_passes'), (data.passes || []).length],
    [t('lbl_pdfa_output_intent'), data.output_intent ? escapeHtml(JSON.stringify(data.output_intent)) : '—'],
  ]);
  if (data.compliance_issues && data.compliance_issues.length) {
    html += '<div class="section-sub-header"><span>' + t('sub_pdfa_issues') + '</span></div>';
    html += '<table class="kv-table" style="width:100%"><tr>';
    [t('col_pdfa_check'), t('col_pdfa_status'), t('col_pdfa_detail')].forEach(function(h) {
      html += '<th style="padding:6px 10px;color:var(--muted);background:var(--surface2);font-size:0.72rem">' + h + '</th>';
    });
    html += '</tr>';
    data.compliance_issues.forEach(function(issue) {
      html += '<tr>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.78rem">' + escapeHtml(String(issue.check || '')) + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--high)">FAIL</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.75rem">' + escapeHtml(String(issue.detail || '')) + '</td>';
      html += '</tr>';
    });
    html += '</table>';
  }
  if (data.passes && data.passes.length) {
    html += '<div class="section-sub-header"><span>' + t('sub_pdfa_passes') + '</span></div>';
    data.passes.slice(0, 10).forEach(function(p) {
      html += '<div style="font-size:0.78rem;color:var(--clean);margin:2px 0">' + escapeHtml(String(p.check || p)) + '</div>';
    });
  }
  if (data.anomalies && data.anomalies.length) html += anomalyMiniList(data.anomalies);
  el.innerHTML = html;
}

function renderLinearization(data) {
  var card = document.getElementById('linearizationCard');
  var el = document.getElementById('linearizationContent');
  if (!el) return;
  if (!data) { if (card) card.style.display = 'none'; return; }
  if (card) card.style.display = '';
  var html = '<div class="section-explanation">' + t('lin_expl') + '</div>';
  if (!data.is_linearized) {
    html += kvTable([[t('lbl_lin_linearized'), '<span class="text-muted">' + t('lin_not_linearized') + '</span>']]);
  } else {
    html += kvTable([
      [t('lbl_lin_linearized'), '<span class="text-clean"></span>'],
      [t('lbl_lin_version'), data.linearization_version || '—'],
      [t('lbl_lin_file_declared'), data.file_length_declared ? data.file_length_declared.toLocaleString() + ' bytes' : '—'],
      [t('lbl_lin_file_actual'), data.file_length_actual ? data.file_length_actual.toLocaleString() + ' bytes' : '—'],
      [t('lbl_lin_mismatch'), data.length_mismatch ? '<span class="text-high">JA</span>' : '<span class="text-clean">Nein</span>'],
      [t('lbl_lin_hint_table'), data.hint_table_present ? '' : ''],
      [t('lbl_lin_first_page'), data.first_page_obj || '—'],
      [t('lbl_lin_pages'), data.page_count_declared || '—'],
    ]);
  }
  if (data.anomalies && data.anomalies.length) html += anomalyMiniList(data.anomalies);
  el.innerHTML = html;
}

function renderIccProfiles(data) {
  var card = document.getElementById('iccProfilesCard');
  var el = document.getElementById('iccProfilesContent');
  if (!el) return;
  if (!data) { if (card) card.style.display = 'none'; return; }
  if (card) card.style.display = '';
  var html = '<div class="section-explanation">' + t('icc_expl') + '</div>';
  html += kvTable([
    [t('lbl_icc_count'), data.profiles_found || 0],
    [t('lbl_icc_colorspaces'), (data.color_spaces_used || []).join(', ') || '—'],
  ]);
  if (data.profiles && data.profiles.length) {
    html += '<div class="section-sub-header"><span>' + t('sub_icc_profiles') + '</span></div>';
    html += '<table class="kv-table" style="width:100%"><tr>';
    [t('col_icc_name'), t('col_icc_version'), t('col_icc_class'), t('col_icc_colorspace'), t('col_icc_platform'), t('col_icc_creator'), t('col_icc_source')].forEach(function(h) {
      html += '<th style="padding:6px 10px;color:var(--muted);background:var(--surface2);font-size:0.72rem">' + h + '</th>';
    });
    html += '</tr>';
    data.profiles.forEach(function(p) {
      html += '<tr>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.75rem">' + escapeHtml(String(p.known_profile || '')) + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.75rem">' + escapeHtml(String(p.version || '')) + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.75rem">' + escapeHtml(String(p.device_class || '')) + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.75rem">' + escapeHtml(String(p.color_space || '')) + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.75rem">' + escapeHtml(String(p.platform || '')) + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.75rem;font-family:monospace">' + escapeHtml(String(p.creator || '')) + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.75rem">' + escapeHtml(String(p.source || '')) + '</td>';
      html += '</tr>';
    });
    html += '</table>';
  } else {
    html += '<div style="color:var(--muted);font-size:0.82rem;margin-top:8px">' + t('icc_no_profiles') + '</div>';
  }
  if (data.anomalies && data.anomalies.length) html += anomalyMiniList(data.anomalies);
  el.innerHTML = html;
}

function renderVisualRender(data) {
  var card = document.getElementById('visualRenderCard');
  var el = document.getElementById('visualRenderContent');
  if (!el) return;
  if (!data) { if (card) card.style.display = 'none'; return; }
  if (card) card.style.display = '';
  var html = '<div class="section-explanation">' + t('vr_expl') + '</div>';
  var dupCount = (data.duplicate_pages || []).length + (data.visual_anomalies || []).length;
  html += kvTable([
    [t('lbl_vr_available'), data.available ? '<span class="text-clean"></span>' : '<span class="text-high"></span>'],
    [t('lbl_vr_pages'), data.pages_rendered || 0],
    [t('lbl_vr_blank'), (data.blank_pages || []).length ? '<span class="text-medium">' + data.blank_pages.join(', ') + '</span>' : '0'],
    [t('lbl_vr_duplicates'), dupCount ? '<span class="text-medium">' + dupCount + '</span>' : '0'],
    [t('lbl_vr_renderer') || 'Renderer', data.renderer || '—'],
    [t('lbl_vr_dpi') || 'DPI', data.resolution_dpi || '—'],
  ]);
  if (data.page_hashes && data.page_hashes.length) {
    html += '<div class="section-sub-header"><span>' + t('sub_vr_hashes') + '</span></div>';
    html += '<table class="kv-table" style="width:100%"><tr>';
    [t('col_vr_page'), t('col_vr_hash'), t('col_vr_blank')].forEach(function(h) {
      html += '<th style="padding:6px 10px;color:var(--muted);background:var(--surface2);font-size:0.72rem">' + h + '</th>';
    });
    html += '</tr>';
    data.page_hashes.slice(0, 20).forEach(function(ph) {
      html += '<tr>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.78rem">' + (ph.page || '') + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.7rem;font-family:monospace;color:var(--muted)">' + escapeHtml(String(ph.hash || '').substring(0, 16)) + '…</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.78rem">' + (ph.is_blank ? '' : '—') + '</td>';
      html += '</tr>';
    });
    html += '</table>';
  }
  if (data.anomalies && data.anomalies.length) html += anomalyMiniList(data.anomalies);
  el.innerHTML = html;
}

function renderObjectGraph(data) {
  var card = document.getElementById('objectGraphCard');
  var el = document.getElementById('objectGraphContent');
  if (!el) return;
  if (!data) { if (card) card.style.display = 'none'; return; }
  if (card) card.style.display = '';
  var html = '<div class="section-explanation">' + t('og_expl') + '</div>';
  html += kvTable([
    [t('lbl_og_objects'), data.total_objects || 0],
    [t('lbl_og_max_depth'), data.max_depth || 0],
  ]);
  if (data.object_types && Object.keys(data.object_types).length) {
    html += '<div class="section-sub-header"><span>' + t('sub_og_types') + '</span></div>';
    html += '<table class="kv-table" style="width:100%"><tr>';
    [t('col_og_type'), t('col_og_count')].forEach(function(h) {
      html += '<th style="padding:6px 10px;color:var(--muted);background:var(--surface2);font-size:0.72rem">' + h + '</th>';
    });
    html += '</tr>';
    Object.keys(data.object_types).sort().forEach(function(typ) {
      html += '<tr>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.78rem;font-family:monospace">' + escapeHtml(typ) + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid var(--border);font-size:0.78rem">' + data.object_types[typ] + '</td>';
      html += '</tr>';
    });
    html += '</table>';
  }
  if (data.catalog_info && Object.keys(data.catalog_info).length) {
    html += '<div class="section-sub-header"><span>' + t('sub_og_catalog') + '</span></div>';
    var catRows = [];
    Object.keys(data.catalog_info).forEach(function(k) {
      if (k !== 'keys') catRows.push([k, String(data.catalog_info[k])]);
    });
    html += kvTable(catRows);
  }
  if (data.anomalies && data.anomalies.length) html += anomalyMiniList(data.anomalies);
  el.innerHTML = html;
}

function renderCrossDocFp(data) {
  var card = document.getElementById('crossDocFpCard');
  var el = document.getElementById('crossDocFpContent');
  if (!el) return;
  if (!data) { if (card) card.style.display = 'none'; return; }
  if (card) card.style.display = '';
  var html = '<div class="section-explanation">' + t('cdf_expl') + '</div>';
  html += kvTable([
    [t('lbl_cdf_version'), data.fingerprint_version || '1.0'],
    [t('lbl_cdf_struct'), '<span style="font-family:monospace;font-size:0.72rem">' + escapeHtml(String(data.structural_hash || '—')) + '</span>'],
    [t('lbl_cdf_font'), '<span style="font-family:monospace;font-size:0.72rem">' + escapeHtml(String(data.font_hash || '—')) + '</span>'],
    [t('lbl_cdf_meta'), '<span style="font-family:monospace;font-size:0.72rem">' + escapeHtml(String(data.metadata_hash || '—')) + '</span>'],
    [t('lbl_cdf_style'), '<span style="font-family:monospace;font-size:0.72rem">' + escapeHtml(String(data.style_hash || '—')) + '</span>'],
    [t('lbl_cdf_content'), '<span style="font-family:monospace;font-size:0.72rem">' + escapeHtml(String(data.content_hash || '—')) + '</span>'],
  ]);
  if (data.anomalies && data.anomalies.length) html += anomalyMiniList(data.anomalies);
  el.innerHTML = html;
}

function renderPrinterForensics(data) {
  var card = document.getElementById('printerForensicsCard');
  var el = document.getElementById('printerForensicsContent');
  if (!el) return;
  if (!data) { if (card) card.style.display = 'none'; return; }
  if (card) card.style.display = '';
  var html = '<div class="section-explanation">' + t('pf_expl') + '</div>';
  html += kvTable([
    [t('lbl_pf_scanned'), data.is_scanned_document ? '<span class="text-medium">JA</span>' : '<span class="text-clean">Nein</span>'],
    [t('lbl_pf_confidence'), (data.scan_confidence * 100).toFixed(0) + '%'],
    [t('lbl_pf_printer_type'), data.printer_type || '—'],
    [t('lbl_pf_dpi'), data.dpi_detected || '—'],
    [t('lbl_pf_halftone'), data.halftone_detected ? '<span class="text-medium">Erkannt</span>' : '—'],
    [t('lbl_pf_banding'), data.banding_detected ? '<span class="text-medium">Erkannt</span>' : '—'],
    [t('lbl_pf_images'), data.images_analyzed || 0],
  ]);
  if (data.scan_indicators && data.scan_indicators.length) {
    html += '<div class="section-sub-header"><span>' + t('sub_pf_indicators') + '</span></div>';
    data.scan_indicators.forEach(function(ind) {
      html += '<div style="font-size:0.78rem;color:var(--medium);margin:2px 0">• ' + escapeHtml(String(ind)) + '</div>';
    });
  }
  if (data.anomalies && data.anomalies.length) html += anomalyMiniList(data.anomalies);
  el.innerHTML = html;
}

// ============================================================
// Phase 4 — Cross-Match
// ============================================================

function runCrossMatchFonts(analysisId) {
  const btn = document.getElementById('btnCrossMatchFonts');
  const out = document.getElementById('crossMatchFontsResult');
  if (!btn || !out) return;
  btn.disabled = true;
  out.innerHTML = '<span style="color:var(--muted)">' + t('cross_match_loading') + '</span>';
  fetch('/cross-match/fonts/' + analysisId)
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (!data.matches || !data.matches.length) {
        out.innerHTML = '<span style="color:var(--muted)">' + t('cross_match_no_results') + '</span>';
      } else {
        var html = '<div style="font-size:0.8rem;color:var(--text);font-weight:600;margin-bottom:6px">' + t('cross_match_results').replace('{n}', data.match_count) + '</div>';
        html += '<table class="kv-table" style="width:100%">';
        html += '<tr><th style="padding:6px 10px;color:var(--muted);background:var(--surface2)">' + t('col_cm_filename') + '</th>';
        html += '<th style="padding:6px 10px;color:var(--muted);background:var(--surface2)">' + t('col_cm_risk') + '</th>';
        html += '<th style="padding:6px 10px;color:var(--muted);background:var(--surface2)">' + t('col_cm_shared') + '</th></tr>';
        data.matches.forEach(function(m) {
          html += '<tr>';
          html += '<td style="padding:6px 10px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">' + escapeHtml(m.filename) + '</td>';
          html += '<td style="padding:6px 10px;border-bottom:1px solid var(--border);font-size:0.78rem" class="text-' + m.risk_level.toLowerCase() + '">' + m.risk_level + '</td>';
          html += '<td style="padding:6px 10px;border-bottom:1px solid var(--border);font-size:0.75rem;font-family:monospace;color:var(--muted)">' + (m.shared_prefixes || []).slice(0, 5).map(function(p) { return escapeHtml(p); }).join(', ') + '</td>';
          html += '</tr>';
        });
        html += '</table>';
        out.innerHTML = html;
      }
    })
    .catch(function(e) { out.innerHTML = '<span style="color:var(--high)">' + e.message + '</span>'; })
    .finally(function() { btn.disabled = false; });
}

function runCrossMatchQuant(analysisId) {
  const btn = document.getElementById('btnCrossMatchQuant');
  const out = document.getElementById('crossMatchQuantResult');
  if (!btn || !out) return;
  btn.disabled = true;
  out.innerHTML = '<span style="color:var(--muted)">' + t('cross_match_loading') + '</span>';
  fetch('/cross-match/quant/' + analysisId)
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (!data.matches || !data.matches.length) {
        out.innerHTML = '<span style="color:var(--muted)">' + t('cross_match_no_results') + '</span>';
      } else {
        var html = '<div style="font-size:0.8rem;color:var(--text);font-weight:600;margin-bottom:6px">' + t('cross_match_results').replace('{n}', data.match_count) + '</div>';
        html += '<table class="kv-table" style="width:100%">';
        html += '<tr><th style="padding:6px 10px;color:var(--muted);background:var(--surface2)">' + t('col_cm_filename') + '</th>';
        html += '<th style="padding:6px 10px;color:var(--muted);background:var(--surface2)">' + t('col_cm_risk') + '</th></tr>';
        data.matches.forEach(function(m) {
          html += '<tr>';
          html += '<td style="padding:6px 10px;border-bottom:1px solid var(--border);font-size:0.78rem;color:var(--text)">' + escapeHtml(m.filename) + '</td>';
          html += '<td style="padding:6px 10px;border-bottom:1px solid var(--border);font-size:0.78rem" class="text-' + m.risk_level.toLowerCase() + '">' + m.risk_level + '</td>';
          html += '</tr>';
        });
        html += '</table>';
        out.innerHTML = html;
      }
    })
    .catch(function(e) { out.innerHTML = '<span style="color:var(--high)">' + e.message + '</span>'; })
    .finally(function() { btn.disabled = false; });
}

// ===== Report Language Modal =====

function showReportLangModal(analysisId) {
  var overlay = document.createElement('div');
  overlay.id = 'reportLangOverlay';
  overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.55);z-index:9999;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(3px)';

  var isDe = (typeof getLang === 'function' ? getLang() : 'de') === 'de';

  overlay.innerHTML = '<div style="background:var(--surface,#fff);border:1px solid var(--border,#e2e8f0);border-radius:14px;padding:32px 36px;width:380px;box-shadow:0 20px 60px rgba(0,0,0,0.25);text-align:center">' +
    '<div style="font-size:2rem;margin-bottom:10px"></div>' +
    '<div style="font-size:1.05rem;font-weight:700;color:var(--text,#0f172a);margin-bottom:6px">' + (isDe ? 'Berichtssprache wählen' : 'Choose Report Language') + '</div>' +
    '<div style="font-size:0.82rem;color:var(--muted,#64748b);margin-bottom:24px">' + (isDe ? 'Der PDF-Bericht wird in der gewählten Sprache generiert.' : 'The PDF report will be generated in the selected language.') + '</div>' +
    '<div style="display:flex;gap:12px;justify-content:center">' +
    '<button id="reportLangDe" style="flex:1;padding:14px 10px;border-radius:10px;border:2px solid var(--accent,#2563eb);background:var(--accent,#2563eb);color:#fff;font-size:0.95rem;font-weight:600;cursor:pointer;display:flex;flex-direction:column;align-items:center;gap:4px"><span style="font-size:1.5rem">🇩🇪</span><span>Deutsch</span></button>' +
    '<button id="reportLangEn" style="flex:1;padding:14px 10px;border-radius:10px;border:2px solid var(--border,#e2e8f0);background:var(--surface2,#f1f5f9);color:var(--text,#0f172a);font-size:0.95rem;font-weight:600;cursor:pointer;display:flex;flex-direction:column;align-items:center;gap:4px"><span style="font-size:1.5rem">🇬🇧</span><span>English</span></button>' +
    '</div>' +
    '<button id="reportLangCancel" style="margin-top:16px;background:none;border:none;color:var(--muted,#64748b);font-size:0.82rem;cursor:pointer;text-decoration:underline">' + (isDe ? 'Abbrechen' : 'Cancel') + '</button>' +
    '</div>';

  document.body.appendChild(overlay);

  function closeModal() { if (document.body.contains(overlay)) document.body.removeChild(overlay); }

  document.getElementById('reportLangDe').onclick = function() { closeModal(); _downloadReport(analysisId, 'de'); };
  document.getElementById('reportLangEn').onclick = function() { closeModal(); _downloadReport(analysisId, 'en'); };
  document.getElementById('reportLangCancel').onclick = closeModal;
  overlay.addEventListener('click', function(e) { if (e.target === overlay) closeModal(); });
}

function _downloadReport(analysisId, lang) {
  var btn = document.getElementById('btnDownloadReport');
  if (btn) {
    var orig = btn.innerHTML;
    btn.innerHTML = (lang === 'de' ? 'Generiere...' : 'Generating...');
    btn.disabled = true;
    setTimeout(function() { btn.innerHTML = orig; btn.disabled = false; }, 10000);
  }
  window.open('/report/' + analysisId + '?lang=' + lang, '_blank');
}

// ===== Status-Badges für Sektionen =====
// Zeigt pro Sektion den Befund-Status an: POSITIV, NEUTRAL, WARNUNG, RED ALERT

function _statusBadge(type, label) {
  var cls = 'sec-status sec-status-' + type;
  return '<span class="' + cls + '">' + label + '</span>';
}

function _setCardStatus(cardBodyId, type, label) {
  var body = document.getElementById(cardBodyId);
  if (!body) return;
  var header = body.previousElementSibling;
  if (!header) return;
  // Remove existing badge
  var old = header.querySelector('.sec-status');
  if (old) old.remove();
  // Insert before collapse-arrow
  var arrow = header.querySelector('.collapse-arrow');
  if (arrow) {
    arrow.insertAdjacentHTML('beforebegin', _statusBadge(type, label));
  }
}

function _applyStatusBadges(data) {
  var de = (typeof getLang === 'function' && getLang() === 'de') || true;

  // Virus Scan
  if (data.virus_scan) {
    if (data.virus_scan.is_clean === false) {
      _setCardStatus('virusScanBody', 'alert', de ? 'RED ALERT' : 'RED ALERT');
    } else {
      _setCardStatus('virusScanBody', 'positive', de ? 'POSITIV' : 'POSITIVE');
    }
  }

  // Anomalies
  var highCount = data.anomaly_count_high || 0;
  var medCount = data.anomaly_count_medium || 0;
  if (highCount > 0) {
    _setCardStatus('anomaliesBody', 'alert', 'RED ALERT');
  } else if (medCount > 0) {
    _setCardStatus('anomaliesBody', 'warning', de ? 'WARNUNG' : 'WARNING');
  } else {
    _setCardStatus('anomaliesBody', 'positive', de ? 'POSITIV' : 'POSITIVE');
  }

  // Hashes — always neutral (informational)
  _setCardStatus('hashesBody', 'neutral', 'NEUTRAL');

  // Metadata
  if (data.metadata) {
    var m = data.metadata;
    var metaSusp = false;
    if (m.mod_date && m.creation_date && m.mod_date < m.creation_date) metaSusp = true;
    _setCardStatus('metaBody', metaSusp ? 'warning' : 'neutral', metaSusp ? (de ? 'WARNUNG' : 'WARNING') : 'NEUTRAL');
  }

  // Software Fingerprint
  if (data.software_fingerprint) {
    var sf = data.software_fingerprint;
    if (sf.ghostscript_traces || sf.version_mismatch) {
      _setCardStatus('softwareBody', 'warning', de ? 'WARNUNG' : 'WARNING');
    } else {
      _setCardStatus('softwareBody', 'neutral', 'NEUTRAL');
    }
  }

  // UUID
  if (data.uuid_decode) {
    var uuids = data.uuid_decode.uuids || [];
    var uuidSusp = uuids.some(function(u) { return u.time_deviation_suspicious; });
    _setCardStatus('uuidBody', uuidSusp ? 'warning' : 'neutral', uuidSusp ? (de ? 'WARNUNG' : 'WARNING') : 'NEUTRAL');
  }

  // Signatures
  if (data.signature) {
    var sig = data.signature;
    if (sig.has_signature) {
      var allValid = (sig.signatures || []).every(function(s) { return s.valid; });
      _setCardStatus('sigBody', allValid ? 'positive' : 'alert', allValid ? (de ? 'POSITIV' : 'POSITIVE') : 'RED ALERT');
    } else {
      _setCardStatus('sigBody', 'info', de ? 'KEINE' : 'NONE');
    }
  }

  // Geometry — neutral
  _setCardStatus('geoBody', 'neutral', 'NEUTRAL');

  // Images
  if (data.jpeg_extractor) {
    var imgCount = (data.jpeg_extractor.images || []).length;
    _setCardStatus('imagesBody', imgCount > 0 ? 'info' : 'neutral',
      imgCount > 0 ? (imgCount + (de ? ' BILDER' : ' IMAGES')) : 'NEUTRAL');
  }

  // Encryption
  if (data.encryption) {
    if (data.encryption.is_encrypted) {
      _setCardStatus('encBody', 'warning', de ? 'WARNUNG' : 'WARNING');
    } else {
      _setCardStatus('encBody', 'positive', de ? 'POSITIV' : 'POSITIVE');
    }
  }

  // Incremental Updates
  if (data.incremental_updates) {
    var revs = data.incremental_updates.revision_count || 0;
    if (revs > 3) {
      _setCardStatus('incBody', 'warning', revs + ' REV');
    } else {
      _setCardStatus('incBody', 'neutral', revs + ' REV');
    }
  }

  // JavaScript
  if (data.javascript) {
    if (data.javascript.has_javascript) {
      _setCardStatus('jsBody', 'alert', 'RED ALERT');
    } else {
      _setCardStatus('jsBody', 'positive', de ? 'POSITIV' : 'POSITIVE');
    }
  }

  // Embedded Files
  if (data.embedded_files) {
    var efCount = (data.embedded_files.files || []).length;
    if (efCount > 0) {
      _setCardStatus('efBody', 'warning', efCount + (de ? ' DATEIEN' : ' FILES'));
    } else {
      _setCardStatus('efBody', 'positive', de ? 'POSITIV' : 'POSITIVE');
    }
  }

  // Shadow Attack
  if (data.shadow_attack) {
    if (data.shadow_attack.shadow_detected) {
      _setCardStatus('shadowBody', 'alert', 'RED ALERT');
    } else {
      _setCardStatus('shadowBody', 'positive', de ? 'POSITIV' : 'POSITIVE');
    }
  }

  // IOC
  if (data.ioc) {
    var iocTotal = (data.ioc.urls || []).length + (data.ioc.ips || []).length + (data.ioc.domains || []).length;
    if (iocTotal > 0) {
      _setCardStatus('iocBody', 'warning', iocTotal + ' IOC');
    } else {
      _setCardStatus('iocBody', 'positive', de ? 'POSITIV' : 'POSITIVE');
    }
  }

  // Hidden Text
  if (data.hidden_text) {
    if (data.hidden_text.has_hidden_text) {
      _setCardStatus('hiddenTextBody', 'alert', 'RED ALERT');
    } else {
      _setCardStatus('hiddenTextBody', 'positive', de ? 'POSITIV' : 'POSITIVE');
    }
  }

  // YARA
  if (data.yara) {
    var yaraMatches = (data.yara.matches || []).length;
    if (yaraMatches > 0) {
      _setCardStatus('yaraBody', 'alert', yaraMatches + ' MATCHES');
    } else {
      _setCardStatus('yaraBody', 'positive', de ? 'POSITIV' : 'POSITIVE');
    }
  }

  // Font Forensics
  if (data.font_forensics) {
    var fontAnom = (data.font_forensics.anomalies || []).length;
    _setCardStatus('fontForensicsBody', fontAnom > 0 ? 'warning' : 'neutral',
      fontAnom > 0 ? (de ? 'WARNUNG' : 'WARNING') : 'NEUTRAL');
  }

  // PDF/A Compliance
  if (data.pdfa_compliance) {
    if (data.pdfa_compliance.is_compliant) {
      _setCardStatus('pdfaComplianceBody', 'positive', de ? 'POSITIV' : 'POSITIVE');
    } else {
      _setCardStatus('pdfaComplianceBody', 'info', de ? 'NICHT KONFORM' : 'NON-COMPLIANT');
    }
  }

  // Linearization
  if (data.linearization) {
    _setCardStatus('linearizationBody', 'neutral', 'NEUTRAL');
  }

  // ICC Profiles
  if (data.icc_profiles) {
    _setCardStatus('iccProfilesBody', 'neutral', 'NEUTRAL');
  }

  // Printer Forensics
  if (data.printer_forensics) {
    var printerFound = data.printer_forensics.printer_detected;
    _setCardStatus('printerForensicsBody', printerFound ? 'info' : 'neutral',
      printerFound ? (de ? 'ERKANNT' : 'DETECTED') : 'NEUTRAL');
  }

  // Chain of Custody
  if (data.chain_of_custody) {
    if (data.chain_of_custody.integrity_verified) {
      _setCardStatus('chainOfCustodyBody', 'positive', de ? 'POSITIV' : 'POSITIVE');
    } else {
      _setCardStatus('chainOfCustodyBody', 'alert', 'RED ALERT');
    }
  }

  // Timezone
  if (data.timezone) {
    _setCardStatus('timezoneBody', 'neutral', 'NEUTRAL');
  }

  // Author Artifacts
  if (data.author_artifacts) {
    _setCardStatus('authorBody', 'neutral', 'NEUTRAL');
  }

  // ELA
  if (data.ela) {
    if (data.ela.manipulation_detected) {
      _setCardStatus('elaBody', 'alert', 'RED ALERT');
    } else {
      _setCardStatus('elaBody', 'positive', de ? 'POSITIV' : 'POSITIVE');
    }
  }

  // Object Streams
  if (data.object_streams) {
    _setCardStatus('objstreamsBody', 'neutral', 'NEUTRAL');
  }

  // Residual Objects
  if (data.residual_objects) {
    var resCount = (data.residual_objects.orphaned || []).length;
    _setCardStatus('residualBody', resCount > 0 ? 'warning' : 'positive',
      resCount > 0 ? (resCount + (de ? ' VERWAIST' : ' ORPHANED')) : (de ? 'POSITIV' : 'POSITIVE'));
  }

  // Cross Analyzer
  if (data.cross_analyzer) {
    _setCardStatus('crossAnalyzerBody', 'info', 'INFO');
  }

  // Fuzzy Hash
  if (data.fuzzy_hash) {
    _setCardStatus('fuzzyHashBody', 'neutral', 'NEUTRAL');
  }

  // Steganography
  if (data.steganography) {
    if (data.steganography.detected) {
      _setCardStatus('steganographyBody', 'alert', 'RED ALERT');
    } else {
      _setCardStatus('steganographyBody', 'positive', de ? 'POSITIV' : 'POSITIVE');
    }
  }

  // Yellow Dots
  if (data.yellow_dots) {
    if (data.yellow_dots.detected) {
      _setCardStatus('yellowDotsBody', 'info', de ? 'ERKANNT' : 'DETECTED');
    } else {
      _setCardStatus('yellowDotsBody', 'neutral', 'NEUTRAL');
    }
  }

  // Redaction
  if (data.redaction) {
    if (data.redaction.has_redactions) {
      _setCardStatus('redactionBody', 'warning', de ? 'WARNUNG' : 'WARNING');
    } else {
      _setCardStatus('redactionBody', 'positive', de ? 'POSITIV' : 'POSITIVE');
    }
  }
}
