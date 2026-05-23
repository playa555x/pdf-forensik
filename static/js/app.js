
function _getAnalysisProfile() {
  const sel = document.querySelector('input[name="analysis_profile"]:checked');
  return sel ? sel.value : 'standard';
}
document.addEventListener('change', (e) => {
  if (e.target && e.target.name === 'analysis_profile') {
    document.querySelectorAll('.profile-opt').forEach(el => el.classList.remove('active'));
    if (e.target.parentElement) e.target.parentElement.classList.add('active');
  }
});
/**
 * app.js — Upload-Handler, Fortschrittsbalken, globale Helfer
 */

// ===== Upload-Handler =====

const uploadZone   = document.getElementById('uploadZone');
const fileInput    = document.getElementById('fileInput');
const progressContainer = document.getElementById('progressContainer');
const progressFill = document.getElementById('progressFill');
const progressLabel= document.getElementById('progressLabel');
const errorAlert   = document.getElementById('errorAlert');
const errorMessage = document.getElementById('errorMessage');
const resultContainer = document.getElementById('resultContainer');

if (uploadZone) {
  // Drag & Drop
  uploadZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadZone.classList.add('drag-over');
  });

  uploadZone.addEventListener('dragleave', () => {
    uploadZone.classList.remove('drag-over');
  });

  uploadZone.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadZone.classList.remove('drag-over');
    const files = Array.from(e.dataTransfer.files);
    if (files.length > 1) {
      handleFiles(files);
    } else if (files.length === 1) {
      handleFile(files[0]);
    }
  });

  // Klick auf gesamte Upload-Zone
  uploadZone.addEventListener('click', (e) => {
    if (e.target !== fileInput && !e.target.closest('label')) {
      fileInput.click();
    }
  });

  fileInput.addEventListener('change', (e) => {
    const files = Array.from(e.target.files);
    if (files.length > 1) {
      handleFiles(files);
    } else if (files.length === 1) {
      handleFile(files[0]);
    }
    fileInput.value = '';
  });
}

const STEPS = ['step-hash', 'step-meta', 'step-img', 'step-uuid', 'step-sig', 'step-fp'];
let stepTimer = null;

function startFakeProgress() {
  let step = 0;
  let pct = 5;

  STEPS.forEach(id => {
    const el = document.getElementById(id);
    if (el) { el.classList.remove('active', 'done'); }
  });

  progressFill.style.width = '5%';

  stepTimer = setInterval(() => {
    if (step < STEPS.length) {
      const el = document.getElementById(STEPS[step]);
      if (el) el.classList.add('active');
      if (step > 0) {
        const prev = document.getElementById(STEPS[step - 1]);
        if (prev) { prev.classList.remove('active'); prev.classList.add('done'); }
      }
      step++;
    }
    pct = Math.min(pct + 12, 88);
    progressFill.style.width = pct + '%';
  }, 700);
}

function stopFakeProgress(success) {
  clearInterval(stepTimer);
  STEPS.forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      if (success) { el.classList.remove('active'); el.classList.add('done'); }
      else { el.classList.remove('active', 'done'); }
    }
  });
  progressFill.style.width = success ? '100%' : '0%';
}

function showError(msg) {
  if (!errorAlert) return;
  errorMessage.textContent = msg;
  errorAlert.style.display = 'flex';
  setTimeout(() => { errorAlert.style.display = 'none'; }, 8000);
}

const _SUPPORTED_EXTS = new Set([
  '.pdf', '.docx', '.xlsx', '.pptx', '.docm', '.xlsm', '.pptm',
  '.doc', '.xls', '.ppt', '.odt', '.ods', '.odp',
]);

async function handleFile(file) {
  const ext = file.name.toLowerCase().match(/\.[^.]+$/)?.[0] || '';
  if (!_SUPPORTED_EXTS.has(ext)) {
    showError(typeof t === 'function' ? t('err_not_supported') : 'Unsupported file format.');
    return;
  }

  if (file.size > 200 * 1024 * 1024) {
    showError(typeof t === 'function' ? t('err_too_large') || 'File too large (max 200 MB).' : 'File too large (max 200 MB).');
    return;
  }

  // UI vorbereiten
  if (uploadZone) uploadZone.style.display = 'none';
  if (progressContainer) progressContainer.style.display = 'block';
  if (errorAlert) errorAlert.style.display = 'none';
  if (resultContainer) resultContainer.style.display = 'none';
  progressLabel.textContent = `${typeof t === 'function' ? t('upload_progress') : 'Analysing…'} "${file.name}"…`;

  startFakeProgress();

  const formData = new FormData();
  formData.append('file', file);

  try {
    const resp = await fetch('/analyze?profile=' + _getAnalysisProfile(), { method: 'POST', body: formData });
    const data = await resp.json();

    if (!resp.ok) {
      throw new Error(data.detail || `HTTP ${resp.status}`);
    }

    stopFakeProgress(true);
    progressLabel.textContent = typeof t === 'function' ? (t('analysis_done') || 'Analysis complete!') : 'Analysis complete!';

    await new Promise(r => setTimeout(r, 400));

    if (progressContainer) progressContainer.style.display = 'none';
    if (uploadZone) uploadZone.style.display = 'flex';

    // Ergebnis rendern (results.js)
    if (typeof renderResult === 'function') {
      renderResult(data);
    }

  } catch (err) {
    stopFakeProgress(false);
    if (progressContainer) progressContainer.style.display = 'none';
    if (uploadZone) uploadZone.style.display = 'flex';
    showError(err.message || t('err_unknown'));
  }
}

// ===== Collapsible-Cards (Smooth Animation) =====

document.addEventListener('click', (e) => {
  var header = e.target.closest('.collapsible');
  if (!header) return;
  var targetId = header.dataset.target;
  var body = document.getElementById(targetId);
  if (!body) return;
  var arrow = header.querySelector('.collapse-arrow');
  var isCollapsed = body.classList.contains('collapsed');

  if (isCollapsed) {
    // Opening: remove collapsed, then set max-height based on actual content
    body.classList.remove('collapsed');
    body.style.maxHeight = body.scrollHeight + 'px';
    if (arrow) arrow.classList.add('open');
    // After transition, remove inline max-height so content can grow
    setTimeout(function() { body.style.maxHeight = ''; }, 400);
  } else {
    // Closing: set explicit max-height first, then collapse
    body.style.maxHeight = body.scrollHeight + 'px';
    // Force reflow
    body.offsetHeight;
    body.classList.add('collapsed');
    body.style.maxHeight = '';
    if (arrow) arrow.classList.remove('open');
  }
});

// ===== Globale Helfer =====

window.formatBytes = function(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1024 / 1024).toFixed(2) + ' MB';
};

window.formatDate = function(iso) {
  if (!iso) return '—';
  try {
    const locale = (typeof getLang === 'function' && getLang() === 'en') ? 'en-GB' : 'de-DE';
    return new Date(iso).toLocaleString(locale, {
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit'
    });
  } catch { return iso; }
};

window.escapeHtml = function(s) {
  return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
};

window.riskBadgeHtml = function(level) {
  return `<span class="risk-badge ${level}">${level}</span>`;
};

window.severityBadgeHtml = function(sev) {
  return `<span class="anomaly-severity severity-${sev}">${sev}</span>`;
};

// ===== Batch Upload =====

let _batchFiles = [];

const batchQueue         = document.getElementById('batchQueue');
const batchQueueList     = document.getElementById('batchQueueList');
const batchResultsCont   = document.getElementById('batchResultsContainer');
const btnStartBatch      = document.getElementById('btnStartBatch');
const btnClearBatch      = document.getElementById('btnClearBatch');

function handleFiles(files) {
  _batchFiles = files.filter(f => {
    const ext = f.name.toLowerCase().match(/\.[^.]+$/)?.[0] || '';
    return _SUPPORTED_EXTS.has(ext) && f.size <= 200 * 1024 * 1024;
  });

  if (_batchFiles.length === 0) {
    showError(typeof t === 'function' ? t('err_not_supported') : 'Keine gültigen Dateien.');
    return;
  }

  // Batch-UI zeigen
  if (batchQueue) batchQueue.style.display = 'block';
  if (batchResultsCont) batchResultsCont.style.display = 'none';
  renderBatchQueue();
}

function renderBatchQueue() {
  if (!batchQueueList) return;
  batchQueueList.innerHTML = _batchFiles.map((f, i) => `
    <div class="batch-item" id="batch-item-${i}">
      <span style="font-size:1rem"></span>
      <span style="flex:1;font-size:0.82rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escapeHtml(f.name)}">${escapeHtml(f.name)}</span>
      <span style="font-size:0.75rem;color:var(--muted)">${window.formatBytes(f.size)}</span>
      <span class="batch-status-badge batch-status-pending" id="batch-badge-${i}">${typeof t === 'function' ? t('batch_status_pending') : 'Wartend'}</span>
    </div>
  `).join('');
}

function setBatchItemStatus(i, status) {
  const item  = document.getElementById(`batch-item-${i}`);
  const badge = document.getElementById(`batch-badge-${i}`);
  if (!item || !badge) return;

  const labels = {
    pending:   typeof t === 'function' ? t('batch_status_pending')   : 'Wartend',
    analyzing: typeof t === 'function' ? t('batch_status_analyzing') : 'Analysiere…',
    done:      typeof t === 'function' ? t('batch_status_done')      : 'Fertig',
    error:     typeof t === 'function' ? t('batch_status_error')     : 'Fehler',
  };

  badge.className = `batch-status-badge batch-status-${status}`;
  badge.textContent = labels[status] || status;

  if (status === 'analyzing') {
    item.style.background = 'rgba(59,130,246,0.05)';
  } else if (status === 'done') {
    item.style.background = 'rgba(34,197,94,0.05)';
  } else if (status === 'error') {
    item.style.background = 'rgba(239,68,68,0.05)';
  }
}

async function runBatchAnalysis() {
  if (!_batchFiles.length) return;

  // Buttons sperren
  if (btnStartBatch) btnStartBatch.disabled = true;
  if (btnClearBatch) btnClearBatch.disabled = true;

  const results = [];

  for (let i = 0; i < _batchFiles.length; i++) {
    setBatchItemStatus(i, 'analyzing');

    const formData = new FormData();
    formData.append('file', _batchFiles[i]);

    try {
      const resp = await fetch('/analyze?profile=' + _getAnalysisProfile(), { method: 'POST', body: formData });
      const data = await resp.json();

      if (!resp.ok) throw new Error(data.detail || `HTTP ${resp.status}`);

      setBatchItemStatus(i, 'done');
      results.push({ filename: _batchFiles[i].name, status: 'ok', data });
    } catch (err) {
      setBatchItemStatus(i, 'error');
      results.push({ filename: _batchFiles[i].name, status: 'error', error: err.message });
    }
  }

  // Ergebnisse anzeigen
  renderBatchResults(results);

  if (btnStartBatch) btnStartBatch.disabled = false;
  if (btnClearBatch) btnClearBatch.disabled = false;
}

function renderBatchResults(results) {
  if (!batchResultsCont) return;
  batchResultsCont.style.display = 'block';

  const ok  = results.filter(r => r.status === 'ok').length;
  const err = results.filter(r => r.status === 'error').length;

  const title = typeof t === 'function' ? t('batch_results_title') : 'Batch-Ergebnisse';

  let html = `
    <div style="margin:12px 0 6px;font-size:0.85rem;font-weight:600;color:var(--text)">${title}</div>
    <div style="font-size:0.8rem;color:var(--muted);margin-bottom:10px">
      ${ok} ${typeof t === 'function' ? t('batch_status_done') : 'Fertig'}
      ${err > 0 ? ` &nbsp;·&nbsp; ${err} ${typeof t === 'function' ? t('batch_status_error') : 'Fehler'}` : ''}
    </div>
    <table style="width:100%;border-collapse:collapse;font-size:0.8rem">
      <thead>
        <tr style="border-bottom:1px solid var(--border);color:var(--muted)">
          <th style="text-align:left;padding:5px 8px;font-weight:600">Datei</th>
          <th style="text-align:center;padding:5px 8px;font-weight:600">Risiko</th>
          <th style="text-align:center;padding:5px 8px;font-weight:600">HIGH</th>
          <th style="text-align:center;padding:5px 8px;font-weight:600">MEDIUM</th>
          <th style="text-align:center;padding:5px 8px;font-weight:600">LOW</th>
          <th style="text-align:center;padding:5px 8px;font-weight:600"></th>
        </tr>
      </thead>
      <tbody>`;

  for (const r of results) {
    if (r.status === 'ok') {
      const d = r.data;
      html += `
        <tr style="border-bottom:1px solid var(--border)">
          <td style="padding:5px 8px;overflow:hidden;text-overflow:ellipsis;max-width:160px;white-space:nowrap" title="${escapeHtml(r.filename)}">${escapeHtml(r.filename)}</td>
          <td style="text-align:center;padding:5px 8px">${riskBadgeHtml(d.risk_level)}</td>
          <td style="text-align:center;padding:5px 8px;color:#ef4444;font-weight:600">${d.anomaly_count_high || 0}</td>
          <td style="text-align:center;padding:5px 8px;color:#f59e0b;font-weight:600">${d.anomaly_count_medium || 0}</td>
          <td style="text-align:center;padding:5px 8px;color:#3b82f6;font-weight:600">${d.anomaly_count_low || 0}</td>
          <td style="text-align:center;padding:5px 8px">
            <button class="btn" style="font-size:0.72rem;padding:3px 8px"
              onclick="if(typeof renderResult==='function') renderResult(${JSON.stringify(d).replace(/"/g,'&quot;')})">
              Anzeigen
            </button>
          </td>
        </tr>`;
    } else {
      html += `
        <tr style="border-bottom:1px solid var(--border)">
          <td style="padding:5px 8px;overflow:hidden;text-overflow:ellipsis;max-width:160px;white-space:nowrap" title="${escapeHtml(r.filename)}">${escapeHtml(r.filename)}</td>
          <td colspan="4" style="padding:5px 8px;color:#ef4444;font-size:0.75rem">${escapeHtml(r.error || 'Fehler')}</td>
          <td></td>
        </tr>`;
    }
  }

  html += `</tbody></table>`;
  batchResultsCont.innerHTML = html;
}

// Batch-Buttons verdrahten
if (btnStartBatch) {
  btnStartBatch.addEventListener('click', () => {
    if (_batchFiles.length) runBatchAnalysis();
  });
}

if (btnClearBatch) {
  btnClearBatch.addEventListener('click', () => {
    _batchFiles = [];
    if (batchQueue) batchQueue.style.display = 'none';
    if (batchResultsCont) batchResultsCont.style.display = 'none';
    if (batchQueueList) batchQueueList.innerHTML = '';
  });
}

// ===== KI-Review =====

// Letztes KI-Review-Ergebnis speichern (für Sprachwechsel)
var _lastAiReviewLang = null;

// Preliminary als sichtbares Erst-Gutachten rendern — ersetzt die
// Loading-Stages und zeigt daneben einen Badge dass die Tiefenanalyse läuft.
function _renderPreliminaryAsResult(text) {
  const panel   = document.getElementById('aiReviewPanel');
  const loading = document.getElementById('aiReviewLoading');
  const content = document.getElementById('aiReviewContent');
  if (!panel || !loading || !content) return;

  loading.style.display = 'none';

  let box = document.getElementById('aiPrelimResult');
  if (!box) {
    box = document.createElement('div');
    box.id = 'aiPrelimResult';
    box.className = 'ai-prelim-result';

    const head = document.createElement('div');
    head.className = 'ai-prelim-result-head';

    const badge = document.createElement('span');
    badge.className = 'ai-prelim-badge';
    badge.textContent = 'Erst-Einschätzung · Gemma 4 · 8B';
    head.appendChild(badge);

    const status = document.createElement('span');
    status.className = 'ai-prelim-deep-status';
    status.id = 'aiPrelimDeepStatus';

    const spin = document.createElement('span');
    spin.className = 'ai-mini-spinner';
    status.appendChild(spin);

    const label = document.createElement('span');
    label.textContent = 'Detail-Gutachten läuft im Hintergrund — ';
    status.appendChild(label);

    const timer = document.createElement('span');
    timer.id = 'aiPrelimDeepTimer';
    timer.textContent = '0:00';
    status.appendChild(timer);

    const hint = document.createElement('span');
    hint.className = 'ai-prelim-deep-hint';
    hint.textContent = ' · Du kannst die Seite verlassen, Ergebnis wird gespeichert.';
    status.appendChild(hint);

    head.appendChild(status);
    box.appendChild(head);

    const txt = document.createElement('div');
    txt.className = 'ai-prelim-result-text';
    txt.id = 'aiPrelimResultText';
    box.appendChild(txt);

    content.parentNode.insertBefore(box, content);
  }
  const t = document.getElementById('aiPrelimResultText');
  if (t) t.textContent = text || '';
  box.style.display = 'block';
  content.style.display = 'none';
}

function _removePreliminaryResult() {
  const box = document.getElementById('aiPrelimResult');
  if (box) box.remove();
}

// Hilfsfunktionen zum Zurücksetzen / Manipulieren des Loading-UIs
function _resetAiLoadingUI() {
  _removePreliminaryResult();
  const prelim = document.getElementById('aiStagePrelim');
  const deep   = document.getElementById('aiStageDeep');
  if (prelim) { prelim.classList.remove('ai-stage-done'); prelim.classList.add('ai-stage-active'); }
  if (deep)   { deep.classList.remove('ai-stage-active','ai-stage-done'); deep.classList.add('ai-stage-pending'); }
  const prelimText = document.getElementById('aiPrelimText');
  if (prelimText) prelimText.textContent = '';
  const prelimStatus = document.getElementById('aiPrelimStatus');
  if (prelimStatus) prelimStatus.textContent = '…';
  const deepStatus = document.getElementById('aiDeepStatus');
  if (deepStatus) deepStatus.textContent = 'wartet…';
  const deepTimer = document.getElementById('aiDeepTimer');
  if (deepTimer) deepTimer.textContent = '0:00';
  const deepBar = document.getElementById('aiDeepBar');
  if (deepBar) deepBar.style.width = '0%';
  const deepSpinner = document.getElementById('aiDeepSpinner');
  if (deepSpinner) deepSpinner.classList.add('ai-spinner-paused');
}

function _fmtTime(sec) {
  const m = Math.floor(sec / 60);
  const s = Math.floor(sec % 60);
  return `${m}:${s.toString().padStart(2,'0')}`;
}

async function requestAiReview(forceRegenerate) {
  if (!currentAnalysisId) return;

  const panel   = document.getElementById('aiReviewPanel');
  const loading = document.getElementById('aiReviewLoading');
  const content = document.getElementById('aiReviewContent');

  panel.querySelectorAll('.alert-error').forEach(el => el.remove());

  panel.style.display   = 'block';
  loading.style.display = 'flex';
  content.style.display = 'none';
  _resetAiLoadingUI();

  panel.scrollIntoView({ behavior: 'smooth', block: 'start' });

  const lang = (typeof getLang === 'function') ? getLang() : 'de';
  // forceRegenerate=true -> Cache verwerfen, neu generieren
  const forceParam = forceRegenerate ? '&force=true' : '';
  const url  = `/ai-review/${currentAnalysisId}/stream?lang=${lang}${forceParam}`;

  // Elemente cachen
  const prelimText   = document.getElementById('aiPrelimText');
  const prelimStatus = document.getElementById('aiPrelimStatus');
  const prelimSpinner= document.getElementById('aiPrelimSpinner');
  const prelimStage  = document.getElementById('aiStagePrelim');
  const deepStage    = document.getElementById('aiStageDeep');
  const deepStatus   = document.getElementById('aiDeepStatus');
  const deepTimer    = document.getElementById('aiDeepTimer');
  const deepBar      = document.getElementById('aiDeepBar');
  const deepSpinner  = document.getElementById('aiDeepSpinner');

  let deepStartedAt = null;
  let etaSeconds    = 300;
  let clientTimerId = null;

  function startClientTimer() {
    if (clientTimerId) clearInterval(clientTimerId);
    clientTimerId = setInterval(() => {
      if (!deepStartedAt) return;
      const elapsed = (Date.now() - deepStartedAt) / 1000;
      const fmt = _fmtTime(elapsed);
      deepTimer.textContent = fmt;
      const prelimTimer = document.getElementById('aiPrelimDeepTimer');
      if (prelimTimer) prelimTimer.textContent = fmt;
      const pct = Math.min(95, (elapsed / etaSeconds) * 100);
      deepBar.style.width = pct.toFixed(1) + '%';
    }, 500);
  }
  function stopClientTimer() {
    if (clientTimerId) { clearInterval(clientTimerId); clientTimerId = null; }
  }

  const es = new EventSource(url);
  let gotFinal = false;

  es.addEventListener('cached', () => {
    // Cache-Hit — Stages überspringen
    prelimStage.classList.add('ai-stage-done');
    prelimStatus.textContent = '✓';
  });

  es.addEventListener('prelim_start', () => {
    prelimStatus.textContent = 'läuft…';
  });

  es.addEventListener('prelim', (ev) => {
    try {
      const d = JSON.parse(ev.data);
      if (d.delta) prelimText.textContent += d.delta;
    } catch {}
  });

  es.addEventListener('prelim_error', (ev) => {
    try {
      const d = JSON.parse(ev.data);
      prelimText.textContent += `\n[Quick-Impression übersprungen: ${d.error}]`;
    } catch {}
  });

  es.addEventListener('prelim_done', () => {
    // Preliminary fertig — sofort als sichtbares "Erst-Gutachten" rendern,
    // Deep läuft parallel im Hintergrund weiter.
    prelimStage.classList.remove('ai-stage-active');
    prelimStage.classList.add('ai-stage-done');
    prelimSpinner.classList.add('ai-spinner-paused');
    prelimStatus.textContent = '✓';
    _renderPreliminaryAsResult(prelimText.textContent);
  });

  es.addEventListener('deep_start', (ev) => {
    try {
      const d = JSON.parse(ev.data);
      if (d.eta_seconds) etaSeconds = d.eta_seconds;
    } catch {}
    deepStartedAt = Date.now();
    startClientTimer();
  });

  es.addEventListener('deep_tick', (ev) => {
    // Server-Heartbeat — wir nutzen eigenen Client-Timer, aber setzen
    // den Balken hiernach nochmal sauber (falls Tab im Hintergrund).
    try {
      const d = JSON.parse(ev.data);
      if (typeof d.elapsed_seconds === 'number' && deepStartedAt == null) {
        deepStartedAt = Date.now() - d.elapsed_seconds * 1000;
        startClientTimer();
      }
    } catch {}
  });

  es.addEventListener('cache_error', (ev) => {
    console.warn('Cache-Fehler (Review wird trotzdem angezeigt):', ev.data);
  });

  es.addEventListener('final', (ev) => {
    gotFinal = true;
    stopClientTimer();
    es.close();
    try {
      const review = JSON.parse(ev.data);
      if (review.error && !review.available) {
        loading.style.display = 'none';
        _removePreliminaryResult();
        const errDiv = document.createElement('div');
        errDiv.className = 'alert alert-error';
        errDiv.style.marginTop = '8px';
        errDiv.textContent = '⚠ KI-Fehler: ' + review.error;
        panel.appendChild(errDiv);
        return;
      }
      // Preliminary entfernen, Final-Review rendern
      _removePreliminaryResult();
      loading.style.display = 'none';
      _lastAiReviewLang = lang;
      _renderAiReview(review);
    } catch (e) {
      loading.style.display = 'none';
      const errDiv = document.createElement('div');
      errDiv.className = 'alert alert-error';
      errDiv.style.marginTop = '8px';
      errDiv.textContent = '⚠ Parse-Fehler: ' + e.message;
      panel.appendChild(errDiv);
    }
  });

  es.onerror = () => {
    if (gotFinal) return; // normaler Close nach Final
    // Wenn Preliminary schon gerendert ist: Tiefenanalyse läuft serverseitig
    // als Background-Task weiter und wird beim nächsten Öffnen aus dem Cache
    // ausgeliefert. Nur Status aktualisieren, keine Fehlermeldung.
    const prelimBox = document.getElementById('aiPrelimResult');
    if (prelimBox) {
      stopClientTimer();
      es.close();
      const status = document.getElementById('aiPrelimDeepStatus');
      if (status) status.textContent = '↻ Tiefenanalyse läuft serverseitig weiter — Seite später erneut öffnen.';
      return;
    }
    stopClientTimer();
    es.close();
    loading.style.display = 'none';
    const errDiv = document.createElement('div');
    errDiv.className = 'alert alert-error';
    errDiv.style.marginTop = '8px';
    errDiv.textContent = '⚠ KI-Verbindung unterbrochen. Läuft der Tunnel?';
    panel.appendChild(errDiv);
  };
}

// Gecachtes KI-Review beim Laden einer Analyse sofort anzeigen
async function _loadCachedAiReview(analysisId) {
  if (!analysisId) return;
  const lang = (typeof getLang === 'function') ? getLang() : 'de';
  try {
    const res = await fetch(`/ai-review/${analysisId}?lang=${lang}`, { method: 'GET' });
    if (res.status === 404) {
      // Kein Cache -> sofort generieren (Auto-Run)
      console.log('[AI-Review] Kein Cache, starte Auto-Generierung...');
      if (typeof requestAiReview === 'function') {
        await requestAiReview();
      }
      return;
    }
    if (!res.ok) return;
    const review = await res.json();
    const panel = document.getElementById('aiReviewPanel');
    if (!panel) return;
    panel.style.display = 'block';
    _lastAiReviewLang = lang;
    _renderAiReview(review);
  } catch (e) {
    // Kein gecachtes Review — kein Problem, Panel bleibt verborgen
  }
}

// Wird von setLang() aufgerufen wenn Sprache wechselt und KI-Panel sichtbar ist
async function refreshAiReviewIfVisible() {
  const panel = document.getElementById('aiReviewPanel');
  if (!panel || panel.style.display === 'none') return;
  if (!currentAnalysisId) return;
  const currentLang = (typeof getLang === 'function') ? getLang() : 'de';
  if (_lastAiReviewLang === currentLang) return; // Sprache hat sich nicht geändert
  await requestAiReview();
}

// Schweregrad-Badge erzeugen
function _severityBadge(level) {
  var cls = 'ai-severity-low';
  if (level === 'HOCH' || level === 'HIGH') cls = 'ai-severity-high';
  else if (level === 'MITTEL' || level === 'MEDIUM') cls = 'ai-severity-medium';
  else if (level === 'NIEDRIG' || level === 'LOW') cls = 'ai-severity-low';
  return '<span class="ai-severity-badge ' + cls + '">' + (level || '—') + '</span>';
}

// Defensive Liste-Helper: LLM-Output kann pro Feld Array ODER Object ODER String sein.
// Liefert immer ein Array zum sicheren forEach.
function _aiArr(x) {
  if (Array.isArray(x)) return x;
  if (x == null) return [];
  if (typeof x === 'object') {
    // Dict -> values als Array (z.B. {"1": "Empfehlung A", "2": "B"})
    try { return Object.values(x); } catch (e) { return []; }
  }
  if (typeof x === 'string') return [x];
  return [];
}

function _renderAiReview(r) {
  var loading = document.getElementById('aiReviewLoading');
  var content = document.getElementById('aiReviewContent');

  // Guard: panel elements must exist
  if (!loading || !content) return;

  // Verdict badge
  var verdictEl = document.getElementById('aiVerdict');
  if (!verdictEl) return;
  var verdictMap = {
    'ECHT':       ['verdict-echt',        'ECHT'],
    'GENUINE':    ['verdict-echt',        'GENUINE'],
    'VERDÄCHTIG': ['verdict-verdaechtig', 'VERDÄCHTIG'],
    'SUSPICIOUS': ['verdict-verdaechtig', 'SUSPICIOUS'],
    'GEFÄLSCHT':  ['verdict-gefaelscht',  'GEFÄLSCHT'],
    'FORGED':     ['verdict-gefaelscht',  'FORGED'],
    'UNBEKANNT':  ['verdict-unbekannt',   'UNBEKANNT'],
    'UNKNOWN':    ['verdict-unbekannt',   'UNKNOWN'],
  };
  var match = verdictMap[r.verdict] || ['verdict-unbekannt', r.verdict || '—'];
  verdictEl.className = 'ai-verdict-badge ' + match[0];
  verdictEl.textContent = match[1];

  function _setText(id, val) { var el = document.getElementById(id); if (el) el.textContent = val; }
  function _setHtml(id, val) { var el = document.getElementById(id); if (el) el.innerHTML = val; }
  function _getEl(id) { return document.getElementById(id); }

  _setText('aiConfidence', (r.confidence != null ? r.confidence : '—') + '%');
  _setText('aiLegitScore', (r.legitimitaets_score != null ? r.legitimitaets_score : '—') + '%');

  // Laien-Box prominent anzeigen
  var laienBox = document.getElementById('aiLaienBox');
  var laienText = document.getElementById('aiLaienText');
  if (laienBox && laienText) {
    if (r.laien_erklaerung) {
      laienText.textContent = r.laien_erklaerung;
      laienBox.style.display = 'block';
      // Farbe je nach Verdict
      var verdictColors = { 'ECHT':'#22c55e','GENUINE':'#22c55e','VERDÄCHTIG':'#f59e0b','SUSPICIOUS':'#f59e0b','GEFÄLSCHT':'#ef4444','FORGED':'#ef4444' };
      var vColor = verdictColors[r.verdict] || '#64748b';
      laienBox.style.borderLeftColor = vColor;
    } else {
      laienBox.style.display = 'none';
    }
  }

  // Verhaltensempfehlung Box
  var verhBox = document.getElementById('aiVerhaltensBox');
  var verhText = document.getElementById('aiVerhaltensBox2');
  if (verhBox && verhText) {
    if (r.verhaltensempfehlung) {
      verhText.textContent = r.verhaltensempfehlung;
      verhBox.style.display = 'block';
    } else {
      verhBox.style.display = 'none';
    }
  }

  _setText('aiZusammenfassung', r.zusammenfassung || '—');

  // Neue Textfelder
  _setText('aiWasGefunden', r.was_wurde_gefunden || '—');
  _setText('aiWasErkennen', r.was_laesst_sich_erkennen || '—');
  _setText('aiWasSchliessen', r.was_laesst_sich_schliessen || '—');
  _setText('aiVerhaltensempfehlung', r.verhaltensempfehlung || '—');

  // Hauptbefunde (jetzt mit Schweregrad)
  var hbEl = _getEl('aiHauptbefunde');
  if (hbEl) {
    hbEl.innerHTML = '';
    var hbItems = _aiArr(r.hauptbefunde);
    hbItems.forEach(function(item) {
      var div = document.createElement('div');
      div.className = 'ai-befund-item';
      if (typeof item === 'string') {
        div.innerHTML = '<div class="ai-befund-text">' + _esc(item) + '</div>';
      } else {
        div.innerHTML =
          '<div class="ai-befund-head">' + _severityBadge(item.schweregrad) + ' <strong>' + _esc(item.befund) + '</strong></div>' +
          '<div class="ai-befund-bedeutung">' + _esc(item.bedeutung) + '</div>';
      }
      hbEl.appendChild(div);
    });
  }

  // Manipulationshinweise
  var manipSection = _getEl('aiManipulationSection');
  var manipItems = _aiArr(r.manipulation_hinweise);
  if (manipItems.length > 0) {
    var manipEl = _getEl('aiManipulation');
    if (manipEl) {
      manipEl.innerHTML = '';
      manipItems.forEach(function(item) {
        var div = document.createElement('div');
        div.className = 'ai-befund-item ai-befund-warn';
        if (typeof item === 'string') {
          div.innerHTML = '<div class="ai-befund-text">' + _esc(item) + '</div>';
        } else {
          div.innerHTML =
            '<div class="ai-befund-head">' + _severityBadge(item.schweregrad) + ' <strong>' + _esc(item.hinweis) + '</strong></div>' +
            '<div class="ai-befund-bedeutung">' + _esc(item.erklaerung) + '</div>';
        }
        manipEl.appendChild(div);
      });
    }
    if (manipSection) manipSection.style.display = 'block';
  } else {
    if (manipSection) manipSection.style.display = 'none';
  }

  // Dokumenteninhalt-Bewertung
  var dokBew = r.dokument_inhalt_bewertung;
  var dokEl = _getEl('aiDokumentBewertung');
  if (dokEl) {
    dokEl.innerHTML = '';
    if (dokBew && typeof dokBew === 'object') {
      var html = '<div class="ai-dok-grid">';
      if (dokBew.dokumenttyp_vermutung) html += '<div class="ai-dok-row"><span class="ai-dok-label">Dokumenttyp:</span> ' + _esc(dokBew.dokumenttyp_vermutung) + '</div>';
      if (dokBew.inhalt_plausibilitaet) html += '<div class="ai-dok-row"><span class="ai-dok-label">Inhalt-Plausibilit\u00E4t:</span> ' + _esc(dokBew.inhalt_plausibilitaet) + '</div>';
      if (dokBew.autor_bewertung) html += '<div class="ai-dok-row"><span class="ai-dok-label">Autor:</span> ' + _esc(dokBew.autor_bewertung) + '</div>';
      if (dokBew.software_bewertung) html += '<div class="ai-dok-row"><span class="ai-dok-label">Software:</span> ' + _esc(dokBew.software_bewertung) + '</div>';
      if (dokBew.zeitstempel_bewertung) html += '<div class="ai-dok-row"><span class="ai-dok-label">Zeitstempel:</span> ' + _esc(dokBew.zeitstempel_bewertung) + '</div>';
      if (dokBew.auffaelligkeiten && dokBew.auffaelligkeiten.length > 0) {
        html += '<div class="ai-dok-row"><span class="ai-dok-label">Auff\u00E4lligkeiten:</span><ul class="ai-list">';
        dokBew.auffaelligkeiten.forEach(function(a) { html += '<li>' + _esc(a) + '</li>'; });
        html += '</ul></div>';
      }
      html += '</div>';
      dokEl.innerHTML = html;
    } else {
      dokEl.innerHTML = '<span class="ai-text">—</span>';
    }
  }

  // Weitere Tests
  var testsEl = _getEl('aiWeitereTests');
  if (testsEl) {
    var tests = _aiArr(r.weitere_tests);
    testsEl.innerHTML = '';
    if (tests.length > 0) {
      tests.forEach(function(t) {
        var div = document.createElement('div');
        div.className = 'ai-test-item';
        if (typeof t === 'string') {
          div.innerHTML = '<div class="ai-befund-text">' + _esc(t) + '</div>';
        } else {
          div.innerHTML =
            '<div class="ai-befund-head">' + _severityBadge(t.prioritaet) + ' <strong>' + _esc(t.test) + '</strong></div>' +
            '<div class="ai-befund-bedeutung">' + _esc(t.grund) + '</div>';
        }
        testsEl.appendChild(div);
      });
    } else {
      testsEl.innerHTML = '<span class="ai-text">Keine weiteren Tests vorgeschlagen</span>';
    }
  }

  // Erweiterungsvorschl\u00E4ge
  var erwEl = _getEl('aiErweiterungen');
  if (erwEl) {
    var erw = r.erweiterungsvorschlaege || [];
    erwEl.innerHTML = '';
    if (erw.length > 0) {
      erw.forEach(function(e) {
        var div = document.createElement('div');
        div.className = 'ai-test-item';
        if (typeof e === 'string') {
          div.innerHTML = '<div class="ai-befund-text">' + _esc(e) + '</div>';
        } else {
          div.innerHTML =
            '<div class="ai-befund-head"><strong>' + _esc(e.vorschlag) + '</strong></div>' +
            '<div class="ai-befund-bedeutung">' + _esc(e.beschreibung) + '</div>';
        }
        erwEl.appendChild(div);
      });
    } else {
      erwEl.innerHTML = '<span class="ai-text">—</span>';
    }
  }

  // Empfehlungen (einfache Liste)
  var empUl = _getEl('aiEmpfehlungen');
  if (empUl) {
    empUl.innerHTML = '';
    _aiArr(r.empfehlungen).forEach(function(item) {
      var li = document.createElement('li');
      li.textContent = typeof item === 'string' ? item : (item.empfehlung || JSON.stringify(item));
      empUl.appendChild(li);
    });
  }

  // Risikoerkl\u00E4rung, Technische Details, Fazit
  _setText('aiRisikoErklaerung', r.risiko_erklaerung || '—');
  _setText('aiTechnisch',        r.technische_details || '—');
  _setText('aiFazit',            r.fazit || '—');
  _setText('aiModelName',        r.model || 'DeepSeek V3');

  loading.style.display = 'none';
  content.style.display = 'block';

  // Smooth scroll zum Content
  content.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// HTML-Escaping Hilfsfunktion
function _esc(str) {
  if (!str) return '—';
  var div = document.createElement('div');
  div.textContent = String(str);
  return div.innerHTML;
}
