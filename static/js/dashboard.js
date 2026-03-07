/**
 * dashboard.js — Orchestriert das Single-Page Dashboard:
 *   - Sidebar-Toggle (collapse/expand)
 *   - Tab-Switching (Verlauf | Vergleich)
 *   - Sidebar-History laden + Klick-Handler
 *   - Compare-Slots (portiert aus compare.js für Sidebar)
 *   - "Zum Vergleich" Button in results.js überschreiben
 */

// ===== Sidebar Toggle =====

const STORAGE_KEY_COLLAPSED = 'pdf_sidebar_collapsed';

function initSidebarToggle() {
  const wrap   = document.getElementById('dashboardWrap');
  const toggle = document.getElementById('sidebarToggle');
  if (!wrap || !toggle) return;

  // Button sichtbar machen (nur auf Index-Seite)
  toggle.style.display = '';

  // State aus localStorage wiederherstellen
  if (localStorage.getItem(STORAGE_KEY_COLLAPSED) === '1') {
    wrap.classList.add('sidebar-collapsed');
    toggle.textContent = '▶';
  }

  toggle.addEventListener('click', () => {
    const collapsed = wrap.classList.toggle('sidebar-collapsed');
    toggle.textContent = collapsed ? '▶' : '◀';
    localStorage.setItem(STORAGE_KEY_COLLAPSED, collapsed ? '1' : '0');
  });
}

// ===== Tab Switching =====

function initTabs() {
  const tabs = document.querySelectorAll('.sidebar-tab');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const target = tab.dataset.tab;
      tabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');

      document.querySelectorAll('.sidebar-panel').forEach(p => p.classList.remove('active'));
      const panel = document.getElementById('panel' + capitalize(target));
      if (panel) panel.classList.add('active');
    });
  });
}

function capitalize(s) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

// ===== Sidebar History =====

let allSidebarItems = [];
let activeAnalysisId = null;
let searchDebounceTimer = null;

async function loadSidebarHistory(query) {
  const list = document.getElementById('sidebarHistoryList');
  if (!list) return;

  const params = new URLSearchParams({ limit: 100 });
  if (query) params.set('q', query);

  try {
    const resp = await fetch('/history/search?' + params.toString());
    const data = await resp.json();
    allSidebarItems = data.analyses || [];
    renderSidebarHistory(allSidebarItems);
  } catch (err) {
    list.innerHTML = `<div class="alert alert-error" style="font-size:0.8rem">${escapeHtml(err.message)}</div>`;
  }
}

function renderSidebarHistory(analyses) {
  const list = document.getElementById('sidebarHistoryList');
  if (!list) return;

  if (!analyses.length) {
    list.innerHTML = `<div class="empty-state" style="padding:20px">
      <div class="empty-icon" style="font-size:2rem"></div>
      <div class="empty-text" style="font-size:0.85rem">${t('hist_empty')}</div>
    </div>`;
    return;
  }

  list.innerHTML = analyses.map(a => sidebarHistoryItemHtml(a)).join('');

  list.querySelectorAll('.sidebar-history-item').forEach(el => {
    el.addEventListener('click', (e) => {
      if (e.target.closest('.sidebar-history-actions')) return;
      loadAnalysisIntoLeft(el.dataset.id);
    });
  });

  list.querySelectorAll('[data-sidebar-action]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const action = btn.dataset.sidebarAction;
      const id     = btn.dataset.id;
      if (action === 'report') {
        window.open(`/report/${id}`, '_blank');
      } else if (action === 'compare') {
        addToCompareSlot(id, btn.dataset.filename);
        // Tab wechseln
        document.querySelectorAll('.sidebar-tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.sidebar-panel').forEach(p => p.classList.remove('active'));
        const compareTab   = document.querySelector('[data-tab="compare"]');
        const comparePanel = document.getElementById('panelCompare');
        if (compareTab)   compareTab.classList.add('active');
        if (comparePanel) comparePanel.classList.add('active');
      } else if (action === 'delete') {
        const item = analyses.find(a => a.id === id);
        const name = item ? item.filename : id;
        if (!confirm(`${t('hist_confirm_del_prefix')} "${name}"?`)) return;
        deleteSidebarAnalysis(id);
      }
    });
  });

  // Active-Highlighting
  if (activeAnalysisId) markActiveItem(activeAnalysisId);
}

function sidebarHistoryItemHtml(a) {
  const riskClass = a.risk_level;
  const dateStr   = formatDate(a.analyzed_at);
  const high      = a.anomaly_count_high || 0;

  return `
    <div class="sidebar-history-item" data-id="${escapeHtml(a.id)}">
      <span class="risk-badge ${riskClass}" style="font-size:0.62rem;padding:2px 6px;flex-shrink:0">${a.risk_level}</span>
      <div style="flex:1;min-width:0">
        <div class="sidebar-history-filename">${escapeHtml(a.filename)}</div>
        <div class="sidebar-history-meta">${dateStr}${high ? ` · <span style="color:var(--high)">${high}×H</span>` : ''}</div>
      </div>
      <div class="sidebar-history-actions">
        <button data-sidebar-action="report" data-id="${escapeHtml(a.id)}" title="${t('hist_download_report')}"></button>
        <button data-sidebar-action="compare" data-id="${escapeHtml(a.id)}" data-filename="${escapeHtml(a.filename)}" title="${t('btn_add_compare')}"></button>
        <button data-sidebar-action="delete" data-id="${escapeHtml(a.id)}" title="${t('hist_delete')}"></button>
      </div>
    </div>`;
}

function markActiveItem(id) {
  document.querySelectorAll('.sidebar-history-item').forEach(el => {
    el.classList.toggle('active-analysis', el.dataset.id === id);
  });
}

async function loadAnalysisIntoLeft(id) {
  const uploadZone = document.getElementById('uploadZone');
  const progressContainer = document.getElementById('progressContainer');
  const progressLabel = document.getElementById('progressLabel');
  const progressFill = document.getElementById('progressFill');
  const errorAlert = document.getElementById('errorAlert');
  const resultContainer = document.getElementById('resultContainer');

  if (uploadZone)    uploadZone.style.display = 'none';
  if (progressContainer) {
    progressContainer.style.display = 'block';
    if (progressLabel) progressLabel.textContent = t('loading_saved_analysis');
    if (progressFill)  progressFill.style.width = '60%';
  }
  if (errorAlert) errorAlert.style.display = 'none';
  if (resultContainer) resultContainer.style.display = 'none';

  try {
    const resp = await fetch(`/analysis/${id}`);
    if (!resp.ok) throw new Error(t('analysis_not_found'));
    const data = await resp.json();

    if (progressContainer) progressContainer.style.display = 'none';
    if (uploadZone) uploadZone.style.display = 'flex';

    if (typeof renderResult === 'function') {
      renderResult(data);
    }

    activeAnalysisId = id;
    markActiveItem(id);

    // URL aktualisieren ohne Seitenwechsel
    history.replaceState(null, '', `/?analysis_id=${id}`);

    // Scroll zur Analyse
    if (resultContainer) {
      resultContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  } catch (err) {
    if (progressContainer) progressContainer.style.display = 'none';
    if (uploadZone) uploadZone.style.display = 'flex';
    if (errorAlert) {
      document.getElementById('errorMessage').textContent = err.message;
      errorAlert.style.display = 'flex';
    }
  }
}

async function deleteSidebarAnalysis(id) {
  try {
    const resp = await fetch(`/analysis/${id}`, { method: 'DELETE' });
    if (!resp.ok) {
      const data = await resp.json();
      throw new Error(data.detail || `HTTP ${resp.status}`);
    }
    // Aus DOM entfernen
    const item = document.querySelector(`.sidebar-history-item[data-id="${id}"]`);
    if (item) {
      item.style.opacity = '0';
      item.style.transition = 'opacity 0.3s';
      setTimeout(() => {
        item.remove();
        allSidebarItems = allSidebarItems.filter(a => a.id !== id);
      }, 300);
    }
    if (activeAnalysisId === id) {
      activeAnalysisId = null;
      document.getElementById('resultContainer').style.display = 'none';
      document.getElementById('uploadZone').style.display = 'flex';
      history.replaceState(null, '', '/');
    }
  } catch (err) {
    alert(t('hist_delete_error') + ': ' + err.message);
  }
}

function initSidebarSearch() {
  const input = document.getElementById('sidebarSearch');
  if (!input) return;
  input.addEventListener('input', (e) => {
    clearTimeout(searchDebounceTimer);
    searchDebounceTimer = setTimeout(() => {
      loadSidebarHistory(e.target.value.trim());
    }, 280);
  });
}

// ===== "Zum Vergleich" überschreiben =====
// results.js setzt btnAddToCompare auf window.location.href='/compare'
// Wir überschreiben das nach renderResult um direkt in den Compare-Tab zu wechseln.

function patchAddToCompareButton() {
  const btn = document.getElementById('btnAddToCompare');
  if (!btn) return;
  btn.onclick = () => {
    if (!window._currentAnalysisId) return;
    addToCompareSlot(window._currentAnalysisId, window._currentFilename);
    // Tab wechseln
    document.querySelectorAll('.sidebar-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.sidebar-panel').forEach(p => p.classList.remove('active'));
    const compareTab   = document.querySelector('[data-tab="compare"]');
    const comparePanel = document.getElementById('panelCompare');
    if (compareTab)   compareTab.classList.add('active');
    if (comparePanel) comparePanel.classList.add('active');
  };
}

// ===== renderResult Wrapper =====
// Wird synchron beim Script-Parse ausgeführt (nach results.js geladen).
// So ist renderResult bereits gepatcht wenn results.js DOMContentLoaded feuert.
(function() {
  const orig = window.renderResult;
  if (typeof orig !== 'function') return;
  window.renderResult = function(data) {
    orig(data);
    window._currentAnalysisId = data.analysis_id;
    window._currentFilename   = data.filename;
    activeAnalysisId = data.analysis_id;
    // History neu laden (zeigt neuen Eintrag & markiert aktives Item)
    loadSidebarHistory(document.getElementById('sidebarSearch')?.value || '');
    patchAddToCompareButton();
  };
})();

// ===== Compare (Sidebar) =====

const MAX_SLOTS = 4;
let compareSlots = [null, null];
let currentPickerSlot = null;
let currentComparisonId = null;
let allPickerItems = [];

function addToCompareSlot(id, filename) {
  // Prüfen ob bereits vorhanden
  const existing = compareSlots.findIndex(s => s && s.analysis_id === id);
  if (existing >= 0) return;

  // Freien Slot finden oder ans Ende
  const freeIdx = compareSlots.findIndex(s => !s);
  if (freeIdx >= 0) {
    compareSlots[freeIdx] = { analysis_id: id, filename: filename || id, risk_level: '…', anomaly_count_high: 0 };
    loadCompareSlotInfo(id, freeIdx);
  } else if (compareSlots.length < MAX_SLOTS) {
    compareSlots.push({ analysis_id: id, filename: filename || id, risk_level: '…', anomaly_count_high: 0 });
    loadCompareSlotInfo(id, compareSlots.length - 1);
  }
  renderCompareSlots();
}

async function loadCompareSlotInfo(id, index) {
  try {
    const resp = await fetch(`/analysis/${id}`);
    if (!resp.ok) { compareSlots[index] = null; renderCompareSlots(); return; }
    const data = await resp.json();
    compareSlots[index] = {
      analysis_id: data.analysis_id,
      filename: data.filename,
      risk_level: data.risk_level,
      anomaly_count_high: data.anomaly_count_high,
    };
    renderCompareSlots();
  } catch {
    compareSlots[index] = null;
    renderCompareSlots();
  }
}

function renderCompareSlots() {
  const container = document.getElementById('compareSlots');
  const btnAdd    = document.getElementById('btnAddSlot');
  const btnRun    = document.getElementById('btnRunCompare');
  if (!container) return;

  container.innerHTML = compareSlots.map((slot, i) => compareSlotHtml(slot, i)).join('');

  container.querySelectorAll('.compare-slot').forEach(el => {
    const idx = parseInt(el.dataset.index);
    if (!compareSlots[idx]) {
      el.addEventListener('click', () => openComparePicker(idx));
    }
  });

  container.querySelectorAll('.slot-remove').forEach(el => {
    el.addEventListener('click', (e) => {
      e.stopPropagation();
      removeCompareSlot(parseInt(el.dataset.index));
    });
  });

  const filledCount = compareSlots.filter(Boolean).length;
  if (btnAdd) btnAdd.style.display = compareSlots.length < MAX_SLOTS ? 'inline-flex' : 'none';
  if (btnRun) btnRun.disabled = filledCount < 2;
}

function compareSlotHtml(slot, index) {
  if (!slot) {
    return `<div class="compare-slot" data-index="${index}">
      <div class="slot-icon"></div>
      <div class="slot-label">${t('cmp_select').replace('{n}', index + 1)}</div>
    </div>`;
  }
  return `<div class="compare-slot filled" data-index="${index}">
    <div class="slot-icon"></div>
    <div class="slot-filename">${escapeHtml(slot.filename)}</div>
    <div class="slot-risk risk-badge ${slot.risk_level}">${slot.risk_level}</div>
    ${slot.anomaly_count_high ? `<div class="text-high" style="font-size:0.72rem">${slot.anomaly_count_high}× HIGH</div>` : ''}
    <div class="slot-remove" data-index="${index}">${t('hist_delete')}</div>
  </div>`;
}

function removeCompareSlot(index) {
  compareSlots[index] = null;
  while (compareSlots.length > 2 && !compareSlots[compareSlots.length - 1]) {
    compareSlots.pop();
  }
  renderCompareSlots();
}

async function openComparePicker(slotIndex) {
  currentPickerSlot = slotIndex;
  const modal = document.getElementById('pickerModal');
  const pickerSearch = document.getElementById('pickerSearch');
  if (!modal) return;
  modal.style.display = 'flex';
  if (pickerSearch) pickerSearch.value = '';

  const list = document.getElementById('pickerList');
  list.innerHTML = '<div class="loading-spinner"><div class="spinner"></div></div>';

  try {
    const resp = await fetch('/history/search?limit=200');
    const data = await resp.json();
    allPickerItems = data.analyses || [];
    renderPickerItems(allPickerItems);
  } catch {
    list.innerHTML = `<div class="alert alert-error">${t('hist_load_error')}</div>`;
  }
}

function renderPickerItems(items) {
  const list = document.getElementById('pickerList');
  if (!list) return;

  if (!items.length) {
    list.innerHTML = `<div class="empty-state"><div class="empty-icon"></div><div class="empty-text">${t('cmp_no_analyses')}</div></div>`;
    return;
  }

  const usedIds = compareSlots.filter(Boolean).map(s => s.analysis_id);

  list.innerHTML = items.map(a => {
    const used = usedIds.includes(a.id);
    return `<div class="picker-item${used ? ' text-muted' : ''}" data-id="${escapeHtml(a.id)}"
         data-filename="${escapeHtml(a.filename)}" data-risk="${a.risk_level}"
         data-high="${a.anomaly_count_high || 0}"
         ${used ? 'style="opacity:0.4;pointer-events:none"' : ''}>
      <span class="risk-badge ${a.risk_level}" style="font-size:0.65rem;padding:2px 6px">${a.risk_level}</span>
      <div style="flex:1;min-width:0">
        <div style="font-size:0.85rem;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${escapeHtml(a.filename)}</div>
        <div style="font-size:0.75rem;color:var(--muted)">${formatDate(a.analyzed_at)} · ${formatBytes(a.file_size)}</div>
      </div>
      ${a.anomaly_count_high ? `<span class="anomaly-severity severity-HIGH">${a.anomaly_count_high}×H</span>` : ''}
    </div>`;
  }).join('');

  list.querySelectorAll('.picker-item:not([style*="pointer-events:none"])').forEach(el => {
    el.addEventListener('click', () => {
      compareSlots[currentPickerSlot] = {
        analysis_id: el.dataset.id,
        filename:    el.dataset.filename,
        risk_level:  el.dataset.risk,
        anomaly_count_high: parseInt(el.dataset.high) || 0,
      };
      closeComparePicker();
      renderCompareSlots();
    });
  });
}

function closeComparePicker() {
  const modal = document.getElementById('pickerModal');
  if (modal) modal.style.display = 'none';
  currentPickerSlot = null;
}

async function runCompare() {
  const ids = compareSlots.filter(Boolean).map(s => s.analysis_id);
  if (ids.length < 2) return;

  const btn = document.getElementById('btnRunCompare');
  if (btn) { btn.disabled = true; btn.textContent = t('cmp_running'); }

  try {
    const resp = await fetch('/compare', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ analysis_ids: ids }),
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.detail || `HTTP ${resp.status}`);

    currentComparisonId = data.comparison_id;
    renderSidebarCompareResult(data);
  } catch (err) {
    alert(t('cmp_failed') + ': ' + err.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = t('cmp_run'); }
    renderCompareSlots(); // re-enable button based on filled count
  }
}

function renderSidebarCompareResult(data) {
  const container = document.getElementById('compareResult');
  if (!container) return;

  container.style.display = 'block';

  // Summary-Tabelle
  const identCount = (data.identical_hashes || []).length;
  const uuidCount  = (data.same_uuid_cluster || []).length;
  const swCount    = (data.same_software || []).length;
  const anomCount  = (data.anomalies || []).filter(a => a.severity !== 'INFO').length;

  let html = `<div class="card" style="margin-bottom:10px">
    <div class="card-header"><h2 style="font-size:0.9rem">${t('cmp_summary')}</h2></div>
    <div class="card-body" style="padding:12px">
      <table class="kv-table" style="font-size:0.82rem">
        <tr><td>${t('cmp_sum_docs')}</td><td>${data.documents.length}</td></tr>
        <tr><td>${t('cmp_sum_hashes')}</td><td>${identCount ? `${identCount}` : t('none_clean')}</td></tr>
        <tr><td>${t('cmp_sum_uuid')}</td><td>${uuidCount ? `${uuidCount}` : t('none_clean')}</td></tr>
        <tr><td>${t('cmp_sum_software')}</td><td>${swCount || '—'}</td></tr>
        <tr><td>${t('cmp_sum_anomalies')}</td><td>${anomCount || '—'}</td></tr>
      </table>
    </div>
  </div>`;

  // Bericht-Button
  html += `<div style="text-align:center;margin-top:8px">
    <button class="btn btn-secondary btn-sm" id="btnSidebarCompareReport" data-i18n="cmp_report_btn">${t('cmp_report_btn')}</button>
  </div>`;

  container.innerHTML = html;

  const reportBtn = document.getElementById('btnSidebarCompareReport');
  if (reportBtn) {
    reportBtn.onclick = () => window.open(`/compare-report/${data.comparison_id}`, '_blank');
  }
}

// ===== Init =====

document.addEventListener('DOMContentLoaded', () => {
  // Main-Content Padding entfernen (Dashboard hat eigenes Padding)
  const mainContent = document.getElementById('mainContent');
  if (mainContent) {
    mainContent.style.maxWidth = 'none';
    mainContent.style.padding = '0';
    mainContent.style.margin = '0';
  }

  initSidebarToggle();
  initTabs();
  initSidebarSearch();
  loadSidebarHistory();
  renderCompareSlots();

  // Compare Buttons
  const btnAddSlot = document.getElementById('btnAddSlot');
  if (btnAddSlot) btnAddSlot.addEventListener('click', () => {
    if (compareSlots.length < MAX_SLOTS) {
      compareSlots.push(null);
      renderCompareSlots();
    }
  });

  const btnRunCompare = document.getElementById('btnRunCompare');
  if (btnRunCompare) btnRunCompare.addEventListener('click', runCompare);

  const btnCloseModal = document.getElementById('btnCloseModal');
  if (btnCloseModal) btnCloseModal.addEventListener('click', closeComparePicker);

  const pickerModal = document.getElementById('pickerModal');
  if (pickerModal) {
    pickerModal.addEventListener('click', (e) => {
      if (e.target === pickerModal) closeComparePicker();
    });
  }

  const pickerSearch = document.getElementById('pickerSearch');
  if (pickerSearch) {
    pickerSearch.addEventListener('input', (e) => {
      const q = e.target.value.toLowerCase();
      const filtered = q
        ? allPickerItems.filter(a => a.filename.toLowerCase().includes(q))
        : allPickerItems;
      renderPickerItems(filtered);
    });
  }

  // localStorage-Slots wiederherstellen (von alter history.js "Zum Vergleich")
  const savedIds = JSON.parse(localStorage.getItem('compareIds') || '[]');
  if (savedIds.length > 0) {
    localStorage.removeItem('compareIds');
    compareSlots = Array(Math.max(savedIds.length, 2)).fill(null);
    savedIds.forEach((id, i) => {
      compareSlots[i] = { analysis_id: id, filename: '…', risk_level: '…', anomaly_count_high: 0 };
      loadCompareSlotInfo(id, i);
    });
    renderCompareSlots();
    // Compare-Tab anzeigen
    document.querySelectorAll('.sidebar-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.sidebar-panel').forEach(p => p.classList.remove('active'));
    const compareTab   = document.querySelector('[data-tab="compare"]');
    const comparePanel = document.getElementById('panelCompare');
    if (compareTab)   compareTab.classList.add('active');
    if (comparePanel) comparePanel.classList.add('active');
  }

  // Analysis-ID aus URL laden
  const params = new URLSearchParams(window.location.search);
  const urlId = params.get('analysis_id');
  if (urlId) {
    activeAnalysisId = urlId;
    // results.js DOMContentLoaded Handler lädt es bereits — nur markieren
    setTimeout(() => markActiveItem(urlId), 800);
  }
});
