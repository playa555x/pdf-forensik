/**
 * history.js — Verlauf-Seite: Laden, Suche, Rendering
 */

document.addEventListener('DOMContentLoaded', () => {
  loadHistory();

  document.getElementById('btnSearch').addEventListener('click', performSearch);
  document.getElementById('btnReset').addEventListener('click', () => {
    document.getElementById('searchQuery').value = '';
    document.getElementById('dateFrom').value = '';
    document.getElementById('dateTo').value = '';
    loadHistory();
  });

  document.getElementById('searchQuery').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') performSearch();
  });
});

async function loadHistory() {
  showLoading();
  try {
    const resp = await fetch('/history/search');
    const data = await resp.json();
    renderHistoryList(data.analyses || []);
  } catch (err) {
    showError(t('hist_load_error') + ': ' + err.message);
  }
}

async function performSearch() {
  const q        = document.getElementById('searchQuery').value.trim();
  const dateFrom = document.getElementById('dateFrom').value;
  const dateTo   = document.getElementById('dateTo').value;

  const params = new URLSearchParams();
  if (q)        params.set('q', q);
  if (dateFrom) params.set('date_from', dateFrom);
  if (dateTo)   params.set('date_to',   dateTo);

  showLoading();
  try {
    const resp = await fetch('/history/search?' + params.toString());
    const data = await resp.json();
    renderHistoryList(data.analyses || []);
  } catch (err) {
    showError(t('hist_search_error') + ': ' + err.message);
  }
}

function showLoading() {
  document.getElementById('historyList').innerHTML = `
    <div class="loading-spinner">
      <div class="spinner"></div>
      <span>${t('loading')}</span>
    </div>`;
  document.getElementById('historyStats').style.display = 'none';
}

function showError(msg) {
  document.getElementById('historyList').innerHTML = `
    <div class="alert alert-error"><span class="alert-icon"></span>${escapeHtml(msg)}</div>`;
}

function renderHistoryList(analyses) {
  const list  = document.getElementById('historyList');
  const stats = document.getElementById('historyStats');

  stats.style.display = 'block';
  document.getElementById('historyCount').textContent =
    `${analyses.length} ${analyses.length !== 1 ? t('hist_analyses_found_plural') : t('hist_analyses_found_singular')}`;

  if (analyses.length === 0) {
    list.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon"></div>
        <div class="empty-text">${t('hist_empty')}</div>
        <div class="empty-hint">${t('hist_empty_hint')}</div>
      </div>`;
    return;
  }

  list.innerHTML = analyses.map(a => historyItemHtml(a)).join('');

  // Event-Delegation für Buttons
  list.addEventListener('click', handleHistoryClick);
}

function historyItemHtml(a) {
  const high   = a.anomaly_count_high   || 0;
  const medium = a.anomaly_count_medium || 0;
  const low    = a.anomaly_count_low    || 0;

  const riskClass = a.risk_level;
  const sizeStr = formatBytes(a.file_size);
  const dateStr = formatDate(a.analyzed_at);
  const sha256short = (a.sha256 || '').slice(0, 16) + '…';

  return `
    <div class="history-item" data-id="${escapeHtml(a.id)}">
      <div class="history-risk risk-badge ${riskClass}">${a.risk_level}</div>
      <div class="history-info">
        <div class="history-filename">${escapeHtml(a.filename)}</div>
        <div class="history-meta">${sizeStr} · ${dateStr} · SHA256: ${sha256short}</div>
      </div>
      <div class="history-anomalies">
        ${high   ? `<span class="anomaly-severity severity-HIGH">${high}×H</span>` : ''}
        ${medium ? `<span class="anomaly-severity severity-MEDIUM">${medium}×M</span>` : ''}
        ${low    ? `<span class="anomaly-severity severity-LOW">${low}×L</span>` : ''}
      </div>
      <div class="history-actions">
        <button class="btn btn-secondary btn-sm" data-action="report" data-id="${escapeHtml(a.id)}"
                title="${t('hist_download_report')}"></button>
        <button class="btn btn-ghost btn-sm" data-action="compare" data-id="${escapeHtml(a.id)}"
                data-filename="${escapeHtml(a.filename)}" title="${t('btn_add_compare')}"></button>
        <button class="btn btn-danger btn-sm" data-action="delete" data-id="${escapeHtml(a.id)}"
                title="${t('hist_delete')}"></button>
      </div>
    </div>`;
}

function handleHistoryClick(e) {
  const btn = e.target.closest('[data-action]');
  if (!btn) {
    // Klick auf history-item → Details öffnen
    const item = e.target.closest('.history-item');
    if (item && !e.target.closest('.history-actions')) {
      const id = item.dataset.id;
      window.location.href = `/?analysis_id=${id}`;
    }
    return;
  }

  e.stopPropagation();
  const action = btn.dataset.action;
  const id     = btn.dataset.id;

  if (action === 'report') {
    window.open(`/report/${id}`, '_blank');
  } else if (action === 'compare') {
    const ids = JSON.parse(localStorage.getItem('compareIds') || '[]');
    if (!ids.includes(id)) {
      if (ids.length >= 4) ids.shift();
      ids.push(id);
      localStorage.setItem('compareIds', JSON.stringify(ids));
    }
    window.location.href = '/compare';
  } else if (action === 'delete') {
    if (!confirm(`${t('hist_confirm_del_prefix')} "${btn.dataset.filename || id}"?`)) return;
    deleteAnalysis(id);
  }
}

async function deleteAnalysis(id) {
  try {
    const resp = await fetch(`/analysis/${id}`, { method: 'DELETE' });
    if (!resp.ok) {
      const data = await resp.json();
      throw new Error(data.detail || `HTTP ${resp.status}`);
    }
    // Item aus DOM entfernen
    const item = document.querySelector(`.history-item[data-id="${id}"]`);
    if (item) {
      item.style.opacity = '0';
      item.style.transition = 'opacity 0.3s';
      setTimeout(() => item.remove(), 300);
    }
  } catch (err) {
    alert(t('hist_delete_error') + ': ' + err.message);
  }
}
