/**
 * compare.js — Vergleichs-Seite: Slot-UI, History-Picker, Vergleich starten
 */

const MAX_SLOTS = 4;
let slots = [null, null];  // Start mit 2 Slots
let currentPickerSlot = null;
let currentComparisonId = null;

document.addEventListener('DOMContentLoaded', () => {
  // Slots aus localStorage wiederherstellen (von Analyse-Seite)
  const savedIds = JSON.parse(localStorage.getItem('compareIds') || '[]');
  localStorage.removeItem('compareIds');

  // Slots aufbauen
  if (savedIds.length > 0) {
    slots = Array(Math.max(savedIds.length, 2)).fill(null);
    savedIds.forEach((id, i) => {
      slots[i] = { analysis_id: id, filename: t('loading') || 'Loading…', risk_level: '…' };
    });
    renderSlots();

    // Metadaten nachladen
    savedIds.forEach((id, i) => loadSlotInfo(id, i));
  } else {
    renderSlots();
  }

  document.getElementById('btnAddSlot').addEventListener('click', addSlot);
  document.getElementById('btnRunCompare').addEventListener('click', runCompare);
  document.getElementById('btnCloseModal').addEventListener('click', closeModal);

  document.getElementById('pickerSearch').addEventListener('input', (e) => {
    filterPickerItems(e.target.value);
  });

  document.getElementById('pickerModal').addEventListener('click', (e) => {
    if (e.target === document.getElementById('pickerModal')) closeModal();
  });
});

async function loadSlotInfo(id, index) {
  try {
    const resp = await fetch(`/analysis/${id}`);
    if (!resp.ok) { slots[index] = null; renderSlots(); return; }
    const data = await resp.json();
    slots[index] = {
      analysis_id: data.analysis_id,
      filename: data.filename,
      risk_level: data.risk_level,
      anomaly_count_high: data.anomaly_count_high,
    };
    renderSlots();
  } catch {
    slots[index] = null;
    renderSlots();
  }
}

function renderSlots() {
  const container = document.getElementById('compareSlots');
  const btnAdd    = document.getElementById('btnAddSlot');
  const btnRun    = document.getElementById('btnRunCompare');

  container.innerHTML = slots.map((slot, i) => slotHtml(slot, i)).join('');

  // Klick-Handler
  container.querySelectorAll('.compare-slot').forEach(el => {
    const idx = parseInt(el.dataset.index);
    if (!slots[idx]) {
      el.addEventListener('click', () => openPicker(idx));
    }
  });

  container.querySelectorAll('.slot-remove').forEach(el => {
    el.addEventListener('click', (e) => {
      e.stopPropagation();
      removeSlot(parseInt(el.dataset.index));
    });
  });

  const filledCount = slots.filter(Boolean).length;
  btnAdd.style.display = slots.length < MAX_SLOTS ? 'inline-flex' : 'none';
  btnRun.disabled = filledCount < 2;
}

function slotHtml(slot, index) {
  if (!slot) {
    return `
      <div class="compare-slot" data-index="${index}">
        <div class="slot-icon"></div>
        <div class="slot-label">${t('cmp_select').replace('{n}', index + 1)}</div>
      </div>`;
  }
  return `
    <div class="compare-slot filled" data-index="${index}">
      <div class="slot-icon"></div>
      <div class="slot-filename">${escapeHtml(slot.filename)}</div>
      <div class="slot-risk risk-badge ${slot.risk_level}">${slot.risk_level}</div>
      ${slot.anomaly_count_high ? `<div class="text-high" style="font-size:0.75rem">${slot.anomaly_count_high}× HIGH</div>` : ''}
      <div class="slot-remove" data-index="${index}">${t('hist_delete')}</div>
    </div>`;
}

function addSlot() {
  if (slots.length < MAX_SLOTS) {
    slots.push(null);
    renderSlots();
  }
}

function removeSlot(index) {
  slots[index] = null;
  // Leere Slots am Ende entfernen (mindestens 2 behalten)
  while (slots.length > 2 && !slots[slots.length - 1]) {
    slots.pop();
  }
  renderSlots();
}

// ===== History-Picker =====

let allHistoryItems = [];

async function openPicker(slotIndex) {
  currentPickerSlot = slotIndex;
  document.getElementById('pickerModal').style.display = 'flex';
  document.getElementById('pickerSearch').value = '';

  const list = document.getElementById('pickerList');
  list.innerHTML = '<div class="loading-spinner"><div class="spinner"></div></div>';

  try {
    const resp = await fetch('/history/search?limit=200');
    const data = await resp.json();
    allHistoryItems = data.analyses || [];
    renderPickerItems(allHistoryItems);
  } catch {
    list.innerHTML = `<div class="alert alert-error">${t('hist_load_error')}</div>`;
  }
}

function renderPickerItems(items) {
  const list = document.getElementById('pickerList');

  if (!items.length) {
    list.innerHTML = `<div class="empty-state"><div class="empty-icon"></div><div class="empty-text">${t('cmp_no_analyses')}</div></div>`;
    return;
  }

  // Bereits ausgewählte IDs ausfiltern
  const usedIds = slots.filter(Boolean).map(s => s.analysis_id);

  list.innerHTML = items.map(a => {
    const used = usedIds.includes(a.id);
    return `
      <div class="picker-item${used ? ' text-muted' : ''}" data-id="${escapeHtml(a.id)}"
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
      slots[currentPickerSlot] = {
        analysis_id: el.dataset.id,
        filename:    el.dataset.filename,
        risk_level:  el.dataset.risk,
        anomaly_count_high: parseInt(el.dataset.high) || 0,
      };
      closeModal();
      renderSlots();
    });
  });
}

function filterPickerItems(query) {
  const q = query.toLowerCase();
  const filtered = q
    ? allHistoryItems.filter(a => a.filename.toLowerCase().includes(q))
    : allHistoryItems;
  renderPickerItems(filtered);
}

function closeModal() {
  document.getElementById('pickerModal').style.display = 'none';
  currentPickerSlot = null;
}

// ===== Vergleich ausführen =====

async function runCompare() {
  const ids = slots.filter(Boolean).map(s => s.analysis_id);
  if (ids.length < 2) return;

  const btn = document.getElementById('btnRunCompare');
  btn.disabled = true;
  btn.textContent = t('cmp_running');

  try {
    const resp = await fetch('/compare', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ analysis_ids: ids }),
    });

    const data = await resp.json();
    if (!resp.ok) throw new Error(data.detail || `HTTP ${resp.status}`);

    currentComparisonId = data.comparison_id;
    renderCompareResult(data);
  } catch (err) {
    alert(t('cmp_failed') + ': ' + err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = t('cmp_run');
  }
}

function renderCompareResult(data) {
  document.getElementById('compareResult').style.display = 'block';
  document.getElementById('compareResult').scrollIntoView({ behavior: 'smooth' });

  renderCompareSummary(data);
  renderTimeline(data.documents);
  renderCompareTable(data);
  renderCompareSoftware(data.same_software || []);
  renderCompareUuidCluster(data.same_uuid_cluster || []);
  renderCompareMetaDiff(data.metadata_diffs || []);
  renderCompareAnomalies(data.anomalies || []);

  document.getElementById('btnDownloadCompareReport').onclick = () => {
    window.open(`/compare-report/${data.comparison_id}`, '_blank');
  };
}

function renderCompareSummary(data) {
  const body = document.getElementById('compareSummaryBody');
  const identCount = (data.identical_hashes || []).length;
  const timeCount  = (data.time_proximity_flags || []).length;
  const anomCount  = (data.anomalies || []).length;

  const swCount   = (data.same_software || []).length;
  const uuidCount = (data.same_uuid_cluster || []).length;
  const metaCount = (data.metadata_diffs || []).length;

  body.innerHTML = kvTableSimple([
    [t('cmp_sum_docs'),        data.documents.length],
    [t('cmp_sum_hashes'),      identCount  ? `${identCount} ${t('cmp_hits')}` : t('none_clean')],
    [t('cmp_sum_time'),        timeCount   ? `${timeCount} ${t('cmp_hits')}`  : t('none_clean')],
    [t('cmp_sum_uuid'),        uuidCount   ? `${uuidCount} ${t('cmp_cluster')}` : t('none_clean')],
    [t('cmp_sum_software'),    swCount     ? `${swCount} ${t('cmp_found')}`       : '—'],
    [t('cmp_sum_metadiff'),    metaCount   ? `${metaCount} ${t('cmp_fields')}`    : '—'],
    [t('cmp_sum_anomalies'),   anomCount || '—'],
    [t('cmp_sum_common_cats'), (data.common_anomalies || []).join(', ') || '—'],
  ]);
}

function renderTimeline(docs) {
  const container = document.getElementById('compareTimeline');

  // Nach CreationDate sortieren
  const sorted = [...docs].sort((a, b) => {
    const da = a.creation_date || '0';
    const db = b.creation_date || '0';
    return da.localeCompare(db);
  });

  container.innerHTML = sorted.map((doc, i) => `
    <div class="timeline-item">
      <div class="timeline-dot" style="background:${riskColor(doc.risk_level)}">${i + 1}</div>
      <div class="timeline-label">${escapeHtml(doc.filename.slice(0, 25))}</div>
      <div class="timeline-date">${formatDate(doc.creation_date)}</div>
    </div>`).join('');
}

function renderCompareTable(data) {
  const container = document.getElementById('compareTable');
  const docs = data.documents;

  const attrs = [
    [t('col_filename'),    d => d.filename],
    [t('cmp_attr_risk'),     d => riskBadgeHtml(d.risk_level)],
    ['SHA256',               d => `<span class="mono" style="font-size:0.75rem">${(d.sha256||'').slice(0,16)}…</span>`],
    ['Producer',             d => d.producer || '—'],
    ['Creator',              d => d.creator || '—'],
    [t('lbl_created'),       d => formatDate(d.creation_date)],
    [t('lbl_modified'),      d => formatDate(d.mod_date)],
    [t('lbl_pages'),         d => d.page_count || 0],
    [t('lbl_extracted_images'), d => d.image_count || 0],
    [t('cmp_attr_high'), d => {
      const v = d.anomaly_count_high || 0;
      return v > 0 ? `<span style="color:var(--high);font-weight:600">${v}</span>` : '0';
    }],
    [t('cmp_attr_medium'), d => {
      const v = d.anomaly_count_medium || 0;
      return v > 0 ? `<span style="color:var(--medium);font-weight:600">${v}</span>` : '0';
    }],
    [t('lbl_javascript'), d => d.has_javascript
      ? `<span style="color:var(--high);font-weight:600">${t('auto_exec_short')}</span>`
      : `<span style="color:var(--clean)">${t('no_clean')}</span>`],
    [t('cmp_attr_encrypted'), d => d.is_encrypted
      ? `<span style="color:var(--medium);font-weight:600">${t('yes_clean')}</span>`
      : `<span style="color:var(--muted)">${t('no_clean')}</span>`],
    [t('lbl_revisions'),   d => {
      const v = d.revision_count || 1;
      return v > 1 ? `<span style="color:var(--medium);font-weight:600">${v}</span>` : v;
    }],
  ];

  let html = `<table class="compare-table"><thead><tr><th class="attr-col">${t('cmp_attr_col')}</th>`;
  docs.forEach((d, i) => {
    html += `<th>${t('cmp_doc_prefix')} ${i+1}: ${escapeHtml(d.filename.slice(0, 20))}</th>`;
  });
  html += '</tr></thead><tbody>';

  attrs.forEach(([label, fn]) => {
    html += `<tr><td class="attr-col">${label}</td>`;
    docs.forEach(d => {
      html += `<td>${fn(d)}</td>`;
    });
    html += '</tr>';
  });

  html += '</tbody></table>';
  container.innerHTML = html;
}

function renderCompareSoftware(items) {
  const card = document.getElementById('compareSoftwareCard');
  const body = document.getElementById('compareSoftwareBody');
  if (!items.length) { card.style.display = 'none'; return; }

  card.style.display = 'block';
  body.innerHTML = items.map(sw => `
    <div class="compare-detail-card">
      <h4>${escapeHtml(sw.tool)}</h4>
      <div style="font-size:0.82rem;color:var(--muted)">
        ${t('cmp_doc_id_a')}: <code>${escapeHtml(sw.analysis_id_a.slice(0,8))}…</code> ·
        ${t('cmp_doc_id_b')}: <code>${escapeHtml(sw.analysis_id_b.slice(0,8))}…</code>
      </div>
    </div>`).join('');
}

function renderCompareUuidCluster(clusters) {
  const card = document.getElementById('compareUuidCard');
  const body = document.getElementById('compareUuidBody');
  if (!clusters.length) { card.style.display = 'none'; return; }

  card.style.display = 'block';
  body.innerHTML = `<p style="font-size:0.83rem;color:var(--high);margin-bottom:10px">
    ${t('cmp_uuid_warning')}</p>` +
    clusters.map(cl => `
      <div class="compare-detail-card">
        <h4>${t('cmp_doc_id_a')}: <code>${escapeHtml(cl.analysis_id_a.slice(0,8))}…</code> ↔ ${t('cmp_doc_id_b')}: <code>${escapeHtml(cl.analysis_id_b.slice(0,8))}…</code></h4>
        <div class="compare-uuid-list">
          ${cl.shared_uuids.map(u => `<span class="compare-uuid-tag">${escapeHtml(u)}</span>`).join('')}
        </div>
      </div>`).join('');
}

function renderCompareMetaDiff(diffs) {
  const card = document.getElementById('compareMetaDiffCard');
  const body = document.getElementById('compareMetaDiffBody');
  if (!diffs.length) { card.style.display = 'none'; return; }

  card.style.display = 'block';
  body.innerHTML = `<p style="font-size:0.83rem;color:var(--muted);margin-bottom:10px">
    ${t('cmp_metadiff_intro')}</p>` +
    diffs.map(diff => {
      const entries = Object.entries(diff.values || {});
      return `
        <div class="compare-detail-card">
          <h4>${escapeHtml(diff.field)}</h4>
          <div class="meta-diff-row">
            ${entries.map(([fn, v]) => `
              <div class="meta-diff-entry"><span>${escapeHtml(fn)}:</span>${escapeHtml(v)}</div>`).join('')}
          </div>
        </div>`;
    }).join('');
}

function renderCompareAnomalies(anomalies) {
  const card = document.getElementById('compareAnomaliesCard');
  const body = document.getElementById('compareAnomaliesBody');

  const significant = anomalies.filter(a => a.severity !== 'INFO');
  if (!significant.length) { card.style.display = 'none'; return; }

  card.style.display = 'block';
  body.innerHTML = significant.map(a => `
    <div class="anomaly-item">
      ${severityBadgeHtml(a.severity)}
      <div class="anomaly-category">${escapeHtml(a.category)}</div>
      <div>
        <div class="anomaly-message">${escapeHtml(a.message)}</div>
        ${a.detail ? `<div class="anomaly-detail">${escapeHtml(a.detail)}</div>` : ''}
      </div>
    </div>`).join('');
}

// ===== Helfer =====

function kvTableSimple(rows) {
  let html = '<table class="kv-table">';
  rows.forEach(([k, v]) => {
    html += `<tr><td>${escapeHtml(k)}</td><td>${v == null ? '—' : v}</td></tr>`;
  });
  html += '</table>';
  return html;
}

function riskColor(level) {
  const colors = { HIGH: '#ef4444', MEDIUM: '#f59e0b', LOW: '#3b82f6', CLEAN: '#22c55e', UNKNOWN: '#6b7280' };
  return colors[level] || '#6b7280';
}
