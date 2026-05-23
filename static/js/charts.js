/**
 * charts.js — Chart.js + GSAP powered forensic visualization dashboard
 * Erzeugt interaktive Diagramme direkt nach dem Risk-Banner
 */

// ─── Farben (gleich wie CSS vars) ────────────────────────────────────────────
const C = {
  high:    '#ef4444', highBg:   'rgba(239,68,68,0.45)',
  medium:  '#f59e0b', mediumBg: 'rgba(245,158,11,0.45)',
  low:     '#3b82f6', lowBg:    'rgba(59,130,246,0.45)',
  clean:   '#22c55e', cleanBg:  'rgba(34,197,94,0.45)',
  info:    '#6b7280',
  accent:  '#3b82f6',
  text:    '#e2e8f0',
  muted:   '#94a3b8',
  surface: '#1a1d23',
  bg:      '#0f1117',
  grid:    'rgba(255,255,255,0.06)',
};

// ─── Chart.js Defaults ──────────────────────────────────────────────────────
function _initChartDefaults() {
  if (!window.Chart) return;
  Chart.defaults.color = C.muted;
  Chart.defaults.borderColor = C.grid;
  Chart.defaults.font.family = "'Segoe UI', system-ui, sans-serif";
  Chart.defaults.font.size = 11;
  Chart.defaults.plugins.legend.labels.usePointStyle = true;
  Chart.defaults.plugins.legend.labels.pointStyleWidth = 8;
  Chart.defaults.plugins.tooltip.backgroundColor = '#1e293b';
  Chart.defaults.plugins.tooltip.borderColor = '#334155';
  Chart.defaults.plugins.tooltip.borderWidth = 1;
  Chart.defaults.plugins.tooltip.cornerRadius = 8;
  Chart.defaults.plugins.tooltip.titleFont = { weight: '600', size: 12 };
  Chart.defaults.plugins.tooltip.bodyFont = { size: 11 };
  Chart.defaults.plugins.tooltip.padding = { top: 8, bottom: 8, left: 12, right: 12 };
  Chart.defaults.animation.duration = 800;
  Chart.defaults.animation.easing = 'easeOutQuart';
}

// ─── Chart instances (für Cleanup) ──────────────────────────────────────────
const _charts = {};
function _destroyChart(id) {
  if (_charts[id]) { try { _charts[id].destroy(); } catch(e){} delete _charts[id]; }
}

// ─── Fallback für leere Charts ──────────────────────────────────────────────
function _showChartEmpty(elementId, message) {
  var el = document.getElementById(elementId);
  if (!el) return;
  // Wenn es ein canvas ist, den Parent nehmen
  var target = el.tagName === 'CANVAS' ? el.parentElement : el;
  target.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:' + C.muted + ';font-size:0.82rem;text-align:center;padding:20px;flex-direction:column;gap:8px">' +
    '<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="' + C.info + '" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" opacity="0.4"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>' +
    '<span>' + message + '</span></div>';
}

// ─── Dashboard rendern ──────────────────────────────────────────────────────
function renderChartDashboard(data) {
  console.log('[Charts] renderChartDashboard aufgerufen, data keys:', Object.keys(data || {}));
  console.log('[Charts] all_anomalies count:', (data.all_anomalies || []).length);
  console.log('[Charts] risk_level:', data.risk_level);

  _initChartDefaults();

  var container = document.getElementById('chartDashboard');
  if (!container) { console.error('[Charts] chartDashboard container nicht gefunden!'); return; }
  container.style.display = 'block';

  // Jede Render-Funktion einzeln mit try/catch, damit ein Fehler nicht alle stoppt
  var renderers = [
    { name: 'RiskGauge',     fn: _renderRiskGauge },
    { name: 'SeverityDonut', fn: _renderSeverityDonut },
    { name: 'AnalyzerRadar', fn: _renderAnalyzerRadar },
    { name: 'PhaseSummary',  fn: _renderPhaseSummary },
    { name: 'CategoryBar',   fn: _renderCategoryBar },
    { name: 'SecurityScore',    fn: _renderSecurityScore },
    { name: 'FileStructure',    fn: _renderFileStructure },
    { name: 'AnalyzerCoverage', fn: _renderAnalyzerCoverage },
    { name: 'Timeline',         fn: _renderTimeline },
  ];

  renderers.forEach(function(r) {
    try {
      console.log('[Charts] Starte ' + r.name + '...');
      r.fn(data);
      console.log('[Charts] ' + r.name + ' OK');
    } catch (e) {
      console.error('[Charts] ' + r.name + ' FEHLER:', e);
      console.error('[Charts] ' + r.name + ' Stack:', e.stack);
    }
  });

  // Animate OHNE opacity — nur Y-Verschiebung, damit Charts nicht unsichtbar werden
  try { _animateDashboard(); } catch(e) { console.error('[Charts] Animation Fehler:', e); }
}

// ─── 1. Severity Donut ──────────────────────────────────────────────────────
function _renderSeverityDonut(data) {
  _destroyChart('severityDonut');
  var canvas = document.getElementById('chartSeverityDonut');
  if (!canvas) return;

  var high = data.anomaly_count_high || 0;
  var med  = data.anomaly_count_medium || 0;
  var low  = data.anomaly_count_low || 0;
  var total = high + med + low;

  _charts['severityDonut'] = new Chart(canvas, {
    type: 'doughnut',
    data: {
      labels: ['HIGH', 'MEDIUM', 'LOW'],
      datasets: [{
        data: total > 0 ? [high, med, low] : [0, 0, 1],
        backgroundColor: total > 0 ? [C.high, C.medium, C.low] : ['rgba(34,197,94,0.3)'],
        borderColor: total > 0 ? [C.high, C.medium, C.low] : [C.clean],
        borderWidth: 2,
        hoverBorderWidth: 3,
        hoverOffset: 6,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '72%',
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: function(ctx) { return ' ' + ctx.label + ': ' + ctx.parsed + (ctx.parsed === 1 ? ' finding' : ' findings'); },
          },
        },
      },
    },
    plugins: [{
      id: 'centerText',
      afterDraw: function(chart) {
        var ctx2 = chart.ctx;
        var chartArea = chart.chartArea;
        var cx = (chartArea.left + chartArea.right) / 2;
        var cy = (chartArea.top + chartArea.bottom) / 2;
        ctx2.save();
        ctx2.textAlign = 'center';
        ctx2.textBaseline = 'middle';
        ctx2.fillStyle = C.text;
        ctx2.font = 'bold 28px system-ui';
        ctx2.fillText(total, cx, cy - 8);
        ctx2.fillStyle = C.muted;
        ctx2.font = '11px system-ui';
        ctx2.fillText(total === 0 ? 'CLEAN' : 'FINDINGS', cx, cy + 14);
        ctx2.restore();
      },
    }],
  });
}

// ─── 2. Analyzer Radar ──────────────────────────────────────────────────────
function _renderAnalyzerRadar(data) {
  _destroyChart('analyzerRadar');
  var canvas = document.getElementById('chartAnalyzerRadar');
  if (!canvas) return;

  var anomalies = data.all_anomalies || [];
  var categories = {};
  anomalies.forEach(function(a) {
    var cat = a.category || 'other';
    categories[cat] = (categories[cat] || 0) + 1;
  });

  var sorted = Object.entries(categories)
    .sort(function(a, b) { return b[1] - a[1]; })
    .slice(0, 8);

  if (sorted.length < 3) {
    _showChartEmpty('chartAnalyzerRadar', t('charts_radar_empty'));
    return;
  }

  var labels = sorted.map(function(e) { return _categoryLabel(e[0]); });
  var values = sorted.map(function(e) { return e[1]; });
  var maxVal = Math.max.apply(null, values.concat([3]));

  _charts['analyzerRadar'] = new Chart(canvas, {
    type: 'radar',
    data: {
      labels: labels,
      datasets: [{
        label: (typeof t === 'function' ? t('lbl_findings') : '') || 'Findings',
        data: values,
        backgroundColor: 'rgba(59,130,246,0.35)',
        borderColor: C.accent,
        borderWidth: 2,
        pointBackgroundColor: C.accent,
        pointBorderColor: '#fff',
        pointBorderWidth: 1,
        pointRadius: 4,
        pointHoverRadius: 6,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        r: {
          beginAtZero: true,
          max: maxVal + 1,
          ticks: { stepSize: 1, display: false },
          grid: { color: C.grid },
          angleLines: { color: C.grid },
          pointLabels: {
            color: C.muted,
            font: { size: 10 },
          },
        },
      },
      plugins: { legend: { display: false } },
    },
  });
}

// ─── 3. Category Horizontal Bar ─────────────────────────────────────────────
function _renderCategoryBar(data) {
  _destroyChart('categoryBar');
  var canvas = document.getElementById('chartCategoryBar');
  if (!canvas) return;

  var anomalies = data.all_anomalies || [];

  if (anomalies.length === 0) {
    _showChartEmpty('chartCategoryBar', t('charts_no_anomalies'));
    return;
  }

  var byCategory = {};
  anomalies.forEach(function(a) {
    var cat = a.category || 'other';
    if (!byCategory[cat]) byCategory[cat] = { high: 0, medium: 0, low: 0 };
    var sev = (a.severity || '').toLowerCase();
    if (sev === 'high') byCategory[cat].high++;
    else if (sev === 'medium') byCategory[cat].medium++;
    else byCategory[cat].low++;
  });

  var sorted = Object.entries(byCategory)
    .sort(function(a, b) { return (b[1].high * 10 + b[1].medium * 3 + b[1].low) - (a[1].high * 10 + a[1].medium * 3 + a[1].low); })
    .slice(0, 10);

  if (sorted.length === 0) {
    _showChartEmpty('chartCategoryBar', t('charts_no_categories'));
    return;
  }

  var labels = sorted.map(function(e) { return _categoryLabel(e[0]); });

  _charts['categoryBar'] = new Chart(canvas, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [
        { label: 'HIGH',   data: sorted.map(function(e) { return e[1].high; }),   backgroundColor: C.highBg,   borderColor: C.high,   borderWidth: 1 },
        { label: 'MEDIUM', data: sorted.map(function(e) { return e[1].medium; }), backgroundColor: C.mediumBg, borderColor: C.medium, borderWidth: 1 },
        { label: 'LOW',    data: sorted.map(function(e) { return e[1].low; }),    backgroundColor: C.lowBg,    borderColor: C.low,    borderWidth: 1 },
      ],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          stacked: true,
          ticks: { stepSize: 1, color: C.muted },
          grid: { color: C.grid },
        },
        y: {
          stacked: true,
          ticks: { color: C.muted, font: { size: 11 } },
          grid: { display: false },
        },
      },
      plugins: {
        legend: {
          position: 'top',
          align: 'end',
          labels: { boxWidth: 12, padding: 10, font: { size: 10 } },
        },
      },
    },
  });
}

// ─── 4. Risk Gauge (SVG — kein Chart.js) ────────────────────────────────────
function _renderRiskGauge(data) {
  var container = document.getElementById('chartRiskGauge');
  if (!container) return;

  var level = (data.risk_level || 'UNKNOWN').toUpperCase();
  var colors = {
    HIGH:    { color: C.high,   angle: 162, glow: 'rgba(239,68,68,0.4)' },
    MEDIUM:  { color: C.medium, angle: 108, glow: 'rgba(245,158,11,0.4)' },
    LOW:     { color: C.low,    angle: 54,  glow: 'rgba(59,130,246,0.4)' },
    CLEAN:   { color: C.clean,  angle: 18,  glow: 'rgba(34,197,94,0.4)' },
    UNKNOWN: { color: C.info,   angle: 90,  glow: 'rgba(107,114,128,0.3)' },
  };
  var cfg = colors[level] || colors.UNKNOWN;

  var needleAngle = cfg.angle;
  var rad = (needleAngle * Math.PI) / 180;
  var nx = 100 + Math.cos(Math.PI - rad) * 65;
  var ny = 95 - Math.sin(Math.PI - rad) * 65;

  container.innerHTML =
    '<svg viewBox="0 0 200 120" style="width:100%;max-width:220px;display:block;margin:0 auto">' +
      '<defs>' +
        '<filter id="gaugeGlow"><feGaussianBlur stdDeviation="3" result="blur"/>' +
          '<feComposite in="SourceGraphic" in2="blur" operator="over"/>' +
        '</filter>' +
      '</defs>' +
      '<path d="M 20 95 A 80 80 0 0 1 180 95" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="12" stroke-linecap="round"/>' +
      '<path d="M 20 95 A 80 80 0 0 1 56 40"   fill="none" stroke="' + C.clean  + '" stroke-width="12" stroke-linecap="round" opacity="0.7"/>' +
      '<path d="M 56 40 A 80 80 0 0 1 100 15"  fill="none" stroke="' + C.low    + '" stroke-width="12" opacity="0.7"/>' +
      '<path d="M 100 15 A 80 80 0 0 1 144 40" fill="none" stroke="' + C.medium + '" stroke-width="12" opacity="0.7"/>' +
      '<path d="M 144 40 A 80 80 0 0 1 180 95" fill="none" stroke="' + C.high   + '" stroke-width="12" stroke-linecap="round" opacity="0.7"/>' +
      '<line x1="100" y1="95" x2="' + nx.toFixed(1) + '" y2="' + ny.toFixed(1) + '" stroke="' + cfg.color + '" stroke-width="3" stroke-linecap="round" filter="url(#gaugeGlow)" class="gauge-needle"/>' +
      '<circle cx="100" cy="95" r="6" fill="' + cfg.color + '" filter="url(#gaugeGlow)"/>' +
      '<circle cx="100" cy="95" r="3" fill="' + C.bg + '"/>' +
      '<text x="100" y="115" text-anchor="middle" fill="' + cfg.color + '" font-size="14" font-weight="700" letter-spacing="2">' + level + '</text>' +
    '</svg>';
}

// ─── 5. Phase Summary (Polar Area) ──────────────────────────────────────────
function _renderPhaseSummary(data) {
  _destroyChart('phaseSummary');
  var canvas = document.getElementById('chartPhaseSummary');
  if (!canvas) return;

  var anomalies = data.all_anomalies || [];

  // Zähle Anomalien pro Phase basierend auf Kategorie
  var phaseLabels = [t('phase_basis'), t('phase_structure'), t('phase_image'), t('phase_ioc_text'), t('phase_deep'), t('phase_extended')];
  var phaseKeywords = [
    ['metadata','hash','software','uuid','signature','geometry','page'],
    ['encrypt','incremental','javascript','embedded','object','residual','stream'],
    ['image','steganograph','ela','jpeg','photo','copy.move'],
    ['ioc','hidden','yellow','text','url','ip'],
    ['xref','deep','redact','content','fuzzy','decomp'],
    ['yara','font','pdfa','pdfx','linear','printer','icc','compliance'],
  ];

  var phaseValues = phaseKeywords.map(function(keywords) {
    var count = 0;
    anomalies.forEach(function(a) {
      var cat = (a.category || '').toLowerCase();
      var msg = (a.message || '').toLowerCase();
      for (var i = 0; i < keywords.length; i++) {
        if (cat.indexOf(keywords[i]) !== -1 || msg.indexOf(keywords[i]) !== -1) {
          count++;
          break;
        }
      }
    });
    return count;
  });

  var phaseColors = ['#3b82f6','#8b5cf6','#ec4899','#f59e0b','#ef4444','#22c55e'];

  // Falls gar keine Anomalien: Dummy-Daten zeigen (alle "clean")
  var hasData = phaseValues.some(function(v) { return v > 0; });
  if (!hasData) {
    phaseValues = [1, 1, 1, 1, 1, 1];
  }

  _charts['phaseSummary'] = new Chart(canvas, {
    type: 'polarArea',
    data: {
      labels: phaseLabels,
      datasets: [{
        data: phaseValues,
        backgroundColor: hasData ? phaseColors.map(function(c) { return c + '66'; }) : phaseColors.map(function(c) { return c + '33'; }),
        borderColor: phaseColors,
        borderWidth: 2,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        r: {
          beginAtZero: true,
          ticks: { display: false, stepSize: 1 },
          grid: { color: C.grid },
        },
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: function(ctx) {
              if (!hasData) return ' ' + ctx.label + ': ' + t('charts_no_findings');
              return ' ' + ctx.label + ': ' + ctx.parsed.r + ' ' + t('lbl_findings');
            },
          },
        },
      },
    },
  });
}

// ─── 6. Security Score (SVG Gauge) ──────────────────────────────────────────
function _renderSecurityScore(data) {
  var container = document.getElementById('chartSecurityScore');
  if (!container) return;

  var score = 100;
  var high = data.anomaly_count_high || 0;
  var med  = data.anomaly_count_medium || 0;
  var low  = data.anomaly_count_low || 0;

  score -= high * 15;
  score -= med * 5;
  score -= low * 1;

  if (data.javascript_actions && data.javascript_actions.has_javascript) score -= 10;
  if (data.virus_scan && !data.virus_scan.is_clean) score -= 30;
  if (data.signatures && data.signatures.all_valid) score += 5;
  if (data.encryption && data.encryption.is_encrypted) score -= 5;

  score = Math.max(0, Math.min(100, Math.round(score)));

  var color, label;
  if (score >= 80)      { color = C.clean;  label = t('score_safe'); }
  else if (score >= 60) { color = C.low;    label = 'OK'; }
  else if (score >= 35) { color = C.medium; label = t('score_warning'); }
  else                  { color = C.high;   label = t('score_critical'); }

  var circumference = 2 * Math.PI * 52;
  var offset = circumference - (score / 100) * circumference;

  container.innerHTML =
    '<svg viewBox="0 0 120 120" style="width:100%;max-width:140px;display:block;margin:0 auto">' +
      '<defs>' +
        '<filter id="scoreGlow"><feGaussianBlur stdDeviation="2" result="blur"/>' +
          '<feComposite in="SourceGraphic" in2="blur" operator="over"/>' +
        '</filter>' +
      '</defs>' +
      '<circle cx="60" cy="60" r="52" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="8"/>' +
      '<circle cx="60" cy="60" r="52" fill="none" stroke="' + color + '" stroke-width="8"' +
              ' stroke-dasharray="' + circumference + '" stroke-dashoffset="' + offset + '"' +
              ' stroke-linecap="round" transform="rotate(-90 60 60)"' +
              ' filter="url(#scoreGlow)"' +
              ' style="transition: stroke-dashoffset 1.2s cubic-bezier(0.4,0,0.2,1)"/>' +
      '<text x="60" y="55" text-anchor="middle" fill="' + color + '" font-size="26" font-weight="700">' + score + '</text>' +
      '<text x="60" y="72" text-anchor="middle" fill="' + C.muted + '" font-size="8" letter-spacing="1.5" font-weight="600">' + label + '</text>' +
      '<text x="60" y="85" text-anchor="middle" fill="' + C.muted + '" font-size="7">/ 100</text>' +
    '</svg>';
}

// ─── 7. File Structure (Doughnut) ────────────────────────────────────────────
function _renderFileStructure(data) {
  var canvas = document.getElementById('chartFileStructure');
  if (!canvas) return;

  var meta = data.metadata || {};
  var structure = data.file_structure || data.structure || {};
  var objStreams = data.object_streams || {};

  var pages = meta.page_count || meta.pages || structure.pages || 0;
  var fonts = 0;
  var images = 0;
  var streams = objStreams.total_objects || structure.streams || 0;
  var scripts = 0;
  var other = 0;

  // Font-Daten
  var fontData = data.font_forensics || data.fonts || {};
  if (fontData.fonts && fontData.fonts.length) {
    fonts = fontData.fonts.length;
  } else if (fontData.total_fonts) {
    fonts = fontData.total_fonts;
  }

  // Bild-Daten
  var jpegData = data.jpeg_analysis || data.deep_jpeg || {};
  if (jpegData.images && jpegData.images.length) {
    images = jpegData.images.length;
  } else if (jpegData.image_count) {
    images = jpegData.image_count;
  }

  // JavaScript
  var jsData = data.javascript_actions || {};
  if (jsData.has_javascript) {
    scripts = (jsData.actions && jsData.actions.length) || 1;
  }

  // Embedded files
  var embedded = data.embedded_files || {};
  other = (embedded.files && embedded.files.length) || embedded.count || 0;

  // Mindestens Seiten zeigen
  if (pages === 0 && fonts === 0 && images === 0 && streams === 0) {
    pages = 1;
  }

  var labels = [t('lbl_pages'), 'Fonts', t('lbl_images'), 'Streams', 'Scripts', 'Embedded'];
  var values = [pages, fonts, images, streams, scripts, other];
  var colors = [C.accent, '#8b5cf6', C.medium, C.low, C.high, '#06b6d4'];
  var bgColors = ['rgba(99,102,241,0.45)', 'rgba(139,92,246,0.45)', 'rgba(245,158,11,0.45)',
                  'rgba(59,130,246,0.45)', 'rgba(239,68,68,0.45)', 'rgba(6,182,212,0.45)'];

  // Nur nicht-leere Werte
  var filteredLabels = [];
  var filteredValues = [];
  var filteredColors = [];
  var filteredBg = [];
  for (var i = 0; i < values.length; i++) {
    if (values[i] > 0) {
      filteredLabels.push(labels[i]);
      filteredValues.push(values[i]);
      filteredColors.push(colors[i]);
      filteredBg.push(bgColors[i]);
    }
  }

  if (filteredValues.length === 0) {
    _showChartEmpty('chartFileStructure', t('charts_no_structure'));
    return;
  }

  _destroyChart('fileStructure');

  _charts['fileStructure'] = new Chart(canvas, {
    type: 'doughnut',
    data: {
      labels: filteredLabels,
      datasets: [{
        data: filteredValues,
        backgroundColor: filteredBg,
        borderColor: filteredColors,
        borderWidth: 2,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '55%',
      plugins: {
        legend: {
          position: 'bottom',
          labels: { color: C.muted, font: { size: 10 }, padding: 8, boxWidth: 10 },
        },
        tooltip: {
          backgroundColor: 'rgba(17,19,24,0.95)',
          titleColor: '#fff',
          bodyColor: C.muted,
        },
      },
    },
  });
}

// ─── 8. Analyzer Coverage (Stacked Bar) ──────────────────────────────────────
function _renderAnalyzerCoverage(data) {
  var canvas = document.getElementById('chartAnalyzerCoverage');
  if (!canvas) return;

  // Phasen durchgehen und Analyzer-Status zählen
  var phases = [
    { key: 'phase1', label: 'P1' },
    { key: 'phase2', label: 'P2' },
    { key: 'phase3', label: 'P3' },
    { key: 'phase4', label: 'P4' },
    { key: 'phase5', label: 'P5' },
    { key: 'phase6', label: 'P6' },
  ];

  // Synchron mit Backend (analyzers/pipeline.py) und tatsächlichen Response-Keys.
  // Vorher waren die meisten Keys falsch (z.B. 'software_id' statt 'software_fingerprint'),
  // dadurch zeigte das Chart Phasen leer/abgebrochen obwohl die Pipeline durchlief.
  var phaseMap = {
    phase1: ['hashes','metadata','uuid_decode','software_fingerprint','signature','page_geometry','page_labels','jpeg_extractor','jpeg_analyzer','quant_fingerprint'],
    phase2: ['encryption','incremental_updates','javascript','embedded_files','virus_scan'],
    phase3: ['timezone','author_artifacts','ela','object_streams','residual_objects','shadow_attack','image_forensics','steganography'],
    phase4: ['ioc','hidden_text','yellow_dots'],
    phase5: ['stream_decomp','xref_validation','deep_jpeg','redaction','ocg_layers','content_stream','incremental_diff','fuzzy_hash'],
    phase6: ['cross_analyzer','yara','font_forensics','pdfa_compliance','linearization','icc_profiles','visual_render','object_graph','cross_doc_fingerprint','printer_forensics','chain_of_custody'],
  };

  var passData = [];
  var warnData = [];
  var failData = [];
  var phaseLabels = [];

  for (var p = 0; p < phases.length; p++) {
    var keys = phaseMap[phases[p].key] || [];
    var pass = 0, warn = 0, fail = 0;

    for (var k = 0; k < keys.length; k++) {
      var section = data[keys[k]];
      if (!section) continue;

      // Anomalien zählen
      var anomalies = section.anomalies || [];
      var hasHigh = false;
      var hasMed = false;
      for (var a = 0; a < anomalies.length; a++) {
        var sev = (anomalies[a].severity || '').toLowerCase();
        if (sev === 'high' || sev === 'critical') hasHigh = true;
        else if (sev === 'medium') hasMed = true;
      }

      if (hasHigh) fail++;
      else if (hasMed) warn++;
      else pass++;
    }

    phaseLabels.push(phases[p].label);
    passData.push(pass);
    warnData.push(warn);
    failData.push(fail);
  }

  // Prüfen ob überhaupt Daten da sind
  var total = 0;
  for (var i = 0; i < passData.length; i++) total += passData[i] + warnData[i] + failData[i];
  if (total === 0) {
    _showChartEmpty('chartAnalyzerCoverage', t('charts_no_analyzer_data'));
    return;
  }

  _destroyChart('analyzerCoverage');

  _charts['analyzerCoverage'] = new Chart(canvas, {
    type: 'bar',
    data: {
      labels: phaseLabels,
      datasets: [
        {
          label: 'OK',
          data: passData,
          backgroundColor: C.cleanBg,
          borderColor: C.clean,
          borderWidth: 1,
        },
        {
          label: t('score_warning'),
          data: warnData,
          backgroundColor: C.mediumBg,
          borderColor: C.medium,
          borderWidth: 1,
        },
        {
          label: t('score_critical'),
          data: failData,
          backgroundColor: C.highBg,
          borderColor: C.high,
          borderWidth: 1,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      indexAxis: 'y',
      scales: {
        x: {
          stacked: true,
          ticks: { color: C.muted, font: { size: 9 }, stepSize: 1 },
          grid: { color: 'rgba(255,255,255,0.04)' },
        },
        y: {
          stacked: true,
          ticks: { color: C.muted, font: { size: 10, weight: '600' } },
          grid: { display: false },
        },
      },
      plugins: {
        legend: {
          position: 'bottom',
          labels: { color: C.muted, font: { size: 9 }, padding: 6, boxWidth: 8 },
        },
        tooltip: {
          backgroundColor: 'rgba(17,19,24,0.95)',
          titleColor: '#fff',
          bodyColor: C.muted,
        },
      },
    },
  });
}

// ─── 9. Timeline ────────────────────────────────────────────────────────────
function _renderTimeline(data) {
  var container = document.getElementById('chartTimeline');
  if (!container) return;

  var events = [];

  // Metadaten-Zeitstempel
  var meta = data.metadata || {};
  if (meta.creation_date_parsed) {
    events.push({ date: meta.creation_date_parsed, label: t('lbl_created'), color: C.accent });
  }
  if (meta.mod_date_parsed) {
    events.push({ date: meta.mod_date_parsed, label: t('lbl_modified'), color: C.medium });
  }

  // Auch Creation/ModDate als String probieren
  if (events.length === 0) {
    if (meta.creation_date) events.push({ date: meta.creation_date, label: t('lbl_created'), color: C.accent });
    if (meta.mod_date) events.push({ date: meta.mod_date, label: t('lbl_modified'), color: C.medium });
  }

  // UUID-Zeitstempel
  var uuidData = data.uuid_decode || {};
  var uuids = uuidData.decoded || [];
  uuids.forEach(function(u, i) {
    var ts = u.timestamp_utc || u.timestamp;
    if (ts) {
      events.push({ date: ts, label: 'UUID #' + (i + 1), color: '#8b5cf6' });
    }
  });

  if (events.length < 2) {
    _showChartEmpty('chartTimeline', t('charts_timeline_empty'));
    return;
  }

  // Sortieren
  events.sort(function(a, b) { return new Date(a.date) - new Date(b.date); });

  var html = '<div class="forensic-timeline">';
  events.forEach(function(ev, i) {
    var dt = new Date(ev.date);
    var locale = getLang() === 'en' ? 'en-US' : 'de-DE';
    var dateStr = isNaN(dt.getTime()) ? String(ev.date).substring(0, 16) : dt.toLocaleDateString(locale, { day: '2-digit', month: '2-digit', year: 'numeric' });
    var timeStr = isNaN(dt.getTime()) ? '' : dt.toLocaleTimeString(locale, { hour: '2-digit', minute: '2-digit' });
    html += '<div class="tl-event">' +
      '<div class="tl-dot" style="background:' + ev.color + ';box-shadow:0 0 8px ' + ev.color + '"></div>' +
      (i < events.length - 1 ? '<div class="tl-line"></div>' : '') +
      '<div class="tl-label">' + ev.label + '</div>' +
      '<div class="tl-date">' + dateStr + '</div>' +
      (timeStr ? '<div class="tl-time">' + timeStr + '</div>' : '') +
    '</div>';
  });
  html += '</div>';
  container.innerHTML = html;
}

// ─── Animate ────────────────────────────────────────────────────────────────
function _animateDashboard() {
  if (!window.gsap) return;
  // NUR Y-Transform, KEIN opacity — opacity:0 verhindert Canvas-Rendering!
  gsap.from('.chart-card', {
    y: 15,
    duration: 0.4,
    stagger: 0.06,
    ease: 'power2.out',
  });
  gsap.from('.gauge-needle', {
    attr: { x2: 100, y2: 95 },
    duration: 1.2,
    ease: 'elastic.out(1, 0.5)',
    delay: 0.3,
  });
}

// ─── Helpers ────────────────────────────────────────────────────────────────
function _categoryLabel(cat) {
  var de = {
    metadata: 'Metadaten', software: 'Software', signature: 'Signatur',
    uuid: 'UUID', timezone: 'Timezone', incremental: 'Revisionen',
    jpeg: 'Bilder', encryption: 'Verschl.', javascript: 'JavaScript',
    hidden_text: 'Versteckter Text', ioc: 'IOC', ela: 'ELA',
    embedded: 'Eingebettet', residual: 'Residual', shadow: 'Shadow',
    image_forensics: 'Bildforensik', steganography: 'Steganographie',
    object_streams: 'Objekt-Streams', page_geometry: 'Seitengeometrie',
    xref_validation: 'XRef', content_stream: 'Content-Stream',
    yara_scan: 'YARA', font_forensics: 'Fonts', pdfa_compliance: 'PDF/A',
    linearization: 'Linearisierung', printer_forensics: 'Drucker',
    deep_jpeg: 'Deep JPEG', redaction: 'Schw\u00e4rzung',
    fuzzy_hash: 'Fuzzy Hash', yellow_dots: 'Yellow Dots',
  };
  var en = {
    metadata: 'Metadata', software: 'Software', signature: 'Signature',
    uuid: 'UUID', timezone: 'Timezone', incremental: 'Revisions',
    jpeg: 'Images', encryption: 'Encryption', javascript: 'JavaScript',
    hidden_text: 'Hidden Text', ioc: 'IOC', ela: 'ELA',
    embedded: 'Embedded', residual: 'Residual', shadow: 'Shadow',
    image_forensics: 'Image Forensics', steganography: 'Steganography',
    object_streams: 'Object Streams', page_geometry: 'Page Geometry',
    xref_validation: 'XRef', content_stream: 'Content Stream',
    yara_scan: 'YARA', font_forensics: 'Fonts', pdfa_compliance: 'PDF/A',
    linearization: 'Linearization', printer_forensics: 'Printer',
    deep_jpeg: 'Deep JPEG', redaction: 'Redaction',
    fuzzy_hash: 'Fuzzy Hash', yellow_dots: 'Yellow Dots',
  };
  var labels = getLang() === 'en' ? en : de;
  return labels[cat] || cat.charAt(0).toUpperCase() + cat.slice(1);
}
