/* eslint-env browser */
// Sicherer PDF-Viewer — Overlay + Sidebar fuer Annotations.
// CSP erlaubt nur 'self'-Scripte; das PDF selbst kommt nie in den Browser.
(function () {
  'use strict';

  var ANALYSIS_ID = (document.body && document.body.getAttribute('data-analysis-id')) || '';
  if (!ANALYSIS_ID) return;

  var sidebar      = document.getElementById('annSidebar');
  var sidebarList  = document.getElementById('annList');
  var sidebarCount = document.getElementById('annCount');
  var sidebarToggle = document.getElementById('annToggle');
  var pagesEl      = document.getElementById('pages');
  if (!pagesEl) return;

  // ---- Sidebar Toggle (auch wenn keine Annotations da sind) ----
  if (sidebarToggle && sidebar) {
    sidebarToggle.addEventListener('click', function () {
      sidebar.classList.toggle('open');
      sidebarToggle.textContent = sidebar.classList.contains('open')
        ? '✕ Schliessen' : '📝 Annotations';
    });
  }

  // ---- Daten laden: Annotations + Markers parallel ----
  Promise.all([
    fetch('/view/' + encodeURIComponent(ANALYSIS_ID) + '/annotations.json').then(function (r) { return r.json(); }).catch(function () { return null; }),
    fetch('/view/' + encodeURIComponent(ANALYSIS_ID) + '/markers.json').then(function (r) { return r.json(); }).catch(function () { return null; }),
  ]).then(function (results) {
    renderAll(results[0], results[1]);
  });

  // ---- Anzeige ----
  function renderAll(annData, markData) {
    var annPages = (annData && annData.pages) || [];
    var markPages = (markData && markData.pages) || [];
    var totalAnn = 0;
    var totalMark = 0;
    var listFrag = document.createDocumentFragment();

    // Pro Seite: erst Overlay anlegen, dann annot-boxes + marker-boxes
    var pageIndexMap = {};   // page_index -> overlay element
    function ensureOverlay(pageIdx) {
      if (pageIndexMap[pageIdx]) return pageIndexMap[pageIdx];
      var pageWrap = pagesEl.children[pageIdx];
      if (!pageWrap) return null;
      var ov = pageWrap.querySelector('.overlay');
      if (!ov) {
        ov = document.createElement('div');
        ov.className = 'overlay';
        pageWrap.appendChild(ov);
      }
      pageIndexMap[pageIdx] = ov;
      return ov;
    }

    // Annotations
    annPages.forEach(function (p) {
      var overlay = ensureOverlay(p.page);
      if (!overlay) return;
      (p.annotations || []).forEach(function (ann, idx) {
        totalAnn += 1;
        var box = drawBox(overlay, p, ann, idx);
        var li = sidebarItem(p.page, ann, box, 'annotation');
        listFrag.appendChild(li);
      });
    });

    // Marker (forensische Befunde mit Koordinaten)
    markPages.forEach(function (p) {
      var overlay = ensureOverlay(p.page);
      if (!overlay) return;
      (p.markers || []).forEach(function (mk, idx) {
        totalMark += 1;
        var box = drawMarker(overlay, p, mk, idx);
        var li = sidebarMarkerItem(p.page, mk, box);
        listFrag.appendChild(li);
      });
    });

    if (sidebarCount) {
      var parts = [];
      if (totalAnn > 0) parts.push(totalAnn + ' Annotation' + (totalAnn === 1 ? '' : 'en'));
      if (totalMark > 0) parts.push(totalMark + ' forensischer Marker' + (totalMark === 1 ? '' : 'e'));
      sidebarCount.textContent = parts.length ? parts.join(' · ') : 'Keine Marker/Annotations';
    }
    if (sidebarList) {
      if (totalAnn + totalMark === 0) {
        var none = document.createElement('div');
        none.className = 'ann-empty';
        none.textContent = 'Dieses PDF enthaelt keine Annotations oder forensischen Marker.';
        sidebarList.appendChild(none);
      } else {
        sidebarList.appendChild(listFrag);
      }
    }
  }

  function drawMarker(overlay, page, mk, idx) {
    var r = mk.rect_top;
    if (!r || r.length < 4) return null;
    var x0 = r[0], y0 = r[1], x1 = r[2], y1 = r[3];
    var pw = page.width || 1, ph = page.height || 1;
    var box = document.createElement('button');
    box.type = 'button';
    box.className = 'ann-box mk-' + (mk.kind || 'other').toLowerCase()
                  + ' sev-' + (mk.severity || 'low').toLowerCase();
    box.style.left   = (x0 / pw * 100) + '%';
    box.style.top    = (y0 / ph * 100) + '%';
    box.style.width  = ((x1 - x0) / pw * 100) + '%';
    box.style.height = ((y1 - y0) / ph * 100) + '%';
    box.setAttribute('data-page', String(page.page));
    box.setAttribute('data-idx', String(idx));
    var label = document.createElement('span');
    label.className = 'ann-label';
    label.textContent = (mk.kind || '?');
    box.appendChild(label);
    box.addEventListener('click', function (e) {
      e.stopPropagation();
      openSidebarFor(page.page, idx);
    });
    overlay.appendChild(box);
    return box;
  }

  function sidebarMarkerItem(pageNum, mk, box) {
    var li = document.createElement('div');
    li.className = 'ann-item mk-item';
    li.setAttribute('data-page', String(pageNum));
    var head = document.createElement('div');
    head.className = 'ann-item-head';
    var tag = document.createElement('span');
    tag.className = 'ann-tag mk-' + (mk.kind || 'other').toLowerCase();
    tag.textContent = mk.kind || '?';
    head.appendChild(tag);
    var sev = document.createElement('span');
    sev.className = 'ann-tag sev-' + (mk.severity || 'low').toLowerCase();
    sev.textContent = mk.severity || '';
    head.appendChild(sev);
    var pg = document.createElement('span');
    pg.className = 'ann-page';
    pg.textContent = 'Seite ' + (pageNum + 1);
    head.appendChild(pg);
    li.appendChild(head);
    var msg = document.createElement('div');
    msg.className = 'ann-content';
    msg.textContent = mk.message || '';
    li.appendChild(msg);
    if (mk.detail) {
      var dt = document.createElement('div');
      dt.className = 'ann-meta';
      dt.textContent = mk.detail;
      li.appendChild(dt);
    }
    li.addEventListener('click', function () {
      if (box && box.scrollIntoView) {
        box.scrollIntoView({behavior: 'smooth', block: 'center'});
        box.classList.add('ann-pulse');
        setTimeout(function () { box.classList.remove('ann-pulse'); }, 1600);
      }
    });
    return li;
  }

  function drawBox(overlay, page, ann, idx) {
    var r = ann.rect_top || ann.rect_pdf;
    if (!r || r.length < 4) return null;
    var x0 = r[0], y0 = r[1], x1 = r[2], y1 = r[3];
    var pw = page.width || 1, ph = page.height || 1;

    var box = document.createElement('button');
    box.type = 'button';
    box.className = 'ann-box ann-' + (ann.subtype || 'other').toLowerCase();
    box.style.left   = (x0 / pw * 100) + '%';
    box.style.top    = (y0 / ph * 100) + '%';
    box.style.width  = ((x1 - x0) / pw * 100) + '%';
    box.style.height = ((y1 - y0) / ph * 100) + '%';
    box.setAttribute('data-page', String(page.page));
    box.setAttribute('data-idx', String(idx));
    box.setAttribute('aria-label',
      (ann.subtype || 'Annotation') + ' Seite ' + (page.page + 1));
    // Label-Chip (sichtbar wenn die Box gross genug ist)
    var label = document.createElement('span');
    label.className = 'ann-label';
    label.textContent = (ann.subtype || '?');
    box.appendChild(label);
    box.addEventListener('click', function (e) {
      e.stopPropagation();
      openSidebarFor(page.page, idx);
    });
    overlay.appendChild(box);
    return box;
  }

  function sidebarItem(pageNum, ann, box) {
    var li = document.createElement('div');
    li.className = 'ann-item';
    li.setAttribute('data-page', String(pageNum));

    var head = document.createElement('div');
    head.className = 'ann-item-head';
    var st = document.createElement('span');
    st.className = 'ann-tag ann-' + (ann.subtype || 'other').toLowerCase();
    st.textContent = ann.subtype || '?';
    head.appendChild(st);
    var pg = document.createElement('span');
    pg.className = 'ann-page';
    pg.textContent = 'Seite ' + (pageNum + 1);
    head.appendChild(pg);
    li.appendChild(head);

    if (ann.author) {
      var au = document.createElement('div');
      au.className = 'ann-meta';
      au.textContent = 'Autor: ' + ann.author;
      li.appendChild(au);
    }
    if (ann.mod_date) {
      var md = document.createElement('div');
      md.className = 'ann-meta';
      md.textContent = 'Geaendert: ' + ann.mod_date;
      li.appendChild(md);
    }
    if (ann.contents) {
      var co = document.createElement('div');
      co.className = 'ann-content';
      co.textContent = ann.contents;
      li.appendChild(co);
    } else {
      var noc = document.createElement('div');
      noc.className = 'ann-meta ann-empty';
      noc.textContent = '(kein Textinhalt)';
      li.appendChild(noc);
    }

    li.addEventListener('click', function () {
      // Scroll zur Box hin
      if (box && box.scrollIntoView) {
        box.scrollIntoView({behavior: 'smooth', block: 'center'});
        box.classList.add('ann-pulse');
        setTimeout(function () { box.classList.remove('ann-pulse'); }, 1600);
      }
    });
    return li;
  }

  function openSidebarFor(pageNum, idx) {
    if (sidebar) {
      sidebar.classList.add('open');
      if (sidebarToggle) sidebarToggle.textContent = '✕ Schliessen';
    }
    // Im Sidebar das passende Item highlighten
    var items = sidebarList ? sidebarList.querySelectorAll('.ann-item') : [];
    var match = null;
    items.forEach(function (el) { el.classList.remove('ann-selected'); });
    items.forEach(function (el) {
      if (el.getAttribute('data-page') === String(pageNum) && !match) {
        match = el;
      }
    });
    if (match) {
      match.classList.add('ann-selected');
      if (match.scrollIntoView) match.scrollIntoView({behavior: 'smooth', block: 'nearest'});
    }
  }
})();
