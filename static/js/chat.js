/**
 * chat.js — KI-Chat Sidebar (DeepSeek V3 via Streaming)
 */

(function() {
  'use strict';

  var _analysisId = null;
  var _filename   = null;
  var _history    = [];   // [{role, content}]
  var _streaming  = false;

  // ── DOM refs ──────────────────────────────────────────────
  function _el(id) { return document.getElementById(id); }

  var _msgs      = function() { return _el('chatMessages'); };
  var _input     = function() { return _el('chatInput'); };
  var _sendBtn   = function() { return _el('chatSendBtn'); };
  var _ctxName   = function() { return _el('chatContextName'); };

  // ── Public API: wird von results.js / dashboard.js aufgerufen ──
  window.chatSetContext = function(analysisId, filename) {
    _analysisId = analysisId || null;
    _filename   = filename   || null;
    _history    = [];

    var bar = _ctxName();
    if (bar) {
      bar.textContent = _filename
        ? '📄 ' + _filename
        : (typeof t === 'function' ? t('chat_no_doc') : 'Kein Dokument geladen');
    }
  };

  // ── Nachricht rendern ─────────────────────────────────────
  function _appendMsg(role, text, streaming) {
    var welcome = _msgs().querySelector('.chat-welcome');
    if (welcome) welcome.remove();

    var div = document.createElement('div');
    div.className = 'chat-msg chat-msg-' + role + (streaming ? ' streaming' : '');
    div.textContent = text;
    _msgs().appendChild(div);
    _msgs().scrollTop = _msgs().scrollHeight;
    return div;
  }

  function _appendError(text) {
    var div = document.createElement('div');
    div.className = 'chat-msg chat-msg-error';
    div.textContent = '⚠ ' + text;
    _msgs().appendChild(div);
    _msgs().scrollTop = _msgs().scrollHeight;
  }

  // ── Senden ────────────────────────────────────────────────
  async function _send() {
    if (_streaming) return;
    var input = _input();
    var msg = input.value.trim();
    if (!msg) return;

    input.value = '';
    input.style.height = 'auto';
    _streaming = true;

    var btn = _sendBtn();
    if (btn) { btn.disabled = true; btn.classList.add('loading'); }

    // User-Nachricht anzeigen
    _appendMsg('user', msg);
    _history.push({ role: 'user', content: msg });

    // Assistent-Bubble vorbereiten
    var bubble = _appendMsg('assistant', '', true);
    var accumulated = '';

    try {
      var lang = typeof getLang === 'function' ? getLang() : 'de';

      var resp = await fetch('/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: msg,
          analysis_id: _analysisId,
          lang: lang,
          history: _history.slice(-10),
        }),
      });

      if (!resp.ok) {
        bubble.remove();
        _appendError('Server-Fehler: ' + resp.status);
        _history.pop();
      } else {
        var reader = resp.body.getReader();
        var decoder = new TextDecoder();
        var buffer = '';

        while (true) {
          var _ref = await reader.read();
          var done = _ref.done, value = _ref.value;
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          var lines = buffer.split('\n');
          buffer = lines.pop();

          for (var i = 0; i < lines.length; i++) {
            var line = lines[i];
            if (!line.startsWith('data: ')) continue;
            var data = line.slice(6);
            if (data === '[DONE]') break;
            try {
              var parsed = JSON.parse(data);
              if (parsed.error) {
                bubble.classList.remove('streaming');
                bubble.textContent = '⚠ ' + parsed.error;
                break;
              }
              if (parsed.content) {
                accumulated += parsed.content;
                bubble.textContent = accumulated;
                bubble.classList.add('streaming');
                _msgs().scrollTop = _msgs().scrollHeight;
              }
            } catch(e) { /* skip */ }
          }
        }

        bubble.classList.remove('streaming');
        if (accumulated) {
          _history.push({ role: 'assistant', content: accumulated });
          // Max History auf 20 Einträge begrenzen
          if (_history.length > 20) _history = _history.slice(-20);
        }
      }
    } catch (err) {
      bubble.remove();
      _appendError(err.message || 'Verbindungsfehler');
      _history.pop();
    }

    _streaming = false;
    if (btn) { btn.disabled = false; btn.classList.remove('loading'); }
    if (input) input.focus();
  }

  // ── Event Listener ────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', function() {
    var sendBtn = _sendBtn();
    var input   = _input();

    if (sendBtn) sendBtn.addEventListener('click', _send);

    if (input) {
      // Enter = senden, Shift+Enter = neue Zeile
      input.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' && !e.shiftKey) {
          e.preventDefault();
          _send();
        }
      });
      // Auto-resize textarea
      input.addEventListener('input', function() {
        this.style.height = 'auto';
        this.style.height = Math.min(this.scrollHeight, 100) + 'px';
      });
    }
  });

})();
