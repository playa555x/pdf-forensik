# Claude CLI als KI-Backend (statt lokales Gemma)

Statt das lokale Ollama / Gemma-Modell anzusprechen, kann der PDF-Forensik-Service
das offizielle `claude` CLI als Subprocess aufrufen. Vorteile:

- **Schema-konforme Antworten** — kein Field-Aliasing-Geschwurbel mehr nötig.
- **Keine API-Kosten** — das CLI nutzt deine Pro/Max-**Subscription**, nicht den API-Key.
- **Kein SSH-Tunnel-Drama** — keine Pre-Warm-BAT, keine Reverse-Tunnel-Watchdogs.

Die Funktion liegt in `analyzers/ai_claude_cli.py`. Aktiviert wird sie über die
Umgebungsvariable `AI_BACKEND=claude` (Default: `ollama` = altes Verhalten).

---

## Einrichtung auf dem VPS (einmalig)

### 1. Claude CLI installieren

```bash
# Option A: offizieller Installer
curl -fsSL https://claude.ai/install.sh | bash

# Option B: via npm (falls Node 20+ vorhanden)
npm install -g @anthropic-ai/claude-code

# Verifizieren
claude --version
```

### 2. Login mit deiner Subscription

```bash
# Im SSH-Terminal auf dem VPS:
claude /login
```

Der Befehl gibt eine URL aus (`https://claude.ai/...`). Diese URL **am eigenen PC im
Browser** öffnen, die Subscription bestätigen → CLI bekommt den Auth-Token und
speichert ihn unter `~/.config/claude/` auf dem VPS.

**Wichtig:** Keine Auth-Files vom PC zum VPS kopieren — der Login-Flow erzeugt
einen eigenen, VPS-spezifischen Token. (Das war die ELITE-Regel "NIEMALS Credentials
kopieren".)

### 3. Service-Konfiguration

Das Drop-in `/etc/systemd/system/pdf-forensik.service.d/port.conf` erweitern:

```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c "PORT=9001 OLLAMA_BASE_URL=http://localhost:11500 \
  AI_BACKEND=claude \
  CLAUDE_CLI_PATH=/usr/local/bin/claude \
  CLAUDE_CLI_TIMEOUT=180 \
  exec /home/ubuntu/pdf-forensik/.venv/bin/python /home/ubuntu/pdf-forensik/app.py"
```

Dann:

```bash
sudo systemctl daemon-reload
sudo systemctl restart pdf-forensik.service
```

### 4. Test

```bash
# Force-Regen des KI-Reviews auf einer existierenden Analyse
ID="50a269f3-3f3c-4e1a-bf8a-4b1de3b03753"
curl -X POST "http://localhost:9001/ai-review/$ID?lang=de&force=true"
```

Im Response sollte `"model":"claude-cli"` stehen, nicht `"igorls/gemma-4-..."`.

---

## Konfiguration

| Env-Variable | Default | Bedeutung |
|---|---|---|
| `AI_BACKEND` | `ollama` | `claude` aktiviert den CLI-Pfad |
| `CLAUDE_CLI_PATH` | `claude` (per PATH) | Absoluter Pfad falls Custom-Install |
| `CLAUDE_CLI_MODEL` | (leer = CLI-Default) | z.B. `opus-4-7` oder `sonnet-4-6` |
| `CLAUDE_CLI_TIMEOUT` | `180` | Subprocess-Timeout in Sekunden |

---

## Fallback

Wenn `AI_BACKEND=claude` gesetzt aber das CLI nicht erreichbar ist, gibt der Endpoint
einen 500/`error`-Response zurück (statt still auf Ollama umzuschalten). Das ist
gewollt — false-positive "alles ok"-Antworten sollen nicht stillschweigend
generiert werden.

Möchte man echten Fallback (Claude → Ollama bei Fehler), gibt es eine TODO-Stelle
in `routes/ai_review.py:_do_ai_review` die das mit ~5 Zeilen Code aktivieren würde.

---

## Sicherheit

- Subprocess wird via `asyncio.create_subprocess_exec` mit ARGV-Liste aufgerufen
  (kein Shell, keine Injection).
- Der vom User gesteuerte Prompt geht als EIN einzelnes Argument durch — selbst
  enthaltene Quotes / Backticks sind harmlos.
- Auth-Token bleiben in `~/.config/claude/` auf dem VPS, werden NIE kopiert oder
  per Env weitergereicht.
