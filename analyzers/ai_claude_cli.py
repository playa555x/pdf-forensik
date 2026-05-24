"""
Claude-CLI-Backend fuer die KI-Reviews.

SICHERHEIT: Wir nutzen asyncio.create_subprocess_exec mit ARGV-LISTE
(kein Shell-String) — keine Command-Injection moeglich. Die Args sind
fest verdrahtet, nur der vom User gesteuerte Prompt geht als EINZELNES
Argument durch (Subprocess-Argv-Trennung).

Statt das Local-LLM (Ollama / gemma4) anzusprechen, wird hier das
`claude` CLI als Subprozess aufgerufen. Das CLI ist mit der Pro/Max-
Subscription des Users authentifiziert — pro Aufruf entstehen also
KEINE API-Kosten (Subscription-Tokens).

Konfiguration via .env / Service-Drop-in:
  AI_BACKEND=claude            # ollama (default) oder claude
  CLAUDE_CLI_PATH=/usr/local/bin/claude  # optional, default per PATH
  CLAUDE_CLI_MODEL=             # optional Model-Override (z.B. "opus-4-7")
  CLAUDE_CLI_TIMEOUT=180        # Sekunden

CLI-Aufruf: `claude -p <prompt> --output-format json`
Liefert ein JSON-Objekt mit `result` (string) und `session_id` (string).
Wir parsen den `result`-Text als unser eigenes Schema-JSON.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

CLAUDE_CLI_PATH    = os.environ.get("CLAUDE_CLI_PATH") or shutil.which("claude") or "claude"
CLAUDE_CLI_MODEL   = os.environ.get("CLAUDE_CLI_MODEL", "").strip()
CLAUDE_CLI_TIMEOUT = float(os.environ.get("CLAUDE_CLI_TIMEOUT", "180"))


def _is_available() -> bool:
    """Prueft ob das claude CLI existiert und aufrufbar ist."""
    return bool(shutil.which(CLAUDE_CLI_PATH) or os.path.isfile(CLAUDE_CLI_PATH))


async def _run_claude(prompt: str, system: Optional[str] = None) -> Dict[str, Any]:
    """
    Ruft `claude -p <prompt> --output-format json` als Subprozess auf.
    Returns:
      {"text": "...", "session_id": "...", "error": "..."}
    """
    if not _is_available():
        return {"error": f"claude CLI nicht gefunden ({CLAUDE_CLI_PATH})"}

    # ARGV-Liste (NICHT shell=True) — keine Injection moeglich
    args = [CLAUDE_CLI_PATH, "-p", "--output-format", "json"]
    if CLAUDE_CLI_MODEL:
        args += ["--model", CLAUDE_CLI_MODEL]
    if system:
        args += ["--append-system-prompt", system]
    args.append(prompt)

    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as e:
        return {"error": f"CLI-Aufruf fehlgeschlagen: {e}"}

    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=CLAUDE_CLI_TIMEOUT)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        return {"error": f"claude CLI Timeout nach {CLAUDE_CLI_TIMEOUT}s"}

    if proc.returncode != 0:
        return {
            "error": f"claude CLI exit={proc.returncode}: "
                     f"{(stderr_b or b'').decode('utf-8','replace')[:500]}",
        }

    out_text = (stdout_b or b"").decode("utf-8", "replace").strip()
    # Erwartetes Format: JSON-Objekt mit `result` (string) und `session_id` (string)
    try:
        cli_obj = json.loads(out_text)
        return {
            "text":       cli_obj.get("result") or "",
            "session_id": cli_obj.get("session_id") or "",
            "raw":        cli_obj,
        }
    except json.JSONDecodeError:
        # Fallback: stdout ist direkt der Text
        return {"text": out_text, "session_id": "", "raw": None}


def _strip_json_fence(text: str) -> str:
    """Markdown ```json fences abschneiden."""
    t = text.strip()
    if t.startswith("```"):
        first_nl = t.find("\n")
        if first_nl > 0:
            t = t[first_nl + 1:]
        if t.endswith("```"):
            t = t[: -3]
    return t.strip()


# ──────────────────────────────────────────────────────────────────────
# AI Review (Voll-Gutachten)
# ──────────────────────────────────────────────────────────────────────

async def run_ai_review_via_claude(analysis_data: Dict[str, Any], lang: str = "de") -> Dict[str, Any]:
    """
    Wie run_ai_review() im Ollama-Pfad — gibt aber via Claude CLI zurueck.
    Output-Schema identisch zum bestehenden run_ai_review.
    """
    # Import lokal um zirkulaere Imports zu vermeiden
    from analyzers.ai_review import (
        _get_system_prompt,
        _build_user_prompt,
        _normalize_ai_review,
        _extract_json_from_response,
    )

    system = _get_system_prompt(lang)
    user_prompt = _build_user_prompt(analysis_data, lang=lang)

    res = await _run_claude(user_prompt, system=system)
    if "error" in res:
        return {"error": res["error"], "available": False}

    raw_text = res.get("text") or ""
    if not raw_text.strip():
        return {"error": "Leere Antwort vom Claude CLI", "available": False}

    try:
        parsed = _extract_json_from_response(_strip_json_fence(raw_text))
    except Exception as e:
        return {
            "error": f"KI-Antwort konnte nicht als JSON geparst werden: {e}",
            "raw_response": raw_text[:1500],
            "available": False,
        }

    review = _normalize_ai_review(parsed)
    review["model"] = f"claude-cli{(':' + CLAUDE_CLI_MODEL) if CLAUDE_CLI_MODEL else ''}"
    review["available"] = True
    if res.get("session_id"):
        review["_session"] = res["session_id"]
    return review


# ──────────────────────────────────────────────────────────────────────
# Balanced-per-Finding (analog zu run_balanced_findings_review)
# ──────────────────────────────────────────────────────────────────────

async def run_balanced_findings_review_via_claude(
    findings: List[Any],
    doc_type: str = "unknown",
    workflow: str = "unknown",
    lang: str = "de",
) -> Dict[str, Any]:
    from analyzers.ai_review import (
        _BALANCED_SYS_DE,
        _BALANCED_SYS_EN,
        _build_balanced_user_prompt,
        _extract_json_from_response,
    )

    if not findings:
        return {"version": 1, "findings": [], "available": True, "model": "claude-cli"}

    system = _BALANCED_SYS_EN if lang == "en" else _BALANCED_SYS_DE
    user_prompt = _build_balanced_user_prompt(findings, doc_type, workflow, lang)

    res = await _run_claude(user_prompt, system=system)
    if "error" in res:
        return {"error": res["error"], "available": False, "findings": []}

    raw_text = res.get("text") or ""
    if not raw_text.strip():
        return {"error": "Leere Antwort vom Claude CLI", "available": False, "findings": []}

    try:
        parsed = _extract_json_from_response(_strip_json_fence(raw_text))
    except Exception as e:
        return {
            "error": f"KI-Antwort konnte nicht als JSON geparst werden: {e}",
            "raw_response": raw_text[:1500],
            "available": False,
            "findings": [],
        }

    if not isinstance(parsed.get("findings"), list):
        parsed["findings"] = []
    parsed["model"] = f"claude-cli{(':' + CLAUDE_CLI_MODEL) if CLAUDE_CLI_MODEL else ''}"
    parsed["available"] = True
    return parsed
