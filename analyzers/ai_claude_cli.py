"""
Claude-Backend via Bridge auf dem User-PC.

Der VPS spricht NIE direkt mit Claude/Anthropic. Stattdessen ruft der App-
Server localhost:11600 an (SSH-Reverse-Tunnel zum PC). Auf dem PC laeuft
`bridge/claude_bridge.py` welches das lokale `claude` CLI mit der Pro/Max-
Subscription des Users als Subprozess aufruft.

Vorteile:
- KEINE API-Kosten (Subscription)
- KEINE Credentials auf VPS (Memory-Regel "NIEMALS Credentials kopieren")
- Tunnel-Architektur identisch zu Ollama (Port 11500)

Konfiguration via .env / Service-Drop-in:
  AI_BACKEND=claude                   # ollama (default) oder claude
  CLAUDE_BRIDGE_URL=http://localhost:11600
  CLAUDE_BRIDGE_TOKEN=                # optional Shared-Secret Header
  CLAUDE_BRIDGE_TIMEOUT=180           # Sekunden
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

CLAUDE_BRIDGE_URL     = os.environ.get("CLAUDE_BRIDGE_URL", "http://localhost:11600").rstrip("/")
CLAUDE_BRIDGE_TOKEN   = os.environ.get("CLAUDE_BRIDGE_TOKEN", "").strip()
CLAUDE_BRIDGE_TIMEOUT = float(os.environ.get("CLAUDE_BRIDGE_TIMEOUT", "180"))
CLAUDE_BRIDGE_MODEL   = os.environ.get("CLAUDE_CLI_MODEL", "").strip()


async def _call_bridge(endpoint: str, prompt: str, system: Optional[str] = None) -> Dict[str, Any]:
    """POST zum Bridge-Endpoint. Liefert das CLI-JSON-Objekt direkt zurueck."""
    payload = {"prompt": prompt}
    if system:
        payload["system"] = system
    if CLAUDE_BRIDGE_MODEL:
        payload["model"] = CLAUDE_BRIDGE_MODEL
    headers = {"Content-Type": "application/json"}
    if CLAUDE_BRIDGE_TOKEN:
        headers["X-Bridge-Token"] = CLAUDE_BRIDGE_TOKEN

    url = f"{CLAUDE_BRIDGE_URL}{endpoint}"
    try:
        async with httpx.AsyncClient(timeout=CLAUDE_BRIDGE_TIMEOUT) as client:
            r = await client.post(url, headers=headers, json=payload)
            r.raise_for_status()
            return r.json()
    except httpx.ConnectError:
        return {"error": f"Claude-Bridge nicht erreichbar unter {url} — laeuft der Tunnel?"}
    except httpx.HTTPStatusError as e:
        return {"error": f"Bridge HTTP {e.response.status_code}: {e.response.text[:300]}"}
    except Exception as e:
        return {"error": f"Bridge-Aufruf fehlgeschlagen: {e}"}


def _strip_json_fence(text: str) -> str:
    """Markdown ```json fences abschneiden."""
    t = (text or "").strip()
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
    """Wie run_ai_review() im Ollama-Pfad, aber via Bridge auf PC."""
    # Lokal um zirkulaere Imports zu vermeiden
    from analyzers.ai_review import (
        _get_system_prompt,
        _build_user_prompt,
        _normalize_ai_review,
        _extract_json_from_response,
    )

    system = _get_system_prompt(lang)
    user_prompt = _build_user_prompt(analysis_data, lang=lang)

    cli_obj = await _call_bridge("/review", prompt=user_prompt, system=system)
    if "error" in cli_obj:
        return {"error": cli_obj["error"], "available": False}

    # Bridge gibt das rohe Claude-CLI-JSON-Objekt zurueck (result, session_id, is_error, ...)
    if cli_obj.get("is_error"):
        return {
            "error": f"Claude-CLI is_error: {cli_obj.get('result', '')[:300]}",
            "available": False,
        }

    raw_text = cli_obj.get("result") or ""
    if not raw_text.strip():
        return {"error": "Leere Antwort von Claude", "available": False}

    try:
        parsed = _extract_json_from_response(_strip_json_fence(raw_text))
    except Exception as e:
        return {
            "error": f"Claude-Antwort konnte nicht als JSON geparst werden: {e}",
            "raw_response": raw_text[:1500],
            "available": False,
        }

    review = _normalize_ai_review(parsed)
    model = (list((cli_obj.get("modelUsage") or {}).keys()) or [""])[0] or "claude-cli"
    review["model"] = model
    review["available"] = True
    sid = cli_obj.get("session_id")
    if sid:
        review["_session"] = sid
    # Diagnose: Duration durchreichen
    if cli_obj.get("duration_ms"):
        review["_duration_ms"] = cli_obj["duration_ms"]
    return review


# ──────────────────────────────────────────────────────────────────────
# Balanced-per-Finding
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

    cli_obj = await _call_bridge("/balanced", prompt=user_prompt, system=system)
    if "error" in cli_obj:
        return {"error": cli_obj["error"], "available": False, "findings": []}

    if cli_obj.get("is_error"):
        return {
            "error": f"Claude-CLI is_error: {cli_obj.get('result', '')[:300]}",
            "available": False,
            "findings": [],
        }

    raw_text = cli_obj.get("result") or ""
    if not raw_text.strip():
        return {"error": "Leere Antwort von Claude", "available": False, "findings": []}

    try:
        parsed = _extract_json_from_response(_strip_json_fence(raw_text))
    except Exception as e:
        return {
            "error": f"Claude-Antwort konnte nicht als JSON geparst werden: {e}",
            "raw_response": raw_text[:1500],
            "available": False,
            "findings": [],
        }

    if not isinstance(parsed.get("findings"), list):
        parsed["findings"] = []
    parsed["model"] = "claude-cli"
    parsed["available"] = True
    return parsed
