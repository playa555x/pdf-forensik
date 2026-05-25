"""
Claude-Bridge auf dem lokalen PC.

SICHERHEIT: Alle Subprozess-Aufrufe via ARGV-Liste (kein Shell, keine Injection).
- asyncio.create_subprocess_exec mit argv
- subprocess.run mit argv-Liste fuer --version Check
Eingaben werden nie als Shell-String interpretiert.

Wrappt das lokale `claude` CLI (das mit der Pro/Max-Subscription des Users
authentifiziert ist) als HTTP-Service. Wird vom PDF-Forensik-Service auf
dem VPS via SSH-Reverse-Tunnel (PC:11600 -> VPS:11600) angesprochen.

Auth bleibt auf dem PC (~/.claude/.credentials.json), wird NICHT exportiert.

Start:
  python claude_bridge.py
"""
from __future__ import annotations
import asyncio
import json
import os
import shutil
from typing import Any, Dict, Optional

import uvicorn
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

CLAUDE_BIN     = os.environ.get("CLAUDE_BIN") or shutil.which("claude") or "claude"
BRIDGE_TOKEN   = os.environ.get("CLAUDE_BRIDGE_TOKEN", "").strip()
BIND_HOST      = os.environ.get("BRIDGE_HOST", "127.0.0.1")
BIND_PORT      = int(os.environ.get("BRIDGE_PORT", "11600"))
CLI_TIMEOUT    = float(os.environ.get("CLI_TIMEOUT", "180"))

app = FastAPI(title="Claude-Bridge", version="1.0")


def _check_token(x_bridge_token: Optional[str]) -> None:
    """Optionaler Token-Schutz. Wenn BRIDGE_TOKEN gesetzt, muss Header passen."""
    if BRIDGE_TOKEN and (x_bridge_token or "").strip() != BRIDGE_TOKEN:
        raise HTTPException(status_code=401, detail="invalid bridge token")


async def _call_claude_cli(prompt: str, system: Optional[str], model: Optional[str]) -> Dict[str, Any]:
    """Asynchroner Aufruf des claude CLI via argv-Liste."""
    args = [CLAUDE_BIN, "-p", "--output-format", "json"]
    if model:
        args += ["--model", model]
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
        return {"error": f"claude CLI not found: {e}"}

    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=CLI_TIMEOUT)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        return {"error": f"claude CLI timeout after {CLI_TIMEOUT}s"}

    if proc.returncode != 0:
        return {
            "error": f"claude exit={proc.returncode}: "
                     f"{(stderr_b or b'').decode('utf-8','replace')[:500]}",
        }

    out = (stdout_b or b"").decode("utf-8", "replace").strip()
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {"result": out, "session_id": "", "raw_output": out[:2000]}


async def _claude_version() -> str:
    """claude --version asynchron lesen."""
    try:
        proc = await asyncio.create_subprocess_exec(
            CLAUDE_BIN, "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
        return (out or b"").decode("utf-8", "replace").strip()
    except Exception as e:
        return f"version-check-failed: {e}"


@app.get("/healthz")
async def health():
    """Schneller Health-Check + claude-Version."""
    v = await _claude_version()
    return {
        "ok": True,
        "claude_bin": CLAUDE_BIN,
        "claude_version": v,
        "token_protected": bool(BRIDGE_TOKEN),
    }


@app.post("/review")
async def review(req: Request, x_bridge_token: Optional[str] = Header(default=None)):
    _check_token(x_bridge_token)
    body = await req.json()
    prompt = body.get("prompt") or ""
    if not prompt:
        raise HTTPException(status_code=400, detail="prompt missing")
    return await _call_claude_cli(
        prompt=prompt,
        system=body.get("system"),
        model=body.get("model"),
    )


@app.post("/balanced")
async def balanced(req: Request, x_bridge_token: Optional[str] = Header(default=None)):
    """Semantisch getrennter Endpoint, gleicher Code-Pfad."""
    _check_token(x_bridge_token)
    body = await req.json()
    prompt = body.get("prompt") or ""
    if not prompt:
        raise HTTPException(status_code=400, detail="prompt missing")
    return await _call_claude_cli(
        prompt=prompt,
        system=body.get("system"),
        model=body.get("model"),
    )


if __name__ == "__main__":
    print(f"[bridge] Starting on {BIND_HOST}:{BIND_PORT}")
    print(f"[bridge] CLAUDE_BIN={CLAUDE_BIN}")
    print(f"[bridge] Token protection: {'ON' if BRIDGE_TOKEN else 'OFF (loopback only)'}")
    uvicorn.run(app, host=BIND_HOST, port=BIND_PORT, log_level="info")
