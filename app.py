"""
PDF Forensik Analyzer — Entry Point
Startet FastAPI + uvicorn und öffnet automatisch den Browser.
"""
import webbrowser
import threading
import mimetypes
from pathlib import Path

import uvicorn

# MIME-Types explizit registrieren (wichtig für Linux/Docker auf Render)
mimetypes.add_type("application/javascript", ".js")
mimetypes.add_type("text/css", ".css")
mimetypes.add_type("image/svg+xml", ".svg")
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi.encoders import jsonable_encoder

from config import HOST, PORT, UPLOAD_DIR, IMAGES_DIR, REPORTS_DIR
from database.db import init_db

# Verzeichnisse sicherstellen
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
IMAGES_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


# ── Numpy-Typen für JSON-Serialisierung registrieren ──────────────────────────
def _register_numpy_encoders():
    try:
        import numpy as np
        from fastapi.encoders import ENCODERS_BY_TYPE
        ENCODERS_BY_TYPE[np.bool_]    = bool
        ENCODERS_BY_TYPE[np.integer]  = int
        ENCODERS_BY_TYPE[np.floating] = float
        ENCODERS_BY_TYPE[np.ndarray]  = lambda v: v.tolist()
        # Subklassen explizit registrieren (numpy hat viele davon)
        for t in [np.int8, np.int16, np.int32, np.int64,
                  np.uint8, np.uint16, np.uint32, np.uint64]:
            ENCODERS_BY_TYPE[t] = int
        for t in [np.float16, np.float32, np.float64]:
            ENCODERS_BY_TYPE[t] = float
    except ImportError:
        pass  # numpy nicht installiert — kein Problem

_register_numpy_encoders()


# FastAPI-App
app = FastAPI(
    title="PDF Forensik Analyzer",
    description="Forensische Analyse von PDF-Dokumenten",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# Statische Dateien & Templates
BASE_DIR = Path(__file__).parent
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


# ===== Seiten-Routen =====

@app.get("/", response_class=HTMLResponse)
async def index_page(request: Request):
    return templates.TemplateResponse(
        request, "index.html", {"active": "index"}
    )


@app.get("/history", response_class=HTMLResponse)
async def history_page(request: Request):
    return templates.TemplateResponse(
        request, "history.html", {"active": "history"}
    )


@app.get("/compare", response_class=HTMLResponse)
async def compare_page(request: Request):
    return templates.TemplateResponse(
        request, "compare.html", {"active": "compare"}
    )


# ===== API-Routen einbinden =====

from routes.analysis  import router as analysis_router
from routes.history   import router as history_router
from routes.compare   import router as compare_router
from routes.report    import router as report_router
from routes.batch     import router as batch_router
from routes.ai_review import router as ai_review_router
from routes.chat      import router as chat_router

app.include_router(analysis_router)
app.include_router(history_router)
app.include_router(compare_router)
app.include_router(report_router)
app.include_router(batch_router)
app.include_router(ai_review_router)
app.include_router(chat_router)


# ===== Startup =====

@app.on_event("startup")
async def on_startup():
    await init_db()
    from analyzers.pipeline import ANALYZER_NAMES
    print(f"\n{'='*50}")
    print(f"  PDF Forensik Analyzer gestartet")
    print(f"  {len(ANALYZER_NAMES)} Analyzer aktiv (Phase 1-6)")
    print(f"  http://{HOST}:{PORT}")
    print(f"  API-Docs: http://{HOST}:{PORT}/api/docs")
    print(f"{'='*50}\n")


# ===== Hauptprogramm =====

def open_browser():
    """Browser nach kurzem Delay öffnen (Warten bis Server ready)."""
    import time
    time.sleep(1.2)
    webbrowser.open(f"http://{HOST}:{PORT}")


if __name__ == "__main__":
    import os
    is_production = os.environ.get("HOST") == "0.0.0.0"

    # Browser nur lokal öffnen (nicht auf Server/Render)
    if not is_production:
        threading.Thread(target=open_browser, daemon=True).start()

    uvicorn.run(
        "app:app",
        host=HOST,
        port=PORT,
        reload=False,
        log_level="info",
    )
