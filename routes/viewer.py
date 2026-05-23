"""
Sicherer In-Browser PDF-Viewer.

Hintergrund: User soll potenziell verseuchte PDFs NICHT in seinem lokalen
Reader (Adobe/Browser-PDF.js) oeffnen muessen — das ist genau der
Angriffsvektor. Statt dessen rendert der Server jede Seite mit PyMuPDF
zu einem PNG, und der Browser zeigt nur statische Bilder. Kein JS, kein
PDF-Parsing im Client = kein Exploit-Risiko.

Endpoints:
  GET /view/{analysis_id}                  -> HTML-Viewer
  GET /view/{analysis_id}/page/{n}.png     -> PNG der Seite n (0-indexiert)
  GET /view/{analysis_id}/page/{n}_box.png -> PNG mit gezeichneter Bounding-Box
                                              (Query: x0,y0,x1,y1 in PDF-pt)
"""
from __future__ import annotations
from pathlib import Path
from typing import Optional
import hashlib

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse, Response
from jinja2 import Environment, FileSystemLoader, select_autoescape

from config import UPLOAD_DIR
from database.db import get_analysis

router = APIRouter()

_jinja = Environment(
    loader=FileSystemLoader(str(Path(__file__).parent.parent / "templates")),
    autoescape=select_autoescape(["html", "xml"]),
    cache_size=0,
)


def _find_source_file(analysis_id: str) -> Optional[Path]:
    """Sucht die hochgeladene Datei unter UPLOAD_DIR/<id>.<ext>."""
    if not analysis_id or not all(c.isalnum() or c == "-" for c in analysis_id):
        return None
    for p in UPLOAD_DIR.glob(f"{analysis_id}.*"):
        if p.is_file():
            return p
    return None


_SECURITY_HEADERS = {
    # Browser darf KEIN JS aus dieser Response ausfuehren — wir liefern nur HTML+IMG
    "Content-Security-Policy": (
        "default-src 'none'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'none'; "
        "form-action 'none'; "
        "frame-ancestors 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "private, max-age=60",
}


@router.get("/view/{analysis_id}/page/{page_num}.png")
async def view_page_png(
    analysis_id: str,
    page_num: int,
    dpi: int = Query(default=144, ge=72, le=240),
):
    """Rendert eine einzelne Seite als PNG."""
    src = _find_source_file(analysis_id)
    if src is None:
        raise HTTPException(status_code=404, detail="Quell-Datei nicht gefunden")
    try:
        import fitz
    except ImportError:
        raise HTTPException(status_code=500, detail="PyMuPDF nicht verfuegbar")

    try:
        doc = fitz.open(src)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF-Open-Fehler: {e}")

    try:
        if page_num < 0 or page_num >= len(doc):
            raise HTTPException(status_code=404, detail=f"Seite {page_num} nicht vorhanden (0..{len(doc)-1})")
        page = doc[page_num]
        scale = dpi / 72.0
        pix = page.get_pixmap(matrix=fitz.Matrix(scale, scale), alpha=False)
        png_bytes = pix.tobytes("png")
    finally:
        doc.close()

    etag = hashlib.sha256(png_bytes).hexdigest()[:16]
    return Response(
        content=png_bytes,
        media_type="image/png",
        headers={**_SECURITY_HEADERS, "ETag": f'"{etag}"'},
    )


@router.get("/view/{analysis_id}/page/{page_num}_box.png")
async def view_page_with_bbox(
    analysis_id: str,
    page_num: int,
    x0: float = Query(...),
    y0: float = Query(...),
    x1: float = Query(...),
    y1: float = Query(...),
    dpi: int = Query(default=144, ge=72, le=240),
):
    """Wie oben, aber mit gezeichneter roter Bounding-Box (Koordinaten in PDF-pt)."""
    src = _find_source_file(analysis_id)
    if src is None:
        raise HTTPException(status_code=404)
    import fitz

    try:
        doc = fitz.open(src)
        if page_num < 0 or page_num >= len(doc):
            raise HTTPException(status_code=404)
        page = doc[page_num]
        scale = dpi / 72.0
        # Bounding-Box in Pixel-Koordinaten umrechnen
        rect = fitz.Rect(x0, y0, x1, y1)
        page.draw_rect(rect, color=(1, 0, 0), width=2.5)
        pix = page.get_pixmap(matrix=fitz.Matrix(scale, scale), alpha=False)
        png_bytes = pix.tobytes("png")
    finally:
        doc.close()

    return Response(content=png_bytes, media_type="image/png", headers=_SECURITY_HEADERS)


@router.get("/view/{analysis_id}", response_class=HTMLResponse)
async def view_pdf(analysis_id: str):
    """HTML-Seite die alle PDF-Seiten als PNGs untereinander zeigt."""
    result = await get_analysis(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Analyse nicht gefunden")
    src = _find_source_file(analysis_id)
    if src is None:
        raise HTTPException(
            status_code=410,
            detail="Quell-Datei wurde nicht aufbewahrt. Bitte das PDF neu hochladen — "
                   "der Viewer ist erst fuer Analysen verfuegbar die mit der neuen "
                   "Code-Version durchgelaufen sind.",
        )

    filename   = result.filename if hasattr(result, "filename") else "?"
    page_count = 1
    try:
        meta = getattr(result, "metadata", None)
        if meta and getattr(meta, "page_count", 0):
            page_count = int(meta.page_count)
    except Exception:
        pass

    template = _jinja.get_template("viewer.html")
    html = template.render(
        analysis_id=analysis_id,
        filename=filename,
        page_count=max(page_count, 1),
    )
    return HTMLResponse(content=html, headers=_SECURITY_HEADERS)
