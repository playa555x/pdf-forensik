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
    # Sicherheits-Ueberlegung: das PDF wird NIE im Browser geladen — wir
    # rendern serverseitig zu PNG. Unser eigenes Viewer-JS (only-self) darf
    # laufen, um Overlays + Sidebar zu bauen. PDF-Bytes erreichen den Browser
    # NICHT, also bringt das auch keinen Angriffsvektor.
    "Content-Security-Policy": (
        "default-src 'none'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "connect-src 'self'; "
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


@router.get("/view/{analysis_id}/markers.json")
async def view_markers(analysis_id: str):
    """
    Liefert pro Seite die forensischen Marker mit Koordinaten:
      - image_forensics: Bilder die ELA/Copy-Move-Anomalien haben
      - hidden_text:     versteckte Text-Bloecke
      - redactions:      ausgewiesene Redaction-Annotations (separat von Annotations-Sidebar)

    Output:
      {"pages": [{"page": 0, "width": w, "height": h, "markers": [...]}]}
      marker = {kind, rect_top, severity, category, message, detail?}
    """
    src = _find_source_file(analysis_id)
    if src is None:
        raise HTTPException(status_code=404, detail="Quell-Datei nicht gefunden")
    result = await get_analysis(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Analyse nicht gefunden")
    try:
        import fitz
    except ImportError:
        raise HTTPException(status_code=500, detail="PyMuPDF nicht verfuegbar")

    data = result.model_dump() if hasattr(result, "model_dump") else (result.dict() if hasattr(result, "dict") else {})

    # ──────────────────────────────────────────────────────
    # Pro Seite ein dict bauen, dann auffuellen
    # ──────────────────────────────────────────────────────
    pages_map: dict = {}

    try:
        doc = fitz.open(src)
        # Seitendimensionen initialisieren
        for i in range(len(doc)):
            page = doc[i]
            pages_map[i] = {
                "page":   i,
                "width":  float(page.rect.width),
                "height": float(page.rect.height),
                "markers": [],
            }

        # ────────────────────────────────────────────────
        # 1) Image Forensics: Bilder mit Anomalien lokalisieren
        # ────────────────────────────────────────────────
        img_an = (data.get("image_forensics") or {}).get("anomalies") or []
        # Image-Forensics meldet typischerweise pro Bild "Seite N (Name)"
        # → wir mappen alle Bilder pro Seite ueber PyMuPDF auf ihre Bboxes
        # und matchen ueber den Seiten-Index. Bei mehreren Bildern pro Seite
        # nehmen wir alle (besser zu viele Boxen als zu wenige).
        flagged_pages: set = set()
        for anom in img_an:
            msg = (anom.get("message") if isinstance(anom, dict) else getattr(anom, "message", "")) or ""
            # Erwarte Format "...Seite N..." oder "...page N..."
            import re as _re
            m = _re.search(r"[Ss]eite\s+(\d+)|page\s+(\d+)", msg)
            if m:
                page_one = int(m.group(1) or m.group(2))
                flagged_pages.add(page_one - 1)
        for p_idx in flagged_pages:
            if p_idx < 0 or p_idx >= len(doc):
                continue
            page = doc[p_idx]
            for img in (page.get_images(full=True) or []):
                try:
                    xref = img[0]
                    rects = page.get_image_rects(xref) or []
                    for r in rects:
                        pages_map[p_idx]["markers"].append({
                            "kind":     "image_forensics",
                            "rect_top": [float(r.x0), float(r.y0), float(r.x1), float(r.y1)],
                            "severity": "MEDIUM",
                            "category": "image_forensics",
                            "message":  "Bild mit forensischer Auffaelligkeit",
                            "detail":   f"PyMuPDF xref={xref}",
                        })
                except Exception:
                    continue

        # ────────────────────────────────────────────────
        # 2) Hidden Text: Bloecke mit coords liefern
        # ────────────────────────────────────────────────
        hidden = (data.get("hidden_text") or {}).get("hidden_blocks") or []
        for blk in hidden:
            if not isinstance(blk, dict):
                continue
            p = blk.get("page")
            coords = blk.get("coords")  # erwartet {x0,y0,x1,y1}
            if not isinstance(p, int) or not isinstance(coords, dict):
                continue
            p_idx = p - 1 if p >= 1 else p  # 1-basiert -> 0-basiert
            if p_idx not in pages_map:
                continue
            try:
                pages_map[p_idx]["markers"].append({
                    "kind":     "hidden_text",
                    "rect_top": [
                        float(coords.get("x0", 0)),
                        float(coords.get("y0", 0)),
                        float(coords.get("x1", 0)),
                        float(coords.get("y1", 0)),
                    ],
                    "severity": "HIGH",
                    "category": "hidden_text",
                    "message":  "Versteckter Text-Block",
                    "detail":   (blk.get("text") or "")[:200],
                })
            except Exception:
                continue

        # ────────────────────────────────────────────────
        # 3) Redaction-Annotations (extra-rot)
        # ────────────────────────────────────────────────
        for p_idx in range(len(doc)):
            page = doc[p_idx]
            try:
                annot_iter = page.annots() or []
            except Exception:
                annot_iter = []
            for annot in annot_iter:
                try:
                    if (annot.type[1] if hasattr(annot, "type") else "").lower() == "redact":
                        r = annot.rect
                        pages_map[p_idx]["markers"].append({
                            "kind":     "redaction",
                            "rect_top": [float(r.x0), float(r.y0), float(r.x1), float(r.y1)],
                            "severity": "HIGH",
                            "category": "redaction",
                            "message":  "Redaction-Markierung",
                            "detail":   (annot.info or {}).get("content", "") or "",
                        })
                except Exception:
                    continue

        doc.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Marker-Extract-Fehler: {e}")

    pages_out = [pages_map[i] for i in sorted(pages_map.keys())]
    total = sum(len(p["markers"]) for p in pages_out)
    return {"analysis_id": analysis_id, "total": total, "pages": pages_out}


@router.get("/view/{analysis_id}/annotations.json")
async def view_annotations(analysis_id: str):
    """
    Liefert pro Seite die Annotations + Page-Dimensionen.
    Output:
      {
        "pages": [
          {"page": 0, "width": 612.0, "height": 792.0,
           "annotations": [{"subtype": "Text", "rect": [x0,y0,x1,y1],
                            "author": "...", "contents": "...",
                            "mod_date_iso": "..."}]}
        ]
      }
    Koordinaten sind in PDF-pt (Origin links-OBEN bereits umgerechnet: y_top = page_h - y1).
    """
    src = _find_source_file(analysis_id)
    if src is None:
        raise HTTPException(status_code=404, detail="Quell-Datei nicht gefunden")
    try:
        import fitz
    except ImportError:
        raise HTTPException(status_code=500, detail="PyMuPDF nicht verfuegbar")

    pages_out = []
    try:
        doc = fitz.open(src)
        for page_idx in range(len(doc)):
            page = doc[page_idx]
            pw, ph = float(page.rect.width), float(page.rect.height)
            anns = []

            # 1) Markup/Sticky/Stamp Annotations via page.annots()
            try:
                annot_iter = page.annots() or []
            except Exception:
                annot_iter = []
            for annot in annot_iter:
                try:
                    r = annot.rect
                    info = annot.info or {}
                    anns.append({
                        "subtype":   annot.type[1] if hasattr(annot, "type") else "?",
                        "rect_pdf":  [float(r.x0), float(r.y0), float(r.x1), float(r.y1)],
                        "rect_top":  [float(r.x0), float(r.y0), float(r.x1), float(r.y1)],
                        "author":    info.get("title") or "",
                        "contents":  info.get("content") or "",
                        "name":      info.get("name") or "",
                        "mod_date":  info.get("modDate") or "",
                        "flags":     int(annot.flags or 0),
                    })
                except Exception:
                    continue

            # 2) Link-Annotations via page.get_links() — PyMuPDF schließt /Link
            # aus page.annots() aus und liefert sie ueber den separaten Endpoint.
            try:
                link_iter = page.get_links() or []
            except Exception:
                link_iter = []
            for lnk in link_iter:
                try:
                    rect = lnk.get("from")
                    if rect is None:
                        continue
                    # rect kann fitz.Rect oder Tuple sein
                    if hasattr(rect, "x0"):
                        x0, y0, x1, y1 = float(rect.x0), float(rect.y0), float(rect.x1), float(rect.y1)
                    else:
                        x0, y0, x1, y1 = float(rect[0]), float(rect[1]), float(rect[2]), float(rect[3])
                    # Inhalt: URI oder GoTo-Ziel oder interner Verweis
                    contents = ""
                    kind = lnk.get("kind")
                    if kind == 2 and lnk.get("uri"):           # LINK_URI
                        contents = "URI: " + str(lnk["uri"])
                    elif kind == 1:                             # LINK_GOTO
                        contents = "Interner Sprung -> Seite " + str(lnk.get("page", "?") + 1 if isinstance(lnk.get("page"), int) else lnk.get("page", "?"))
                    elif kind == 3:                             # LINK_NAMED
                        contents = "Named Destination: " + str(lnk.get("name", "?"))
                    elif kind == 4 and lnk.get("file"):         # LINK_LAUNCH
                        contents = "Launch: " + str(lnk["file"])
                    else:
                        contents = "Link (kind=" + str(kind) + ")"
                    anns.append({
                        "subtype":   "Link",
                        "rect_pdf":  [x0, y0, x1, y1],
                        "rect_top":  [x0, y0, x1, y1],
                        "author":    "",
                        "contents":  contents,
                        "name":      lnk.get("name", "") or "",
                        "mod_date":  "",
                        "flags":     0,
                    })
                except Exception:
                    continue

            pages_out.append({
                "page": page_idx,
                "width": pw,
                "height": ph,
                "annotations": anns,
            })
        doc.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Annotation-Extract-Fehler: {e}")

    return {"analysis_id": analysis_id, "pages": pages_out}


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
