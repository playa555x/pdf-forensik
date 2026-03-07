"""
Embedded Files + Annotations + Object Streams Analyzer.
Erkennt versteckte Dateien, Annotations mit verdächtigem Inhalt und komprimierte Object Streams.
"""
from __future__ import annotations
import hashlib
from pathlib import Path
from typing import List, Dict, Any

import pikepdf

from models.schemas import EmbeddedFilesResult, Anomaly, AnomalySeverity

# Gefährliche Dateierweiterungen in eingebetteten Dateien
_DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
    ".scr", ".com", ".pif", ".lnk", ".reg", ".msi", ".sh", ".py",
}

_SUSPICIOUS_MIME = {
    "application/x-msdownload",
    "application/x-executable",
    "application/x-sh",
    "application/javascript",
}


def analyze_embedded_files(pdf_path: Path) -> EmbeddedFilesResult:
    anomalies:      list[Anomaly]      = []
    embedded_files: List[Dict[str, Any]] = []
    annotations:    List[Dict[str, Any]] = []
    obj_streams:    List[Dict[str, Any]] = []

    try:
        pdf = pikepdf.open(pdf_path)
    except Exception as e:
        return EmbeddedFilesResult(anomalies=[
            Anomaly(severity=AnomalySeverity.HIGH, category="embedded_files",
                    message="PDF konnte nicht geöffnet werden", detail=str(e))
        ])

    with pdf:
        catalog = pdf.Root

        # ===== 1. Eingebettete Dateien =====
        try:
            if "/Names" in catalog:
                names = catalog["/Names"]
                if "/EmbeddedFiles" in names:
                    ef_tree = names["/EmbeddedFiles"]
                    _scan_ef_tree(ef_tree, embedded_files, anomalies)
        except Exception:
            pass

        # Auch direkte /EmbeddedFile Streams in allen Objekten suchen
        try:
            for obj in pdf.objects:
                try:
                    if not hasattr(obj, "keys"):
                        continue
                    if str(obj.get("/Type", "")) == "/Filespec" or "/EF" in obj:
                        fname = str(obj.get("/F", obj.get("/UF", "unbekannt")))
                        ef = obj.get("/EF", {})
                        if ef and hasattr(ef, "get"):
                            stream = ef.get("/F") or ef.get("/UF")
                            if stream:
                                try:
                                    data = bytes(stream.read_bytes())
                                    file_hash = hashlib.sha256(data).hexdigest()
                                    entry = {
                                        "filename": fname,
                                        "size_bytes": len(data),
                                        "sha256": file_hash,
                                        "mime_type": str(stream.get("/Subtype", "?")) if hasattr(stream, "get") else "?",
                                    }
                                    # Duplikate vermeiden
                                    if not any(e.get("sha256") == file_hash for e in embedded_files):
                                        embedded_files.append(entry)
                                        _check_embedded_file(entry, anomalies)
                                except Exception:
                                    pass
                except Exception:
                    continue
        except Exception:
            pass

        # ===== 2. Annotations pro Seite =====
        for page_num, page in enumerate(pdf.pages):
            try:
                annots = page.get("/Annots", [])
                for annot in annots:
                    try:
                        annot_type = str(annot.get("/Subtype", "?"))
                        contents   = str(annot.get("/Contents", ""))
                        rect       = list(annot.get("/Rect", []))
                        flags      = int(annot.get("/F", 0))

                        # Versteckte Annotation (Flag Bit 1 = Hidden, Bit 6 = NoView)
                        is_hidden  = bool(flags & 0x02) or bool(flags & 0x20)

                        entry = {
                            "page":      page_num + 1,
                            "type":      annot_type,
                            "contents":  contents[:200] if contents else None,
                            "is_hidden": is_hidden,
                            "flags":     flags,
                        }

                        # URI aus Link-Annotation
                        if annot_type == "/Link":
                            action = annot.get("/A", {})
                            if hasattr(action, "get"):
                                uri = str(action.get("/URI", ""))
                                if uri:
                                    entry["uri"] = uri

                        annotations.append(entry)

                        if is_hidden:
                            anomalies.append(Anomaly(
                                severity=AnomalySeverity.MEDIUM,
                                category="embedded_files",
                                message=f"Versteckte Annotation auf Seite {page_num+1} (Typ: {annot_type})",
                                detail=f"Flags: {flags} | Inhalt: {contents[:100] if contents else '—'}",
                            ))
                    except Exception:
                        continue
            except Exception:
                continue

        # ===== 3. Object Streams (/ObjStm) =====
        try:
            for obj in pdf.objects:
                try:
                    if not hasattr(obj, "keys"):
                        continue
                    if str(obj.get("/Type", "")) == "/ObjStm":
                        n = int(obj.get("/N", 0))
                        first = int(obj.get("/First", 0))
                        try:
                            raw = bytes(obj.read_bytes())
                            size = len(raw)
                        except Exception:
                            size = 0
                        obj_streams.append({
                            "object_count": n,
                            "first_offset": first,
                            "size_bytes": size,
                        })
                except Exception:
                    continue
        except Exception:
            pass

        if obj_streams:
            total_objs = sum(o["object_count"] for o in obj_streams)
            anomalies.append(Anomaly(
                severity=AnomalySeverity.INFO,
                category="embedded_files",
                message=f"{len(obj_streams)} Object-Stream(s) mit insgesamt {total_objs} komprimierten Objekten",
                detail="Object Streams komprimieren PDF-Objekte — normale Optimierung, kann aber Inhalte verschleiern",
            ))

        # Zusammenfassung embedded files
        if embedded_files:
            anomalies.append(Anomaly(
                severity=AnomalySeverity.HIGH,
                category="embedded_files",
                message=f"{len(embedded_files)} eingebettete Datei(en) gefunden",
                detail=", ".join(e["filename"] for e in embedded_files[:5]),
            ))

    hidden_annot_count = sum(1 for a in annotations if a.get("is_hidden"))

    return EmbeddedFilesResult(
        embedded_file_count=len(embedded_files),
        embedded_files=embedded_files,
        annotation_count=len(annotations),
        annotations=annotations[:50],  # max 50 in DB
        hidden_annotation_count=hidden_annot_count,
        obj_stream_count=len(obj_streams),
        obj_streams=obj_streams,
        anomalies=anomalies,
    )


def _scan_ef_tree(node, embedded_files: list, anomalies: list, depth=0):
    if depth > 5:
        return
    try:
        if "/Names" in node:
            names_list = list(node["/Names"])
            for i in range(0, len(names_list) - 1, 2):
                try:
                    fname = str(names_list[i])
                    filespec = names_list[i + 1]
                    ef = filespec.get("/EF", {})
                    if ef and hasattr(ef, "get"):
                        stream = ef.get("/F") or ef.get("/UF")
                        if stream:
                            try:
                                data = bytes(stream.read_bytes())
                                entry = {
                                    "filename": fname,
                                    "size_bytes": len(data),
                                    "sha256": hashlib.sha256(data).hexdigest(),
                                    "mime_type": str(stream.get("/Subtype", "?")) if hasattr(stream, "get") else "?",
                                }
                                embedded_files.append(entry)
                                _check_embedded_file(entry, anomalies)
                            except Exception:
                                pass
                except Exception:
                    continue
        if "/Kids" in node:
            for kid in node["/Kids"]:
                _scan_ef_tree(kid, embedded_files, anomalies, depth + 1)
    except Exception:
        pass


def _check_embedded_file(entry: dict, anomalies: list):
    fname = entry.get("filename", "").lower()
    mime  = entry.get("mime_type", "").lower()

    ext = "." + fname.rsplit(".", 1)[-1] if "." in fname else ""
    if ext in _DANGEROUS_EXTENSIONS:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.HIGH,
            category="embedded_files",
            message=f"Gefährliche eingebettete Datei: '{entry['filename']}'",
            detail=f"Dateierweiterung '{ext}' kann ausführbaren Code enthalten",
        ))
    elif any(m in mime for m in _SUSPICIOUS_MIME):
        anomalies.append(Anomaly(
            severity=AnomalySeverity.HIGH,
            category="embedded_files",
            message=f"Verdächtiger MIME-Type: '{mime}' für Datei '{entry['filename']}'",
        ))
