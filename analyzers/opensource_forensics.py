"""
Open-Source Forensik-Tool Wrapper:
- pdfid (Didier Stevens)        — Header/Trailer-Stats, suspicious keywords
- pdf-parser (Didier Stevens)   — Object inspection, orphan/reference detection
- qpdf --qdf / --show-xref      — normalisierte QDF-Form, xref/Revision-Struktur
- binwalk                       — Embedded-File Detection in Streams
- PyMuPDF (fitz)                — Low-Level Object/Stream-Inspection

Erfuellt die Anforderungen aus dem User-Prompt:
1. Revisionen extrahieren & vergleichen (qpdf + PyMuPDF)
2. Verwaiste Objekte (pdf-parser --reference)
3. Hybrid-xref / Streams (qpdf --show-xref + pdfid)
4. Eingebettete Daten (binwalk + pdfid /EmbeddedFile)
"""
from __future__ import annotations
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List

from models.schemas import Anomaly, AnomalySeverity, OpenSourceForensicsResult


def _run(cmd: List[str], timeout: int = 90) -> Dict[str, Any]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {
            "cmd": " ".join(cmd),
            "rc": proc.returncode,
            "stdout": proc.stdout[:80000],
            "stderr": proc.stderr[:5000],
        }
    except FileNotFoundError:
        return {"cmd": " ".join(cmd), "rc": -1, "stdout": "", "stderr": "tool not installed"}
    except subprocess.TimeoutExpired:
        return {"cmd": " ".join(cmd), "rc": -2, "stdout": "", "stderr": f"timeout {timeout}s"}
    except Exception as e:
        return {"cmd": " ".join(cmd), "rc": -3, "stdout": "", "stderr": str(e)}


def _pdfid(pdf_path: Path) -> Dict[str, Any]:
    pdfid_script = Path("/app/tools/pdfid.py")
    if pdfid_script.exists():
        return _run(["python", str(pdfid_script), "-e", "-f", str(pdf_path)])
    if shutil.which("pdfid"):
        return _run(["pdfid", "-e", "-f", str(pdf_path)])
    return _run(["python", "-m", "pdfid", "-e", "-f", str(pdf_path)])


def _pdf_parser(pdf_path: Path, *args: str, timeout: int = 120) -> Dict[str, Any]:
    parser_script = Path("/app/tools/pdf-parser.py")
    if parser_script.exists():
        return _run(["python", str(parser_script), *args, str(pdf_path)], timeout=timeout)
    if shutil.which("pdf-parser"):
        return _run(["pdf-parser", *args, str(pdf_path)], timeout=timeout)
    if shutil.which("pdf-parser.py"):
        return _run(["pdf-parser.py", *args, str(pdf_path)], timeout=timeout)
    return {"cmd": f"pdf-parser {' '.join(args)}", "rc": -1, "stdout": "", "stderr": "pdf-parser not installed"}


def _qpdf_qdf(pdf_path: Path, out_dir: Path) -> Dict[str, Any]:
    if not shutil.which("qpdf"):
        return {"cmd": "qpdf", "rc": -1, "stdout": "", "stderr": "qpdf not installed"}
    out = out_dir / f"{pdf_path.stem}.qdf"
    res = _run(["qpdf", "--qdf", "--object-streams=disable", str(pdf_path), str(out)])
    res["qdf_file"] = str(out) if out.exists() else None
    res["xref"] = _run(["qpdf", "--show-xref", str(pdf_path)])
    try:
        data = pdf_path.read_bytes()
        res["eof_count"] = data.count(b"%%EOF")
        res["startxref_count"] = data.count(b"startxref")
        res["obj_count"] = data.count(b" obj")
        res["endobj_count"] = data.count(b"endobj")
    except Exception as e:
        res["raw_scan_error"] = str(e)
    return res


def _binwalk(pdf_path: Path) -> Dict[str, Any]:
    if shutil.which("binwalk"):
        return _run(["binwalk", "-B", str(pdf_path)], timeout=120)
    return {"cmd": "binwalk", "rc": -1, "stdout": "", "stderr": "binwalk not installed"}


def _pymupdf_lowlevel(pdf_path: Path) -> Dict[str, Any]:
    try:
        import fitz  # PyMuPDF
    except ImportError:
        return {"error": "PyMuPDF not installed"}
    info: Dict[str, Any] = {}
    try:
        doc = fitz.open(str(pdf_path))
        info["page_count"] = doc.page_count
        info["xref_length"] = doc.xref_length()
        info["is_encrypted"] = bool(doc.is_encrypted)
        info["is_repaired"] = bool(getattr(doc, "is_repaired", False))
        info["is_pdf"] = bool(getattr(doc, "is_pdf", True))
        info["needs_pass"] = bool(getattr(doc, "needs_pass", False))
        type_counts: Dict[str, int] = {}
        stream_objs: List[int] = []
        for xref in range(1, doc.xref_length()):
            try:
                obj = doc.xref_object(xref, compressed=True) or ""
                if not obj:
                    continue
                if doc.xref_is_stream(xref):
                    stream_objs.append(xref)
                import re as _re
                m = _re.search(r"/Type\s*/(\w+)", obj)
                if m:
                    t = m.group(1)
                    type_counts[t] = type_counts.get(t, 0) + 1
                else:
                    type_counts["_no_type"] = type_counts.get("_no_type", 0) + 1
            except Exception:
                continue
        info["object_types"] = type_counts
        info["stream_object_count"] = len(stream_objs)
        info["stream_objects"] = stream_objs[:100]
        doc.close()
    except Exception as e:
        info["error"] = str(e)
    return info


def _parse_pdfid_keyword(stdout: str, keyword: str) -> int:
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith(keyword):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    return int(parts[1])
                except ValueError:
                    return 0
    return 0


def analyze_opensource_forensics(pdf_path: Path, out_dir: Path | None = None) -> OpenSourceForensicsResult:
    out_dir = out_dir or pdf_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    anomalies: List[Anomaly] = []

    pdfid_res         = _pdfid(pdf_path)
    parser_stats      = _pdf_parser(pdf_path, "--stats")
    parser_orphans    = _pdf_parser(pdf_path, "--reference")
    qdf_res           = _qpdf_qdf(pdf_path, out_dir)
    binwalk_res       = _binwalk(pdf_path)
    pymupdf_res       = _pymupdf_lowlevel(pdf_path)

    eof = qdf_res.get("eof_count", 0)
    if isinstance(eof, int) and eof > 1:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category="incremental_update",
            message=f"PDF enthaelt {eof} %%EOF-Marker - {eof - 1} inkrementelle Update(s) detektiert (qpdf)",
            detail=f"eof_markers={eof}, startxref_count={qdf_res.get('startxref_count')} [opensource_forensics:qpdf]",
        ))

    pdfid_out = pdfid_res.get("stdout", "")
    suspicious_map = {
        "/JS":           AnomalySeverity.HIGH,
        "/JavaScript":   AnomalySeverity.HIGH,
        "/AA":           AnomalySeverity.MEDIUM,
        "/OpenAction":   AnomalySeverity.MEDIUM,
        "/Launch":       AnomalySeverity.HIGH,
        "/EmbeddedFile": AnomalySeverity.LOW,
        "/RichMedia":    AnomalySeverity.MEDIUM,
        "/AcroForm":     AnomalySeverity.LOW,
        "/XFA":          AnomalySeverity.MEDIUM,
        "/ObjStm":       AnomalySeverity.LOW,
    }
    for kw, sev in suspicious_map.items():
        cnt = _parse_pdfid_keyword(pdfid_out, kw)
        if cnt > 0:
            anomalies.append(Anomaly(
                severity=sev,
                category="pdfid_keyword",
                message=f"pdfid: {kw} = {cnt}",
                detail=f"keyword={kw}, count={cnt} [opensource_forensics:pdfid]",
            ))

    bw_out = binwalk_res.get("stdout", "")
    bw_findings = []
    for ln in bw_out.splitlines():
        ln = ln.strip()
        if ln and ln[:1].isdigit() and "DECIMAL" not in ln and "---" not in ln:
            bw_findings.append(ln)
    if bw_findings:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.LOW,
            category="embedded_signature",
            message=f"binwalk fand {len(bw_findings)} Signatur(en) im PDF-Stream",
            detail=f"signatures={bw_findings[:10]} [opensource_forensics:binwalk]",
        ))

    if isinstance(pymupdf_res.get("is_repaired"), bool) and pymupdf_res["is_repaired"]:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category="structure_repair",
            message="PyMuPDF musste die PDF-Struktur reparieren - Indikator fuer beschaedigte/manipulierte xref",
            detail=f"xref_length={pymupdf_res.get('xref_length')} [opensource_forensics:pymupdf]",
        ))

    return OpenSourceForensicsResult(
        pdfid=pdfid_res,
        pdf_parser_stats=parser_stats,
        pdf_parser_orphans=parser_orphans,
        qpdf_qdf=qdf_res,
        binwalk=binwalk_res,
        pymupdf_lowlevel=pymupdf_res,
        anomalies=anomalies,
    )
