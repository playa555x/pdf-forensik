"""
Shadow-Attack & ISA-Detector: Erkennt Signatur-Umgehungsangriffe auf signierten PDFs.

Shadow Attack (2021, Müller et al.):
- Angreifer ersetzt sichtbaren Inhalt nach der Signatur durch andere Seiten
- Die Signatur bleibt mathematisch gültig, zeigt aber anderen Inhalt
- Erkennungsmerkmale: große Objekte außerhalb der ByteRange, versteckte Seiten

Incremental Saving Attack (ISA):
- Nach Signatur wird per Incremental Update neuer Inhalt hinzugefügt
- Signatur kann dadurch "ausgehebelt" werden ohne sie zu brechen
- Erkennungsmerkmale: Seiten-/Objekt-Änderungen nach Signatur-ByteRange

Signature Wrapping:
- Signatur-Dictionary wird verschoben, referenziert falschen Byte-Range
"""
from __future__ import annotations
import re
import struct
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

import pikepdf

from models.schemas import Anomaly, AnomalySeverity


def _get_signature_byte_ranges(pdf_path: Path) -> List[Dict[str, Any]]:
    """
    Extrahiert alle ByteRange-Angaben aus Signatur-Feldern.
    ByteRange = [[offset1, length1, offset2, length2]]
    Das signierte Dokument = Bytes [offset1..offset1+length1] + [offset2..offset2+length2]
    Der unsignierte Teil (Signatur-Blob selbst) liegt dazwischen.
    """
    ranges = []
    try:
        pdf = pikepdf.open(pdf_path)
        with pdf:
            acroform = pdf.Root.get("/AcroForm")
            if not acroform:
                return ranges

            fields = acroform.get("/Fields")
            if not fields:
                return ranges

            def _scan(field_list):
                for field in field_list:
                    try:
                        if not isinstance(field, pikepdf.Dictionary):
                            field = field.get_object()
                        ft = str(field.get("/FT", ""))
                        if ft == "/Sig":
                            v = field.get("/V")
                            if v and isinstance(v, pikepdf.Dictionary):
                                byte_range = v.get("/ByteRange")
                                sub_filter = str(v.get("/SubFilter", ""))
                                if byte_range:
                                    br = [int(x) for x in byte_range]
                                    if len(br) == 4:
                                        ranges.append({
                                            "byte_range":  br,
                                            "sub_filter":  sub_filter,
                                            "sig_offset":  br[0] + br[1],
                                            "sig_length":  br[2] - (br[0] + br[1]),
                                            "doc_end":     br[2] + br[3],
                                        })
                        kids = field.get("/Kids")
                        if kids:
                            _scan(kids)
                    except Exception:
                        continue

            _scan(fields)
    except Exception:
        pass
    return ranges


def _get_file_size(pdf_path: Path) -> int:
    try:
        return pdf_path.stat().st_size
    except Exception:
        return 0


def _check_shadow_attack(byte_ranges: List[Dict[str, Any]], file_size: int) -> List[Dict[str, Any]]:
    """
    Shadow-Attack-Erkennung:
    - Wenn der signierte ByteRange nicht das gesamte Dokument umfasst → verdächtig
    - Besonders: wenn große Menge an Bytes VOR offset[0] liegt (versteckte Objekte)
    """
    findings = []
    for br_info in byte_ranges:
        br = br_info["byte_range"]
        o1, l1, o2, l2 = br

        # Bytes vor der Signatur (sollte normalerweise 0 sein)
        prefix_size = o1
        # Bytes nach dem Ende der Signatur bis Dateiende
        doc_end     = o2 + l2
        suffix_size = file_size - doc_end

        findings.append({
            "byte_range":    br,
            "signed_from":   0,
            "signed_to":     doc_end,
            "prefix_bytes":  prefix_size,   # Bytes vor signiertem Bereich
            "suffix_bytes":  suffix_size,   # Bytes nach signiertem Bereich
            "covers_full":   (prefix_size == 0 and suffix_size <= 5),
            "sub_filter":    br_info["sub_filter"],
        })

    return findings


def _check_isa(byte_ranges: List[Dict[str, Any]], pdf_path: Path) -> List[Dict[str, Any]]:
    """
    ISA-Erkennung (Incremental Saving Attack):
    Prüft ob nach dem Signatur-ByteRange signifikante Objekte per Incremental Update hinzugefügt wurden.
    """
    findings = []
    file_size = _get_file_size(pdf_path)

    try:
        with open(pdf_path, "rb") as f:
            content = f.read()
    except Exception:
        return findings

    for br_info in byte_ranges:
        br     = br_info["byte_range"]
        doc_end = br[2] + br[3]

        if doc_end >= file_size - 10:
            findings.append({
                "isa_detected": False,
                "note":         "Signatur deckt das gesamte Dokument ab",
            })
            continue

        # Daten nach dem signierten Bereich
        after_sig = content[doc_end:]
        after_str = after_sig.decode("latin-1", errors="replace")

        # Prüfe auf xref/trailer nach der Signatur
        has_xref_after = b"xref" in after_sig or b"/XRef" in after_sig
        has_obj_after  = bool(re.search(rb"\d+\s+0\s+obj", after_sig))
        has_page_changes = "/Page" in after_str or "/Pages" in after_str

        findings.append({
            "isa_detected":     has_xref_after or has_obj_after,
            "bytes_after_sig":  len(after_sig),
            "has_xref_after":   has_xref_after,
            "has_obj_after":    has_obj_after,
            "has_page_changes": has_page_changes,
            "doc_end_offset":   doc_end,
            "file_size":        file_size,
            "note":             f"{len(after_sig)} Bytes nach signiertem Bereich" +
                                (" — Objekte/xref gefunden!" if has_obj_after else ""),
        })

    return findings


def _check_signature_wrapping(pdf_path: Path) -> Dict[str, Any]:
    """
    Signature Wrapping: Prüft ob das Signatur-Objekt korrekt referenziert wird.
    Vereinfachte Prüfung: Sucht nach mehreren /ByteRange-Definitionen im Dokument.
    """
    try:
        with open(pdf_path, "rb") as f:
            content = f.read()
        count = content.count(b"/ByteRange")
        return {
            "byte_range_occurrences": count,
            "suspicious": count > 2,
            "note": f"/ByteRange {count}x gefunden" + (" — mehr als erwartet" if count > 2 else ""),
        }
    except Exception:
        return {"byte_range_occurrences": 0, "suspicious": False}


def analyze_shadow_attacks(pdf_path: Path) -> Dict[str, Any]:
    """Hauptfunktion: Erkennt Shadow-Attack, ISA und Signature-Wrapping."""
    anomalies: List[Anomaly] = []
    file_size = _get_file_size(pdf_path)

    byte_ranges = _get_signature_byte_ranges(pdf_path)

    if not byte_ranges:
        return {
            "has_signature":      False,
            "shadow_analysis":    [],
            "isa_analysis":       [],
            "wrapping_check":     {},
            "anomalies":          [],
        }

    shadow_analysis = _check_shadow_attack(byte_ranges, file_size)
    isa_analysis    = _check_isa(byte_ranges, pdf_path)
    wrapping_check  = _check_signature_wrapping(pdf_path)

    # Anomalien
    for sa in shadow_analysis:
        if not sa.get("covers_full"):
            extra = sa.get("prefix_bytes", 0) + sa.get("suffix_bytes", 0)
            anomalies.append(Anomaly(
                severity=AnomalySeverity.HIGH,
                category="shadow_attack",
                message=f"Signatur deckt nicht das gesamte Dokument ab — Shadow-Attack möglich",
                detail=f"{sa.get('prefix_bytes', 0)} Bytes vor + {sa.get('suffix_bytes', 0)} Bytes nach signiertem Bereich",
            ))

    for isa in isa_analysis:
        if isa.get("isa_detected"):
            anomalies.append(Anomaly(
                severity=AnomalySeverity.HIGH,
                category="shadow_attack",
                message=f"ISA: Objekte nach Signatur-ByteRange gefunden — mögliche ISA-Manipulation",
                detail=isa.get("note", ""),
            ))
        elif isa.get("bytes_after_sig", 0) > 100:
            anomalies.append(Anomaly(
                severity=AnomalySeverity.MEDIUM,
                category="shadow_attack",
                message=f"ISA: {isa.get('bytes_after_sig', 0)} Bytes nach signiertem Bereich",
                detail="Incremental Update nach Signierung — Inhalt könnte verändert worden sein",
            ))

    if wrapping_check.get("suspicious"):
        anomalies.append(Anomaly(
            severity=AnomalySeverity.HIGH,
            category="shadow_attack",
            message="Signature Wrapping: Mehrere /ByteRange-Definitionen im Dokument",
            detail=wrapping_check.get("note", ""),
        ))

    return {
        "has_signature":   True,
        "signature_count": len(byte_ranges),
        "shadow_analysis": shadow_analysis,
        "isa_analysis":    isa_analysis,
        "wrapping_check":  wrapping_check,
        "anomalies":       anomalies,
    }
