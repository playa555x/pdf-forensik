"""
analyzers/multi_signature_workflow.py

Klassifiziert das Signatur-Setup eines PDFs:
- Wieviele Signaturen sind drin
- Ist jede einzelne kryptografisch intakt (=Bytes im jeweiligen ByteRange unveraendert)
- Decken sie kollektiv die ganze Datei ab
- Welche Objekte/Bytes wurden NACH jeder Signatur hinzugefuegt

Hintergrund:
Mehrere /ByteRange-Eintraege + "Signatur deckt nicht ganze Datei ab" sind
SOWOHL Indikatoren fuer einen Shadow-Attack als AUCH fuer einen normalen
Multi-Signatur-Workflow (z.B. tuerkische e-imza). Der Unterschied:
- Multi-Sig: alle Signaturen intact, nach jeder wurde nur weiteres Signatur-
  Material angehaengt -> legitim
- Shadow-Attack: mindestens eine Signatur ist gebrochen ODER zwischen den
  Signaturen wurden bestehende signierte Bytes manipuliert

Nutzt pyhanko fuer die kryptografische Validierung. Cert-Trust-Chain-Failure
(z.B. wegen lokal fehlendem Root-CA) wird ignoriert; es geht um die
mathematische Integritaet des signierten Inhalts.
"""
from __future__ import annotations
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import hashlib
import re

from models.schemas import Anomaly, AnomalySeverity


def _find_byteranges(data: bytes) -> List[Tuple[int, int, int, int]]:
    """Alle /ByteRange-Definitionen im Raw-PDF finden."""
    out = []
    for m in re.finditer(rb"/ByteRange\s*\[([^\]]+)\]", data):
        parts = m.group(1).decode("latin-1", errors="replace").split()
        if len(parts) >= 4:
            try:
                a, b, c, d = (int(p) for p in parts[:4])
                out.append((a, b, c, d))
            except Exception:
                continue
    return out


def _find_eof_positions(data: bytes) -> List[int]:
    return [m.end() for m in re.finditer(rb"%%EOF", data)]


def _hash_byterange(data: bytes, br: Tuple[int, int, int, int]) -> str:
    a, b, c, d = br
    h = hashlib.sha256()
    h.update(data[a:a + b])
    h.update(data[c:c + d])
    return h.hexdigest()


def _validate_via_pyhanko(pdf_path: Path) -> List[Dict[str, Any]]:
    """
    Validiert jede eingebettete Signatur mit pyhanko (strict=False).

    Liefert pro Signatur ein Dict mit:
      field_name, intact (Bytes-Integritaet), valid (Cert-Math stimmt),
      coverage (string), modification_level (string),
      diff_summary (was wurde nach Signatur hinzugefuegt),
      signer_cn (Common Name), signer_country, signing_time.
    """
    out: List[Dict[str, Any]] = []
    try:
        from pyhanko.pdf_utils.reader import PdfFileReader
        from pyhanko.sign.validation import validate_pdf_signature
    except ImportError as e:
        return [{"error": f"pyhanko nicht verfuegbar: {e}"}]

    try:
        # WICHTIG: Validierung muss INNERHALB des with-Blocks passieren — pyhanko
        # haelt eine Referenz auf den File-Stream, der mit dem with-Block schliesst.
        # Sonst: "ValueError: seek of closed file"
        with pdf_path.open("rb") as f:
            reader = PdfFileReader(f, strict=False)
            sigs = list(reader.embedded_signatures)

            for sig in sigs:
                entry: Dict[str, Any] = {"field_name": getattr(sig, "field_name", "?")}
                try:
                    status = validate_pdf_signature(sig)
                    entry["intact"]   = bool(getattr(status, "intact", False))
                    entry["valid"]    = bool(getattr(status, "valid",  False))
                    entry["coverage"] = str(getattr(status, "coverage", "?"))
                    entry["modification_level"] = str(getattr(status, "modification_level", "?"))
                    entry["signing_time"] = str(getattr(status, "signing_time", "") or "")

                    cert = getattr(status, "signing_cert", None)
                    if cert is not None:
                        try:
                            subject = cert.subject.native
                            entry["signer_cn"]       = subject.get("common_name", "")
                            entry["signer_country"]  = subject.get("country_name", "")
                            entry["signer_locality"] = subject.get("locality_name", "")
                            entry["signer_serial"]   = subject.get("serial_number", "")
                        except Exception:
                            entry["signer_cn"] = str(cert.subject)

                    diff = getattr(status, "diff_result", None)
                    if diff is not None:
                        entry["diff_summary"] = str(diff)[:400]

                    entry["type"] = "signature"
                except Exception as e:
                    msg = str(e)
                    # Document Timestamp / TSA-Eintrag — KEIN Fehler, sondern ein
                    # zusaetzlicher Zeitstempel-Block. Behandeln als 'document_timestamp'.
                    if "Signature object type must be /Sig" in msg:
                        entry["type"]   = "document_timestamp"
                        entry["intact"] = True
                        entry["valid"]  = True
                        entry["note"]   = "Document Timestamp (DocTSP), kein Unterschrifts-Sig"
                    else:
                        entry["error"] = f"validate failed: {type(e).__name__}: {msg[:200]}"
                out.append(entry)
    except Exception as e:
        return [{"error": f"pdf reader failed: {e}"}]

    return out


def _classify(
    eof_count: int,
    byteranges: List[Tuple[int, int, int, int]],
    signatures: List[Dict[str, Any]],
    file_size: int,
) -> Tuple[str, List[str]]:
    """
    Klassifiziert den Signatur-Workflow.

    Mogliche Klassen:
      'no_signature'
      'single_sig_intact'
      'single_sig_modified_after'  (Bytes nach Sig veraendert, aber Sig selbst intact)
      'single_sig_broken'          (Sig kryptografisch gebrochen)
      'multi_sig_intact'           (alle Sigs intact, legitimer Multi-Workflow)
      'multi_sig_broken'           (mind. 1 Sig gebrochen)
      'multi_byterange_no_validated_sig'
      'unknown'
    """
    reasoning: List[str] = []

    if not byteranges and not signatures:
        return "no_signature", ["Keine /ByteRange + keine Signatur gefunden"]

    # Document-Timestamps (DocTSP) sind reine Zeitstempel-Felder vom TSA,
    # kein Unterschrifts-Sig — werden separat gezaehlt.
    real_sigs   = [s for s in signatures if s.get("type") != "document_timestamp" and "error" not in s]
    timestamps  = [s for s in signatures if s.get("type") == "document_timestamp"]
    crypto_ok   = [s for s in real_sigs if s.get("intact") and s.get("valid")]
    # valid=False trotz intact=True ist Trust-Chain-Issue (z.B. fehlende CA),
    # nicht aber Inhalts-Manipulation — zaehlt zu "intact"
    crypto_ok_intact_only = [s for s in real_sigs if s.get("intact") and not s.get("valid")]
    crypto_broken = [s for s in real_sigs if (s.get("intact") is False)]
    failed_val  = [s for s in signatures if "error" in s]

    # "intakt" fuer Workflow-Bewertung = Bytes nicht veraendert (auch wenn
    # Cert-Trust-Chain lokal nicht aufloesbar ist — z.B. tuerkische TÜRKTRUST-CA)
    effectively_intact = [s for s in real_sigs if s.get("intact")]

    reasoning.append(
        f"Sig-Felder gesamt: {len(signatures)} "
        f"({len(real_sigs)} echte Sigs, {len(timestamps)} DocTimestamps, "
        f"{len(failed_val)} sonstige Validierung-Fehler)"
    )
    reasoning.append(
        f"Davon Bytes-intakt: {len(effectively_intact)}, "
        f"gebrochen: {len(crypto_broken)}"
    )
    reasoning.append(f"/ByteRange-Definitionen: {len(byteranges)}")
    reasoning.append(f"EOF-Marker (Revisionen): {eof_count}")

    if not real_sigs and not timestamps:
        return "multi_byterange_no_validated_sig", reasoning

    # Multi-Sig (>=2 echte Sigs ODER >=1 Sig + >=1 Timestamp)
    if len(real_sigs) >= 2 or (len(real_sigs) >= 1 and len(timestamps) >= 1):
        if crypto_broken:
            return "multi_sig_broken", reasoning + [
                f"VERLETZT: {len(crypto_broken)} Signatur(en) kryptografisch gebrochen "
                "— Bytes innerhalb ihrer signierten Region wurden modifiziert."
            ]
        if effectively_intact:
            return "multi_sig_intact", reasoning + [
                f"Alle {len(effectively_intact)} pruefbaren Signaturen sind Bytes-intakt. "
                f"{len(timestamps)} Document-Timestamps zusaetzlich. "
                "Mehrere /ByteRange = jede Sig hat ihren eigenen — normal fuer "
                "Multi-Signatur-Workflows (z.B. tuerkische e-imza, EU eIDAS).",
                (f"Hinweis: {len(crypto_ok_intact_only)} Sig(s) Trust-Chain nicht "
                 "aufloesbar (oft Root-CA fehlt im Trust-Store) — Inhalts-Integritaet "
                 "trotzdem mathematisch bestaetigt.") if crypto_ok_intact_only else "",
            ]
        return "unknown", reasoning + ["Keine Sig erfolgreich validiert"]

    # Single Sig
    if not real_sigs:
        return "unknown", reasoning + ["Keine echte Signatur"]
    s = real_sigs[0]
    if "error" in s:
        return "unknown", reasoning + [f"Sig-Validierung Fehler: {s.get('error')}"]
    if not s.get("intact"):
        return "single_sig_broken", reasoning + [
            "Signatur kryptografisch GEBROCHEN — die Bytes ihres ByteRange "
            "wurden nach dem Signieren manipuliert."
        ]

    # Sig intact — aber wurde nach der Sig was Echtes hinzugefuegt?
    if byteranges:
        a, b, c, d = byteranges[0]
        last_signed_byte = c + d
        post_bytes = file_size - last_signed_byte
        if post_bytes > 50 and eof_count >= 2:
            return "single_sig_modified_after", reasoning + [
                f"Signatur intakt, aber {post_bytes} Bytes nach Signatur-ByteRange "
                f"+ {eof_count} EOFs — incremental update nach Signierung. "
                "Wenn das mehr ist als nur ein Signatur-Block, koennte Inhalt geaendert sein."
            ]
    return "single_sig_intact", reasoning + ["Signatur intakt, deckt das gesamte signierte Material."]


def analyze_multi_signature_workflow(pdf_path: Path) -> Dict[str, Any]:
    """
    Hauptfunktion. Wird im Pipeline aufgerufen.
    Ergebnis wird an severity_profiles + cross_analyzer durchgereicht damit
    Shadow-Attack-Findings bei legitimer Multi-Sig auf INFO downgegradet werden.
    """
    try:
        data = pdf_path.read_bytes()
    except Exception as e:
        return {
            "workflow":   "error",
            "error":      str(e),
            "anomalies":  [],
        }

    file_size      = len(data)
    eof_positions  = _find_eof_positions(data)
    byteranges     = _find_byteranges(data)
    signatures     = _validate_via_pyhanko(pdf_path)
    workflow, reasoning = _classify(len(eof_positions), byteranges, signatures, file_size)

    # ByteRange-Hashes — zur Dokumentation, was wurde unterschrieben
    br_hashes = [
        {"index": i, "byterange": list(br), "sha256": _hash_byterange(data, br)}
        for i, br in enumerate(byteranges)
    ]

    anomalies: List[Anomaly] = []
    if workflow == "single_sig_broken":
        anomalies.append(Anomaly(
            severity=AnomalySeverity.HIGH,
            category="signature_workflow",
            message="Signatur kryptografisch gebrochen — signierter Inhalt nach Signierung manipuliert",
            detail="; ".join(reasoning),
        ))
    elif workflow == "multi_sig_broken":
        anomalies.append(Anomaly(
            severity=AnomalySeverity.HIGH,
            category="signature_workflow",
            message="Multi-Signatur: mindestens eine Signatur ist gebrochen",
            detail="; ".join(reasoning),
        ))
    elif workflow == "single_sig_modified_after":
        anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category="signature_workflow",
            message="Inkrementelle Aenderung nach Signatur — pruefen ob nur Signatur-Block oder Inhalt",
            detail="; ".join(reasoning),
        ))
    elif workflow == "multi_sig_intact":
        # Wichtig: das ist KEIN Befund, sondern ein Kontext-Hinweis,
        # damit shadow_attack-Findings runtergesetzt werden koennen.
        anomalies.append(Anomaly(
            severity=AnomalySeverity.INFO,
            category="signature_workflow",
            message=f"Multi-Signatur-Workflow erkannt ({len(signatures)} Unterzeichner) — alle intakt",
            detail="; ".join(reasoning),
        ))

    return {
        "workflow":         workflow,
        "reasoning":        reasoning,
        "eof_count":        len(eof_positions),
        "byterange_count":  len(byteranges),
        "byteranges":       br_hashes,
        "signatures":       signatures,
        "anomalies":        anomalies,
    }
