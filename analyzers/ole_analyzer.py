"""
OLE-Analyzer: Forensische Analyse von DOC, XLS, PPT (OLE2/CFB-Format).

Das OLE2-Format (Compound File Binary) ist der Container für alte Office-Formate.
Forensisch relevante Quellen:
- SummaryInformation-Stream: Author, LastAuthor, CreateTime, LastSaveTime, RevisionCount
- DocumentSummaryInformation-Stream: Company, Manager, AppName, Template
- WordDocument-Stream: Revisions, UserInfoAtom
- \x05DocumentSummaryInformation: Custom Properties mit Tracker-IDs

Ohne olefile-Library: Raw-Byte-Parsing der bekannten Offsets.
"""
from __future__ import annotations
import struct
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone, timedelta

from models.schemas import Anomaly, AnomalySeverity


# OLE2-Magic-Bytes
OLE_MAGIC = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'

# Windows FILETIME → Unix Timestamp (Differenz in 100-Nanosekunden-Intervallen)
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_FILETIME_SCALE = 10_000_000  # 100ns → 1s


def _filetime_to_iso(ft_bytes: bytes) -> Optional[str]:
    """Konvertiert Windows FILETIME (8 Bytes LE) zu ISO-8601."""
    try:
        ft = struct.unpack('<Q', ft_bytes)[0]
        if ft == 0:
            return None
        seconds = ft / _FILETIME_SCALE
        dt = _FILETIME_EPOCH + timedelta(seconds=seconds)
        return dt.isoformat().replace('+00:00', 'Z')
    except Exception:
        return None


def _read_codepage_string(data: bytes, offset: int) -> Optional[str]:
    """Liest einen längen-präfixierten String aus PropertySet."""
    try:
        size = struct.unpack_from('<I', data, offset)[0]
        raw  = data[offset + 4: offset + 4 + size]
        return raw.rstrip(b'\x00').decode('latin-1', errors='replace') or None
    except Exception:
        return None


def _parse_property_set(data: bytes) -> Dict[str, Any]:
    """
    Parst einen PROPERTYSETSTREAM-Header und extrahiert bekannte Property-IDs.
    Property-IDs für SummaryInformation:
      2 = Title, 3 = Subject, 4 = Author, 5 = Keywords, 6 = Comments,
      7 = Template, 8 = LastSavedBy, 9 = RevisionNumber,
      10 = EditTime, 11 = LastPrinted, 12 = Created, 13 = LastSaved,
      14 = PageCount, 15 = WordCount, 16 = CharCount, 18 = AppName
    """
    result = {}
    prop_name_map = {
        2:  'title', 3: 'subject', 4: 'author', 5: 'keywords',
        6:  'comments', 7: 'template', 8: 'last_author', 9: 'revision',
        10: 'edit_time_100ns', 11: 'last_printed', 12: 'created',
        13: 'last_saved', 14: 'page_count', 15: 'word_count',
        16: 'char_count', 18: 'app_name', 19: 'security',
    }

    try:
        # Byte-Order-ID prüfen
        if len(data) < 48:
            return result

        # PropertySet-Header: Offset 28 = cSections, 32 = FMTID + Offset
        # Erster PropertySet beginnt normalerweise bei Offset 60
        c_sections = struct.unpack_from('<I', data, 44)[0]
        if c_sections < 1:
            return result

        # Erster Section-Offset (bytes 52..55 im Header)
        try:
            sect_offset = struct.unpack_from('<I', data, 52)[0]
        except Exception:
            sect_offset = 48

        if sect_offset >= len(data):
            return result

        # cProperties
        c_props = struct.unpack_from('<I', data, sect_offset + 4)[0]
        ident_offset = sect_offset + 8

        for i in range(min(c_props, 50)):
            try:
                prop_id = struct.unpack_from('<I', data, ident_offset + i * 8)[0]
                prop_off = struct.unpack_from('<I', data, ident_offset + i * 8 + 4)[0]
                abs_off = sect_offset + prop_off

                if abs_off + 4 > len(data):
                    continue

                prop_type = struct.unpack_from('<I', data, abs_off)[0]

                name = prop_name_map.get(prop_id)
                if name is None:
                    continue

                # VT_LPSTR (30) — Length-prefixed string
                if prop_type == 30:
                    s = _read_codepage_string(data, abs_off + 4)
                    if s:
                        result[name] = s.strip()

                # VT_LPWSTR (31) — Unicode string
                elif prop_type == 31:
                    try:
                        size = struct.unpack_from('<I', data, abs_off + 4)[0]
                        raw  = data[abs_off + 8: abs_off + 8 + size * 2]
                        s    = raw.rstrip(b'\x00').decode('utf-16-le', errors='replace')
                        if s.strip():
                            result[name] = s.strip()
                    except Exception:
                        pass

                # VT_FILETIME (64) — Windows FILETIME
                elif prop_type == 64:
                    if abs_off + 12 <= len(data):
                        iso = _filetime_to_iso(data[abs_off + 4: abs_off + 12])
                        if iso:
                            result[name] = iso

                # VT_I4 (3) / VT_UI4 (19) — Integer
                elif prop_type in (3, 19):
                    if abs_off + 8 <= len(data):
                        val = struct.unpack_from('<I', data, abs_off + 4)[0]
                        result[name] = val

            except Exception:
                continue

    except Exception:
        pass

    return result


def _find_stream_in_ole(content: bytes, stream_name: bytes) -> Optional[bytes]:
    """
    Einfache Heuristik: Suche nach bekannten Stream-Namen im OLE2-Byte-Strom.
    Nicht exakt, aber ohne olefile-Bibliothek funktional genug.
    """
    try:
        idx = content.find(stream_name)
        if idx == -1:
            return None
        # FAT-Sektor-Größe: 512 Bytes standardmäßig
        sector_size = 512
        # PropertySet-Header beginnt nach GUID + weiteren Headerdaten
        # Heuristisch: Lese 4096 Bytes ab dem nächsten Sektor-Beginn
        sector_start = (idx // sector_size + 1) * sector_size
        return content[sector_start: sector_start + 8192]
    except Exception:
        return None


def _extract_strings_from_ole(content: bytes) -> List[str]:
    """
    Extraktion von Strings aus OLE2-Datei durch Byte-Pattern-Suche.
    Findet Autorennamen, Pfade, E-Mail-Adressen die im Klartext gespeichert sind.
    """
    strings = []
    # Suche nach druckbaren ASCII-Strings ≥ 4 Zeichen
    for m in re.finditer(rb'[\x20-\x7e]{4,}', content):
        s = m.group(0).decode('latin-1', errors='replace').strip()
        # Nur relevante Strings (Pfade, E-Mails, Namen-Kandidaten)
        if any([
            '\\' in s and len(s) > 8,              # Windows-Pfad
            '@' in s and '.' in s,                  # E-Mail
            re.match(r'^[A-Z][a-z]+ [A-Z][a-z]+$', s),  # Vor- und Nachname
            'Microsoft' in s or 'Word' in s or 'Excel' in s,
        ]):
            strings.append(s)
    return list(dict.fromkeys(strings))[:30]  # Dedupliziert, max 30


def analyze_ole(file_path: Path, fmt: str) -> Dict[str, Any]:
    """Hauptfunktion: OLE2-Forensik für DOC/XLS/PPT."""
    anomalies: List[Anomaly] = []

    try:
        with open(file_path, 'rb') as f:
            content = f.read()
    except Exception as e:
        return {
            'format':       fmt,
            'summary':      {},
            'doc_summary':  {},
            'strings':      [],
            'anomalies': [Anomaly(
                severity=AnomalySeverity.HIGH,
                category='ole',
                message=f'{fmt}-Datei konnte nicht gelesen werden',
                detail=str(e),
            )],
        }

    # Prüfe OLE2-Magic
    if not content.startswith(OLE_MAGIC):
        return {
            'format':       fmt,
            'summary':      {},
            'doc_summary':  {},
            'strings':      [],
            'anomalies': [Anomaly(
                severity=AnomalySeverity.HIGH,
                category='ole',
                message='Keine gültige OLE2-Signatur — Datei möglicherweise beschädigt',
            )],
        }

    # SummaryInformation-Stream parsen
    # Stream-Name: "\x05SummaryInformation" (Unicode LE im Directory)
    si_marker = b'\x05\x00S\x00u\x00m\x00m\x00a\x00r\x00y'
    si_data   = _find_stream_in_ole(content, si_marker)
    summary   = _parse_property_set(si_data) if si_data else {}

    # DocumentSummaryInformation
    dsi_marker = b'\x05\x00D\x00o\x00c\x00u\x00m\x00e\x00n\x00t'
    dsi_data   = _find_stream_in_ole(content, dsi_marker)
    doc_summary = _parse_property_set(dsi_data) if dsi_data else {}

    # Strings aus dem gesamten File
    strings = _extract_strings_from_ole(content)

    # Makro-Erkennung (häufig in .doc/.xls vorhanden)
    has_macros = b'VBA' in content or b'_VBA_PROJECT' in content
    if has_macros:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.HIGH,
            category='ole',
            message='Makros (VBA) im Dokument erkannt',
            detail='VBA-Makros in alten Office-Formaten sind ein erhöhtes Sicherheitsrisiko.',
        ))

    # Autoren-Anomalien
    author   = summary.get('author')
    last_auth = summary.get('last_author')
    if author and last_auth and author != last_auth:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.INFO,
            category='ole',
            message=f'Erstautor "{author}" ≠ Letzter Autor "{last_auth}"',
        ))

    # Zeitstempel-Anomalie
    created   = summary.get('created')
    modified  = summary.get('last_saved')
    if created and modified:
        try:
            dt_c = datetime.fromisoformat(created.replace('Z', '+00:00'))
            dt_m = datetime.fromisoformat(modified.replace('Z', '+00:00'))
            if dt_m < dt_c:
                anomalies.append(Anomaly(
                    severity=AnomalySeverity.HIGH,
                    category='ole',
                    message='LastSaved liegt vor Created — mögliche Zeitstempel-Manipulation',
                    detail=f'Created: {created} | LastSaved: {modified}',
                ))
        except Exception:
            pass

    # Hohe Revision
    revision = summary.get('revision')
    if revision and isinstance(revision, int) and revision > 100:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.INFO,
            category='ole',
            message=f'Revisionsnummer sehr hoch: {revision}',
        ))

    return {
        'format':      fmt,
        'summary':     summary,
        'doc_summary': doc_summary,
        'has_macros':  has_macros,
        'strings':     strings,
        'anomalies':   anomalies,
    }
