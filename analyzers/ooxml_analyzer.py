"""
OOXML-Analyzer: Forensische Analyse von DOCX, XLSX, PPTX (Open XML / ZIP-Format).

Extrahiert:
- Core Properties (creator, lastModifiedBy, created, modified, revision)
- App Properties (application, appVersion, company, template)
- RSID-Liste (Revisions-IDs → Autorenmuster, Bearbeitungssitzungen)
- Track-Changes (Autoren, Zeitstempel, Änderungstypen)
- Eingebettete Bilder (in /word/media/, /xl/media/, /ppt/media/)
- Verknüpfte externe Ressourcen (relationships)
- Makro-Erkennung (vbaProject.bin)
- Custom XML / Custom Properties
- Versteckte Text-Runs / Kommentare
"""
from __future__ import annotations
import re
import zipfile
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

try:
    import defusedxml.ElementTree as ET
    DEFUSED_AVAILABLE = True
except ImportError:
    import xml.etree.ElementTree as ET
    DEFUSED_AVAILABLE = False

from models.schemas import Anomaly, AnomalySeverity


# XML-Namespaces
_NS = {
    'cp':    'http://schemas.openxmlformats.org/package/2006/metadata/core-properties',
    'dc':    'http://purl.org/dc/elements/1.1/',
    'dcterms':'http://purl.org/dc/terms/',
    'app':   'http://schemas.openxmlformats.org/officeDocument/2006/extended-properties',
    'vt':    'http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes',
    'w':     'http://schemas.openxmlformats.org/wordprocessingml/2006/main',
    'r':     'http://schemas.openxmlformats.org/officeDocument/2006/relationships',
    'custom':'http://schemas.openxmlformats.org/officeDocument/2006/custom-properties',
}

_RSID_RE = re.compile(r'rsid[A-Z]*="([0-9A-Fa-f]{8})"')


def _xml_text(element, tag: str, ns_prefix: str) -> Optional[str]:
    """Liest Text eines XML-Tags mit Namespace."""
    ns = _NS.get(ns_prefix, '')
    node = element.find(f'{{{ns}}}{tag}') if ns else element.find(tag)
    return node.text if node is not None and node.text else None


def _parse_core_props(zf: zipfile.ZipFile) -> Dict[str, Any]:
    """Extrahiert Core-Properties (docProps/core.xml)."""
    result = {}
    try:
        with zf.open('docProps/core.xml') as f:
            root = ET.parse(f).getroot()
        result['creator']        = _xml_text(root, 'creator', 'dc')
        result['last_modified_by'] = _xml_text(root, 'lastModifiedBy', 'cp')
        result['created']        = _xml_text(root, 'created', 'dcterms')
        result['modified']       = _xml_text(root, 'modified', 'dcterms')
        result['revision']       = _xml_text(root, 'revision', 'cp')
        result['description']    = _xml_text(root, 'description', 'dc')
        result['keywords']       = _xml_text(root, 'keywords', 'cp')
        result['subject']        = _xml_text(root, 'subject', 'dc')
        result['title']          = _xml_text(root, 'title', 'dc')
        result['category']       = _xml_text(root, 'category', 'cp')
        result['content_status'] = _xml_text(root, 'contentStatus', 'cp')
    except (KeyError, zipfile.BadZipFile, Exception):
        pass
    return {k: v for k, v in result.items() if v is not None}


def _parse_app_props(zf: zipfile.ZipFile) -> Dict[str, Any]:
    """Extrahiert App-Properties (docProps/app.xml)."""
    result = {}
    try:
        with zf.open('docProps/app.xml') as f:
            root = ET.parse(f).getroot()
        ns = _NS['app']
        for tag in ['Application', 'AppVersion', 'Company', 'Template',
                    'Manager', 'Pages', 'Words', 'Characters', 'Lines',
                    'Paragraphs', 'Slides', 'Sheets']:
            node = root.find(f'{{{ns}}}{tag}')
            if node is not None and node.text:
                result[tag.lower()] = node.text
    except (KeyError, zipfile.BadZipFile, Exception):
        pass
    return result


def _extract_rsids(zf: zipfile.ZipFile, doc_path: str) -> List[str]:
    """Extrahiert alle RSID-Werte aus dem Haupt-Dokument."""
    rsids = set()
    try:
        with zf.open(doc_path) as f:
            content = f.read().decode('utf-8', errors='replace')
        for match in _RSID_RE.finditer(content):
            rsids.add(match.group(1).upper())
    except Exception:
        pass
    return sorted(rsids)


def _extract_track_changes(zf: zipfile.ZipFile, doc_path: str) -> List[Dict[str, Any]]:
    """Extrahiert Track-Changes-Einträge (Autoren, Zeitstempel, Typen)."""
    changes = []
    try:
        with zf.open(doc_path) as f:
            root = ET.parse(f).getroot()

        ns_w = _NS['w']
        # Suche nach ins/del/rPrChange/pPrChange/sectPrChange
        change_tags = [f'{{{ns_w}}}ins', f'{{{ns_w}}}del',
                       f'{{{ns_w}}}rPrChange', f'{{{ns_w}}}pPrChange']

        for tag in change_tags:
            for elem in root.iter(tag):
                author = elem.get(f'{{{ns_w}}}author')
                date   = elem.get(f'{{{ns_w}}}date')
                change_type = elem.tag.split('}')[-1]
                if author:
                    changes.append({
                        'type':   change_type,
                        'author': author,
                        'date':   date,
                    })
        # Kommentare
        for elem in root.iter(f'{{{ns_w}}}comment'):
            author = elem.get(f'{{{ns_w}}}author')
            date   = elem.get(f'{{{ns_w}}}date')
            text_nodes = elem.findall(f'.//{{{ns_w}}}t')
            text = ' '.join(t.text or '' for t in text_nodes).strip()
            if author:
                changes.append({
                    'type':   'comment',
                    'author': author,
                    'date':   date,
                    'text':   text[:200] if text else None,
                })
    except Exception:
        pass
    return changes


def _extract_relationships(zf: zipfile.ZipFile) -> List[Dict[str, Any]]:
    """Extrahiert alle Relationships aus _rels/*.rels Dateien."""
    rels = []
    for name in zf.namelist():
        if '_rels' in name and name.endswith('.rels'):
            try:
                with zf.open(name) as f:
                    root = ET.parse(f).getroot()
                for rel in root:
                    target = rel.get('Target', '')
                    rel_type = rel.get('Type', '').split('/')[-1]
                    target_mode = rel.get('TargetMode', 'Internal')
                    rels.append({
                        'source':   name,
                        'type':     rel_type,
                        'target':   target,
                        'external': target_mode == 'External',
                    })
            except Exception:
                continue
    return rels


def _extract_embedded_media(zf: zipfile.ZipFile) -> List[Dict[str, Any]]:
    """Listet alle eingebetteten Mediendateien auf."""
    media = []
    for name in zf.namelist():
        if '/media/' in name:
            try:
                info = zf.getinfo(name)
                with zf.open(name) as f:
                    data = f.read(4096)
                md5 = hashlib.md5(data).hexdigest()[:16]
                media.append({
                    'path':       name,
                    'size_bytes': info.file_size,
                    'md5_prefix': md5,
                    'filename':   Path(name).name,
                })
            except Exception:
                continue
    return media


def _check_macros(zf: zipfile.ZipFile) -> Dict[str, Any]:
    """Prüft ob ein vbaProject.bin vorhanden ist (Makro-Erkennung)."""
    has_macros = any('vbaProject' in n.lower() for n in zf.namelist())
    macro_files = [n for n in zf.namelist() if 'vbaProject' in n.lower() or n.endswith('.bin')]
    return {
        'has_macros':  has_macros,
        'macro_files': macro_files,
    }


def _extract_custom_props(zf: zipfile.ZipFile) -> List[Dict[str, Any]]:
    """Extrahiert Custom Properties (können Tracker-IDs etc. enthalten)."""
    props = []
    try:
        with zf.open('docProps/custom.xml') as f:
            root = ET.parse(f).getroot()
        ns_c = _NS['custom']
        ns_v = _NS['vt']
        for prop in root:
            name = prop.get('name', '')
            val_node = None
            for child in prop:
                val_node = child
                break
            value = val_node.text if val_node is not None else None
            props.append({'name': name, 'value': value})
    except (KeyError, zipfile.BadZipFile, Exception):
        pass
    return props


def _get_doc_path_for_format(zf: zipfile.ZipFile, fmt: str) -> Optional[str]:
    """Gibt den Hauptdokument-Pfad je nach Format zurück."""
    candidates = {
        'DOCX': ['word/document.xml'],
        'XLSX': ['xl/workbook.xml'],
        'PPTX': ['ppt/presentation.xml'],
    }
    for path in candidates.get(fmt, []):
        if path in zf.namelist():
            return path
    # Fallback: alle XML-Dateien im Hauptverzeichnis
    return None


def analyze_ooxml(file_path: Path, fmt: str) -> Dict[str, Any]:
    """Hauptfunktion: vollständige OOXML-Forensik für DOCX/XLSX/PPTX."""
    anomalies: List[Anomaly] = []

    try:
        zf = zipfile.ZipFile(file_path, 'r')
    except Exception as e:
        return {
            'format':      fmt,
            'core_props':  {},
            'app_props':   {},
            'rsids':       [],
            'track_changes': [],
            'relationships': [],
            'media':       [],
            'macros':      {},
            'custom_props': [],
            'anomalies': [Anomaly(
                severity=AnomalySeverity.HIGH,
                category='ooxml',
                message=f'{fmt}-Datei konnte nicht geöffnet werden',
                detail=str(e),
            )],
        }

    with zf:
        core_props  = _parse_core_props(zf)
        app_props   = _parse_app_props(zf)
        macro_info  = _check_macros(zf)
        media       = _extract_embedded_media(zf)
        rels        = _extract_relationships(zf)
        custom_props = _extract_custom_props(zf)

        doc_path    = _get_doc_path_for_format(zf, fmt)
        rsids       = _extract_rsids(zf, doc_path) if doc_path and fmt == 'DOCX' else []
        track_changes = _extract_track_changes(zf, doc_path) if doc_path and fmt == 'DOCX' else []

    # Anomalien
    creator  = core_props.get('creator')
    last_mod = core_props.get('last_modified_by')

    if creator and last_mod and creator != last_mod:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.INFO,
            category='ooxml',
            message=f'Erstellt von "{creator}", zuletzt bearbeitet von "{last_mod}"',
            detail='Verschiedene Personen haben das Dokument bearbeitet.',
        ))

    if macro_info.get('has_macros'):
        anomalies.append(Anomaly(
            severity=AnomalySeverity.HIGH,
            category='ooxml',
            message=f'Makros gefunden: {", ".join(macro_info["macro_files"][:3])}',
            detail='VBA-Makros können beliebigen Code ausführen.',
        ))

    ext_rels = [r for r in rels if r.get('external')]
    if ext_rels:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category='ooxml',
            message=f'{len(ext_rels)} externe Verknüpfung(en) gefunden',
            detail='; '.join(r['target'] for r in ext_rels[:3]),
        ))

    # Track-Changes-Autoren
    tc_authors = list({c['author'] for c in track_changes if c.get('author')})
    if tc_authors:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.INFO,
            category='ooxml',
            message=f'Track-Changes-Autoren: {", ".join(tc_authors[:5])}',
            detail=f'{len(track_changes)} Änderungseinträge gesamt',
        ))

    # Viele RSIDs → viele Bearbeitungssitzungen
    if len(rsids) > 50:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.INFO,
            category='ooxml',
            message=f'{len(rsids)} RSIDs — Dokument wurde vielfach bearbeitet',
            detail='Jede RSID = eine Bearbeitungssitzung in Microsoft Word',
        ))

    # Revision sehr hoch
    revision = core_props.get('revision')
    if revision and revision.isdigit() and int(revision) > 100:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.INFO,
            category='ooxml',
            message=f'Revisionsnummer sehr hoch: {revision}',
            detail='Viele manuelle Speicherungen oder umfangreiche Bearbeitungshistorie.',
        ))

    # CreationDate vs ModDate
    created  = core_props.get('created', '')
    modified = core_props.get('modified', '')
    if created and modified:
        try:
            dt_c = datetime.fromisoformat(created.replace('Z', '+00:00'))
            dt_m = datetime.fromisoformat(modified.replace('Z', '+00:00'))
            if dt_m < dt_c:
                anomalies.append(Anomaly(
                    severity=AnomalySeverity.HIGH,
                    category='ooxml',
                    message='ModifiedDate liegt vor CreatedDate — mögliche Zeitstempel-Manipulation',
                    detail=f'Created: {created} | Modified: {modified}',
                ))
        except Exception:
            pass

    return {
        'format':        fmt,
        'core_props':    core_props,
        'app_props':     app_props,
        'rsids':         rsids,
        'rsid_count':    len(rsids),
        'track_changes': track_changes,
        'tc_author_count': len(set(c.get('author', '') for c in track_changes if c.get('author'))),
        'relationships': rels,
        'external_links': ext_rels,
        'media':         media,
        'macros':        macro_info,
        'custom_props':  custom_props,
        'anomalies':     anomalies,
    }
