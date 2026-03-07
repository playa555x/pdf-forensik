"""
Format-Detektor: Erkennt das Dateiformat anhand Magic-Bytes und Extension.
Gibt einen normalisierten Format-String zurück.

Unterstützte Formate:
  PDF, DOCX, XLSX, PPTX, DOC, XLS, PPT, ODT, ODS, ODP, JPEG, PNG
"""
from __future__ import annotations
from pathlib import Path
from typing import Tuple

# Magic-Byte-Signaturen
_MAGIC: list[Tuple[bytes, str]] = [
    (b'%PDF',                          'PDF'),
    (b'PK\x03\x04',                   'OOXML'),   # ZIP-Container → DOCX/XLSX/PPTX/ODT
    (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'OLE'), # OLE2 → DOC/XLS/PPT
    (b'\xff\xd8\xff',                  'JPEG'),
    (b'\x89PNG\r\n\x1a\n',            'PNG'),
    (b'GIF87a',                        'GIF'),
    (b'GIF89a',                        'GIF'),
    (b'BM',                            'BMP'),
    (b'II\x2a\x00',                   'TIFF'),
    (b'MM\x00\x2a',                   'TIFF'),
    (b'RIFF',                          'WEBP'),
]

# Extension-Mapping für OOXML-Untertypen (ZIP-Container)
_OOXML_EXT_MAP = {
    '.docx': 'DOCX',
    '.xlsx': 'XLSX',
    '.pptx': 'PPTX',
    '.docm': 'DOCX',   # Macro-enabled Word
    '.xlsm': 'XLSX',   # Macro-enabled Excel
    '.pptm': 'PPTX',   # Macro-enabled PowerPoint
    '.odt':  'ODT',
    '.ods':  'ODS',
    '.odp':  'ODP',
}

# Extension-Mapping für OLE2-Untertypen
_OLE_EXT_MAP = {
    '.doc':  'DOC',
    '.xls':  'XLS',
    '.ppt':  'PPT',
}

# Alle unterstützten Upload-Extensions
SUPPORTED_EXTENSIONS = {
    '.pdf', '.docx', '.xlsx', '.pptx', '.docm', '.xlsm', '.pptm',
    '.doc', '.xls', '.ppt', '.odt', '.ods', '.odp',
    '.jpg', '.jpeg', '.png',
}


def detect_format(file_path: Path, filename: str) -> str:
    """
    Gibt den normalisierten Format-String zurück.
    Priorität: Magic-Bytes → Extension-Disambiguierung → Extension-Fallback.
    """
    ext = Path(filename).suffix.lower()

    try:
        with open(file_path, 'rb') as f:
            header = f.read(16)
    except Exception:
        return ext.lstrip('.').upper() or 'UNKNOWN'

    # Magic-Byte erkennen
    magic_type = None
    for magic, fmt in _MAGIC:
        if header.startswith(magic):
            magic_type = fmt
            break

    if magic_type == 'PDF':
        return 'PDF'

    if magic_type == 'OOXML':
        # ZIP-Container — Extension entscheidet über Untertyp
        return _OOXML_EXT_MAP.get(ext, 'OOXML')

    if magic_type == 'OLE':
        return _OLE_EXT_MAP.get(ext, 'OLE')

    if magic_type in ('JPEG', 'PNG', 'GIF', 'BMP', 'TIFF', 'WEBP'):
        return magic_type

    # Fallback auf Extension
    if ext in _OOXML_EXT_MAP:
        return _OOXML_EXT_MAP[ext]
    if ext in _OLE_EXT_MAP:
        return _OLE_EXT_MAP[ext]
    if ext == '.pdf':
        return 'PDF'

    return ext.lstrip('.').upper() or 'UNKNOWN'


def is_supported(filename: str) -> bool:
    ext = Path(filename).suffix.lower()
    return ext in SUPPORTED_EXTENSIONS


def is_pdf_format(fmt: str) -> bool:
    return fmt == 'PDF'


def is_office_format(fmt: str) -> bool:
    return fmt in {'DOCX', 'XLSX', 'PPTX', 'DOC', 'XLS', 'PPT', 'ODT', 'ODS', 'ODP', 'OOXML', 'OLE'}


def is_image_format(fmt: str) -> bool:
    return fmt in {'JPEG', 'PNG', 'GIF', 'BMP', 'TIFF', 'WEBP'}
