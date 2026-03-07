"""
IOC Extractor — URLs, IPs, Domains, Emails aus allen PDF-Bereichen.
Scannt raw PDF-Bytes, dekomprimierte Streams, /Info-Keys, XMP, JavaScript.
"""
from __future__ import annotations
import re
import ipaddress
from pathlib import Path
from typing import List, Dict, Any, Set

try:
    import pikepdf
    PIKEPDF_OK = True
except ImportError:
    PIKEPDF_OK = False

from models.schemas import IocResult, Anomaly, AnomalySeverity

# Regex-Patterns
_RE_URL     = re.compile(r'https?://[^\s<>"{}|\\^`\[\]\']{4,}', re.IGNORECASE)
_RE_IP      = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
_RE_EMAIL   = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
_RE_DOMAIN  = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,})\b')

# Verdächtige TLDs / Shortener
_SUSPICIOUS_TLDS = {'.onion', '.ru', '.to', '.xyz', '.bit', '.tk', '.cc', '.su'}
_URL_SHORTENERS  = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link',
                    'cutt.ly', 'rebrand.ly', 'is.gd', 'buff.ly', 'adf.ly'}

# Private IP-Ranges
_PRIVATE_NETS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
]


def _is_internal_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def _is_suspicious_url(url: str) -> bool:
    url_lower = url.lower()
    for tld in _SUSPICIOUS_TLDS:
        if tld in url_lower:
            return True
    try:
        from urllib.parse import urlparse
        host = urlparse(url).netloc.lower().lstrip('www.')
        if host in _URL_SHORTENERS:
            return True
    except Exception:
        pass
    return False


def _extract_domain(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return urlparse(url).netloc
    except Exception:
        return ""


def _collect_text_blocks(pdf_path: Path) -> List[str]:
    """Sammelt dekomprimierten Text aus allen PDF-Quellen."""
    blocks: List[str] = []

    if not PIKEPDF_OK:
        # Fallback: raw bytes
        raw = pdf_path.read_bytes()
        blocks.append(raw.decode('latin-1', errors='replace'))
        return blocks

    try:
        with pikepdf.open(pdf_path, suppress_warnings=True) as pdf:
            # 1. /Info-Dictionary
            if pdf.docinfo:
                for k, v in pdf.docinfo.items():
                    blocks.append(str(v))

            # 2. Alle Objekte — Streams dekomprimieren
            for obj in pdf.objects:
                try:
                    if isinstance(obj, pikepdf.Stream):
                        data = obj.read_bytes()
                        blocks.append(data.decode('latin-1', errors='replace'))
                    elif isinstance(obj, pikepdf.Dictionary):
                        # /URI-Actions
                        if '/URI' in obj:
                            blocks.append(str(obj['/URI']))
                        # /JS, /JavaScript
                        for key in ['/JS', '/JavaScript']:
                            if key in obj:
                                val = obj[key]
                                if isinstance(val, pikepdf.Stream):
                                    blocks.append(val.read_bytes().decode('latin-1', errors='replace'))
                                else:
                                    blocks.append(str(val))
                        # /Contents in Annotations
                        if '/Contents' in obj and obj.get('/Subtype') in ['/Text', '/FreeText', '/Link']:
                            blocks.append(str(obj['/Contents']))
                except Exception:
                    pass

            # 3. Seiten-Inhalts-Streams
            for page in pdf.pages:
                try:
                    for key in ['/Contents']:
                        if key in page:
                            contents = page[key]
                            if isinstance(contents, pikepdf.Array):
                                for c in contents:
                                    try:
                                        blocks.append(c.read_bytes().decode('latin-1', errors='replace'))
                                    except Exception:
                                        pass
                            elif isinstance(contents, pikepdf.Stream):
                                blocks.append(contents.read_bytes().decode('latin-1', errors='replace'))
                except Exception:
                    pass

    except Exception:
        # Fallback
        raw = pdf_path.read_bytes()
        blocks.append(raw.decode('latin-1', errors='replace'))

    return blocks


def extract_iocs(file_path: Path) -> IocResult:
    """Hauptfunktion — extrahiert alle IOCs aus einem PDF."""
    blocks = _collect_text_blocks(file_path)
    combined = "\n".join(blocks)

    found_urls: List[Dict[str, Any]] = []
    found_ips: List[Dict[str, Any]] = []
    found_emails: List[str] = []
    found_domains: List[str] = []
    suspicious_iocs: List[Dict[str, Any]] = []
    anomalies: List[Anomaly] = []

    seen_urls: Set[str] = set()
    seen_ips: Set[str] = set()
    seen_emails: Set[str] = set()

    # URLs
    for m in _RE_URL.finditer(combined):
        url = m.group(0).rstrip('.,;)"\'')
        if url in seen_urls:
            continue
        seen_urls.add(url)
        suspicious = _is_suspicious_url(url)
        domain = _extract_domain(url)
        entry = {"url": url, "source": "stream", "suspicious": suspicious, "domain": domain}
        found_urls.append(entry)
        if domain:
            found_domains.append(domain)
        if suspicious:
            suspicious_iocs.append({"type": "url", "value": url, "reason": "suspicious_tld_or_shortener"})

    # IPs
    for m in _RE_IP.finditer(combined):
        ip = m.group(0)
        if ip in seen_ips:
            continue
        # Filter falsche positives (z.B. Versionsnummern 16.11.10.16)
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        seen_ips.add(ip)
        internal = _is_internal_ip(ip)
        ip_type = "internal" if internal else "external"
        entry = {"ip": ip, "type": ip_type, "source": "stream"}
        found_ips.append(entry)
        if not internal:
            suspicious_iocs.append({"type": "ip", "value": ip, "reason": "external_ip"})

    # Emails
    for m in _RE_EMAIL.finditer(combined):
        email = m.group(0).lower()
        if email not in seen_emails:
            seen_emails.add(email)
            found_emails.append(email)

    # Anomalien
    onion_urls = [u for u in found_urls if '.onion' in u['url'].lower()]
    if onion_urls:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.HIGH,
            category="ioc",
            message=f"Darknet-URL(s) gefunden: {len(onion_urls)} .onion-Adresse(n)",
            detail=", ".join(u['url'][:80] for u in onion_urls[:3]),
        ))

    ext_ips = [ip for ip in found_ips if ip['type'] == 'external']
    if ext_ips:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category="ioc",
            message=f"Externe IP-Adressen im Dokument: {len(ext_ips)}",
            detail=", ".join(ip['ip'] for ip in ext_ips[:5]),
        ))

    int_ips = [ip for ip in found_ips if ip['type'] == 'internal']
    if int_ips:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.LOW,
            category="ioc",
            message=f"Interne Netzwerkadressen gefunden: {len(int_ips)}",
            detail=", ".join(ip['ip'] for ip in int_ips[:5]),
        ))

    suspicious_urls_list = [u for u in found_urls if u['suspicious']]
    if suspicious_urls_list and not onion_urls:
        anomalies.append(Anomaly(
            severity=AnomalySeverity.MEDIUM,
            category="ioc",
            message=f"Verdächtige URLs (Shortener/auffällige TLD): {len(suspicious_urls_list)}",
            detail=", ".join(u['url'][:80] for u in suspicious_urls_list[:3]),
        ))

    total = len(found_urls) + len(found_ips) + len(found_emails)

    # Domains deduplizieren
    unique_domains = list(dict.fromkeys(found_domains))

    return IocResult(
        urls=found_urls[:100],
        ips=found_ips[:50],
        emails=list(seen_emails)[:50],
        domains=unique_domains[:50],
        suspicious_iocs=suspicious_iocs[:50],
        total_count=total,
        anomalies=anomalies,
    )
