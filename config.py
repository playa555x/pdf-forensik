"""
PDF Forensik Analyzer — Konfiguration
Alle Pfade, Konstanten und Schwellenwerte zentral hier.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).parent.resolve()

# Persistentes Datenverzeichnis — auf Render: /var/data, lokal: ./data
_DATA_DIR = Path(os.environ.get("DATA_DIR", str(BASE_DIR / "data")))
_DATA_DIR.mkdir(parents=True, exist_ok=True)

# Verzeichnisse
UPLOAD_DIR  = _DATA_DIR / "uploads"
IMAGES_DIR  = _DATA_DIR / "extracted_images"
REPORTS_DIR = _DATA_DIR / "generated_reports"
DB_PATH     = _DATA_DIR / "forensik.db"

# Server — Render setzt HOST=0.0.0.0 und PORT=10000 via Env-Var
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "9000"))

# Upload-Limits
MAX_UPLOAD_SIZE_MB = 200
MAX_UPLOAD_SIZE_BYTES = MAX_UPLOAD_SIZE_MB * 1024 * 1024

# Anomalie-Schwellenwerte
UUID_TIMESTAMP_HIGH_DELTA_SECONDS = 3600   # > 1 Stunde → HIGH
UUID_TIMESTAMP_MEDIUM_DELTA_SECONDS = 60   # > 1 Minute → MEDIUM

COMPARE_MIN_TIME_DIFF_SECONDS = 300        # < 5 Minuten → MEDIUM

# Risk-Level-Logik
RISK_HIGH_MIN_COUNT = 1    # ≥1 HIGH-Anomalie → RISK = HIGH
RISK_MEDIUM_MIN_COUNT = 1  # ≥1 MEDIUM → RISK = MEDIUM (wenn kein HIGH)

# Bekannte Software-Fingerprints
KNOWN_PRODUCERS = {
    "Microsoft Word":             "Microsoft Word",
    "Microsoft® Word":            "Microsoft Word",
    "Acrobat Distiller":          "Adobe Acrobat Distiller",
    "Adobe PDF Library":          "Adobe PDF Library",
    "Adobe Acrobat":              "Adobe Acrobat",
    "GPL Ghostscript":            "Ghostscript",
    "Ghostscript":                "Ghostscript",
    "LibreOffice":                "LibreOffice",
    "OpenOffice":                 "OpenOffice",
    "PScript5":                   "Adobe PostScript Driver",
    "pdfTeX":                     "pdfTeX (LaTeX)",
    "LaTeX":                      "LaTeX",
    "FPDF":                       "FPDF (PHP Library)",
    "iTextSharp":                 "iTextSharp (.NET)",
    "iText":                      "iText (Java)",
    "PDFsharp":                   "PDFsharp (.NET)",
    "PDFium":                     "PDFium (Chromium)",
    "Chromium":                   "Chromium/Chrome",
    "Prince":                     "Prince (XML → PDF)",
    "wkhtmltopdf":                "wkhtmltopdf",
    "Bullzip":                    "Bullzip PDF Printer",
    "CutePDF":                    "CutePDF Writer",
    "doPDF":                      "doPDF",
    "PDF24":                      "PDF24 Creator",
    "Nitro":                      "Nitro PDF",
    "Foxit":                      "Foxit PDF",
    "PDFelement":                 "Wondershare PDFelement",
    "pdfcreator":                 "PDFCreator",
    "PyPDF":                      "PyPDF (Python)",
    "reportlab":                  "ReportLab (Python)",
    "pikepdf":                    "pikepdf (Python)",
    "cairo":                      "Cairo Graphics",
    "Scribus":                    "Scribus",
    "Quark":                      "QuarkXPress",
    "InDesign":                   "Adobe InDesign",
    "FrameMaker":                 "Adobe FrameMaker",
    "CorelDRAW":                  "CorelDRAW",
    "Illustrator":                "Adobe Illustrator",
    "Pages":                      "Apple Pages",
    "Word for Mac":               "Microsoft Word (macOS)",
    "Mac OS X":                   "macOS CoreGraphics/Quartz",
    "Quartz":                     "macOS Quartz PDFContext",
    "PDF Architect":              "PDF Architect",
    "SmallPDF":                   "Smallpdf (Online)",
    "ILovePDF":                   "iLovePDF (Online)",
    "Sejda":                      "Sejda PDF (Online)",
    "PDF2GO":                     "PDF2Go (Online)",
    "pdfforge":                   "PDFForge",
    "ABBYY":                      "ABBYY FineReader (OCR)",
    "OmniPage":                   "OmniPage (OCR)",
    "Tesseract":                  "Tesseract OCR",
}

# Ghostscript-Quantisierungstabellen (Luminanz Q=75)
GHOSTSCRIPT_LUMA_QUANT_SIGNATURE = [
    16, 11, 10, 16, 24, 40, 51, 61,
    12, 12, 14, 19, 26, 58, 60, 55,
    14, 13, 16, 24, 40, 57, 69, 56,
    14, 17, 22, 29, 51, 87, 80, 62,
    18, 22, 37, 56, 68, 109, 103, 77,
    24, 35, 55, 64, 81, 104, 113, 92,
    49, 64, 78, 87, 103, 121, 120, 101,
    72, 92, 95, 98, 112, 100, 103, 99,
]

# Virus-Scan
VIRUSTOTAL_API_KEY = os.environ.get("VT_API_KEY", "")   # leer = deaktiviert
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"
CLAMAV_SOCKET     = os.environ.get("CLAMAV_SOCKET", "/var/run/clamav/clamd.ctl")

# KI-Backend — lokales Ollama (OpenAI-kompatibler Endpoint)
OLLAMA_BASE_URL    = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_API_URL     = f"{OLLAMA_BASE_URL}/v1/chat/completions"
# Review = tiefe forensische Bewertung → großes Reasoning-Modell (26B, Q8_0)
OLLAMA_REVIEW_MODEL = os.environ.get("OLLAMA_REVIEW_MODEL", "gemma4-heretic:latest")
# Chat = schnelle Interaktion → kleines Modell (7.5B, Q8_0, passt voll in VRAM)
OLLAMA_CHAT_MODEL   = os.environ.get("OLLAMA_CHAT_MODEL", "igorls/gemma-4-E4B-it-heretic-GGUF:latest")
OLLAMA_TIMEOUT      = float(os.environ.get("OLLAMA_TIMEOUT", "600"))

# Bekannte A4-Dimensionen in Punkten (72 pt/inch)
A4_WIDTH_PT  = 595.28
A4_HEIGHT_PT = 841.89
A4_TOLERANCE_PT = 5.0  # Toleranz in Punkten
