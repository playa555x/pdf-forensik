# PDF Forensik Analyzer — Docker Image
# Playwright braucht Chromium + System-Dependencies

FROM python:3.11-slim

# System-Dependencies für pikepdf, Pillow, Playwright Chromium
RUN apt-get update && apt-get install -y --no-install-recommends \
    # pikepdf / qpdf
    libqpdf-dev \
    qpdf \
    binwalk \
    curl \
    tesseract-ocr \
    tesseract-ocr-deu \
    tesseract-ocr-eng \
    libimage-exiftool-perl \
    poppler-utils \
    libgl1 \
    libglib2.0-0 \
    # Pillow
    libjpeg-dev \
    libpng-dev \
    libtiff-dev \
    libwebp-dev \
    # pyhanko / cryptography
    libssl-dev \
    libffi-dev \
    # Playwright Chromium System-Deps
    libglib2.0-0 \
    libnss3 \
    libnspr4 \
    libdbus-1-3 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxcb1 \
    libxkbcommon0 \
    libx11-6 \
    libxcomposite1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libpango-1.0-0 \
    libcairo2 \
    libasound2 \
    libexpat1 \
    libxshmfence1 \
    fonts-liberation \
    fonts-noto-color-emoji \
    # Build tools
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Requirements zuerst (Layer-Caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Playwright Chromium installieren
RUN pip install --no-deps peepdf==0.4.2 jsbeautifier==1.6.2 pythonaes==1.0 && playwright install chromium

# App-Code
COPY . .

# Verzeichnisse anlegen
RUN mkdir -p uploads extracted_images generated_reports tools && (curl -sL -o tools/mpeepdf.py https://raw.githubusercontent.com/Tholep/mpeepdf/master/peepdf.py || curl -sL -o tools/mpeepdf.py https://raw.githubusercontent.com/jesparza/peepdf/master/peepdf.py || true)

# Host auf 0.0.0.0 für Container (Render setzt PORT env var)
ENV HOST=0.0.0.0
ENV PORT=10000

EXPOSE 10000

CMD ["python", "app.py"]
