# Phase 1+2 — Calibration Upgrade

Branch: `rescue/vps-snapshot-2026-05-23`

## Ziel

Score 100/100 auf normaler Marketing-Broschüre eliminieren. Stattdessen:
- Dokumenttyp-bewusste Bewertung (`design_brochure` braucht andere Regeln als `office_letter`)
- Hard-HIGH (echte Security) vs. Soft-HIGH (Heuristik) trennen
- Risk-Level gewichtet, nicht „1 HIGH = HIGH gesamt"

## Phase 1 — Dokumenttyp-Klassifikator

- [ ] **A1** `analyzers/doc_type_classifier.py` neu — heuristische Klassifikation:
  - Kategorien: `office_letter`, `office_document`, `design_brochure`, `scan`,
    `form`, `technical_document`, `online_converted`, `unknown`
  - Inputs: `software_fingerprint`, `metadata.page_count`,
    `printer_forensics.is_scanned_document`, `signature.has_acroform`
  - Output: `DocTypeResult(doc_type, confidence, reasoning)`
- [ ] **A2** `models/schemas.py` — `DocTypeResult` hinzufügen, in `AnalysisResult` einhängen
- [ ] **A3** `analyzers/pipeline.py` — Classifier **früh** ausführen, an Cross-Analyzer durchreichen

## Phase 2 — Severity-Profile + gewichtetes Risk-Level

- [ ] **B1** `analyzers/severity_profiles.py` neu — Downgrade-Tabelle pro Doc-Typ:
  - `design_brochure`: ocr_text_mismatch → INFO, signature_reuse(phash) → INFO,
    ocg "Layer 1" → INFO, splicing_jpeg_ghost → LOW, residual_objects → LOW
  - `scan`: ocr_text_mismatch → LOW, font_forensics → INFO, yellow_dots → INFO
  - `form`: acroform → INFO
  - `office_letter`: keine Downgrades (Baseline)
- [ ] **B2** `HARD_HIGH_CATEGORIES` — Liste echter Security-Befunde die nie downgegradet werden
  (javascript_auto_exec, shadow_attack, embedded_executable, redaction_bypass,
   yara_critical, malware_clamav, signature_invalid_after_update)
- [ ] **B3** `analyzers/cross_analyzer.py` — `_compute_manipulation_score`:
  - Nimmt `doc_type` als Parameter
  - Wendet Downgrades aus B1 auf Anomalien an, bevor gezählt wird
  - Score = Hard-HIGH × 25 + Soft-HIGH × 5 + MEDIUM × 2 + LOW × 0.5
    + Korrelations-Bonus (wie bisher, aber Hard-/Soft-getrennt)
- [ ] **B4** `analyzers/pipeline.py` — `risk_level`-Berechnung weg von „1 HIGH = HIGH":
  - Hard-HIGH-Count: ≥1 → `HIGH`
  - Sonst Soft-HIGH-Count: ≥3 → `HIGH`, 1-2 → `MEDIUM`
  - Sonst MEDIUM-Count: ≥5 → `MEDIUM`, sonst `LOW`
  - Schwellen aus `config.py` per ENV überschreibbar
- [ ] **B5** `config.py` — neue Konstanten:
  `RISK_HARD_HIGH_THRESHOLD`, `RISK_SOFT_HIGH_THRESHOLD`, `RISK_MEDIUM_THRESHOLD`,
  `SCORE_HARD_HIGH_WEIGHT`, `SCORE_SOFT_HIGH_WEIGHT`, …

## Abnahme-Test

- [ ] Dangote-Marketing-PDF (`CorelDRAW`-Broschüre, 19 MB) → erwartet:
  - `doc_type = design_brochure`
  - OCR-Mismatch-Findings → INFO statt HIGH
  - Manipulation-Score < 30
  - Risk-Level `LOW` oder `MEDIUM`, nicht `HIGH`
- [ ] NOSA-Petroleum-PDF (Office-Brief mit Scans, 1.66 MB) → unverändert sinnvoll (HIGH wenn echte Befunde)
- [ ] Pipeline läuft weiterhin in < 30 s (Profile=standard)
- [ ] Tests im Browser: Phase 6 weiterhin korrekt, AI-Review weiterhin sauber
