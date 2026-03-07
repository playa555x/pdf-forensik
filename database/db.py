"""
Datenbankzugriff für PDF-Forensik-Analyzer.
SQLite via aiosqlite für async I/O.
"""
import json
import sqlite3
from pathlib import Path
from typing import Optional, List

import aiosqlite

from config import DB_PATH
from models.schemas import AnalysisResult, AnalysisSummary, CompareResult, RiskLevel


class _NumpyEncoder(json.JSONEncoder):
    """JSON-Encoder der numpy-Typen in native Python-Typen konvertiert."""
    def default(self, obj):
        try:
            import numpy as np
            if isinstance(obj, np.bool_):
                return bool(obj)
            if isinstance(obj, np.integer):
                return int(obj)
            if isinstance(obj, np.floating):
                return float(obj)
            if isinstance(obj, np.ndarray):
                return obj.tolist()
        except ImportError:
            pass
        return super().default(obj)


def _safe_model_json(result) -> str:
    """model_dump_json()-Ersatz der numpy-Typen korrekt serialisiert."""
    data = result.model_dump()
    return json.dumps(data, cls=_NumpyEncoder)

SCHEMA_PATH = Path(__file__).parent / "schema.sql"


async def init_db() -> None:
    """Datenbank initialisieren und Schema anlegen."""
    schema = SCHEMA_PATH.read_text(encoding="utf-8")
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(schema)
        await db.commit()


async def _ensure_phase4_columns(db) -> None:
    """Fügt Phase-4-Spalten hinzu falls noch nicht vorhanden (Migration)."""
    for col in ["font_prefixes_json TEXT", "quant_tables_json TEXT",
                "ai_review_de TEXT", "ai_review_en TEXT"]:
        try:
            await db.execute(f"ALTER TABLE analyses ADD COLUMN {col}")
        except Exception:
            pass


async def save_analysis(result: AnalysisResult) -> None:
    """Analyse-Ergebnis in DB speichern."""
    # Font-Präfixe für Cross-Match
    font_prefixes = json.dumps([
        fp.get('prefix', fp.get('name', ''))
        for fp in (result.author_artifacts.font_prefixes if result.author_artifacts else [])
    ], cls=_NumpyEncoder)
    # Quant-Signatur für Cross-Match
    quant_sig = json.dumps(
        result.quant_fingerprint.matches[:3] if result.quant_fingerprint else [],
        cls=_NumpyEncoder,
    )

    async with aiosqlite.connect(DB_PATH) as db:
        await _ensure_phase4_columns(db)
        await db.execute(
            """
            INSERT INTO analyses
                (id, filename, file_size, analyzed_at, md5, sha1, sha256, sha512,
                 result_json, report_path, risk_level,
                 anomaly_count_high, anomaly_count_medium, anomaly_count_low,
                 font_prefixes_json, quant_tables_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.analysis_id,
                result.filename,
                result.file_size_bytes,
                result.analyzed_at,
                result.hashes.md5,
                result.hashes.sha1,
                result.hashes.sha256,
                result.hashes.sha512,
                _safe_model_json(result),
                None,
                result.risk_level.value,
                result.anomaly_count_high,
                result.anomaly_count_medium,
                result.anomaly_count_low,
                font_prefixes,
                quant_sig,
            ),
        )
        await db.commit()


async def get_analysis(analysis_id: str) -> Optional[AnalysisResult]:
    """Einzelne Analyse aus DB laden."""
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT result_json FROM analyses WHERE id = ?", (analysis_id,)
        ) as cursor:
            row = await cursor.fetchone()
            if row is None:
                return None
            return AnalysisResult.model_validate_json(row[0])


async def get_analysis_summary(analysis_id: str) -> Optional[dict]:
    """Zusammenfassung einer Analyse laden (ohne vollständiges JSON)."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            """
            SELECT id, filename, file_size, analyzed_at, md5, sha256,
                   risk_level, anomaly_count_high, anomaly_count_medium,
                   anomaly_count_low, report_path
            FROM analyses WHERE id = ?
            """,
            (analysis_id,),
        ) as cursor:
            row = await cursor.fetchone()
            if row is None:
                return None
            return dict(row)


async def update_report_path(analysis_id: str, report_path: str) -> None:
    """Report-Pfad nach Generierung speichern."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE analyses SET report_path = ? WHERE id = ?",
            (report_path, analysis_id),
        )
        await db.commit()


async def update_comparison_report_path(comparison_id: str, report_path: str) -> None:
    """Report-Pfad für Vergleich speichern."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE comparisons SET report_path = ? WHERE id = ?",
            (report_path, comparison_id),
        )
        await db.commit()


async def delete_analysis(analysis_id: str) -> bool:
    """Analyse aus DB löschen. Gibt True zurück wenn gefunden."""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            "DELETE FROM analyses WHERE id = ?", (analysis_id,)
        )
        await db.commit()
        return cursor.rowcount > 0


async def list_analyses(limit: int = 50, offset: int = 0) -> List[dict]:
    """Alle Analysen sortiert nach Datum (neueste zuerst)."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            """
            SELECT id, filename, file_size, analyzed_at, md5, sha256,
                   risk_level, anomaly_count_high, anomaly_count_medium,
                   anomaly_count_low, report_path
            FROM analyses
            ORDER BY analyzed_at DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]


async def search_analyses(
    q: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
) -> List[dict]:
    """Analysen suchen nach Dateiname und Datumsbereich."""
    conditions = []
    params = []

    if q:
        conditions.append("(filename LIKE ? OR md5 LIKE ? OR sha256 LIKE ?)")
        like = f"%{q}%"
        params.extend([like, like, like])

    if date_from:
        conditions.append("analyzed_at >= ?")
        params.append(date_from)

    if date_to:
        conditions.append("analyzed_at <= ?")
        params.append(date_to + "T23:59:59Z")

    where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            f"""
            SELECT id, filename, file_size, analyzed_at, md5, sha256,
                   risk_level, anomaly_count_high, anomaly_count_medium,
                   anomaly_count_low, report_path
            FROM analyses
            {where_clause}
            ORDER BY analyzed_at DESC
            LIMIT 200
            """,
            params,
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]


async def save_comparison(result: CompareResult) -> None:
    """Vergleichs-Ergebnis speichern."""
    async with aiosqlite.connect(DB_PATH) as db:
        analysis_ids = json.dumps([d.analysis_id for d in result.documents])
        await db.execute(
            """
            INSERT INTO comparisons (id, compared_at, analysis_ids, result_json, report_path)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                result.comparison_id,
                result.compared_at,
                analysis_ids,
                _safe_model_json(result),
                None,
            ),
        )
        await db.commit()


async def get_comparison(comparison_id: str) -> Optional[CompareResult]:
    """Vergleich aus DB laden."""
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT result_json FROM comparisons WHERE id = ?", (comparison_id,)
        ) as cursor:
            row = await cursor.fetchone()
            if row is None:
                return None
            return CompareResult.model_validate_json(row[0])


async def count_analyses() -> int:
    """Gesamtanzahl der Analysen."""
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT COUNT(*) FROM analyses") as cursor:
            row = await cursor.fetchone()
            return row[0] if row else 0


async def find_font_prefix_matches(prefixes: list, exclude_id: str) -> list:
    """Gibt alle Analysen zurück die mindestens einen der Font-Präfixe enthalten."""
    if not prefixes:
        return []
    results = []
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            """
            SELECT id, filename, analyzed_at, risk_level, font_prefixes_json,
                   anomaly_count_high, anomaly_count_medium, anomaly_count_low
            FROM analyses
            WHERE id != ? AND font_prefixes_json IS NOT NULL
            ORDER BY analyzed_at DESC
            LIMIT 100
            """,
            (exclude_id,),
        ) as cursor:
            rows = await cursor.fetchall()
            for row in rows:
                try:
                    stored = json.loads(row['font_prefixes_json'] or '[]')
                    shared = [p for p in prefixes if p and p in stored]
                    if shared:
                        results.append({
                            "id": row['id'],
                            "filename": row['filename'],
                            "analyzed_at": row['analyzed_at'],
                            "risk_level": row['risk_level'],
                            "shared_prefixes": shared[:10],
                            "anomaly_count_high": row['anomaly_count_high'],
                        })
                except Exception:
                    pass
    return results


async def find_quant_table_matches(quant_sig: str, exclude_id: str) -> list:
    """Gibt alle Analysen zurück mit derselben Quantisierungstabellen-Signatur."""
    if not quant_sig or quant_sig == '[]':
        return []
    results = []
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            """
            SELECT id, filename, analyzed_at, risk_level, quant_tables_json,
                   anomaly_count_high
            FROM analyses
            WHERE id != ? AND quant_tables_json = ? AND quant_tables_json != '[]'
            ORDER BY analyzed_at DESC
            LIMIT 50
            """,
            (exclude_id, quant_sig),
        ) as cursor:
            rows = await cursor.fetchall()
            for row in rows:
                results.append({
                    "id": row['id'],
                    "filename": row['filename'],
                    "analyzed_at": row['analyzed_at'],
                    "risk_level": row['risk_level'],
                    "anomaly_count_high": row['anomaly_count_high'],
                })
    return results


async def save_ai_review(analysis_id: str, lang: str, review: dict) -> None:
    """KI-Review-Ergebnis persistent in DB speichern."""
    col = "ai_review_de" if lang == "de" else "ai_review_en"
    async with aiosqlite.connect(DB_PATH) as db:
        await _ensure_phase4_columns(db)
        await db.execute(
            f"UPDATE analyses SET {col} = ? WHERE id = ?",
            (json.dumps(review, ensure_ascii=False), analysis_id),
        )
        await db.commit()


async def get_ai_review(analysis_id: str, lang: str) -> Optional[dict]:
    """Gespeichertes KI-Review aus DB laden. None wenn noch nicht vorhanden."""
    col = "ai_review_de" if lang == "de" else "ai_review_en"
    async with aiosqlite.connect(DB_PATH) as db:
        await _ensure_phase4_columns(db)
        db.row_factory = aiosqlite.Row
        async with db.execute(
            f"SELECT {col} FROM analyses WHERE id = ?", (analysis_id,)
        ) as cursor:
            row = await cursor.fetchone()
            if row and row[col]:
                try:
                    return json.loads(row[col])
                except Exception:
                    return None
    return None
