from __future__ import annotations

import sqlite3
from pathlib import Path


CREATE_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scanned_at TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_name TEXT NOT NULL,
    label TEXT NOT NULL,
    legit_probability REAL NOT NULL,
    spam_probability REAL NOT NULL,
    confidence REAL NOT NULL,
    notes TEXT
);
"""


class ScanLogStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _init_db(self) -> None:
        with self._connect() as connection:
            connection.execute(CREATE_SQL)
            connection.commit()

    def log_scan(
        self,
        scanned_at: str,
        source_type: str,
        source_name: str,
        label: str,
        legit_probability: float,
        spam_probability: float,
        confidence: float,
        notes: str,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO scans (
                    scanned_at,
                    source_type,
                    source_name,
                    label,
                    legit_probability,
                    spam_probability,
                    confidence,
                    notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scanned_at,
                    source_type,
                    source_name,
                    label,
                    legit_probability,
                    spam_probability,
                    confidence,
                    notes,
                ),
            )
            connection.commit()

    def recent_scans(self, limit: int = 25) -> list[tuple]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT scanned_at, source_type, source_name, label,
                       legit_probability, spam_probability, confidence, notes
                FROM scans
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return rows
