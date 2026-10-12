from __future__ import annotations

import hashlib
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit


DB_PATH = Path(__file__).with_name("sitesentinel.db")
TRIAGE_STATES = ("Open", "Acknowledged", "Resolved")


@contextmanager
def _connection(db_path: str | Path = DB_PATH) -> Iterator[sqlite3.Connection]:
	connection = sqlite3.connect(db_path, timeout=5)
	connection.row_factory = sqlite3.Row
	connection.execute("PRAGMA foreign_keys = ON")
	try:
		yield connection
		connection.commit()
	except Exception:
		connection.rollback()
		raise
	finally:
		connection.close()


def initialize_db(db_path: str | Path = DB_PATH) -> None:
	with _connection(db_path) as connection:
		connection.executescript("""
		CREATE TABLE IF NOT EXISTS assessments (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			target TEXT NOT NULL,
			final_url TEXT NOT NULL,
			checked_at TEXT NOT NULL,
			status_code INTEGER NOT NULL,
			elapsed_ms INTEGER NOT NULL,
			redirects INTEGER NOT NULL,
			score INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS triage (
			fingerprint TEXT PRIMARY KEY,
			status TEXT NOT NULL CHECK (status IN ('Open', 'Acknowledged', 'Resolved')),
			updated_at TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS findings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
			fingerprint TEXT NOT NULL,
			title TEXT NOT NULL,
			severity TEXT NOT NULL,
			category TEXT NOT NULL,
			evidence TEXT NOT NULL,
			remediation TEXT NOT NULL,
			UNIQUE (assessment_id, fingerprint)
		);
		CREATE INDEX IF NOT EXISTS findings_assessment_idx ON findings(assessment_id);
		""")


def finding_fingerprint(target: str, category: str, title: str) -> str:
	host = urlsplit(target).netloc.lower()
	identity = "|".join((host, category.strip().lower(), title.strip().lower()))
	return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _finding_dict(finding: Any) -> dict[str, Any]:
	return asdict(finding) if is_dataclass(finding) else dict(finding)


def save_assessment(assessment: dict[str, Any], db_path: str | Path = DB_PATH) -> int:
	initialize_db(db_path)
	with _connection(db_path) as connection:
		cursor = connection.execute(
			"""INSERT INTO assessments
			   (target, final_url, checked_at, status_code, elapsed_ms, redirects, score)
			   VALUES (?, ?, ?, ?, ?, ?, ?)""",
			(
				assessment["target"], assessment["final_url"], assessment["checked_at"],
				assessment["status_code"], assessment["elapsed_ms"], assessment["redirects"],
				assessment["score"],
			),
		)
		assessment_id = int(cursor.lastrowid)
		for item in assessment["findings"]:
			finding = _finding_dict(item)
			fingerprint = finding_fingerprint(
				assessment["target"], finding["category"], finding["title"]
			)
			connection.execute(
				"""INSERT INTO findings
				   (assessment_id, fingerprint, title, severity, category, evidence, remediation)
				   VALUES (?, ?, ?, ?, ?, ?, ?)""",
				(
					assessment_id, fingerprint, finding["title"], finding["severity"],
					finding["category"], finding["evidence"], finding["remediation"],
				),
			)
	return assessment_id


def list_assessments(limit: int = 100, db_path: str | Path = DB_PATH) -> list[dict[str, Any]]:
	initialize_db(db_path)
	limit = max(1, min(int(limit), 500))
	with _connection(db_path) as connection:
		rows = connection.execute(
			"""SELECT a.*,
				COUNT(f.id) AS finding_count,
				COALESCE(SUM(CASE WHEN COALESCE(t.status, 'Open') = 'Open' THEN 1 ELSE 0 END), 0) AS open_count
			   FROM assessments AS a
			   LEFT JOIN findings AS f ON f.assessment_id = a.id
			   LEFT JOIN triage AS t ON t.fingerprint = f.fingerprint
			   GROUP BY a.id
			   ORDER BY a.id DESC
			   LIMIT ?""",
			(limit,),
		).fetchall()
	return [dict(row) for row in rows]


def get_assessment(assessment_id: int, db_path: str | Path = DB_PATH) -> dict[str, Any] | None:
	initialize_db(db_path)
	with _connection(db_path) as connection:
		assessment_row = connection.execute(
			"SELECT * FROM assessments WHERE id = ?", (assessment_id,)
		).fetchone()
		if assessment_row is None:
			return None
		assessment = dict(assessment_row)
		finding_rows = connection.execute(
			"""SELECT f.*, COALESCE(t.status, 'Open') AS triage_status
			   FROM findings AS f
			   LEFT JOIN triage AS t ON t.fingerprint = f.fingerprint
			   WHERE f.assessment_id = ?
			   ORDER BY CASE f.severity
				WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2
				WHEN 'Low' THEN 3 ELSE 4 END, f.title""",
			(assessment_id,),
		).fetchall()
		assessment["findings"] = [dict(row) for row in finding_rows]
	return assessment


def get_triage_status(fingerprint: str, db_path: str | Path = DB_PATH) -> str:
	initialize_db(db_path)
	with _connection(db_path) as connection:
		row = connection.execute(
			"SELECT status FROM triage WHERE fingerprint = ?", (fingerprint,)
		).fetchone()
	return str(row["status"]) if row else "Open"


def update_triage(fingerprint: str, status: str, db_path: str | Path = DB_PATH) -> None:
	if status not in TRIAGE_STATES:
		raise ValueError(f"Triage status must be one of: {', '.join(TRIAGE_STATES)}")
	initialize_db(db_path)
	updated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
	with _connection(db_path) as connection:
		connection.execute(
			"""INSERT INTO triage (fingerprint, status, updated_at) VALUES (?, ?, ?)
			   ON CONFLICT(fingerprint) DO UPDATE SET status = excluded.status,
			   updated_at = excluded.updated_at""",
			(fingerprint, status, updated_at),
		)


def export_assessment(assessment_id: int, db_path: str | Path = DB_PATH) -> dict[str, Any] | None:
	assessment = get_assessment(assessment_id, db_path)
	if assessment is None:
		return None
	for finding in assessment["findings"]:
		finding.pop("id", None)
		finding.pop("assessment_id", None)
		finding.pop("fingerprint", None)
	return assessment