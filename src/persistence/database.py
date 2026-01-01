"""SQLite database for scan persistence."""
import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import contextmanager
from .models import Target, Scan, Finding


class Database:
    """SQLite database for storing scan results."""

    def __init__(self, db_path: str = "scans.db"):
        self.db_path = Path(db_path)
        self._init_db()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self):
        """Initialize database schema."""
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    value TEXT NOT NULL,
                    target_type TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER REFERENCES targets(id),
                    scan_type TEXT,
                    status TEXT DEFAULT 'pending',
                    started_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    config TEXT DEFAULT '{}',
                    summary TEXT DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER REFERENCES scans(id),
                    finding_type TEXT,
                    severity TEXT DEFAULT 'info',
                    title TEXT,
                    description TEXT,
                    evidence TEXT,
                    url TEXT,
                    param TEXT,
                    payload TEXT,
                    raw_data TEXT DEFAULT '{}',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
                CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
                CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_id);
            """)

    # Target operations
    def create_target(self, target: Target) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO targets (value, target_type, metadata) VALUES (?, ?, ?)",
                (target.value, target.target_type, json.dumps(target.metadata))
            )
            return cur.lastrowid

    def get_target(self, target_id: int) -> Optional[Target]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
            return self._row_to_target(row) if row else None

    def find_target(self, value: str) -> Optional[Target]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM targets WHERE value = ?", (value,)).fetchone()
            return self._row_to_target(row) if row else None

    # Scan operations
    def create_scan(self, scan: Scan) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO scans (target_id, scan_type, status, started_at, config) VALUES (?, ?, ?, ?, ?)",
                (scan.target_id, scan.scan_type, scan.status, scan.started_at, json.dumps(scan.config))
            )
            return cur.lastrowid

    def update_scan(self, scan_id: int, status: str = None, summary: Dict = None, completed_at: datetime = None):
        updates, params = [], []
        if status:
            updates.append("status = ?"); params.append(status)
        if summary:
            updates.append("summary = ?"); params.append(json.dumps(summary))
        if completed_at:
            updates.append("completed_at = ?"); params.append(completed_at)
        if updates:
            params.append(scan_id)
            with self._conn() as conn:
                conn.execute(f"UPDATE scans SET {', '.join(updates)} WHERE id = ?", params)

    def get_scan(self, scan_id: int, include_findings: bool = True) -> Optional[Scan]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if not row:
                return None
            scan = self._row_to_scan(row)
            if include_findings:
                scan.findings = self.get_findings(scan_id)
            return scan

    def get_scans(self, target_id: int = None, limit: int = 50) -> List[Scan]:
        with self._conn() as conn:
            if target_id:
                rows = conn.execute(
                    "SELECT * FROM scans WHERE target_id = ? ORDER BY id DESC LIMIT ?",
                    (target_id, limit)
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [self._row_to_scan(r) for r in rows]

    # Finding operations
    def add_finding(self, finding: Finding) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                """INSERT INTO findings (scan_id, finding_type, severity, title, description,
                   evidence, url, param, payload, raw_data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (finding.scan_id, finding.finding_type, finding.severity, finding.title,
                 finding.description, finding.evidence, finding.url, finding.param,
                 finding.payload, json.dumps(finding.raw_data))
            )
            return cur.lastrowid

    def add_findings(self, findings: List[Finding]):
        with self._conn() as conn:
            conn.executemany(
                """INSERT INTO findings (scan_id, finding_type, severity, title, description,
                   evidence, url, param, payload, raw_data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [(f.scan_id, f.finding_type, f.severity, f.title, f.description,
                  f.evidence, f.url, f.param, f.payload, json.dumps(f.raw_data)) for f in findings]
            )

    def get_findings(self, scan_id: int, severity: str = None) -> List[Finding]:
        with self._conn() as conn:
            if severity:
                rows = conn.execute(
                    "SELECT * FROM findings WHERE scan_id = ? AND severity = ?", (scan_id, severity)
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,)).fetchall()
            return [self._row_to_finding(r) for r in rows]

    def get_findings_by_type(self, scan_id: int, finding_type: str) -> List[Finding]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE scan_id = ? AND finding_type = ?", (scan_id, finding_type)
            ).fetchall()
            return [self._row_to_finding(r) for r in rows]

    # Stats
    def get_stats(self, scan_id: int = None) -> Dict[str, Any]:
        with self._conn() as conn:
            if scan_id:
                rows = conn.execute(
                    "SELECT severity, COUNT(*) as cnt FROM findings WHERE scan_id = ? GROUP BY severity",
                    (scan_id,)
                ).fetchall()
            else:
                rows = conn.execute("SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity").fetchall()
            return {r["severity"]: r["cnt"] for r in rows}

    # Converters
    def _row_to_target(self, row) -> Target:
        return Target(
            id=row["id"], value=row["value"], target_type=row["target_type"],
            created_at=row["created_at"] if isinstance(row["created_at"], datetime) else datetime.now(),
            metadata=json.loads(row["metadata"] or "{}")
        )

    def _row_to_scan(self, row) -> Scan:
        return Scan(
            id=row["id"], target_id=row["target_id"], scan_type=row["scan_type"],
            status=row["status"], started_at=row["started_at"], completed_at=row["completed_at"],
            config=json.loads(row["config"] or "{}"), summary=json.loads(row["summary"] or "{}")
        )

    def _row_to_finding(self, row) -> Finding:
        return Finding(
            id=row["id"], scan_id=row["scan_id"], finding_type=row["finding_type"],
            severity=row["severity"], title=row["title"], description=row["description"],
            evidence=row["evidence"], url=row["url"], param=row["param"],
            payload=row["payload"], raw_data=json.loads(row["raw_data"] or "{}"),
            created_at=row["created_at"] if isinstance(row["created_at"], datetime) else datetime.now()
        )
