from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any, Iterator

from secureops.analysis.models import PacketEvent, TrafficSnapshot
from secureops.detection import DetectionAlert


class SQLiteStore:
    """SQLite persistence for packet events, traffic snapshots, and alerts."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def initialize(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS packet_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    src_port INTEGER,
                    dst_port INTEGER
                );

                CREATE INDEX IF NOT EXISTS idx_packet_events_timestamp
                ON packet_events(timestamp);

                CREATE INDEX IF NOT EXISTS idx_packet_events_src_ip
                ON packet_events(src_ip);

                CREATE TABLE IF NOT EXISTS traffic_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    generated_at TEXT NOT NULL,
                    window_seconds INTEGER NOT NULL,
                    total_packets INTEGER NOT NULL,
                    packets_per_second REAL NOT NULL,
                    unique_sources INTEGER NOT NULL,
                    unique_destinations INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS detection_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    detector TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    observed_value TEXT NOT NULL,
                    threshold TEXT NOT NULL,
                    src_ip TEXT ,
                    
                    confidence REAL DEFAULT 0,
                    risk_score INTEGER DEFAULT 0,
                    action TEXT DEFAULT 'Logged',
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    resolved_at TEXT
                );

                """
            )
            self._migrate_detection_alerts(conn)
            conn.executescript(
                """
                CREATE INDEX IF NOT EXISTS idx_detection_alerts_status
                ON detection_alerts(status);

                CREATE INDEX IF NOT EXISTS idx_detection_alerts_timestamp
                ON detection_alerts(timestamp);

                CREATE UNIQUE INDEX IF NOT EXISTS idx_detection_alerts_active_unique
                ON detection_alerts(detector, reason, COALESCE(src_ip, ''), status)
                WHERE status = 'ACTIVE';
                """
            )

    def save_packet(self, event: PacketEvent) -> None:
        with self._locked_connection() as conn:
            conn.execute(
                """
                INSERT INTO packet_events
                (timestamp, src_ip, dst_ip, protocol, size_bytes, src_port, dst_port)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.timestamp.isoformat(),
                    event.src_ip,
                    event.dst_ip,
                    event.protocol,
                    event.size_bytes,
                    event.src_port,
                    event.dst_port,
                ),
            )

    def save_snapshot(self, snapshot: TrafficSnapshot) -> None:
        with self._locked_connection() as conn:
            conn.execute(
                """
                INSERT INTO traffic_snapshots
                (generated_at, window_seconds, total_packets, packets_per_second,
                 unique_sources, unique_destinations)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot.generated_at.isoformat(),
                    snapshot.window_seconds,
                    snapshot.total_packets,
                    snapshot.packets_per_second,
                    snapshot.unique_sources,
                    snapshot.unique_destinations,
                ),
            )

    def save_alert(self, alert: DetectionAlert) -> bool:
        """Insert a new ACTIVE alert or refresh the existing active alert evidence.

        Returns True when a new row was inserted and False when an existing
        active alert was updated.
        """
        with self._locked_connection() as conn:
            existing = conn.execute(
                """
                SELECT id
                FROM detection_alerts
                WHERE detector = ?
                  AND reason = ?
                  AND COALESCE(src_ip, '') = COALESCE(?, '')
                  AND status = 'ACTIVE'
                ORDER BY id DESC
                LIMIT 1
                """,
                (alert.detector, alert.reason, alert.src_ip),
            ).fetchone()

            if existing:
                conn.execute(
                    """
                    UPDATE detection_alerts
                    SET timestamp = ?,
                        severity = ?,
                        observed_value = ?,
                        threshold = ?,
                        confidence = ?,
                        risk_score = ?,
                        action = ?
                    WHERE id = ?
                    """,
                    (
                        alert.timestamp.isoformat(),
                        alert.severity,
                        str(alert.observed_value),
                        str(alert.threshold),
                        alert.confidence,
                        alert.risk_score,
                        alert.action,
                        existing["id"],
                    ),
                )
                return False

            conn.execute(
                """
                INSERT INTO detection_alerts
                (
                detector,
                timestamp,
                severity,
                reason,
                observed_value,
                threshold,
                src_ip,
                confidence,
                risk_score,
                action,
                status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE')
                """,
                (
                    alert.detector,
                    alert.timestamp.isoformat(),
                    alert.severity,
                    alert.reason,
                    str(alert.observed_value),
                    str(alert.threshold),
                    alert.src_ip,
                    alert.confidence,
                    alert.risk_score,
                    alert.action,
                ),
            )
            return True

    def recent_alerts(
        self,
        limit: int = 100,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        normalized_status = status.upper() if status else None
        with self._connect() as conn:
            if normalized_status:
                rows = conn.execute(
                    """
                    SELECT id,
                           detector,
                           timestamp,
                           severity,
                           reason,
                           observed_value,
                           threshold,
                           src_ip,
                           confidence,
                           risk_score,
                           action,
                           status,
                           resolved_at
                    FROM detection_alerts
                    WHERE status = ?
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (normalized_status, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                """
                SELECT id,
                       detector,
                       timestamp,
                       severity,
                       reason,
                       observed_value,
                       threshold,
                       src_ip,
                       confidence,
                       risk_score,
                       action,
                       status,
                       resolved_at
                FROM detection_alerts
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
                ).fetchall()
        return [dict(row) for row in rows]

    def recent_packets(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT timestamp, src_ip, dst_ip, protocol, size_bytes, src_port, dst_port
                FROM packet_events
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def counts(self) -> dict[str, int]:
        with self._connect() as conn:
            packet_count = conn.execute("SELECT COUNT(*) FROM packet_events").fetchone()[0]
            alert_count = conn.execute("SELECT COUNT(*) FROM detection_alerts").fetchone()[0]
            active_alert_count = conn.execute(
                "SELECT COUNT(*) FROM detection_alerts WHERE status = 'ACTIVE'"
            ).fetchone()[0]
        return {
            "packet_events": packet_count,
            "alerts": alert_count,
            "active_alerts": active_alert_count,
        }

    def resolve_alert(self, alert_id: int) -> bool:
        resolved_at = datetime.now(timezone.utc).isoformat()
        with self._locked_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE detection_alerts
                SET status = 'RESOLVED',
                    resolved_at = ?
                WHERE id = ? AND status != 'RESOLVED'
                """,
                (resolved_at, alert_id),
            )
            return cursor.rowcount > 0

    def delete_alert(self, alert_id: int) -> bool:
        with self._locked_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM detection_alerts WHERE id = ?",
                (alert_id,),
            )
            return cursor.rowcount > 0

    def clear_alerts(self, status: str | None = None) -> int:
        with self._locked_connection() as conn:
            if status:
                cursor = conn.execute(
                    "DELETE FROM detection_alerts WHERE status = ?",
                    (status.upper(),),
                )
            else:
                cursor = conn.execute("DELETE FROM detection_alerts")
            return cursor.rowcount

    @contextmanager
    def _locked_connection(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            with self._connect() as conn:
                yield conn

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _migrate_detection_alerts(self, conn: sqlite3.Connection) -> None:
        columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(detection_alerts)").fetchall()
        }
        if "status" not in columns:
            conn.execute(
                "ALTER TABLE detection_alerts ADD COLUMN status TEXT NOT NULL DEFAULT 'ACTIVE'"
            )
        if "resolved_at" not in columns:
            conn.execute("ALTER TABLE detection_alerts ADD COLUMN resolved_at TEXT")
        if "confidence" not in columns:
            conn.execute("ALTER TABLE detection_alerts ADD COLUMN confidence REAL DEFAULT 0")
        if "risk_score" not in columns:
            conn.execute("ALTER TABLE detection_alerts ADD COLUMN risk_score INTEGER DEFAULT 0")
        if "action" not in columns:
            conn.execute("ALTER TABLE detection_alerts ADD COLUMN action TEXT DEFAULT 'Logged'")
        self._resolve_duplicate_active_alerts(conn)

    def _resolve_duplicate_active_alerts(self, conn: sqlite3.Connection) -> None:
        resolved_at = datetime.now(timezone.utc).isoformat()
        rows = conn.execute(
            """
            SELECT detector, reason, COALESCE(src_ip, '') AS src_ip_key, MAX(id) AS keep_id
            FROM detection_alerts
            WHERE status = 'ACTIVE'
            GROUP BY detector, reason, COALESCE(src_ip, '')
            HAVING COUNT(*) > 1
            """
        ).fetchall()
        for row in rows:
            conn.execute(
                """
                UPDATE detection_alerts
                SET status = 'RESOLVED',
                    resolved_at = ?
                WHERE status = 'ACTIVE'
                  AND detector = ?
                  AND reason = ?
                  AND COALESCE(src_ip, '') = ?
                  AND id != ?
                """,
                (
                    resolved_at,
                    row["detector"],
                    row["reason"],
                    row["src_ip_key"],
                    row["keep_id"],
                ),
            )

    def _to_jsonable(self, value: Any) -> Any:
        if is_dataclass(value):
            return self._to_jsonable(asdict(value))
        if isinstance(value, datetime):
            return value.astimezone(timezone.utc).isoformat()
        if isinstance(value, dict):
            return {key: self._to_jsonable(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [self._to_jsonable(item) for item in value]
        return value
