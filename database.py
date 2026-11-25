"""SQLite persistence layer.

Every query uses bound parameters (?), never string formatting, so user input
can not alter the SQL statement (SQL-injection protection).

Run ``python database.py`` to create / verify the database manually.
The app also calls init_db() automatically on start-up.
"""
import os
import sqlite3
from contextlib import contextmanager

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR = os.path.join(BASE_DIR, "database")
DB_PATH = os.path.join(DB_DIR, "scanner.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id          INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target           TEXT NOT NULL,
    resolved_ip      TEXT NOT NULL,
    start_port       INTEGER NOT NULL,
    end_port         INTEGER NOT NULL,
    timeout          REAL NOT NULL,
    workers          INTEGER NOT NULL,
    status           TEXT NOT NULL DEFAULT 'running',
    started_at       TEXT NOT NULL,
    completed_at     TEXT,
    duration_seconds REAL,
    total_scanned    INTEGER NOT NULL DEFAULT 0,
    open_count       INTEGER NOT NULL DEFAULT 0,
    closed_count     INTEGER NOT NULL DEFAULT 0,
    filtered_count   INTEGER NOT NULL DEFAULT 0,
    high_count       INTEGER NOT NULL DEFAULT 0,
    medium_count     INTEGER NOT NULL DEFAULT 0,
    overall_risk     TEXT NOT NULL DEFAULT 'NONE',
    error            TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id, id DESC);

CREATE TABLE IF NOT EXISTS scan_ports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    port        INTEGER NOT NULL,
    service     TEXT NOT NULL,
    status      TEXT NOT NULL,
    risk        TEXT NOT NULL,
    explanation TEXT NOT NULL,
    mitigation  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ports_scan ON scan_ports(scan_id, port);

CREATE TABLE IF NOT EXISTS authorized_targets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target     TEXT NOT NULL COLLATE NOCASE,
    note       TEXT,
    created_at TEXT NOT NULL,
    UNIQUE (user_id, target)
);

CREATE TABLE IF NOT EXISTS risk_overrides (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    port    INTEGER NOT NULL,
    risk    TEXT NOT NULL,
    PRIMARY KEY (user_id, port)
);
"""


def get_connection():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def db():
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create tables and mark scans interrupted by a restart as failed."""
    with db() as c:
        c.executescript(SCHEMA)
        c.execute(
            "UPDATE scans SET status='failed', error='Interrupted: application was restarted.' "
            "WHERE status='running'"
        )


# ---------------------------------------------------------------- users
def create_user(username, email, password_hash, created_at):
    with db() as c:
        cur = c.execute(
            "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (username, email, password_hash, created_at),
        )
        return cur.lastrowid


def get_user_by_login(identifier):
    with db() as c:
        row = c.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?", (identifier, identifier)
        ).fetchone()
    return dict(row) if row else None


def get_user_by_id(user_id):
    with db() as c:
        row = c.execute("SELECT id, username, email, created_at FROM users WHERE id = ?", (user_id,)).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------- scans
def create_scan(user_id, target, resolved_ip, start_port, end_port, timeout, workers, started_at):
    with db() as c:
        cur = c.execute(
            "INSERT INTO scans (user_id, target, resolved_ip, start_port, end_port, timeout, workers, "
            "status, started_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'running', ?)",
            (user_id, target, resolved_ip, start_port, end_port, timeout, workers, started_at),
        )
        return cur.lastrowid


def finish_scan(scan_id, status, completed_at, duration, scanned, closed, filtered,
                high, medium, overall_risk, ports):
    with db() as c:
        c.execute(
            "UPDATE scans SET status=?, completed_at=?, duration_seconds=?, total_scanned=?, "
            "open_count=?, closed_count=?, filtered_count=?, high_count=?, medium_count=?, "
            "overall_risk=? WHERE id=?",
            (status, completed_at, duration, scanned, len(ports), closed, filtered,
             high, medium, overall_risk, scan_id),
        )
        c.executemany(
            "INSERT INTO scan_ports (scan_id, port, service, status, risk, explanation, mitigation) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(scan_id, p["port"], p["service"], p["status"], p["risk"], p["explanation"], p["mitigation"])
             for p in ports],
        )


def fail_scan(scan_id, completed_at, message):
    with db() as c:
        c.execute(
            "UPDATE scans SET status='failed', completed_at=?, error=? WHERE id=?",
            (completed_at, message, scan_id),
        )


def get_scan(user_id, scan_id):
    with db() as c:
        row = c.execute("SELECT * FROM scans WHERE id = ? AND user_id = ?", (scan_id, user_id)).fetchone()
    return dict(row) if row else None


def get_scan_ports(scan_id):
    with db() as c:
        rows = c.execute("SELECT * FROM scan_ports WHERE scan_id = ? ORDER BY port", (scan_id,)).fetchall()
    return [dict(r) for r in rows]


def list_scans(user_id, limit=None):
    sql = "SELECT * FROM scans WHERE user_id = ? ORDER BY id DESC"
    params = [user_id]
    if limit:
        sql += " LIMIT ?"
        params.append(int(limit))
    with db() as c:
        rows = c.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def delete_scan(user_id, scan_id):
    with db() as c:
        cur = c.execute("DELETE FROM scans WHERE id = ? AND user_id = ?", (scan_id, user_id))
        return cur.rowcount > 0


def dashboard_stats(user_id):
    with db() as c:
        totals = c.execute(
            "SELECT COUNT(*) AS scans, COALESCE(SUM(open_count),0) AS open_ports, "
            "COALESCE(SUM(closed_count),0) AS closed_ports, COALESCE(SUM(filtered_count),0) AS filtered_ports "
            "FROM scans WHERE user_id = ? AND status IN ('completed','cancelled')", (user_id,)
        ).fetchone()
        high = c.execute(
            "SELECT COUNT(*) AS n FROM scan_ports sp JOIN scans s ON s.id = sp.scan_id "
            "WHERE s.user_id = ? AND sp.risk = 'HIGH'", (user_id,)
        ).fetchone()["n"]
        dist = c.execute(
            "SELECT sp.port, sp.service, COUNT(*) AS n FROM scan_ports sp JOIN scans s ON s.id = sp.scan_id "
            "WHERE s.user_id = ? GROUP BY sp.port, sp.service ORDER BY n DESC, sp.port LIMIT 10", (user_id,)
        ).fetchall()
        risks = c.execute(
            "SELECT sp.risk, COUNT(*) AS n FROM scan_ports sp JOIN scans s ON s.id = sp.scan_id "
            "WHERE s.user_id = ? GROUP BY sp.risk", (user_id,)
        ).fetchall()
    return {
        "total_scans": totals["scans"],
        "total_open_ports": totals["open_ports"],
        "total_closed_ports": totals["closed_ports"],
        "total_filtered_ports": totals["filtered_ports"],
        "high_risk_ports": high,
        "open_port_distribution": [dict(r) for r in dist],
        "risk_distribution": {r["risk"]: r["n"] for r in risks},
    }


# ---------------------------------------------------- authorized targets
def list_authorized_targets(user_id):
    with db() as c:
        rows = c.execute(
            "SELECT id, target, note, created_at FROM authorized_targets WHERE user_id = ? ORDER BY id DESC",
            (user_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def add_authorized_target(user_id, target, note, created_at):
    with db() as c:
        cur = c.execute(
            "INSERT INTO authorized_targets (user_id, target, note, created_at) VALUES (?, ?, ?, ?)",
            (user_id, target, note, created_at),
        )
        return cur.lastrowid


def delete_authorized_target(user_id, target_id):
    with db() as c:
        cur = c.execute("DELETE FROM authorized_targets WHERE id = ? AND user_id = ?", (target_id, user_id))
        return cur.rowcount > 0


# ------------------------------------------------------- risk overrides
def get_risk_overrides(user_id):
    with db() as c:
        rows = c.execute("SELECT port, risk FROM risk_overrides WHERE user_id = ?", (user_id,)).fetchall()
    return {r["port"]: r["risk"] for r in rows}


def set_risk_override(user_id, port, risk):
    with db() as c:
        c.execute(
            "INSERT INTO risk_overrides (user_id, port, risk) VALUES (?, ?, ?) "
            "ON CONFLICT(user_id, port) DO UPDATE SET risk = excluded.risk",
            (user_id, port, risk),
        )


def delete_risk_override(user_id, port):
    with db() as c:
        c.execute("DELETE FROM risk_overrides WHERE user_id = ? AND port = ?", (user_id, port))


if __name__ == "__main__":
    init_db()
    print(f"Database ready: {DB_PATH}")
