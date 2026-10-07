"""Load parsed authentication events into SQLite.

One row per attempt, so COUNT(*) is the number of attempts. Each load replaces
the table inside a single transaction: running it twice gives the same result,
and a failure halfway leaves the previous data untouched.

Usage:
    python -m src.storage data/raw/SSH.log --start-year 2017
"""

import argparse
import sqlite3
import time
from collections.abc import Iterable
from pathlib import Path

from src.parser import AuthEvent, parse_file

DEFAULT_DB = Path(__file__).resolve().parent.parent / "data" / "processed" / "ssh.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS auth_events (
    id            INTEGER PRIMARY KEY,
    timestamp     TEXT    NOT NULL,  -- ISO 8601, 'YYYY-MM-DD HH:MM:SS'
    host          TEXT    NOT NULL,
    pid           INTEGER NOT NULL,
    ip            TEXT    NOT NULL,
    port          INTEGER NOT NULL,
    username      TEXT    NOT NULL,
    method        TEXT    NOT NULL,
    success       INTEGER NOT NULL CHECK (success IN (0, 1)),
    invalid_user  INTEGER NOT NULL CHECK (invalid_user IN (0, 1)),
    repeated      INTEGER NOT NULL CHECK (repeated IN (0, 1))
);
CREATE INDEX IF NOT EXISTS idx_auth_events_timestamp ON auth_events (timestamp);
CREATE INDEX IF NOT EXISTS idx_auth_events_ip        ON auth_events (ip);
CREATE INDEX IF NOT EXISTS idx_auth_events_username  ON auth_events (username);
"""

INSERT = """
INSERT INTO auth_events
    (timestamp, host, pid, ip, port, username, method, success, invalid_user, repeated)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def connect(db_path: str | Path = DEFAULT_DB) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    return conn


def to_row(e: AuthEvent) -> tuple:
    return (
        e.timestamp.isoformat(sep=" "),
        e.host,
        e.pid,
        e.ip,
        e.port,
        e.user,
        e.method,
        int(e.success),
        int(e.invalid_user),
        int(e.repeated),
    )


def load_events(conn: sqlite3.Connection, events: Iterable[AuthEvent]) -> int:
    """Replace all rows with the given events. Returns the number of rows."""
    with conn:  # one transaction: commit on success, rollback on error
        conn.execute("DELETE FROM auth_events")
        conn.executemany(INSERT, (to_row(e) for e in events))
    return conn.execute("SELECT COUNT(*) FROM auth_events").fetchone()[0]


def main() -> None:
    cli = argparse.ArgumentParser(description="Parse an sshd log and load it into SQLite.")
    cli.add_argument("path", help="path to the log file")
    cli.add_argument("--start-year", type=int, required=True,
                     help="year of the first line (logs have no year)")
    cli.add_argument("--db", default=DEFAULT_DB, help=f"SQLite file (default: {DEFAULT_DB})")
    args = cli.parse_args()

    start = time.perf_counter()
    conn = connect(args.db)
    try:
        rows = load_events(conn, parse_file(args.path, args.start_year))
    finally:
        conn.close()
    print(f"Loaded {rows:,} events into {args.db} in {time.perf_counter() - start:.1f}s")


if __name__ == "__main__":
    main()
