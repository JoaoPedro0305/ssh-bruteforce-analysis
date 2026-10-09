from pathlib import Path

import pytest

from src.parser import parse_file, parse_lines
from src.storage import connect, load_events

SAMPLE = Path(__file__).resolve().parent.parent / "data" / "sample" / "auth_sample.log"


@pytest.fixture
def conn(tmp_path):
    conn = connect(tmp_path / "test.db")
    yield conn
    conn.close()


def count(conn, where="1=1"):
    return conn.execute(f"SELECT COUNT(*) FROM auth_events WHERE {where}").fetchone()[0]


def test_loads_one_row_per_attempt(conn):
    rows = load_events(conn, parse_file(SAMPLE, 2026))
    assert rows == 13
    assert count(conn, "success = 0") == 12
    assert count(conn, "repeated = 1") == 3


def test_loading_twice_does_not_duplicate(conn):
    load_events(conn, parse_file(SAMPLE, 2026))
    load_events(conn, parse_file(SAMPLE, 2026))
    assert count(conn) == 13


def test_values_round_trip(conn):
    line = "Dec 10 08:24:35 LabSZ sshd[24361]: Failed password for invalid user  0101 from 5.188.10.180 port 36279 ssh2"
    load_events(conn, parse_lines([line], 2017))
    row = conn.execute(
        "SELECT timestamp, host, pid, ip, port, username, method, success, invalid_user, repeated FROM auth_events"
    ).fetchone()
    assert row == ("2017-12-10 08:24:35", "LabSZ", 24361, "5.188.10.180", 36279, " 0101", "password", 0, 1, 0)


def test_failed_load_keeps_previous_data(conn):
    load_events(conn, parse_file(SAMPLE, 2026))

    def broken_events():
        yield from parse_file(SAMPLE, 2026)
        raise RuntimeError("parser crashed halfway")

    with pytest.raises(RuntimeError):
        load_events(conn, broken_events())
    assert count(conn) == 13


def test_timestamps_work_with_sqlite_date_functions(conn):
    load_events(conn, parse_file(SAMPLE, 2026))
    hours = conn.execute(
        "SELECT strftime('%H', timestamp) AS h, COUNT(*) FROM auth_events WHERE success = 0 GROUP BY h ORDER BY h"
    ).fetchall()
    assert hours == [("03", 9), ("05", 2), ("14", 1)]
