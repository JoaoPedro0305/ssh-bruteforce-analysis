from pathlib import Path
from types import SimpleNamespace

import geoip2.errors
import pytest

import src.geo as geo
from src.parser import parse_file
from src.storage import connect, load_events

SAMPLE = Path(__file__).resolve().parent.parent / "data" / "sample" / "auth_sample.log"

FAKE_COUNTRIES = {
    "203.0.113.45": ("CN", "China"),
    "198.51.100.17": ("BR", "Brazil"),
}


class FakeReader:
    """Stands in for geoip2.database.Reader so tests need no .mmdb file."""

    def __init__(self, path):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def country(self, ip):
        if ip not in FAKE_COUNTRIES:
            raise geoip2.errors.AddressNotFoundError(ip)
        code, name = FAKE_COUNTRIES[ip]
        return SimpleNamespace(country=SimpleNamespace(iso_code=code, name=name))


@pytest.fixture
def conn(tmp_path, monkeypatch):
    monkeypatch.setattr(geo.geoip2.database, "Reader", FakeReader)
    conn = connect(tmp_path / "test.db")
    load_events(conn, parse_file(SAMPLE, 2026))
    yield conn
    conn.close()


def test_one_row_per_distinct_ip(conn):
    assert geo.geolocate_ips(conn, "fake.mmdb") == 4  # 3 attackers + 1 legitimate login


def test_unknown_ip_is_stored_as_null(conn):
    geo.geolocate_ips(conn, "fake.mmdb")
    row = conn.execute("SELECT country_code, country_name FROM ip_countries WHERE ip = '203.0.113.88'").fetchone()
    assert row == (None, None)


def test_rerun_does_not_duplicate(conn):
    geo.geolocate_ips(conn, "fake.mmdb")
    geo.geolocate_ips(conn, "fake.mmdb")
    assert conn.execute("SELECT COUNT(*) FROM ip_countries").fetchone()[0] == 4


def test_join_with_events(conn):
    geo.geolocate_ips(conn, "fake.mmdb")
    rows = conn.execute(
        "SELECT c.country_code, COUNT(*) FROM auth_events e JOIN ip_countries c USING (ip) "
        "WHERE e.success = 0 AND c.country_code IS NOT NULL GROUP BY 1 ORDER BY 2 DESC"
    ).fetchall()
    assert rows == [("CN", 9), ("BR", 2)]
