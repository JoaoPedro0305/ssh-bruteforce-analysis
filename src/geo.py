"""Map source IPs to countries and store the result in SQLite.

Each distinct IP in auth_events is looked up once in the DB-IP Country Lite
database and saved to the ip_countries table, so analyses can JOIN on ip
instead of repeating 1,000+ lookups.

Caveat: the database reflects who holds each IP range *today*, not when the
logs were written, and an IP's country is not where the attacker sits
(botnets, VPNs, proxies).

Usage:
    python -m src.geo
"""

import argparse
import sqlite3
from pathlib import Path

import geoip2.database
import geoip2.errors

from src.storage import DEFAULT_DB, connect

DEFAULT_GEO_DB = Path(__file__).resolve().parent.parent / "data" / "raw" / "dbip-country-lite.mmdb"

SCHEMA = """
CREATE TABLE IF NOT EXISTS ip_countries (
    ip            TEXT PRIMARY KEY,
    country_code  TEXT,   -- ISO 3166-1 alpha-2, NULL if not found
    country_name  TEXT
);
"""


def lookup(reader: geoip2.database.Reader, ip: str) -> tuple[str | None, str | None]:
    try:
        country = reader.country(ip).country
    except geoip2.errors.AddressNotFoundError:
        return None, None
    return country.iso_code, country.name


def geolocate_ips(conn: sqlite3.Connection, geo_db: str | Path = DEFAULT_GEO_DB) -> int:
    """Rebuild ip_countries for every distinct IP in auth_events. Returns the row count."""
    conn.executescript(SCHEMA)
    ips = [row[0] for row in conn.execute("SELECT DISTINCT ip FROM auth_events")]
    with geoip2.database.Reader(str(geo_db)) as reader:
        rows = [(ip, *lookup(reader, ip)) for ip in ips]
    with conn:
        conn.execute("DELETE FROM ip_countries")
        conn.executemany("INSERT INTO ip_countries VALUES (?, ?, ?)", rows)
    return len(rows)


def main() -> None:
    cli = argparse.ArgumentParser(description="Geolocate the IPs already loaded in SQLite.")
    cli.add_argument("--db", default=DEFAULT_DB, help=f"SQLite file (default: {DEFAULT_DB})")
    cli.add_argument("--geo-db", default=DEFAULT_GEO_DB, help="DB-IP .mmdb file")
    args = cli.parse_args()

    conn = connect(args.db)
    try:
        rows = geolocate_ips(conn, args.geo_db)
        found = conn.execute("SELECT COUNT(*) FROM ip_countries WHERE country_code IS NOT NULL").fetchone()[0]
    finally:
        conn.close()
    print(f"Geolocated {found:,} of {rows:,} IPs")


if __name__ == "__main__":
    main()
