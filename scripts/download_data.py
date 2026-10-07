"""Download the datasets used by the project into data/raw/.

1. Loghub OpenSSH log (Zenodo). Not committed to this repository: Loghub asks
   for a link back instead of redistribution.
2. DB-IP "IP to Country Lite" database (CC BY 4.0), used to map IPs to
   countries. Published monthly; the newest available month is used.

Usage:
    python scripts/download_data.py
"""

import gzip
import shutil
import tarfile
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path

RAW_DIR = Path(__file__).resolve().parent.parent / "data" / "raw"

LOG_URL = "https://zenodo.org/records/8196385/files/SSH.tar.gz?download=1"
LOG_ARCHIVE = RAW_DIR / "SSH.tar.gz"
LOG_FILE = RAW_DIR / "SSH.log"

GEO_URL = "https://download.db-ip.com/free/dbip-country-lite-{month}.mmdb.gz"
GEO_FILE = RAW_DIR / "dbip-country-lite.mmdb"


def download(url: str, dest: Path) -> None:
    print(f"Downloading {url} ...")
    # Some hosts (db-ip.com) reject Python's default User-Agent with 403.
    request = urllib.request.Request(url, headers={"User-Agent": "ssh-bruteforce-analysis/1.0"})
    with urllib.request.urlopen(request) as response, dest.open("wb") as f:
        shutil.copyfileobj(response, f)
    print(f"Saved {dest.name} ({dest.stat().st_size / 1_048_576:.1f} MiB)")


def get_log() -> None:
    if LOG_FILE.exists():
        print(f"Log already extracted: {LOG_FILE}")
        return
    if not LOG_ARCHIVE.exists():
        download(LOG_URL, LOG_ARCHIVE)
    with tarfile.open(LOG_ARCHIVE) as tar:
        member = next(m for m in tar.getmembers() if m.name.endswith("SSH.log"))
        member.name = LOG_FILE.name  # flatten any folder inside the archive
        tar.extract(member, RAW_DIR, filter="data")
    with LOG_FILE.open(encoding="utf-8", errors="replace") as f:
        lines = sum(1 for _ in f)
    print(f"Extracted {LOG_FILE.name}: {lines:,} lines")


def recent_months(n: int = 3) -> list[str]:
    """This month and the previous ones, as 'YYYY-MM' (newest first)."""
    today = date.today()
    months = []
    year, month = today.year, today.month
    for _ in range(n):
        months.append(f"{year}-{month:02d}")
        year, month = (year - 1, 12) if month == 1 else (year, month - 1)
    return months


def get_geo_db() -> None:
    if GEO_FILE.exists():
        print(f"Geo database already exists: {GEO_FILE}")
        return
    gz = GEO_FILE.with_suffix(".mmdb.gz")
    # The file for the current month may not be published yet early in the month.
    for month in recent_months():
        try:
            download(GEO_URL.format(month=month), gz)
            break
        except urllib.error.HTTPError as err:
            print(f"  {month} not available ({err.code}), trying previous month")
    else:
        raise SystemExit("Could not download the DB-IP database.")
    with gzip.open(gz, "rb") as src, GEO_FILE.open("wb") as dst:
        shutil.copyfileobj(src, dst)
    gz.unlink()
    print(f"Extracted {GEO_FILE.name}")


def main() -> None:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    get_log()
    get_geo_db()


if __name__ == "__main__":
    main()
