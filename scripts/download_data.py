"""Download the Loghub OpenSSH dataset into data/raw/.

The dataset is not committed to this repository (license asks for a link back
to Loghub instead of redistribution), so this script fetches it from Zenodo.

Usage:
    python scripts/download_data.py
"""

import tarfile
import urllib.request
from pathlib import Path

URL = "https://zenodo.org/records/8196385/files/SSH.tar.gz?download=1"
RAW_DIR = Path(__file__).resolve().parent.parent / "data" / "raw"
ARCHIVE = RAW_DIR / "SSH.tar.gz"
LOG_FILE = RAW_DIR / "SSH.log"


def download() -> None:
    if ARCHIVE.exists():
        print(f"Archive already exists: {ARCHIVE}")
        return
    print(f"Downloading {URL} ...")
    urllib.request.urlretrieve(URL, ARCHIVE)
    print(f"Saved {ARCHIVE.stat().st_size / 1_048_576:.1f} MiB")


def extract() -> None:
    if LOG_FILE.exists():
        print(f"Log already extracted: {LOG_FILE}")
        return
    with tarfile.open(ARCHIVE) as tar:
        member = next(m for m in tar.getmembers() if m.name.endswith("SSH.log"))
        member.name = LOG_FILE.name  # flatten any folder inside the archive
        tar.extract(member, RAW_DIR, filter="data")
    print(f"Extracted {LOG_FILE}")


def main() -> None:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    download()
    extract()
    with LOG_FILE.open(encoding="utf-8", errors="replace") as f:
        lines = sum(1 for _ in f)
    print(f"{lines:,} lines in {LOG_FILE.name}")


if __name__ == "__main__":
    main()
