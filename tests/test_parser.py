from datetime import datetime
from pathlib import Path

from src.parser import parse_auth_message, parse_file, parse_lines

SAMPLE = Path(__file__).resolve().parent.parent / "data" / "sample" / "auth_sample.log"


def parse_one(line: str, year: int = 2017):
    events = list(parse_lines([line], year))
    assert len(events) == 1
    return events[0]


def test_failed_password_valid_user():
    e = parse_one("Dec 10 07:13:43 LabSZ sshd[24227]: Failed password for root from 5.36.59.76 port 42393 ssh2")
    assert e.timestamp == datetime(2017, 12, 10, 7, 13, 43)
    assert e.host == "LabSZ"
    assert e.pid == 24227
    assert e.user == "root"
    assert e.ip == "5.36.59.76"
    assert e.port == 42393
    assert e.method == "password"
    assert e.success is False
    assert e.invalid_user is False
    assert e.repeated is False


def test_failed_password_invalid_user():
    e = parse_one(
        "Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2"
    )
    assert e.user == "webmaster"
    assert e.invalid_user is True


def test_username_with_leading_space_is_kept():
    e = parse_one(
        "Dec 10 08:24:35 LabSZ sshd[24361]: Failed password for invalid user  0101 from 5.188.10.180 port 36279 ssh2"
    )
    assert e.user == " 0101"


def test_accepted_with_key_fingerprint():
    e = parse_one(
        "Oct  7 09:15:44 vm sshd[11002]: Accepted publickey for azureuser from 192.0.2.10 port 60001 ssh2: RSA SHA256:abc"
    )
    assert e.success is True
    assert e.method == "publickey"
    assert e.user == "azureuser"


def test_failed_none_method():
    e = parse_one(
        "Dec 10 08:24:40 LabSZ sshd[24363]: Failed none for invalid user admin from 5.188.10.180 port 49811 ssh2"
    )
    assert e.method == "none"


def test_repeated_message_expands_to_n_events():
    line = "Dec 10 07:13:56 LabSZ sshd[24227]: message repeated 5 times: [ Failed password for root from 5.36.59.76 port 42393 ssh2]"
    events = list(parse_lines([line], 2017))
    assert len(events) == 5
    assert all(e.repeated and e.user == "root" for e in events)


def test_repeated_non_auth_message_is_ignored():
    assert parse_auth_message("message repeated 2 times: [ Connection closed by 1.2.3.4 [preauth]]") is None


def test_non_auth_lines_are_skipped():
    lines = [
        "Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186",
        "Dec 10 06:55:46 LabSZ sshd[24200]: pam_unix(sshd:auth): check pass; user unknown",
        "Dec 10 06:55:48 LabSZ sshd[24200]: Connection closed by 173.234.31.186 [preauth]",
        "this is not a syslog line",
        "",
    ]
    assert list(parse_lines(lines, 2017)) == []


def test_year_rolls_over_from_december_to_january():
    lines = [
        "Dec 31 23:59:59 h sshd[1]: Failed password for root from 1.1.1.1 port 1 ssh2",
        "Jan  1 00:00:01 h sshd[2]: Failed password for root from 1.1.1.1 port 2 ssh2",
    ]
    first, second = parse_lines(lines, 2017)
    assert first.timestamp == datetime(2017, 12, 31, 23, 59, 59)
    assert second.timestamp == datetime(2018, 1, 1, 0, 0, 1)


def test_windows_line_endings():
    e = parse_one("Dec 10 07:13:43 LabSZ sshd[1]: Failed password for root from 5.36.59.76 port 1 ssh2\r\n")
    assert e.port == 1


def test_sample_file_totals():
    events = list(parse_file(SAMPLE, 2026))
    failed = [e for e in events if not e.success]
    assert len(failed) == 12  # 9 direct lines + 3 from "message repeated"
    assert sum(e.success for e in events) == 1
    assert sum(e.repeated for e in events) == 3
    assert {e.ip for e in failed} == {"203.0.113.45", "198.51.100.17", "203.0.113.88"}
