"""Parse sshd syslog lines into authentication events.

One event = one authentication attempt (failed or accepted). Lines that only
repeat information about an attempt already logged (pam_unix, "Invalid user",
"Disconnecting") are skipped so each attempt is counted once.

Usage:
    python -m src.parser data/raw/SSH.log --start-year 2017
"""

import argparse
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

# "Dec 10 06:55:46 LabSZ sshd[24200]: <message>"
# The day is space-padded ("Jan  7"), hence \s+.
LINE_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<message>.*)$"
)

# "Failed password for invalid user admin from 1.2.3.4 port 22 ssh2"
# The username is matched lazily (.*?) because attackers try names with spaces;
# the IP/port/ssh2 tail anchors where it ends. Some versions append the key
# fingerprint after "ssh2: ...".
AUTH_RE = re.compile(
    r"^(?P<result>Failed|Accepted) (?P<method>\S+) for "
    r"(?P<invalid>invalid user )?(?P<user>.*?) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+) ssh2(?::.*)?$"
)

# syslog collapses identical consecutive messages into
# "message repeated N times: [ <message>]", meaning N attempts *in addition*
# to the line logged just before it.
REPEATED_RE = re.compile(r"^message repeated (?P<count>\d+) times: \[ (?P<inner>.*)\]$")

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1
)}


@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    host: str
    pid: int
    ip: str
    port: int
    user: str
    method: str          # password, none, publickey, ...
    success: bool
    invalid_user: bool   # the username does not exist on the server
    repeated: bool       # expanded from a "message repeated N times" line


def parse_auth_message(message: str) -> tuple[dict, int] | None:
    """Return (fields, count) for an auth message, or None if it is not one.

    count is how many attempts the message stands for: 1 for a normal line,
    N for "message repeated N times".
    """
    count = 1
    repeated = REPEATED_RE.match(message)
    if repeated:
        count = int(repeated["count"])
        message = repeated["inner"]

    match = AUTH_RE.match(message)
    if not match:
        return None
    fields = match.groupdict()
    fields["repeated"] = bool(repeated)
    return fields, count


def parse_lines(lines: Iterable[str], start_year: int) -> Iterator[AuthEvent]:
    """Yield one AuthEvent per authentication attempt.

    syslog lines have no year, so the year starts at start_year and goes up
    by one every time the month goes backwards (Dec -> Jan).
    """
    year = start_year
    prev_month = None

    for line in lines:
        line_match = LINE_RE.match(line.rstrip("\r\n"))
        if not line_match:
            continue

        month = MONTHS[line_match["month"]]
        if prev_month is not None and month < prev_month:
            year += 1
        prev_month = month

        parsed = parse_auth_message(line_match["message"])
        if parsed is None:
            continue
        fields, count = parsed

        timestamp = datetime.strptime(
            f"{year}-{month:02d}-{int(line_match['day']):02d} {line_match['time']}",
            "%Y-%m-%d %H:%M:%S",
        )
        event = AuthEvent(
            timestamp=timestamp,
            host=line_match["host"],
            pid=int(line_match["pid"]),
            ip=fields["ip"],
            port=int(fields["port"]),
            user=fields["user"],
            method=fields["method"],
            success=fields["result"] == "Accepted",
            invalid_user=fields["invalid"] is not None,
            repeated=fields["repeated"],
        )
        for _ in range(count):
            yield event


def parse_file(path: str | Path, start_year: int) -> Iterator[AuthEvent]:
    with open(path, encoding="utf-8", errors="replace") as f:
        yield from parse_lines(f, start_year)


def main() -> None:
    cli = argparse.ArgumentParser(description="Parse an sshd log and print a summary.")
    cli.add_argument("path", help="path to the log file")
    cli.add_argument("--start-year", type=int, default=datetime.now().year,
                     help="year of the first line (logs have no year)")
    args = cli.parse_args()

    events = list(parse_file(args.path, args.start_year))
    if not events:
        print("No authentication events found.")
        return

    failed = [e for e in events if not e.success]
    print(f"Events:            {len(events):,}")
    print(f"  failed:          {len(failed):,}")
    print(f"  accepted:        {len(events) - len(failed):,}")
    print(f"  from 'repeated': {sum(e.repeated for e in events):,}")
    print(f"Unique IPs:        {len({e.ip for e in events}):,}")
    print(f"Unique usernames:  {len({e.user for e in events}):,}")
    print(f"First event:       {events[0].timestamp}")
    print(f"Last event:        {events[-1].timestamp}")


if __name__ == "__main__":
    main()
