"""Replay authentication events through fail2ban's banning logic.

fail2ban (sshd jail) watches failures per IP. When an IP reaches `maxretry`
failures within `findtime`, it is banned for `bantime`: the firewall drops its
connections, so its attempts never reach sshd.

Replay rules:
- An attempt from an IP that is currently banned is *blocked*. It does not
  count as a failure, because it would never have reached sshd.
- The failure that triggers a ban is not blocked: fail2ban only acts after
  seeing it.
- A successful login from a banned IP is a *locked-out user*: the cost of the
  policy.
- With `increment`, each new ban of the same IP doubles the ban time
  (fail2ban's `bantime.increment`).

Simplifications: one failure per attempt (fail2ban may match several log lines
per attempt), and attackers are assumed not to change behavior when banned.

Usage:
    python -m src.simulation
"""

import argparse
import csv
import sqlite3
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from src.storage import DEFAULT_DB

DEFAULT_CSV = Path(__file__).resolve().parent.parent / "reports" / "fail2ban_policies.csv"


def fmt_duration(d: timedelta) -> str:
    seconds = int(d.total_seconds())
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds % size == 0:
            return f"{seconds // size}{unit}"
    return f"{seconds}s"


@dataclass(frozen=True)
class Policy:
    maxretry: int = 5
    findtime: timedelta = timedelta(minutes=10)
    bantime: timedelta = timedelta(minutes=10)
    increment: bool = False

    @property
    def name(self) -> str:
        name = f"{self.maxretry} in {fmt_duration(self.findtime)} -> ban {fmt_duration(self.bantime)}"
        return name + " (x2 per repeat)" if self.increment else name


DEFAULT_POLICY = Policy()  # fail2ban's sshd defaults


@dataclass
class IpState:
    failures: deque = field(default_factory=deque)  # timestamps of recent failures
    banned_until: datetime | None = None
    bans: int = 0


@dataclass
class Result:
    policy: Policy
    failed: int = 0             # failed attempts in the log
    blocked: int = 0            # of those, dropped by a ban
    successes: int = 0          # successful logins in the log
    locked_out: int = 0         # of those, dropped by a ban
    bans: int = 0
    banned_ips: set = field(default_factory=set)
    decisions: list[bool] | None = None   # per event: True if dropped by a ban (only with record=True)

    @property
    def blocked_share(self) -> float:
        return self.blocked / self.failed if self.failed else 0.0

    @property
    def reached_sshd(self) -> int:
        return self.failed - self.blocked

    def as_row(self) -> dict:
        return {
            "policy": self.policy.name,
            "maxretry": self.policy.maxretry,
            "findtime_min": self.policy.findtime.total_seconds() / 60,
            "bantime_min": self.policy.bantime.total_seconds() / 60,
            "increment": self.policy.increment,
            "failed": self.failed,
            "blocked": self.blocked,
            "blocked_share": round(self.blocked_share, 4),
            "reached_sshd": self.reached_sshd,
            "bans": self.bans,
            "banned_ips": len(self.banned_ips),
            "successes": self.successes,
            "locked_out": self.locked_out,
        }


def simulate(events: Iterable[tuple[datetime, str, bool]], policy: Policy = DEFAULT_POLICY,
             record: bool = False) -> Result:
    """events: (timestamp, ip, success) sorted by timestamp.

    With record=True, result.decisions holds one bool per event (True = dropped by a ban).
    """
    result = Result(policy, decisions=[] if record else None)
    state: dict[str, IpState] = {}

    for ts, ip, success in events:
        st = state.setdefault(ip, IpState())
        banned = st.banned_until is not None and ts < st.banned_until
        if record:
            result.decisions.append(banned)

        if success:
            result.successes += 1
            result.locked_out += banned
            continue

        result.failed += 1
        if banned:
            result.blocked += 1
            continue

        st.failures.append(ts)
        while ts - st.failures[0] >= policy.findtime:
            st.failures.popleft()

        if len(st.failures) >= policy.maxretry:
            st.bans += 1
            duration = policy.bantime * (2 ** (st.bans - 1)) if policy.increment else policy.bantime
            st.banned_until = ts + duration
            st.failures.clear()
            result.bans += 1
            result.banned_ips.add(ip)

    return result


def load_events(db_path: str | Path = DEFAULT_DB) -> list[tuple[datetime, str, bool]]:
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute("SELECT timestamp, ip, success FROM auth_events ORDER BY timestamp, id")
        return [(datetime.fromisoformat(ts), ip, bool(ok)) for ts, ip, ok in rows]
    finally:
        conn.close()


def policy_grid() -> list[Policy]:
    """fail2ban defaults plus stricter and looser variants."""
    minutes = lambda m: timedelta(minutes=m)  # noqa: E731
    grid = [
        Policy(maxretry, minutes(findtime), minutes(bantime))
        for maxretry in (3, 5, 10)
        for findtime in (10, 60)
        for bantime in (10, 60, 24 * 60)
    ]
    grid += [Policy(maxretry, minutes(10), minutes(10), increment=True) for maxretry in (3, 5, 10)]
    return grid


def main() -> None:
    cli = argparse.ArgumentParser(description="Replay the log through fail2ban policies.")
    cli.add_argument("--db", default=DEFAULT_DB, help=f"SQLite file (default: {DEFAULT_DB})")
    cli.add_argument("--csv", default=DEFAULT_CSV, help=f"where to save results (default: {DEFAULT_CSV})")
    args = cli.parse_args()

    events = load_events(args.db)
    results = sorted((simulate(events, p) for p in policy_grid()), key=lambda r: -r.blocked_share)

    print(f"{'policy':<40} {'blocked':>8} {'reached sshd':>13} {'banned IPs':>11} {'locked out':>11}")
    for r in results:
        print(f"{r.policy.name:<40} {r.blocked_share:>8.1%} {r.reached_sshd:>13,} "
              f"{len(r.banned_ips):>11,} {r.locked_out:>8}/{r.successes}")

    Path(args.csv).parent.mkdir(parents=True, exist_ok=True)
    with open(args.csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].as_row().keys())
        writer.writeheader()
        writer.writerows(r.as_row() for r in results)
    print(f"\nSaved {args.csv}")


if __name__ == "__main__":
    main()
