from datetime import datetime, timedelta

from src.simulation import Policy, fmt_duration, simulate

T0 = datetime(2017, 12, 10, 12, 0, 0)
POLICY = Policy(maxretry=3, findtime=timedelta(minutes=10), bantime=timedelta(minutes=10))


def fail(minute: float, ip: str = "1.1.1.1"):
    return (T0 + timedelta(minutes=minute), ip, False)


def ok(minute: float, ip: str = "1.1.1.1"):
    return (T0 + timedelta(minutes=minute), ip, True)


def test_ban_starts_after_maxretry_and_trigger_is_not_blocked():
    r = simulate([fail(0), fail(1), fail(2), fail(3), fail(4)], POLICY)
    assert r.failed == 5
    assert r.blocked == 2          # attempts at minute 3 and 4; the 3rd (minute 2) triggered the ban
    assert r.bans == 1
    assert r.banned_ips == {"1.1.1.1"}


def test_failures_spread_beyond_findtime_never_ban():
    r = simulate([fail(0), fail(6), fail(12), fail(18), fail(24)], POLICY)
    assert r.bans == 0
    assert r.blocked == 0


def test_attempts_after_ban_expires_are_not_blocked():
    # ban from minute 2 until minute 12
    r = simulate([fail(0), fail(1), fail(2), fail(11), fail(12), fail(13)], POLICY)
    assert r.blocked == 1          # only minute 11
    assert r.bans == 1             # counter was reset by the ban, minutes 12-13 are just 2 failures


def test_blocked_attempts_do_not_count_towards_next_ban():
    events = [fail(0), fail(1), fail(2)] + [fail(2 + i * 0.1) for i in range(1, 50)]
    r = simulate(events, POLICY)
    assert r.bans == 1
    assert r.blocked == 49


def test_increment_doubles_ban_time():
    policy = Policy(maxretry=3, findtime=timedelta(minutes=10), bantime=timedelta(minutes=10), increment=True)
    events = [fail(0), fail(1), fail(2),          # ban 1: minutes 2-12
              fail(12), fail(13), fail(14),       # ban 2: minutes 14-34 (20 min)
              fail(30), fail(35)]
    r = simulate(events, policy)
    assert r.bans == 2
    assert r.blocked == 1          # minute 30 blocked, minute 35 not

    plain = simulate(events, POLICY)
    assert plain.blocked == 0      # with fixed 10 min, ban 2 ends at minute 24


def test_successful_login_during_ban_is_locked_out():
    r = simulate([fail(0), fail(1), fail(2), ok(5), ok(20)], POLICY)
    assert r.successes == 2
    assert r.locked_out == 1


def test_ips_are_independent():
    events = [fail(0, "a"), fail(0.5, "b"), fail(1, "a"), fail(1.5, "b"), fail(2, "a"), fail(3, "b")]
    r = simulate(events, POLICY)
    assert r.banned_ips == {"a", "b"}
    assert r.blocked == 0


def test_repeated_events_with_same_timestamp():
    # "message repeated 5 times" expands into identical timestamps
    events = [fail(0)] * 6
    r = simulate(events, POLICY)
    assert r.bans == 1
    assert r.blocked == 3          # the 3rd triggers the ban; the next 3, same second, are already blocked


def test_policy_name():
    assert Policy().name == "5 in 10m -> ban 10m"
    assert Policy(3, timedelta(hours=1), timedelta(days=1), True).name == "3 in 1h -> ban 1d (x2 per repeat)"
    assert fmt_duration(timedelta(seconds=90)) == "90s"


def test_record_keeps_one_decision_per_event():
    events = [fail(0), fail(1), fail(2), fail(3), ok(4), fail(30)]
    r = simulate(events, POLICY, record=True)
    assert r.decisions == [False, False, False, True, True, False]
    assert simulate(events, POLICY).decisions is None
