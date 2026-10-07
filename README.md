# SSH Brute-Force Analysis

Analysis of 655k real SSH log lines from an internet-facing server: who tries to break in, with which usernames, from where, and how many attacks a `fail2ban` policy would have blocked.

> Status: work in progress

## The problem

Any server with port 22 open to the internet receives automated login attempts within minutes. This project parses a real `sshd` log, turns it into structured data and answers: how many attacks, when, from where, which users are targeted, and how much a simple blocking rule would actually help.

## Data

- **Source:** the OpenSSH dataset from [Loghub](https://github.com/logpai/loghub), 655,147 lines (~70 MiB) of `sshd` logs collected over ~28 days from a lab server exposed to the internet.
- **Not committed:** the log is downloaded by `scripts/download_data.py` into `data/raw/`, which is git-ignored. Loghub asks users to link back to the original repository instead of redistributing the data.
- **Geolocation:** [IP to Country Lite](https://db-ip.com/db/download/ip-to-country-lite) by DB-IP (CC BY 4.0, no account needed), also downloaded by `scripts/download_data.py`.
- `data/sample/auth_sample.log` is a small **synthetic** log (documentation IP ranges) used by the tests.

## Results

| Metric | Value |
|---|---|
| Log lines parsed | 655,147 |
| Authentication attempts | 345,245 |
| Failed attempts | 345,063 |
| Successful logins | 182 |
| Source IPs with failed attempts | 1,010 |
| Share of attempts from the top 10 IPs | 74.8% |
| Countries | 72 |
| IPs flagged as brute force | – |
| Attempts blocked by the simulated fail2ban policy | – |

**Top 5 targeted usernames:** `root` (94.0%), `admin` (2.3%), `test`, `oracle`, `support`.

Attacks are extremely concentrated: the single most active IP made 25% of all failed attempts (86k in 3 days), and the top 50 IPs made 95%. Blocking a handful of sources removes most of the noise, which is why tools like `fail2ban` work.

Full analysis: [`notebooks/01_exploration.ipynb`](notebooks/01_exploration.ipynb).

### Volume is bursty: Jan 1-4 produced 65% of all attempts

![Failed attempts per day](reports/figures/attempts_per_day.png)

The median online day had ~6k failed attempts. The hatched area is the period when the server was unreachable (see *Data quality notes*).

### A few fast bots, not more attackers

![Cumulative share of attempts by source IP](reports/figures/ip_concentration.png)

The top 7 IPs tried **only `root`**, at 20-28 attempts per minute for 15-50 hours straight. Two IPs made exactly 10,852 attempts over 51 usernames, three weeks apart: almost certainly the same tool and wordlist.

### There is no real peak hour

![Failed attempts by hour of day](reports/figures/attempts_by_hour.png)

Attempts per hour vary 2.5x, but the number of distinct attacking IPs per hour only varies between 82 and 128. The same population attacks all day; the "peaks" are a few heavy bots.

### Usernames: root, then service accounts

![Top targeted usernames besides root](reports/figures/top_usernames.png)

94% of failed passwords target a username that exists on the server, mostly `root`. Disabling SSH root login would turn nearly all of them into guaranteed failures.

### Countries: volume is not headcount

![Attempts by country](reports/figures/top_countries.png)

IPs registered in China are 316 of the 1,010 sources but 94% of the attempts; Vietnam has 71 IPs and under 1%. The country is where the infrastructure is registered, not where the attacker sits.

## How the parser works

`src/parser.py` turns each authentication attempt into one event (timestamp, IP, port, username, method, success, invalid user). A few things in real `sshd` logs make this less trivial than one regex:

- **One attempt, many lines.** A single failed password also produces `pam_unix`, `Invalid user` and `Disconnecting` lines. Only the `Failed ...` / `Accepted ...` line is counted, so nothing is counted twice.
- **"message repeated N times".** syslog collapses identical consecutive lines into `message repeated 5 times: [ Failed password ... ]`, meaning 5 attempts *in addition* to the previous line. In this dataset these lines hide **184,011 of 345,245 attempts (53%)**. A parser that ignores them counts less than half of the attacks.
- **No year in timestamps.** The year starts at `--start-year` and goes up when the month goes backwards (Dec → Jan). The dataset runs from 2017-12-10 to 2018-01-07.
- **Odd usernames.** Attackers try names with leading spaces (`" 0101"`), so the username is matched up to the `from <ip> port` tail instead of up to the first space.

The parser's total matches an independent `grep`/`awk` count of the raw file exactly (345,245 events).

## Storage

`src/storage.py` loads the events into SQLite (`data/processed/ssh.db`, table `auth_events`), one row per attempt so `COUNT(*)` is the number of attempts. Each load replaces the table in a single transaction: running it twice gives the same result, and a crash halfway keeps the previous data. Exploration queries are in [`sql/exploration.sql`](sql/exploration.sql).

## Data quality notes

- **Gap from 2017-12-23 10:20 to 2017-12-29 17:24.** No external traffic at all; on Dec 26 `sshd` logs `Server listening on ... port 22` with low PIDs, i.e. the server was restarted, and only an internal address shows up. The server was likely offline or unreachable over the holidays. Daily averages exclude these days.
- **Legitimate users are not published.** Successful logins belong to real lab users, so their usernames are left out of this README; only usernames tried by attackers are shown.

## Detection rule

An IP is flagged as brute force when it has more than **N** failed logins within **M** minutes.

## fail2ban simulation

The log is replayed through the same logic `fail2ban` uses: after `maxretry` failures within `findtime`, the IP is banned for `bantime`. Every attempt that happens during a ban counts as blocked. Running the replay with different settings shows how much each policy would have stopped and where stricter rules stop paying off.

## How to run

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python scripts/download_data.py
python -m src.parser data/raw/SSH.log --start-year 2017    # summary only
python -m src.storage data/raw/SSH.log --start-year 2017   # load into SQLite
python -m src.geo                                          # add countries
jupyter nbconvert --to notebook --execute --inplace notebooks/01_exploration.ipynb
pytest
```

## Project structure

```
data/
  raw/         # downloaded dataset (git-ignored)
  processed/   # SQLite database (git-ignored)
  sample/      # synthetic sample log for tests
notebooks/     # exploratory analysis
scripts/       # dataset download
sql/           # exploration queries
src/           # parser, storage, detection, simulation, geolocation
tests/         # pytest
reports/figures/  # charts used in this README
```

## Stack

- **Python + regex** – parsing `sshd` log lines
- **pandas** – aggregation
- **SQLite** – simple, file-based storage, no server needed
- **matplotlib** – charts
- **geoip2** – IP → country lookup (reads DB-IP's `.mmdb` format)
- **Jupyter** – exploratory analysis
- **pytest** – tests for parser, storage and geolocation

## Limitations and next steps

- One server over ~28 days, so the results describe that server, not the whole internet.
- Log lines have no year, so dates are inferred from the December → January rollover.
- Country of an IP is not the attacker's real location (VPNs, botnets, proxies), and IP-to-country data from today may differ from when the logs were collected.
- The fail2ban numbers are a simulation: real attackers may change behavior once they get banned.

## Acknowledgements

IP geolocation by [DB-IP](https://db-ip.com), licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

Dataset from Loghub:

> Jieming Zhu, Shilin He, Pinjia He, Jinyang Liu, Michael R. Lyu. *Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics.* IEEE International Symposium on Software Reliability Engineering (ISSRE), 2023.

## License

Code: MIT. Dataset: see [Loghub](https://github.com/logpai/loghub).
