-- Exploration queries for data/processed/ssh.db
-- Run with: sqlite3 data/processed/ssh.db < sql/exploration.sql
-- (or open the file in any SQLite client)

.headers on
.mode column

-- 1. Which usernames do attackers try?
SELECT username,
       COUNT(*) AS attempts,
       ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 1) AS pct
FROM auth_events
WHERE success = 0 AND method = 'password'
GROUP BY username
ORDER BY attempts DESC
LIMIT 10;

-- 2. How concentrated are the attacks? Share of failed attempts
--    coming from the top 1, 10 and 50 source IPs.
WITH per_ip AS (
    SELECT ip, COUNT(*) AS n
    FROM auth_events
    WHERE success = 0
    GROUP BY ip
),
ranked AS (
    SELECT n, ROW_NUMBER() OVER (ORDER BY n DESC) AS rk
    FROM per_ip
)
SELECT (SELECT COUNT(*) FROM per_ip) AS source_ips,
       ROUND(100.0 * SUM(CASE WHEN rk <= 1  THEN n END) / SUM(n), 1) AS top1_pct,
       ROUND(100.0 * SUM(CASE WHEN rk <= 10 THEN n END) / SUM(n), 1) AS top10_pct,
       ROUND(100.0 * SUM(CASE WHEN rk <= 50 THEN n END) / SUM(n), 1) AS top50_pct
FROM ranked;

-- 3. Most active IPs: volume, how long they kept going, first/last seen.
SELECT ip,
       COUNT(*) AS attempts,
       COUNT(DISTINCT date(timestamp)) AS active_days,
       MIN(timestamp) AS first_seen,
       MAX(timestamp) AS last_seen
FROM auth_events
WHERE success = 0
GROUP BY ip
ORDER BY attempts DESC
LIMIT 10;

-- 4. Failed attempts per day (note the gap 2017-12-24 .. 2017-12-28).
SELECT date(timestamp) AS day, COUNT(*) AS attempts
FROM auth_events
WHERE success = 0
GROUP BY day
ORDER BY day;

-- 5. Failed attempts by hour of day.
SELECT strftime('%H', timestamp) AS hour, COUNT(*) AS attempts
FROM auth_events
WHERE success = 0
GROUP BY hour
ORDER BY hour;

-- 6. IPs that failed and later logged in: either a user mistyping
--    the password or a successful break-in. A blocking rule that is too
--    strict would have locked these out.
SELECT s.ip,
       MIN(s.timestamp) AS first_success,
       (SELECT COUNT(*) FROM auth_events f
         WHERE f.ip = s.ip AND f.success = 0 AND f.timestamp <= MIN(s.timestamp)) AS failures_before
FROM auth_events s
WHERE s.success = 1
GROUP BY s.ip
HAVING failures_before > 0
ORDER BY failures_before DESC;
