# Brute-Force SSH Login Detector

A log-analysis tool that parses OpenSSH auth logs to find brute-force and username-enumeration attacks in progress — and flags, with the highest severity, any attacker who eventually succeeded. Generates a reviewable (never auto-applied) firewall block list for the IPs it flags.

## What This Project Does

- **Parses real OpenSSH auth log format** (`/var/log/auth.log` on Debian/Ubuntu, `/var/log/secure` on RHEL/CentOS) — failed passwords, invalid users, and accepted logins
- **Sliding-window rate detection** — flags an IP once its failed-attempt rate crosses a threshold within a time window, the classic brute-force signature, rather than just counting totals (which misses a fast burst inside a long, mostly-quiet log)
- **Username enumeration detection** — separately flags an IP that tries many distinct usernames even if it never bursts fast enough to trip the rate threshold (a slow, patient scan looks different from a fast brute force, and both matter)
- **Breach escalation** — an IP that eventually logs in successfully after a string of failures is flagged **critical**, distinct from an attacker who just made noise and never got in
- **Generates a block list** (`iptables` and `ufw` commands) for every flagged IP — written to a script a human reviews and runs; nothing is blocked automatically
- JSON report + CI-friendly exit code (non-zero on critical/high findings)

## Example Output

```
2 suspicious IP(s) found:

  [CRITICAL] 198.51.100.23 — SUCCEEDED (possible breach!)
             12 failed attempts total, peak 12 in 60s
             1 distinct username(s) tried: root
             window: 2026-01-10T03:14:00 -> 2026-01-10T03:14:22

  [MEDIUM  ] 203.0.113.77
             5 failed attempts total, peak 3 in 60s
             5 distinct username(s) tried: test1, test2, test3, test4, test5
             window: 2026-01-10T03:20:00 -> 2026-01-10T03:21:40

Summary — critical: 1, high: 0, medium: 1

*** At least one flagged IP eventually succeeded - treat as a confirmed compromise, not just noise. ***
```

## Tech Stack

- Python 3.11, standard library only (`re`, `collections`, `datetime`) — no dependencies to install

## Setup

No dependencies required.

```bash
python3 detector.py /var/log/auth.log
```

Options:

```bash
python3 detector.py /var/log/auth.log --json report.json          # write a full JSON report
python3 detector.py /var/log/auth.log --blocklist block.sh         # write suggested firewall rules
python3 detector.py /var/log/auth.log --year 2025                  # syslog timestamps have no year - set it for old/archived logs
```

### Testing it against the included fixture

`test_fixtures/sample_auth.log` has four scenarios planted in one file: a fast brute-force attack that succeeds (critical), a slow username-enumeration scan (medium), a normal user who mistyped their password once before logging in successfully (should NOT be flagged), and a clean single-shot login (should NOT be flagged).

```bash
python3 detector.py test_fixtures/sample_auth.log --year 2026
```

## Tuning detection

Edit the constants at the top of `detector.py`:

- `WINDOW_SECONDS` / `FAILED_THRESHOLD` — how fast is "too fast" (default: 5 failed attempts in 60 seconds)
- `ENUMERATION_THRESHOLD` — how many distinct usernames from one IP counts as a scan (default: 4)

## Architecture

```
auth.log
    |
    v
log_parser.py - regex-extract (timestamp, event_type, user, ip, port) per line
    |
    v
Group failed/invalid-user events by source IP
    |
    v
Sliding time-window pass per IP -> peak attempt rate
    |                                    |
    v                                    v
Rate threshold exceeded?          Distinct usernames >= threshold?
    |                                    |
    +------------------+-----------------+
                        v
         Flagged, severity escalated to CRITICAL
         if that IP ever had an Accepted login
                        |
                        v
     Console report + JSON report + suggested firewall block list
```

## Project Structure

```
brute-force-login-detector/
├── detector.py              # Main CLI: analysis, reporting, blocklist generation
├── log_parser.py            # OpenSSH auth log line parsing
├── test_fixtures/
│   └── sample_auth.log      # Brute force + enumeration + two legitimate-login scenarios
└── README.md
```

## What I Learned

- Why a sliding time window catches bursts that a flat "total failed attempts" counter misses — a brute force concentrated in 20 seconds inside a week-long log has a tiny total but a very high peak rate
- Treating "many failed attempts" and "many distinct usernames tried" as two different signals, because a fast password-guessing attack and a slow username-enumeration scan look different in the data and deserve separate detection logic
- Why "did this IP ever succeed" has to be checked independently of the rate/volume signals — it's the single fact that turns a noisy-but-harmless attacker into a confirmed breach, and it has nothing to do with how many attempts they made
- Generating remediation (a block list) as a reviewable artifact rather than an automatic action — a security tool that blocks IPs on its own can itself become a denial-of-service vector if its detection logic ever misfires on a legitimate but noisy client

## Next Steps

- Extend parsing to other auth sources: web app login endpoints, VPN logs, RDP (Windows Event Log)
- Geolocation/ASN lookup on flagged IPs to distinguish "likely a bot farm" from "an employee who mistyped their password many times"
- Real-time mode: tail the log file and alert as events happen, rather than batch-analyzing a static file
- HTML dashboard report, consistent with the other projects in this portfolio
