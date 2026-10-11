"""
Brute-Force SSH Login Detector

Parses an OpenSSH auth log, finds IPs hammering the server with failed
logins within a sliding time window, and flags anything that looks like
a brute-force or credential-stuffing attempt - with extra severity for
an attacker who eventually succeeded (the breach case, not just noise).

Usage:
    python3 detector.py /var/log/auth.log
    python3 detector.py /var/log/auth.log --json report.json --blocklist blocklist.sh
"""

import sys
import json
import argparse
from collections import defaultdict, deque
from datetime import datetime

from log_parser import parse_log_file

# ---------- Config ----------
WINDOW_SECONDS = 60       # sliding time window to measure attempt rate
FAILED_THRESHOLD = 5      # failed attempts within the window to flag as brute force
ENUMERATION_THRESHOLD = 4  # distinct usernames tried from one IP to flag as enumeration


def analyze_events(events):
    """Groups failed-login events by source IP and finds every IP whose
    failed-attempt rate crosses FAILED_THRESHOLD within WINDOW_SECONDS at
    any point in the log, or that tried enough distinct usernames to look
    like credential stuffing / user enumeration rather than a typo."""

    by_ip = defaultdict(list)
    accepted_ips = set()

    for event in events:
        if event["event_type"] in ("failed_password", "invalid_user"):
            by_ip[event["ip"]].append(event)
        elif event["event_type"] == "accepted":
            accepted_ips.add(event["ip"])

    findings = []

    for ip, ip_events in by_ip.items():
        timestamped = [e for e in ip_events if e["timestamp"] is not None]
        timestamped.sort(key=lambda e: e["timestamp"])

        window = deque()
        peak_count_in_window = 0
        peak_window_start = None

        for event in timestamped:
            window.append(event)
            while window and (event["timestamp"] - window[0]["timestamp"]).total_seconds() > WINDOW_SECONDS:
                window.popleft()
            if len(window) > peak_count_in_window:
                peak_count_in_window = len(window)
                peak_window_start = window[0]["timestamp"]

        distinct_users = sorted({e["user"] for e in ip_events})
        total_failed = len(ip_events)
        succeeded = ip in accepted_ips

        is_brute_force = peak_count_in_window >= FAILED_THRESHOLD
        is_enumeration = len(distinct_users) >= ENUMERATION_THRESHOLD

        if not (is_brute_force or is_enumeration):
            continue

        if succeeded:
            severity = "critical"   # attacker eventually got in - this is a confirmed breach, not just noise
        elif is_brute_force:
            severity = "high"
        else:
            severity = "medium"

        findings.append({
            "ip": ip,
            "severity": severity,
            "total_failed_attempts": total_failed,
            "peak_attempts_in_window": peak_count_in_window,
            "window_seconds": WINDOW_SECONDS,
            "distinct_usernames_tried": distinct_users,
            "distinct_username_count": len(distinct_users),
            "flagged_as_brute_force": is_brute_force,
            "flagged_as_enumeration": is_enumeration,
            "eventually_succeeded": succeeded,
            "first_attempt": timestamped[0]["timestamp"].isoformat() if timestamped else None,
            "last_attempt": timestamped[-1]["timestamp"].isoformat() if timestamped else None,
        })

    findings.sort(key=lambda f: (
        {"critical": 0, "high": 1, "medium": 2}.get(f["severity"], 9),
        -f["total_failed_attempts"],
    ))
    return findings


def print_report(findings, total_events):
    print(f"\nParsed {total_events} SSH auth event(s).\n")

    if not findings:
        print("No brute-force or enumeration patterns detected.")
        return

    print(f"{len(findings)} suspicious IP(s) found:\n")
    for f in findings:
        breach_note = " — SUCCEEDED (possible breach!)" if f["eventually_succeeded"] else ""
        print(f"  [{f['severity'].upper():8}] {f['ip']}{breach_note}")
        print(f"             {f['total_failed_attempts']} failed attempts total, "
              f"peak {f['peak_attempts_in_window']} in {f['window_seconds']}s")
        print(f"             {f['distinct_username_count']} distinct username(s) tried: "
              f"{', '.join(f['distinct_usernames_tried'][:6])}"
              f"{' ...' if f['distinct_username_count'] > 6 else ''}")
        print(f"             window: {f['first_attempt']} -> {f['last_attempt']}\n")

    critical = sum(1 for f in findings if f["severity"] == "critical")
    high = sum(1 for f in findings if f["severity"] == "high")
    medium = sum(1 for f in findings if f["severity"] == "medium")
    print(f"Summary — critical: {critical}, high: {high}, medium: {medium}")
    if critical:
        print("\n*** At least one flagged IP eventually succeeded - treat as a confirmed compromise, not just noise. ***")


def write_blocklist(findings, path):
    """Writes a shell script with both iptables and ufw deny commands for
    every flagged IP - a human reviews and runs it, this tool never blocks
    anything automatically."""
    lines = [
        "#!/bin/sh",
        "# Generated block list from brute-force-login-detector.",
        "# Review before running - this script does NOT run automatically.",
        f"# Generated at: {datetime.now().isoformat()}",
        "",
    ]
    for f in findings:
        lines.append(f"# {f['ip']} - {f['severity']} - {f['total_failed_attempts']} failed attempts"
                      f"{' - SUCCEEDED LOGIN' if f['eventually_succeeded'] else ''}")
        lines.append(f"iptables -A INPUT -s {f['ip']} -j DROP")
        lines.append(f"# ufw deny from {f['ip']}")
        lines.append("")

    with open(path, "w") as f_out:
        f_out.write("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(description="Detect brute-force SSH login attempts in an auth log.")
    parser.add_argument("logfile", help="Path to auth.log / secure log file")
    parser.add_argument("--json", help="Write a JSON report to this path")
    parser.add_argument("--blocklist", help="Write a shell script of suggested firewall rules to this path")
    parser.add_argument("--year", type=int, help="Year to assume for timestamps (syslog format has no year)")
    args = parser.parse_args()

    try:
        events = parse_log_file(args.logfile, year=args.year)
    except FileNotFoundError:
        print(f"Log file not found: {args.logfile}")
        sys.exit(1)

    findings = analyze_events(events)
    print_report(findings, len(events))

    if args.json:
        report = {
            "generated_at": datetime.now().isoformat(),
            "logfile": args.logfile,
            "total_events_parsed": len(events),
            "findings": findings,
        }
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\nJSON report written to {args.json}")

    if args.blocklist and findings:
        write_blocklist(findings, args.blocklist)
        print(f"Suggested firewall rules written to {args.blocklist} (review before running)")

    if any(f["severity"] in ("critical", "high") for f in findings):
        sys.exit(1)


if __name__ == "__main__":
    main()
