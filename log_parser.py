"""
Parser for OpenSSH auth log lines (the format found in /var/log/auth.log on
Debian/Ubuntu or /var/log/secure on RHEL/CentOS).

Handles the three event types that matter for brute-force detection:
  - Failed password            (wrong password, valid username)
  - Invalid user                (username doesn't exist on the system)
  - Accepted password / publickey  (successful login)
"""

import re
from datetime import datetime

# Jan  1 03:14:15 hostname sshd[1234]: Failed password for root from 192.168.1.50 port 54321 ssh2
# Jan  1 03:14:15 hostname sshd[1234]: Failed password for invalid user admin from 10.0.0.9 port 51234 ssh2
# Jan  1 03:14:15 hostname sshd[1234]: Invalid user test3 from 10.0.0.9 port 51235
# Jan  1 03:14:15 hostname sshd[1234]: Accepted password for deploy from 203.0.113.9 port 22 ssh2
# Jan  1 03:14:15 hostname sshd[1234]: Accepted publickey for deploy from 203.0.113.9 port 22 ssh2

LINE_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<message>.+)$"
)

FAILED_PASSWORD = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)"
)
INVALID_USER = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)"
)
ACCEPTED = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)"
)


def parse_timestamp(month, day, time_str, year=None):
    """Syslog timestamps have no year, so we assume the current year unless
    one is supplied (useful for parsing older archived logs correctly)."""
    year = year or datetime.now().year
    try:
        return datetime.strptime(f"{year} {month} {int(day):02d} {time_str}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


def parse_line(line, year=None):
    """Parses one auth.log line into a structured event dict, or None if
    the line isn't one of the event types this tool cares about."""
    match = LINE_PATTERN.match(line.strip())
    if not match:
        return None

    message = match.group("message")
    timestamp = parse_timestamp(match.group("month"), match.group("day"), match.group("time"), year)

    for event_type, pattern in (
        ("failed_password", FAILED_PASSWORD),
        ("invalid_user", INVALID_USER),
        ("accepted", ACCEPTED),
    ):
        m = pattern.search(message)
        if m:
            return {
                "timestamp": timestamp,
                "event_type": event_type,
                "user": m.group("user"),
                "ip": m.group("ip"),
                "port": m.group("port"),
                "host": match.group("host"),
                "raw": line.strip(),
            }

    return None


def parse_log_file(path, year=None):
    """Parses a full log file, returning only recognized SSH auth events
    in file order. Unrecognized lines (other services, malformed lines)
    are silently skipped - this tool only cares about SSH auth."""
    events = []
    with open(path, "r", errors="ignore") as f:
        for line in f:
            event = parse_line(line, year)
            if event:
                events.append(event)
    return events
