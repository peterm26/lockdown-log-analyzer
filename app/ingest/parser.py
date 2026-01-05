import hashlib
import re
from datetime import datetime, timezone

# Example log format:
# Dec 29 12:00:00 server sshd[123]: Failed password for root from 203.0.113.10 port 5555 ssh2

SSH_FAILED_RE = re.compile(
    r'^(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}).*'
    r'Failed password for (?:invalid user\s+)?(?P<user>\S+) from (?P<ip>\S+)'
)

MONTHS = {
    "JAN": 1, "FEB": 2, "MAR": 3, "APR": 4,
    "MAY": 5, "JUN": 6, "JUL": 7, "AUG": 8,
    "SEP": 9, "OCT": 10, "NOV": 11, "DEC": 12
}

# -------------------------
# Parse: SSH auth.log lines
# -------------------------
def parse_ssh_line(line: str):
    """
    Parse SSH failed password log line into normalized event dict.
    Returns None if line doesn't match expected format.
    """
    match = SSH_FAILED_RE.match(line)
    if not match:
        return None

    month_int = MONTHS.get(match.group("month").upper())
    if month_int is None:
        return None

    hour, minute, second = map(int, match.group("time").split(":"))
    now = datetime.now(timezone.utc)

    ts = datetime(
        year=now.year,
        month=month_int,
        day=int(match.group("day")),
        hour=hour,
        minute=minute,
        second=second,
        tzinfo=timezone.utc,
    )

    # Stable deduplication fingerprint
    fp_src = (
        f"{ts.isoformat()}|ssh|ssh_failed_password|"
        f"{match.group('ip')}|{match.group('user')}|failed|{line.strip()}"
    )
    fingerprint = hashlib.sha256(fp_src.encode("utf-8")).hexdigest()

    return {
        "ts": ts,
        "source": "ssh",
        "event_type": "ssh_failed_password",
        "ip": match.group("ip"),
        "username": match.group("user"),
        "status": "failed",
        "raw": line.strip(),
        "fingerprint": fingerprint,
    }