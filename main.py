"""
Simple host-based intrusion detection script.
It scans log lines for quick heuristics like brute-force SSH attempts and port scanning.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Deque, Dict, Iterable, List, Tuple

# Basic IPv4 matcher; adjust if you need IPv6.
IP_RE = re.compile(r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})")
SYSLOG_TS_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
)

# Common auth log patterns.
FAILED_LOGIN_PATTERNS = [
    re.compile(r"Failed password .* from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})"),
    re.compile(r"Invalid user .* from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})"),
]

# Example iptables-style firewall line: "IN=... OUT=... SRC=1.2.3.4 ... DPT=22"
PORT_SCAN_PATTERN = re.compile(
    r"SRC=(?P<ip>(?:\d{1,3}\.){3}\d{1,3}).*DPT=(?P<port>\d+)"
)


DEMO_LOG = """
May 19 12:01:00 host sshd[100]: Failed password for invalid user admin from 10.0.0.5 port 51114 ssh2
May 19 12:01:05 host sshd[100]: Failed password for invalid user admin from 10.0.0.5 port 51114 ssh2
May 19 12:01:10 host sshd[100]: Failed password for invalid user admin from 10.0.0.5 port 51114 ssh2
May 19 12:01:15 host sshd[100]: Failed password for invalid user admin from 10.0.0.5 port 51114 ssh2
May 19 12:01:20 host sshd[100]: Failed password for invalid user admin from 10.0.0.5 port 51114 ssh2
May 19 12:02:01 host kernel: IN=eth0 OUT= MAC= SRC=10.1.1.23 DST=192.168.0.10 LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=54321 PROTO=TCP SPT=55555 DPT=22 WINDOW=65535 RES=0x00 SYN URGP=0
May 19 12:02:02 host kernel: IN=eth0 OUT= MAC= SRC=10.1.1.23 DST=192.168.0.10 LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=54321 PROTO=TCP SPT=55555 DPT=23 WINDOW=65535 RES=0x00 SYN URGP=0
May 19 12:02:03 host kernel: IN=eth0 OUT= MAC= SRC=10.1.1.23 DST=192.168.0.10 LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=54321 PROTO=TCP SPT=55555 DPT=25 WINDOW=65535 RES=0x00 SYN URGP=0
May 19 12:02:04 host kernel: IN=eth0 OUT= MAC= SRC=10.1.1.23 DST=192.168.0.10 LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=54321 PROTO=TCP SPT=55555 DPT=80 WINDOW=65535 RES=0x00 SYN URGP=0
May 19 12:02:05 host kernel: IN=eth0 OUT= MAC= SRC=10.1.1.23 DST=192.168.0.10 LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=54321 PROTO=TCP SPT=55555 DPT=443 WINDOW=65535 RES=0x00 SYN URGP=0
May 19 12:02:06 host kernel: IN=eth0 OUT= MAC= SRC=10.1.1.23 DST=192.168.0.10 LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=54321 PROTO=TCP SPT=55555 DPT=445 WINDOW=65535 RES=0x00 SYN URGP=0
May 19 12:02:07 host kernel: IN=eth0 OUT= MAC= SRC=10.1.1.23 DST=192.168.0.10 LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=54321 PROTO=TCP SPT=55555 DPT=3389 WINDOW=65535 RES=0x00 SYN URGP=0
""".strip()


@dataclass
class Alert:
    category: str
    ip: str
    count: int
    first_seen: datetime
    last_seen: datetime
    detail: str


class IntrusionDetector:
    def __init__(
        self,
        fail_threshold: int = 5,
        fail_window: timedelta = timedelta(minutes=5),
        portscan_ports: int = 6,
        portscan_window: timedelta = timedelta(minutes=3),
    ) -> None:
        self.fail_threshold = fail_threshold
        self.fail_window = fail_window
        self.portscan_ports = portscan_ports
        self.portscan_window = portscan_window
        self.failed_logins: Dict[str, Deque[datetime]] = defaultdict(deque)
        self.port_activity: Dict[str, Deque[Tuple[str, datetime]]] = defaultdict(deque)

    def process_line(self, line: str) -> List[Alert]:
        ts = self._parse_timestamp(line)
        alerts: List[Alert] = []

        failed_ip = self._match_failed_login(line)
        if failed_ip:
            alerts.extend(self._handle_failed_login(failed_ip, ts))

        port_match = PORT_SCAN_PATTERN.search(line)
        if port_match:
            ip = port_match.group("ip")
            port = port_match.group("port")
            alerts.extend(self._handle_port_activity(ip, port, ts))

        return alerts

    def _handle_failed_login(self, ip: str, ts: datetime) -> List[Alert]:
        bucket = self.failed_logins[ip]
        bucket.append(ts)
        self._prune_older_than(bucket, ts - self.fail_window)

        if len(bucket) >= self.fail_threshold:
            return [
                Alert(
                    category="brute_force",
                    ip=ip,
                    count=len(bucket),
                    first_seen=bucket[0],
                    last_seen=bucket[-1],
                    detail=f"{len(bucket)} failed logins within {self.fail_window}",
                )
            ]
        return []

    def _handle_port_activity(self, ip: str, port: str, ts: datetime) -> List[Alert]:
        bucket = self.port_activity[ip]
        bucket.append((port, ts))
        self._prune_port_activity(bucket, ts - self.portscan_window)

        unique_ports = {p for p, _ in bucket}
        if len(unique_ports) >= self.portscan_ports:
            earliest = min(t for _, t in bucket)
            return [
                Alert(
                    category="port_scan",
                    ip=ip,
                    count=len(unique_ports),
                    first_seen=earliest,
                    last_seen=ts,
                    detail=f"{len(unique_ports)} unique destination ports within {self.portscan_window}",
                )
            ]
        return []

    @staticmethod
    def _prune_older_than(bucket: Deque[datetime], threshold: datetime) -> None:
        while bucket and bucket[0] < threshold:
            bucket.popleft()

    @staticmethod
    def _prune_port_activity(bucket: Deque[Tuple[str, datetime]], threshold: datetime) -> None:
        while bucket and bucket[0][1] < threshold:
            bucket.popleft()

    @staticmethod
    def _match_failed_login(line: str) -> str | None:
        for pattern in FAILED_LOGIN_PATTERNS:
            match = pattern.search(line)
            if match:
                return match.group("ip")
        return None

    @staticmethod
    def _parse_timestamp(line: str) -> datetime:
        """
        Parse syslog-style timestamps; fall back to now if parsing fails.
        """
        match = SYSLOG_TS_RE.match(line)
        if not match:
            return datetime.now()

        current_year = datetime.now().year
        ts_str = f"{current_year} {match.group('month')} {match.group('day')} {match.group('time')}"
        try:
            return datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")
        except ValueError:
            return datetime.now()


def iter_log_lines(path: Path) -> Iterable[str]:
    if str(path) == "-":
        for line in sys.stdin:
            yield line.rstrip("\n")
    else:
        with path.open("r", encoding="utf-8", errors="ignore") as log_file:
            for line in log_file:
                yield line.rstrip("\n")


def render_alert(alert: Alert) -> str:
    return (
        f"[ALERT] {alert.category} | ip={alert.ip} | count={alert.count} | "
        f"first_seen={alert.first_seen.isoformat()} | last_seen={alert.last_seen.isoformat()} | {alert.detail}"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Lightweight heuristic intrusion detection for system logs."
    )
    parser.add_argument(
        "-f",
        "--log-file",
        type=Path,
        help="Path to a log file to scan (or '-' for stdin).",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run against a built-in demo log to see sample alerts.",
    )
    parser.add_argument(
        "--fail-threshold",
        type=int,
        default=5,
        help="Failed login attempts per window that trigger brute-force alert.",
    )
    parser.add_argument(
        "--fail-window-minutes",
        type=int,
        default=5,
        help="Time window (minutes) for failed login counting.",
    )
    parser.add_argument(
        "--portscan-ports",
        type=int,
        default=6,
        help="Unique ports per window that trigger port-scan alert.",
    )
    parser.add_argument(
        "--portscan-window-minutes",
        type=int,
        default=3,
        help="Time window (minutes) for port-scan detection.",
    )
    args = parser.parse_args()

    # If nothing is provided, fall back to demo mode to avoid hard failure in IDE runs.
    if not args.demo and not args.log_file:
        print(
            "No log file provided; defaulting to demo. "
            "Use -f /path/to/log to scan real logs."
        )
        args.demo = True
    return args


def main() -> None:
    args = parse_args()

    detector = IntrusionDetector(
        fail_threshold=args.fail_threshold,
        fail_window=timedelta(minutes=args.fail_window_minutes),
        portscan_ports=args.portscan_ports,
        portscan_window=timedelta(minutes=args.portscan_window_minutes),
    )

    if args.demo:
        lines = DEMO_LOG.splitlines()
        print("Running demo. Alerts below:\n")
    else:
        assert args.log_file is not None
        lines = iter_log_lines(args.log_file)

    total_alerts = 0
    for line in lines:
        for alert in detector.process_line(line):
            print(render_alert(alert))
            total_alerts += 1

    if total_alerts == 0:
        print("No alerts triggered with current thresholds.")


if __name__ == "__main__":
    main()
