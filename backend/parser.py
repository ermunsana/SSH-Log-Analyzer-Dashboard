import re
from collections import Counter, defaultdict

from schemas import (
    AnalysisStatistics,
    AnalyzeResponse,
    FailedLoginEvent,
    SecurityAlert,
    TargetedUsername,
    TopIP,
)


AUTH_MARKERS = (
    "sshd",
    "pam_unix",
    "authentication failure",
    "Failed password",
    "Accepted password",
    "Invalid user",
)
BRUTE_FORCE_THRESHOLD = 5
USERNAME_ENUMERATION_THRESHOLD = 3
FAILED_SSH_PATTERN = re.compile(
    r"""
    ^
    (?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})
    \s+
    (?P<host>\S+)
    \s+
    sshd(?:\[\d+\])?:
    \s+
    Failed
    \s+
    (?P<method>[\w/-]+)
    \s+
    for
    \s+
    (?:(?:invalid\s+user)\s+)?
    (?P<username>\S+)
    \s+
    from
    \s+
    (?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[A-Fa-f0-9:]+)
    """,
    re.VERBOSE,
)


class InvalidLogFormatError(ValueError):
    pass


def analyze_auth_log(log_content: str, source_name: str = "uploaded file") -> AnalyzeResponse:
    lines = [line.strip() for line in log_content.splitlines() if line.strip()]
    if not lines:
        raise InvalidLogFormatError("The uploaded file does not contain any readable log lines.")

    events, has_auth_context = parse_failed_login_events(lines)

    if not has_auth_context:
        raise InvalidLogFormatError(
            f"{source_name} does not look like a Linux auth.log or SSH authentication log."
        )

    statistics = compute_statistics(events)
    alerts = build_security_alerts(events, statistics)

    return AnalyzeResponse(
        total_failed_logins=len(events),
        top_ips=statistics.top_ips,
        events=events,
        statistics=statistics,
        alerts=alerts,
    )


def parse_failed_login_events(lines: list[str]) -> tuple[list[FailedLoginEvent], bool]:
    events: list[FailedLoginEvent] = []
    has_auth_context = False

    for line_number, line in enumerate(lines, start=1):
        if any(marker in line for marker in AUTH_MARKERS):
            has_auth_context = True

        match = FAILED_SSH_PATTERN.search(line)
        if not match:
            continue

        events.append(
            FailedLoginEvent(
                timestamp=match.group("timestamp"),
                ip_address=match.group("ip"),
                username=match.group("username"),
                method=match.group("method"),
                line_number=line_number,
                raw_line=line,
            )
        )

    return events, has_auth_context


def compute_statistics(events: list[FailedLoginEvent]) -> AnalysisStatistics:
    ip_counter: Counter[str] = Counter()
    username_counter: Counter[str] = Counter()
    usernames_by_ip: defaultdict[str, set[str]] = defaultdict(set)

    for event in events:
        ip_counter[event.ip_address] += 1
        if event.username:
            username_counter[event.username] += 1
            usernames_by_ip[event.ip_address].add(event.username)

    suspicious_ips = sorted(
        ip_address
        for ip_address, attempts in ip_counter.items()
        if attempts >= BRUTE_FORCE_THRESHOLD or len(usernames_by_ip[ip_address]) >= USERNAME_ENUMERATION_THRESHOLD
    )

    top_ips = [
        TopIP(
            ip_address=ip_address,
            attempts=count,
            is_suspicious=ip_address in suspicious_ips,
        )
        for ip_address, count in ip_counter.most_common(5)
    ]
    most_targeted_usernames = [
        TargetedUsername(username=username, attempts=count)
        for username, count in username_counter.most_common(5)
    ]

    return AnalysisStatistics(
        top_ips=top_ips,
        most_targeted_usernames=most_targeted_usernames,
        suspicious_ips=suspicious_ips,
    )


def build_security_alerts(
    events: list[FailedLoginEvent], statistics: AnalysisStatistics
) -> list[SecurityAlert]:
    alerts: list[SecurityAlert] = []
    username_sets_by_ip: defaultdict[str, set[str]] = defaultdict(set)
    attempts_by_ip: Counter[str] = Counter()

    for event in events:
        attempts_by_ip[event.ip_address] += 1
        if event.username:
            username_sets_by_ip[event.ip_address].add(event.username)

    for ip_address in statistics.suspicious_ips:
        attempts = attempts_by_ip[ip_address]
        targeted_usernames = sorted(username_sets_by_ip[ip_address])

        if attempts >= BRUTE_FORCE_THRESHOLD:
            alerts.append(
                SecurityAlert(
                    severity="high",
                    alert_type="brute_force",
                    ip_address=ip_address,
                    message=(
                        f"Possible brute-force activity detected from {ip_address}: "
                        f"{attempts} failed SSH login attempts."
                    ),
                )
            )

        if len(targeted_usernames) >= USERNAME_ENUMERATION_THRESHOLD:
            username_preview = ", ".join(targeted_usernames[:4])
            alerts.append(
                SecurityAlert(
                    severity="medium",
                    alert_type="username_enumeration",
                    ip_address=ip_address,
                    message=(
                        f"Possible username enumeration from {ip_address}: "
                        f"the source tried {len(targeted_usernames)} different usernames "
                        f"including {username_preview}."
                    ),
                )
            )

    if not alerts and statistics.top_ips:
        busiest_ip = statistics.top_ips[0]
        alerts.append(
            SecurityAlert(
                severity="info",
                alert_type="summary",
                ip_address=busiest_ip.ip_address,
                message=(
                    f"No high-confidence attack pattern was detected, but {busiest_ip.ip_address} "
                    f"generated the most failed SSH attempts ({busiest_ip.attempts})."
                ),
            )
        )

    return alerts
