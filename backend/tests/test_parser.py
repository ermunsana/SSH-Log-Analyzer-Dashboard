from parser import InvalidLogFormatError, analyze_auth_log


ATTACK_LOG = """\
Jan 12 09:02:11 web01 sshd[1201]: Failed password for invalid user admin from 203.0.113.10 port 51122 ssh2
Jan 12 09:02:15 web01 sshd[1202]: Failed password for invalid user oracle from 203.0.113.10 port 51123 ssh2
Jan 12 09:02:18 web01 sshd[1203]: Failed password for invalid user backup from 203.0.113.10 port 51124 ssh2
Jan 12 09:02:22 web01 sshd[1204]: Failed password for root from 203.0.113.10 port 51125 ssh2
Jan 12 09:02:25 web01 sshd[1205]: Failed password for test from 203.0.113.10 port 51126 ssh2
Jan 12 09:03:01 web01 sshd[1211]: Failed publickey for deploy from 198.51.100.44 port 52110 ssh2
Jan 12 09:04:02 web01 sshd[1214]: Accepted publickey for deploy from 198.51.100.22 port 54500 ssh2
"""

QUIET_LOG = """\
Jan 12 09:14:02 web01 sshd[1301]: Accepted publickey for deploy from 198.51.100.22 port 54500 ssh2
Jan 12 09:14:15 web01 sshd[1302]: Failed password for root from 198.51.100.60 port 53111 ssh2
Jan 12 09:14:30 web01 sudo:    deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl status ssh
"""


def test_analyze_auth_log_returns_events_stats_and_alerts():
    result = analyze_auth_log(ATTACK_LOG)

    assert result.total_failed_logins == 6
    assert result.top_ips[0].ip_address == "203.0.113.10"
    assert result.top_ips[0].attempts == 5
    assert result.top_ips[0].is_suspicious is True
    assert result.statistics.most_targeted_usernames[0].username == "admin"
    assert "203.0.113.10" in result.statistics.suspicious_ips
    assert any(alert.alert_type == "brute_force" for alert in result.alerts)
    assert any(alert.alert_type == "username_enumeration" for alert in result.alerts)


def test_valid_auth_log_with_small_number_of_failures_returns_summary_alert():
    result = analyze_auth_log(QUIET_LOG)

    assert result.total_failed_logins == 1
    assert result.statistics.suspicious_ips == []
    assert result.alerts[0].alert_type == "summary"


def test_invalid_log_format_raises_error():
    invalid_log = "application started successfully"

    try:
        analyze_auth_log(invalid_log)
    except InvalidLogFormatError as exc:
        assert "does not look like a Linux auth.log" in str(exc)
    else:
        raise AssertionError("Expected InvalidLogFormatError to be raised")
