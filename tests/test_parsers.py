"""Unit tests for offline multi-surface appliance and web log parsers."""

from pathlib import Path

from artex_defense.parsers import (
    detect_log_format,
    parse_auto,
    parse_cisco_asa_ftd_syslog,
    parse_citrix_netscaler_log,
    parse_f5_bigip_log,
    parse_panos_log,
    parse_web_access_log,
)


def test_parse_cisco_asa_and_ftd_syslog() -> None:
    lines = [
        "2026-11-20T10:00:01Z fw-asa-01 %ASA-6-113005: AAA user authentication Rejected : reason = AAA failure : user = admin : user IP = 203.0.113.10 /+CSCOE+/logon.html",
        "2026-11-20T10:00:02Z fw-ftd-01 %FTD-6-113004: AAA user authentication Successful : server = 10.1.1.5 : user = jsmith : user IP = 203.0.113.11",
    ]
    assert detect_log_format(lines) == "cisco_asa_ftd"
    events = parse_cisco_asa_ftd_syslog(lines)
    assert len(events) == 2
    assert events[0]["appliance"] == "cisco_asa_ftd"
    assert events[0]["surface"] == "edge_appliance"
    assert events[0]["status_code"] == 401
    assert events[0]["http_path"] == "/+CSCOE+/logon.html"
    assert events[1]["status_code"] == 200


def test_parse_citrix_netscaler_log() -> None:
    lines = [
        "2026-11-20T10:01:00Z adc-gw-01 PPE-0 : SSLVPN LOGIN_FAILED : User extuser - Client_ip 203.0.113.20 - /nf/auth/doAuthentication.do"
    ]
    assert detect_log_format(lines) == "citrix_netscaler"
    events = parse_citrix_netscaler_log(lines)
    assert len(events) == 1
    assert events[0]["appliance"] == "citrix_netscaler"
    assert events[0]["status_code"] == 401
    assert events[0]["http_path"] == "/nf/auth/doAuthentication.do"


def test_parse_panos_and_f5_and_web_access(tmp_path: Path) -> None:
    panos_lines = [
        "2026-11-20T10:02:00Z,007200001234,GLOBALPROTECT,gateway-auth,203.0.113.30,gp.corp.local,admin,failure,/global-protect/login.esp,Nuclei"
    ]
    assert detect_log_format(panos_lines) == "panos"
    panos_ev = parse_panos_log(panos_lines)
    assert panos_ev[0]["appliance"] == "panos"
    assert panos_ev[0]["status_code"] == 401

    f5_lines = [
        "2026-11-20T10:03:00Z bigip-01 err apmd[3210]: Authentication failed for user=admin from 203.0.113.40 /tmui/login.jsp"
    ]
    assert detect_log_format(f5_lines) == "f5_bigip"
    f5_ev = parse_f5_bigip_log(f5_lines)
    assert f5_ev[0]["appliance"] == "f5_bigip"
    assert f5_ev[0]["status_code"] == 401
    assert f5_ev[0]["http_path"] == "/tmui/login.jsp"

    nginx_file = tmp_path / "edge.access.log"
    nginx_file.write_text(
        '203.0.113.50 - - [20/Nov/2026:10:04:00 +0000] "GET /mgmt/tm/util/bash HTTP/1.1" 401 256 "-" "HeadlessChrome/130"\n',
        encoding="utf-8",
    )
    parsed = parse_auto(nginx_file)
    assert len(parsed) == 1
    assert parsed[0]["appliance"] == "f5_bigip"
    assert parsed[0]["surface"] == "edge_appliance"
    assert parsed[0]["user_agent"] == "HeadlessChrome/130"


def test_wave1_native_cloudtrail_rfc3164_citrix_status_success_and_malformed_line_resilience(tmp_path: Path) -> None:
    # 1. Native AWS CloudTrail JSON (nested userIdentity.arn, camelCase userAgent, requestParameters)
    ct_file = tmp_path / "cloudtrail.jsonl"
    ct_file.write_text(
        '{"eventTime":"2026-11-21T12:00:00Z","eventSource":"ec2.amazonaws.com","eventName":"DescribeInstanceAttribute",'
        '"sourceIPAddress":"203.0.113.241","userAgent":"Boto3/1.35.0","userIdentity":{"arn":"arn:aws:sts::111122223333:assumed-role/WebRole/i-0abc1234567890"},'
        '"requestParameters":{"attribute":"userData","instanceId":"i-0001"}}\n'
        '{malformed truncated json line\n'
        '{"timestamp":"2026-11-21T12:00:05Z","source_host":"10.1.1.5","status":"success","userAgent":"CustomApp/1.0"}\n',
        encoding="utf-8",
    )
    events = parse_auto(ct_file)
    assert len(events) == 2
    assert events[0]["surface"] == "cloud_iam"
    assert events[0]["appliance"] == "aws_cloudtrail"
    assert events[0]["actor"].startswith("arn:aws:sts::")
    assert events[0]["user_agent"] == "Boto3/1.35.0"
    assert "userData" in events[0]["command_line"]
    assert events[0]["status_code"] == 200
    # "status": "success" MUST map to 200 (never 403!)
    assert events[1]["status_code"] == 200
    assert events[1]["user_agent"] == "CustomApp/1.0"

    # 2. RFC 3164 Citrix NetScaler syslog + malformed line skipped cleanly
    citrix_lines = [
        "Nov 21 10:00:00 ns01 11/21/2026:10:00:00 GMT ns01 0-PPE-0 : SSLVPN LOGIN_FAILED : User extuser - Client_ip 203.0.113.20 - /vpn/index.html",
        "BADTS host PPE-0 : SSLVPN garbage line",
    ]
    citrix_ev = parse_citrix_netscaler_log(citrix_lines)
    assert len(citrix_ev) == 1
    assert citrix_ev[0]["appliance"] == "citrix_netscaler"
    assert citrix_ev[0]["status_code"] == 401
