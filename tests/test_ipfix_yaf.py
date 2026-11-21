"""Tests for CERT NetSA YAF / super_mediator bidirectional IPFIX-JSON (RFC 5103) parsing and detection."""

import json
from pathlib import Path

from artex_defense.detectors import scan_telemetry_file
from artex_defense.parsers import parse_auto


def _write_jsonl(path: Path, records: list[dict]) -> Path:
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    return path


def test_parse_yaf_super_mediator_nested_and_flat_ipfix_biflows(tmp_path: Path) -> None:
    records = [
        # Nested super_mediator JSON format with flowStartMicroseconds as epoch microseconds
        {
            "flows": {
                "flowStartMicroseconds": 1795183200000000,
                "sourceIPv4Address": "10.20.30.40",
                "destinationIPv4Address": "198.51.100.244",
                "destinationTransportPort": 443,
                "protocolIdentifier": 6,
                "octetTotalCount": 14500,
                "reverseOctetTotalCount": 2400,
                "silkAppLabel": 443,
            },
            "tls": {
                "ja4": "t13d1516h2_8daaf6152771_b186095e22b6",
                "sslServerName": "relay-node.example-vps.net",
                "sslClientJA3": "771,4865-4866",
            },
        },
        # Flat IPFIX JSON format with HTTP DPI fields on non-standard port 8787
        {
            "flowStartMilliseconds": "2026-11-20 14:00:10.500",
            "sourceIPv4Address": "10.20.30.41",
            "destinationIPv4Address": "10.99.0.10",
            "destinationTransportPort": 8787,
            "octetTotalCount": 820,
            "reverseOctetTotalCount": 4200,
            "silkAppLabel": 80,
            "httpUserAgent": "artex-enrich/1.0",
            "httpGet": "/api/exploration/graph",
            "httpResponse": "200 OK",
        },
    ]
    path = _write_jsonl(tmp_path / "yaf_sample.jsonl", records)
    events = parse_auto(path)

    assert len(events) == 2
    ev0, ev1 = events
    assert ev0["appliance"] == "yaf_ipfix"
    assert ev0["source_host"] == "10.20.30.40"
    assert ev0["dest_host"] == "relay-node.example-vps.net"
    assert ev0["dest_port"] == 443
    assert ev0["bytes_out"] == 14500
    assert ev0["bytes_in"] == 2400
    assert ev0["ja4"] == "t13d1516h2_8daaf6152771_b186095e22b6"
    assert ev0["action"] == "ipfix_app_443"

    assert ev1["dest_port"] == 8787
    assert ev1["http_method"] == "GET"
    assert ev1["http_path"] == "/api/exploration/graph"
    assert ev1["user_agent"] == "artex-enrich/1.0"
    assert ev1["status_code"] == 200


def test_yaf_ipfix_encrypted_tls_sawtooth_caught_and_benign_media_clean(tmp_path: Path) -> None:
    # 1. Encrypted TLS 1.3 sawtooth LLM relay in raw YAF IPFIX biflows (ZERO HTTP fields, ZERO SNI -> raw IP!)
    base_us = 1795186800000000
    attack_flows = []
    for i, (b_out, b_in) in enumerate(
        [
            (4100, 1900),
            (9400, 2300),
            (17200, 2800),
            (29500, 3100),
            (44800, 3600),
            (63100, 2900),
        ]
    ):
        attack_flows.append(
            {
                "flows": {
                    "flowStartMicroseconds": base_us + i * 15_000_000,
                    "sourceIPv4Address": "10.40.1.25",
                    "destinationIPv4Address": "198.51.100.244",
                    "destinationTransportPort": 443,
                    "octetTotalCount": b_out,
                    "reverseOctetTotalCount": b_in,
                    "silkAppLabel": 443,
                },
                "tls": {
                    "ja4": "t13i1516h2_8daaf6152771_b186095e22b6",
                },
            }
        )
    cands = scan_telemetry_file(_write_jsonl(tmp_path / "yaf_sawtooth.jsonl", attack_flows))
    assert cands and "llm_sawtooth_context_flow" in cands[0].reasons
    assert cands[0].alert_tier == "alert"

    # 2. Benign stable S3 / media upload biflows in YAF IPFIX format -> MUST be 0 FPs
    benign_flows = [
        {
            "flows": {
                "flowStartMicroseconds": base_us + i * 8_000_000,
                "sourceIPv4Address": "10.40.1.90",
                "destinationIPv4Address": "52.216.10.5",
                "destinationTransportPort": 443,
                "octetTotalCount": 250000,
                "reverseOctetTotalCount": 180,
                "silkAppLabel": 443,
            },
            "tls": {
                "ja4": "t13d1516h2_8daaf6152771_b186095e22b6",
                "sslServerName": "s3.us-east-1.amazonaws.com",
            },
        }
        for i in range(6)
    ]
    assert scan_telemetry_file(_write_jsonl(tmp_path / "yaf_benign.jsonl", benign_flows)) == []
