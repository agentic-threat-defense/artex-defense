"""Unit tests for Stage 1 deterministic DuckDB + Python behavioral & artifact detectors."""

from pathlib import Path

from artex_defense.detectors import scan_telemetry_file

FIXTURE = Path(__file__).parent / "fixtures" / "sample_telemetry.jsonl"


def test_scan_separates_baseline_from_synthetic_agentic_windows() -> None:
    candidates = scan_telemetry_file(FIXTURE)
    hosts = {c.source_host for c in candidates}

    # Normal human-paced baseline traffic should NOT be flagged
    assert "wkstn-alice" not in hosts

    # Synthetic machine-speed burst + artifact + EDR probe + LLM egress window MUST be flagged
    assert "edge-portal-01" in hosts
    edge = next(c for c in candidates if c.source_host == "edge-portal-01")
    assert "machine_speed_burst" in edge.reasons
    assert "low_jitter_programmatic_cadence" in edge.reasons
    assert "automated_error_retry_loop" in edge.reasons
    assert "known_artex_artifact" in edge.reasons
    assert "agentic_default_port" in edge.reasons
    assert "llm_api_egress" in edge.reasons
    assert "edr_sensor_enumeration" in edge.reasons
    assert edge.cadence.event_count == 11
    assert edge.cadence.mean_interval_sec is not None and edge.cadence.mean_interval_sec < 1.5

    # Synthetic Cloud/IAM privilege burst MUST be flagged
    assert "entra-audit" in hosts
    iam = next(c for c in candidates if c.source_host == "entra-audit")
    assert "cloud_iam_privilege_burst" in iam.reasons


def test_bloodalchemy_and_artex_config_proxy_artifacts_detected(tmp_path: Path) -> None:
    log_file = tmp_path / "ba_test.jsonl"
    log_file.write_text(
        "\n".join(
            [
                '{"timestamp": "2026-11-20T12:00:00Z", "source_host": "srv-01", "actor": "svc", "event_type": "process", "process": "rundll32.exe", "command_line": "rundll32.exe graphics-hook-filter64.dll,Init"}',
                '{"timestamp": "2026-11-20T12:00:02Z", "source_host": "srv-01", "actor": "svc", "event_type": "http", "dest_host": "api.xcai.com", "http_path": "/Inform/logger/check", "status_code": 200}',
                '{"timestamp": "2026-11-20T12:00:04Z", "source_host": "srv-01", "actor": "svc", "event_type": "file", "command_line": "type artex_config.json"}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    candidates = scan_telemetry_file(log_file)
    assert len(candidates) == 1
    c = candidates[0]
    assert "known_artex_artifact" in c.reasons
    assert "llm_api_egress" in c.reasons
    indicators = " ".join(c.matched_indicators)
    assert "graphics-hook-filter64.dll" in indicators
    assert "/Inform/logger/" in indicators
    assert "artex_config.json" in indicators
    assert "xcai.com" in indicators


def test_unit42_canary_spec_targeting_and_write_readback_detected(tmp_path: Path) -> None:
    log_file = tmp_path / "unit42_test.jsonl"
    log_file.write_text(
        "\n".join(
            [
                '{"timestamp": "2026-11-20T13:00:00Z", "source_host": "31.40.205.155", "actor": "zz_no_such_user_9f3a", "event_type": "http", "http_method": "GET", "http_path": "/openapi.json", "user_agent": "Mozilla/5.0 (security-testing; authorized)", "status_code": 200}',
                '{"timestamp": "2026-11-20T13:00:02Z", "source_host": "31.40.205.155", "actor": "zz_no_such_user_9f3a", "event_type": "http", "http_method": "PUT", "http_path": "/api/v1/update-documents", "status_code": 422}',
                '{"timestamp": "2026-11-20T13:00:05Z", "source_host": "31.40.205.155", "actor": "zz_no_such_user_9f3a", "event_type": "http", "http_method": "PUT", "http_path": "/api/v1/update-documents", "status_code": 200}',
                '{"timestamp": "2026-11-20T13:00:06Z", "source_host": "31.40.205.155", "actor": "zz_no_such_user_9f3a", "event_type": "http", "http_method": "GET", "http_path": "/api/v1/update-documents", "status_code": 200}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    candidates = scan_telemetry_file(log_file)
    assert len(candidates) == 1
    reasons = set(candidates[0].reasons)
    assert "unit42_agentic_canary_probe" in reasons
    assert "spec_driven_api_targeting" in reasons
    assert "write_then_readback_verification" in reasons
    assert "agentic_user_agent_burst" in reasons


def test_artex_function_workspace_console_route_tp_and_tn(tmp_path: Path) -> None:
    """TP: Next.js i18n ARTEX console route `/function/workspace`; TN: benign workspace paths."""
    tp_log = tmp_path / "workspace_tp.jsonl"
    tp_log.write_text(
        "\n".join(
            [
                '{"timestamp": "2026-11-24T12:00:00Z", "source_host": "198.51.100.42", "actor": "op1", "event_type": "http", "http_method": "GET", "http_path": "/function/workspace", "status_code": 200}',
                '{"timestamp": "2026-11-24T12:00:02Z", "source_host": "198.51.100.42", "actor": "op1", "event_type": "http", "http_method": "GET", "http_path": "/function/workspace?tab=files", "status_code": 200}',
                '{"timestamp": "2026-11-24T12:00:04Z", "source_host": "198.51.100.42", "actor": "op1", "event_type": "http", "http_method": "GET", "http_path": "/function/workspace/download", "status_code": 200}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    tp_candidates = scan_telemetry_file(tp_log)
    assert len(tp_candidates) == 1
    assert "artex_console_or_host_forensics" in tp_candidates[0].reasons
    assert any("artex_console_route:/function/workspace" in ind for ind in tp_candidates[0].matched_indicators)

    tn_log = tmp_path / "workspace_tn.jsonl"
    tn_log.write_text(
        "\n".join(
            [
                '{"timestamp": "2026-11-24T12:10:00Z", "source_host": "198.51.100.43", "actor": "alice", "event_type": "http", "http_method": "GET", "http_path": "/function/workspace_docs", "status_code": 200}',
                '{"timestamp": "2026-11-24T12:10:30Z", "source_host": "198.51.100.43", "actor": "alice", "event_type": "http", "http_method": "GET", "http_path": "/workspaces/dev", "status_code": 200}',
                '{"timestamp": "2026-11-24T12:11:00Z", "source_host": "198.51.100.43", "actor": "alice", "event_type": "http", "http_method": "GET", "http_path": "/api/workspace/list", "status_code": 200}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    assert scan_telemetry_file(tn_log) == []


def test_wiz_leaked_intent_id_sequence_tp_and_benign_catalog_tn(tmp_path: Path) -> None:
    """Wiz Research (2026-11-25): cross-IP monotonic iNNNN Intent IDs TP vs benign catalog & arch tokens TN."""
    # TP1: Cross-IP rotating proxy pool hitting probe paths with monotonic i0412 -> i0415 -> i0419 (200 OK),
    # even with an unrelated benign /blog/post-i900 interleaved on the same dest_host.
    tp_cross_ip = tmp_path / "intent_cross_ip_tp.jsonl"
    tp_cross_ip.write_text(
        "\n".join(
            [
                '{"timestamp": "2026-11-26T10:00:00Z", "source_host": "203.0.113.11", "dest_host": "portal.corp.local", "event_type": "http", "http_method": "GET", "http_path": "/api/probe_i0412", "status_code": 200}',
                '{"timestamp": "2026-11-26T10:01:00Z", "source_host": "198.51.100.99", "dest_host": "portal.corp.local", "event_type": "http", "http_method": "GET", "http_path": "/blog/post-i900", "user_agent": "Mozilla/5.0 Chrome/131.0.0.0", "status_code": 200}',
                '{"timestamp": "2026-11-26T10:02:00Z", "source_host": "198.51.100.12", "dest_host": "portal.corp.local", "event_type": "http", "http_method": "GET", "http_path": "/api/probe_i0415", "status_code": 200}',
                '{"timestamp": "2026-11-26T10:04:00Z", "source_host": "192.0.2.13", "dest_host": "portal.corp.local", "event_type": "http", "http_method": "GET", "http_path": "/api/probe_i0419", "status_code": 200}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    tp1 = scan_telemetry_file(tp_cross_ip)
    seq1 = [c for c in tp1 if "leaked_intent_id_sequence" in c.reasons]
    assert len(seq1) == 1
    assert seq1[0].risk_score >= 75 and seq1[0].alert_tier == "alert"
    inds1 = " ".join(seq1[0].matched_indicators)
    assert "intent_id_sequence:i0412->i0415->i0419" in inds1
    assert "distinct_source_ips:3" in inds1

    # TP2: Single-IP 404 probe sweep with ascending i1201 -> i1204 -> i1209
    tp_single_ip = tmp_path / "intent_single_ip_tp.jsonl"
    tp_single_ip.write_text(
        "\n".join(
            [
                '{"timestamp": "2026-11-26T11:00:00Z", "source_host": "203.0.113.44", "dest_host": "app.corp.local", "event_type": "http", "http_method": "GET", "http_path": "/check-i1201", "status_code": 404}',
                '{"timestamp": "2026-11-26T11:01:00Z", "source_host": "203.0.113.44", "dest_host": "app.corp.local", "event_type": "http", "http_method": "GET", "http_path": "/check-i1204", "status_code": 404}',
                '{"timestamp": "2026-11-26T11:02:00Z", "source_host": "203.0.113.44", "dest_host": "app.corp.local", "event_type": "http", "http_method": "GET", "http_path": "/check-i1209", "status_code": 404}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    tp2 = scan_telemetry_file(tp_single_ip)
    seq2 = [c for c in tp2 if "leaked_intent_id_sequence" in c.reasons]
    assert len(seq2) == 1
    assert "intent_id_sequence:i1201->i1204->i1209" in " ".join(seq2[0].matched_indicators)

    # TN1: Benign e-commerce catalog browsing (BOTH single-IP and multi-customer 200 OK browsers) -> 0 FP
    tn_catalog = tmp_path / "intent_benign_catalog_tn.jsonl"
    tn_catalog.write_text(
        "\n".join(
            [
                '{"timestamp": "2026-11-26T12:00:00Z", "source_host": "198.51.100.10", "dest_host": "shop.corp.local", "event_type": "http", "http_method": "GET", "http_path": "/products/i0001", "user_agent": "Mozilla/5.0 Chrome/131.0.0.0", "status_code": 200}',
                '{"timestamp": "2026-11-26T12:00:20Z", "source_host": "198.51.100.11", "dest_host": "shop.corp.local", "event_type": "http", "http_method": "GET", "http_path": "/products/i0002", "user_agent": "Mozilla/5.0 Chrome/131.0.0.0", "status_code": 200}',
                '{"timestamp": "2026-11-26T12:00:45Z", "source_host": "198.51.100.12", "dest_host": "shop.corp.local", "event_type": "http", "http_method": "GET", "http_path": "/products/i0003", "user_agent": "Mozilla/5.0 Chrome/131.0.0.0", "status_code": 200}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    assert scan_telemetry_file(tn_catalog) == []

    # TN2: Benign x86 architecture / year tokens (`i386`, `i586`, `i686`) even returning 404 -> 0 FP
    tn_arch = tmp_path / "intent_benign_arch_tn.jsonl"
    tn_arch.write_text(
        "\n".join(
            [
                '{"timestamp": "2026-11-26T13:00:00Z", "source_host": "198.51.100.20", "dest_host": "mirror.corp.local", "event_type": "http", "http_method": "GET", "http_path": "/downloads/pkg-i386.deb", "status_code": 404}',
                '{"timestamp": "2026-11-26T13:00:30Z", "source_host": "198.51.100.20", "dest_host": "mirror.corp.local", "event_type": "http", "http_method": "GET", "http_path": "/downloads/pkg-i586.deb", "status_code": 404}',
                '{"timestamp": "2026-11-26T13:01:00Z", "source_host": "198.51.100.20", "dest_host": "mirror.corp.local", "event_type": "http", "http_method": "GET", "http_path": "/downloads/pkg-i686.deb", "status_code": 404}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    assert scan_telemetry_file(tn_arch) == []

    # TN3: Benign substring/hostname lookalikes (`uploads`, `author`, `admin.corp.local`) with 200 OK Chrome UA -> 0 FP
    for name, dest, path_tpl in (
        ("benign_uploads_200", "cdn.corp.local", "/uploads/item_i100{n}.jpg"),
        ("benign_author_200", "blog.corp.local", "/author/profile_i100{n}"),
        ("benign_admin_host_200", "admin.corp.local", "/invoices/i100{n}"),
    ):
        tn_sub = tmp_path / f"{name}.jsonl"
        tn_sub.write_text(
            "\n".join(
                f'{{"timestamp": "2026-11-26T14:0{n}:00Z", "source_host": "198.51.100.30", "dest_host": "{dest}", '
                f'"event_type": "http", "http_method": "GET", "http_path": "{path_tpl.format(n=n)}", '
                f'"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0", "status_code": 200}}'
                for n in (1, 2, 3)
            )
            + "\n",
            encoding="utf-8",
        )
        assert scan_telemetry_file(tn_sub) == [], f"Unexpected FP on {name}"
