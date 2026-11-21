"""Tests for strictly read-only ARTEX operator/transit-host forensic triage (`host_triage.py`)."""

from pathlib import Path

from artex_defense.host_triage import run_host_triage


def _write_proc_net_tcp(path: Path, listen_ports: list[int]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"]
    for idx, port in enumerate(listen_ports):
        # 0100007F == 127.0.0.1, state 0A == TCP_LISTEN
        lines.append(
            f"   {idx}: 0100007F:{port:04X} 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 {50000 + idx} 1 0 100 0 0 10 0"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_host_triage_reports_clean_on_benign_offline_host(tmp_path: Path) -> None:
    host = tmp_path / "clean_host"
    proc = host / "proc"
    _write_proc_net_tcp(proc / "net" / "tcp", [22, 443, 8080])  # 8080 alone must NOT alert!

    pid_dir = proc / "1234"
    pid_dir.mkdir(parents=True)
    (pid_dir / "cmdline").write_bytes(b"/usr/bin/python3\x00app.py\x00")
    (pid_dir / "environ").write_bytes(b"PATH=/usr/bin\x00HOME=/home/user\x00")

    ca_dir = host / "etc" / "ssl" / "certs"
    ca_dir.mkdir(parents=True)
    (ca_dir / "DigiCert_Global_Root_G2.pem").write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")

    app_dir = host / "opt" / "corp-app"
    app_dir.mkdir(parents=True)
    (app_dir / "config.json").write_text('{"env": "prod"}\n', encoding="utf-8")

    pg_file = tmp_path / "benign_pg.sql"
    pg_file.write_text("CREATE TABLE assets (id int); CREATE TABLE companies (id int);\n", encoding="utf-8")

    report = run_host_triage(fs_root=host, proc_root=proc, pg_schema_file=pg_file)
    assert report.verdict == "clean", f"Expected clean verdict, got findings: {report.findings}"
    assert report.finding_count == 0


def test_host_triage_detects_all_artex_operator_host_artifacts(tmp_path: Path) -> None:
    host = tmp_path / "compromised_relay"
    proc = host / "proc"
    # Listening on 8787 (console), 8788 (recording proxy), 8790 (worker API), and co-located 8080 (Sub2API)
    _write_proc_net_tcp(proc / "net" / "tcp", [8787, 8788, 8790, 8080])

    # Simulated worker subprocess with injected HTTP_PROXY + mitmproxy CA env vars
    pid_worker = proc / "4242"
    pid_worker.mkdir(parents=True)
    (pid_worker / "cmdline").write_bytes(b"/usr/bin/curl\x00-sSk\x00https://target.example\x00")
    (pid_worker / "environ").write_bytes(
        b"HTTP_PROXY=http://127.0.0.1:8788\x00"
        b"SSL_CERT_FILE=/opt/artex/traffic/_ca/mitmproxy-ca-cert.pem\x00"
    )

    # Installed rogue mitmproxy CA in system trust store
    ca_dir = host / "usr" / "local" / "share" / "ca-certificates"
    ca_dir.mkdir(parents=True)
    (ca_dir / "mitmproxy-ca-cert.crt").write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")

    # ARTEX spill dir, traffic sqlite, jwt.key, config, and audit guard framing
    spill = host / "opt" / "artex" / "tasks" / "104" / "i3185" / "cmd-output"
    spill.mkdir(parents=True)
    (spill / "001.txt").write_text("whoami\n", encoding="utf-8")

    traffic_idx = host / "opt" / "artex" / "traffic" / "_index"
    traffic_idx.mkdir(parents=True)
    (traffic_idx / "index.sqlite").write_bytes(b"SQLite format 3\x00")

    (host / "opt" / "artex" / "jwt.key").write_text("secret-key\n", encoding="utf-8")
    (host / "opt" / "artex" / "artex_config.json").write_text('{"mode": "auto"}\n', encoding="utf-8")
    (host / "opt" / "artex" / "audit.log").write_text(
        "blocked action: 【ARTEX 平台管控·非目标防御】 out of scope\n", encoding="utf-8"
    )

    # PostgreSQL dual-graph schema dump
    pg_file = tmp_path / "artex_pg_tables.txt"
    pg_file.write_text(
        "public | exploration_nodes | table\n"
        "public | assets            | table\n"
        "public | companies         | table\n"
        "public | activity          | table\n"
        "public | agent_prompts     | table\n",
        encoding="utf-8",
    )

    report = run_host_triage(fs_root=host, proc_root=proc, pg_schema_file=pg_file)
    assert report.verdict == "likely_artex_host"
    checks_hit = {f.check for f in report.findings}
    assert checks_hit == {
        "listening_ports",
        "proc_proxy_ca_injection",
        "filesystem_artifacts",
        "audit_and_log_markers",
        "installed_ca_certs",
        "postgres_dual_graph",
    }
    # Verify co-located 8080 was surfaced alongside the 3 ARTEX ports
    port_evidences = [f.evidence for f in report.findings if f.check == "listening_ports"]
    assert any("8787" in e for e in port_evidences)
    assert any("8788" in e for e in port_evidences)
    assert any("8790" in e for e in port_evidences)
    assert any("8080" in e for e in port_evidences)
