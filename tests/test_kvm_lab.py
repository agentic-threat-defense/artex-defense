"""Automated validation for the reproducible host-only isolated KVM/QEMU Sensor + Target Lab (`lab/kvm/`)."""

import importlib.util
import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
import yaml

from artex_defense.detectors import scan_telemetry_file

REPO_ROOT = Path(__file__).resolve().parent.parent
LAB_DIR = REPO_ROOT / "lab" / "kvm"


def _load_exporter():
    spec = importlib.util.spec_from_file_location("export_sensor_to_jsonl", LAB_DIR / "export_sensor_to_jsonl.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_kvm_network_xml_enforces_strict_host_only_isolation() -> None:
    xml_path = LAB_DIR / "network_artex_isolated.xml"
    tree = ET.parse(xml_path)
    root = tree.getroot()
    assert root.findtext("name") == "artex-lab-isolated"
    # HARD SECURITY INVARIANT: zero <forward> directive allowed
    assert root.find("forward") is None, "Host-only isolated network XML must NOT contain <forward>!"
    ip_el = root.find("ip")
    assert ip_el is not None and ip_el.attrib.get("address") == "192.168.250.1"


def test_cloud_init_configs_valid_and_have_no_default_gateway() -> None:
    for role, expected_ip in (("sensor", "192.168.250.10/24"), ("target", "192.168.250.20/24")):
        role_dir = LAB_DIR / "cloud-init" / role
        user_data = yaml.safe_load((role_dir / "user-data.yaml").read_text(encoding="utf-8"))
        meta_data = yaml.safe_load((role_dir / "meta-data.yaml").read_text(encoding="utf-8"))
        net_cfg = yaml.safe_load((role_dir / "network-config.yaml").read_text(encoding="utf-8"))

        assert user_data["hostname"] == f"artex-{role}-01"
        assert meta_data["local-hostname"] == f"artex-{role}-01"
        nic = net_cfg["ethernets"]["nic0"]
        assert nic["dhcp4"] is False
        assert expected_ip in nic["addresses"]
        assert "gateway4" not in nic and "routes" not in nic, f"{role} network-config must NOT set a default gateway!"


def test_lab_ctl_syntax_and_offline_seed_iso_build(tmp_path: Path) -> None:
    ctl = LAB_DIR / "lab-ctl.sh"
    res_syn = subprocess.run(["bash", "-n", str(ctl)], capture_output=True, text=True, check=False)
    assert res_syn.returncode == 0, f"lab-ctl.sh syntax error: {res_syn.stderr}"

    if shutil.which("xorriso") is None:
        pytest.skip("xorriso not installed; skipping offline cloud-init seed ISO build")

    env = dict(os.environ, ARTEX_LAB_STATE_DIR=str(tmp_path / "state"))
    seeds_dir = tmp_path / "seeds"
    res_iso = subprocess.run(
        ["bash", str(ctl), "build-seeds", str(seeds_dir)],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert res_iso.returncode == 0, f"build-seeds failed: {res_iso.stderr}"
    for name in ("sensor-seed.iso", "target-seed.iso"):
        iso = seeds_dir / name
        assert iso.is_file() and iso.stat().st_size >= 32768


def test_raw_zeek_json_and_linux_auditd_converter_feeds_artex_hunt(tmp_path: Path) -> None:
    exporter = _load_exporter()
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()

    # Real Zeek conn.log JSON with encrypted TLS sawtooth growth (orig_bytes growing, resp_bytes steady)
    conn_lines = [
        f'{{"ts":"2026-11-20T22:00:{i*10:02d}.000Z","id.orig_h":"192.168.250.20","id.resp_h":"192.168.250.99","id.resp_p":443,"orig_bytes":{b_out},"resp_bytes":{b_in},"conn_state":"SF"}}'
        for i, (b_out, b_in) in enumerate([(4000, 1800), (9200, 2100), (16800, 2700), (27500, 3100), (42000, 3500), (58000, 2900)])
    ]
    (raw_dir / "conn.log").write_text("\n".join(conn_lines) + "\n", encoding="utf-8")

    # Real raw Linux Auditd SYSCALL + EXECVE lines (with split a0/a1/a2 args) for redundant recon + idioms
    audit_lines = [
        'type=SYSCALL msg=audit(1795212001.100:101): arch=c000003e syscall=59 exe="/usr/bin/whoami" comm="whoami" auid=1000 uid=33',
        'type=EXECVE msg=audit(1795212001.100:101): argc=1 a0="whoami"',
        'type=SYSCALL msg=audit(1795212011.100:102): arch=c000003e syscall=59 exe="/usr/bin/whoami" comm="whoami" auid=1000 uid=33',
        'type=EXECVE msg=audit(1795212011.100:102): argc=1 a0="whoami"',
        'type=SYSCALL msg=audit(1795212021.100:103): arch=c000003e syscall=59 exe="/usr/bin/whoami" comm="whoami" auid=1000 uid=33',
        'type=EXECVE msg=audit(1795212021.100:103): argc=1 a0="whoami"',
    ]
    (raw_dir / "target_audit.log").write_text("\n".join(audit_lines) + "\n", encoding="utf-8")

    out_jsonl = tmp_path / "lab_telemetry.jsonl"
    count = exporter.convert_directory(raw_dir, out_jsonl)
    assert count == 9

    cands = scan_telemetry_file(out_jsonl)
    observed = {r for c in cands for r in c.reasons}
    assert "llm_sawtooth_context_flow" in observed
    assert "multi_worker_redundant_recon" in observed


def test_zeek_ssl_uid_joins_sni_and_ja4_onto_conn_log_for_per_sni_sawtooth(tmp_path: Path) -> None:
    """Real Zeek writes byte counts in conn.log and SNI/JA4 in ssl.log linked by `uid`."""
    exporter = _load_exporter()
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()

    # Two distinct SNIs sharing the same reverse-proxy IP (172.30.0.20), plus a second ssl.log row
    # with empty server_name/ja4 for the same uid (must NOT overwrite prior values) and an HTTP uid
    # present in both conn.log and http.log (must deduplicate to 1 event instead of double-counting).
    conn_lines = [
        '{"ts":1795212000.0,"uid":"Cbenign1","id.orig_h":"172.30.0.10","id.resp_h":"172.30.0.20","id.resp_p":443,"orig_bytes":500,"resp_bytes":1200,"conn_state":"SF"}',
        '{"ts":1795212001.0,"uid":"Chttp1","id.orig_h":"172.30.0.10","id.resp_h":"172.30.0.20","id.resp_p":80,"orig_bytes":120,"resp_bytes":400,"conn_state":"SF"}',
        "not-valid-json-line",
    ]
    http_lines = [
        '{"ts":1795212001.0,"uid":"Chttp1","id.orig_h":"172.30.0.10","id.resp_h":"172.30.0.20","id.resp_p":80,"method":"GET","uri":"/dashboard","status_code":200,"user_agent":"Mozilla/5.0"}',
    ]
    ssl_lines = [
        '{"ts":1795212000.0,"uid":"Cbenign1","id.orig_h":"172.30.0.10","id.resp_h":"172.30.0.20","id.resp_p":443,"server_name":"benign-cdn.lab.local","ja4":"t13d1516h2_8daaf6152771_e5627efa2ab1"}',
        '{"ts":1795212000.1,"uid":"Cbenign1","id.orig_h":"172.30.0.10","id.resp_h":"172.30.0.20","id.resp_p":443}',
    ]
    for i, b_out in enumerate((4000, 9500, 17500, 29000, 44000, 62000)):
        ts = 1795212005.0 + i * 3.5
        uid = f"Csaw{i}"
        conn_lines.append(
            f'{{"ts":{ts},"uid":"{uid}","id.orig_h":"172.30.0.10","id.resp_h":"172.30.0.20","id.resp_p":443,"orig_bytes":{b_out},"resp_bytes":2200,"conn_state":"SF"}}'
        )
        ssl_lines.append(
            f'{{"ts":{ts},"uid":"{uid}","id.orig_h":"172.30.0.10","id.resp_h":"172.30.0.20","id.resp_p":443,"server_name":"relay-node-44.lab.local","ja4":"t13d1516h2_8daaf6152771_e5627efa2ab1"}}'
        )
    (raw_dir / "conn.log").write_text("\n".join(conn_lines) + "\n", encoding="utf-8")
    (raw_dir / "http.log").write_text("\n".join(http_lines) + "\n", encoding="utf-8")
    (raw_dir / "ssl.log").write_text("\n".join(ssl_lines) + "\n", encoding="utf-8")

    out_jsonl = tmp_path / "zeek_joined.jsonl"
    count = exporter.convert_directory(raw_dir, out_jsonl)
    # 1 benign TLS conn + 6 sawtooth TLS conn + 1 http (Chttp1 conn & merged ssl rows deduplicated) = 8
    assert count == 8
    text = out_jsonl.read_text(encoding="utf-8")
    assert '"dest_host": "benign-cdn.lab.local"' in text
    assert '"dest_host": "relay-node-44.lab.local"' in text
    assert '"ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1"' in text

    cands = scan_telemetry_file(out_jsonl)
    observed = {r for c in cands for r in c.reasons}
    assert "llm_sawtooth_context_flow" in observed


def test_lab_ctl_isolated_xml_check_ignores_xml_comments() -> None:
    """`require_isolated_xml` and `require_isolated_stdin` must parse XML elements rather than grepping comments."""
    ctl = LAB_DIR / "lab-ctl.sh"
    xml_path = LAB_DIR / "network_artex_isolated.xml"
    res = subprocess.run(
        ["bash", "-c", f'source <(sed "/^case /,\\$d" "{ctl}"); NET_XML="{xml_path}"; require_isolated_xml'],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0, f"require_isolated_xml failed on isolated XML: {res.stderr}"

    res_stdin_ok = subprocess.run(
        ["bash", "-c", f'source <(sed "/^case /,\\$d" "{ctl}"); require_isolated_stdin'],
        input="<network><!-- no <forward> --><name>artex-lab-isolated</name></network>",
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_stdin_ok.returncode == 0

    res_stdin_bad = subprocess.run(
        ["bash", "-c", f'source <(sed "/^case /,\\$d" "{ctl}"); require_isolated_stdin'],
        input='<network><name>bad</name><forward mode="nat"/></network>',
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_stdin_bad.returncode != 0


def test_auditd_exporter_skips_failed_path_probes_resolves_ppid_and_decodes_hex() -> None:
    """Real Linux kernel auditd emits `success=no` ENOENT PATH probes, `pid`/`ppid`, and hex-encoded EXECVE args."""
    exporter = _load_exporter()
    # Hex for `pgrep -a csfalcon` -> 7067726570202D6120637366616C636F6E
    audit_lines = [
        'type=SYSCALL msg=audit(1795369199.100:250): arch=c000003e syscall=59 success=yes exit=0 ppid=900 pid=910 auid=1000 uid=1000 comm="bash" exe="/usr/bin/bash"',
        'type=EXECVE msg=audit(1795369199.100:250): argc=3 a0="bash" a1="-c" a2=7067726570202D6120637366616C636F6E',
        # Failed PATH lookup (success=no, exit=-2, no EXECVE) -> must be skipped
        'type=SYSCALL msg=audit(1795369199.116:251): arch=c000003e syscall=59 success=no exit=-2 ppid=910 pid=911 auid=1000 uid=1000 comm="env" exe="/usr/bin/env"',
        # Child process referencing ppid=910 -> parent_process must resolve to /usr/bin/bash
        'type=SYSCALL msg=audit(1795369199.120:252): arch=c000003e syscall=59 success=yes exit=0 ppid=910 pid=912 auid=1000 uid=1000 comm="pgrep" exe="/usr/bin/pgrep"',
        'type=EXECVE msg=audit(1795369199.120:252): argc=3 a0="pgrep" a1="-a" a2="csfalcon"',
    ]
    events = exporter.convert_auditd_lines(audit_lines)
    assert len(events) == 2
    assert events[0]["process"] == "/usr/bin/bash"
    assert events[0]["command_line"] == "bash -c pgrep -a csfalcon"
    assert events[1]["process"] == "/usr/bin/pgrep"
    assert events[1]["parent_process"] == "/usr/bin/bash"
    assert events[1]["command_line"] == "pgrep -a csfalcon"


def _write_synthetic_pcap(path: Path, packets: list[tuple[float, str, int, str, int, int]], *, linktype: int = 1) -> None:
    """Build a minimal valid PCAP (Ethernet DLT=1 or Linux SLL2 DLT=276) with IPv4/TCP payload packets."""
    import socket
    import struct

    chunks = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)]
    for ts, src_ip, sport, dst_ip, dport, pay_len in packets:
        remaining = pay_len
        while remaining > 0:
            seg = min(remaining, 1400)
            remaining -= seg
            tcp_hdr = struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 0x50, 0x18, 65535, 0, 0)
            ip_tot = 20 + 20 + seg
            ip_hdr = struct.pack(
                "!BBHHHBBH4s4s",
                0x45,
                0,
                ip_tot,
                1,
                0,
                64,
                6,
                0,
                socket.inet_aton(src_ip),
                socket.inet_aton(dst_ip),
            )
            if linktype == 276:
                l2 = struct.pack("!HHI", 0x0800, 0, 1) + b"\x00" * 12
            else:
                l2 = b"\x00" * 12 + struct.pack("!H", 0x0800)
            frame = l2 + ip_hdr + tcp_hdr + (b"X" * seg)
            sec = int(ts)
            usec = int((ts - sec) * 1_000_000)
            chunks.append(struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame)
    path.write_bytes(b"".join(chunks))


def test_persistent_tls_agent_turn_loop_detects_single_socket_agent_and_rejects_rest_and_human_chat(tmp_path: Path) -> None:
    """Zero-IOC persistent TLS 1.3 detector: catches single-socket autonomous agent loops, rejects fast REST & human chat."""
    exporter = _load_exporter()

    # 1. TP: Single persistent TLS 1.3 socket (custom VPS IP) with 5 growing turns (35KB->40KB),
    # 1.2s LLM inference latency, 0.05s autonomous client turnaround, plus an interleaved 2.4KB sidecar!
    tp_pkts: list[tuple[float, str, int, str, int, int]] = []
    t = 1795374100.0
    for idx, (o_b, i_b) in enumerate([(35156, 117491), (2400, 18000), (35967, 128042), (36943, 119618), (37734, 124499), (39708, 132454)]):
        tp_pkts.append((t, "192.0.2.10", 41850, "198.51.100.77", 443, o_b))
        t += 1.4  # server LLM inference latency
        tp_pkts.append((t, "198.51.100.77", 443, "192.0.2.10", 41850, i_b))
        t += 0.05  # sub-second autonomous tool-loop turnaround
    tp_pcap = tmp_path / "agent_single_socket.pcap"
    _write_synthetic_pcap(tp_pcap, tp_pkts, linktype=276)  # Also tests Linux SLL2 (tcpdump -i any)!

    raw_tp = tmp_path / "tp_raw"
    raw_tp.mkdir()
    (raw_tp / "ssl.log").write_text(
        '{"ts":1795374099.0,"uid":"Ctp1","id.orig_h":"192.0.2.10","id.orig_p":41850,"id.resp_h":"198.51.100.77","id.resp_p":443,"server_name":"proxy-relay.example.test"}\n',
        encoding="utf-8",
    )
    tp_jsonl = tmp_path / "tp.jsonl"
    exporter.convert_directory(raw_tp, tp_jsonl, pcap_path=tp_pcap)
    cands = scan_telemetry_file(tp_jsonl)
    assert len(cands) == 1
    assert cands[0].reasons == ["encrypted_tls_agent_turn_loop"]
    assert cands[0].risk_score == 65
    assert cands[0].alert_tier == "hunt"
    assert any("tls_agent_loop:proxy-relay.example.test(" in ind for ind in cands[0].matched_indicators)

    # 2. FP Guard A: Benign fast REST/analytics stream (0.03s latency, chaotic sizes, 10s periodic flush) -> 0 hits
    rest_pkts: list[tuple[float, str, int, str, int, int]] = []
    t = 1795375000.0
    for o_b, i_b in [(53000, 485), (17900, 1216), (206000, 478), (566000, 401), (26400, 1136)]:
        rest_pkts.append((t, "192.0.2.20", 37840, "198.51.100.90", 443, o_b))
        t += 0.03  # fast REST ACK
        rest_pkts.append((t, "198.51.100.90", 443, "192.0.2.20", 37840, i_b))
        t += 10.0
    rest_pcap = tmp_path / "benign_rest.pcap"
    _write_synthetic_pcap(rest_pcap, rest_pkts, linktype=1)
    assert exporter.extract_pcap_tls_turns(rest_pcap) == []

    # 3. FP Guard B: Benign fresh human ChatGPT/Claude session (4KB->22KB, 1.6s latency, 18s human reading/typing pause) -> 0 candidates!
    human_pkts: list[tuple[float, str, int, str, int, int]] = []
    t = 1795376000.0
    for o_b, i_b in [(4000, 8000), (7200, 11000), (11000, 13000), (16000, 15000), (22000, 17000)]:
        human_pkts.append((t, "192.0.2.30", 51000, "198.51.100.91", 443, o_b))
        t += 1.6  # real LLM latency
        human_pkts.append((t, "198.51.100.91", 443, "192.0.2.30", 51000, i_b))
        t += 18.0  # human pauses 18s to read response and type next prompt
    human_pcap = tmp_path / "benign_human_chat.pcap"
    _write_synthetic_pcap(human_pcap, human_pkts, linktype=1)
    raw_h = tmp_path / "human_raw"
    raw_h.mkdir()
    human_jsonl = tmp_path / "human.jsonl"
    exporter.convert_directory(raw_h, human_jsonl, pcap_path=human_pcap)
    assert scan_telemetry_file(human_jsonl) == []

    # 4. Guard: explicit nonexistent --pcap path raises FileNotFoundError instead of silently falling back
    with pytest.raises(FileNotFoundError):
        exporter.convert_directory(raw_h, tmp_path / "missing.jsonl", pcap_path=tmp_path / "does_not_exist.pcap")


def test_persistent_tls_turn_slicer_generalizes_across_wan_tools_vllm_compaction_and_benign_traps(tmp_path: Path) -> None:
    """De-overtuning regression suite: 6 realistic agent variations (TP) + 5 benign persistent-TLS traps (0 FP)."""
    exporter = _load_exporter()

    def run_case(name: str, pkts: list[tuple[float, str, int, str, int, int]]) -> list[str]:
        pcap = tmp_path / f"{name}.pcap"
        _write_synthetic_pcap(pcap, pkts, linktype=1)
        raw = tmp_path / f"{name}_raw"
        raw.mkdir()
        out_j = tmp_path / f"{name}.jsonl"
        exporter.convert_directory(raw, out_j, pcap_path=pcap)
        return [r for c in scan_telemetry_file(out_j) for r in c.reasons]

    # TP 1: Agent running real 3-5s WAN tools (nmap/ffuf/curl) between turns
    pkts: list[tuple[float, str, int, str, int, int]] = []
    t = 1795400000.0
    for ob, ib, tool_s in [(32000, 90000, 3.8), (34500, 85000, 4.5), (37100, 95000, 2.9), (39800, 92000, 5.2), (43000, 88000, 0.0)]:
        pkts.append((t, "192.0.2.10", 50001, "198.51.100.1", 443, ob))
        t += 1.4
        pkts.append((t, "198.51.100.1", 443, "192.0.2.10", 50001, ib))
        t += tool_s
    assert "encrypted_tls_agent_turn_loop" in run_case("a1_wan_tools", pkts)

    # TP 2: Fast H100/vLLM proxy (0.22s TTFT)
    pkts = []
    t = 1795400000.0
    for ob, ib in [(28000, 45000), (30200, 48000), (32500, 44000), (35100, 50000), (38000, 47000)]:
        pkts.append((t, "192.0.2.10", 50002, "198.51.100.2", 443, ob))
        t += 0.22
        pkts.append((t, "198.51.100.2", 443, "192.0.2.10", 50002, ib))
        t += 0.30
    assert "encrypted_tls_agent_turn_loop" in run_case("a2_fast_vllm", pkts)

    # TP 3: HTTP/2 48B WINDOW_UPDATE interleaved mid-SSE-stream + 2.5s reasoning pause
    pkts = []
    t = 1795400000.0
    for ob, ib in [(35000, 90000), (36500, 95000), (38200, 92000), (40100, 98000), (42300, 96000)]:
        pkts.append((t, "192.0.2.10", 50003, "198.51.100.3", 443, ob))
        t += 1.5
        pkts.append((t, "198.51.100.3", 443, "192.0.2.10", 50003, 12000))
        t += 0.3
        pkts.append((t, "192.0.2.10", 50003, "198.51.100.3", 443, 48))  # H2 WINDOW_UPDATE
        t += 2.5  # reasoning thinking pause mid-stream
        pkts.append((t, "198.51.100.3", 443, "192.0.2.10", 50003, ib - 12000))
        t += 0.15
    assert "encrypted_tls_agent_turn_loop" in run_case("a3_h2_reasoning_pause", pkts)

    # TP 4: Mid-session context compaction (35K->37K->39K -> compact to 18K -> 21K -> 24K)
    pkts = []
    t = 1795400000.0
    for ob, ib in [(35000, 60000), (37000, 62000), (39000, 58000), (18000, 55000), (21000, 60000), (24000, 61000)]:
        pkts.append((t, "192.0.2.10", 50004, "198.51.100.4", 443, ob))
        t += 1.3
        pkts.append((t, "198.51.100.4", 443, "192.0.2.10", 50004, ib))
        t += 0.2
    assert "encrypted_tls_agent_turn_loop" in run_case("a4_compaction", pkts)

    # FP 1: Fast-reading human web-LLM user (8.5-12s pauses) -> 0 candidates
    pkts = []
    t = 1795400000.0
    for ob, ib, pause in [(6000, 12000, 9.0), (9000, 14000, 11.0), (12500, 11000, 8.5), (16000, 15000, 12.0), (20000, 13000, 0.0)]:
        pkts.append((t, "192.0.2.20", 51001, "198.51.100.11", 443, ob))
        t += 1.6
        pkts.append((t, "198.51.100.11", 443, "192.0.2.20", 51001, ib))
        t += pause
    assert run_case("b1_fast_human", pkts) == []

    # FP 2: Chunked S3/Docker upload (fixed 64KB chunks) -> 0 candidates
    pkts = []
    t = 1795400000.0
    for _ in range(6):
        pkts.append((t, "192.0.2.20", 51002, "198.51.100.12", 443, 65536))
        t += 0.45
        pkts.append((t, "198.51.100.12", 443, "192.0.2.20", 51002, 1200))
        t += 0.05
    assert run_case("b2_chunked_upload", pkts) == []

    # FP 3: Slow BI/GraphQL dashboard (chaotic sizes, 1.2s DB latency) -> 0 candidates
    pkts = []
    t = 1795400000.0
    for ob, ib in [(8000, 45000), (14000, 12000), (6500, 88000), (19000, 5400), (9200, 31000)]:
        pkts.append((t, "192.0.2.20", 51003, "198.51.100.13", 443, ob))
        t += 1.2
        pkts.append((t, "198.51.100.13", 443, "192.0.2.20", 51003, ib))
        t += 0.2
    assert run_case("b3_bi_graphql", pkts) == []

    # FP 4: Slow API pagination (+50B req, growing resp) -> 0 candidates
    pkts = []
    t = 1795400000.0
    for ob, ib in [(4200, 20000), (4250, 40000), (4300, 60000), (4350, 80000), (4400, 100000)]:
        pkts.append((t, "192.0.2.20", 51004, "198.51.100.14", 443, ob))
        t += 0.8
        pkts.append((t, "198.51.100.14", 443, "192.0.2.20", 51004, ib))
        t += 0.1
    assert run_case("b4_api_pagination", pkts) == []
