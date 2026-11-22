"""Automated validation for the reproducible air-gapped KVM/QEMU Sensor + Target Lab (`lab/kvm/`)."""

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


def test_kvm_network_xml_enforces_strict_airgap() -> None:
    xml_path = LAB_DIR / "network_artex_isolated.xml"
    tree = ET.parse(xml_path)
    root = tree.getroot()
    assert root.findtext("name") == "artex-lab-isolated"
    # HARD SECURITY INVARIANT: zero <forward> directive allowed
    assert root.find("forward") is None, "Air-gapped network XML must NOT contain <forward>!"
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


def test_lab_ctl_airgap_xml_check_ignores_xml_comments() -> None:
    """`require_airgap_xml` and `require_airgap_stdin` must parse XML elements rather than grepping comments."""
    ctl = LAB_DIR / "lab-ctl.sh"
    xml_path = LAB_DIR / "network_artex_isolated.xml"
    res = subprocess.run(
        ["bash", "-c", f'source <(sed "/^case /,\\$d" "{ctl}"); NET_XML="{xml_path}"; require_airgap_xml'],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0, f"require_airgap_xml failed on air-gapped XML: {res.stderr}"

    res_stdin_ok = subprocess.run(
        ["bash", "-c", f'source <(sed "/^case /,\\$d" "{ctl}"); require_airgap_stdin'],
        input="<network><!-- no <forward> --><name>artex-lab-isolated</name></network>",
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_stdin_ok.returncode == 0

    res_stdin_bad = subprocess.run(
        ["bash", "-c", f'source <(sed "/^case /,\\$d" "{ctl}"); require_airgap_stdin'],
        input='<network><name>bad</name><forward mode="nat"/></network>',
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_stdin_bad.returncode != 0
