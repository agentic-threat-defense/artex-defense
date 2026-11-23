#!/usr/bin/env bash
# End-to-end Non-Routed Isolated Docker Purple-Team Validation Runner
# Runs REAL Suricata 7, REAL Zeek LTS, REAL YARA, REAL Nginx, and `artex-hunt scan`
# over an `internal: true` (zero-WAN) Docker bridge network.
set -euo pipefail

RANGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${RANGE_DIR}/../.." && pwd)"
OUT_DIR="${RANGE_DIR}/out"

cleanup() {
  docker compose -f "${RANGE_DIR}/docker-compose.yml" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}/suricata_base" "${OUT_DIR}/suricata_atk" "${OUT_DIR}/zeek_base" "${OUT_DIR}/zeek_atk" "${OUT_DIR}/yara_fixtures"

echo "=== [1/7] Building sensor/target image & booting non-routed isolated range (internal: true) ==="
docker compose -f "${RANGE_DIR}/docker-compose.yml" build --quiet
docker compose -f "${RANGE_DIR}/docker-compose.yml" up -d
sleep 2

stop_capture() {
  local rc=0
  docker exec artex-range-capture pkill -INT tcpdump || rc=$?
  if [[ "${rc}" -ne 0 && "${rc}" -ne 1 ]]; then
    echo "ERROR: Failed to stop tcpdump (pkill exited ${rc})" >&2
    exit "${rc}"
  fi
}

echo "=== [2/7] Capturing Phase 1 (Benign Baseline) PCAP + Nginx Access Log ==="
docker exec -d artex-range-capture tcpdump -i eth0 -U -w /out/baseline.pcap
sleep 1
docker exec artex-range-replayer python3 /replayer/replay_range.py baseline
sleep 1
stop_capture
sleep 1
cp "${OUT_DIR}/nginx_access.log" "${OUT_DIR}/baseline_nginx.log"
docker exec artex-range-target truncate -s 0 /out/nginx_access.log

echo "=== [3/7] Capturing Phase 2 (Harmless Behavioral Replay) PCAP + Nginx Access Log ==="
docker exec -d artex-range-capture tcpdump -i eth0 -U -w /out/attack.pcap
sleep 1
docker exec artex-range-replayer python3 /replayer/replay_range.py attack
sleep 2
stop_capture
sleep 1
cp "${OUT_DIR}/nginx_access.log" "${OUT_DIR}/attack_nginx.log"

echo "=== [4/7] Validating REAL Suricata 7 (suricata -T + baseline.pcap + attack.pcap) ==="
docker run --rm --network=none \
  -v "${REPO_ROOT}/rules/network:/rules:ro" \
  -v "${OUT_DIR}:/out" \
  artex-range-sensor:local \
  bash -euo pipefail -c '
    suricata -T -S /rules/artex_edge_and_harness.rules --set vars.address-groups.HOME_NET="[172.30.0.0/24]" --set vars.address-groups.EXTERNAL_NET="any" -l /out/suricata_base
    suricata -r /out/baseline.pcap -S /rules/artex_edge_and_harness.rules --set vars.address-groups.HOME_NET="[172.30.0.0/24]" --set vars.address-groups.EXTERNAL_NET="any" --set app-layer.protocols.tls.ja3-fingerprints=yes -k none -l /out/suricata_base
    suricata -r /out/attack.pcap -S /rules/artex_edge_and_harness.rules --set vars.address-groups.HOME_NET="[172.30.0.0/24]" --set vars.address-groups.EXTERNAL_NET="any" --set app-layer.protocols.tls.ja3-fingerprints=yes -k none -l /out/suricata_atk
  '

echo "=== [5/7] Validating REAL Zeek LTS (baseline.pcap + attack.pcap) ==="
docker run --rm --network=none \
  -v "${REPO_ROOT}/rules/network:/rules:ro" \
  -v "${OUT_DIR}:/out" \
  zeek/zeek:lts \
  bash -euo pipefail -c '
    cd /out/zeek_base && zeek -C -r /out/baseline.pcap /rules/artex_agentic_cadence.zeek policy/tuning/json-logs.zeek "Site::local_nets+={172.30.0.10/32}"
    cd /out/zeek_atk  && zeek -C -r /out/attack.pcap   /rules/artex_agentic_cadence.zeek policy/tuning/json-logs.zeek "Site::local_nets+={172.30.0.10/32}"
  '

echo "=== [6/7] Validating REAL YARA binary on Benign & Seeded Fixtures ==="
python3 "${RANGE_DIR}/yara_fixtures.py" "${OUT_DIR}/yara_fixtures"
docker run --rm --network=none \
  -v "${REPO_ROOT}/rules/yara:/yara:ro" \
  -v "${OUT_DIR}/yara_fixtures:/fixtures:ro" \
  -v "${OUT_DIR}:/out" \
  artex-range-sensor:local \
  bash -euo pipefail -c '
    {
      yara -w /yara/artex_scopeweaver_artifacts.yar /fixtures/benign/
      yara -w /yara/gti_retrohunt_vaporpanda_bloodalchemy_artex.yar /fixtures/benign/
    } | tee /out/yara_benign.txt
    {
      yara -w /yara/artex_scopeweaver_artifacts.yar /fixtures/seeded/
      yara -w /yara/gti_retrohunt_vaporpanda_bloodalchemy_artex.yar /fixtures/seeded/
    } | tee /out/yara_seeded.txt
  '

echo "=== [7/7] Asserting Real-Sensor Scorecard (Suricata, Zeek, YARA, artex-hunt) ==="
PY_BIN="${REPO_ROOT}/.venv/bin/python"
[[ -x "${PY_BIN}" ]] || PY_BIN="python3"
"${PY_BIN}" "${REPO_ROOT}/lab/kvm/export_sensor_to_jsonl.py" --input-dir "${OUT_DIR}/zeek_base" --pcap "${OUT_DIR}/baseline.pcap" --out "${OUT_DIR}/zeek_base.jsonl"
"${PY_BIN}" "${REPO_ROOT}/lab/kvm/export_sensor_to_jsonl.py" --input-dir "${OUT_DIR}/zeek_atk"  --pcap "${OUT_DIR}/attack.pcap" --out "${OUT_DIR}/zeek_atk.jsonl"

"${PY_BIN}" - "${OUT_DIR}" <<'PYEOF'
import json, sys
from pathlib import Path

out = Path(sys.argv[1])

def suri_sids(path: Path) -> set[int]:
    if not path.is_file():
        return set()
    sids: set[int] = set()
    for ln in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not ln.strip():
            continue
        obj = json.loads(ln)
        if obj.get("event_type") == "alert":
            sids.add(int(obj["alert"]["signature_id"]))
    return sids

def zeek_notes(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    return {json.loads(ln)["note"] for ln in path.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip()}

base_sids = suri_sids(out / "suricata_base/eve.json")
atk_sids = suri_sids(out / "suricata_atk/eve.json")
assert len(base_sids) == 0, f"Suricata baseline FP alerts: {sorted(base_sids)}"
assert len(atk_sids) == 18, f"Expected 18/18 Suricata SIDs, got {len(atk_sids)}: {sorted(atk_sids)}"

base_notes = zeek_notes(out / "zeek_base/notice.log")
atk_notes = zeek_notes(out / "zeek_atk/notice.log")
assert len(base_notes) == 0, f"Zeek baseline FP notices: {sorted(base_notes)}"
expected_zeek = {
    "ArtexDefense::Agentic_Harness_UserAgent",
    "ArtexDefense::Agentic_HTTP_Error_Burst",
    "ArtexDefense::Agentic_ControlPlane_Or_Canary_URI",
    "ArtexDefense::Malicious_LLM_Relay_C2",
    "ArtexDefense::Webhook_Exfil_Traffic",
    "ArtexDefense::Anomalous_LLM_API_Egress",
}
assert expected_zeek.issubset(atk_notes), f"Missing Zeek notices: {sorted(expected_zeek - atk_notes)}"

yara_benign = [ln for ln in (out / "yara_benign.txt").read_text(encoding="utf-8").splitlines() if ln.strip()]
yara_seeded = [ln for ln in (out / "yara_seeded.txt").read_text(encoding="utf-8").splitlines() if ln.strip()]
assert len(yara_benign) == 0, f"YARA benign FP matches: {yara_benign}"
assert len(yara_seeded) >= 4, f"Expected >=4 YARA seeded matches, got {yara_seeded}"

def jsonl_ja4s(path: Path) -> set[str]:
    vals: set[str] = set()
    for ln in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not ln.strip():
            continue
        j = json.loads(ln).get("ja4")
        if j:
            vals.add(str(j))
    return vals

base_ja4s = jsonl_ja4s(out / "zeek_base.jsonl")
atk_ja4s = jsonl_ja4s(out / "zeek_atk.jsonl")
assert len(base_ja4s) == 1, f"Expected 1 consistent real wire JA4 in baseline, got {sorted(base_ja4s)}"
assert len(atk_ja4s) >= 4, f"Expected >=4 distinct real wire JA4s in attack, got {sorted(atk_ja4s)}"
assert any(j.startswith("t13i") for j in atk_ja4s), f"Expected raw-IP TLS (t13i...) JA4, got {sorted(atk_ja4s)}"
assert any(j.startswith("t13d") and j[8:10] == "h2" for j in atk_ja4s), f"Expected ALPN h2 JA4, got {sorted(atk_ja4s)}"
assert any(j.startswith("t12d") for j in atk_ja4s), f"Expected TLS 1.2 (t12d...) JA4, got {sorted(atk_ja4s)}"

# Cross-validate cipher/extension counts from pure-Python PCAP JA4 against real Suricata 7.0.3 tls.ja3.string!
suri_tls_ja3_counts: set[tuple[int, int]] = set()
for ln in (out / "suricata_atk/eve.json").read_text(encoding="utf-8", errors="ignore").splitlines():
    if not ln.strip():
        continue
    obj = json.loads(ln)
    if obj.get("event_type") == "tls":
        ja3_s = obj.get("tls", {}).get("ja3", {}).get("string", "")
        parts = ja3_s.split(",")
        if len(parts) >= 3 and parts[1]:
            cc = len([x for x in parts[1].split("-") if x])
            ec = len([x for x in parts[2].split("-") if x])
            suri_tls_ja3_counts.add((min(cc, 99), min(ec, 99)))
py_ja4_counts = {(int(j[4:6]), int(j[6:8])) for j in atk_ja4s}
assert suri_tls_ja3_counts and suri_tls_ja3_counts.issubset(py_ja4_counts), (
    f"PCAP JA4 cipher/ext counts {sorted(py_ja4_counts)} mismatch Suricata 7.0.3 JA3 {sorted(suri_tls_ja3_counts)}"
)

try:
    from artex_defense.detectors import scan_telemetry_file
except ImportError:
    print("PASS: Suricata 18/18, Zeek 6/6, YARA 0 FP / seeded OK, Wire JA4 verified (install artex-defense to also assert artex-hunt)")
    sys.exit(0)

base_ng = scan_telemetry_file(out / "baseline_nginx.log")
base_zk = scan_telemetry_file(out / "zeek_base.jsonl")
assert base_ng == [], f"baseline_nginx.log FP candidates: {[(c.risk_score, c.alert_tier, c.reasons) for c in base_ng]}"
assert base_zk == [], f"zeek_base.jsonl FP candidates: {[(c.risk_score, c.alert_tier, c.reasons) for c in base_zk]}"

atk_ng = scan_telemetry_file(out / "attack_nginx.log")
atk_zk = scan_telemetry_file(out / "zeek_atk.jsonl")
assert atk_ng and atk_ng[0].risk_score == 100 and atk_ng[0].alert_tier == "alert", f"Unexpected attack_nginx: {atk_ng}"
assert atk_zk and atk_zk[0].risk_score == 100 and atk_zk[0].alert_tier == "alert", f"Unexpected zeek_atk: {atk_zk}"
assert "llm_sawtooth_context_flow" in atk_zk[0].reasons, f"Sawtooth missing on real Zeek TLS 1.3: {atk_zk[0].reasons}"
assert "ja4_client_stack_whiplash" in atk_zk[0].reasons, f"Real-wire JA4 whiplash missing on Zeek+PCAP: {atk_zk[0].reasons}"

print(
    f"PASS: Suricata 0 FP / {len(atk_sids)}/18 SIDs | "
    f"Zeek 0 FP / {len(atk_notes)}/6 notices | "
    f"Wire JA4 1 baseline / {len(atk_ja4s)} attack stacks (cross-validated vs Suricata 7.0.3) | "
    f"YARA 0 FP / {len(yara_seeded)} seeded hits | "
    f"artex-hunt 0 baseline candidates / Nginx risk={atk_ng[0].risk_score} ({len(atk_ng[0].reasons)} reasons) / "
    f"Zeek+PCAP risk={atk_zk[0].risk_score} ({len(atk_zk[0].reasons)} reasons, incl. llm_sawtooth_context_flow + ja4_client_stack_whiplash)"
)
PYEOF
