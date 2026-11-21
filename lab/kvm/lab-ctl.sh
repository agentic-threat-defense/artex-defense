#!/usr/bin/env bash
# Reproducible air-gapped KVM/QEMU Sensor + Target Lab controller (Tier 3 Quarantine)
# All VMs attach EXCLUSIVELY to `artex-lab-isolated` (192.168.250.0/24, zero WAN/LAN forwarding).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
NET_NAME="artex-lab-isolated"
NET_XML="${SCRIPT_DIR}/network_artex_isolated.xml"
STATE_DIR="${ARTEX_LAB_STATE_DIR:-${HOME}/.local/share/artex-kvm-lab}"
SSH_KEY_FILE="${ARTEX_LAB_SSH_KEY:-${STATE_DIR}/id_ed25519_lab}"

SENSOR_VM="artex-sensor-01"
TARGET_VM="artex-target-01"
SENSOR_MAC="52:54:00:a7:e0:10"
TARGET_MAC="52:54:00:a7:e0:20"

usage() {
  cat <<'EOF'
Usage: lab-ctl.sh <command> [args]

Commands:
  check                     Verify host KVM/QEMU tooling and air-gapped network invariant
  init-network              Ensure artex-lab-isolated (192.168.250.0/24, no <forward>) is active
  build-seeds [out_dir]     Generate cloud-init NoCloud seed ISOs via xorriso (100% offline)
  up <base_qcow2>           Create thin CoW overlays, boot sensor & target VMs air-gapped, take clean-baseline snapshot
  snapshot [name]           Take snapshots of both VMs (default: clean-baseline)
  revert [name]             Revert both VMs to snapshot (default: clean-baseline)
  status                    Show network and VM status
  export-logs <out_dir>     Pull Zeek JSON & Auditd logs over host-only bridge and normalize to JSONL
  destroy                   Power off and remove lab VMs & overlay disks (keeps base image)
EOF
}

require_airgap_xml() {
  if grep -qi "<forward" "${NET_XML}"; then
    echo "ERROR: Security invariant violated — ${NET_XML} must NOT contain a <forward> directive!" >&2
    exit 1
  fi
}

ensure_ssh_key() {
  mkdir -p "${STATE_DIR}"
  if [[ ! -f "${SSH_KEY_FILE}" ]]; then
    ssh-keygen -t ed25519 -N "" -C "artex-airgap-lab" -f "${SSH_KEY_FILE}" >/dev/null
  fi
}

cmd_check() {
  require_airgap_xml
  echo "[check] Verifying required host tools..."
  for bin in virsh qemu-img virt-install xorriso ssh-keygen; do
    if command -v "${bin}" >/dev/null 2>&1; then
      echo "  OK  ${bin} -> $(command -v "${bin}")"
    else
      echo "  MISS ${bin}" >&2
      exit 1
    fi
  done
  echo "[check] Network XML air-gap check: PASS (zero <forward> directives)"
  if virsh --connect qemu:///system net-info "${NET_NAME}" >/dev/null 2>&1; then
    if virsh --connect qemu:///system net-dumpxml "${NET_NAME}" | grep -qi "<forward"; then
      echo "ERROR: Live libvirt network ${NET_NAME} has a <forward> directive!" >&2
      exit 1
    fi
    echo "[check] Live libvirt network ${NET_NAME}: ACTIVE & AIR-GAPPED"
  else
    echo "[check] Live libvirt network ${NET_NAME}: not yet defined (run 'lab-ctl.sh init-network')"
  fi
}

cmd_init_network() {
  require_airgap_xml
  if ! virsh --connect qemu:///system net-info "${NET_NAME}" >/dev/null 2>&1; then
    virsh --connect qemu:///system net-define "${NET_XML}"
  fi
  virsh --connect qemu:///system net-autostart "${NET_NAME}" >/dev/null || true
  virsh --connect qemu:///system net-start "${NET_NAME}" >/dev/null 2>&1 || true
  if virsh --connect qemu:///system net-dumpxml "${NET_NAME}" | grep -qi "<forward"; then
    echo "ERROR: Active ${NET_NAME} contains <forward>; refusing to continue!" >&2
    exit 1
  fi
  echo "[init-network] ${NET_NAME} is active and verified air-gapped (192.168.250.0/24)."
}

cmd_build_seeds() {
  local out_dir="${1:-${STATE_DIR}/seeds}"
  mkdir -p "${out_dir}"
  ensure_ssh_key
  local pubkey
  pubkey="$(cat "${SSH_KEY_FILE}.pub")"

  for role in sensor target; do
    local stage="${out_dir}/${role}_stage"
    rm -rf "${stage}"
    mkdir -p "${stage}"
    sed "s|__LAB_SSH_PUBKEY__|${pubkey}|g" \
      "${SCRIPT_DIR}/cloud-init/${role}/user-data.yaml" > "${stage}/user-data"
    cp "${SCRIPT_DIR}/cloud-init/${role}/meta-data.yaml" "${stage}/meta-data"
    cp "${SCRIPT_DIR}/cloud-init/${role}/network-config.yaml" "${stage}/network-config"
    local iso="${out_dir}/${role}-seed.iso"
    rm -f "${iso}"
    xorriso -as mkisofs \
      -output "${iso}" \
      -volid cidata \
      -joliet -rock \
      "${stage}/user-data" "${stage}/meta-data" "${stage}/network-config" >/dev/null 2>&1
    rm -rf "${stage}"
    echo "[build-seeds] Built ${iso}"
  done
}

cmd_up() {
  local base_img="${1:-}"
  if [[ -z "${base_img}" || ! -f "${base_img}" ]]; then
    echo "ERROR: Provide path to a local cloud base image (.qcow2/.img), e.g. debian-12-genericcloud-amd64.qcow2" >&2
    exit 1
  fi
  cmd_init_network
  cmd_build_seeds "${STATE_DIR}/seeds"
  mkdir -p "${STATE_DIR}/disks"

  local sensor_disk="${STATE_DIR}/disks/${SENSOR_VM}.qcow2"
  local target_disk="${STATE_DIR}/disks/${TARGET_VM}.qcow2"
  [[ -f "${sensor_disk}" ]] || qemu-img create -f qcow2 -b "$(realpath "${base_img}")" -F qcow2 "${sensor_disk}" 20G
  [[ -f "${target_disk}" ]] || qemu-img create -f qcow2 -b "$(realpath "${base_img}")" -F qcow2 "${target_disk}" 20G

  for entry in "${SENSOR_VM}|${sensor_disk}|${STATE_DIR}/seeds/sensor-seed.iso|${SENSOR_MAC}|4096" \
               "${TARGET_VM}|${target_disk}|${STATE_DIR}/seeds/target-seed.iso|${TARGET_MAC}|2048"; do
    IFS='|' read -r vm disk seed mac ram <<< "${entry}"
    if virsh --connect qemu:///system dominfo "${vm}" >/dev/null 2>&1; then
      virsh --connect qemu:///system start "${vm}" >/dev/null 2>&1 || true
      continue
    fi
    virt-install \
      --connect qemu:///system \
      --name "${vm}" \
      --memory "${ram}" \
      --vcpus 2 \
      --disk "path=${disk},format=qcow2,bus=virtio" \
      --disk "path=${seed},device=cdrom" \
      --network "network=${NET_NAME},mac=${mac},model=virtio" \
      --os-variant debian12 \
      --graphics none \
      --console pty,target_type=serial \
      --import \
      --noautoconsole
    echo "[up] Provisioned air-gapped VM ${vm} on ${NET_NAME}"
  done
  cmd_snapshot "clean-baseline"
}

cmd_snapshot() {
  local snap="${1:-clean-baseline}"
  for vm in "${SENSOR_VM}" "${TARGET_VM}"; do
    if virsh --connect qemu:///system dominfo "${vm}" >/dev/null 2>&1; then
      virsh --connect qemu:///system snapshot-create-as "${vm}" --name "${snap}" --description "ARTEX lab ${snap}" >/dev/null 2>&1 || true
      echo "[snapshot] ${vm} -> ${snap}"
    fi
  done
}

cmd_revert() {
  local snap="${1:-clean-baseline}"
  for vm in "${SENSOR_VM}" "${TARGET_VM}"; do
    virsh --connect qemu:///system snapshot-revert "${vm}" --snapshotname "${snap}" --force
    echo "[revert] ${vm} <- ${snap}"
  done
}

cmd_status() {
  virsh --connect qemu:///system net-list --all
  virsh --connect qemu:///system list --all
}

cmd_export_logs() {
  local out_dir="${1:-${REPO_ROOT}/quarantine/kvm_export}"
  mkdir -p "${out_dir}/raw"
  local ssh_opts=(-i "${SSH_KEY_FILE}" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5)
  scp "${ssh_opts[@]}" "labops@192.168.250.10:/var/log/zeek/*.log" "${out_dir}/raw/" 2>/dev/null || true
  scp "${ssh_opts[@]}" "labops@192.168.250.20:/var/log/audit/audit.log" "${out_dir}/raw/target_audit.log" 2>/dev/null || true
  python3 "${SCRIPT_DIR}/export_sensor_to_jsonl.py" --input-dir "${out_dir}/raw" --out "${out_dir}/lab_telemetry.jsonl"
  echo "[export-logs] Normalized lab telemetry written to ${out_dir}/lab_telemetry.jsonl"
}

cmd_destroy() {
  for vm in "${SENSOR_VM}" "${TARGET_VM}"; do
    if virsh --connect qemu:///system dominfo "${vm}" >/dev/null 2>&1; then
      virsh --connect qemu:///system destroy "${vm}" >/dev/null 2>&1 || true
      virsh --connect qemu:///system undefine "${vm}" --snapshots-metadata --remove-all-storage >/dev/null 2>&1 || true
      echo "[destroy] Removed ${vm}"
    fi
  done
}

case "${1:-}" in
  check) cmd_check ;;
  init-network) cmd_init_network ;;
  build-seeds) cmd_build_seeds "${2:-}" ;;
  up) cmd_up "${2:-}" ;;
  snapshot) cmd_snapshot "${2:-clean-baseline}" ;;
  revert) cmd_revert "${2:-clean-baseline}" ;;
  status) cmd_status ;;
  export-logs) cmd_export_logs "${2:-}" ;;
  destroy) cmd_destroy ;;
  *) usage; exit 1 ;;
esac
