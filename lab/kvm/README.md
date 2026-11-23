# Tier 3 Reproducible Host-Only Isolated KVM/QEMU Sensor + Target Lab

> **Isolation Boundary Note:** Both VMs attach **exclusively** to libvirt network `artex-lab-isolated` (`virbr-artex`, `192.168.250.0/24`), which has **no `<forward>` directive** and **no default gateway** in cloud-init (guests cannot route to WAN or LAN). Clipboard and host-folder sharing are disabled. Because VMs on a networked host still share the host hypervisor and host-only management bridge, this is a **host-only / non-routed isolated lab** — not a physical air-gap — and is intended for harmless behavioral telemetry replays and offline log validation, not detonating live untrusted malware.

## Architecture
| VM | Static IP | MAC | Role | Telemetry Emitted |
| :--- | :--- | :--- | :--- | :--- |
| **`artex-sensor-01`** | `192.168.250.10/24` | `52:54:00:a7:e0:10` | Passive Network & Audit Sensor | Zeek JSON (`conn.log`, `http.log`, `ssl.log`, JA4/JA4H) + `tcpdump` PCAP + Auditd |
| **`artex-target-01`** | `192.168.250.20/24` | `52:54:00:a7:e0:20` | Benign Mock Web Portal & Endpoint | `benign-mock-portal.py` (`:8080`) + Linux Auditd `execve` (`99-artex-execve.rules`) |

## Quick-Start Workflow
```bash
# 1. Verify KVM/QEMU tooling & non-routed network invariant
./lab/kvm/lab-ctl.sh check

# 2. Download an official minimal cloud base image ONCE into a qemu-traversable directory (0755):
mkdir -p /var/tmp/artex-kvm-lab/base && chmod 755 /var/tmp/artex-kvm-lab /var/tmp/artex-kvm-lab/base
curl -fL "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2" \
  -o /var/tmp/artex-kvm-lab/base/debian-12-genericcloud-amd64.qcow2

# 3. Boot both host-only isolated VMs with thin CoW overlays + automatic `clean-baseline` snapshot
./lab/kvm/lab-ctl.sh up /var/tmp/artex-kvm-lab/base/debian-12-genericcloud-amd64.qcow2

# 4. Run 100% benign behavioral replay inside 192.168.250.0/24
python3 ./lab/kvm/benign_replay.py --target 192.168.250.20 --mode sawtooth

# 5. Optional: Run the 4-phase unscripted live-LLM falsification benchmark (requires local Ollama)
#    Phase 1: Debian 12 auditd + sysadmin/browser baseline (0 FP)
#    Phase 2: Unscripted organic LLM agent (Zero static IOCs)
#    Phase 3: Stealth 4.5s-paced agent spoofing Chrome UA
#    Phase 4: Ultra-stealth 12.0s-paced agent (causal TLS + wire JA4H ceiling test)
python3 ./lab/kvm/run_falsification.py --model gemma4:26b --phases 1,2,3,4

# 6. Export raw Zeek JSON + DNS + Auditd logs -> normalized JSONL -> scan in Tier 2 offline Docker sandbox
./lab/kvm/lab-ctl.sh export-logs quarantine/kvm_run_01
./scripts/sandbox-scan.sh quarantine/kvm_run_01/lab_telemetry.jsonl quarantine/kvm_run_01/candidates.json

# 7. Always revert to clean-baseline (or auditd-ready) after every test run
./lab/kvm/lab-ctl.sh revert clean-baseline
```
