# Tier 3 Reproducible Air-Gapped KVM/QEMU Sensor + Target Lab

> **OpSec Invariant:** Both VMs attach **exclusively** to libvirt network `artex-lab-isolated` (`virbr-artex`, `192.168.250.0/24`), which has **no `<forward>` directive** and **no default gateway** in cloud-init. Clipboard and host-folder sharing are disabled.

## Architecture
| VM | Static IP | MAC | Role | Telemetry Emitted |
| :--- | :--- | :--- | :--- | :--- |
| **`artex-sensor-01`** | `192.168.250.10/24` | `52:54:00:a7:e0:10` | Passive Network & Audit Sensor | Zeek JSON (`conn.log`, `http.log`, `ssl.log`, JA4/JA4H) + `tcpdump` PCAP + Auditd |
| **`artex-target-01`** | `192.168.250.20/24` | `52:54:00:a7:e0:20` | Benign Mock Web Portal & Endpoint | `benign-mock-portal.py` (`:8080`) + Linux Auditd `execve` (`99-artex-execve.rules`) |

## Quick-Start Workflow
```bash
# 1. Verify KVM/QEMU tooling & air-gap invariant
./lab/kvm/lab-ctl.sh check

# 2. Download an official minimal cloud base image ONCE (e.g. Debian 12 GenericCloud):
mkdir -p ~/.local/share/artex-kvm-lab/base
curl -fL "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2" \
  -o ~/.local/share/artex-kvm-lab/base/debian-12-genericcloud-amd64.qcow2

# 3. Boot both air-gapped VMs with thin CoW overlays + automatic `clean-baseline` snapshot
./lab/kvm/lab-ctl.sh up ~/.local/share/artex-kvm-lab/base/debian-12-genericcloud-amd64.qcow2

# 4. Run 100% benign behavioral replay inside 192.168.250.0/24
python3 ./lab/kvm/benign_replay.py --target 192.168.250.20 --mode sawtooth

# 5. Export raw Zeek JSON + Auditd logs -> normalized JSONL -> scan in Tier 2 offline Docker sandbox
./lab/kvm/lab-ctl.sh export-logs quarantine/kvm_run_01
./scripts/sandbox-scan.sh quarantine/kvm_run_01/lab_telemetry.jsonl quarantine/kvm_run_01/candidates.json

# 6. Always revert to clean-baseline after every test run
./lab/kvm/lab-ctl.sh revert clean-baseline
```
