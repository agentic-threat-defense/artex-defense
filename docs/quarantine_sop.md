# ARTEX Research Quarantine & OpSec Standard Operating Procedure

> **WARNING — Operational Safety (Zero Bare-Metal Exposure):** Never browse, curl, download, or inspect raw attacker directories (`SimpleHTTP`), exposed operator consoles, or suspect C2 infrastructure from a bare-metal host or corporate workstation. Identify and triage exposed infrastructure strictly through passive intelligence platforms (e.g., **Censys**, **Shodan**, **Hunt.io**, **Google Threat Intelligence (GTI)**, **GreyNoise**, **Team Cymru**, **FOFA**, **Validin**, **Silent Push**, **URLScan.io**, or equivalent passive TI services). Any retrieved artifacts or `TaskID` transcripts must be inspected exclusively inside an isolated, snapshotted analysis VM (Tier 3 air-gapped KVM/QEMU) and sanitized/redacted (stripping victim IPs, domains, and credentials) prior to offline analysis or rule tuning.

## Four-Tier Isolation Model

| Tier | Environment | Allowed Activities | Network Policy |
| :--- | :--- | :--- | :--- |
| **Tier 1 (Host)** | Bare-metal Linux + Local GPU | Local Ollama (`gemma4-hunter`), rule authoring, reviewing sanitized reports | `ollama.service` locked to `127.0.0.1:11434` with `IPAddressDeny=any` + `IPAddressAllow=localhost` |
| **Tier 2 (Offline Container)** | Docker (`scripts/sandbox-scan.sh`, `scripts/sandbox-analyze-tasks.sh`) | Parsing untrusted JSONL/telemetry exports via Stage 1 DuckDB + sanitizer | `--network=none`, `--read-only`, `--cap-drop=ALL`, non-root, single read-only file mount |
| **Tier 3 (Air-Gapped VMs)** | KVM/QEMU (`virt-manager` / `libvirt`) | Inspecting untrusted repos/artifacts, binary/YARA testing, isolated target + sensor labs | `artex-lab-isolated` (`192.168.250.0/24`, **no WAN/LAN forwarding**), snapshots before every run |
| **Tier 4 (External / MCP Boundary)** | Stdio MCP Server (`artex-gemma4`) | Orchestration, rule review, architecture | Automatic secret/email redaction, IP pseudonymization, URL/domain defanging (`sanitize=True` default) |

---

## 1. Managing Ollama Egress Lock
`ollama.service` is locked to localhost-only via `/etc/systemd/system/ollama.service.d/20-egress-lock.conf` so it cannot initiate outbound connections during hunting sessions.

```bash
# Check lock status
./scripts/ollama-egress.sh status

# Temporarily unlock ONLY when pulling a new model
./scripts/ollama-egress.sh unlock
ollama pull <model>
./scripts/ollama-egress.sh lock
```

---

## 2. Offline Parsing of Untrusted Telemetry & `TaskID` Transcripts (Tier 2)
```bash
# Scan & sanitize untrusted telemetry JSONL inside --network=none container
./scripts/sandbox-scan.sh quarantine/raw_logs.jsonl quarantine/sanitized_candidates.json

# Extract tool usage & failure->retry chains from quarantined TaskID transcripts (mandatory redaction/defanging)
./scripts/sandbox-analyze-tasks.sh quarantine/task_transcripts/ quarantine/sanitized_tasks.json
```
Both wrappers execute inside an ephemeral `--network=none --read-only --cap-drop=ALL` non-root container that mounts only the specified input path read-only and emits sanitized, defanged JSON.

---

## 3. Spinning Up Air-Gapped Lab VMs (Tier 3)
A strictly isolated virtual network **`artex-lab-isolated`** (`virbr-artex`, `192.168.250.0/24`) is preconfigured with **no `<forward>` directive** (zero internet or LAN routing).

Recommended workflow in `virt-manager`:
1. Create your analysis VM (e.g., REMnux / Ubuntu / Windows+Sysmon with `edk2-ovmf` + `swtpm`) attached **only** to `artex-lab-isolated`.
2. **Disable clipboard/folder sharing** between host and untrusted analysis VMs (export only sanitized JSONL logs when needed).
3. Take a clean **Snapshot** (`clean-baseline`) before introducing any untrusted sample, repo, or test replay.
4. Revert to `clean-baseline` after every test cycle.

---

## 4. Prompt-Injection Hygiene
- `worker.py` fences all untrusted log/document payloads in explicit `<<<BEGIN_...>>>` / `<<<END_...>>>` data delimiters before calling local Gemma 4.
- `mcp_server.py` prepends an untrusted-data security notice and enables `sanitize=True` by default on all four tools.
- Never allow an LLM verdict derived from untrusted telemetry to trigger automated shell execution without explicit human review.
