# Air-Gapped Docker Purple-Team Validation Range (`lab/docker-range/`)

Runs **real Suricata 7**, **real Zeek LTS**, **real YARA**, **real Nginx**, and **`artex-hunt scan`** end-to-end over a strictly isolated (`internal: true`, zero-WAN) Docker bridge (`172.30.0.0/24`).

> **Safety Invariant:** Zero third-party offensive frameworks, zero live C2 infrastructure, zero external network access. All traffic consists of 100% harmless synthetic HTTP/TLS behavioral replays against the local isolated mock OpenAPI/web portal (`172.30.0.20`), plus benign & seeded local byte fixtures for YARA.

## Architecture

| Container / Stage | IP / Network | Role |
|---|---|---|
| `artex-range-target` | `172.30.0.20` (`internal: true`) | Nginx (HTTP `:80`, console `:8787`, TLS `:443` with self-signed `O=ARTEX` cert) + harmless Python mock OpenAPI backend (`target/app.py`) |
| `artex-range-capture` | Shared netns with `target` | Real `tcpdump` packet capture (`baseline.pcap` & `attack.pcap`) |
| `artex-range-replayer` | `172.30.0.10` (`internal: true`) | Phase 1 benign human/enterprise baseline + Phase 2 harmless behavioral replay (`replayer/replay_range.py`) |
| Offline Suricata 7 (`--network=none`) | None | Validates `suricata -T` + runs `rules/network/artex_edge_and_harness.rules` on both PCAPs |
| Offline Zeek LTS (`--network=none`) | None | Runs `rules/network/artex_agentic_cadence.zeek` + `policy/tuning/json-logs.zeek` on both PCAPs |
| Offline YARA (`--network=none`) | None | Scans benign vs. seeded fixtures with `rules/yara/*.yar` |

## Quick Start

```bash
bash lab/docker-range/run-range.sh
```

After the run finishes, inspect the real sensor outputs under `lab/docker-range/out/` (gitignored):

```bash
# Convert real Zeek attack logs to JSONL and scan with artex-hunt
python3 lab/kvm/export_sensor_to_jsonl.py \
  --input-dir lab/docker-range/out/zeek_atk \
  --out lab/docker-range/out/zeek_atk.jsonl

uv run artex-hunt scan lab/docker-range/out/baseline_nginx.log
uv run artex-hunt scan lab/docker-range/out/attack_nginx.log
uv run artex-hunt scan lab/docker-range/out/zeek_atk.jsonl
```
