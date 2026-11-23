# Non-Routed Isolated Docker Purple-Team Validation Range (`lab/docker-range/`)

Runs **real Suricata 7**, **real Zeek LTS**, **real YARA**, **real Nginx**, and **`artex-hunt scan`** end-to-end over a non-routed (`internal: true`, zero-WAN) Docker bridge (`172.30.0.0/24`).

> **Safety & Isolation Boundary:** Zero third-party offensive frameworks, zero live C2 infrastructure, zero external network routing. All traffic consists of 100% harmless synthetic HTTP/TLS behavioral replays against the local isolated mock OpenAPI/web portal (`172.30.0.20`), plus benign & seeded local byte fixtures for YARA. Note that Docker `internal: true` provides non-routed network isolation on a shared host kernel — it is **not** a physical air-gap and must never be used to detonate live untrusted malware.

## Architecture

| Container / Stage | IP / Network | Role |
|---|---|---|
| `artex-range-target` | `172.30.0.20` (`internal: true`) | Nginx (HTTP `:80`, console `:8787`, Keep-Alive TLS 1.2/1.3 `:443` with self-signed `O=ARTEX` cert) + harmless Python mock OpenAPI/LLM-turn backend & isolated UDP/53 mock DNS responder (`target/app.py`) |
| `artex-range-capture` | Shared netns with `target` | Real `tcpdump` packet capture (`baseline.pcap`, `attack.pcap`, & `proxy_collapse.pcap`) |
| `artex-range-replayer` | `172.30.0.10` (`internal: true`) | Phase 1 benign human/enterprise baseline (authentic browser JA4H + benign DNS) + Phase 2 behavioral replay (persistent Keep-Alive TLS 1.3 + causal probes, stripped-JA4H impersonation, UDP/53 DNS OOB, deception canary) + Phase 3 single-JA4 recording-proxy collapse (`replayer/replay_range.py`) |
| Offline Suricata 7 (`--network=none`) | None | Validates `suricata -T --init-errors-fatal` + runs `rules/network/artex_edge_and_harness.rules` on baseline & attack PCAPs + direct `eve.json` ingestion in `artex-hunt` |
| Offline Zeek LTS (`--network=none`) | None | Runs `rules/network/artex_agentic_cadence.zeek` + `policy/tuning/json-logs.zeek` across all 3 PCAPs (HTTP, TLS, Conn, & DNS logs) |
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
