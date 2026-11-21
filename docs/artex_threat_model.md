# ARTEX & Autonomous Agentic Offensive Frameworks — Defensive Threat Model

## 1. Overview
**ARTEX** (and localized forks/variants such as **ScopeWeaver**, alongside related frameworks like Cairn, CyberStrikeAI, PentAGI, and Hexstrike) represents an autonomous multi-agent offensive architecture written in Go with a web/API control plane and shared dual-graph memory (assets + findings).

Rather than relying on a single static malware implant, a central **Planner** agent decomposes operator goals into tasks executed by **Worker** agents invoking standard tools (`nmap`, `curl`, `Impacket`, headless browsers, PowerShell/shell interpreters, cloud CLIs/APIs) in continuous feedback loops powered by external or self-hosted LLMs.

## 2. Why Traditional Static Signatures Fail
- Standard dual-use tooling (`curl`, `python`, `Impacket`, `az`/`aws`/Graph APIs) blends into admin noise if viewed as isolated single events.
- Prompts, filenames, and command wrappers mutate dynamically across runs and forks.
- Intrusions compress from days into **minutes or <3 hours**, outpacing manual alert queues.

## 3. High-Signal Defensive Detection Axes

| Axis | Behavioral / Artifact Signal | Primary Telemetry |
| :--- | :--- | :--- |
| **Machine-Speed Cadence** | Sustained bursts with low inter-event timing jitter (e.g., mean interval < 3s, stddev < 1.25s) across multi-step recon/access chains | HTTP/Proxy, Zeek, Sysmon, CloudTrail, Entra ID |
| **Automated Error-Retry Loops** | High ratio of 4xx/403/AccessDenied or command failures rapidly followed by mutated retry parameters within seconds | Web/WAF logs, API Gateway, PowerShell/Bash audit |
| **Known Framework Artifacts** | Default listener/console port `8787`, staging paths such as `C:\ProgramData\artx5v\`, binary/config strings (`artex`, `ScopeWeaver`) | EDR/Sysmon, Zeek/Firewall, YARA |
| **Anomalous LLM API Egress** | Servers, jump hosts, or non-developer endpoints calling commercial LLM endpoints (`api.anthropic.com`, `api.deepseek.com`, `open.bigmodel.cn`, `api.x.ai`, `api.openai.com`) | DNS, TLS SNI / Proxy, Firewall |
| **Automated Sensor-Evasion Probes** | Rapid programmatic querying of EDR/AV services (`CSFalcon`, `SentinelAgent`, `WinDefend`, `Sysmon`) prior to payload execution | Sysmon Event 1, EDR process creation |
| **Compressed Cloud/IAM Escalation** | Rapid service principal creation, secret/key additions, OAuth app consent grants, and cross-service Graph/IAM enumeration | Entra ID Audit, AWS CloudTrail, GCP Audit |

## 4. Hardening Checklist
- **Control-Plane & Identity Hygiene:** Enforce phishing-resistant MFA, short-lived tokens, strict conditional access, and alerting on every new service principal credential or OAuth app consent.
- **Edge & Peripheral Surface Reduction:** Inventory and shield legacy portals, partner apps, developer panels, and backup/management appliances behind Zero Trust access; sanitize verbose HTTP/API error responses that feed agentic error-correction loops.
- **Egress Control:** Restrict and log outbound traffic to external LLM API domains from production servers and administrative subnets.
- **EDR & Telemetry Coverage:** Ensure tamper protection on EDR sensors, centralize Sysmon/process + DNS/proxy + cloud audit logs with synchronized UTC timestamps for cadence analytics.
