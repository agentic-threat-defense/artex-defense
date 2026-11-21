# Security Policy & Defensive Use Scope

## Defensive-Only Scope
This repository contains **strictly defensive** detection rules, log parsers, forensic triage utilities, synthetic telemetry generators, and air-gapped lab configurations intended exclusively for security monitoring, threat hunting, incident response, and detection engineering.

- **No Offensive Tooling:** This project does not contain, distribute, or invoke offensive exploits, scanners, or autonomous attack frameworks.
- **No Unverified or Victim Indicators:** All threat indicators are drawn strictly from published public threat intelligence advisories and are defanged in documentation. Never submit live victim telemetry, unredacted credentials, proprietary schemas, or unverified third-party IP addresses in issues or pull requests.

## Operational Safety (Zero Bare-Metal Exposure)
- Never browse, curl, download, or inspect raw attacker directories (`SimpleHTTP`), exposed operator consoles, or suspect C2 infrastructure from a bare-metal host or corporate workstation.
- Use passive third-party intelligence platforms (e.g., Censys, Shodan, Hunt.io, Google Threat Intelligence, GreyNoise, Team Cymru, FOFA, Validin, Silent Push, URLScan.io, or equivalent services) for infrastructure triage.
- Process untrusted telemetry exports or `TaskID` transcripts strictly inside the hardened `--network=none` Docker wrappers (`scripts/sandbox-scan.sh`, `scripts/sandbox-analyze-tasks.sh`) or an isolated, snapshotted Tier 3 air-gapped VM (`lab/kvm/`).

## Reporting Security Issues
If you discover a security vulnerability in the parsers, Docker sandbox wrappers, MCP server sanitization, or KVM lab templates (for example, path traversal, command injection, or sanitizer bypass), please report it privately via GitHub Security Advisories rather than opening a public issue.
