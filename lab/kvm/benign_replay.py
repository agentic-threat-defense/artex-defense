#!/usr/bin/env python3
"""100% benign behavioral traffic replay strictly scoped to the air-gapped 192.168.250.0/24 KVM lab.

Generates real HTTP wire traffic (benign browsing, growing-payload sawtooth POSTs, Unit 42 control-404
paths, and REST write->readback verification) so Zeek + Auditd capture authentic raw telemetry for
testing `artex-hunt` parsers and detectors without any malware or offensive tooling.
"""

from __future__ import annotations

import argparse
import ipaddress
import time
import urllib.error
import urllib.request

LAB_SUBNET = ipaddress.ip_network("192.168.250.0/24")


def _assert_airgap_ip(host: str) -> None:
    ip = ipaddress.ip_address(host)
    if ip not in LAB_SUBNET:
        raise SystemExit(f"REFUSED: Target {host} is outside air-gapped lab subnet {LAB_SUBNET}!")


def _req(url: str, *, method: str = "GET", body: bytes | None = None, ua: str = "Mozilla/5.0 Chrome/131.0") -> int:
    req = urllib.request.Request(url, data=body, method=method, headers={"User-Agent": ua})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            _ = resp.read()
            return int(resp.status)
    except urllib.error.HTTPError as err:
        return int(err.code)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run benign behavioral traffic replay inside 192.168.250.0/24.")
    parser.add_argument("--target", default="192.168.250.20", help="Target IP inside 192.168.250.0/24")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--mode", choices=("baseline", "sawtooth", "canary_spec"), default="baseline")
    args = parser.parse_args()

    _assert_airgap_ip(args.target)
    base = f"http://{args.target}:{args.port}"

    if args.mode == "baseline":
        for path in ("/health", "/", "/api/v1/documents"):
            code = _req(f"{base}{path}")
            print(f"[baseline] GET {path} -> {code}")
            time.sleep(6)
    elif args.mode == "sawtooth":
        for size in (4000, 9200, 16800, 27500, 42000, 58000):
            code = _req(f"{base}/sync", method="POST", body=b"A" * size)
            print(f"[sawtooth] POST /sync ({size}B) -> {code}")
            time.sleep(5)
    elif args.mode == "canary_spec":
        for method, path in [
            ("GET", "/zzzrandom12345"),
            ("GET", "/openapi.json"),
            ("PUT", "/api/v1/documents"),
            ("GET", "/api/v1/documents"),
        ]:
            code = _req(f"{base}{path}", method=method, body=b"{}" if method == "PUT" else None)
            print(f"[canary_spec] {method} {path} -> {code}")
            time.sleep(1.2)


if __name__ == "__main__":
    main()
