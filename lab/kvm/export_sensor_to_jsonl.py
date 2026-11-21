#!/usr/bin/env python3
"""Offline converter: raw Zeek JSON (conn.log, http.log, ssl.log) + Linux Auditd EXECVE -> artex-hunt JSONL.

Bridges real KVM/QEMU sensor telemetry (including ugly Auditd `a0`/`a1`/`a2` argument splits and
Zeek `orig_bytes`/`resp_bytes`/`ja4`/`server_name`) directly into `artex-hunt scan`.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

AUDIT_TS_RE = re.compile(r"msg=audit\((\d+\.\d+):(\d+)\):")
AUDIT_KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|([0-9A-Fa-f]+|\S+))')
HEX_RE = re.compile(r"^[0-9A-Fa-f]{2,}$")


def _iso_from_epoch(ts: float | str) -> str:
    if isinstance(ts, str):
        try:
            float(ts)
            ts = float(ts)
        except ValueError:
            return ts
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _decode_audit_arg(val: str, quoted: bool) -> str:
    if quoted:
        return val
    if len(val) % 2 == 0 and HEX_RE.match(val):
        try:
            decoded = bytes.fromhex(val).decode("utf-8", errors="ignore")
            if decoded and all(32 <= ord(c) < 127 or c in "\t\n" for c in decoded):
                return decoded
        except ValueError:
            pass
    return val


def convert_zeek_json_lines(lines: list[str], kind: str) -> list[dict[str, Any]]:
    """Convert Zeek JSONL (`conn`, `http`, or `ssl`) into normalized artex-hunt JSONL dicts."""
    out: list[dict[str, Any]] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        rec = json.loads(line)
        ts = _iso_from_epoch(rec.get("ts", 0))
        src = rec.get("id.orig_h", "unknown")
        dst = rec.get("host") or rec.get("server_name") or rec.get("id.resp_h", "")
        port = rec.get("id.resp_p")

        if kind == "http":
            out.append(
                {
                    "timestamp": ts,
                    "source_host": src,
                    "actor": rec.get("username") or src,
                    "event_type": "http",
                    "surface": "web_portal",
                    "appliance": "zeek_http",
                    "dest_host": dst,
                    "dest_port": port,
                    "http_method": rec.get("method", ""),
                    "http_path": rec.get("uri", ""),
                    "user_agent": rec.get("user_agent", ""),
                    "ja4h": rec.get("ja4h", ""),
                    "bytes_out": rec.get("request_body_len"),
                    "bytes_in": rec.get("response_body_len"),
                    "status_code": rec.get("status_code"),
                    "action": "zeek_http",
                }
            )
        elif kind == "ssl":
            out.append(
                {
                    "timestamp": ts,
                    "source_host": src,
                    "actor": src,
                    "event_type": "network",
                    "surface": "network",
                    "appliance": "zeek_ssl",
                    "dest_host": dst,
                    "dest_port": port,
                    "ja4": rec.get("ja4", ""),
                    "action": "zeek_ssl",
                }
            )
        else:  # conn.log
            out.append(
                {
                    "timestamp": ts,
                    "source_host": src,
                    "actor": src,
                    "event_type": "network",
                    "surface": "network",
                    "appliance": "zeek_conn",
                    "dest_host": dst,
                    "dest_port": port,
                    "ja4": rec.get("ja4", ""),
                    "bytes_out": rec.get("orig_bytes") if rec.get("orig_bytes") is not None else rec.get("orig_ip_bytes"),
                    "bytes_in": rec.get("resp_bytes") if rec.get("resp_bytes") is not None else rec.get("resp_ip_bytes"),
                    "action": f"zeek_conn_{rec.get('conn_state', 'SF')}",
                }
            )
    return out


def convert_auditd_lines(lines: list[str], *, hostname: str = "artex-target-01") -> list[dict[str, Any]]:
    """Correlate Linux Auditd `SYSCALL` + `EXECVE` records by audit event ID into endpoint JSONL."""
    grouped: dict[str, dict[str, Any]] = {}
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        m_ts = AUDIT_TS_RE.search(line)
        if not m_ts:
            continue
        epoch_s, eid = float(m_ts.group(1)), m_ts.group(2)
        entry = grouped.setdefault(eid, {"epoch": epoch_s, "args": {}, "exe": "", "comm": "", "uid": "unknown"})

        if line.startswith("type=SYSCALL"):
            for k, qv, uv in AUDIT_KV_RE.findall(line):
                val = qv if qv != "" else uv
                if k == "exe":
                    entry["exe"] = val
                elif k == "comm":
                    entry["comm"] = val
                elif k in {"auid", "uid"} and entry["uid"] == "unknown":
                    entry["uid"] = val
        elif line.startswith("type=EXECVE"):
            for k, qv, uv in AUDIT_KV_RE.findall(line):
                if re.match(r"^a\d+$", k):
                    idx = int(k[1:])
                    entry["args"][idx] = _decode_audit_arg(qv if qv != "" else uv, quoted=(qv != ""))

    events: list[dict[str, Any]] = []
    for eid in sorted(grouped, key=lambda x: grouped[x]["epoch"]):
        g = grouped[eid]
        if not g["args"] and not g["exe"]:
            continue
        ordered_args = [g["args"][i] for i in sorted(g["args"])]
        cmdline = " ".join(ordered_args).strip() or g["exe"]
        proc = g["exe"] or (ordered_args[0] if ordered_args else g["comm"])
        events.append(
            {
                "timestamp": _iso_from_epoch(g["epoch"]),
                "source_host": hostname,
                "actor": f"uid:{g['uid']}",
                "event_type": "process",
                "surface": "endpoint",
                "appliance": "linux_auditd",
                "process": proc,
                "command_line": cmdline,
                "status_code": 0,
                "action": "execve",
            }
        )
    return events


def convert_directory(input_dir: Path, out_file: Path, *, target_host: str = "artex-target-01") -> int:
    """Convert all Zeek JSON logs and Auditd logs in `input_dir` into a single sorted JSONL file."""
    all_events: list[dict[str, Any]] = []
    for name, kind in (("conn.log", "conn"), ("http.log", "http"), ("ssl.log", "ssl")):
        p = input_dir / name
        if p.is_file():
            all_events.extend(convert_zeek_json_lines(p.read_text(encoding="utf-8", errors="ignore").splitlines(), kind))
    for audit_file in sorted(input_dir.glob("*audit*.log")):
        all_events.extend(
            convert_auditd_lines(
                audit_file.read_text(encoding="utf-8", errors="ignore").splitlines(),
                hostname=target_host,
            )
        )
    all_events.sort(key=lambda e: e["timestamp"])
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text("\n".join(json.dumps(e, ensure_ascii=False) for e in all_events) + ("\n" if all_events else ""), encoding="utf-8")
    return len(all_events)


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert raw Zeek JSON & Linux Auditd logs to artex-hunt JSONL.")
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--target-host", default="artex-target-01")
    args = parser.parse_args()
    count = convert_directory(args.input_dir, args.out, target_host=args.target_host)
    print(f"Converted {count} sensor events -> {args.out}")


if __name__ == "__main__":
    main()
