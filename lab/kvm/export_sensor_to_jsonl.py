#!/usr/bin/env python3
"""Offline converter: raw Zeek JSON (conn.log, http.log, ssl.log) + Linux Auditd EXECVE -> artex-hunt JSONL.

Bridges real KVM/QEMU sensor telemetry (including ugly Auditd `a0`/`a1`/`a2` argument splits and
Zeek `orig_bytes`/`resp_bytes`/`ja4`/`server_name`) directly into `artex-hunt scan`.
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TLS_LLM_PORTS: frozenset[int] = frozenset({443, 8443, 8788, 11434})

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


def convert_zeek_json_lines(
    lines: list[str],
    kind: str,
    *,
    ssl_by_uid: dict[str, tuple[str, str]] | None = None,
    skip_uids: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Convert Zeek JSONL (`conn`, `http`, or `ssl`) into normalized artex-hunt JSONL dicts."""
    out: list[dict[str, Any]] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict):
            continue
        uid = str(rec.get("uid") or "")
        if skip_uids and uid and uid in skip_uids:
            continue
        ts = _iso_from_epoch(rec.get("ts", 0))
        src = rec.get("id.orig_h", "unknown")
        sni_join, ja4_join = (ssl_by_uid.get(uid, ("", "")) if ssl_by_uid and uid else ("", ""))
        dst = rec.get("host") or rec.get("server_name") or sni_join or rec.get("id.resp_h", "")
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
                    "ja4": rec.get("ja4") or ja4_join,
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
        entry = grouped.setdefault(
            eid,
            {"epoch": epoch_s, "args": {}, "exe": "", "comm": "", "uid": "unknown", "pid": "", "ppid": "", "success": ""},
        )

        if line.startswith("type=SYSCALL"):
            for k, qv, uv in AUDIT_KV_RE.findall(line):
                val = qv if qv != "" else uv
                if k == "exe":
                    entry["exe"] = val
                elif k == "comm":
                    entry["comm"] = val
                elif k == "pid":
                    entry["pid"] = val
                elif k == "ppid":
                    entry["ppid"] = val
                elif k == "success":
                    entry["success"] = val
                elif k in {"auid", "uid"} and entry["uid"] == "unknown":
                    entry["uid"] = val
        elif line.startswith("type=EXECVE"):
            for k, qv, uv in AUDIT_KV_RE.findall(line):
                if re.match(r"^a\d+$", k):
                    idx = int(k[1:])
                    entry["args"][idx] = _decode_audit_arg(qv if qv != "" else uv, quoted=(qv != ""))

    pid_to_exe: dict[str, str] = {}
    events: list[dict[str, Any]] = []
    for eid in sorted(grouped, key=lambda x: grouped[x]["epoch"]):
        g = grouped[eid]
        # Skip failed execve() PATH-resolution probes (success=no, e.g. ENOENT with no EXECVE record)
        if g["success"] == "no" and not g["args"]:
            continue
        if not g["args"] and not g["exe"]:
            continue
        ordered_args = [g["args"][i] for i in sorted(g["args"])]
        cmdline = " ".join(ordered_args).strip() or g["exe"]
        proc = g["exe"] or (ordered_args[0] if ordered_args else g["comm"])
        if g["pid"] and proc:
            pid_to_exe[g["pid"]] = proc
        parent_proc = pid_to_exe.get(g["ppid"], "") if g["ppid"] else ""
        events.append(
            {
                "timestamp": _iso_from_epoch(g["epoch"]),
                "source_host": hostname,
                "actor": f"uid:{g['uid']}",
                "event_type": "process",
                "surface": "endpoint",
                "appliance": "linux_auditd",
                "process": proc,
                "parent_process": parent_proc,
                "command_line": cmdline,
                "status_code": 0,
                "action": "execve",
            }
        )
    return events


def extract_pcap_tls_turns(
    pcap_path: Path,
    *,
    ssl_by_tuple: dict[tuple[str, int, str, int], tuple[str, str]] | None = None,
    min_reversal_bytes: int = 128,
) -> list[dict[str, Any]]:
    """Stream-parse a PCAP (Ethernet DLT=1, Linux SLL DLT=113, or SLL2 DLT=276) into persistent TLS turn events.

    Slices single-socket HTTP/2 or Keep-Alive TLS 1.2/1.3 streams into directional `(OUT, IN)` turns by
    coalescing same-direction payload bursts until the opposite direction sends `>= min_reversal_bytes`
    (ignoring tiny HTTP/2 `WINDOW_UPDATE`/`PING` control frames and surviving multi-second reasoning pauses).
    """
    streams: dict[tuple[str, int, str, int], list[tuple[float, str, int]]] = {}
    tracked_ports = set(TLS_LLM_PORTS)
    if ssl_by_tuple:
        for _, _, _, rp in ssl_by_tuple:
            tracked_ports.add(rp)

    with pcap_path.open("rb") as fh:
        ghdr = fh.read(24)
        if len(ghdr) < 24:
            return []
        magic_le = struct.unpack("<I", ghdr[:4])[0]
        if magic_le == 0xA1B2C3D4:
            endian, ts_div = "<", 1_000_000.0
        elif magic_le == 0xD4C3B2A1:
            endian, ts_div = ">", 1_000_000.0
        elif magic_le == 0xA1B23C4D:
            endian, ts_div = "<", 1_000_000_000.0
        elif magic_le == 0x4D3CB2A1:
            endian, ts_div = ">", 1_000_000_000.0
        else:
            return []
        _, _, _, _, _, _, linktype = struct.unpack(f"{endian}IHHiIII", ghdr)

        while True:
            phdr = fh.read(16)
            if len(phdr) < 16:
                break
            ts_sec, ts_sub, incl_len, _ = struct.unpack(f"{endian}IIII", phdr)
            if incl_len > 16 * 1024 * 1024:  # Guard against corrupt/malformed PCAP packet lengths
                break
            pkt = fh.read(incl_len)
            if len(pkt) < incl_len:
                break

            # Decode L2 header -> IPv4 payload offset
            if linktype == 1:  # Ethernet (DLT_EN10MB)
                if len(pkt) < 14:
                    continue
                eth_type = struct.unpack("!H", pkt[12:14])[0]
                l3_off = 14
                if eth_type == 0x8100 and len(pkt) >= 18:  # 802.1Q VLAN
                    eth_type = struct.unpack("!H", pkt[16:18])[0]
                    l3_off = 18
                if eth_type != 0x0800:
                    continue
            elif linktype == 276:  # Linux SLL2 (tcpdump -i any)
                if len(pkt) < 20 or struct.unpack("!H", pkt[0:2])[0] != 0x0800:
                    continue
                l3_off = 20
            elif linktype == 113:  # Linux SLL v1
                if len(pkt) < 16 or struct.unpack("!H", pkt[14:16])[0] != 0x0800:
                    continue
                l3_off = 16
            else:
                continue

            if len(pkt) < l3_off + 20:
                continue
            ver_ihl = pkt[l3_off]
            if (ver_ihl >> 4) != 4 or pkt[l3_off + 9] != 6:  # IPv4 + TCP only
                continue
            ihl = (ver_ihl & 0x0F) * 4
            tot_len = struct.unpack("!H", pkt[l3_off + 2 : l3_off + 4])[0]
            if tot_len == 0:  # Linux NIC TSO offload leaves IPv4 tot_len=0 on outbound segments
                tot_len = len(pkt) - l3_off
            tcp_off = l3_off + ihl
            if ihl < 20 or len(pkt) < tcp_off + 20:
                continue
            sport, dport = struct.unpack("!HH", pkt[tcp_off : tcp_off + 4])
            tcp_hl = ((pkt[tcp_off + 12] >> 4) & 0x0F) * 4
            if tcp_hl < 20:
                continue
            pay_len = max(0, tot_len - ihl - tcp_hl)
            if pay_len == 0:
                continue

            ts = ts_sec + ts_sub / ts_div
            src = socket.inet_ntoa(pkt[l3_off + 12 : l3_off + 16])
            dst = socket.inet_ntoa(pkt[l3_off + 16 : l3_off + 20])
            if dport in tracked_ports and sport not in tracked_ports:
                streams.setdefault((src, sport, dst, dport), []).append((ts, "OUT", pay_len))
            elif sport in tracked_ports and dport not in tracked_ports:
                streams.setdefault((dst, dport, src, sport), []).append((ts, "IN", pay_len))

    out_events: list[dict[str, Any]] = []
    for key, pkts in streams.items():
        pkts.sort(key=lambda x: x[0])
        bursts: list[list[Any]] = []
        for ts, direction, nbytes in pkts:
            # Ignore tiny opposite-direction HTTP/2 WINDOW_UPDATE/PING/TLS control frames so
            # mid-stream server SSE responses are not shattered into fragments.
            if nbytes < min_reversal_bytes and bursts and bursts[-1][1] != direction:
                continue
            if bursts and bursts[-1][1] == direction:
                bursts[-1][2] = ts
                bursts[-1][3] += nbytes
            else:
                bursts.append([ts, direction, ts, nbytes])

        turns: list[tuple[float, float, int, float, float, int]] = []
        i = 0
        while i + 1 < len(bursts):
            if bursts[i][1] == "OUT" and bursts[i + 1][1] == "IN":
                o_s, _, o_e, o_b = bursts[i]
                i_s, _, i_e, i_b = bursts[i + 1]
                if o_b >= 2000 and i_b >= 400:
                    turns.append((o_s, o_e, o_b, i_s, i_e, i_b))
                i += 2
            else:
                i += 1

        # Emit only streams showing real multi-turn server inference latency (>=2 turns with lat >= 0.18s)
        if len(turns) < 3 or sum(1 for t in turns if (t[3] - t[1]) >= 0.18) < 2:
            continue

        src, sport, dst, dport = key
        sni, ja4 = ssl_by_tuple.get(key, ("", "")) if ssl_by_tuple else ("", "")
        dest_host = sni or dst
        stream_id = f"{src}:{sport}->{dst}:{dport}"

        for idx, (o_s, o_e, o_b, i_s, i_e, i_b) in enumerate(turns):
            inf_lat = max(0.0, i_s - o_e)
            turnaround = max(0.0, o_s - turns[idx - 1][4]) if idx > 0 else None
            out_events.append(
                {
                    "timestamp": _iso_from_epoch(o_s),
                    "source_host": src,
                    "actor": src,
                    "event_type": "network",
                    "surface": "network",
                    "appliance": "pcap_tls_turn",
                    "dest_host": dest_host,
                    "dest_port": dport,
                    "ja4": ja4,
                    "bytes_out": o_b,
                    "bytes_in": i_b,
                    "action": "tls_persistent_turn",
                    "raw_json": {
                        "stream_id": stream_id,
                        "inference_latency_s": round(inf_lat, 3),
                        "client_turnaround_s": round(turnaround, 3) if turnaround is not None else None,
                        "out_duration_s": round(max(0.0, o_e - o_s), 3),
                        "in_duration_s": round(max(0.0, i_e - i_s), 3),
                    },
                }
            )
    return out_events


def convert_directory(
    input_dir: Path,
    out_file: Path,
    *,
    target_host: str = "artex-target-01",
    pcap_path: Path | None = None,
) -> int:
    """Convert all Zeek JSON logs, Auditd logs, and optional PCAP TLS turns into a single sorted JSONL file."""
    all_events: list[dict[str, Any]] = []
    ssl_by_uid: dict[str, tuple[str, str]] = {}
    ssl_by_tuple: dict[tuple[str, int, str, int], tuple[str, str]] = {}
    http_uids: set[str] = set()
    conn_uids: set[str] = set()

    ssl_path = input_dir / "ssl.log"
    if ssl_path.is_file():
        for raw in ssl_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(rec, dict):
                continue
            uid = str(rec.get("uid") or "")
            new_sni = str(rec.get("server_name") or "")
            new_ja4 = str(rec.get("ja4") or "")
            if uid:
                prev_sni, prev_ja4 = ssl_by_uid.get(uid, ("", ""))
                ssl_by_uid[uid] = (new_sni or prev_sni, new_ja4 or prev_ja4)
            orig_h, orig_p = rec.get("id.orig_h"), rec.get("id.orig_p")
            resp_h, resp_p = rec.get("id.resp_h"), rec.get("id.resp_p")
            if orig_h and orig_p is not None and resp_h and resp_p is not None:
                tkey = (str(orig_h), int(orig_p), str(resp_h), int(resp_p))
                prev_tsni, prev_tja4 = ssl_by_tuple.get(tkey, ("", ""))
                ssl_by_tuple[tkey] = (new_sni or prev_tsni, new_ja4 or prev_tja4)

    http_path = input_dir / "http.log"
    if http_path.is_file():
        for raw in http_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict) and rec.get("uid"):
                http_uids.add(str(rec["uid"]))

    conn_path = input_dir / "conn.log"
    if conn_path.is_file():
        for raw in conn_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict) and rec.get("uid"):
                conn_uids.add(str(rec["uid"]))

    for name, kind, skips in (
        # Avoid double-counting connections: HTTP connections use rich http.log rows;
        # TLS connections use conn.log rows enriched with ssl.log server_name/ja4.
        ("conn.log", "conn", http_uids),
        ("http.log", "http", None),
        ("ssl.log", "ssl", conn_uids),
    ):
        p = input_dir / name
        if p.is_file():
            all_events.extend(
                convert_zeek_json_lines(
                    p.read_text(encoding="utf-8", errors="ignore").splitlines(),
                    kind,
                    ssl_by_uid=ssl_by_uid if kind == "conn" else None,
                    skip_uids=skips,
                )
            )
    for audit_file in sorted(input_dir.glob("*audit*.log")):
        all_events.extend(
            convert_auditd_lines(
                audit_file.read_text(encoding="utf-8", errors="ignore").splitlines(),
                hostname=target_host,
            )
        )
    if pcap_path is not None:
        if not pcap_path.is_file():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
        pcaps_to_scan = [pcap_path]
    else:
        pcaps_to_scan = sorted(input_dir.glob("*.pcap"))
    for pfile in pcaps_to_scan:
        all_events.extend(extract_pcap_tls_turns(pfile, ssl_by_tuple=ssl_by_tuple or None))
    all_events.sort(key=lambda e: e["timestamp"])
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text("\n".join(json.dumps(e, ensure_ascii=False) for e in all_events) + ("\n" if all_events else ""), encoding="utf-8")
    return len(all_events)


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert raw Zeek JSON, PCAP TLS turns & Linux Auditd logs to artex-hunt JSONL.")
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--pcap", type=Path, default=None, help="Optional PCAP file for intra-stream persistent TLS 1.3 turn extraction")
    parser.add_argument("--target-host", default="artex-target-01")
    args = parser.parse_args()
    count = convert_directory(args.input_dir, args.out, target_host=args.target_host, pcap_path=args.pcap)
    print(f"Converted {count} sensor events -> {args.out}")


if __name__ == "__main__":
    main()
