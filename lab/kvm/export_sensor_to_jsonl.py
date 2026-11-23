#!/usr/bin/env python3
"""Offline converter: raw Zeek JSON (conn.log, http.log, ssl.log) + Linux Auditd EXECVE -> artex-hunt JSONL.

Bridges real KVM/QEMU sensor telemetry (including ugly Auditd `a0`/`a1`/`a2` argument splits and
Zeek `orig_bytes`/`resp_bytes`/`ja4`/`server_name`) directly into `artex-hunt scan`.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import socket
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TLS_LLM_PORTS: frozenset[int] = frozenset({443, 8443, 8788, 11434})
_TLS_VER_MAP: dict[int, str] = {
    0x0304: "13",
    0x0303: "12",
    0x0302: "11",
    0x0301: "10",
    0x0300: "s3",
    0x0002: "s2",
}


def _is_grease(val: int) -> bool:
    """Return True if uint16 `val` is one of the 16 RFC 8701 GREASE codepoints (0x?a?a)."""
    return (val & 0x0F0F) == 0x0A0A and (val >> 8) == (val & 0xFF)


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def parse_tls_client_hello_ja4(payload: bytes) -> tuple[str, str]:
    """Compute spec-compliant FoxIO JA4 (`t{ver}{sni}{cc}{ec}{alpn}_{c_hash}_{e_hash}`) from a TLS ClientHello.

    Returns `(sni, ja4)` where `sni` is the extracted hostname (empty if absent) and `ja4` is the
    36-char FoxIO JA4 fingerprint (or `""` if `payload` is not a complete TLS ClientHello).
    """
    if len(payload) < 48 or payload[0] != 0x16 or payload[1] != 0x03 or payload[5] != 0x01:
        return "", ""
    rec_len = struct.unpack("!H", payload[3:5])[0]
    hs_len = (payload[6] << 16) | (payload[7] << 8) | payload[8]
    if len(payload) < 9 + hs_len or rec_len < 42:
        return "", ""
    hs_end = 9 + hs_len
    pos = 9

    if pos + 35 > hs_end:
        return "", ""
    client_ver = struct.unpack("!H", payload[pos : pos + 2])[0]
    pos += 34  # version (2) + random (32)
    sid_len = payload[pos]
    pos += 1 + sid_len
    if pos + 2 > hs_end:
        return "", ""

    cs_len = struct.unpack("!H", payload[pos : pos + 2])[0]
    pos += 2
    if cs_len % 2 != 0 or pos + cs_len > hs_end:
        return "", ""
    ciphers: list[int] = []
    for off in range(pos, pos + cs_len, 2):
        c = struct.unpack("!H", payload[off : off + 2])[0]
        if not _is_grease(c):
            ciphers.append(c)
    pos += cs_len

    if pos + 1 > hs_end:
        return "", ""
    comp_len = payload[pos]
    pos += 1 + comp_len

    sni = ""
    alpn_first = b""
    best_ver = 0
    all_exts: list[int] = []
    sig_algs: list[int] = []

    if pos + 2 <= hs_end:
        ext_total = struct.unpack("!H", payload[pos : pos + 2])[0]
        pos += 2
        ext_end = min(hs_end, pos + ext_total)
        while pos + 4 <= ext_end:
            ext_type, ext_len = struct.unpack("!HH", payload[pos : pos + 4])
            pos += 4
            if pos + ext_len > ext_end:
                break
            edata = payload[pos : pos + ext_len]
            pos += ext_len
            if _is_grease(ext_type):
                continue
            all_exts.append(ext_type)

            if ext_type == 0x0000 and len(edata) >= 5:  # SNI
                ep = 2
                while ep + 3 <= len(edata):
                    ntype = edata[ep]
                    nlen = struct.unpack("!H", edata[ep + 1 : ep + 3])[0]
                    ep += 3
                    if ep + nlen > len(edata):
                        break
                    if ntype == 0 and not sni:
                        sni = edata[ep : ep + nlen].decode("ascii", errors="ignore").strip()
                    ep += nlen
            elif ext_type == 0x0010 and len(edata) >= 3:  # ALPN
                plen = edata[2]
                if 3 + plen <= len(edata) and plen > 0 and not alpn_first:
                    alpn_first = edata[3 : 3 + plen]
            elif ext_type == 0x002B and len(edata) >= 3:  # supported_versions
                vlen = edata[0]
                for voff in range(1, min(len(edata), 1 + vlen) - 1, 2):
                    v = struct.unpack("!H", edata[voff : voff + 2])[0]
                    if not _is_grease(v) and v in _TLS_VER_MAP and v > best_ver:
                        best_ver = v
            elif ext_type == 0x000D and len(edata) >= 4:  # signature_algorithms
                slen = struct.unpack("!H", edata[0:2])[0]
                for soff in range(2, min(len(edata), 2 + slen) - 1, 2):
                    sa = struct.unpack("!H", edata[soff : soff + 2])[0]
                    if not _is_grease(sa):
                        sig_algs.append(sa)

    tls_ver = _TLS_VER_MAP.get(best_ver, _TLS_VER_MAP.get(client_ver, "00"))
    sni_flag = "d" if (sni and not _is_ip_literal(sni)) else "i"
    cipher_cnt = min(len(ciphers), 99)
    ext_cnt = min(len(all_exts), 99)

    if alpn_first:
        b0, b1 = alpn_first[0], alpn_first[-1]
        if b0 < 128 and b1 < 128 and chr(b0).isalnum() and chr(b1).isalnum():
            alpn_str = chr(b0) + chr(b1)
        else:
            alpn_str = f"{b0:02x}"[0] + f"{b1:02x}"[-1]
    else:
        alpn_str = "00"

    ja4_a = f"t{tls_ver}{sni_flag}{cipher_cnt:02d}{ext_cnt:02d}{alpn_str}"
    if ciphers:
        c_csv = ",".join(sorted(f"{c:04x}" for c in ciphers))
        ja4_b = hashlib.sha256(c_csv.encode("ascii")).hexdigest()[:12]
    else:
        ja4_b = "000000000000"

    ext_hex = sorted(f"{e:04x}" for e in all_exts if e not in (0x0000, 0x0010))
    sig_hex = [f"{s:04x}" for s in sig_algs]
    if not ext_hex and not sig_hex:
        ja4_c = "000000000000"
    elif sig_hex:
        raw_c = f"{','.join(ext_hex)}_{','.join(sig_hex)}"
        ja4_c = hashlib.sha256(raw_c.encode("ascii")).hexdigest()[:12]
    else:
        ja4_c = hashlib.sha256(",".join(ext_hex).encode("ascii")).hexdigest()[:12]

    return sni, f"{ja4_a}_{ja4_b}_{ja4_c}"


def _iter_pcap_tcp_payloads(pcap_path: Path):
    """Yield `(ts, src_ip, sport, dst_ip, dport, payload_bytes)` from Ethernet, Linux SLL, or SLL2 PCAPs."""
    with pcap_path.open("rb") as fh:
        ghdr = fh.read(24)
        if len(ghdr) < 24:
            return
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
            return
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
            pay_off = tcp_off + tcp_hl
            pay_len = max(0, min(len(pkt) - pay_off, tot_len - ihl - tcp_hl))
            if pay_len <= 0:
                continue
            ts = ts_sec + ts_sub / ts_div
            src = socket.inet_ntoa(pkt[l3_off + 12 : l3_off + 16])
            dst = socket.inet_ntoa(pkt[l3_off + 16 : l3_off + 20])
            yield ts, src, sport, dst, dport, pkt[pay_off : pay_off + pay_len]


_HTTP_METHODS: frozenset[bytes] = frozenset(
    {b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE"}
)


def parse_http_request_ja4h(payload: bytes) -> tuple[str, str, str]:
    """Compute spec-compliant FoxIO JA4H (`{m2}{v2}{c|n}{r|n}{hc:02d}{lang4}_{b}_{c}_{d}`) from an HTTP/1.x request.

    Returns `(method, uri, ja4h)` or `("", "", "")` if `payload` is not an HTTP/1.x request header block.
    """
    hdr_end = payload.find(b"\r\n\r\n")
    if hdr_end == -1:
        return "", "", ""
    hdr_blob = payload[:hdr_end]

    lines = hdr_blob.split(b"\r\n")
    if not lines:
        return "", "", ""
    parts = lines[0].split(b" ")
    if len(parts) < 3 or parts[0] not in _HTTP_METHODS or not parts[2].startswith(b"HTTP/"):
        return "", "", ""

    method = parts[0].decode("ascii", errors="ignore").upper()
    uri = parts[1].decode("utf-8", errors="ignore")
    ver_raw = parts[2][5:].decode("ascii", errors="ignore")
    ver2 = ver_raw.replace(".", "")[:2]
    if len(ver2) != 2 or not ver2.isdigit():
        ver2 = "11"

    has_cookie = False
    has_referer = False
    hdr_names: list[str] = []
    lang_raw = ""
    cookie_pairs: list[tuple[str, str]] = []

    for hline in lines[1:]:
        if b":" not in hline:
            continue
        raw_k, raw_v = hline.split(b":", 1)
        k = raw_k.decode("latin-1", errors="ignore").strip()
        v = raw_v.decode("latin-1", errors="ignore").strip()
        kl = k.lower()
        if not kl:
            continue
        if kl == "cookie":
            has_cookie = True
            for item in v.split(";"):
                item = item.strip()
                if not item:
                    continue
                if "=" in item:
                    ck, cv = item.split("=", 1)
                    cookie_pairs.append((ck.strip(), cv.strip()))
                else:
                    cookie_pairs.append((item, ""))
            continue
        if kl == "referer":
            has_referer = True
            continue
        if kl == "accept-language" and not lang_raw:
            lang_raw = v
        hdr_names.append(k)

    # FoxIO JA4H lang: first 4 lowercase alphanumeric chars of primary Accept-Language token, padded with '0'
    lang_primary = lang_raw.split(",", 1)[0].split(";", 1)[0]
    lang_alnum = "".join(ch for ch in lang_primary.lower() if ch.isalnum())
    lang4 = (lang_alnum[:4]).ljust(4, "0") if lang_alnum else "0000"

    m2 = method.lower()[:2].ljust(2, "x")
    c_flag = "c" if has_cookie else "n"
    r_flag = "r" if has_referer else "n"
    hc = min(len(hdr_names), 99)
    ja4h_a = f"{m2}{ver2}{c_flag}{r_flag}{hc:02d}{lang4}"

    if hdr_names:
        ja4h_b = hashlib.sha256(",".join(hdr_names).encode("latin-1")).hexdigest()[:12]
    else:
        ja4h_b = "000000000000"

    if cookie_pairs:
        c_names = sorted(ck for ck, _ in cookie_pairs)
        c_full = sorted(f"{ck}={cv}" if cv != "" else ck for ck, cv in cookie_pairs)
        ja4h_c = hashlib.sha256(",".join(c_names).encode("latin-1")).hexdigest()[:12]
        ja4h_d = hashlib.sha256(",".join(c_full).encode("latin-1")).hexdigest()[:12]
    else:
        ja4h_c = "000000000000"
        ja4h_d = "000000000000"

    return method, uri, f"{ja4h_a}_{ja4h_b}_{ja4h_c}_{ja4h_d}"


def extract_pcap_http_ja4h(pcap_path: Path) -> dict[tuple[str, int, str, int], list[tuple[str, str, str]]]:
    """Extract wire-computed `(method, uri, foxio_ja4h)` requests per 4-tuple directly from a PCAP."""
    out: dict[tuple[str, int, str, int], list[tuple[str, str, str]]] = {}
    for _, src, sport, dst, dport, payload in _iter_pcap_tcp_payloads(pcap_path):
        if len(payload) < 16 or payload[0] in (0x14, 0x15, 0x16, 0x17):
            continue
        method, uri, ja4h = parse_http_request_ja4h(payload)
        if ja4h:
            out.setdefault((src, sport, dst, dport), []).append((method, uri, ja4h))
    return out


def extract_pcap_tls_ja4(
    pcap_path: Path,
    *,
    extra_ports: set[int] | None = None,
) -> dict[tuple[str, int, str, int], tuple[str, str]]:
    """Extract wire-computed `(sni, foxio_ja4)` per 4-tuple `(src, sport, dst, dport)` directly from a PCAP."""
    tracked_ports = set(TLS_LLM_PORTS) | (extra_ports or set())
    buffers: dict[tuple[str, int, str, int], bytearray] = {}
    resolved: dict[tuple[str, int, str, int], tuple[str, str]] = {}

    for _, src, sport, dst, dport, payload in _iter_pcap_tcp_payloads(pcap_path):
        if dport not in tracked_ports or sport in tracked_ports:
            continue
        key = (src, sport, dst, dport)
        if key in resolved:
            continue
        buf = buffers.setdefault(key, bytearray())
        if len(buf) >= 4096:
            continue
        buf.extend(payload[: 4096 - len(buf)])
        if len(buf) >= 48 and buf[0] == 0x16 and buf[1] == 0x03 and buf[5] == 0x01:
            sni, ja4 = parse_tls_client_hello_ja4(bytes(buf))
            if ja4:
                resolved[key] = (sni, ja4)
                buffers.pop(key, None)
    return resolved

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
    ssl_by_tuple: dict[tuple[str, int, str, int], tuple[str, str]] | None = None,
    http_ja4h_by_tuple: dict[tuple[str, int, str, int], list[tuple[str, str, str]]] | None = None,
    skip_uids: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Convert Zeek JSONL (`conn`, `http`, or `ssl`) into normalized artex-hunt JSONL dicts."""
    out: list[dict[str, Any]] = []
    http_ja4h_cursors: dict[tuple[str, int, str, int], int] = {}
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
        orig_p = rec.get("id.orig_p")
        resp_h = rec.get("id.resp_h", "")
        port = rec.get("id.resp_p")
        sni_join, ja4_join = (ssl_by_uid.get(uid, ("", "")) if ssl_by_uid and uid else ("", ""))
        if ssl_by_tuple and orig_p is not None and port is not None and resp_h:
            t_sni, t_ja4 = ssl_by_tuple.get((str(src), int(orig_p), str(resp_h), int(port)), ("", ""))
            sni_join = sni_join or t_sni
            ja4_join = ja4_join or t_ja4
        dst = str(rec.get("host") or rec.get("server_name") or sni_join or resp_h)
        if kind == "http":
            if dst.startswith("[") and "]" in dst:
                dst = dst[1 : dst.index("]")]
            elif dst.count(":") == 1 and dst.rsplit(":", 1)[1].isdigit():
                dst = dst.rsplit(":", 1)[0]

        if kind == "http":
            ja4h_val = str(rec.get("ja4h") or "")
            if not ja4h_val and http_ja4h_by_tuple and orig_p is not None and port is not None and resp_h:
                tkey = (str(src), int(orig_p), str(resp_h), int(port))
                candidates_h = http_ja4h_by_tuple.get(tkey)
                if candidates_h:
                    cur_i = http_ja4h_cursors.get(tkey, 0)
                    rec_m = str(rec.get("method") or "").upper()
                    rec_u = str(rec.get("uri") or "")
                    matched_j = ""
                    for idx_h in range(cur_i, len(candidates_h)):
                        cm, cu, cj = candidates_h[idx_h]
                        if (not rec_m or cm == rec_m) and (not rec_u or cu == rec_u):
                            matched_j = cj
                            http_ja4h_cursors[tkey] = idx_h + 1
                            break
                    if not matched_j and cur_i < len(candidates_h):
                        matched_j = candidates_h[cur_i][2]
                        http_ja4h_cursors[tkey] = cur_i + 1
                    ja4h_val = matched_j
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
                    "ja4h": ja4h_val,
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
                    "ja4": rec.get("ja4") or ja4_join,
                    "action": "zeek_ssl",
                }
            )
        elif kind == "dns":
            # Skip local multicast/broadcast discovery (mDNS UDP/5353, LLMNR UDP/5355)
            resp_low = str(resp_h).lower()
            if port in (5353, 5355) or resp_low.startswith(("224.0.0.", "239.255.255.", "ff0")):
                continue
            qname = str(rec.get("query") or resp_h)
            qtype = str(rec.get("qtype_name") or "A")
            out.append(
                {
                    "timestamp": ts,
                    "source_host": src,
                    "actor": src,
                    "event_type": "dns",
                    "surface": "network",
                    "appliance": "zeek_dns",
                    "dest_host": qname,
                    "dest_port": port or 53,
                    "action": f"dns_{qtype.lower()}",
                }
            )
        else:  # conn.log
            # Skip local link-layer / IPv6 router-solicitation / MLD multicast discovery chatter
            resp_low = str(resp_h).lower()
            if resp_low.startswith(("224.0.0.", "239.255.255.", "ff0")):
                continue
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
            {"epoch": epoch_s, "args": {}, "exe": "", "comm": "", "auid": "", "uid": "unknown", "pid": "", "ppid": "", "success": ""},
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
                elif k == "auid":
                    entry["auid"] = val
                elif k == "uid" and entry["uid"] == "unknown":
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
        actor_uid = g["auid"] if g["auid"] not in {"", "4294967295", "-1", "unset"} else g["uid"]
        events.append(
            {
                "timestamp": _iso_from_epoch(g["epoch"]),
                "source_host": hostname,
                "actor": f"uid:{actor_uid}",
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

    for ts, src, sport, dst, dport, payload in _iter_pcap_tcp_payloads(pcap_path):
        pay_len = len(payload)
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
                bursts[-1][4].append((ts, nbytes))
            else:
                bursts.append([ts, direction, ts, nbytes, [(ts, nbytes)]])

        turns: list[tuple[float, float, int, float, float, int]] = []
        i = 0
        while i + 1 < len(bursts):
            if bursts[i][1] == "OUT" and bursts[i + 1][1] == "IN":
                o_s, _, o_e, o_b, _ = bursts[i]
                i_s, _, i_e, i_b, in_pkts = bursts[i + 1]
                # RFC 8446 §4.6.1 TLS 1.3 NewSessionTicket / HTTP/2 SETTINGS ACK:
                # Servers often emit 1-2 small (<=350B) post-handshake tickets <=50ms after Turn 1's request,
                # followed by the real LLM inference pause (>=0.15s) before the actual HTTP response arrives.
                if (i_s - o_e) < 0.05 and len(in_pkts) >= 2:
                    lead_bytes = 0
                    for k in range(len(in_pkts) - 1):
                        lead_bytes += in_pkts[k][1]
                        if lead_bytes <= 768 and (in_pkts[k + 1][0] - in_pkts[k][0]) >= 0.15:
                            i_s = in_pkts[k + 1][0]
                            i_b = max(0, i_b - lead_bytes)
                            break
                if o_b >= 1000 and i_b >= 400:
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
    dns_uids: set[str] = set()
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

    dns_path = input_dir / "dns.log"
    if dns_path.is_file():
        for raw in dns_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict) and rec.get("uid"):
                dns_uids.add(str(rec["uid"]))

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

    if pcap_path is not None:
        if not pcap_path.is_file():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
        pcaps_to_scan = [pcap_path]
    else:
        pcaps_to_scan = sorted(input_dir.glob("*.pcap"))

    # Enrich ssl_by_tuple with real wire-computed FoxIO JA4 and HTTP requests with FoxIO JA4H from PCAPs
    extra_ports = {rp for _, _, _, rp in ssl_by_tuple}
    http_ja4h_by_tuple: dict[tuple[str, int, str, int], list[tuple[str, str, str]]] = {}
    for pfile in pcaps_to_scan:
        for tkey, (psni, pja4) in extract_pcap_tls_ja4(pfile, extra_ports=extra_ports).items():
            prev_tsni, prev_tja4 = ssl_by_tuple.get(tkey, ("", ""))
            ssl_by_tuple[tkey] = (prev_tsni or psni, prev_tja4 or pja4)
        for hkey, hlist in extract_pcap_http_ja4h(pfile).items():
            http_ja4h_by_tuple.setdefault(hkey, []).extend(hlist)

    for name, kind, skips in (
        # Avoid double-counting connections: HTTP connections use rich http.log rows, DNS uses dns.log;
        # TLS/raw connections use conn.log rows enriched with ssl.log + PCAP-computed FoxIO JA4.
        ("conn.log", "conn", http_uids | dns_uids),
        ("http.log", "http", None),
        ("dns.log", "dns", None),
        ("ssl.log", "ssl", conn_uids),
    ):
        p = input_dir / name
        if p.is_file():
            all_events.extend(
                convert_zeek_json_lines(
                    p.read_text(encoding="utf-8", errors="ignore").splitlines(),
                    kind,
                    ssl_by_uid=ssl_by_uid if kind == "conn" else None,
                    ssl_by_tuple=ssl_by_tuple if kind in ("conn", "ssl") else None,
                    http_ja4h_by_tuple=http_ja4h_by_tuple if kind == "http" else None,
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
