"""Strictly read-only forensic host triage utility for ARTEX operator / transit host artifacts.

Implements the operator/forensic checks documented in the ARTEX defense guide
(`artex-global/docs/defense-en.md`), Theori AIPT detections, and CrowdStrike/Unit 42
reporting — without executing untrusted binaries or modifying host state.

Works against both a live Linux host (default `/proc` & standard paths) and an offline
mounted forensic image or captured triage bundle (`--root`, `--proc-root`, `--pg-schema`).
"""

from __future__ import annotations

import os
import re
import socket
import struct
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Default ARTEX / ScopeWeaver / recording proxy ports
ARTEX_LISTEN_PORTS: dict[int, tuple[str, str]] = {
    8787: ("high", "Default ARTEX web management console HTTP port (:8787)"),
    8788: ("high", "Default ARTEX loopback recording MITM proxy port (127.0.0.1:8788)"),
    8790: ("high", "Default ARTEX / ScopeWeaver worker API port (:8790)"),
    8890: ("high", "Observed alternate ARTEX console listener port (:8890, ThreatDefence)"),
}
SUB2API_COLOCATED_PORT = 8080

PROXY_ENV_KEYS: frozenset[str] = frozenset({"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"})
CA_ENV_KEYS: frozenset[str] = frozenset(
    {
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS",
        "CURL_CA_BUNDLE",
        "GIT_SSL_CAINFO",
    }
)

CMDLINE_ARTIFACT_RE = re.compile(
    r"((?:^|[/\\\s\"'])artex(?:[-_](?:server|worker|cli|pro|mx|agent|enrich|readonly|audit|pentest|verify|spawn)|(?=$|[\s\"']))|"
    r"scopeweaver|antifox|pojun|forang|sco-fix2|"
    r"tomicdd/artex|congdonglinux/artex|mitmproxy-ca-cert\.pem|graphics-hook-filter64\.dll|"
    r"artex_config\.json|artex\.yaml)",
    re.IGNORECASE,
)
EXACT_CMDLINE_ARTIFACT_RE = re.compile(
    r"(scopeweaver|antifox|pojun|forang|sco-fix2|tomicdd/artex|congdonglinux/artex|"
    r"mitmproxy-ca-cert\.pem|graphics-hook-filter64\.dll|artex_config\.json|artex\.yaml)",
    re.IGNORECASE,
)
BENIGN_DOC_VIEWER_BINS: frozenset[str] = frozenset(
    {"less", "more", "cat", "head", "tail", "grep", "egrep", "fgrep", "rg", "vim", "nvim", "vi", "nano", "code"}
)
BENIGN_DOC_EXT_RE = re.compile(r"\.(?:md|markdown|rst|txt|adoc)(?=$|[\s\"'])", re.IGNORECASE)
CA_CERT_ARTIFACT_RE = re.compile(r"(?:mitmproxy|(?:^|[._\-])artex(?:$|[._\-]))", re.IGNORECASE)
SQL_BLOCK_COMMENT_RE = re.compile(r"/\*[\s\S]*?\*/")
SQL_LINE_COMMENT_RE = re.compile(r"--[^\r\n]*")

TASK_CMD_OUTPUT_RE = re.compile(r"(?:^|[/\\])tasks[/\\]\d+[/\\]i\d+[/\\]cmd-output(?:$|[/\\])", re.IGNORECASE)

EXACT_ARTIFACT_FILENAMES: dict[str, tuple[str, str]] = {
    "mitmproxy-ca-cert.pem": ("high", "ARTEX / mitmproxy TLS interception CA certificate"),
    "artex_config.json": ("critical", "ARTEX configuration artifact"),
    "artex.yaml": ("critical", "ARTEX YAML configuration artifact"),
    "xcai-effort-shim.py": ("critical", "ARTEX Claude Code Router LLM effort-injection proxy shim (Hunt.io)"),
    "graphics-hook-filter64.dll": ("critical", "VAPOR PANDA BLOODALCHEMY sideloaded DLL"),
    "graphics-hook_config.bin": ("critical", "VAPOR PANDA BLOODALCHEMY config binary"),
}

LOG_FORENSIC_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("artex_guard_framing", "critical", re.compile(r"【ARTEX 平台管控·非目标防御】")),
    ("artex_selfupdate_ua", "high", re.compile(r"\bartex-selfupdate\b", re.IGNORECASE)),
    ("artex_session_cookie", "high", re.compile(r"\bartex_token=", re.IGNORECASE)),
    ("artex_probe_marker", "high", re.compile(r"\b(ARTEX_WRITE_PROBE|ARTEX_PERSIST_OK|artex_control_marker)\b")),
]

# Signature ARTEX dual-graph PostgreSQL tables (`exploration_nodes` is the anchor)
ARTEX_PG_ANCHOR_TABLE = "exploration_nodes"
ARTEX_PG_COMPANION_TABLES: frozenset[str] = frozenset({"assets", "companies", "activity", "agent_prompts"})

CA_STORE_RELPATHS: tuple[str, ...] = (
    "etc/ca-certificates/trust-source/anchors",
    "usr/local/share/ca-certificates",
    "etc/pki/ca-trust/source/anchors",
    "etc/ssl/certs",
)
SYSTEMD_UNIT_RELPATHS: tuple[str, ...] = (
    "etc/systemd/system",
    "etc/systemd/user",
)
SYSTEMD_EXECSTART_RE = re.compile(r"^\s*ExecStart\s*=\s*[-+@!:]*\s*(.+)$", re.IGNORECASE)
SYSTEMD_LINE_CONT_RE = re.compile(r"\\\r?\n[ \t]*")
# Case-sensitive `-R` with explicit port-forward bind target (avoids FPs on remote `ssh host "chmod -R / cp -r"`),
# while matching quoted ssh binaries (`"/usr/bin/ssh"`), compact `-fNR8080:127.0.0.1:22`, and `-oRemoteForward=`.
SYSTEMD_SSH_REVERSE_RE = re.compile(
    r"(?:^|[/\s\"'])ssh[\"']?(?=\s|$).*(?:\s-[A-Za-z0-9]*R(?:\s*(?:\[[^\]]+\]:|[A-Za-z0-9_.*-]*:)?\d{2,5}:)|(?:^|[\s\"']|-o\s*)(?i:RemoteForward)(?:\s|=|$))"
)
SYSTEMD_VOLATILE_BIN_RE = re.compile(r"(?:^|[\s\"'=])(?:/tmp/|/var/tmp/|/dev/shm/)", re.IGNORECASE)
# Scope `socks*` strictly to standalone executables/scripts (never `--socks5` CLI flags or `socks5://` proxy URLs)
SYSTEMD_TUNNEL_TOOL_RE = re.compile(
    r"(?:\b(?:chisel|ligolo-agent|scopeweaver|antifox|artex-(?:server|worker|agent)|sshtun\d*)\b|"
    r"(?:^|[\s/\"'])(?:socks(?:5|4|proxy|node|srv)\.(?:py|sh|pl|js|bin|exe)|socks(?:node|srv|proxy)|socks[45])(?=\s|$|[\"']))",
    re.IGNORECASE,
)


@dataclass
class TriageFinding:
    check: str
    severity: str  # critical | high | medium | low
    summary: str
    evidence: str
    path_or_pid: str = ""


@dataclass
class HostTriageReport:
    timestamp_utc: str
    hostname: str
    mode: str
    verdict: str  # clean | suspicious | likely_artex_host
    finding_count: int
    severity_counts: dict[str, int]
    checks_run: list[str]
    findings: list[TriageFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp_utc": self.timestamp_utc,
            "hostname": self.hostname,
            "mode": self.mode,
            "verdict": self.verdict,
            "finding_count": self.finding_count,
            "severity_counts": self.severity_counts,
            "checks_run": self.checks_run,
            "findings": [asdict(f) for f in self.findings],
        }


def _decode_proc_ip(hex_ip: str, ipv6: bool = False) -> str:
    try:
        if not ipv6 and len(hex_ip) == 8:
            packed = struct.pack("<L", int(hex_ip, 16))
            return socket.inet_ntoa(packed)
        if ipv6 and len(hex_ip) == 32:
            # /proc/net/tcp6 stores four 32-bit little-endian words
            words = [struct.pack("<L", int(hex_ip[i : i + 8], 16)) for i in range(0, 32, 8)]
            return socket.inet_ntop(socket.AF_INET6, b"".join(words))
    except Exception:
        pass
    return hex_ip


def _build_inode_pid_map(proc_root: Path) -> dict[str, tuple[str, str]]:
    """Map socket inode -> (pid, cmdline) using strictly read-only /proc traversal."""
    inode_map: dict[str, tuple[str, str]] = {}
    if not proc_root.is_dir():
        return inode_map
    try:
        entries = list(proc_root.iterdir())
    except OSError:
        return inode_map

    for entry in entries:
        if not entry.name.isdigit():
            continue
        fd_dir = entry / "fd"
        if not fd_dir.is_dir():
            continue
        try:
            fds = list(fd_dir.iterdir())
        except OSError:
            continue
        cmd_cached: str | None = None
        for fd in fds:
            try:
                target = os.readlink(fd)
            except OSError:
                continue
            if target.startswith("socket:[") and target.endswith("]"):
                inode = target[8:-1]
                if cmd_cached is None:
                    cmd_cached = _read_proc_cmdline(entry)
                inode_map[inode] = (entry.name, cmd_cached)
    return inode_map


def _read_proc_cmdline(pid_dir: Path) -> str:
    try:
        raw = (pid_dir / "cmdline").read_bytes()
        return raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
    except OSError:
        return ""


def check_listening_ports(proc_root: Path) -> tuple[list[TriageFinding], bool]:
    """Read /proc/net/tcp{,6} (read-only) for listening ARTEX ports (8787, 8788, 8790, co-located 8080)."""
    findings: list[TriageFinding] = []
    saw_sub2api_8080 = False
    inode_map = _build_inode_pid_map(proc_root)
    seen_ports: set[tuple[str, int]] = set()

    for rel, is_v6 in (("net/tcp", False), ("net/tcp6", True)):
        tcp_file = proc_root / rel
        if not tcp_file.is_file():
            continue
        try:
            lines = tcp_file.read_text(encoding="utf-8", errors="replace").splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 10:
                continue
            local_addr_port, state, inode = parts[1], parts[3], parts[9]
            if state != "0A":  # 0A == TCP_LISTEN
                continue
            if ":" not in local_addr_port:
                continue
            hex_ip, hex_port = local_addr_port.split(":", 1)
            try:
                port = int(hex_port, 16)
            except ValueError:
                continue
            ip_str = _decode_proc_ip(hex_ip, ipv6=is_v6)
            if (ip_str, port) in seen_ports:
                continue
            seen_ports.add((ip_str, port))

            if port == SUB2API_COLOCATED_PORT:
                saw_sub2api_8080 = True

            if port in ARTEX_LISTEN_PORTS:
                sev, desc = ARTEX_LISTEN_PORTS[port]
                pid, cmd = inode_map.get(inode, ("unknown", ""))
                ev = f"listen={ip_str}:{port} inode={inode}" + (f" cmd={cmd[:140]}" if cmd else "")
                findings.append(
                    TriageFinding(
                        check="listening_ports",
                        severity=sev,
                        summary=desc,
                        evidence=ev,
                        path_or_pid=f"pid:{pid}" if pid != "unknown" else f"{ip_str}:{port}",
                    )
                )
    return findings, saw_sub2api_8080


def check_proc_proxy_ca_injection(proc_root: Path) -> list[TriageFinding]:
    """Inspect /proc/<pid>/environ and /proc/<pid>/cmdline for ARTEX worker proxy+CA env injection."""
    findings: list[TriageFinding] = []
    if not proc_root.is_dir():
        return findings

    try:
        entries = sorted(proc_root.iterdir(), key=lambda p: p.name)
    except OSError:
        return findings

    self_pid = str(os.getpid())
    for entry in entries:
        if not entry.name.isdigit() or entry.name == self_pid:
            continue

        cmdline = _read_proc_cmdline(entry)
        # Skip our own workbench CLI/pytest processes to prevent self-match FPs
        if "artex-hunt" in cmdline or "artex_defense" in cmdline or "pytest" in cmdline:
            continue

        env_vars: dict[str, str] = {}
        env_path = entry / "environ"
        if env_path.is_file():
            try:
                raw_env = env_path.read_bytes()
                for item in raw_env.split(b"\x00"):
                    if b"=" in item:
                        k, v = item.split(b"=", 1)
                        env_vars[k.decode("utf-8", errors="replace")] = v.decode("utf-8", errors="replace")
            except OSError:
                pass

        proxy_hits = {k: v for k, v in env_vars.items() if k in PROXY_ENV_KEYS and v}
        ca_hits = {
            k: v
            for k, v in env_vars.items()
            if k in CA_ENV_KEYS and ("mitmproxy" in v.lower() or "traffic/_ca" in v.lower() or "artex" in v.lower())
        }

        if proxy_hits and ca_hits:
            has_8788 = any("8788" in v for v in proxy_hits.values())
            findings.append(
                TriageFinding(
                    check="proc_proxy_ca_injection",
                    severity="critical" if has_8788 else "high",
                    summary="Process carries injected HTTP_PROXY + mitmproxy/ARTEX CA trust environment variables",
                    evidence=(
                        f"proxy={proxy_hits} ca={ca_hits}"
                        + (f" cmd={cmdline[:120]}" if cmdline else "")
                    ),
                    path_or_pid=f"pid:{entry.name}",
                )
            )
        elif cmdline and CMDLINE_ARTIFACT_RE.search(cmdline):
            # Ignore workbench repo paths and read-only viewers/editors opening markdown/doc notes
            first_bin = cmdline.split(None, 1)[0].rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
            is_benign_doc_view = (
                first_bin in BENIGN_DOC_VIEWER_BINS
                and not EXACT_CMDLINE_ARTIFACT_RE.search(cmdline)
                and bool(BENIGN_DOC_EXT_RE.search(cmdline))
            )
            if not is_benign_doc_view and not any(benign in cmdline for benign in ("artex-defense", "artex_defense")):
                findings.append(
                    TriageFinding(
                        check="proc_proxy_ca_injection",
                        severity="high",
                        summary="Running process command line matches ARTEX / fork / BLOODALCHEMY indicator",
                        evidence=f"cmd={cmdline[:180]}",
                        path_or_pid=f"pid:{entry.name}",
                    )
                )
    return findings


def check_filesystem_artifacts(
    scan_roots: list[Path],
    *,
    max_depth: int = 6,
    max_files: int = 25000,
    scan_log_contents: bool = True,
) -> list[TriageFinding]:
    """Bounded, symlink-safe, read-only walk for ARTEX spill dirs, jwt.key, mitmproxy CA, and log markers."""
    findings: list[TriageFinding] = []
    seen_evidence: set[str] = set()
    files_visited = 0

    for root in scan_roots:
        if not root.exists():
            continue
        root_depth = len(root.resolve().parts)
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            cur = Path(dirpath)
            depth = len(cur.resolve().parts) - root_depth
            # Skip virtual / workbench-repo directories to keep scans fast and FP-free
            dirnames[:] = [
                d
                for d in dirnames
                if d not in {".git", "node_modules", "__pycache__", ".venv", "artex-defense"}
                and not d.startswith("pytest-of-")
            ]
            if depth >= max_depth:
                dirnames[:] = []

            norm_dir = dirpath.replace("\\", "/")
            if TASK_CMD_OUTPUT_RE.search(norm_dir):
                key = f"cmd_output:{norm_dir}"
                if key not in seen_evidence:
                    seen_evidence.add(key)
                    findings.append(
                        TriageFinding(
                            check="filesystem_artifacts",
                            severity="critical",
                            summary="ARTEX worker command-output spill directory (/tasks/<id>/i<id>/cmd-output/)",
                            evidence=f"dir={norm_dir}",
                            path_or_pid=norm_dir,
                        )
                    )

            if "/artx5v" in norm_dir.lower():
                key = f"artx5v:{norm_dir}"
                if key not in seen_evidence:
                    seen_evidence.add(key)
                    findings.append(
                        TriageFinding(
                            check="filesystem_artifacts",
                            severity="critical",
                            summary="ARTEX Windows staging directory marker (artx5v)",
                            evidence=f"dir={norm_dir}",
                            path_or_pid=norm_dir,
                        )
                    )

            for fname in filenames:
                files_visited += 1
                if files_visited > max_files:
                    return findings

                full_path = cur / fname
                full_norm = str(full_path).replace("\\", "/")
                fname_low = fname.lower()

                if fname_low in EXACT_ARTIFACT_FILENAMES:
                    sev, desc = EXACT_ARTIFACT_FILENAMES[fname_low]
                    findings.append(
                        TriageFinding(
                            check="filesystem_artifacts",
                            severity=sev,
                            summary=desc,
                            evidence=f"file={full_norm}",
                            path_or_pid=full_norm,
                        )
                    )
                elif fname_low == "index.sqlite" and "traffic/_index" in full_norm.lower():
                    findings.append(
                        TriageFinding(
                            check="filesystem_artifacts",
                            severity="critical",
                            summary="ARTEX recording-proxy SQLite traffic index (traffic/_index/index.sqlite)",
                            evidence=f"file={full_norm}",
                            path_or_pid=full_norm,
                        )
                    )
                elif fname_low == "jwt.key" and any(
                    tok in full_norm.lower() for tok in ("artex", "scopeweaver", "antifox", "pojun", "forang")
                ):
                    findings.append(
                        TriageFinding(
                            check="filesystem_artifacts",
                            severity="high",
                            summary="ARTEX / fork JWT signing key artifact (jwt.key)",
                            evidence=f"file={full_norm}",
                            path_or_pid=full_norm,
                        )
                    )

                # Optional bounded read-only scan of small text/log/json files for hard-coded ARTEX audit markers
                if (
                    scan_log_contents
                    and not full_path.is_symlink()
                    and full_path.suffix.lower() in {".log", ".jsonl", ".json", ".txt", ".audit"}
                ):
                    try:
                        if full_path.stat().st_size <= 2 * 1024 * 1024:
                            text = full_path.read_text(encoding="utf-8", errors="ignore")
                            for label, sev, pat in LOG_FORENSIC_PATTERNS:
                                m = pat.search(text)
                                if m:
                                    findings.append(
                                        TriageFinding(
                                            check="audit_and_log_markers",
                                            severity=sev,
                                            summary=f"ARTEX forensic marker ({label}) found in host log/file",
                                            evidence=f"match={m.group(0)} file={full_norm}",
                                            path_or_pid=full_norm,
                                        )
                                    )
                                    break
                    except OSError:
                        pass

    return findings


def check_installed_ca_certs(fs_root: Path) -> list[TriageFinding]:
    """Check system CA trust anchor directories for rogue mitmproxy / ARTEX CA certs."""
    findings: list[TriageFinding] = []
    for rel in CA_STORE_RELPATHS:
        store = fs_root / rel
        if not store.is_dir():
            continue
        try:
            entries = list(store.iterdir())
        except OSError:
            continue
        for item in entries:
            # Inspect symlink names too (Debian/Ubuntu update-ca-certificates & c_rehash populate
            # /etc/ssl/certs with symlinks); Path.iterdir() never follows/reads symlink targets.
            if not item.is_symlink() and not item.is_file():
                continue
            name_low = item.name.lower()
            if CA_CERT_ARTIFACT_RE.search(name_low):
                findings.append(
                    TriageFinding(
                        check="installed_ca_certs",
                        severity="critical",
                        summary="Rogue mitmproxy / ARTEX CA certificate present in system trust store",
                        evidence=f"ca_file={item}",
                        path_or_pid=str(item),
                    )
                )
    return findings


def _pg_has_table_reference(clean_sql: str, table_name: str) -> bool:
    """Match a PostgreSQL table in DDL statements, psql \\dt listings, or bare table-list lines."""
    t = re.escape(table_name)
    ddl_pat = rf"\b(?:create\s+table(?:\s+if\s+not\s+exists)?|alter\s+table(?:\s+only)?|copy|insert\s+into)\s+(?:(?:\"?[a-z_][a-z0-9_$]*\"?\.)?\"?{t}\"?)\b"
    psql_pat = rf"(?:^|\|)\s*(?:[a-z_][a-z0-9_$]*\.)?{t}\s*(?:\||$)"
    return bool(re.search(ddl_pat, clean_sql, re.IGNORECASE) or re.search(psql_pat, clean_sql, re.IGNORECASE | re.MULTILINE))


def check_postgres_dual_graph(pg_schema_file: Path | None) -> list[TriageFinding]:
    """Inspect a read-only PostgreSQL table/schema listing or SQL dump for ARTEX's dual-graph tables."""
    if pg_schema_file is None or not pg_schema_file.is_file():
        return []
    if pg_schema_file.stat().st_size > 10 * 1024 * 1024:
        return []
    raw_text = pg_schema_file.read_text(encoding="utf-8", errors="ignore")
    clean_sql = SQL_LINE_COMMENT_RE.sub("", SQL_BLOCK_COMMENT_RE.sub("", raw_text)).lower()
    has_anchor = _pg_has_table_reference(clean_sql, ARTEX_PG_ANCHOR_TABLE)
    if not has_anchor:
        return []
    companions = sorted(t for t in ARTEX_PG_COMPANION_TABLES if _pg_has_table_reference(clean_sql, t))
    if "agent_prompts" in companions or len(companions) >= 3:
        return [
            TriageFinding(
                check="postgres_dual_graph",
                severity="critical",
                summary="PostgreSQL schema matches ARTEX dual-graph data store (exploration_nodes + companion tables)",
                evidence=f"anchor={ARTEX_PG_ANCHOR_TABLE} companions={companions}",
                path_or_pid=str(pg_schema_file),
            )
        ]
    if len(companions) == 2:
        return [
            TriageFinding(
                check="postgres_dual_graph",
                severity="high",
                summary="PostgreSQL schema contains exploration_nodes with 2 generic companion tables (verify ARTEX dual-graph)",
                evidence=f"anchor={ARTEX_PG_ANCHOR_TABLE} companions={companions}",
                path_or_pid=str(pg_schema_file),
            )
        ]
    return []


def check_systemd_persistence(fs_root: Path) -> list[TriageFinding]:
    """Read-only, symlink-safe scan of custom systemd service units for SSH reverse tunnels or volatile-path staging."""
    findings: list[TriageFinding] = []
    for rel in SYSTEMD_UNIT_RELPATHS:
        unit_dir = fs_root / rel
        if not unit_dir.is_dir():
            continue
        try:
            entries = sorted(unit_dir.iterdir(), key=lambda p: p.name)
        except OSError:
            continue
        for item in entries:
            if item.is_symlink() or not item.is_file() or item.suffix.lower() != ".service":
                continue
            try:
                if item.stat().st_size > 256 * 1024:
                    continue
                text = item.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            unfolded = SYSTEMD_LINE_CONT_RE.sub(" ", text)
            for line in unfolded.splitlines():
                m = SYSTEMD_EXECSTART_RE.match(line)
                if not m:
                    continue
                exec_cmd = m.group(1).strip()
                if SYSTEMD_TUNNEL_TOOL_RE.search(exec_cmd):
                    findings.append(
                        TriageFinding(
                            check="systemd_persistence",
                            severity="critical",
                            summary="Systemd service ExecStart invokes ARTEX/Chisel/Ligolo tunnel or harness binary",
                            evidence=f"unit={item.name} exec={exec_cmd[:160]}",
                            path_or_pid=str(item),
                        )
                    )
                    break
                if SYSTEMD_SSH_REVERSE_RE.search(exec_cmd):
                    findings.append(
                        TriageFinding(
                            check="systemd_persistence",
                            severity="high",
                            summary="Systemd service ExecStart configures persistent SSH reverse port-forwarding (-R)",
                            evidence=f"unit={item.name} exec={exec_cmd[:160]}",
                            path_or_pid=str(item),
                        )
                    )
                    break
                if SYSTEMD_VOLATILE_BIN_RE.search(exec_cmd):
                    findings.append(
                        TriageFinding(
                            check="systemd_persistence",
                            severity="high",
                            summary="Systemd service ExecStart launches binary from volatile staging path (/tmp, /var/tmp, /dev/shm)",
                            evidence=f"unit={item.name} exec={exec_cmd[:160]}",
                            path_or_pid=str(item),
                        )
                    )
                    break
    return findings


def _default_live_scan_specs(max_depth: int) -> list[tuple[Path, int]]:
    """Return bounded high-yield live Linux scan roots with tighter depth on /root and /home."""
    specs: list[tuple[Path, int]] = []
    for path in (Path("/opt"), Path("/srv"), Path("/var/lib"), Path("/tmp")):
        if path.exists():
            specs.append((path, max_depth))
    home_depth = min(max_depth, 4)
    for path in (Path("/root"), Path("/home")):
        if path.exists():
            specs.append((path, home_depth))
    return specs


def run_host_triage(
    *,
    fs_root: str | Path = "/",
    proc_root: str | Path | None = None,
    scan_paths: list[str | Path] | None = None,
    pg_schema_file: str | Path | None = None,
    max_depth: int = 6,
) -> HostTriageReport:
    """Execute all read-only ARTEX operator-host forensic checks and produce a structured report."""
    root_path = Path(fs_root)
    proc_path = Path(proc_root) if proc_root is not None else (root_path / "proc")
    is_offline = str(root_path) != "/"

    if scan_paths is not None:
        scan_specs: list[tuple[Path, int]] = [(Path(p), max_depth) for p in scan_paths]
    elif is_offline:
        scan_specs = [(root_path, max_depth)]
    else:
        scan_specs = _default_live_scan_specs(max_depth)

    checks_run = [
        "listening_ports",
        "proc_proxy_ca_injection",
        "filesystem_artifacts",
        "installed_ca_certs",
        "systemd_persistence",
    ]
    findings: list[TriageFinding] = []

    port_findings, saw_8080 = check_listening_ports(proc_path)
    findings.extend(port_findings)
    findings.extend(check_proc_proxy_ca_injection(proc_path))
    for scan_root, depth_limit in scan_specs:
        findings.extend(check_filesystem_artifacts([scan_root], max_depth=depth_limit))
    findings.extend(check_installed_ca_certs(root_path))
    findings.extend(check_systemd_persistence(root_path))

    if pg_schema_file is not None:
        checks_run.append("postgres_dual_graph")
        findings.extend(check_postgres_dual_graph(Path(pg_schema_file)))

    # Only flag port 8080 (Unit 42 Sub2API co-location) if another ARTEX signal already fired
    if saw_8080 and findings:
        findings.append(
            TriageFinding(
                check="listening_ports",
                severity="medium",
                summary="Co-located TCP :8080 listener observed alongside ARTEX host artifacts (check for Sub2API gateway)",
                evidence="listen_port=8080 co_located_with_artex_signals=true",
                path_or_pid="port:8080",
            )
        )

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        if f.severity in sev_counts:
            sev_counts[f.severity] += 1

    if sev_counts["critical"] >= 1 or (sev_counts["high"] >= 2):
        verdict = "likely_artex_host"
    elif findings:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return HostTriageReport(
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        hostname=socket.gethostname() if not is_offline else f"offline:{root_path.name}",
        mode="offline_image" if is_offline else "live_readonly",
        verdict=verdict,
        finding_count=len(findings),
        severity_counts=sev_counts,
        checks_run=checks_run,
        findings=findings,
    )
