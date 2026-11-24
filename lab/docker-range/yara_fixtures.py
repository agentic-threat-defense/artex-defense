"""Generate harmless synthetic binary/text fixtures to runtime-test YARA rules with real `yara` binary."""

from __future__ import annotations

import struct
import sys
from pathlib import Path


def make_minimal_pe(payload: bytes) -> bytes:
    """Build a tiny, non-executable structural PE header so YARA's `pe` module parses 1 section cleanly."""
    buf = bytearray(1024 + len(payload))
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)  # e_lfanew
    buf[0x80:0x84] = b"PE\x00\x00"
    # COFF FileHeader (20 bytes at 0x84): Machine=x64, NumberOfSections=1, SizeOfOptionalHeader=0xF0
    struct.pack_into("<HHIIIHH", buf, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x0022)
    # OptionalHeader PE32+ magic (0x20B) at 0x98
    struct.pack_into("<H", buf, 0x98, 0x020B)
    # Section header (40 bytes at 0x188)
    buf[0x188:0x190] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", buf, 0x190, len(payload), 0x1000, len(payload), 0x400)
    buf[0x400 : 0x400 + len(payload)] = payload
    return bytes(buf)


def main(out_dir: Path) -> None:
    benign_dir = out_dir / "benign"
    seeded_dir = out_dir / "seeded"
    benign_dir.mkdir(parents=True, exist_ok=True)
    seeded_dir.mkdir(parents=True, exist_ok=True)

    # BENIGN FIXTURES (MUST produce 0 YARA hits across all local rules!)
    # 1. Benign Go ELF binary containing AWS Step Functions `StartExecution`, SQL `planner`, and `LUCKY`
    (benign_dir / "benign_go_planner.elf").write_bytes(
        b"\x7fELF" + b"\x00" * 60 + b"runtime.main\x00StartExecution\x00QueryPlanner\x00LUCKY\x00"
    )
    # 2. Benign CTI report mentioning BLOODALCHEMY, graphics-hook-filter64.dll, and Agent Security Workbench
    (benign_dir / "benign_cti_report.txt").write_text(
        "Threat Intelligence Summary: BLOODALCHEMY uses graphics-hook-filter64.dll and Agent Security Workbench.\n",
        encoding="utf-8",
    )
    # 3. Benign CTI PDF & HTML reports quoting artex.yaml, artex_config.json, and ARTEX_WRITE_PROBE (must NOT trigger Path C)
    (benign_dir / "benign_cti_report.pdf").write_bytes(
        b"%PDF-1.7\nThreat Report: artex.yaml artex_config.json exploration_nodes prompt_templates port: 8787\n"
    )
    (benign_dir / "benign_cti_blog.html").write_text(
        "<!DOCTYPE html><html><body>Blog discussing artex.yaml, artex_config.json, exploration_nodes, and ARTEX_WRITE_PROBE.</body></html>\n",
        encoding="utf-8",
    )
    # 4. Benign unsigned PE using /Inform/logger/ + Windows Internet Settings registry path (must NOT trigger Retrohunt Path A)
    (benign_dir / "benign_unsigned_logger.pe").write_bytes(
        make_minimal_pe(
            b"/Inform/logger/\x00SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\x00" + b"\x00" * 256
        )
    )
    # 5. Benign generic mitmproxy setup doc & CTI PDF/HTML quoting BOTH mitmproxy-ca-cert.pem + traffic/_index/index.sqlite (must NOT match!)
    (benign_dir / "benign_generic_mitmproxy.txt").write_text(
        "Install ~/.mitmproxy/mitmproxy-ca-cert.pem into your browser trust store for local debugging.\n",
        encoding="utf-8",
    )
    (benign_dir / "benign_cti_mitm_pair.pdf").write_bytes(
        b"%PDF-1.7\nCTI Report: ARTEX uses mitmproxy-ca-cert.pem and traffic/_index/index.sqlite for traffic capture.\n"
    )
    (benign_dir / "benign_cti_mitm_pair.html").write_text(
        "<!DOCTYPE html><html><body>Analysis of mitmproxy-ca-cert.pem and traffic/_index/index.sqlite in ARTEX.</body></html>\n",
        encoding="utf-8",
    )

    # SEEDED FIXTURES (MUST match their expected YARA rules!)
    # 1. Seeded Go ELF with ScopeWeaver + :8787
    (seeded_dir / "seeded_scopeweaver.elf").write_bytes(
        b"\x7fELF" + b"\x00" * 60 + b"runtime.main\x00ScopeWeaver\x00:8787\x00" + b"\x00" * 10240
    )
    # 2. Seeded stripped Go ELF (`-ldflags="-s -w"`, NO runtime.main — uses Go buildinfo header!)
    (seeded_dir / "seeded_stripped_go_scopeweaver.elf").write_bytes(
        b"\x7fELF" + b"\x00" * 60 + b"\xff Go buildinf:\x00ScopeWeaver\x00:8787\x00" + b"\x00" * 10240
    )
    # 3. Seeded Universal/Fat Mach-O (`0xCAFEBABE` -> YARA `0xBEBAFECA`) with CyberStrikeAI
    (seeded_dir / "seeded_cyberstrikeai_universal.macho").write_bytes(
        b"\xca\xfe\xba\xbe" + b"\x00" * 60 + b"CyberStrikeAI\x00" + b"\x00" * 10240
    )
    # 4. Seeded <1KB artex.yaml config (validates Retrohunt Path C allows <1KB configs paired with config keys!)
    (seeded_dir / "seeded_small_config.txt").write_text("config: artex.yaml\nport: 8787\n", encoding="utf-8")
    # 5. Seeded unsigned PE with BLOODALCHEMY graphics-hook-filter64.dll (validates Retrohunt Path A `pe.is_pe`!)
    (seeded_dir / "seeded_bloodalchemy.pe").write_bytes(
        make_minimal_pe(b"graphics-hook-filter64.dll\x00/Inform/logger/\x00" + b"\x00" * 256)
    )
    # 6. Seeded de-branded / white-labeled Go ELF with ZERO ARTEX brand strings (ONLY mitmproxy CA + SQLite index pair!)
    (seeded_dir / "seeded_debranded_artex_fork.elf").write_bytes(
        b"\x7fELF"
        + b"\x00" * 60
        + b"traffic/_ca/mitmproxy-ca-cert.pem\x00traffic/_index/index.sqlite\x00"
        + b"\x00" * 10240
    )
    # 7. Seeded synthetic i18n source tarball with 512B POSIX header + embedded Next.js `<html` + recording-proxy pair
    tar_hdr = b"web/src/app/(main)/function/workspace/page.tsx".ljust(512, b"\x00")
    (seeded_dir / "seeded_artex_i18n_tarball.tar").write_bytes(
        tar_hdr
        + b'<html lang="en"><body>Workspace</body></html>\x00'
        + b"traffic/_ca/mitmproxy-ca-cert.pem\x00"
        + b"traffic/_index/index.sqlite\x00"
        + b"\x00" * 512
    )


if __name__ == "__main__":
    main(Path(sys.argv[1]))
