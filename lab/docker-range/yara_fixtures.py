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

    # SEEDED FIXTURES (MUST match their expected YARA rules!)
    # 1. Seeded Go ELF with ScopeWeaver + :8787
    (seeded_dir / "seeded_scopeweaver.elf").write_bytes(
        b"\x7fELF" + b"\x00" * 60 + b"runtime.main\x00ScopeWeaver\x00:8787\x00" + b"\x00" * 10240
    )
    # 2. Seeded <1KB artex.yaml config (validates Retrohunt Path C allows <1KB configs!)
    (seeded_dir / "seeded_small_config.txt").write_text("config: artex.yaml\nport: 8787\n", encoding="utf-8")
    # 3. Seeded unsigned PE with BLOODALCHEMY graphics-hook-filter64.dll (validates Retrohunt Path A `pe.is_pe`!)
    (seeded_dir / "seeded_bloodalchemy.pe").write_bytes(
        make_minimal_pe(b"graphics-hook-filter64.dll\x00/Inform/logger/\x00" + b"\x00" * 256)
    )


if __name__ == "__main__":
    main(Path(sys.argv[1]))
