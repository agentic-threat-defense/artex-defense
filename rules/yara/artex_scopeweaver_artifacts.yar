rule ARTEX_ScopeWeaver_Framework_Artifacts
{
    meta:
        description = "Detects Go binaries, harness artifacts, or HTML console assets referencing ARTEX, ScopeWeaver, AntiFox, Pojun, FORANG, or norma agentic offensive frameworks"
        author = "ARTEX Defensive Research Workbench"
        date = "2026-11-22"
        tlp = "CLEAR"
        mitre_attack = "T1588.002"

    strings:
        // High-specificity Go module, fork, and harness anchors (no bare 4-5 char substring traps)
        $mod_artex = "github.com/Autumn-27/artex" nocase ascii wide
        $mod_norma = "github.com/Autumn-27/norma" nocase ascii wide
        $name_enrich = "artex-enrich/1.0" ascii wide
        $name_readonly = "artex-readonly/1.0" ascii wide
        $name_worker = "ARTEX-worker/1.0" ascii wide
        $name_selfupd = "artex-selfupdate" ascii wide
        $name_verify = "ArtExVerify/1.0" ascii wide
        $name_probe = "ArtexProbe" nocase ascii wide
        $name_scope = "ScopeWeaver" nocase ascii wide
        $name_antifox = "AntiFox" nocase ascii wide
        $name_pojun = "Pojun" ascii wide
        $name_forang = "FORANG" ascii wide
        $name_scofix = "sco-fix2" nocase ascii wide
        $name_artex_mx = "ARTEX MX" ascii wide
        $name_guanlan = "Guanlan SEC" nocase ascii wide
        $name_norma = "norma/0." ascii wide
        $name_norma_agent = "norma-agent" nocase ascii wide
        $name_worker_chat = "ARTEX_WORKER_CHAT" ascii wide
        $name_shim = "xcai-effort-shim.py" ascii wide
        $path_stage = "artx5v" nocase ascii wide
        $port_8787 = ":8787" ascii wide
        $port_8788 = ":8788" ascii wide
        $port_8790 = ":8790" ascii wide
        $port_8890 = ":8890" ascii wide
        $console_zh = { E8 87 AA E4 B8 BB E6 B8 97 E9 80 8F E6 B5 8B E8 AF 95 E6 8E A7 E5 88 B6 E5 8F B0 }
        $console_title = "<title" nocase ascii
        $next_static = "_next/static" ascii
        $go_marker = "runtime.main" ascii

    condition:
        filesize < 50MB and (
            // 1. Compiled Go PE / ELF / Mach-O framework binary with high-specificity anchor + default port
            (
                (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F or uint32(0) == 0xFEEDFACF or uint32(0) == 0xCFFAEDFE) and
                $go_marker and (
                    any of ($mod_artex, $mod_norma, $name_enrich, $name_readonly, $name_worker, $name_selfupd, $name_verify, $name_worker_chat) or
                    (any of ($name_probe, $name_scope, $name_antifox, $name_pojun, $name_forang, $name_scofix, $name_artex_mx, $name_guanlan, $name_norma, $name_norma_agent, $path_stage) and any of ($port_8787, $port_8788, $port_8790, $port_8890))
                )
            )
            or
            // 2. Binary or Next.js/HTML console containing the Chinese ARTEX autonomous pentest console title
            (
                $console_zh and (
                    uint16(0) == 0x5A4D or uint32(0) == 0x464C457F or uint32(0) == 0xFEEDFACF or uint32(0) == 0xCFFAEDFE or
                    any of ($console_title, $next_static, $port_8787, $port_8790)
                )
            )
            or
            // 3. Explicit staging path + console port, or explicit shim/module anchor in scripts/configs
            ($path_stage and any of ($port_8787, $port_8788, $port_8790, $port_8890))
            or any of ($mod_artex, $mod_norma, $name_shim)
        )
}
