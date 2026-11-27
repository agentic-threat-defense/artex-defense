rule ARTEX_ScopeWeaver_Framework_Artifacts
{
    meta:
        description = "Detects Go/stripped binaries, harness artifacts, CyberStrikeAI/AdaptixC2/Wisp-C2 tooling, or HTML console assets referencing ARTEX, ScopeWeaver, AntiFox, Pojun, FORANG, or norma agentic offensive frameworks"
        author = "ARTEX Defensive Research Workbench"
        date = "2026-11-26"
        reference = "https://github.com/Athar-HQ/Athar (DRL 1.1: Gameel Ali & Florian Roth — Korean/English console titles, meta tag, and /function/tasks/ redirect stub)"
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
        $name_csai = "CyberStrikeAI" nocase ascii wide
        $name_csai_bin = "cyberstrikeai-" nocase ascii wide
        $name_exploit_agent = "exploit_agent" ascii wide
        $name_adaptix = "adaptixc2" nocase ascii wide
        $name_wisp = "wisp-c2" nocase ascii wide
        $path_stage = "artx5v" nocase ascii wide
        $port_8787 = ":8787" ascii wide
        $port_8788 = ":8788" ascii wide
        $port_8790 = ":8790" ascii wide
        $port_8890 = ":8890" ascii wide
        $canary_write = "ARTEX_WRITE_PROBE" ascii wide
        $canary_persist = "ARTEX_PERSIST_OK" ascii wide
        // UTF-8: 自主渗透测试控制台 (Chinese ARTEX console title)
        $console_zh = { E8 87 AA E4 B8 BB E6 B8 97 E9 80 8F E6 B5 8B E8 AF 95 E6 8E A7 E5 88 B6 E5 8F B0 }
        // UTF-8: 자율 침투 테스트 콘솔 (Korean ARTEX/rebrand console title — Athar / Gameel Ali)
        $console_ko = { EC 9E 90 EC 9C A8 20 EC B9 A8 ED 88 AC 20 ED 85 8C EC 8A A4 ED 8A B8 20 EC BD 98 EC 86 94 }
        // English ARTEX/rebrand console title — Athar / Gameel Ali (tag-scoped for HTML to avoid CTI blog body-prose FPs)
        $console_en = "Autonomous Penetration Testing Console" nocase ascii wide
        $console_en_title = /<title[^>]*>[^<]{0,120}Autonomous Penetration Testing Console[^<]{0,120}<\/title>/i ascii
        // UTF-8: LLM 驱动的自主渗透测试系统控制台 (Chinese meta tag variant — Athar / Gameel Ali)
        $meta_zh = { 4C 4C 4D 20 E9 A9 B1 E5 8A A8 E7 9A 84 E8 87 AA E4 B8 BB E6 B8 97 E9 80 8F E6 B5 8B E8 AF 95 E7 B3 BB E7 BB 9F E6 8E A7 E5 88 B6 E5 8F B0 }
        // UTF-8: 【ARTEX 平台管控·非目标防御】
        $audit_zh = { E3 80 90 41 52 54 45 58 20 E5 B9 B3 E5 8F B0 E7 AE A1 E6 8E A7 C2 B7 E9 9D 9E E7 9B AE E6 A0 87 E9 98 B2 E5 BE A1 E3 80 91 }
        $console_title = "<title" nocase ascii
        $meta_desc = "<meta" nocase ascii
        // ARTEX landing-page redirect stub (`<title>artex</title>` + `url=/function/tasks/`) — Athar v0.5.0 / Florian Roth (DRL 1.1)
        $title_artex_exact = "<title>artex</title>" nocase ascii
        $redir_tasks = "url=/function/tasks/" nocase ascii
        $next_static = "_next/static" ascii
        $doc_html = "<html" nocase ascii
        $doc_doctype = "<!doctype" nocase ascii
        // Multi-marker Go runtime anchors (survives `-ldflags="-s -w"` and garble symbol stripping)
        $go_buildinf = { FF 20 47 6F 20 62 75 69 6C 64 69 6E 66 3A }
        $go_ver = "go1.2" ascii
        $go_main = "runtime.main" ascii
        // Fork-resilient ARTEX recording-proxy CA + SQLite traffic index pair (survives brand-stripping & i18n forks)
        $mitm_ca = "mitmproxy-ca-cert.pem" ascii wide
        $traffic_idx = "traffic/_index/index.sqlite" ascii wide

    condition:
        filesize < 50MB and (
            // 1. Compiled PE / ELF / Mach-O / Universal Fat Mach-O framework binary (handles stripped Go & de-branded binaries)
            (
                (
                    uint16(0) == 0x5A4D or
                    uint32(0) == 0x464C457F or
                    uint32(0) == 0xFEEDFACF or
                    uint32(0) == 0xCFFAEDFE or
                    uint32(0) == 0xBEBAFECA
                ) and (
                    any of ($mod_artex, $mod_norma, $name_enrich, $name_readonly, $name_worker, $name_selfupd, $name_verify, $name_worker_chat, $name_csai, $name_csai_bin, $name_adaptix, $name_wisp) or
                    ($mitm_ca and $traffic_idx) or
                    (
                        any of ($go_*) and
                        any of ($name_probe, $name_scope, $name_antifox, $name_pojun, $name_forang, $name_scofix, $name_artex_mx, $name_guanlan, $name_norma, $name_norma_agent, $path_stage, $name_exploit_agent) and
                        any of ($port_8787, $port_8788, $port_8790, $port_8890)
                    )
                )
            )
            or
            // 2. Binary or Next.js/HTML console containing the Chinese, Korean, or tag-scoped English ARTEX autonomous pentest console title / meta tag
            (
                (
                    any of ($console_zh, $console_ko, $meta_zh) and (
                        uint16(0) == 0x5A4D or uint32(0) == 0x464C457F or uint32(0) == 0xFEEDFACF or uint32(0) == 0xCFFAEDFE or uint32(0) == 0xBEBAFECA or
                        any of ($console_title, $meta_desc, $next_static, $port_8787, $port_8790)
                    )
                )
                or $console_en_title
                or (($doc_html in (0..511) or $doc_doctype in (0..511)) and filesize < 64KB and $title_artex_exact and $redir_tasks)
                or (
                    $console_en and (
                        uint16(0) == 0x5A4D or uint32(0) == 0x464C457F or uint32(0) == 0xFEEDFACF or uint32(0) == 0xCFFAEDFE or uint32(0) == 0xBEBAFECA or
                        any of ($next_static, $port_8787, $port_8790)
                    )
                )
            )
            or
            // 3. Explicit staging path + console port, shim/module anchor, or non-PDF/HTML operator audit transcripts
            ($path_stage and any of ($port_8787, $port_8788, $port_8790, $port_8890))
            or any of ($mod_artex, $mod_norma, $name_shim)
            or (
                filesize < 5MB and
                not uint32(0) == 0x46445025 and
                not any of ($doc_html, $doc_doctype) and (
                    $audit_zh or
                    (any of ($canary_write, $canary_persist) and any of ($name_enrich, $name_readonly, $name_worker, $name_norma, $name_probe, $name_scope, $path_stage, $port_8787, $port_8788, $port_8790, $port_8890))
                )
            )
            or
            // 4. Fork-resilient recording-proxy CA + SQLite index pair in source tarballs/scripts/configs (blocks PDF & HTML pages without dropping .tar bundles containing Next.js layout.tsx)
            (
                not uint32(0) == 0x46445025 and
                not ($doc_html in (0..511) or $doc_doctype in (0..511)) and
                $mitm_ca and $traffic_idx
            )
        )
}
