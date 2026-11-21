rule ARTEX_ScopeWeaver_Framework_Artifacts
{
    meta:
        description = "Detects binary, harness, or console artifacts referencing ARTEX, ScopeWeaver, LUCK, or norma agentic offensive frameworks"
        author = "ARTEX Defensive Research Workbench"
        date = "2026-11-20"
        tlp = "CLEAR"
        mitre_attack = "T1588.002"

    strings:
        $name_artex = "artex" nocase ascii wide
        $name_enrich = "artex-enrich/1.0" ascii wide
        $name_probe = "ArtexProbe" nocase ascii wide
        $name_scope = "ScopeWeaver" nocase ascii wide
        $name_antifox = "AntiFox" nocase ascii wide
        $name_pojun = "Pojun" ascii wide
        $name_forang = "FORANG" ascii wide
        $name_scofix = "sco-fix2" nocase ascii wide
        $name_workbench = "Agent Security Workbench" ascii wide
        $name_artex_mx = "ARTEX MX" ascii wide
        $name_guanlan = "Guanlan SEC" nocase ascii wide
        $name_luck = "LUCK" ascii wide
        $name_norma = "norma/0." ascii wide
        $name_norma_agent = "norma-agent" nocase ascii wide
        $name_bloodalchemy = "BLOODALCHEMY" nocase ascii wide
        $path_stage = "artx5v" nocase ascii wide
        $port_8787 = ":8787" ascii wide
        $port_8790 = ":8790" ascii wide
        $console_zh = { E8 87 AA E4 B8 BB E6 B8 97 E9 80 8F E6 B5 8B E8 AF 95 E6 8E A7 E5 88 B6 E5 8F B0 }
        $go_marker = "runtime.main" ascii
        $agent_loop = "planner" nocase ascii

    condition:
        (
            (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and
            $go_marker and
            (any of ($name_artex, $name_enrich, $name_probe, $name_scope, $name_antifox, $name_pojun, $name_forang, $name_scofix, $name_workbench, $name_artex_mx, $name_guanlan, $name_norma, $name_norma_agent, $path_stage) or ($name_luck and $agent_loop)) and
            (any of ($port_8787, $port_8790, $agent_loop))
        )
        or ($path_stage and any of ($port_8787, $port_8790))
        or $name_enrich
        or $name_bloodalchemy
        or $console_zh
}
