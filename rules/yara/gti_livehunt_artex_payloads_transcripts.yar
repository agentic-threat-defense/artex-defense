/*
  Google Threat Intelligence (GTI) Livehunt Ruleset
  Learn more: https://gtidocs.virustotal.com/docs/livehunt-guide
*/
import "vt"

rule ARTEX_Payloads_and_Agent_Transcripts {
    meta:
        description = "Livehunt rule for BLOODALCHEMY drops, ARTEX/ScopeWeaver payloads, and agent transcripts/configs"
        author = "Threat Hunt"
        entity = "file"
        date = "2026-11-20"
        version = "1.1"

    strings:
        // High-confidence BLOODALCHEMY masqueraded sideload artifacts
        $ba_dll = "graphics-hook-filter64.dll" ascii wide nocase
        $ba_cfg = "graphics-hook_config.bin" ascii wide nocase
        $ba_uri = "/Inform/logger/" ascii wide

        // Strong ARTEX / norma SDK anchors
        $art_path  = "artx5v" ascii wide
        $art_yaml  = "artex.yaml" ascii wide nocase
        $art_json  = "artex_config.json" ascii wide nocase
        $art_ua1   = "artex-enrich/1.0" ascii wide
        $art_ua2   = "artex-readonly/1.0" ascii wide
        $art_ua3   = "ARTEX-worker/1.0" ascii wide
        $art_norma = "norma/0." ascii wide
        $art_probe = "ArtexProbe" ascii wide nocase
        $art_scope = "ScopeWeaver" ascii wide nocase
        $art_fork1 = "AntiFox" ascii wide nocase
        $art_fork2 = "sco-fix2" ascii wide nocase
        $art_fork3 = "Agent Security Workbench" ascii wide
        $art_proxy = ".xcai.com" ascii wide nocase

        // Supporting transcript / prompt-harness markers (never matched alone)
        $ctx_claude = "CLAUDE.md" ascii wide
        $ctx_tmpl   = "prompt_templates" ascii wide
        $ctx_intent = /"intent_id"\s*:\s*"i[0-9]{1,6}"/ ascii
        $ctx_graph  = "exploration_nodes" ascii wide

    condition:
        vt.metadata.new_file and
        filesize < 25MB and (
            // 1. Unsigned BLOODALCHEMY binaries / loaders
            (
                not for any tag in vt.metadata.tags : ( tag == "signed" ) and
                any of ($ba_dll, $ba_cfg, $ba_uri)
            )
            or
            // 2. Direct ARTEX configs, private builds, or explicit framework User-Agents
            any of ($art_yaml, $art_json, $art_ua1, $art_ua2, $art_ua3, $art_fork2, $art_fork3)
            or
            // 3. Agent transcripts / staging files combining an ARTEX anchor with prompt/intent/graph context
            (
                filesize < 5MB and
                any of ($art_path, $art_norma, $art_probe, $art_scope, $art_fork1, $art_proxy) and
                any of ($ctx_claude, $ctx_tmpl, $ctx_intent, $ctx_graph)
            )
            or
            // 4. Dual-graph Exploration Graph intent logs with harness templates
            (
                filesize < 5MB and
                $ctx_intent and $ctx_graph and any of ($ctx_claude, $ctx_tmpl)
            )
        )
}
