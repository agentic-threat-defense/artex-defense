"""Multi-backend pySigma compiler and offline schema validator for ARTEX Sigma rules.

Compiles rules/sigma/*.yml across enterprise SIEM/XDR backends:
- Elastic ES|QL (with ECS Windows pipeline)
- Elastic Lucene (with ECS Windows pipeline)
- Microsoft KQL (generic Kusto, plus MDE XDR & Sentinel ASIM pipelines for Windows endpoint rules)
- CrowdStrike Falcon LogScale CQL (with CrowdStrike Falcon pipeline)
- Splunk SPL (with Splunk Windows pipeline)
- SentinelOne S1QL (for Windows endpoint process/network rules)
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sigma.collection import SigmaCollection
from sigma.plugins import InstalledSigmaPlugins
from sigma.validation import SigmaValidator
from sigma.validators.core import validators as core_validators


@dataclass(frozen=True)
class TargetSpec:
    key: str
    label: str
    backend: str
    pipeline: str | None
    extension: str
    comment_prefix: str
    # If set, only rules whose (product, category) match this filter are required for this vendor pipeline
    applicable_categories: frozenset[tuple[str | None, str | None]] | None = None


WINDOWS_ENDPOINT_CATS: frozenset[tuple[str | None, str | None]] = frozenset(
    {
        ("windows", "process_creation"),
        ("windows", "network_connection"),
    }
)

ENTERPRISE_TARGETS: tuple[TargetSpec, ...] = (
    TargetSpec("esql_ecs", "Elastic ES|QL (ECS)", "esql", "ecs_windows", "esql", "//"),
    TargetSpec("lucene_ecs", "Elastic Lucene (ECS)", "lucene", "ecs_windows", "lucene", "#"),
    TargetSpec("kusto_generic", "Microsoft KQL (Generic)", "kusto", None, "kql", "//"),
    TargetSpec(
        "kusto_mde_xdr",
        "Microsoft Defender XDR (KQL)",
        "kusto",
        "microsoft_xdr",
        "kql",
        "//",
        applicable_categories=WINDOWS_ENDPOINT_CATS,
    ),
    TargetSpec(
        "kusto_sentinel_asim",
        "Microsoft Sentinel ASIM (KQL)",
        "kusto",
        "sentinel_asim",
        "kql",
        "//",
        applicable_categories=WINDOWS_ENDPOINT_CATS,
    ),
    TargetSpec("crowdstrike_logscale", "CrowdStrike Falcon LogScale (CQL)", "log_scale", "crowdstrike_falcon", "cql", "//"),
    TargetSpec("splunk_spl", "Splunk SPL (Windows)", "splunk", "splunk_windows", "spl", "#"),
    TargetSpec(
        "sentinelone_s1ql",
        "SentinelOne S1QL (Endpoint)",
        "sentinel_one",
        None,
        "s1ql",
        "#",
        applicable_categories=WINDOWS_ENDPOINT_CATS,
    ),
)


def validate_sigma_schema_offline(rules_dir: str | Path) -> list[str]:
    """Run pySigma's built-in core schema validators offline (skipping remote MITRE/D3FEND fetches)."""
    rule_paths = sorted(Path(rules_dir).glob("*.yml"))
    collection = SigmaCollection.load_ruleset([str(p) for p in rule_paths])
    active = [v for name, v in core_validators.items() if "tag" not in name.lower()]
    validator = SigmaValidator(active)
    issues = validator.validate_rules(list(collection.rules))
    return [str(iss) for iss in issues]


def compile_sigma_directory(
    rules_dir: str | Path,
    *,
    targets: tuple[TargetSpec, ...] = ENTERPRISE_TARGETS,
    export_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Validate and compile all Sigma YAML rules across enterprise SIEM/XDR backends."""
    rules_path = Path(rules_dir)
    rule_files = sorted(rules_path.glob("*.yml"))
    plugins = InstalledSigmaPlugins.autodiscover()
    resolver = plugins.get_pipeline_resolver()

    schema_issues = validate_sigma_schema_offline(rules_path)
    target_reports: list[dict[str, Any]] = []

    out_root = Path(export_dir) if export_dir is not None else None
    if out_root is not None:
        out_root.mkdir(parents=True, exist_ok=True)

    for spec in targets:
        pipe = resolver.resolve([spec.pipeline]) if spec.pipeline else None
        backend_cls = plugins.backends[spec.backend]
        backend = backend_cls(processing_pipeline=pipe) if pipe else backend_cls()

        compiled_rules: list[dict[str, Any]] = []
        failures: list[dict[str, str]] = []
        skipped = 0

        for rf in rule_files:
            collection = SigmaCollection.from_yaml(rf.read_text(encoding="utf-8"))
            rule = collection.rules[0]
            ls_pair = (rule.logsource.product, rule.logsource.category)
            if spec.applicable_categories is not None and ls_pair not in spec.applicable_categories:
                skipped += 1
                continue

            try:
                queries = backend.convert(collection)
                if isinstance(queries, str):
                    query_text = queries.strip()
                else:
                    query_text = "\n\n".join(str(q) for q in queries).strip()
                if not query_text:
                    raise ValueError("Backend produced an empty query")
                compiled_rules.append(
                    {
                        "file": rf.name,
                        "id": str(rule.id or ""),
                        "title": rule.title,
                        "level": str(rule.level or ""),
                        "query": query_text,
                    }
                )
            except Exception as exc:
                failures.append(
                    {
                        "file": rf.name,
                        "error_type": type(exc).__name__,
                        "error": str(exc).splitlines()[0],
                    }
                )

        exported_file: str | None = None
        if out_root is not None and compiled_rules:
            dest = out_root / f"compiled_{spec.key}.{spec.extension}"
            blocks = [
                f"{spec.comment_prefix} Auto-compiled by artex-hunt sigma-compile ({spec.label})\n"
                f"{spec.comment_prefix} Source: {rules_path} ({len(compiled_rules)} rules)\n"
            ]
            for item in compiled_rules:
                blocks.append(
                    f"{spec.comment_prefix} === {item['title']} ({item['file']} | id={item['id']} | level={item['level']}) ===\n"
                    f"{item['query']}\n"
                )
            dest.write_text("\n".join(blocks), encoding="utf-8")
            exported_file = str(dest)

        applicable_total = len(rule_files) - skipped
        target_reports.append(
            {
                "key": spec.key,
                "label": spec.label,
                "backend": spec.backend,
                "pipeline": spec.pipeline,
                "applicable": applicable_total,
                "compiled": len(compiled_rules),
                "skipped": skipped,
                "failed": len(failures),
                "failures": failures,
                "exported_file": exported_file,
                "rules": compiled_rules,
            }
        )

    total_failures = sum(t["failed"] for t in target_reports)
    return {
        "rules_dir": str(rules_path),
        "total_rules": len(rule_files),
        "schema_issues": schema_issues,
        "all_ok": (len(schema_issues) == 0 and total_failures == 0),
        "targets": target_reports,
    }
