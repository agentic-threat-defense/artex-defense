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

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Union

from sigma.backends.crowdstrike.logscale import LogScaleBackend
from sigma.backends.elasticsearch.elasticsearch_esql import ESQLBackend
from sigma.backends.elasticsearch.elasticsearch_lucene import LuceneBackend
from sigma.backends.kusto import KustoBackend
from sigma.backends.sentinelone import SentinelOneBackend
from sigma.collection import SigmaCollection
from sigma.conditions import ConditionAND, ConditionFieldEqualsValueExpression, ConditionOR
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.plugins import InstalledSigmaPlugins
from sigma.processing.conditions import IncludeFieldCondition, LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation, ReplaceStringTransformation
from sigma.types import SigmaBool, SigmaNumber, SigmaRegularExpression, SigmaString, SpecialChars
from sigma.validation import SigmaValidator
from sigma.validators.core import validators as core_validators

_KQL_SIMPLE_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_KQL_DOTTED_PATH_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")
_ECS_KEYWORD_FIELDS: frozenset[str] = frozenset(
    {
        "event.code",
        "azure.signinlogs.result_type",
    }
)


def _lowercase_sigma_string(val: SigmaString) -> SigmaString:
    """Return a copy of SigmaString with literal text segments lowercased (preserving wildcards)."""
    out = SigmaString()
    out.s = tuple(part.lower() if isinstance(part, str) else part for part in val.s)
    return out


def _to_lucene_regex(pattern: str) -> str:
    """Translate PCRE/Sigma regex syntax into Apache Lucene RegExp DFA syntax (full-string match, no `(?:...)` or `^`/`$`)."""
    out = pattern.replace("(?:", "(")
    # Convert common boundary groups `(^|[...])` and `([...]|$)` into full-string Lucene DFA equivalents
    # (Apache Lucene RegExp forbids empty alternation branches `(|...)`; use postfix `?` instead.)
    out = re.sub(r"\(\^\|(\[[^\]]+\])\)", r"(.*\1)?", out)
    out = re.sub(r"\((\[[^\]]+\])\|\$\)", r"(\1.*)?", out)
    # Handle plain leading ^ / trailing $ anchors (Lucene always anchors full-string)
    anchored_start = out.startswith("^") or bool(re.match(r"^\(\.\*\[[^\]]+\]\)\?", out))
    if out.startswith("^"):
        out = out[1:]
    anchored_end = out.endswith("$") or out.endswith(".*)?")
    if out.endswith("$"):
        out = out[:-1]
    if not anchored_start and not out.startswith(".*"):
        out = ".*" + out
    if not anchored_end and not out.endswith(".*"):
        out = out + ".*"
    return out


class HardenedKustoBackend(KustoBackend):
    """KustoBackend fixed for valid KQL identifier quoting (['field']), dynamic dotted paths, boolean `==`, and numeric `in (...)`."""

    def escape_and_quote_field(self, field_name: str) -> str:
        # Leave plain identifiers and clean dotted dynamic-JSON paths (e.g. status.errorCode,
        # requestParameters.filterPattern) unbracketed so KQL resolves nested JSON properties
        # instead of looking for a literal flat column containing a dot.
        if _KQL_DOTTED_PATH_RE.match(field_name):
            return field_name
        if field_name.startswith("['") and field_name.endswith("']"):
            return field_name
        if "." in field_name:
            parts = field_name.split(".")
            rendered: list[str] = []
            for idx, seg in enumerate(parts):
                if _KQL_SIMPLE_IDENT_RE.match(seg):
                    rendered.append(seg if idx == 0 else f".{seg}")
                else:
                    esc = seg.replace("'", "\\'")
                    rendered.append(f"['{esc}']")
            return "".join(rendered)
        escaped = field_name.replace("'", "\\'")
        return f"['{escaped}']"

    def convert_condition_field_eq_val_bool(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str | DeferredQueryExpression:
        if not isinstance(cond.value, SigmaBool):
            raise TypeError(f"Expected SigmaBool for cond.value, got {type(cond.value)}")
        bool_token = self.bool_values[cond.value.boolean]
        if bool_token is None:
            raise NotImplementedError(f"Boolean value {cond.value.boolean} not supported by the backend.")
        return f"{self.escape_and_quote_field(cond.field)} == {bool_token}"

    def convert_condition_as_in_expression(
        self, cond: Union[ConditionOR, ConditionAND], state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        raw_field = cond.args[0].field  # type: ignore[union-attr]
        quoted_field = self.escape_and_quote_field(raw_field)
        op1 = self.or_in_operator if isinstance(cond, ConditionOR) else self.and_in_operator
        op2 = self.or_token if isinstance(cond, ConditionOR) else self.and_token

        num_args = [
            arg
            for arg in cond.args
            if isinstance(arg, ConditionFieldEqualsValueExpression) and isinstance(arg.value, SigmaNumber)
        ]
        str_nonwildcard_args = [
            arg
            for arg in cond.args
            if isinstance(arg, ConditionFieldEqualsValueExpression)
            and isinstance(arg.value, SigmaString)
            and not arg.value.contains_special()
        ]
        list_wildcards = [
            arg.value
            for arg in cond.args
            if isinstance(arg, ConditionFieldEqualsValueExpression)
            and isinstance(arg.value, SigmaString)
            and arg.value.contains_special()
        ]

        as_in_expr = ""
        if num_args and not str_nonwildcard_args:
            # Numeric KQL columns (RemotePort, DstPortNumber, status.errorCode) require unquoted ints + `in`
            num_op = "in" if isinstance(cond, ConditionOR) else op1
            num_list = self.list_separator.join(str(a.value.number) for a in num_args)
            as_in_expr = self.field_in_list_expression.format(field=quoted_field, op=num_op, list=num_list)
        elif str_nonwildcard_args or num_args:
            mixed_items = [self.convert_value_str(a.value, state) for a in str_nonwildcard_args] + [
                str(a.value.number) for a in num_args
            ]
            as_in_expr = self.field_in_list_expression.format(
                field=quoted_field, op=op1, list=self.list_separator.join(mixed_items)
            )

        wildcard_exprs_list: list[str] = []
        for arg_val in list_wildcards:
            # Pass raw_field (NOT quoted_field) so nested conversion never double-quotes the identifier
            new_cond = ConditionFieldEqualsValueExpression(field=raw_field, value=arg_val)
            if arg_val[1:-1].contains_special():
                expr = f"{self.token_separator}{self.and_token}{self.token_separator}".join(
                    [
                        self.contains_expression.format(
                            field=quoted_field, value=self.convert_value_str(SigmaString(str(x)), state)
                        )
                        for x in arg_val.s
                        if not isinstance(x, SpecialChars)
                    ]
                )
                expr = self.group_expression.format(expr=expr)
            else:
                expr = str(self.convert_condition_field_eq_val_str(new_cond, state))
            wildcard_exprs_list.append(expr)

        wildcard_exprs = f"{self.token_separator}{op2}{self.token_separator}".join(wildcard_exprs_list)
        if as_in_expr and wildcard_exprs:
            return as_in_expr + self.token_separator + op2 + self.token_separator + wildcard_exprs
        return as_in_expr + wildcard_exprs


_ESQL_LIKE_LITERAL_RE = re.compile(r'(\blike\s+")((?:[^"\\]|\\.)*)"')
_ESQL_BAD_WILDCARD_ESCAPE_RE = re.compile(r'(?<!\\)\\([?*])')


def _fix_esql_like_escapes(expr: str | DeferredQueryExpression) -> str | DeferredQueryExpression:
    """Double-escape LIKE wildcard escapes (`\\?`, `\\*`) inside standard ES|QL double-quoted strings."""
    if not isinstance(expr, str) or ' like "' not in expr:
        return expr

    def _repl(match: re.Match[str]) -> str:
        prefix, body = match.group(1), match.group(2)
        fixed = _ESQL_BAD_WILDCARD_ESCAPE_RE.sub(lambda m: "\\\\" + m.group(1), body)
        return f'{prefix}{fixed}"'

    return _ESQL_LIKE_LITERAL_RE.sub(_repl, expr)


class HardenedESQLBackend(ESQLBackend):
    """ESQLBackend fixed for lowercase `*.caseless` literals, string-typed ECS `keyword` fields, Lucene-valid `rlike`, and ES|QL `LIKE` escapes."""

    def convert_value_re(
        self, r: SigmaRegularExpression, state: ConversionState
    ) -> str | DeferredQueryExpression:
        lucene_re = SigmaRegularExpression(_to_lucene_regex(str(r.regexp)))
        return super().convert_value_re(lucene_re, state)

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str | DeferredQueryExpression:
        if cond.field and cond.field.endswith(".caseless") and isinstance(cond.value, SigmaString):
            cond = ConditionFieldEqualsValueExpression(
                field=cond.field,
                value=_lowercase_sigma_string(cond.value),
            )
        return _fix_esql_like_escapes(super().convert_condition_field_eq_val_str(cond, state))

    def convert_condition_field_eq_val_num(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str | DeferredQueryExpression:
        if cond.field in _ECS_KEYWORD_FIELDS and isinstance(cond.value, SigmaNumber):
            str_cond = ConditionFieldEqualsValueExpression(
                field=cond.field,
                value=SigmaString(str(cond.value.number)),
            )
            return super().convert_condition_field_eq_val_str(str_cond, state)
        return super().convert_condition_field_eq_val_num(cond, state)

    def convert_condition_as_in_expression(
        self, cond: ConditionOR | ConditionAND, state: ConversionState
    ) -> str | DeferredQueryExpression:
        if cond.args and isinstance(cond.args[0], ConditionFieldEqualsValueExpression):
            field_name = cond.args[0].field
            if field_name and field_name.endswith(".caseless"):
                lowered_args = [
                    ConditionFieldEqualsValueExpression(
                        field=arg.field,
                        value=_lowercase_sigma_string(arg.value) if isinstance(arg.value, SigmaString) else arg.value,
                    )
                    if isinstance(arg, ConditionFieldEqualsValueExpression)
                    else arg
                    for arg in cond.args
                ]
                cond = type(cond)(lowered_args)
            elif field_name in _ECS_KEYWORD_FIELDS:
                str_args = [
                    ConditionFieldEqualsValueExpression(
                        field=arg.field,
                        value=SigmaString(str(arg.value.number)) if isinstance(arg.value, SigmaNumber) else arg.value,
                    )
                    if isinstance(arg, ConditionFieldEqualsValueExpression)
                    else arg
                    for arg in cond.args
                ]
                cond = type(cond)(str_args)
        return _fix_esql_like_escapes(super().convert_condition_as_in_expression(cond, state))


class HardenedSentinelOneBackend(SentinelOneBackend):
    """SentinelOneBackend fixed to use exact numeric `=` and `In` for ports/numbers rather than `Contains AnyCase`."""

    def convert_condition_field_eq_val_num(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        if isinstance(cond.value, SigmaNumber) or cond.field in {"DstPort", "SrcPort"}:
            num_val = cond.value.number if isinstance(cond.value, SigmaNumber) else str(cond.value)
            return f"{self.escape_and_quote_field(cond.field)} = {num_val}"
        return super().convert_condition_field_eq_val_num(cond, state)

    def convert_condition_as_in_expression(
        self, cond: Union[ConditionOR, ConditionAND], state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        if cond.args and (
            all(isinstance(arg.value, SigmaNumber) for arg in cond.args)
            or cond.args[0].field in {"DstPort", "SrcPort"}
        ):
            return self.field_in_list_expression.format(
                field=self.escape_and_quote_field(cond.args[0].field),
                op="In",
                list=self.list_separator.join(
                    self.convert_value_str(arg.value, state)
                    if isinstance(arg.value, SigmaString)
                    else str(arg.value)
                    for arg in cond.args
                ),
            )
        return super().convert_condition_as_in_expression(cond, state)


def _build_ecs_real_wire_pipeline() -> ProcessingPipeline:
    """Supplemental Elastic ECS field mappings for web/proxy, DNS, AWS CloudTrail, Okta, and Entra ID."""
    return ProcessingPipeline(
        name="artex_ecs_real_wire",
        priority=50,
        items=[
            ProcessingItem(
                identifier="artex_ecs_linux_proc",
                transformation=FieldMappingTransformation(
                    {
                        "Image": "process.executable",
                        "ParentImage": "process.parent.executable",
                        "CommandLine": "process.command_line",
                    }
                ),
                rule_conditions=[LogsourceCondition(product="linux", category="process_creation")],
            ),
            ProcessingItem(
                identifier="artex_ecs_web_proxy_fw",
                transformation=FieldMappingTransformation(
                    {
                        "c-uri": "url.original",
                        "cs-user-agent": "user_agent.original",
                        "sc-status": "http.response.status_code",
                        "cs-host": "url.domain",
                    }
                ),
            ),
            ProcessingItem(
                identifier="artex_ecs_cloudtrail",
                transformation=FieldMappingTransformation(
                    {
                        "eventName": "event.action",
                        "errorCode": "error.code",
                        "userIdentity.arn": "aws.cloudtrail.user_identity.arn",
                        "requestParameters.filterPattern": "aws.cloudtrail.request_parameters.filterPattern",
                        "requestParameters.attribute": "aws.cloudtrail.request_parameters.attribute",
                        "requestParameters.withDecryption": "aws.cloudtrail.request_parameters.withDecryption",
                    }
                ),
                rule_conditions=[LogsourceCondition(product="aws", service="cloudtrail")],
            ),
            ProcessingItem(
                identifier="artex_ecs_okta",
                transformation=FieldMappingTransformation(
                    {
                        "eventType": "event.action",
                        "outcome.reason": "okta.outcome.reason",
                        "outcome.result": "okta.outcome.result",
                        "debugContext.debugData.requestUri": "okta.debug_context.debug_data.request_uri",
                    }
                ),
                rule_conditions=[LogsourceCondition(product="okta")],
            ),
            ProcessingItem(
                identifier="artex_ecs_entra",
                transformation=FieldMappingTransformation(
                    {
                        "status.errorCode": "azure.signinlogs.result_type",
                        "operationName": "event.action",
                    }
                ),
                rule_conditions=[LogsourceCondition(product="azure")],
            ),
        ],
    )


def _build_kusto_generic_pipeline() -> ProcessingPipeline:
    """Clean ASIM/KQL column mappings for generic web, proxy, firewall, DNS, and cloud rules."""
    return ProcessingPipeline(
        name="artex_kusto_generic_real_wire",
        priority=50,
        items=[
            ProcessingItem(
                identifier="artex_kql_web_proxy",
                transformation=FieldMappingTransformation(
                    {
                        "c-uri": "UrlOriginal",
                        "cs-user-agent": "HttpUserAgentOriginal",
                        "sc-status": "HttpStatusCode",
                        "cs-host": "DstDomain",
                        "ComputerName": "Computer",
                    }
                ),
            ),
        ],
    )


def _build_splunk_cim_web_pipeline() -> ProcessingPipeline:
    """Supplemental Splunk CIM field mappings for web/proxy/firewall and Linux Endpoint.Processes logs."""
    return ProcessingPipeline(
        name="artex_splunk_cim_web",
        priority=50,
        items=[
            ProcessingItem(
                identifier="artex_splunk_linux_proc",
                transformation=FieldMappingTransformation(
                    {
                        "Image": "process_path",
                        "ParentImage": "parent_process_path",
                        "CommandLine": "process",
                    }
                ),
                rule_conditions=[LogsourceCondition(product="linux", category="process_creation")],
            ),
            ProcessingItem(
                identifier="artex_splunk_web_proxy",
                transformation=FieldMappingTransformation(
                    {
                        "c-uri": "uri_path",
                        "cs-user-agent": "http_user_agent",
                        "sc-status": "status",
                        "cs-host": "dest",
                    }
                ),
            ),
        ],
    )


def _build_crowdstrike_linux_basename_pipeline() -> ProcessingPipeline:
    """Strip leading Linux `/` path prefixes on Falcon basename-only fields (ParentBaseFileName, FileName)."""
    return ProcessingPipeline(
        name="artex_crowdstrike_linux_basenames",
        priority=50,
        items=[
            ProcessingItem(
                identifier="artex_cql_linux_basename_only",
                transformation=ReplaceStringTransformation(regex=r"^\*/([^/]+)$", replacement=r"\1"),
                field_name_conditions=[IncludeFieldCondition(fields=["ParentBaseFileName", "FileName"])],
            ),
        ],
    )


class HardenedLuceneBackend(LuceneBackend):
    """LuceneBackend fixed to translate PCRE `|re` patterns into Apache Lucene DFA syntax (no `(?:...)`, `^`, or `$`)."""

    def convert_value_re(
        self, r: SigmaRegularExpression, state: ConversionState
    ) -> str | DeferredQueryExpression:
        lucene_re = SigmaRegularExpression(_to_lucene_regex(str(r.regexp)))
        return super().convert_value_re(lucene_re, state)


class HardenedLogScaleBackend(LogScaleBackend):
    """LogScaleBackend fixed to escape `/` inside `/regex/` literals (prevents `=//` comment syntax corruption)."""

    re_escape = ["/"]


_BACKEND_OVERRIDES: dict[str, type[Any]] = {
    "kusto": HardenedKustoBackend,
    "esql": HardenedESQLBackend,
    "lucene": HardenedLuceneBackend,
    "log_scale": HardenedLogScaleBackend,
    "sentinel_one": HardenedSentinelOneBackend,
}

_EXTRA_PIPELINES: dict[str, Any] = {
    "esql_ecs": _build_ecs_real_wire_pipeline,
    "lucene_ecs": _build_ecs_real_wire_pipeline,
    "kusto_generic": _build_kusto_generic_pipeline,
    "crowdstrike_logscale": _build_crowdstrike_linux_basename_pipeline,
    "splunk_spl": _build_splunk_cim_web_pipeline,
}


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
        ("linux", "process_creation"),
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
    # Skip remote tag lookups and low-severity escaped-wildcard reminders (intentional literal `\?` in URL query strings)
    active = [
        v
        for name, v in core_validators.items()
        if "tag" not in name.lower() and "escaped_wildcard" not in name.lower()
    ]
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
        extra_factory = _EXTRA_PIPELINES.get(spec.key)
        if extra_factory is not None:
            extra_pipe = extra_factory()
            pipe = (pipe + extra_pipe) if pipe is not None else extra_pipe
        backend_cls = _BACKEND_OVERRIDES.get(spec.backend, plugins.backends[spec.backend])
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
