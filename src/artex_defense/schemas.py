"""Pydantic data models for normalized telemetry, deterministic candidates, kill chains, and Gemma 4 outputs."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

SurfaceType = Literal[
    "edge_appliance",
    "web_portal",
    "endpoint",
    "cloud_iam",
    "network",
    "unknown",
]


class NormalizedEvent(BaseModel):
    """Normalized defensive telemetry event across edge appliances, web portals, endpoints, and cloud logs."""

    timestamp: datetime
    source_host: str = "unknown"
    actor: str = "unknown"
    event_type: str = "generic"  # process, network, http, vpn, edge_auth, cloud_iam, file
    surface: SurfaceType = "unknown"
    appliance: str | None = None
    process: str | None = None
    parent_process: str | None = None
    command_line: str | None = None
    dest_host: str | None = None
    dest_port: int | None = None
    http_method: str | None = None
    http_path: str | None = None
    user_agent: str | None = None
    ja4: str | None = None
    ja4h: str | None = None
    bytes_out: int | None = None
    bytes_in: int | None = None
    status_code: int | None = None
    action: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class CadenceStats(BaseModel):
    """Timing and behavioral cadence metrics for a candidate window."""

    event_count: int
    window_seconds: float
    events_per_minute: float
    mean_interval_sec: float | None = None
    stddev_interval_sec: float | None = None
    error_count: int = 0
    error_ratio: float = 0.0
    unique_targets: int = 0


class CandidateWindow(BaseModel):
    """High-signal behavioral or artifact window surfaced by Stage 1 deterministic rules."""

    window_id: str
    source_host: str
    actor: str
    surface: SurfaceType = "unknown"
    appliance: str | None = None
    start_time: datetime
    end_time: datetime
    reasons: list[str]
    risk_score: int = 0
    alert_tier: Literal["alert", "hunt", "info"] = "info"
    matched_indicators: list[str] = Field(default_factory=list)
    cadence: CadenceStats
    sample_events: list[dict[str, Any]] = Field(default_factory=list)


class KillChainStoryline(BaseModel):
    """Cross-surface correlated storyline linking compressed-timeline candidate windows."""

    storyline_id: str
    start_time: datetime
    end_time: datetime
    duration_minutes: float
    surfaces_involved: list[str]
    appliances_involved: list[str] = Field(default_factory=list)
    actors: list[str]
    hosts: list[str]
    window_ids: list[str]
    combined_reasons: list[str]
    combined_indicators: list[str]
    progression_summary: str


class TriageVerdict(BaseModel):
    """Structured Stage 2 triage verdict returned by local Gemma 4."""

    window_id: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    likelihood_agentic: Literal["unlikely", "possible", "likely", "high_confidence"]
    summary: str
    mitre_techniques: list[str] = Field(default_factory=list)
    key_evidence: list[str] = Field(default_factory=list)
    false_positive_considerations: list[str] = Field(default_factory=list)
    recommended_next_queries: list[str] = Field(default_factory=list)


class IntelExtraction(BaseModel):
    """Structured defensive threat-intelligence extraction produced by local Gemma 4."""

    title: str
    summary: str
    iocs: list[str] = Field(default_factory=list)
    behavioral_signatures: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    detection_ideas: list[str] = Field(default_factory=list)
    hardening_actions: list[str] = Field(default_factory=list)
