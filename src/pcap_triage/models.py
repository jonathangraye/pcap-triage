"""The shared, versioned report contract. No payloads belong in this model."""

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class Evidence:
    frame: int
    time_seconds: float


@dataclass
class Finding:
    rule: str
    severity: str
    confidence: str
    title: str
    observed: str
    meaning: str
    endpoints: list[str]
    count: int
    evidence: list[Evidence]
    next_checks: list[str]
    alternatives: list[str]
    metrics: dict[str, int | float] = field(default_factory=dict)


@dataclass
class Report:
    capture: str
    status: str
    summary: str
    packet_count: int
    duration_seconds: float
    findings: list[Finding]
    limitations: list[str]
    schema_version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
