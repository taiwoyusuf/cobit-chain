"""Synthetic deterministic Step 172C runtime component.

Platform B1 evaluates assurance state. Source systems remain authoritative.
Only an accountable human may bind regulated action.
RAMAT Vision and Thread D2 are display-only.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass(frozen=True)
class DimensionResult:
    name: str
    satisfied: bool
    state: str
    reason: str


@dataclass(frozen=True)
class EvaluationResult:
    evaluation_id: str
    outcome: str
    reasons: List[str]
    dimensions: Dict[str, DimensionResult]
    no_bind_state: bool
    human_review_required: bool
    evidence_references: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class SourceStateSnapshot:
    snapshot_id: str
    source_system_id: str
    source_record_id: str
    regulated_object_id: str
    state_code: str
    state_version: str
    observed_at: str
    retrieved_at: str
    content_digest: str
    authoritative_state: bool


Record = Dict[str, Any]
