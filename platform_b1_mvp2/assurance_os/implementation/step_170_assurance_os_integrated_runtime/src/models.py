from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List


@dataclass(frozen=True)
class AssuranceDecision:
    track_id: str
    scenario_id: str
    decision: str
    no_bind_state: str
    action_held: bool
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EvaluationResult:
    evidence: Dict[str, Any]
    dependencies: Dict[str, Any]
    authority: Dict[str, Any]
    admissibility: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
