from dataclasses import dataclass
from enum import Enum
from typing import FrozenSet, Iterable


class ServiceLane(str, Enum):
    CONTINUOUS_ASSURANCE = "CONTINUOUS_ASSURANCE"
    BOUNDED_ASSURANCE_REVIEW = "BOUNDED_ASSURANCE_REVIEW"
    ARCHITECTURE_EVIDENCE_PROVENANCE = "ARCHITECTURE_EVIDENCE_PROVENANCE"
    ENTERPRISE_ASSURANCE_DEPLOYMENT = "ENTERPRISE_ASSURANCE_DEPLOYMENT"


class AssuranceStanding(str, Enum):
    NOT_ESTABLISHED = "NOT_ESTABLISHED"
    SUPPORTABLE = "SUPPORTABLE"


@dataclass(frozen=True)
class CommercialContext:
    lane: ServiceLane
    paid: bool = False
    registered: bool = False
    subscribed: bool = False
    review_purchased: bool = False


@dataclass(frozen=True)
class TechnicalBasis:
    admissible_evidence: bool
    applicable_criteria: bool
    valid_dependencies: bool
    current_authority: bool
    verified_evaluation: bool


@dataclass(frozen=True)
class DomainProfileUpdate:
    domain: str
    inherited_capabilities: FrozenSet[str]
    domain_specific_focus: FrozenSet[str]


def evaluate_assurance_standing(commercial: CommercialContext, basis: TechnicalBasis) -> AssuranceStanding:
    """Commercial status is deliberately non-evidentiary.

    Payment, registration, subscription and purchase cannot increase technical
    assurance standing. Standing is supportable only when every technical
    predicate required by this bounded policy is established.
    """
    _ = commercial
    if all((
        basis.admissible_evidence,
        basis.applicable_criteria,
        basis.valid_dependencies,
        basis.current_authority,
        basis.verified_evaluation,
    )):
        return AssuranceStanding.SUPPORTABLE
    return AssuranceStanding.NOT_ESTABLISHED


def commercial_status_can_raise_standing() -> bool:
    return False


def build_domain_profile_update(domain: str, inherited: Iterable[str], focus: Iterable[str]) -> DomainProfileUpdate:
    return DomainProfileUpdate(
        domain=domain,
        inherited_capabilities=frozenset(inherited),
        domain_specific_focus=frozenset(focus),
    )
