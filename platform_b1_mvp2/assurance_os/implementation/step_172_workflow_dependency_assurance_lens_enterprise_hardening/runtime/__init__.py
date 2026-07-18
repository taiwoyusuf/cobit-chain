"""Synthetic deterministic Step 172C runtime component.

Platform B1 evaluates assurance state. Source systems remain authoritative.
Only an accountable human may bind regulated action.
RAMAT Vision and Thread D2 are display-only.
"""

WORKSTREAM = "workflow_dependency_assurance_lens"
VERSION = "step_172c_v1"

EVALUATION_DIMENSIONS = (
    "dependency_present",
    "dependency_identity_valid",
    "dependency_current",
    "source_state_available",
    "source_state_current",
    "source_state_agreement",
    "mapping_present",
    "mapping_valid",
    "evidence_present",
    "evidence_integrity_valid",
    "evidence_current",
    "workflow_sequence_valid",
    "timing_valid",
    "authority_present",
    "authority_valid",
    "authority_current",
    "authority_delegated",
    "approver_available",
    "escalation_available",
    "pre_authorized_rule_exists",
    "human_accountability_identified",
    "action_consequence_level",
    "release_or_execution_condition_satisfied",
    "no_bind_state",
)

DECISION_PRECEDENCE = (
    "DENY",
    "FAIL-CLOSED",
    "NO-BIND",
    "HOLD",
    "ALLOW",
)
