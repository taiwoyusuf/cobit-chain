"""Synthetic deterministic Step 172C runtime component.

Platform B1 evaluates assurance state. Source systems remain authoritative.
Only an accountable human may bind regulated action.
RAMAT Vision and Thread D2 are display-only.
"""

from typing import Any, Dict


DOMAIN_PROFILE = {'domain_id': 'AURORA17', 'name': 'Aurora17 QC batch-release demonstration', 'priority': 'GOVERNED_DEMONSTRATION', 'objects': ['sample', 'instrument', 'method', 'result', 'review', 'batch', 'release_condition'], 'dependencies': ['sample_identity', 'instrument_state', 'method_version', 'result_integrity', 'review_state', 'batch_state', 'human_release_authority']}


def adapt_synthetic_input(
    source: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "domain_track": DOMAIN_PROFILE["domain_id"],
        "profile": DOMAIN_PROFILE,
        "source": dict(source),
        "source_systems_authoritative": True,
        "write_back_enabled": False,
        "human_binding_authority_required": True,
    }
