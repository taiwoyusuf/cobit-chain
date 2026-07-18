"""Synthetic deterministic Step 172C runtime component.

Platform B1 evaluates assurance state. Source systems remain authoritative.
Only an accountable human may bind regulated action.
RAMAT Vision and Thread D2 are display-only.
"""

from typing import Any, Dict


DOMAIN_PROFILE = {'domain_id': 'IRLT', 'name': 'IRLT radiopharmaceutical operations', 'priority': 'FIRST_TIER', 'objects': ['accession', 'sample', 'instrument_result', 'middleware_state', 'lis_state', 'batch', 'release_condition'], 'dependencies': ['identity_agreement', 'instrument_state', 'middleware_state', 'lis_state', 'result_verification', 'timing_window', 'human_release_authority']}


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
