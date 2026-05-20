from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

ACTIVE_MARKER = "# RLT_OPERATIONS_PLATFORM_HEALTH_ACTIVE"

if ACTIVE_MARKER in text:
    print("RLT Platform Health registration already exists. No duplicate patch applied.")
    raise SystemExit(0)

required = [
    "RLT_OPERATIONS_VERTICAL_ACTIVE",
    "# ROAT_PLATFORM_HEALTH_REGISTRATION_ACTIVE",
    "# ASSURANCE_PRODUCT_STACK_PLATFORM_HEALTH_ACTIVE",
    "# DR_BRANCH_PLATFORM_HEALTH_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required existing marker not found: {item}")

target = "        # ROAT_PLATFORM_HEALTH_REGISTRATION_ACTIVE"

rlt_entries = '''        # RLT_OPERATIONS_PLATFORM_HEALTH_ACTIVE
        {
            "tier": "RLT Operations AssuranceLayer",
            "module": "RLT Operations Mission Control™",
            "route": "/rlt-operations",
            "test_route": "",
            "register": "COMPOSITE_VIEW:rlt-operations",
            "purpose": "Executive command surface for radioligand manufacturing readiness, operational trust, governance integrity, deviation probability, environmental stability, and audit readiness."
        },
        {
            "tier": "RLT Operations AssuranceLayer",
            "module": "Operational Readiness Assurance Engine™",
            "route": "/rlt-operations/readiness",
            "test_route": "",
            "register": "COMPOSITE_VIEW:rlt-operations-readiness",
            "purpose": "Evaluates whether RLT manufacturing operations are trustworthy enough to proceed using SOP currency, CAPA exposure, training validity, backup verification, audit trail review, and shift handoff integrity."
        },
        {
            "tier": "RLT Operations AssuranceLayer",
            "module": "Manufacturing Trust Score™",
            "route": "/rlt-operations/trust-score",
            "test_route": "",
            "register": "COMPOSITE_VIEW:rlt-operations-trust-score",
            "purpose": "Calculates operational trustworthiness across evidence integrity, documentation completeness, governance stability, audit readiness, and unresolved operational risk indicators."
        },
        {
            "tier": "RLT Operations AssuranceLayer",
            "module": "Deviation Blast Radius Intelligence™",
            "route": "/rlt-operations/blast-radius",
            "test_route": "",
            "register": "COMPOSITE_VIEW:rlt-operations-blast-radius",
            "purpose": "Maps how an RLT deviation or operational issue may affect equipment, batches, shifts, SOPs, operators, reviewers, and release exposure."
        },
        {
            "tier": "RLT Operations AssuranceLayer",
            "module": "Operational Risk Heat Map",
            "route": "/rlt-operations/risk-heatmap",
            "test_route": "",
            "register": "COMPOSITE_VIEW:rlt-operations-risk-heatmap",
            "purpose": "Displays executive-level governance risk across isolator readiness, environmental monitoring, shift handoff governance, audit trail review, SOP alignment, and CAPA exposure."
        },
'''

if target not in text:
    raise RuntimeError("Could not find ROAT Platform Health insertion point.")

text = text.replace(target, rlt_entries + target)

APP.write_text(text, encoding="utf-8")

print("RLT Platform Health registration patch applied successfully.")
