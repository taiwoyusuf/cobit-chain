from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# ASSURANCE_PRODUCT_STACK_PLATFORM_HEALTH_ACTIVE"

PRIMARY_ANCHOR = '''        # DR_BRANCH_PLATFORM_HEALTH_ACTIVE'''
FALLBACK_ANCHOR = '''        {
            "tier": "Life Sciences",
            "module": "TrialTrust™ / Clinical Trial Integrity",'''

ASSURANCE_PRODUCT_STACK_BLOCK = '''        # ASSURANCE_PRODUCT_STACK_PLATFORM_HEALTH_ACTIVE
        {
            "tier": "Assurance Product Stack",
            "module": "Enterprise Assurance Passport Factory™",
            "route": "/enterprise-assurance-passport-factory",
            "test_route": "",
            "register": "COMPOSITE_VIEW:enterprise-assurance-passport-factory",
            "purpose": "Cross-domain product engine that evaluates governed objects and generates portable assurance logic across batches, SOPs, CIs, sterile records, DR events, access reviews, and CAPA items."
        },
        {
            "tier": "Assurance Product Stack",
            "module": "Governance Assurance Passport™",
            "route": "/governance-assurance-passport/BATCH-2026-041",
            "test_route": "",
            "register": "COMPOSITE_VIEW:governance-assurance-passport",
            "purpose": "Portable audit-ready assurance record showing object identity, control coverage, evidence completeness, integrity anchors, reconciliation, dependencies, exceptions, DR readiness, and closure verdict."
        },
        {
            "tier": "Assurance Product Stack",
            "module": "COBIT-Chain Maturity Scorecard™",
            "route": "/cobit-chain-maturity-scorecard",
            "test_route": "",
            "register": "COMPOSITE_VIEW:cobit-chain-maturity-scorecard",
            "purpose": "Interactive maturity diagnostic across evidence standardization, integrity anchoring, cross-system reconciliation, dependency validation, exception/CAPA linkage, and DR governance readiness."
        },
'''

def main():
    if not APP_FILE.exists():
        raise SystemExit("ERROR: app.py was not found in the current folder.")

    text = APP_FILE.read_text(encoding="utf-8")

    if ACTIVE_MARKER in text:
        print("SKIP: Assurance Product Stack is already registered in Platform Health. No duplicate rows inserted.")
        return

    if PRIMARY_ANCHOR in text:
        updated = text.replace(
            PRIMARY_ANCHOR,
            ASSURANCE_PRODUCT_STACK_BLOCK + PRIMARY_ANCHOR,
            1
        )
    elif FALLBACK_ANCHOR in text:
        updated = text.replace(
            FALLBACK_ANCHOR,
            ASSURANCE_PRODUCT_STACK_BLOCK + FALLBACK_ANCHOR,
            1
        )
    else:
        raise SystemExit("ERROR: Could not find Platform Health insertion anchor.")

    required_markers = [
        ACTIVE_MARKER,
        '"tier": "Assurance Product Stack"',
        '"module": "Enterprise Assurance Passport Factory™"',
        '"module": "Governance Assurance Passport™"',
        '"module": "COBIT-Chain Maturity Scorecard™"',
        '"route": "/enterprise-assurance-passport-factory"',
        '"route": "/governance-assurance-passport/BATCH-2026-041"',
        '"route": "/cobit-chain-maturity-scorecard"',
        '"register": "COMPOSITE_VIEW:enterprise-assurance-passport-factory"',
        '"register": "COMPOSITE_VIEW:governance-assurance-passport"',
        '"register": "COMPOSITE_VIEW:cobit-chain-maturity-scorecard"',
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: Assurance Product Stack registered safely in Platform Health.")
    print("VERIFIED: Factory, Passport, and Maturity Scorecard Platform Health rows found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
