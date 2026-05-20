from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# DR_BRANCH_PLATFORM_HEALTH_ACTIVE"

ANCHOR = '''        {
            "tier": "Life Sciences",
            "module": "TrialTrust™ / Clinical Trial Integrity",'''

DR_PLATFORM_HEALTH_BLOCK = '''        # DR_BRANCH_PLATFORM_HEALTH_ACTIVE
        {
            "tier": "Operational Recovery Governance",
            "module": "DR Activation Intelligence™",
            "route": "/dr-activation-intelligence",
            "test_route": "",
            "register": "COMPOSITE_VIEW:dr-activation-intelligence",
            "purpose": "Determines when an incident crosses into formal disaster recovery based on RTO, RPO, compliance, cybersecurity, infrastructure, and utility triggers."
        },
        {
            "tier": "Operational Recovery Governance",
            "module": "RTO / RPO Governance Intelligence™",
            "route": "/rto-rpo-governance-intelligence",
            "test_route": "",
            "register": "COMPOSITE_VIEW:rto-rpo-governance-intelligence",
            "purpose": "Monitors recovery-time and recovery-point thresholds, drift, breach severity, and governance consequence."
        },
        {
            "tier": "Operational Recovery Governance",
            "module": "Recovery Dependency Validation™",
            "route": "/recovery-dependency-validation",
            "test_route": "",
            "register": "COMPOSITE_VIEW:recovery-dependency-validation",
            "purpose": "Prevents false recovery closure by validating technical restore, reconciliation, CSQA integrity, BQA impact, and downstream dependencies."
        },
        {
            "tier": "Operational Recovery Governance",
            "module": "DR Evidence Passport™",
            "route": "/dr-evidence-passport",
            "test_route": "",
            "register": "COMPOSITE_VIEW:dr-evidence-passport",
            "purpose": "Creates the audit-ready recovery evidence spine across damage assessment, restore proof, reconciliation, QA verification, GMP impact, and root cause."
        },
        {
            "tier": "Operational Recovery Governance",
            "module": "GMP Restart Gate™",
            "route": "/gmp-restart-gate",
            "test_route": "",
            "register": "COMPOSITE_VIEW:gmp-restart-gate",
            "purpose": "Separates technical recovery from regulated resumption by requiring evidence, QA clearance, dependency resolution, and restart authority."
        },
        {
            "tier": "Operational Recovery Governance",
            "module": "Recovery Governance Command Center™",
            "route": "/recovery-governance-command-center",
            "test_route": "",
            "register": "COMPOSITE_VIEW:recovery-governance-command-center",
            "purpose": "Unifies activation, thresholds, dependencies, evidence, restart readiness, authority queues, and leadership priorities into one recovery digital twin."
        },
        {
            "tier": "Operational Recovery Governance",
            "module": "DR Recovery Certificate™",
            "route": "/dr-recovery-certificate",
            "test_route": "",
            "register": "COMPOSITE_VIEW:dr-recovery-certificate",
            "purpose": "Issues final audit-defensible closure only when the full recovery chain is proven, approved, and ready for controlled certification."
        },
'''

def main():
    if not APP_FILE.exists():
        raise SystemExit("ERROR: app.py was not found in the current folder.")

    text = APP_FILE.read_text(encoding="utf-8")

    if ACTIVE_MARKER in text:
        print("SKIP: DR branch is already registered in Platform Health. No duplicate rows inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit("ERROR: Could not find Platform Health Life Sciences anchor.")

    updated = text.replace(
        ANCHOR,
        DR_PLATFORM_HEALTH_BLOCK + ANCHOR,
        1
    )

    required_markers = [
        ACTIVE_MARKER,
        '"tier": "Operational Recovery Governance"',
        '"route": "/dr-activation-intelligence"',
        '"route": "/rto-rpo-governance-intelligence"',
        '"route": "/recovery-dependency-validation"',
        '"route": "/dr-evidence-passport"',
        '"route": "/gmp-restart-gate"',
        '"route": "/recovery-governance-command-center"',
        '"route": "/dr-recovery-certificate"',
        '"register": "COMPOSITE_VIEW:dr-activation-intelligence"',
        '"register": "COMPOSITE_VIEW:dr-recovery-certificate"',
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: DR branch registered safely in Platform Health.")
    print("VERIFIED: Operational Recovery Governance tier and all 7 DR module rows found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
