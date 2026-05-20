from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "<!-- DR_BRANCH_MODULES_DIRECTORY_ACTIVE -->"

CSS_ANCHOR = ".support{background:#f1f5f9;color:#334155}"
SECTION_ANCHOR = """<div class="section">
<h2>Tier 1 Life Sciences Modules</h2>"""

RECOVERY_CSS = """
.recovery{background:#eef2ff;color:#4338ca}
"""

RECOVERY_SECTION = """
<!-- DR_BRANCH_MODULES_DIRECTORY_ACTIVE -->
<div class="section">
<h2>Operational Recovery Governance</h2>
<div class="grid">
<div class="module-card"><span class="badge recovery">RECOVERY GOVERNANCE</span><h3>DR Activation Intelligence™</h3><p>Determines when an incident crosses into formal disaster recovery based on RTO, RPO, compliance, cybersecurity, infrastructure, and utility triggers.</p><a href="/dr-activation-intelligence">Open Module</a></div>
<div class="module-card"><span class="badge recovery">RECOVERY GOVERNANCE</span><h3>RTO / RPO Governance Intelligence™</h3><p>Monitors recovery-time and recovery-point thresholds, drift, breach severity, and the governance consequence of delay or data loss.</p><a href="/rto-rpo-governance-intelligence">Open Module</a></div>
<div class="module-card"><span class="badge recovery">RECOVERY GOVERNANCE</span><h3>Recovery Dependency Validation™</h3><p>Prevents false recovery closure by validating technical restore, reconciliation, CSQA integrity, BQA impact, and downstream dependencies.</p><a href="/recovery-dependency-validation">Open Module</a></div>
<div class="module-card"><span class="badge recovery">RECOVERY GOVERNANCE</span><h3>DR Evidence Passport™</h3><p>Creates the audit-ready recovery evidence spine: damage assessment, restore log, reconciliation matrix, QA verification, GMP impact, and root cause.</p><a href="/dr-evidence-passport">Open Module</a></div>
<div class="module-card"><span class="badge recovery">RECOVERY GOVERNANCE</span><h3>GMP Restart Gate™</h3><p>Separates technical recovery from regulated resumption by requiring evidence, QA clearance, dependency resolution, and restart authority before GMP activity resumes.</p><a href="/gmp-restart-gate">Open Module</a></div>
<div class="module-card"><span class="badge recovery">RECOVERY GOVERNANCE</span><h3>Recovery Governance Command Center™</h3><p>Unifies activation, thresholds, dependencies, evidence, restart readiness, authority queues, and leadership priorities into one recovery digital twin.</p><a href="/recovery-governance-command-center">Open Module</a></div>
<div class="module-card"><span class="badge recovery">RECOVERY GOVERNANCE</span><h3>DR Recovery Certificate™</h3><p>Issues final audit-defensible closure only when the complete recovery chain is proven, approved, and ready for controlled certification.</p><a href="/dr-recovery-certificate">Open Module</a></div>
</div>
</div>

"""

def main():
    if not APP_FILE.exists():
        raise SystemExit("ERROR: app.py was not found in the current folder.")

    text = APP_FILE.read_text(encoding="utf-8")

    if ACTIVE_MARKER in text:
        print("SKIP: DR branch is already registered in the Modules Directory. No duplicate section inserted.")
        return

    if CSS_ANCHOR not in text:
        raise SystemExit("ERROR: Could not find Modules Directory CSS anchor.")

    if SECTION_ANCHOR not in text:
        raise SystemExit("ERROR: Could not find Tier 1 Life Sciences section anchor.")

    updated = text.replace(
        CSS_ANCHOR,
        CSS_ANCHOR + RECOVERY_CSS,
        1
    )

    updated = updated.replace(
        SECTION_ANCHOR,
        RECOVERY_SECTION + SECTION_ANCHOR,
        1
    )

    required_markers = [
        ACTIVE_MARKER,
        '<h2>Operational Recovery Governance</h2>',
        'href="/dr-activation-intelligence"',
        'href="/rto-rpo-governance-intelligence"',
        'href="/recovery-dependency-validation"',
        'href="/dr-evidence-passport"',
        'href="/gmp-restart-gate"',
        'href="/recovery-governance-command-center"',
        'href="/dr-recovery-certificate"',
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: DR branch registered safely in the Modules Directory.")
    print("VERIFIED: Operational Recovery Governance section and all 7 DR links found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
