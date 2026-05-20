from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "<!-- ASSURANCE_PRODUCT_STACK_MODULES_DIRECTORY_ACTIVE -->"

PRODUCT_CSS = """
.assurance{background:#ecfeff;color:#0e7490}
"""

PRIMARY_SECTION_ANCHOR = """<!-- DR_BRANCH_MODULES_DIRECTORY_ACTIVE -->
<div class="section">
<h2>Operational Recovery Governance</h2>"""

FALLBACK_SECTION_ANCHOR = """<div class="section">
<h2>Tier 1 Life Sciences Modules</h2>"""

PRODUCT_SECTION = """
<!-- ASSURANCE_PRODUCT_STACK_MODULES_DIRECTORY_ACTIVE -->
<div class="section">
<h2>Assurance Product Stack</h2>
<div class="grid">
<div class="module-card"><span class="badge assurance">PRODUCT ENGINE</span><h3>Enterprise Assurance Passport Factory™</h3><p>Cross-domain assurance engine that evaluates batches, SOPs, CIs, sterile compounding records, DR events, access reviews, and CAPA items using one common governance truth model.</p><a href="/enterprise-assurance-passport-factory">Open Factory</a></div>
<div class="module-card"><span class="badge assurance">PORTABLE OUTPUT</span><h3>Governance Assurance Passport™</h3><p>Portable audit-ready assurance record showing object identity, control coverage, evidence completeness, integrity anchors, reconciliation, dependencies, exceptions, DR readiness, and closure verdict.</p><a href="/governance-assurance-passport/BATCH-2026-041">Open Sample Passport</a></div>
<div class="module-card"><span class="badge assurance">DIAGNOSTIC MODEL</span><h3>COBIT-Chain Maturity Scorecard™</h3><p>Interactive 0–4 maturity model across evidence standardization, integrity anchoring, cross-system reconciliation, dependency validation, exception/CAPA linkage, and DR governance readiness.</p><a href="/cobit-chain-maturity-scorecard">Open Scorecard</a></div>
</div>
</div>

"""

def main():
    if not APP_FILE.exists():
        raise SystemExit("ERROR: app.py was not found in the current folder.")

    text = APP_FILE.read_text(encoding="utf-8")

    if ACTIVE_MARKER in text:
        print("SKIP: Assurance Product Stack is already registered in the Modules Directory. No duplicate section inserted.")
        return

    updated = text

    if ".assurance{background:#ecfeff;color:#0e7490}" not in updated:
        if ".recovery{background:#eef2ff;color:#4338ca}" in updated:
            updated = updated.replace(
                ".recovery{background:#eef2ff;color:#4338ca}",
                ".recovery{background:#eef2ff;color:#4338ca}" + PRODUCT_CSS,
                1
            )
        elif ".support{background:#f1f5f9;color:#334155}" in updated:
            updated = updated.replace(
                ".support{background:#f1f5f9;color:#334155}",
                ".support{background:#f1f5f9;color:#334155}" + PRODUCT_CSS,
                1
            )
        else:
            raise SystemExit("ERROR: Could not find Modules Directory CSS anchor.")

    if PRIMARY_SECTION_ANCHOR in updated:
        updated = updated.replace(
            PRIMARY_SECTION_ANCHOR,
            PRODUCT_SECTION + PRIMARY_SECTION_ANCHOR,
            1
        )
    elif FALLBACK_SECTION_ANCHOR in updated:
        updated = updated.replace(
            FALLBACK_SECTION_ANCHOR,
            PRODUCT_SECTION + FALLBACK_SECTION_ANCHOR,
            1
        )
    else:
        raise SystemExit("ERROR: Could not find Modules Directory section anchor.")

    required_markers = [
        ACTIVE_MARKER,
        '<h2>Assurance Product Stack</h2>',
        'href="/enterprise-assurance-passport-factory"',
        'href="/governance-assurance-passport/BATCH-2026-041"',
        'href="/cobit-chain-maturity-scorecard"',
        'Enterprise Assurance Passport Factory™',
        'Governance Assurance Passport™',
        'COBIT-Chain Maturity Scorecard™',
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: Assurance Product Stack registered safely in the Modules Directory.")
    print("VERIFIED: Factory, Passport, and Maturity Scorecard links found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
