from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "<!-- ROAT_MODULES_DIRECTORY_REGISTRATION_ACTIVE -->"

TWIN_CSS = """
.twin{background:#ede9fe;color:#6d28d9}
"""

ASSURANCE_SECTION_ANCHOR = """<!-- ASSURANCE_PRODUCT_STACK_MODULES_DIRECTORY_ACTIVE -->
<div class="section">
<h2>Assurance Product Stack</h2>
<div class="grid">"""

ROAT_CARD = """
<!-- ROAT_MODULES_DIRECTORY_REGISTRATION_ACTIVE -->
<div class="module-card"><span class="badge twin">UMBRELLA FLAGSHIP</span><h3>Regulated Operations Assurance Twin™</h3><p>Top-level platform concept that connects governance digital twin, reconciliation, dependency validation, decision logic, DR recovery governance, maturity scoring, passport factory, and portable assurance passports into one regulated-operations assurance model.</p><a href="/regulated-operations-assurance-twin">Open Assurance Twin</a></div>
"""

def main():
    if not APP_FILE.exists():
        raise SystemExit("ERROR: app.py was not found in the current folder.")

    text = APP_FILE.read_text(encoding="utf-8")

    if ACTIVE_MARKER in text:
        print("SKIP: Regulated Operations Assurance Twin is already registered in the Modules Directory.")
        return

    updated = text

    if ".twin{background:#ede9fe;color:#6d28d9}" not in updated:
        if ".assurance{background:#ecfeff;color:#0e7490}" in updated:
            updated = updated.replace(
                ".assurance{background:#ecfeff;color:#0e7490}",
                ".assurance{background:#ecfeff;color:#0e7490}" + TWIN_CSS,
                1
            )
        elif ".recovery{background:#eef2ff;color:#4338ca}" in updated:
            updated = updated.replace(
                ".recovery{background:#eef2ff;color:#4338ca}",
                ".recovery{background:#eef2ff;color:#4338ca}" + TWIN_CSS,
                1
            )
        else:
            raise SystemExit("ERROR: Could not find Modules Directory CSS anchor.")

    if ASSURANCE_SECTION_ANCHOR not in updated:
        raise SystemExit("ERROR: Could not find Assurance Product Stack section anchor.")

    updated = updated.replace(
        ASSURANCE_SECTION_ANCHOR,
        ASSURANCE_SECTION_ANCHOR + ROAT_CARD,
        1
    )

    required_markers = [
        ACTIVE_MARKER,
        ".twin{background:#ede9fe;color:#6d28d9}",
        "Regulated Operations Assurance Twin™",
        'href="/regulated-operations-assurance-twin"',
        "UMBRELLA FLAGSHIP",
        "Top-level platform concept",
        "Enterprise Assurance Passport Factory™",
        "COBIT-Chain Maturity Scorecard™",
        "Governance Assurance Passport™",
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: Regulated Operations Assurance Twin registered safely in Modules Directory.")
    print("VERIFIED: umbrella flagship card and route link found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
