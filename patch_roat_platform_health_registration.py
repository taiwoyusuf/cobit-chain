from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# ROAT_PLATFORM_HEALTH_REGISTRATION_ACTIVE"

PRIMARY_ANCHOR = '''        # ASSURANCE_PRODUCT_STACK_PLATFORM_HEALTH_ACTIVE'''
FALLBACK_ANCHOR = '''        # DR_BRANCH_PLATFORM_HEALTH_ACTIVE'''

ROAT_PLATFORM_HEALTH_BLOCK = '''        # ROAT_PLATFORM_HEALTH_REGISTRATION_ACTIVE
        {
            "tier": "Assurance Product Stack",
            "module": "Regulated Operations Assurance Twin™",
            "route": "/regulated-operations-assurance-twin",
            "test_route": "",
            "register": "COMPOSITE_VIEW:regulated-operations-assurance-twin",
            "purpose": "Umbrella flagship capability that connects governance digital twin, reconciliation, dependency validation, decision logic, DR recovery governance, maturity scoring, passport factory, and portable assurance passports into one regulated-operations assurance model."
        },
'''

def main():
    if not APP_FILE.exists():
        raise SystemExit("ERROR: app.py was not found in the current folder.")

    text = APP_FILE.read_text(encoding="utf-8")

    if ACTIVE_MARKER in text:
        print("SKIP: Regulated Operations Assurance Twin is already registered in Platform Health.")
        return

    if PRIMARY_ANCHOR in text:
        updated = text.replace(
            PRIMARY_ANCHOR,
            ROAT_PLATFORM_HEALTH_BLOCK + PRIMARY_ANCHOR,
            1
        )
    elif FALLBACK_ANCHOR in text:
        updated = text.replace(
            FALLBACK_ANCHOR,
            ROAT_PLATFORM_HEALTH_BLOCK + FALLBACK_ANCHOR,
            1
        )
    else:
        raise SystemExit("ERROR: Could not find Platform Health insertion anchor.")

    required_markers = [
        ACTIVE_MARKER,
        '"tier": "Assurance Product Stack"',
        '"module": "Regulated Operations Assurance Twin™"',
        '"route": "/regulated-operations-assurance-twin"',
        '"register": "COMPOSITE_VIEW:regulated-operations-assurance-twin"',
        "Umbrella flagship capability",
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: Regulated Operations Assurance Twin registered safely in Platform Health.")
    print("VERIFIED: umbrella flagship Platform Health row and route link found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
