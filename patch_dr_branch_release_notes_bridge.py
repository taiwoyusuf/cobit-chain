from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# DR_BRANCH_RELEASE_NOTES_BRIDGE_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

bridge_code = r'''

# ============================================================
# DR_BRANCH_RELEASE_NOTES_BRIDGE_ACTIVE
# Operational Recovery Governance / DR Digital Twin
# Safe Release Notes bridge:
#   - Does not overwrite the protected /release-notes route
#   - Uses after_request injection only
#   - Adds one DR release panel before </body>
# ============================================================

try:
    from flask import request as dr_release_notes_request
except Exception as dr_release_notes_import_error:
    raise RuntimeError(f"DR Release Notes bridge import failed: {dr_release_notes_import_error}")


def dr_release_notes_panel():
    return """
    <section id="dr-operational-recovery-release-notes-panel"
             style="margin:24px 0; padding:22px; border:1px solid #bfdbfe; border-radius:18px;
                    background:linear-gradient(135deg,#eff6ff,#ffffff);
                    box-shadow:0 8px 24px rgba(15,23,42,0.08);">
        <div style="display:flex; justify-content:space-between; gap:16px; flex-wrap:wrap; align-items:flex-start;">
            <div style="max-width:980px;">
                <div style="font-size:13px; font-weight:800; letter-spacing:.08em; text-transform:uppercase; color:#1d4ed8;">
                    Release Entry
                </div>
                <h2 style="margin:8px 0 8px 0; font-size:28px; line-height:1.15;">
                    Added: Operational Recovery Governance / DR Digital Twin
                </h2>
                <p style="margin:0; color:#334155; font-size:15px; line-height:1.55;">
                    Added a complete disaster-recovery governance branch that models the full controlled path from
                    DR activation to RTO/RPO intelligence, dependency validation, evidence passports, GMP restart control,
                    recovery command-center visibility, and final recovery certification. This turns recovery from a
                    technical restore event into a governed, evidence-backed enterprise decision chain.
                </p>
            </div>
            <div style="font-weight:900; color:#1d4ed8; background:#dbeafe; border:1px solid #93c5fd;
                        padding:8px 12px; border-radius:999px;">
                LIVE
            </div>
        </div>

        <div style="margin-top:18px; overflow-x:auto;">
            <table style="width:100%; border-collapse:collapse; border-radius:14px; overflow:hidden; font-size:13px;">
                <thead>
                    <tr>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">Component</th>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">Status</th>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">Route</th>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">What It Adds</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><b>DR Activation Intelligence™</b></td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Live</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">/dr-activation-intelligence</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Determines when an incident becomes formal DR.</td>
                    </tr>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><b>RTO / RPO Governance Intelligence™</b></td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Live</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">/rto-rpo-governance-intelligence</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Tracks recovery thresholds, drift, and escalation logic.</td>
                    </tr>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><b>Recovery Dependency Validation™</b></td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Live</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">/recovery-dependency-validation</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Prevents false closure after technical restore.</td>
                    </tr>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><b>DR Evidence Passport™</b></td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Live</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">/dr-evidence-passport</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Creates the controlled evidence spine for recovery.</td>
                    </tr>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><b>GMP Restart Gate™</b></td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Live</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">/gmp-restart-gate</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Separates system restore from regulated restart permission.</td>
                    </tr>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><b>Recovery Governance Command Center™</b></td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Live</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">/recovery-governance-command-center</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Unifies enterprise recovery posture and leadership priority.</td>
                    </tr>
                    <tr>
                        <td style="padding:11px;"><b>DR Recovery Certificate™</b></td>
                        <td style="padding:11px;">Live</td>
                        <td style="padding:11px;">/dr-recovery-certificate</td>
                        <td style="padding:11px;">Issues final audit-defensible closure only when the chain is complete.</td>
                    </tr>
                </tbody>
            </table>
        </div>

        <div style="display:flex; flex-wrap:wrap; gap:10px; margin-top:18px;">
            <a href="/modules"
               style="display:inline-block; padding:10px 14px; border-radius:12px; background:#1d4ed8;
                      color:#fff; text-decoration:none; font-weight:800;">
                View Modules Directory
            </a>
            <a href="/recovery-governance-command-center"
               style="display:inline-block; padding:10px 14px; border-radius:12px; background:#0f172a;
                      color:#fff; text-decoration:none; font-weight:800;">
                Open Recovery Command Center
            </a>
            <a href="/dr-recovery-certificate"
               style="display:inline-block; padding:10px 14px; border-radius:12px; background:#0f172a;
                      color:#fff; text-decoration:none; font-weight:800;">
                Open DR Recovery Certificate
            </a>
            <a href="/platform-health"
               style="display:inline-block; padding:10px 14px; border-radius:12px; background:#0f172a;
                      color:#fff; text-decoration:none; font-weight:800;">
                View Platform Health
            </a>
        </div>

        <p style="margin:14px 0 0 0; color:#64748b; font-size:13px;">
            Boundary: this is a release-note bridge only. It does not overwrite the protected Release Notes route,
            change existing sterile-compounding panels, replace validated enterprise systems, or create production DR automation.
        </p>
    </section>
    """


def dr_insert_release_notes_panel(html, panel):
    if 'id="dr-operational-recovery-release-notes-panel"' in html:
        return html

    lower_html = html.lower()

    if "</body>" in lower_html:
        index = lower_html.rfind("</body>")
        return html[:index] + panel + html[index:]

    return html + panel


@app.after_request
def dr_branch_release_notes_injection(response):
    try:
        if dr_release_notes_request.path != "/release-notes":
            return response

        if response.status_code != 200:
            return response

        content_type = response.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            return response

        if getattr(response, "direct_passthrough", False):
            return response

        html = response.get_data(as_text=True)

        if not html:
            return response

        updated_html = dr_insert_release_notes_panel(html, dr_release_notes_panel())

        response.set_data(updated_html)
        response.headers["Content-Length"] = str(len(response.get_data()))

        return response

    except Exception as exc:
        print(f"DR Release Notes bridge skipped safely: {exc}")
        return response
'''

def main():
    if not APP_FILE.exists():
        raise SystemExit("ERROR: app.py was not found in the current folder.")

    text = APP_FILE.read_text(encoding="utf-8")

    if ACTIVE_MARKER in text:
        print("SKIP: DR Release Notes bridge already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, bridge_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        'def dr_release_notes_panel():',
        'id="dr-operational-recovery-release-notes-panel"',
        '@app.after_request',
        'def dr_branch_release_notes_injection(response):',
        'if dr_release_notes_request.path != "/release-notes":',
        'Added: Operational Recovery Governance / DR Digital Twin',
        'href="/recovery-governance-command-center"',
        'href="/dr-recovery-certificate"',
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: DR Release Notes bridge inserted safely.")
    print("VERIFIED: protected /release-notes route left intact; DR panel injection markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
