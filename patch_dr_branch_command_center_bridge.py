from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# DR_BRANCH_COMMAND_CENTER_BRIDGE_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

bridge_code = r'''

# ============================================================
# DR_BRANCH_COMMAND_CENTER_BRIDGE_ACTIVE
# Operational Recovery Governance / DR Digital Twin
# Safe Command Center bridge:
#   - Does not overwrite the protected /command-center route
#   - Uses after_request injection only
#   - Adds one DR enterprise capability panel before </main> / </body>
# ============================================================

try:
    from flask import request as dr_command_center_request
except Exception as dr_command_center_import_error:
    raise RuntimeError(f"DR Command Center bridge import failed: {dr_command_center_import_error}")


def dr_command_center_panel():
    return """
    <section id="dr-operational-recovery-command-center-panel"
             style="margin:24px 0; padding:22px; border:1px solid #bfdbfe; border-radius:18px;
                    background:linear-gradient(135deg,#eff6ff,#ffffff);
                    box-shadow:0 8px 24px rgba(15,23,42,0.08);">
        <div style="display:flex; justify-content:space-between; gap:16px; flex-wrap:wrap; align-items:flex-start;">
            <div style="max-width:980px;">
                <div style="font-size:13px; font-weight:800; letter-spacing:.08em; text-transform:uppercase; color:#1d4ed8;">
                    Enterprise Capability
                </div>
                <h2 style="margin:8px 0 8px 0; font-size:28px; line-height:1.15;">
                    Operational Recovery Governance / DR Digital Twin
                </h2>
                <p style="margin:0; color:#334155; font-size:15px; line-height:1.55;">
                    A complete disaster-recovery governance branch that tracks the full controlled path from
                    activation to recovery thresholds, dependency truth, audit-ready evidence, GMP restart permission,
                    executive mission control, and final recovery certification. It proves that a system being restored
                    is not the same as the enterprise being ready to resume regulated work.
                </p>
            </div>
            <div style="font-weight:900; color:#1d4ed8; background:#dbeafe; border:1px solid #93c5fd;
                        padding:8px 12px; border-radius:999px;">
                LIVE
            </div>
        </div>

        <div style="margin-top:18px; display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:14px;">
            <div style="border:1px solid #dbeafe; border-radius:16px; padding:16px; background:#ffffff;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">Branch</div>
                <div style="font-size:22px; font-weight:900; margin-top:7px;">7 Modules</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">End-to-end DR governance chain.</p>
            </div>
            <div style="border:1px solid #dbeafe; border-radius:16px; padding:16px; background:#ffffff;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">Core Distinction</div>
                <div style="font-size:22px; font-weight:900; margin-top:7px;">Restore ≠ Ready</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">Technical restore is tested against governance truth.</p>
            </div>
            <div style="border:1px solid #dbeafe; border-radius:16px; padding:16px; background:#ffffff;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">Command View</div>
                <div style="font-size:22px; font-weight:900; margin-top:7px;">Recovery Twin</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">Leadership sees blockers, evidence gaps, and restart holds.</p>
            </div>
            <div style="border:1px solid #dbeafe; border-radius:16px; padding:16px; background:#ffffff;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">Final Outcome</div>
                <div style="font-size:22px; font-weight:900; margin-top:7px;">Certified Closure</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">Recovery closes only when the chain is defensible.</p>
            </div>
        </div>

        <div style="margin-top:18px; overflow-x:auto;">
            <table style="width:100%; border-collapse:collapse; border-radius:14px; overflow:hidden; font-size:13px;">
                <thead>
                    <tr>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">Module</th>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">Route</th>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">Decision Value</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><b>DR Activation Intelligence™</b></td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">/dr-activation-intelligence</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Determines when an incident becomes formal DR.</td>
                    </tr>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><b>RTO / RPO Governance Intelligence™</b></td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">/rto-rpo-governance-intelligence</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Shows threshold drift, breach severity, and escalation need.</td>
                    </tr>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><b>Recovery Dependency Validation™</b></td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">/recovery-dependency-validation</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Prevents false closure after only technical restore.</td>
                    </tr>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><b>DR Evidence Passport™</b></td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">/dr-evidence-passport</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Builds the controlled recovery evidence spine.</td>
                    </tr>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><b>GMP Restart Gate™</b></td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">/gmp-restart-gate</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Separates restored systems from restart permission.</td>
                    </tr>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><b>Recovery Governance Command Center™</b></td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">/recovery-governance-command-center</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Unifies the recovery estate into one executive posture.</td>
                    </tr>
                    <tr>
                        <td style="padding:11px;"><b>DR Recovery Certificate™</b></td>
                        <td style="padding:11px;">/dr-recovery-certificate</td>
                        <td style="padding:11px;">Issues final audit-defensible closure only when all gates agree.</td>
                    </tr>
                </tbody>
            </table>
        </div>

        <div style="display:flex; flex-wrap:wrap; gap:10px; margin-top:18px;">
            <a href="/recovery-governance-command-center"
               style="display:inline-block; padding:10px 14px; border-radius:12px; background:#1d4ed8;
                      color:#fff; text-decoration:none; font-weight:800;">
                Open Recovery Command Center
            </a>
            <a href="/dr-recovery-certificate"
               style="display:inline-block; padding:10px 14px; border-radius:12px; background:#0f172a;
                      color:#fff; text-decoration:none; font-weight:800;">
                Open DR Recovery Certificate
            </a>
            <a href="/modules"
               style="display:inline-block; padding:10px 14px; border-radius:12px; background:#0f172a;
                      color:#fff; text-decoration:none; font-weight:800;">
                View Modules Directory
            </a>
            <a href="/monday-demo"
               style="display:inline-block; padding:10px 14px; border-radius:12px; background:#0f172a;
                      color:#fff; text-decoration:none; font-weight:800;">
                View Demo Flow
            </a>
        </div>

        <p style="margin:14px 0 0 0; color:#64748b; font-size:13px;">
            Boundary: enterprise visibility bridge only. This does not overwrite the protected Command Center route,
            replace validated enterprise systems, or create production DR automation.
        </p>
    </section>
    """


def dr_insert_command_center_panel(html, panel):
    if 'id="dr-operational-recovery-command-center-panel"' in html:
        return html

    lower_html = html.lower()

    if "</main>" in lower_html:
        index = lower_html.rfind("</main>")
        return html[:index] + panel + html[index:]

    if "</body>" in lower_html:
        index = lower_html.rfind("</body>")
        return html[:index] + panel + html[index:]

    return html + panel


@app.after_request
def dr_branch_command_center_injection(response):
    try:
        if dr_command_center_request.path != "/command-center":
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

        updated_html = dr_insert_command_center_panel(html, dr_command_center_panel())

        response.set_data(updated_html)
        response.headers["Content-Length"] = str(len(response.get_data()))

        return response

    except Exception as exc:
        print(f"DR Command Center bridge skipped safely: {exc}")
        return response
'''

def main():
    if not APP_FILE.exists():
        raise SystemExit("ERROR: app.py was not found in the current folder.")

    text = APP_FILE.read_text(encoding="utf-8")

    if ACTIVE_MARKER in text:
        print("SKIP: DR Command Center bridge already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, bridge_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        'def dr_command_center_panel():',
        'id="dr-operational-recovery-command-center-panel"',
        '@app.after_request',
        'def dr_branch_command_center_injection(response):',
        'if dr_command_center_request.path != "/command-center":',
        'Operational Recovery Governance / DR Digital Twin',
        'href="/recovery-governance-command-center"',
        'href="/dr-recovery-certificate"',
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: DR Command Center bridge inserted safely.")
    print("VERIFIED: protected /command-center route left intact; DR panel injection markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
