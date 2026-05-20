from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# DR_BRANCH_EXECUTIVE_OVERVIEW_BRIDGE_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

bridge_code = r'''

# ============================================================
# DR_BRANCH_EXECUTIVE_OVERVIEW_BRIDGE_ACTIVE
# Operational Recovery Governance / DR Digital Twin
# Safe Executive Overview bridge:
#   - Does not overwrite /executive-overview redirect logic
#   - Does not overwrite /executive-overview-v3-test route code
#   - Uses after_request injection only
#   - Adds one leadership DR posture panel before </main> / </body>
# ============================================================

try:
    from flask import request as dr_executive_overview_request
except Exception as dr_executive_overview_import_error:
    raise RuntimeError(f"DR Executive Overview bridge import failed: {dr_executive_overview_import_error}")


def dr_executive_overview_panel():
    return """
    <section id="dr-operational-recovery-executive-overview-panel"
             style="margin:24px 0; padding:22px; border:1px solid #bfdbfe; border-radius:18px;
                    background:linear-gradient(135deg,#eff6ff,#ffffff);
                    box-shadow:0 8px 24px rgba(15,23,42,0.08);">
        <div style="display:flex; justify-content:space-between; gap:16px; flex-wrap:wrap; align-items:flex-start;">
            <div style="max-width:980px;">
                <div style="font-size:13px; font-weight:800; letter-spacing:.08em; text-transform:uppercase; color:#1d4ed8;">
                    Executive Recovery Posture
                </div>
                <h2 style="margin:8px 0 8px 0; font-size:28px; line-height:1.15;">
                    Operational Recovery Governance / DR Digital Twin
                </h2>
                <p style="margin:0; color:#334155; font-size:15px; line-height:1.55;">
                    Leadership view of whether disaster recovery is merely technically restored or truly ready for
                    regulated resumption. This branch links DR activation, RTO/RPO thresholds, dependency truth,
                    evidence readiness, GMP restart permission, command-center visibility, and final recovery certification
                    into one executive decision story.
                </p>
            </div>
            <div style="font-weight:900; color:#1d4ed8; background:#dbeafe; border:1px solid #93c5fd;
                        padding:8px 12px; border-radius:999px;">
                DEMO-SAFE
            </div>
        </div>

        <div style="margin-top:18px; display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:14px;">
            <div style="border-left:7px solid #2563eb; border-radius:16px; padding:16px; background:#ffffff; border-top:1px solid #dbeafe; border-right:1px solid #dbeafe; border-bottom:1px solid #dbeafe;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">Recovery Branch</div>
                <div style="font-size:28px; font-weight:900; margin-top:7px;">7 Modules</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">Full path from activation to certification.</p>
            </div>
            <div style="border-left:7px solid #dc2626; border-radius:16px; padding:16px; background:#ffffff; border-top:1px solid #fecaca; border-right:1px solid #fecaca; border-bottom:1px solid #fecaca;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">Restart Holds</div>
                <div style="font-size:28px; font-weight:900; margin-top:7px; color:#dc2626;">2</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">Illustrative cases where restore ≠ GMP restart.</p>
            </div>
            <div style="border-left:7px solid #f59e0b; border-radius:16px; padding:16px; background:#ffffff; border-top:1px solid #fde68a; border-right:1px solid #fde68a; border-bottom:1px solid #fde68a;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">Evidence Gaps</div>
                <div style="font-size:28px; font-weight:900; margin-top:7px; color:#d97706;">1 Reviewable</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">Recovery proof still incomplete for closure.</p>
            </div>
            <div style="border-left:7px solid #16a34a; border-radius:16px; padding:16px; background:#ffffff; border-top:1px solid #bbf7d0; border-right:1px solid #bbf7d0; border-bottom:1px solid #bbf7d0;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">Certified Closure</div>
                <div style="font-size:28px; font-weight:900; margin-top:7px; color:#16a34a;">2 Issued</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">Illustrative cases fully closed and defensible.</p>
            </div>
        </div>

        <div style="margin-top:18px; display:grid; grid-template-columns:1.15fr .85fr; gap:16px;">
            <div style="border:1px solid #dbeafe; border-radius:18px; padding:18px; background:#ffffff;">
                <h3 style="margin:0 0 12px 0;">Executive Recovery Posture Board</h3>
                <div style="overflow-x:auto;">
                    <table style="width:100%; border-collapse:collapse; border-radius:14px; overflow:hidden; font-size:13px;">
                        <thead>
                            <tr>
                                <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">Recovery Case</th>
                                <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">Current State</th>
                                <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">Leadership Meaning</th>
                                <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><b>LIMS / QC</b></td>
                                <td style="border-bottom:1px solid #e5e7eb; padding:11px; color:#dc2626; font-weight:900;">Restart Hold</td>
                                <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Technical restore exists, but lot-impact and QA gates remain open.</td>
                                <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Escalate to Recovery Command Center</td>
                            </tr>
                            <tr>
                                <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><b>ERP / Supply Chain</b></td>
                                <td style="border-bottom:1px solid #e5e7eb; padding:11px; color:#dc2626; font-weight:900;">Dependency Blocked</td>
                                <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Reconciliation and downstream dependency truth are not complete.</td>
                                <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Keep DR open</td>
                            </tr>
                            <tr>
                                <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><b>Continuous Environmental Monitoring</b></td>
                                <td style="border-bottom:1px solid #e5e7eb; padding:11px; color:#d97706; font-weight:900;">Reviewable</td>
                                <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Nearly ready, but one final evidence/restart condition remains.</td>
                                <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Prepare closure</td>
                            </tr>
                            <tr>
                                <td style="padding:11px;"><b>Filter Integrity Testing</b></td>
                                <td style="padding:11px; color:#16a34a; font-weight:900;">Certified</td>
                                <td style="padding:11px;">Full recovery chain complete, restart approved, closure issued.</td>
                                <td style="padding:11px;">Archive certificate</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <div style="border:1px solid #dbeafe; border-radius:18px; padding:18px; background:#ffffff;">
                <h3 style="margin:0 0 12px 0;">What Leadership Learns</h3>
                <ul style="margin:0; padding-left:20px; color:#475569; line-height:1.65;">
                    <li><b>Restore does not equal readiness.</b> GMP restart needs separate proof.</li>
                    <li><b>Thresholds matter.</b> RTO/RPO drift can become a business and compliance issue.</li>
                    <li><b>Dependency truth matters.</b> One green system can still hide an incomplete recovery estate.</li>
                    <li><b>Closure needs evidence.</b> Final certificates should issue only after the whole chain agrees.</li>
                </ul>
            </div>
        </div>

        <div style="margin-top:18px; display:flex; flex-wrap:wrap; gap:10px;">
            <a href="/recovery-governance-command-center"
               style="display:inline-block; padding:10px 14px; border-radius:12px; background:#1d4ed8;
                      color:#fff; text-decoration:none; font-weight:800;">
                Open Recovery Command Center
            </a>
            <a href="/gmp-restart-gate"
               style="display:inline-block; padding:10px 14px; border-radius:12px; background:#0f172a;
                      color:#fff; text-decoration:none; font-weight:800;">
                Open GMP Restart Gate
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
            Boundary: executive demo-safe posture panel only. It does not replace production DR tooling,
            create operational automation, or change the existing Executive Overview register calculations.
        </p>
    </section>
    """


def dr_insert_executive_overview_panel(html, panel):
    if 'id="dr-operational-recovery-executive-overview-panel"' in html:
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
def dr_branch_executive_overview_injection(response):
    try:
        if dr_executive_overview_request.path != "/executive-overview-v3-test":
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

        updated_html = dr_insert_executive_overview_panel(html, dr_executive_overview_panel())

        response.set_data(updated_html)
        response.headers["Content-Length"] = str(len(response.get_data()))

        return response

    except Exception as exc:
        print(f"DR Executive Overview bridge skipped safely: {exc}")
        return response
'''

def main():
    if not APP_FILE.exists():
        raise SystemExit("ERROR: app.py was not found in the current folder.")

    text = APP_FILE.read_text(encoding="utf-8")

    if ACTIVE_MARKER in text:
        print("SKIP: DR Executive Overview bridge already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, bridge_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        'def dr_executive_overview_panel():',
        'id="dr-operational-recovery-executive-overview-panel"',
        '@app.after_request',
        'def dr_branch_executive_overview_injection(response):',
        'if dr_executive_overview_request.path != "/executive-overview-v3-test":',
        'Operational Recovery Governance / DR Digital Twin',
        'href="/recovery-governance-command-center"',
        'href="/dr-recovery-certificate"',
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: DR Executive Overview bridge inserted safely.")
    print("VERIFIED: /executive-overview redirect left intact; V3 executive panel injection markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
