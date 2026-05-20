from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# DR_BRANCH_MONDAY_DEMO_BRIDGE_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

bridge_code = r'''

# ============================================================
# DR_BRANCH_MONDAY_DEMO_BRIDGE_ACTIVE
# Operational Recovery Governance / DR Digital Twin
# Safe Monday Demo bridge:
#   - Does not overwrite the protected /monday-demo route
#   - Uses after_request injection only
#   - Adds one optional DR demo panel before </body>
# ============================================================

try:
    from flask import request as dr_monday_demo_request
except Exception as dr_monday_demo_import_error:
    raise RuntimeError(f"DR Monday Demo bridge import failed: {dr_monday_demo_import_error}")


def dr_monday_demo_panel():
    return """
    <section id="dr-operational-recovery-monday-demo-panel"
             style="margin:24px 0; padding:22px; border:1px solid #bfdbfe; border-radius:18px;
                    background:linear-gradient(135deg,#eff6ff,#ffffff);
                    box-shadow:0 8px 24px rgba(15,23,42,0.08);">
        <div style="display:flex; justify-content:space-between; gap:16px; flex-wrap:wrap; align-items:flex-start;">
            <div style="max-width:980px;">
                <div style="font-size:13px; font-weight:800; letter-spacing:.08em; text-transform:uppercase; color:#1d4ed8;">
                    Optional Demo Add-On
                </div>
                <h2 style="margin:8px 0 8px 0; font-size:28px; line-height:1.15;">
                    Operational Recovery Governance / DR Digital Twin
                </h2>
                <p style="margin:0; color:#334155; font-size:15px; line-height:1.55;">
                    Use this after the core Monday flow when you want to show that AssuranceLayer™ can extend beyond
                    ticket-to-audit lineage into full enterprise recovery governance: not just whether a system is back,
                    but whether disaster recovery is justified, whether thresholds failed, whether dependencies are truly
                    complete, whether GMP may restart, and whether recovery can be formally certified.
                </p>
            </div>
            <div style="font-weight:900; color:#1d4ed8; background:#dbeafe; border:1px solid #93c5fd;
                        padding:8px 12px; border-radius:999px;">
                OPTIONAL
            </div>
        </div>

        <div style="margin-top:18px; padding:16px; border-left:7px solid #2563eb; border-radius:16px; background:#f8fafc;
                    color:#334155; line-height:1.65;">
            <b>Suggested opening line:</b>
            “The first demo shows how COBIT-Chain™ governs work while operations are running.
            This second storyline shows what happens when operations are disrupted: the platform can govern the full
            recovery truth from DR activation all the way to restart and certified closure.”
        </div>

        <div style="margin-top:18px; overflow-x:auto;">
            <table style="width:100%; border-collapse:collapse; border-radius:14px; overflow:hidden; font-size:13px;">
                <thead>
                    <tr>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">Step</th>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">Open Page</th>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">What It Proves</th>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">What To Say</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px; font-size:20px; font-weight:900; color:#1d4ed8;">1</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><a href="/dr-activation-intelligence">DR Activation Intelligence™</a></td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Incident-to-disaster decision logic.</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">“The platform first decides whether this is still an incident or whether formal DR governance must activate.”</td>
                    </tr>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px; font-size:20px; font-weight:900; color:#1d4ed8;">2</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><a href="/rto-rpo-governance-intelligence">RTO / RPO Governance Intelligence™</a></td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Threshold drift and escalation logic.</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">“Now it evaluates whether time loss or data loss has crossed the point where recovery becomes a governance problem, not just a technical issue.”</td>
                    </tr>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px; font-size:20px; font-weight:900; color:#1d4ed8;">3</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><a href="/recovery-dependency-validation">Recovery Dependency Validation™</a></td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Prevents false closure after technical restore.</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">“A server being restored does not prove recovery is complete. We test reconciliation, QA, downstream dependencies, and approval truth.”</td>
                    </tr>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px; font-size:20px; font-weight:900; color:#1d4ed8;">4</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><a href="/dr-evidence-passport">DR Evidence Passport™</a></td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Audit-ready recovery evidence spine.</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">“The recovery evidence is not scattered across emails and folders; it becomes a governed passport with the required artifacts.”</td>
                    </tr>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px; font-size:20px; font-weight:900; color:#1d4ed8;">5</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><a href="/gmp-restart-gate">GMP Restart Gate™</a></td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Separates restore from regulated restart.</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">“This is the strongest distinction: system restored does not automatically mean GMP operations may resume.”</td>
                    </tr>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px; font-size:20px; font-weight:900; color:#1d4ed8;">6</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><a href="/recovery-governance-command-center">Recovery Governance Command Center™</a></td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Executive digital twin of the recovery estate.</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">“Leadership sees active DR events, threshold breaches, evidence gaps, blocked restart gates, and who must act first.”</td>
                    </tr>
                    <tr>
                        <td style="padding:11px; font-size:20px; font-weight:900; color:#1d4ed8;">7</td>
                        <td style="padding:11px;"><a href="/dr-recovery-certificate">DR Recovery Certificate™</a></td>
                        <td style="padding:11px;">Final audit-defensible recovery closure.</td>
                        <td style="padding:11px;">“Recovery is not closed because someone says it is restored; it is closed only when the complete governed chain is proven.”</td>
                    </tr>
                </tbody>
            </table>
        </div>

        <div style="margin-top:18px; display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:14px;">
            <div style="border:1px solid #dbeafe; border-radius:16px; padding:16px; background:#ffffff;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">Best Audience</div>
                <div style="font-size:18px; font-weight:900; margin-top:7px;">IT / QA / Leadership</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">Useful when explaining business continuity, GMP restart control, audit readiness, or enterprise resilience.</p>
            </div>
            <div style="border:1px solid #dbeafe; border-radius:16px; padding:16px; background:#ffffff;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">Core Message</div>
                <div style="font-size:18px; font-weight:900; margin-top:7px;">Restore ≠ Ready</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">The platform proves the difference between technical recovery, governance recovery, and permission to resume regulated work.</p>
            </div>
            <div style="border:1px solid #dbeafe; border-radius:16px; padding:16px; background:#ffffff;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">Wow Factor</div>
                <div style="font-size:18px; font-weight:900; margin-top:7px;">Recovery Digital Twin</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">It turns DR from a document exercise into an executable, explainable, evidence-backed decision chain.</p>
            </div>
        </div>

        <div style="display:flex; flex-wrap:wrap; gap:10px; margin-top:18px;">
            <a href="/recovery-governance-command-center"
               style="display:inline-block; padding:10px 14px; border-radius:12px; background:#1d4ed8;
                      color:#fff; text-decoration:none; font-weight:800;">
                Start DR Demo
            </a>
            <a href="/dr-recovery-certificate"
               style="display:inline-block; padding:10px 14px; border-radius:12px; background:#0f172a;
                      color:#fff; text-decoration:none; font-weight:800;">
                Open Final Certificate
            </a>
            <a href="/modules"
               style="display:inline-block; padding:10px 14px; border-radius:12px; background:#0f172a;
                      color:#fff; text-decoration:none; font-weight:800;">
                View Modules Directory
            </a>
        </div>

        <p style="margin:14px 0 0 0; color:#64748b; font-size:13px;">
            Boundary: optional demo add-on only. This does not overwrite the protected Monday Demo route,
            replace validated enterprise systems, or alter the original 17-step operational-lineage presentation path.
        </p>
    </section>
    """


def dr_insert_monday_demo_panel(html, panel):
    if 'id="dr-operational-recovery-monday-demo-panel"' in html:
        return html

    lower_html = html.lower()

    if "</body>" in lower_html:
        index = lower_html.rfind("</body>")
        return html[:index] + panel + html[index:]

    return html + panel


@app.after_request
def dr_branch_monday_demo_injection(response):
    try:
        if dr_monday_demo_request.path != "/monday-demo":
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

        updated_html = dr_insert_monday_demo_panel(html, dr_monday_demo_panel())

        response.set_data(updated_html)
        response.headers["Content-Length"] = str(len(response.get_data()))

        return response

    except Exception as exc:
        print(f"DR Monday Demo bridge skipped safely: {exc}")
        return response
'''

def main():
    if not APP_FILE.exists():
        raise SystemExit("ERROR: app.py was not found in the current folder.")

    text = APP_FILE.read_text(encoding="utf-8")

    if ACTIVE_MARKER in text:
        print("SKIP: DR Monday Demo bridge already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, bridge_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        'def dr_monday_demo_panel():',
        'id="dr-operational-recovery-monday-demo-panel"',
        '@app.after_request',
        'def dr_branch_monday_demo_injection(response):',
        'if dr_monday_demo_request.path != "/monday-demo":',
        'Operational Recovery Governance / DR Digital Twin',
        'href="/recovery-governance-command-center"',
        'href="/dr-recovery-certificate"',
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: DR Monday Demo bridge inserted safely.")
    print("VERIFIED: protected /monday-demo route left intact; DR panel injection markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
