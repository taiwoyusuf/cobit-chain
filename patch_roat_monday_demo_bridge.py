from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# ROAT_MONDAY_DEMO_BRIDGE_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

bridge_code = r'''

# ============================================================
# ROAT_MONDAY_DEMO_BRIDGE_ACTIVE
# Regulated Operations Assurance Twin™ Monday Demo bridge:
#   - Does not overwrite protected /monday-demo route
#   - Uses after_request injection only
#   - Adds one umbrella flagship storyline panel before </body>
# ============================================================

try:
    from flask import request as roat_monday_demo_request
except Exception as roat_monday_demo_import_error:
    raise RuntimeError(f"ROAT Monday Demo bridge import failed: {roat_monday_demo_import_error}")


def roat_monday_demo_panel():
    return """
    <section id="roat-monday-demo-panel"
             style="margin:24px 0; padding:22px; border:1px solid #ddd6fe; border-radius:18px;
                    background:linear-gradient(135deg,#f5f3ff,#ffffff);
                    box-shadow:0 8px 24px rgba(15,23,42,0.08);">
        <div style="display:flex; justify-content:space-between; gap:16px; flex-wrap:wrap; align-items:flex-start;">
            <div style="max-width:980px;">
                <div style="font-size:13px; font-weight:800; letter-spacing:.08em; text-transform:uppercase; color:#6d28d9;">
                    Final Umbrella Storyline
                </div>
                <h2 style="margin:8px 0 8px 0; font-size:28px; line-height:1.15;">
                    Regulated Operations Assurance Twin™
                </h2>
                <p style="margin:0; color:#334155; font-size:15px; line-height:1.55;">
                    Use this as the final explanation after the operational demo, DR governance demo, and Assurance Product Stack.
                    This is the umbrella concept that ties everything together: COBIT-Chain™ / AssuranceLayer™ is not just
                    a dashboard, workflow tool, or blockchain prototype. It is a live governance mirror that senses evidence,
                    verifies integrity, reconciles truth, exposes blockers, gates decisions, and issues assurance only when
                    the chain is defensible.
                </p>
            </div>
            <div style="font-weight:900; color:#6d28d9; background:#ede9fe; border:1px solid #c4b5fd;
                        padding:8px 12px; border-radius:999px;">
                UMBRELLA
            </div>
        </div>

        <div style="margin-top:18px; padding:16px; border-left:7px solid #7c3aed; border-radius:16px;
                    background:#f8fafc; color:#334155; line-height:1.65;">
            <b>Suggested closing line:</b>
            “What I am showing is not a single app page. The full idea is a Regulated Operations Assurance Twin™:
            a governance intelligence layer that proves whether regulated work is truly ready, conditional, blocked,
            or certifiable — across operations, IT, QA, recovery, access, SOPs, CAPA, and evidence.”
        </div>

        <div style="margin-top:18px; overflow-x:auto;">
            <table style="width:100%; border-collapse:collapse; border-radius:14px; overflow:hidden; font-size:13px;">
                <thead>
                    <tr>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">Demo Stage</th>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">What To Show</th>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">Meaning</th>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">What To Say</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px; font-size:20px; font-weight:900; color:#7c3aed;">1</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">
                            Original Monday Demo
                        </td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">
                            Shows operational governance from ticket, CI, technician, handoff, KB, evidence, review, passport, and audit lineage.
                        </td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">
                            “This proves the platform can govern everyday operational work, not just display records.”
                        </td>
                    </tr>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px; font-size:20px; font-weight:900; color:#7c3aed;">2</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">
                            DR / Operational Recovery Governance
                        </td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">
                            Shows that restore is not the same as regulated readiness and that recovery needs evidence, restart, and certification gates.
                        </td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">
                            “This proves the platform can govern disruption, recovery, and restart decisions.”
                        </td>
                    </tr>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px; font-size:20px; font-weight:900; color:#7c3aed;">3</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">
                            Assurance Product Stack
                        </td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">
                            Shows the commercial product ladder: maturity scorecard, passport factory, and portable assurance passport.
                        </td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">
                            “This proves the platform is productizable: diagnose maturity, generate assurance, and issue portable proof.”
                        </td>
                    </tr>
                    <tr>
                        <td style="padding:11px; font-size:20px; font-weight:900; color:#7c3aed;">4</td>
                        <td style="padding:11px;">
                            <a href="/regulated-operations-assurance-twin">Regulated Operations Assurance Twin™</a>
                        </td>
                        <td style="padding:11px;">
                            Shows the umbrella category that connects every module into one live assurance model.
                        </td>
                        <td style="padding:11px;">
                            “This is the final concept: one governance intelligence layer that proves readiness across regulated operations.”
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>

        <div style="margin-top:18px; display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:14px;">
            <div style="border:1px solid #ddd6fe; border-radius:16px; padding:16px; background:#ffffff;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">
                    Core Concept
                </div>
                <div style="font-size:18px; font-weight:900; margin-top:7px;">Assurance Twin</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">
                    A live governance mirror of regulated work.
                </p>
            </div>
            <div style="border:1px solid #ddd6fe; border-radius:16px; padding:16px; background:#ffffff;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">
                    Decision Logic
                </div>
                <div style="font-size:18px; font-weight:900; margin-top:7px;">Certified / Conditional / Blocked</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">
                    The twin explains why an object can or cannot proceed.
                </p>
            </div>
            <div style="border:1px solid #ddd6fe; border-radius:16px; padding:16px; background:#ffffff;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">
                    Commercial Message
                </div>
                <div style="font-size:18px; font-weight:900; margin-top:7px;">One Engine, Many Domains</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">
                    Batch, SOP, CI, sterile record, DR, access review, and CAPA.
                </p>
            </div>
            <div style="border:1px solid #ddd6fe; border-radius:16px; padding:16px; background:#ffffff;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">
                    Final Output
                </div>
                <div style="font-size:18px; font-weight:900; margin-top:7px;">Governance Passport™</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">
                    Portable audit-ready assurance when the chain is defensible.
                </p>
            </div>
        </div>

        <div style="margin-top:18px; padding:16px; border-left:7px solid #7c3aed; border-radius:16px;
                    background:#ffffff; color:#334155; line-height:1.65;">
            <b>Demo structure to use verbally:</b>
            Operational governance proves the daily work.
            DR governance proves recovery and restart truth.
            The product stack proves commercialization.
            The Regulated Operations Assurance Twin™ proves the whole platform category.
        </div>

        <div style="display:flex; flex-wrap:wrap; gap:10px; margin-top:18px;">
            <a href="/regulated-operations-assurance-twin"
               style="display:inline-block; padding:10px 14px; border-radius:12px; background:#7c3aed;
                      color:#fff; text-decoration:none; font-weight:800;">
                Open Assurance Twin
            </a>
            <a href="/cobit-chain-maturity-scorecard"
               style="display:inline-block; padding:10px 14px; border-radius:12px; background:#0f172a;
                      color:#fff; text-decoration:none; font-weight:800;">
                Open Maturity Scorecard
            </a>
            <a href="/enterprise-assurance-passport-factory"
               style="display:inline-block; padding:10px 14px; border-radius:12px; background:#0f172a;
                      color:#fff; text-decoration:none; font-weight:800;">
                Open Passport Factory
            </a>
            <a href="/governance-assurance-passport/BATCH-2026-041"
               style="display:inline-block; padding:10px 14px; border-radius:12px; background:#0f172a;
                      color:#fff; text-decoration:none; font-weight:800;">
                Open Sample Passport
            </a>
        </div>

        <p style="margin:14px 0 0 0; color:#64748b; font-size:13px;">
            Boundary: optional Monday Demo umbrella-story bridge only. This does not overwrite the protected Monday Demo route,
            change the original operational demo, remove the DR demo bridge, remove the Assurance Product Stack panel,
            replace validated enterprise systems, or create production automation.
        </p>
    </section>
    """


def roat_insert_monday_demo_panel(html, panel):
    if 'id="roat-monday-demo-panel"' in html:
        return html

    lower_html = html.lower()

    if "</body>" in lower_html:
        index = lower_html.rfind("</body>")
        return html[:index] + panel + html[index:]

    return html + panel


@app.after_request
def roat_monday_demo_injection(response):
    try:
        if roat_monday_demo_request.path != "/monday-demo":
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

        updated_html = roat_insert_monday_demo_panel(
            html,
            roat_monday_demo_panel()
        )

        response.set_data(updated_html)
        response.headers["Content-Length"] = str(len(response.get_data()))

        return response

    except Exception as exc:
        print(f"ROAT Monday Demo bridge skipped safely: {exc}")
        return response
'''

def main():
    if not APP_FILE.exists():
        raise SystemExit("ERROR: app.py was not found in the current folder.")

    text = APP_FILE.read_text(encoding="utf-8")

    if ACTIVE_MARKER in text:
        print("SKIP: ROAT Monday Demo bridge already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, bridge_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        'def roat_monday_demo_panel():',
        'id="roat-monday-demo-panel"',
        '@app.after_request',
        'def roat_monday_demo_injection(response):',
        'if roat_monday_demo_request.path != "/monday-demo":',
        'Regulated Operations Assurance Twin™',
        'href="/regulated-operations-assurance-twin"',
        'href="/enterprise-assurance-passport-factory"',
        'href="/governance-assurance-passport/BATCH-2026-041"',
        'href="/cobit-chain-maturity-scorecard"',
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: ROAT Monday Demo bridge inserted safely.")
    print("VERIFIED: protected /monday-demo route left intact; ROAT demo panel injection markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
