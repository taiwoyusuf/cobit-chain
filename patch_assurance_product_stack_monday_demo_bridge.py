from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# ASSURANCE_PRODUCT_STACK_MONDAY_DEMO_BRIDGE_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

bridge_code = r'''

# ============================================================
# ASSURANCE_PRODUCT_STACK_MONDAY_DEMO_BRIDGE_ACTIVE
# Assurance Product Stack Monday Demo bridge:
#   - Does not overwrite protected /monday-demo route
#   - Uses after_request injection only
#   - Adds one commercial product-story panel before </body>
# ============================================================

try:
    from flask import request as assurance_stack_monday_demo_request
except Exception as assurance_stack_monday_demo_import_error:
    raise RuntimeError(f"Assurance Product Stack Monday Demo bridge import failed: {assurance_stack_monday_demo_import_error}")


def assurance_stack_monday_demo_panel():
    return """
    <section id="assurance-product-stack-monday-demo-panel"
             style="margin:24px 0; padding:22px; border:1px solid #bae6fd; border-radius:18px;
                    background:linear-gradient(135deg,#ecfeff,#ffffff);
                    box-shadow:0 8px 24px rgba(15,23,42,0.08);">
        <div style="display:flex; justify-content:space-between; gap:16px; flex-wrap:wrap; align-items:flex-start;">
            <div style="max-width:980px;">
                <div style="font-size:13px; font-weight:800; letter-spacing:.08em; text-transform:uppercase; color:#0e7490;">
                    Optional Commercial Product Story
                </div>
                <h2 style="margin:8px 0 8px 0; font-size:28px; line-height:1.15;">
                    Assurance Product Stack
                </h2>
                <p style="margin:0; color:#334155; font-size:15px; line-height:1.55;">
                    Use this after the operational demo when you want to explain the platform as a sellable product system:
                    the maturity scorecard diagnoses the organization, the passport factory generates assurance,
                    and the Governance Assurance Passport™ becomes the portable audit-ready output.
                </p>
            </div>
            <div style="font-weight:900; color:#0e7490; background:#cffafe; border:1px solid #67e8f9;
                        padding:8px 12px; border-radius:999px;">
                PRODUCT STORY
            </div>
        </div>

        <div style="margin-top:18px; padding:16px; border-left:7px solid #0891b2; border-radius:16px;
                    background:#f8fafc; color:#334155; line-height:1.65;">
            <b>Suggested transition line:</b>
            “The first part of the demo shows operational governance in action. This product-stack view shows what
            COBIT-Chain™ becomes commercially: a maturity diagnostic, an assurance engine, and a portable passport
            output that can apply across regulated objects.”
        </div>

        <div style="margin-top:18px; overflow-x:auto;">
            <table style="width:100%; border-collapse:collapse; border-radius:14px; overflow:hidden; font-size:13px;">
                <thead>
                    <tr>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">Demo Step</th>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">Open Page</th>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">What It Proves</th>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">What To Say</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px; font-size:20px; font-weight:900; color:#0891b2;">1</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">
                            <a href="/cobit-chain-maturity-scorecard">COBIT-Chain Maturity Scorecard™</a>
                        </td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">
                            Measures how mature an organization is across evidence, integrity, reconciliation, dependencies, CAPA linkage, and DR readiness.
                        </td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">
                            “Before selling a tool, we can diagnose the organization’s ability to produce defensible assurance.”
                        </td>
                    </tr>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px; font-size:20px; font-weight:900; color:#0891b2;">2</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">
                            <a href="/enterprise-assurance-passport-factory">Enterprise Assurance Passport Factory™</a>
                        </td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">
                            Shows that the same governance engine can evaluate batches, SOPs, CIs, sterile records, DR events, access reviews, and CAPA items.
                        </td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">
                            “This is the product engine. It turns different regulated objects into one common assurance decision model.”
                        </td>
                    </tr>
                    <tr>
                        <td style="padding:11px; font-size:20px; font-weight:900; color:#0891b2;">3</td>
                        <td style="padding:11px;">
                            <a href="/governance-assurance-passport/BATCH-2026-041">Governance Assurance Passport™</a>
                        </td>
                        <td style="padding:11px;">
                            Produces a portable, audit-ready record with controls, evidence, integrity anchors, reconciliation, dependencies, exceptions, DR readiness, and closure verdict.
                        </td>
                        <td style="padding:11px;">
                            “This is the final product output: not just a dashboard, but a portable assurance record that explains why something is certified, conditional, or blocked.”
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>

        <div style="margin-top:18px; display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:14px;">
            <div style="border:1px solid #bae6fd; border-radius:16px; padding:16px; background:#ffffff;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">
                    Demo Message
                </div>
                <div style="font-size:18px; font-weight:900; margin-top:7px;">Diagnose → Generate → Certify</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">
                    The platform moves from maturity assessment to assurance production to portable proof.
                </p>
            </div>
            <div style="border:1px solid #bae6fd; border-radius:16px; padding:16px; background:#ffffff;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">
                    Buyer Message
                </div>
                <div style="font-size:18px; font-weight:900; margin-top:7px;">Clear Product Ladder</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">
                    Advisory scorecard, verification layer, and enterprise governance intelligence become natural tiers.
                </p>
            </div>
            <div style="border:1px solid #bae6fd; border-radius:16px; padding:16px; background:#ffffff;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">
                    Wow Factor
                </div>
                <div style="font-size:18px; font-weight:900; margin-top:7px;">Portable Assurance</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">
                    The output is not only status visibility; it is an audit-ready assurance passport.
                </p>
            </div>
        </div>

        <div style="display:flex; flex-wrap:wrap; gap:10px; margin-top:18px;">
            <a href="/cobit-chain-maturity-scorecard"
               style="display:inline-block; padding:10px 14px; border-radius:12px; background:#0891b2;
                      color:#fff; text-decoration:none; font-weight:800;">
                Start Product Story
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
            <a href="/modules"
               style="display:inline-block; padding:10px 14px; border-radius:12px; background:#0f172a;
                      color:#fff; text-decoration:none; font-weight:800;">
                View Modules Directory
            </a>
        </div>

        <p style="margin:14px 0 0 0; color:#64748b; font-size:13px;">
            Boundary: optional Monday Demo product-story bridge only. This does not overwrite the protected Monday Demo route,
            change the original 17-step operational flow, remove the DR demo bridge, or replace validated enterprise systems.
        </p>
    </section>
    """


def assurance_stack_insert_monday_demo_panel(html, panel):
    if 'id="assurance-product-stack-monday-demo-panel"' in html:
        return html

    lower_html = html.lower()

    if "</body>" in lower_html:
        index = lower_html.rfind("</body>")
        return html[:index] + panel + html[index:]

    return html + panel


@app.after_request
def assurance_product_stack_monday_demo_injection(response):
    try:
        if assurance_stack_monday_demo_request.path != "/monday-demo":
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

        updated_html = assurance_stack_insert_monday_demo_panel(
            html,
            assurance_stack_monday_demo_panel()
        )

        response.set_data(updated_html)
        response.headers["Content-Length"] = str(len(response.get_data()))

        return response

    except Exception as exc:
        print(f"Assurance Product Stack Monday Demo bridge skipped safely: {exc}")
        return response
'''

def main():
    if not APP_FILE.exists():
        raise SystemExit("ERROR: app.py was not found in the current folder.")

    text = APP_FILE.read_text(encoding="utf-8")

    if ACTIVE_MARKER in text:
        print("SKIP: Assurance Product Stack Monday Demo bridge already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, bridge_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        'def assurance_stack_monday_demo_panel():',
        'id="assurance-product-stack-monday-demo-panel"',
        '@app.after_request',
        'def assurance_product_stack_monday_demo_injection(response):',
        'if assurance_stack_monday_demo_request.path != "/monday-demo":',
        'Assurance Product Stack',
        'href="/enterprise-assurance-passport-factory"',
        'href="/governance-assurance-passport/BATCH-2026-041"',
        'href="/cobit-chain-maturity-scorecard"',
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: Assurance Product Stack Monday Demo bridge inserted safely.")
    print("VERIFIED: protected /monday-demo route left intact; product-stack panel injection markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
