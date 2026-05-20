from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# ASSURANCE_PRODUCT_STACK_COMMAND_CENTER_BRIDGE_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

bridge_code = r'''

# ============================================================
# ASSURANCE_PRODUCT_STACK_COMMAND_CENTER_BRIDGE_ACTIVE
# Assurance Product Stack Command Center bridge:
#   - Does not overwrite protected /command-center route
#   - Uses after_request injection only
#   - Adds one product-stack enterprise capability panel before </main> / </body>
# ============================================================

try:
    from flask import request as assurance_stack_command_center_request
except Exception as assurance_stack_command_center_import_error:
    raise RuntimeError(f"Assurance Product Stack Command Center bridge import failed: {assurance_stack_command_center_import_error}")


def assurance_stack_command_center_panel():
    return """
    <section id="assurance-product-stack-command-center-panel"
             style="margin:24px 0; padding:22px; border:1px solid #bae6fd; border-radius:18px;
                    background:linear-gradient(135deg,#ecfeff,#ffffff);
                    box-shadow:0 8px 24px rgba(15,23,42,0.08);">
        <div style="display:flex; justify-content:space-between; gap:16px; flex-wrap:wrap; align-items:flex-start;">
            <div style="max-width:980px;">
                <div style="font-size:13px; font-weight:800; letter-spacing:.08em; text-transform:uppercase; color:#0e7490;">
                    Commercial Product Stack
                </div>
                <h2 style="margin:8px 0 8px 0; font-size:28px; line-height:1.15;">
                    Assurance Product Stack
                </h2>
                <p style="margin:0; color:#334155; font-size:15px; line-height:1.55;">
                    The product layer that turns COBIT-Chain™ from a set of governance modules into a sellable,
                    measurable assurance platform. It diagnoses organizational maturity, generates cross-domain assurance,
                    and issues portable Governance Assurance Passports™ only when the control, evidence, integrity,
                    reconciliation, dependency, exception, recovery, and closure chain is defensible.
                </p>
            </div>
            <div style="font-weight:900; color:#0e7490; background:#cffafe; border:1px solid #67e8f9;
                        padding:8px 12px; border-radius:999px;">
                LIVE
            </div>
        </div>

        <div style="margin-top:18px; display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:14px;">
            <div style="border:1px solid #bae6fd; border-radius:16px; padding:16px; background:#ffffff;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">Product Stack</div>
                <div style="font-size:22px; font-weight:900; margin-top:7px;">3 Layers</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">Scorecard, factory, and passport output.</p>
            </div>
            <div style="border:1px solid #bae6fd; border-radius:16px; padding:16px; background:#ffffff;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">Core Message</div>
                <div style="font-size:22px; font-weight:900; margin-top:7px;">Diagnose → Generate → Certify</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">A clear commercial and academic storyline.</p>
            </div>
            <div style="border:1px solid #bae6fd; border-radius:16px; padding:16px; background:#ffffff;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">Output</div>
                <div style="font-size:22px; font-weight:900; margin-top:7px;">Portable Passport</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">Audit-ready assurance record per governed object.</p>
            </div>
            <div style="border:1px solid #bae6fd; border-radius:16px; padding:16px; background:#ffffff;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">Commercial Path</div>
                <div style="font-size:22px; font-weight:900; margin-top:7px;">3 Tiers</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">Assurance Pack → Verification Layer → Governance Intelligence.</p>
            </div>
        </div>

        <div style="margin-top:18px; overflow-x:auto;">
            <table style="width:100%; border-collapse:collapse; border-radius:14px; overflow:hidden; font-size:13px;">
                <thead>
                    <tr>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">Layer</th>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">Route</th>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">Enterprise Value</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><b>COBIT-Chain Maturity Scorecard™</b></td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">/cobit-chain-maturity-scorecard</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">
                            Measures organizational maturity across evidence, integrity, reconciliation, dependencies,
                            exception/CAPA linkage, and DR governance readiness.
                        </td>
                    </tr>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><b>Enterprise Assurance Passport Factory™</b></td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">/enterprise-assurance-passport-factory</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">
                            Converts batches, SOPs, CIs, sterile records, DR events, access reviews, and CAPA items into
                            one common assurance decision model.
                        </td>
                    </tr>
                    <tr>
                        <td style="padding:11px;"><b>Governance Assurance Passport™</b></td>
                        <td style="padding:11px;">/governance-assurance-passport/BATCH-2026-041</td>
                        <td style="padding:11px;">
                            Produces the portable assurance output with control coverage, evidence pack, integrity anchors,
                            reconciliation verdict, dependencies, exceptions, DR readiness, and closure decision.
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>

        <div style="margin-top:18px; padding:16px; border-left:7px solid #0891b2; border-radius:16px; background:#f8fafc;
                    color:#334155; line-height:1.65;">
            <b>Command Center message:</b>
            “This is where COBIT-Chain™ becomes more than a governance dashboard. The platform can assess maturity,
            generate cross-domain assurance, and issue portable audit-ready passports that explain why a governed object
            is certified, conditional, or blocked.”
        </div>

        <div style="display:flex; flex-wrap:wrap; gap:10px; margin-top:18px;">
            <a href="/cobit-chain-maturity-scorecard"
               style="display:inline-block; padding:10px 14px; border-radius:12px; background:#0891b2;
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
            <a href="/modules"
               style="display:inline-block; padding:10px 14px; border-radius:12px; background:#0f172a;
                      color:#fff; text-decoration:none; font-weight:800;">
                View Modules Directory
            </a>
        </div>

        <p style="margin:14px 0 0 0; color:#64748b; font-size:13px;">
            Boundary: enterprise visibility bridge only. This does not overwrite the protected Command Center route,
            remove existing DR panels, replace validated systems, or create production automation.
        </p>
    </section>
    """


def assurance_stack_insert_command_center_panel(html, panel):
    if 'id="assurance-product-stack-command-center-panel"' in html:
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
def assurance_product_stack_command_center_injection(response):
    try:
        if assurance_stack_command_center_request.path != "/command-center":
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

        updated_html = assurance_stack_insert_command_center_panel(
            html,
            assurance_stack_command_center_panel()
        )

        response.set_data(updated_html)
        response.headers["Content-Length"] = str(len(response.get_data()))

        return response

    except Exception as exc:
        print(f"Assurance Product Stack Command Center bridge skipped safely: {exc}")
        return response
'''

def main():
    if not APP_FILE.exists():
        raise SystemExit("ERROR: app.py was not found in the current folder.")

    text = APP_FILE.read_text(encoding="utf-8")

    if ACTIVE_MARKER in text:
        print("SKIP: Assurance Product Stack Command Center bridge already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, bridge_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        'def assurance_stack_command_center_panel():',
        'id="assurance-product-stack-command-center-panel"',
        '@app.after_request',
        'def assurance_product_stack_command_center_injection(response):',
        'if assurance_stack_command_center_request.path != "/command-center":',
        'Assurance Product Stack',
        'href="/enterprise-assurance-passport-factory"',
        'href="/governance-assurance-passport/BATCH-2026-041"',
        'href="/cobit-chain-maturity-scorecard"',
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: Assurance Product Stack Command Center bridge inserted safely.")
    print("VERIFIED: protected /command-center route left intact; product-stack panel injection markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
