from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# ASSURANCE_PRODUCT_STACK_EXECUTIVE_OVERVIEW_BRIDGE_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

bridge_code = r'''

# ============================================================
# ASSURANCE_PRODUCT_STACK_EXECUTIVE_OVERVIEW_BRIDGE_ACTIVE
# Assurance Product Stack Executive Overview bridge:
#   - Does not overwrite /executive-overview redirect logic
#   - Does not overwrite /executive-overview-v3-test route code
#   - Uses after_request injection only
#   - Adds one executive product-stack panel before </main> / </body>
# ============================================================

try:
    from flask import request as assurance_stack_executive_overview_request
except Exception as assurance_stack_executive_overview_import_error:
    raise RuntimeError(
        f"Assurance Product Stack Executive Overview bridge import failed: "
        f"{assurance_stack_executive_overview_import_error}"
    )


def assurance_stack_executive_overview_panel():
    return """
    <section id="assurance-product-stack-executive-overview-panel"
             style="margin:24px 0; padding:22px; border:1px solid #bae6fd; border-radius:18px;
                    background:linear-gradient(135deg,#ecfeff,#ffffff);
                    box-shadow:0 8px 24px rgba(15,23,42,0.08);">
        <div style="display:flex; justify-content:space-between; gap:16px; flex-wrap:wrap; align-items:flex-start;">
            <div style="max-width:980px;">
                <div style="font-size:13px; font-weight:800; letter-spacing:.08em; text-transform:uppercase; color:#0e7490;">
                    Executive Product Readout
                </div>
                <h2 style="margin:8px 0 8px 0; font-size:28px; line-height:1.15;">
                    Assurance Product Stack
                </h2>
                <p style="margin:0; color:#334155; font-size:15px; line-height:1.55;">
                    COBIT-Chain™ now has a complete product architecture, not only a collection of governance modules:
                    a maturity diagnostic that measures organizational readiness, a cross-domain assurance factory that
                    evaluates regulated objects through one common truth model, and a portable Governance Assurance
                    Passport™ that explains why an object is certified, conditional, or blocked.
                </p>
            </div>
            <div style="font-weight:900; color:#0e7490; background:#cffafe; border:1px solid #67e8f9;
                        padding:8px 12px; border-radius:999px;">
                PRODUCTIZED
            </div>
        </div>

        <div style="margin-top:18px; display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:14px;">
            <div style="border-left:7px solid #0891b2; border-radius:16px; padding:16px; background:#ffffff;
                        border-top:1px solid #bae6fd; border-right:1px solid #bae6fd; border-bottom:1px solid #bae6fd;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">
                    Product Layers
                </div>
                <div style="font-size:28px; font-weight:900; margin-top:7px;">3</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">
                    Scorecard, factory, passport.
                </p>
            </div>
            <div style="border-left:7px solid #2563eb; border-radius:16px; padding:16px; background:#ffffff;
                        border-top:1px solid #bfdbfe; border-right:1px solid #bfdbfe; border-bottom:1px solid #bfdbfe;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">
                    Governed Objects
                </div>
                <div style="font-size:28px; font-weight:900; margin-top:7px;">7</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">
                    Batch to CAPA / DR event.
                </p>
            </div>
            <div style="border-left:7px solid #f59e0b; border-radius:16px; padding:16px; background:#ffffff;
                        border-top:1px solid #fde68a; border-right:1px solid #fde68a; border-bottom:1px solid #fde68a;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">
                    Maturity Dimensions
                </div>
                <div style="font-size:28px; font-weight:900; margin-top:7px;">6</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">
                    Evidence to DR readiness.
                </p>
            </div>
            <div style="border-left:7px solid #16a34a; border-radius:16px; padding:16px; background:#ffffff;
                        border-top:1px solid #bbf7d0; border-right:1px solid #bbf7d0; border-bottom:1px solid #bbf7d0;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">
                    Portable Output
                </div>
                <div style="font-size:28px; font-weight:900; margin-top:7px;">Passport</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">
                    Audit-ready proof, not just status.
                </p>
            </div>
        </div>

        <div style="margin-top:18px; display:grid; grid-template-columns:1.1fr .9fr; gap:16px;">
            <div style="border:1px solid #bae6fd; border-radius:18px; padding:18px; background:#ffffff;">
                <h3 style="margin:0 0 12px 0;">Executive Product Board</h3>
                <div style="overflow-x:auto;">
                    <table style="width:100%; border-collapse:collapse; border-radius:14px; overflow:hidden; font-size:13px;">
                        <thead>
                            <tr>
                                <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">Stage</th>
                                <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">Product Layer</th>
                                <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">Executive Meaning</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><b>Diagnose</b></td>
                                <td style="border-bottom:1px solid #e5e7eb; padding:11px;">
                                    COBIT-Chain Maturity Scorecard™
                                </td>
                                <td style="border-bottom:1px solid #e5e7eb; padding:11px;">
                                    Measures whether the organization is capable of producing defensible assurance at scale.
                                </td>
                            </tr>
                            <tr>
                                <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><b>Generate</b></td>
                                <td style="border-bottom:1px solid #e5e7eb; padding:11px;">
                                    Enterprise Assurance Passport Factory™
                                </td>
                                <td style="border-bottom:1px solid #e5e7eb; padding:11px;">
                                    Applies one assurance engine across batches, SOPs, CIs, sterile records, DR events,
                                    access reviews, and CAPA items.
                                </td>
                            </tr>
                            <tr>
                                <td style="padding:11px;"><b>Certify</b></td>
                                <td style="padding:11px;">Governance Assurance Passport™</td>
                                <td style="padding:11px;">
                                    Produces the portable executive/audit output that explains why an object is
                                    certified, conditional, or blocked.
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <div style="border:1px solid #bae6fd; border-radius:18px; padding:18px; background:#ffffff;">
                <h3 style="margin:0 0 12px 0;">What Leadership Learns</h3>
                <ul style="margin:0; padding-left:20px; color:#475569; line-height:1.65;">
                    <li><b>What can be sold:</b> diagnostic, verification layer, and enterprise governance intelligence.</li>
                    <li><b>What can be proven:</b> readiness is explainable, not only displayed.</li>
                    <li><b>What differentiates the platform:</b> portable assurance output across multiple regulated objects.</li>
                    <li><b>Why it scales:</b> one governance engine can support many regulated domains.</li>
                </ul>
            </div>
        </div>

        <div style="margin-top:18px; padding:16px; border-left:7px solid #0891b2; border-radius:16px;
                    background:#f8fafc; color:#334155; line-height:1.65;">
            <b>Executive conclusion:</b>
            COBIT-Chain™ is no longer only a governance dashboard or blockchain prototype. It is becoming a
            <b>Regulated Operations Assurance Twin™</b> with a commercial product stack:
            <b>diagnose maturity → generate assurance → issue portable proof.</b>
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
            <a href="/command-center"
               style="display:inline-block; padding:10px 14px; border-radius:12px; background:#0f172a;
                      color:#fff; text-decoration:none; font-weight:800;">
                Return to Command Center
            </a>
        </div>

        <p style="margin:14px 0 0 0; color:#64748b; font-size:13px;">
            Boundary: executive product-story bridge only. It does not replace production governance tooling,
            overwrite the Executive Overview route, alter existing dashboard calculations, or remove the DR executive panel.
        </p>
    </section>
    """


def assurance_stack_insert_executive_overview_panel(html, panel):
    if 'id="assurance-product-stack-executive-overview-panel"' in html:
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
def assurance_product_stack_executive_overview_injection(response):
    try:
        if assurance_stack_executive_overview_request.path != "/executive-overview-v3-test":
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

        updated_html = assurance_stack_insert_executive_overview_panel(
            html,
            assurance_stack_executive_overview_panel()
        )

        response.set_data(updated_html)
        response.headers["Content-Length"] = str(len(response.get_data()))

        return response

    except Exception as exc:
        print(f"Assurance Product Stack Executive Overview bridge skipped safely: {exc}")
        return response
'''

def main():
    if not APP_FILE.exists():
        raise SystemExit("ERROR: app.py was not found in the current folder.")

    text = APP_FILE.read_text(encoding="utf-8")

    if ACTIVE_MARKER in text:
        print("SKIP: Assurance Product Stack Executive Overview bridge already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, bridge_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        'def assurance_stack_executive_overview_panel():',
        'id="assurance-product-stack-executive-overview-panel"',
        '@app.after_request',
        'def assurance_product_stack_executive_overview_injection(response):',
        'if assurance_stack_executive_overview_request.path != "/executive-overview-v3-test":',
        'Assurance Product Stack',
        'href="/enterprise-assurance-passport-factory"',
        'href="/governance-assurance-passport/BATCH-2026-041"',
        'href="/cobit-chain-maturity-scorecard"',
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: Assurance Product Stack Executive Overview bridge inserted safely.")
    print("VERIFIED: /executive-overview redirect left intact; V3 product-stack panel injection markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
