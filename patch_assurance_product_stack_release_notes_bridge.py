from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# ASSURANCE_PRODUCT_STACK_RELEASE_NOTES_BRIDGE_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

bridge_code = r'''

# ============================================================
# ASSURANCE_PRODUCT_STACK_RELEASE_NOTES_BRIDGE_ACTIVE
# Assurance Product Stack Release Notes bridge:
#   - Does not overwrite protected /release-notes route
#   - Uses after_request injection only
#   - Adds one product-stack release panel before </body>
# ============================================================

try:
    from flask import request as assurance_stack_release_notes_request
except Exception as assurance_stack_release_notes_import_error:
    raise RuntimeError(f"Assurance Product Stack Release Notes bridge import failed: {assurance_stack_release_notes_import_error}")


def assurance_stack_release_notes_panel():
    return """
    <section id="assurance-product-stack-release-notes-panel"
             style="margin:24px 0; padding:22px; border:1px solid #bae6fd; border-radius:18px;
                    background:linear-gradient(135deg,#ecfeff,#ffffff);
                    box-shadow:0 8px 24px rgba(15,23,42,0.08);">
        <div style="display:flex; justify-content:space-between; gap:16px; flex-wrap:wrap; align-items:flex-start;">
            <div style="max-width:980px;">
                <div style="font-size:13px; font-weight:800; letter-spacing:.08em; text-transform:uppercase; color:#0e7490;">
                    Release Entry
                </div>
                <h2 style="margin:8px 0 8px 0; font-size:28px; line-height:1.15;">
                    Added: Assurance Product Stack
                </h2>
                <p style="margin:0; color:#334155; font-size:15px; line-height:1.55;">
                    Added the commercial and academic product layer that turns COBIT-Chain™ from a collection of
                    governance modules into a measurable assurance product system. The new stack includes the
                    Enterprise Assurance Passport Factory™, Governance Assurance Passport™, and COBIT-Chain Maturity
                    Scorecard™.
                </p>
            </div>
            <div style="font-weight:900; color:#0e7490; background:#cffafe; border:1px solid #67e8f9;
                        padding:8px 12px; border-radius:999px;">
                LIVE
            </div>
        </div>

        <div style="margin-top:18px; padding:16px; border-left:7px solid #0891b2; border-radius:16px;
                    background:#f8fafc; color:#334155; line-height:1.65;">
            <b>Strategic meaning:</b>
            This release adds the missing product architecture:
            <b>diagnose maturity → generate assurance → issue portable passport</b>.
            It gives the platform a buyer-friendly diagnostic, a cross-domain assurance engine,
            and a tangible audit-ready output.
        </div>

        <div style="margin-top:18px; overflow-x:auto;">
            <table style="width:100%; border-collapse:collapse; border-radius:14px; overflow:hidden; font-size:13px;">
                <thead>
                    <tr>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">Product Layer</th>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">Status</th>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">Route</th>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">What It Adds</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><b>Enterprise Assurance Passport Factory™</b></td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Live</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">/enterprise-assurance-passport-factory</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">
                            Cross-domain engine that evaluates batches, SOPs, CIs, sterile records, DR events,
                            access reviews, and CAPA items using one assurance model.
                        </td>
                    </tr>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><b>Governance Assurance Passport™</b></td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Live</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">/governance-assurance-passport/BATCH-2026-041</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">
                            Portable assurance record showing object identity, controls, evidence, integrity anchors,
                            reconciliation, dependencies, exceptions, DR readiness, and closure verdict.
                        </td>
                    </tr>
                    <tr>
                        <td style="padding:11px;"><b>COBIT-Chain Maturity Scorecard™</b></td>
                        <td style="padding:11px;">Live</td>
                        <td style="padding:11px;">/cobit-chain-maturity-scorecard</td>
                        <td style="padding:11px;">
                            0–4 maturity diagnostic across evidence standardization, integrity anchoring,
                            reconciliation, dependency validation, exception/CAPA linkage, and DR governance readiness.
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>

        <div style="margin-top:18px; display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:14px;">
            <div style="border:1px solid #bae6fd; border-radius:16px; padding:16px; background:#ffffff;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">
                    Academic Value
                </div>
                <div style="font-size:18px; font-weight:900; margin-top:7px;">Evaluation Instrument</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">
                    The maturity scorecard makes the framework measurable rather than only conceptual.
                </p>
            </div>
            <div style="border:1px solid #bae6fd; border-radius:16px; padding:16px; background:#ffffff;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">
                    Commercial Value
                </div>
                <div style="font-size:18px; font-weight:900; margin-top:7px;">Product Ladder</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">
                    Creates a path from advisory scorecard to verification layer to enterprise governance intelligence.
                </p>
            </div>
            <div style="border:1px solid #bae6fd; border-radius:16px; padding:16px; background:#ffffff;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">
                    Platform Value
                </div>
                <div style="font-size:18px; font-weight:900; margin-top:7px;">Portable Proof</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">
                    The platform now produces a tangible assurance passport, not just dashboards and status pages.
                </p>
            </div>
        </div>

        <div style="display:flex; flex-wrap:wrap; gap:10px; margin-top:18px;">
            <a href="/enterprise-assurance-passport-factory"
               style="display:inline-block; padding:10px 14px; border-radius:12px; background:#0891b2;
                      color:#fff; text-decoration:none; font-weight:800;">
                Open Passport Factory
            </a>
            <a href="/governance-assurance-passport/BATCH-2026-041"
               style="display:inline-block; padding:10px 14px; border-radius:12px; background:#0f172a;
                      color:#fff; text-decoration:none; font-weight:800;">
                Open Sample Passport
            </a>
            <a href="/cobit-chain-maturity-scorecard"
               style="display:inline-block; padding:10px 14px; border-radius:12px; background:#0f172a;
                      color:#fff; text-decoration:none; font-weight:800;">
                Open Maturity Scorecard
            </a>
            <a href="/modules"
               style="display:inline-block; padding:10px 14px; border-radius:12px; background:#0f172a;
                      color:#fff; text-decoration:none; font-weight:800;">
                View Modules Directory
            </a>
        </div>

        <p style="margin:14px 0 0 0; color:#64748b; font-size:13px;">
            Boundary: this is a release-note bridge only. It does not overwrite the protected Release Notes route,
            modify existing DR or sterile release panels, replace validated enterprise systems, or create production automation.
        </p>
    </section>
    """


def assurance_stack_insert_release_notes_panel(html, panel):
    if 'id="assurance-product-stack-release-notes-panel"' in html:
        return html

    lower_html = html.lower()

    if "</body>" in lower_html:
        index = lower_html.rfind("</body>")
        return html[:index] + panel + html[index:]

    return html + panel


@app.after_request
def assurance_product_stack_release_notes_injection(response):
    try:
        if assurance_stack_release_notes_request.path != "/release-notes":
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

        updated_html = assurance_stack_insert_release_notes_panel(
            html,
            assurance_stack_release_notes_panel()
        )

        response.set_data(updated_html)
        response.headers["Content-Length"] = str(len(response.get_data()))

        return response

    except Exception as exc:
        print(f"Assurance Product Stack Release Notes bridge skipped safely: {exc}")
        return response
'''

def main():
    if not APP_FILE.exists():
        raise SystemExit("ERROR: app.py was not found in the current folder.")

    text = APP_FILE.read_text(encoding="utf-8")

    if ACTIVE_MARKER in text:
        print("SKIP: Assurance Product Stack Release Notes bridge already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, bridge_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        'def assurance_stack_release_notes_panel():',
        'id="assurance-product-stack-release-notes-panel"',
        '@app.after_request',
        'def assurance_product_stack_release_notes_injection(response):',
        'if assurance_stack_release_notes_request.path != "/release-notes":',
        'Added: Assurance Product Stack',
        'href="/enterprise-assurance-passport-factory"',
        'href="/governance-assurance-passport/BATCH-2026-041"',
        'href="/cobit-chain-maturity-scorecard"',
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: Assurance Product Stack Release Notes bridge inserted safely.")
    print("VERIFIED: protected /release-notes route left intact; product-stack panel injection markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
