from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# ROAT_COMMAND_CENTER_BRIDGE_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

bridge_code = r'''

# ============================================================
# ROAT_COMMAND_CENTER_BRIDGE_ACTIVE
# Regulated Operations Assurance Twin™ Command Center bridge:
#   - Does not overwrite protected /command-center route
#   - Uses after_request injection only
#   - Adds one umbrella flagship Command Center panel before </main> / </body>
# ============================================================

try:
    from flask import request as roat_command_center_request
except Exception as roat_command_center_import_error:
    raise RuntimeError(f"ROAT Command Center bridge import failed: {roat_command_center_import_error}")


def roat_command_center_panel():
    return """
    <section id="roat-command-center-panel"
             style="margin:24px 0; padding:22px; border:1px solid #ddd6fe; border-radius:18px;
                    background:linear-gradient(135deg,#f5f3ff,#ffffff);
                    box-shadow:0 8px 24px rgba(15,23,42,0.08);">
        <div style="display:flex; justify-content:space-between; gap:16px; flex-wrap:wrap; align-items:flex-start;">
            <div style="max-width:980px;">
                <div style="font-size:13px; font-weight:800; letter-spacing:.08em; text-transform:uppercase; color:#6d28d9;">
                    Umbrella Flagship Capability
                </div>
                <h2 style="margin:8px 0 8px 0; font-size:28px; line-height:1.15;">
                    Regulated Operations Assurance Twin™
                </h2>
                <p style="margin:0; color:#334155; font-size:15px; line-height:1.55;">
                    The top-level platform concept that connects COBIT-Chain™ / AssuranceLayer™ into one enterprise story:
                    a live governance mirror that senses operational evidence, verifies integrity, reconciles cross-system
                    truth, exposes blockers, gates decisions, and issues portable assurance only when the chain is defensible.
                </p>
            </div>
            <div style="font-weight:900; color:#6d28d9; background:#ede9fe; border:1px solid #c4b5fd;
                        padding:8px 12px; border-radius:999px;">
                LIVE
            </div>
        </div>

        <div style="margin-top:18px; display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:14px;">
            <div style="border:1px solid #ddd6fe; border-radius:16px; padding:16px; background:#ffffff;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">Platform Category</div>
                <div style="font-size:22px; font-weight:900; margin-top:7px;">Assurance Twin</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">A live governance mirror of regulated work.</p>
            </div>
            <div style="border:1px solid #ddd6fe; border-radius:16px; padding:16px; background:#ffffff;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">Operating Logic</div>
                <div style="font-size:22px; font-weight:900; margin-top:7px;">Sense → Certify</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">Evidence, integrity, reconciliation, validation, decision, certification.</p>
            </div>
            <div style="border:1px solid #ddd6fe; border-radius:16px; padding:16px; background:#ffffff;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">Coverage</div>
                <div style="font-size:22px; font-weight:900; margin-top:7px;">7+ Objects</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">Batch, SOP, CI, CSP, DR, access review, CAPA.</p>
            </div>
            <div style="border:1px solid #ddd6fe; border-radius:16px; padding:16px; background:#ffffff;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">Final Output</div>
                <div style="font-size:22px; font-weight:900; margin-top:7px;">Passport</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">Portable assurance proof when the full chain is defensible.</p>
            </div>
        </div>

        <div style="margin-top:18px; overflow-x:auto;">
            <table style="width:100%; border-collapse:collapse; border-radius:14px; overflow:hidden; font-size:13px;">
                <thead>
                    <tr>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">Connected Layer</th>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">Route</th>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">Role in the Assurance Twin</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><b>Regulated Operations Assurance Twin™</b></td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">/regulated-operations-assurance-twin</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">
                            Umbrella flagship page that explains the complete governance intelligence category.
                        </td>
                    </tr>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><b>COBIT-Chain Maturity Scorecard™</b></td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">/cobit-chain-maturity-scorecard</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">
                            Diagnoses whether an organization is mature enough to produce defensible assurance.
                        </td>
                    </tr>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><b>Enterprise Assurance Passport Factory™</b></td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">/enterprise-assurance-passport-factory</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">
                            Applies one assurance model across multiple regulated objects and domains.
                        </td>
                    </tr>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><b>Governance Assurance Passport™</b></td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">/governance-assurance-passport/BATCH-2026-041</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">
                            Issues portable proof showing why an object is certified, conditional, or blocked.
                        </td>
                    </tr>
                    <tr>
                        <td style="padding:11px;"><b>Recovery Governance Command Center™</b></td>
                        <td style="padding:11px;">/recovery-governance-command-center</td>
                        <td style="padding:11px;">
                            Proves recovery readiness, restart permission, and closure certification after disruption.
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>

        <div style="margin-top:18px; padding:16px; border-left:7px solid #7c3aed; border-radius:16px; background:#f8fafc;
                    color:#334155; line-height:1.65;">
            <b>Command Center message:</b>
            “This is the top-level product category. COBIT-Chain™ is not only a dashboard or blockchain demo.
            It is a Regulated Operations Assurance Twin™ that proves readiness across regulated work before assurance is issued.”
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
            Boundary: enterprise visibility bridge only. This does not overwrite the protected Command Center route,
            remove existing DR or Assurance Product Stack panels, replace validated systems, or create production automation.
        </p>
    </section>
    """


def roat_insert_command_center_panel(html, panel):
    if 'id="roat-command-center-panel"' in html:
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
def roat_command_center_injection(response):
    try:
        if roat_command_center_request.path != "/command-center":
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

        updated_html = roat_insert_command_center_panel(
            html,
            roat_command_center_panel()
        )

        response.set_data(updated_html)
        response.headers["Content-Length"] = str(len(response.get_data()))

        return response

    except Exception as exc:
        print(f"ROAT Command Center bridge skipped safely: {exc}")
        return response
'''

def main():
    if not APP_FILE.exists():
        raise SystemExit("ERROR: app.py was not found in the current folder.")

    text = APP_FILE.read_text(encoding="utf-8")

    if ACTIVE_MARKER in text:
        print("SKIP: ROAT Command Center bridge already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, bridge_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        'def roat_command_center_panel():',
        'id="roat-command-center-panel"',
        '@app.after_request',
        'def roat_command_center_injection(response):',
        'if roat_command_center_request.path != "/command-center":',
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
    print("SUCCESS: ROAT Command Center bridge inserted safely.")
    print("VERIFIED: protected /command-center route left intact; ROAT panel injection markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
