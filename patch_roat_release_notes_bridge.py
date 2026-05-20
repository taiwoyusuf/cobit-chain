from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# ROAT_RELEASE_NOTES_BRIDGE_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

bridge_code = r'''

# ============================================================
# ROAT_RELEASE_NOTES_BRIDGE_ACTIVE
# Regulated Operations Assurance Twin™ Release Notes bridge:
#   - Does not overwrite protected /release-notes route
#   - Uses after_request injection only
#   - Adds one umbrella flagship release panel before </body>
# ============================================================

try:
    from flask import request as roat_release_notes_request
except Exception as roat_release_notes_import_error:
    raise RuntimeError(f"ROAT Release Notes bridge import failed: {roat_release_notes_import_error}")


def roat_release_notes_panel():
    return """
    <section id="roat-release-notes-panel"
             style="margin:24px 0; padding:22px; border:1px solid #ddd6fe; border-radius:18px;
                    background:linear-gradient(135deg,#f5f3ff,#ffffff);
                    box-shadow:0 8px 24px rgba(15,23,42,0.08);">
        <div style="display:flex; justify-content:space-between; gap:16px; flex-wrap:wrap; align-items:flex-start;">
            <div style="max-width:980px;">
                <div style="font-size:13px; font-weight:800; letter-spacing:.08em; text-transform:uppercase; color:#6d28d9;">
                    Release Entry
                </div>
                <h2 style="margin:8px 0 8px 0; font-size:28px; line-height:1.15;">
                    Added: Regulated Operations Assurance Twin™
                </h2>
                <p style="margin:0; color:#334155; font-size:15px; line-height:1.55;">
                    Added the umbrella flagship concept that explains COBIT-Chain™ / AssuranceLayer™ as one platform:
                    a live governance mirror that senses operational evidence, verifies integrity, reconciles cross-system
                    truth, exposes blockers, gates decisions, and issues portable assurance only when the chain is defensible.
                </p>
            </div>
            <div style="font-weight:900; color:#6d28d9; background:#ede9fe; border:1px solid #c4b5fd;
                        padding:8px 12px; border-radius:999px;">
                UMBRELLA
            </div>
        </div>

        <div style="margin-top:18px; padding:16px; border-left:7px solid #7c3aed; border-radius:16px;
                    background:#f8fafc; color:#334155; line-height:1.65;">
            <b>Strategic meaning:</b>
            This release gives the whole platform one top-level story:
            <b>Regulated Operations Assurance Twin™ → Maturity Scorecard → Passport Factory → Governance Assurance Passport™ → DR / Recovery Governance</b>.
            It makes COBIT-Chain™ easier to explain as a product category, dissertation contribution, and commercial platform.
        </div>

        <div style="margin-top:18px; overflow-x:auto;">
            <table style="width:100%; border-collapse:collapse; border-radius:14px; overflow:hidden; font-size:13px;">
                <thead>
                    <tr>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">Capability</th>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">Status</th>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">Route</th>
                        <th style="background:#0f172a; color:#fff; text-align:left; padding:11px;">What It Adds</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><b>Regulated Operations Assurance Twin™</b></td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Live</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">/regulated-operations-assurance-twin</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">
                            Umbrella flagship page connecting governance digital twin, reconciliation, dependency validation,
                            decision logic, DR recovery governance, maturity scoring, passport factory, and portable assurance passports.
                        </td>
                    </tr>
                    <tr>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;"><b>Assurance Twin Operating Model</b></td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Live</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">Embedded in ROAT page</td>
                        <td style="border-bottom:1px solid #e5e7eb; padding:11px;">
                            Defines the end-to-end logic: sense, verify, reconcile, validate, decide, certify, and learn.
                        </td>
                    </tr>
                    <tr>
                        <td style="padding:11px;"><b>Interactive Assurance Twin Simulator</b></td>
                        <td style="padding:11px;">Live</td>
                        <td style="padding:11px;">Embedded in ROAT page</td>
                        <td style="padding:11px;">
                            Demonstrates how evidence, integrity, reconciliation, dependencies, exceptions, recovery,
                            and closure conditions drive certifiable, conditional, or blocked assurance.
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>

        <div style="margin-top:18px; display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:14px;">
            <div style="border:1px solid #ddd6fe; border-radius:16px; padding:16px; background:#ffffff;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">
                    Product Category
                </div>
                <div style="font-size:18px; font-weight:900; margin-top:7px;">Assurance Twin</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">
                    Defines COBIT-Chain™ as a governance intelligence layer, not only a dashboard or blockchain prototype.
                </p>
            </div>
            <div style="border:1px solid #ddd6fe; border-radius:16px; padding:16px; background:#ffffff;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">
                    Executive Message
                </div>
                <div style="font-size:18px; font-weight:900; margin-top:7px;">Truth Before Certification</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">
                    The system proves whether regulated work is truly ready, not merely recorded as complete.
                </p>
            </div>
            <div style="border:1px solid #ddd6fe; border-radius:16px; padding:16px; background:#ffffff;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:900;">
                    Commercial Value
                </div>
                <div style="font-size:18px; font-weight:900; margin-top:7px;">One Engine, Many Domains</div>
                <p style="margin:8px 0 0 0; color:#475569; line-height:1.5;">
                    The same assurance logic can support batches, SOPs, CIs, CSPs, DR events, access reviews, and CAPA.
                </p>
            </div>
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
            Boundary: this is a release-note bridge only. It does not overwrite the protected Release Notes route,
            modify existing release panels, replace validated enterprise systems, or create production automation.
        </p>
    </section>
    """


def roat_insert_release_notes_panel(html, panel):
    if 'id="roat-release-notes-panel"' in html:
        return html

    lower_html = html.lower()

    if "</body>" in lower_html:
        index = lower_html.rfind("</body>")
        return html[:index] + panel + html[index:]

    return html + panel


@app.after_request
def roat_release_notes_injection(response):
    try:
        if roat_release_notes_request.path != "/release-notes":
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

        updated_html = roat_insert_release_notes_panel(
            html,
            roat_release_notes_panel()
        )

        response.set_data(updated_html)
        response.headers["Content-Length"] = str(len(response.get_data()))

        return response

    except Exception as exc:
        print(f"ROAT Release Notes bridge skipped safely: {exc}")
        return response
'''

def main():
    if not APP_FILE.exists():
        raise SystemExit("ERROR: app.py was not found in the current folder.")

    text = APP_FILE.read_text(encoding="utf-8")

    if ACTIVE_MARKER in text:
        print("SKIP: ROAT Release Notes bridge already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, bridge_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        'def roat_release_notes_panel():',
        'id="roat-release-notes-panel"',
        '@app.after_request',
        'def roat_release_notes_injection(response):',
        'if roat_release_notes_request.path != "/release-notes":',
        'Added: Regulated Operations Assurance Twin™',
        'href="/regulated-operations-assurance-twin"',
        'href="/enterprise-assurance-passport-factory"',
        'href="/governance-assurance-passport/BATCH-2026-041"',
        'href="/cobit-chain-maturity-scorecard"',
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: ROAT Release Notes bridge inserted safely.")
    print("VERIFIED: protected /release-notes route left intact; ROAT panel injection markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
