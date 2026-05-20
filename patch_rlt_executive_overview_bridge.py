from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

ACTIVE_MARKER = "# RLT_OPERATIONS_EXECUTIVE_OVERVIEW_BRIDGE_ACTIVE"

if ACTIVE_MARKER in text:
    print("RLT Executive Overview bridge already exists. No duplicate patch applied.")
    raise SystemExit(0)

required = [
    "RLT_OPERATIONS_VERTICAL_ACTIVE",
    "RLT_OPERATIONS_MODULES_DIRECTORY_ACTIVE",
    "RLT_OPERATIONS_PLATFORM_HEALTH_ACTIVE",
    "# RLT_OPERATIONS_RELEASE_NOTES_BRIDGE_ACTIVE",
    "# RLT_OPERATIONS_MONDAY_DEMO_BRIDGE_ACTIVE",
    "# RLT_OPERATIONS_COMMAND_CENTER_BRIDGE_ACTIVE",
    "# ROAT_EXECUTIVE_OVERVIEW_BRIDGE_ACTIVE",
    "# DR_BRANCH_EXECUTIVE_OVERVIEW_BRIDGE_ACTIVE",
    "# ASSURANCE_PRODUCT_STACK_EXECUTIVE_OVERVIEW_BRIDGE_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required existing marker not found: {item}")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError('Could not find if __name__ == "__main__": insertion point.')

code = r'''

# RLT_OPERATIONS_EXECUTIVE_OVERVIEW_BRIDGE_ACTIVE
# Safe after_request bridge: adds RLT Operations executive panel without overwriting /executive-overview.

@app.after_request
def rlt_operations_executive_overview_injection(response):
    try:
        if request.path != "/executive-overview":
            return response

        if response.status_code != 200:
            return response

        content_type = response.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            return response

        html = response.get_data(as_text=True)

        if 'id="rlt-operations-executive-overview-panel"' in html:
            return response

        panel = """
        <section id="rlt-operations-executive-overview-panel"
            style="margin:28px auto;max-width:1180px;padding:26px;border-radius:24px;
            background:linear-gradient(135deg,#ecfeff,#ffffff);
            border:1px solid #99f6e4;
            box-shadow:0 8px 28px rgba(15,23,42,0.10);
            color:#0f172a;">

            <div style="font-size:12px;letter-spacing:1.5px;text-transform:uppercase;
                color:#0f766e;font-weight:900;margin-bottom:8px;">
                Executive RLT Operations Layer
            </div>

            <h2 style="margin:0 0 10px 0;font-size:29px;color:#0f172a;">
                RLT Operations AssuranceLayer™
            </h2>

            <p style="font-size:15px;line-height:1.7;color:#334155;max-width:1000px;">
                RLT Operations AssuranceLayer™ positions COBIT-Chain™ as an operational trust and governance
                intelligence layer for Radioligand Manufacturing. It helps leadership understand whether production
                readiness, evidence integrity, SOP alignment, CAPA exposure, shift governance, and deviation impact
                are complete and defensible before operational pressure becomes a quality event.
            </p>

            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
                gap:14px;margin-top:20px;">

                <div style="padding:17px;border-radius:17px;background:#f0fdfa;border:1px solid #99f6e4;">
                    <div style="font-size:12px;color:#0f766e;text-transform:uppercase;font-weight:900;">Operational Readiness</div>
                    <div style="font-size:25px;font-weight:900;color:#0f172a;margin-top:7px;">96%</div>
                    <div style="font-size:13px;color:#475569;margin-top:8px;">Current RLT state is safe to proceed.</div>
                </div>

                <div style="padding:17px;border-radius:17px;background:#f0fdfa;border:1px solid #99f6e4;">
                    <div style="font-size:12px;color:#0f766e;text-transform:uppercase;font-weight:900;">Manufacturing Trust</div>
                    <div style="font-size:25px;font-weight:900;color:#0f172a;margin-top:7px;">94%</div>
                    <div style="font-size:13px;color:#475569;margin-top:8px;">Evidence and governance confidence.</div>
                </div>

                <div style="padding:17px;border-radius:17px;background:#f0fdfa;border:1px solid #99f6e4;">
                    <div style="font-size:12px;color:#0f766e;text-transform:uppercase;font-weight:900;">Deviation Probability</div>
                    <div style="font-size:25px;font-weight:900;color:#0f172a;margin-top:7px;">LOW</div>
                    <div style="font-size:13px;color:#475569;margin-top:8px;">Predictive governance-risk signal.</div>
                </div>

                <div style="padding:17px;border-radius:17px;background:#f0fdfa;border:1px solid #99f6e4;">
                    <div style="font-size:12px;color:#0f766e;text-transform:uppercase;font-weight:900;">Audit Readiness</div>
                    <div style="font-size:25px;font-weight:900;color:#0f172a;margin-top:7px;">READY</div>
                    <div style="font-size:13px;color:#475569;margin-top:8px;">Operational evidence chain is defensible.</div>
                </div>
            </div>

            <div style="margin-top:22px;padding:18px;border-radius:18px;
                background:#ccfbf1;border:1px solid #5eead4;">
                <div style="font-weight:900;color:#0f172a;margin-bottom:8px;">
                    Executive Value
                </div>
                <div style="font-size:14px;line-height:1.7;color:#334155;">
                    This is not presented as blockchain, crypto, or a generic IT tool. It is positioned as
                    operational trust infrastructure for time-sensitive RLT manufacturing: readiness before execution,
                    trust scoring before escalation, blast-radius visibility before investigation delay, and executive
                    confidence before release exposure.
                </div>
            </div>

            <div style="display:flex;flex-wrap:wrap;gap:10px;margin-top:22px;">
                <a href="/rlt-operations" style="background:#0f766e;color:#fff;padding:10px 14px;
                    border-radius:12px;text-decoration:none;font-weight:900;">Open RLT Mission Control</a>
                <a href="/rlt-operations/readiness" style="border:1px solid #0f766e;color:#0f766e;
                    padding:10px 14px;border-radius:12px;text-decoration:none;font-weight:800;">Readiness Engine</a>
                <a href="/rlt-operations/trust-score" style="border:1px solid #0f766e;color:#0f766e;
                    padding:10px 14px;border-radius:12px;text-decoration:none;font-weight:800;">Trust Score</a>
                <a href="/rlt-operations/blast-radius" style="border:1px solid #0f766e;color:#0f766e;
                    padding:10px 14px;border-radius:12px;text-decoration:none;font-weight:800;">Blast Radius</a>
                <a href="/rlt-operations/risk-heatmap" style="border:1px solid #0f766e;color:#0f766e;
                    padding:10px 14px;border-radius:12px;text-decoration:none;font-weight:800;">Risk Heat Map</a>
            </div>
        </section>
        """

        lower_html = html.lower()
        if "</main>" in lower_html:
            index = lower_html.rfind("</main>")
            html = html[:index] + panel + html[index:]
        elif "</body>" in lower_html:
            index = lower_html.rfind("</body>")
            html = html[:index] + panel + html[index:]
        else:
            html = html + panel

        response.set_data(html)
        response.headers["Content-Length"] = str(len(response.get_data()))
        return response

    except Exception as exc:
        print(f"RLT Executive Overview bridge skipped safely: {exc}")
        return response

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("RLT Executive Overview bridge patch applied successfully.")
