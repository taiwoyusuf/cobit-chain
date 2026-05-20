from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

ACTIVE_MARKER = "# RLT_OPERATIONS_MONDAY_DEMO_BRIDGE_ACTIVE"

if ACTIVE_MARKER in text:
    print("RLT Monday Demo bridge already exists. No duplicate patch applied.")
    raise SystemExit(0)

required = [
    "RLT_OPERATIONS_VERTICAL_ACTIVE",
    "RLT_OPERATIONS_MODULES_DIRECTORY_ACTIVE",
    "RLT_OPERATIONS_PLATFORM_HEALTH_ACTIVE",
    "# RLT_OPERATIONS_RELEASE_NOTES_BRIDGE_ACTIVE",
    "# ROAT_MONDAY_DEMO_BRIDGE_ACTIVE",
    "# DR_BRANCH_MONDAY_DEMO_BRIDGE_ACTIVE",
    "# ASSURANCE_PRODUCT_STACK_MONDAY_DEMO_BRIDGE_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required existing marker not found: {item}")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError('Could not find if __name__ == "__main__": insertion point.')

code = r'''

# RLT_OPERATIONS_MONDAY_DEMO_BRIDGE_ACTIVE
# Safe after_request bridge: adds RLT Operations storyline panel without overwriting /monday-demo.

@app.after_request
def rlt_operations_monday_demo_injection(response):
    try:
        if request.path != "/monday-demo":
            return response

        if response.status_code != 200:
            return response

        content_type = response.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            return response

        html = response.get_data(as_text=True)

        if 'id="rlt-operations-monday-demo-panel"' in html:
            return response

        panel = """
        <section id="rlt-operations-monday-demo-panel"
            style="margin:24px 0;padding:22px;border:1px solid #99f6e4;border-radius:18px;
            background:linear-gradient(135deg,#ecfeff,#ffffff);
            box-shadow:0 8px 24px rgba(15,23,42,0.08);">

            <div style="font-size:13px;font-weight:800;letter-spacing:.08em;
                text-transform:uppercase;color:#0f766e;">
                Monday Demo Storyline
            </div>

            <h2 style="margin:8px 0 10px;color:#0f172a;">
                RLT Operations AssuranceLayer™
            </h2>

            <p style="font-size:15px;line-height:1.65;color:#334155;max-width:1000px;">
                This demo shows COBIT-Chain™ extending into Radioligand Therapies Operations as an operational
                trust layer. The storyline is simple: before production pressure becomes a deviation, the system
                evaluates whether the RLT operating state is trustworthy enough to proceed.
            </p>

            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));
                gap:12px;margin-top:16px;">

                <div style="padding:14px;border-radius:14px;background:#f0fdfa;border:1px solid #99f6e4;">
                    <strong>1. Readiness Before Execution</strong>
                    <div style="font-size:13px;color:#475569;margin-top:6px;">
                        Checks SOP currency, training validity, CAPA exposure, audit trail review, backup verification, and shift handoff integrity.
                    </div>
                </div>

                <div style="padding:14px;border-radius:14px;background:#f0fdfa;border:1px solid #99f6e4;">
                    <strong>2. Manufacturing Trust Score</strong>
                    <div style="font-size:13px;color:#475569;margin-top:6px;">
                        Converts scattered governance signals into a clear operational trust score for leadership.
                    </div>
                </div>

                <div style="padding:14px;border-radius:14px;background:#f0fdfa;border:1px solid #99f6e4;">
                    <strong>3. Deviation Blast Radius</strong>
                    <div style="font-size:13px;color:#475569;margin-top:6px;">
                        Maps how one issue may affect equipment, batch, shift, SOP, operator, reviewer, and release exposure.
                    </div>
                </div>

                <div style="padding:14px;border-radius:14px;background:#f0fdfa;border:1px solid #99f6e4;">
                    <strong>4. Executive Decision</strong>
                    <div style="font-size:13px;color:#475569;margin-top:6px;">
                        Presents SAFE TO PROCEED, REVIEW REQUIRED, or HOLD logic without replacing existing GMP systems.
                    </div>
                </div>
            </div>

            <div style="margin-top:18px;padding:16px;border-radius:16px;background:#ccfbf1;border:1px solid #5eead4;">
                <strong style="color:#0f172a;">Demo message:</strong>
                <span style="color:#334155;">
                    COBIT-Chain™ is not replacing MES, quality systems, or production records. It is acting as a governance
                    intelligence layer that helps leadership see whether the production state is complete, defensible, and trusted.
                </span>
            </div>

            <div style="display:flex;flex-wrap:wrap;gap:10px;margin-top:18px;">
                <a href="/rlt-operations" style="background:#0f766e;color:#fff;padding:10px 14px;
                    border-radius:12px;text-decoration:none;font-weight:800;">Open RLT Mission Control</a>
                <a href="/rlt-operations/readiness" style="border:1px solid #0f766e;color:#0f766e;
                    padding:10px 14px;border-radius:12px;text-decoration:none;font-weight:700;">Readiness Engine</a>
                <a href="/rlt-operations/trust-score" style="border:1px solid #0f766e;color:#0f766e;
                    padding:10px 14px;border-radius:12px;text-decoration:none;font-weight:700;">Trust Score</a>
                <a href="/rlt-operations/blast-radius" style="border:1px solid #0f766e;color:#0f766e;
                    padding:10px 14px;border-radius:12px;text-decoration:none;font-weight:700;">Blast Radius</a>
            </div>
        </section>
        """

        lower_html = html.lower()
        if "</body>" in lower_html:
            index = lower_html.rfind("</body>")
            html = html[:index] + panel + html[index:]
        else:
            html = html + panel

        response.set_data(html)
        response.headers["Content-Length"] = str(len(response.get_data()))
        return response

    except Exception as exc:
        print(f"RLT Monday Demo bridge skipped safely: {exc}")
        return response

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("RLT Monday Demo bridge patch applied successfully.")
