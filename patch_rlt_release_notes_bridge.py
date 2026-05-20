from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

ACTIVE_MARKER = "# RLT_OPERATIONS_RELEASE_NOTES_BRIDGE_ACTIVE"

if ACTIVE_MARKER in text:
    print("RLT Release Notes bridge already exists. No duplicate patch applied.")
    raise SystemExit(0)

required = [
    "RLT_OPERATIONS_VERTICAL_ACTIVE",
    "RLT_OPERATIONS_MODULES_DIRECTORY_ACTIVE",
    "RLT_OPERATIONS_PLATFORM_HEALTH_ACTIVE",
    "# ROAT_RELEASE_NOTES_BRIDGE_ACTIVE",
    "# DR_BRANCH_RELEASE_NOTES_BRIDGE_ACTIVE",
    "# ASSURANCE_PRODUCT_STACK_RELEASE_NOTES_BRIDGE_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required existing marker not found: {item}")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError('Could not find if __name__ == "__main__": insertion point.')

code = r'''

# RLT_OPERATIONS_RELEASE_NOTES_BRIDGE_ACTIVE
# Safe after_request bridge: adds RLT Operations release panel without overwriting /release-notes.

@app.after_request
def rlt_operations_release_notes_injection(response):
    try:
        if request.path != "/release-notes":
            return response

        if response.status_code != 200:
            return response

        content_type = response.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            return response

        html = response.get_data(as_text=True)

        if 'id="rlt-operations-release-notes-panel"' in html:
            return response

        panel = """
        <section id="rlt-operations-release-notes-panel"
            style="margin:24px 0;padding:22px;border:1px solid #99f6e4;border-radius:18px;
            background:linear-gradient(135deg,#ecfeff,#ffffff);
            box-shadow:0 8px 24px rgba(15,23,42,0.08);">

            <div style="font-size:13px;font-weight:800;letter-spacing:.08em;
                text-transform:uppercase;color:#0f766e;">
                Release Entry
            </div>

            <h2 style="margin:8px 0 10px;color:#0f172a;">
                RLT Operations AssuranceLayer™
            </h2>

            <p style="font-size:15px;line-height:1.65;color:#334155;max-width:1000px;">
                Added a dedicated Radioligand Therapies Operations vertical for operational trust and governance
                intelligence. This release introduces RLT Operations Mission Control™, Operational Readiness
                Assurance Engine™, Manufacturing Trust Score™, Deviation Blast Radius Intelligence™, and an
                Operational Risk Heat Map.
            </p>

            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
                gap:12px;margin-top:16px;">

                <div style="padding:14px;border-radius:14px;background:#f0fdfa;border:1px solid #99f6e4;">
                    <strong>Mission Control</strong>
                    <div style="font-size:13px;color:#475569;margin-top:6px;">Executive view of RLT readiness and trust.</div>
                </div>

                <div style="padding:14px;border-radius:14px;background:#f0fdfa;border:1px solid #99f6e4;">
                    <strong>Readiness Engine</strong>
                    <div style="font-size:13px;color:#475569;margin-top:6px;">SAFE / REVIEW / HOLD operational decision support.</div>
                </div>

                <div style="padding:14px;border-radius:14px;background:#f0fdfa;border:1px solid #99f6e4;">
                    <strong>Trust Score</strong>
                    <div style="font-size:13px;color:#475569;margin-top:6px;">Manufacturing trustworthiness scoring.</div>
                </div>

                <div style="padding:14px;border-radius:14px;background:#f0fdfa;border:1px solid #99f6e4;">
                    <strong>Blast Radius</strong>
                    <div style="font-size:13px;color:#475569;margin-top:6px;">Deviation impact mapping across batch, shift, SOP, operator, and release risk.</div>
                </div>
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
        print(f"RLT Release Notes bridge skipped safely: {exc}")
        return response

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("RLT Release Notes bridge patch applied successfully.")
