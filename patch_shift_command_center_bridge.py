from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_COMMAND_CENTER_BRIDGE_ACTIVE"

if MARKER in text:
    print("Shift Command Center bridge already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_AUTONOMOUS_CONTINUITY_INTELLIGENCE_ACTIVE",
    "SHIFT_TREATMENT_CONTINUITY_RISK_ENGINE_ACTIVE",
    "SHIFT_PEER_BACKUP_COVERAGE_RESILIENCE_ACTIVE",
    "SHIFT_TOPOLOGY_INTELLIGENCE_ACTIVE",
    "SHIFT_ROTATION_DIGITAL_TWIN_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_COMMAND_CENTER_BRIDGE_ACTIVE
# Safe bridge: adds ShiftTrust™ advanced panel to /command-center
# ============================================================

@app.after_request
def shift_command_center_bridge(response):
    try:
        if request.path != "/command-center":
            return response

        if response.status_code != 200:
            return response

        content_type = response.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            return response

        html = response.get_data(as_text=True)

        if 'id="shift-command-center-advanced-panel"' in html:
            return response

        panel = """
        <section id="shift-command-center-advanced-panel"
            style="margin:24px 0;padding:24px;border-radius:22px;
            background:linear-gradient(135deg,#06111f,#0f2a44);
            border:1px solid rgba(127,255,212,.30);
            box-shadow:0 18px 46px rgba(0,0,0,.20);color:#eaf6ff;">

            <div style="font-size:12px;letter-spacing:1.3px;text-transform:uppercase;
                color:#7fffd4;font-weight:900;margin-bottom:8px;">
                ShiftTrust™ Advanced Operational Continuity
            </div>

            <h2 style="margin:0 0 10px 0;font-size:28px;color:#ffffff;">
                Time-Critical Manufacturing Continuity Intelligence
            </h2>

            <p style="color:#b7ddf5;line-height:1.65;max-width:1050px;">
                ShiftTrust™ now extends beyond handoff tracking into operational survivability: treatment-continuity risk,
                peer backup resilience, permanent shift topology, future rotation simulation, governance fatigue,
                and autonomous continuity intelligence for time-critical manufacturing support.
            </p>

            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin-top:18px;">
                <div style="padding:16px;border-radius:16px;background:rgba(16,42,69,.80);border:1px solid rgba(127,255,212,.22);">
                    <div style="font-size:12px;color:#9fc4dd;text-transform:uppercase;font-weight:800;">Treatment Continuity</div>
                    <div style="font-size:28px;font-weight:900;color:#7fffd4;margin-top:8px;">84%</div>
                    <a href="/shift-treatment-continuity" style="color:#7fffd4;text-decoration:none;font-weight:800;">Open Engine</a>
                </div>

                <div style="padding:16px;border-radius:16px;background:rgba(16,42,69,.80);border:1px solid rgba(127,255,212,.22);">
                    <div style="font-size:12px;color:#9fc4dd;text-transform:uppercase;font-weight:800;">Coverage Resilience</div>
                    <div style="font-size:28px;font-weight:900;color:#7fffd4;margin-top:8px;">92%</div>
                    <a href="/shift-peer-backup" style="color:#7fffd4;text-decoration:none;font-weight:800;">Open Backup Layer</a>
                </div>

                <div style="padding:16px;border-radius:16px;background:rgba(16,42,69,.80);border:1px solid rgba(127,255,212,.22);">
                    <div style="font-size:12px;color:#9fc4dd;text-transform:uppercase;font-weight:800;">Topology Stability</div>
                    <div style="font-size:28px;font-weight:900;color:#7fffd4;margin-top:8px;">93%</div>
                    <a href="/shift-topology" style="color:#7fffd4;text-decoration:none;font-weight:800;">Open Topology</a>
                </div>

                <div style="padding:16px;border-radius:16px;background:rgba(16,42,69,.80);border:1px solid rgba(127,255,212,.22);">
                    <div style="font-size:12px;color:#9fc4dd;text-transform:uppercase;font-weight:800;">Rotation Readiness</div>
                    <div style="font-size:28px;font-weight:900;color:#7fffd4;margin-top:8px;">86%</div>
                    <a href="/shift-rotation-digital-twin" style="color:#7fffd4;text-decoration:none;font-weight:800;">Open Digital Twin</a>
                </div>
            </div>

            <div style="margin-top:18px;padding:16px;border-radius:16px;background:rgba(127,255,212,.10);
                border:1px solid rgba(127,255,212,.22);color:#dff7ff;line-height:1.6;">
                <b>Executive meaning:</b> most shift tools show who is working. ShiftTrust™ now shows whether the
                operation can survive absence, handoff pressure, unresolved support risk, night-shift fatigue,
                and time-critical treatment-continuity pressure without losing governance control.
            </div>
        </section>
        """

        lower_html = html.lower()
        if "</main>" in lower_html:
            idx = lower_html.rfind("</main>")
            html = html[:idx] + panel + html[idx:]
        elif "</body>" in lower_html:
            idx = lower_html.rfind("</body>")
            html = html[:idx] + panel + html[idx:]
        else:
            html = html + panel

        response.set_data(html)
        response.headers["Content-Length"] = str(len(response.get_data()))
        return response

    except Exception as exc:
        print(f"Shift Command Center bridge skipped safely: {exc}")
        return response

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("Shift Command Center bridge patch applied.")
