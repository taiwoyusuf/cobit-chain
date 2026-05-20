from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_ASSURANCE_ADVANCED_LAUNCHER_ACTIVE"

if MARKER in text:
    print("Shift Assurance advanced launcher already exists.")
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
# SHIFT_ASSURANCE_ADVANCED_LAUNCHER_ACTIVE
# Safe bridge: adds ShiftTrust™ advanced launcher to /shift-assurance
# ============================================================

@app.after_request
def shift_assurance_advanced_launcher(response):
    try:
        if request.path != "/shift-assurance":
            return response

        if response.status_code not in [200, 302]:
            return response

        # /shift-assurance currently redirects, so this safely avoids breaking that behavior.
        # Advanced launcher is exposed through /shift-assurance-v2-test and core navigation links.
        return response

    except Exception as exc:
        print(f"Shift Assurance advanced launcher skipped safely: {exc}")
        return response


@app.route("/shift-advanced")
def shift_advanced_launcher():
    body = """
    <div class="hero">
        <h1>ShiftTrust™ Advanced Launcher</h1>
        <div class="sub">
            Executive launchpad for the advanced ShiftTrust™ ecosystem: autonomous continuity, treatment-continuity risk,
            peer backup resilience, permanent shift topology, and workforce continuity simulation.
        </div>
        <div class="nav">
            <a href="/shift-assurance">Shift Assurance</a>
            <a href="/shift-assurance-enterprise">Shift Enterprise</a>
            <a href="/shift-handoff-lineage">Handoff Lineage</a>
            <a href="/shift-overlap-intelligence">Shift Overlap</a>
            <a href="/command-center">Command Center</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Continuity Trust</div><div class="value">90%</div><p><a href="/shift-autonomous-continuity">Open Autonomous Continuity</a></p></div>
        <div class="card"><div class="label">Treatment Continuity</div><div class="value">84%</div><p><a href="/shift-treatment-continuity">Open Treatment Engine</a></p></div>
        <div class="card"><div class="label">Coverage Resilience</div><div class="value">92%</div><p><a href="/shift-peer-backup">Open Peer Backup</a></p></div>
        <div class="card"><div class="label">Topology Stability</div><div class="value">93%</div><p><a href="/shift-topology">Open Shift Topology</a></p></div>
        <div class="card"><div class="label">Rotation Readiness</div><div class="value">86%</div><p><a href="/shift-rotation-digital-twin">Open Workforce Twin</a></p></div>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>
        <div class="decision">SHIFTTRUST™ HAS EVOLVED FROM HANDOFF TRACKING INTO OPERATIONAL SURVIVABILITY INTELLIGENCE</div>
        <p>
            This launcher shows the full advanced ShiftTrust™ story: whether the operation can survive missed shifts,
            handoff pressure, backup activation, night-shift burden, unresolved production support risk, and
            time-critical treatment-continuity pressure without losing governance control.
        </p>
    </div>
    """
    return rlt_page("ShiftTrust Advanced Launcher", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("ShiftTrust advanced launcher patch applied.")
