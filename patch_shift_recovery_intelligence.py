from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_EXECUTIVE_RECOVERY_INTELLIGENCE_ACTIVE"

if MARKER in text:
    print("Executive Recovery Intelligence already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_EXECUTIVE_STABILITY_ENGINE_ACTIVE",
    "SHIFT_EXECUTIVE_ASSURANCE_MATRIX_ACTIVE",
    "SHIFT_EXECUTIVE_CONFIDENCE_FABRIC_ACTIVE",
    "SHIFT_EXECUTIVE_RESILIENCE_ORCHESTRATOR_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'

if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_EXECUTIVE_RECOVERY_INTELLIGENCE_ACTIVE
# ShiftTrust™ Executive Recovery Intelligence
# ============================================================

@app.route("/shift-executive-recovery-intelligence")
def shift_executive_recovery_intelligence():

    recovery_matrix = [
        {
            "domain": "Operational Survivability",
            "recovery": "Fast",
            "confidence": "92%",
            "status": "Stable"
        },
        {
            "domain": "Governance Drift Recovery",
            "recovery": "Moderate",
            "confidence": "87%",
            "status": "Improving"
        },
        {
            "domain": "Escalation Continuity",
            "recovery": "Fast",
            "confidence": "91%",
            "status": "Stable"
        },
        {
            "domain": "Human Dependency Resilience",
            "recovery": "Monitored",
            "confidence": "84%",
            "status": "Watch"
        }
    ]

    rows = ''.join([
        f"""
        <tr>
            <td>{x["domain"]}</td>
            <td>{x["recovery"]}</td>
            <td>{x["confidence"]}</td>
            <td>{x["status"]}</td>
        </tr>
        """
        for x in recovery_matrix
    ])

    body = f"""
    <div class="hero">
        <h1>ShiftTrust™ Executive Recovery Intelligence</h1>

        <div class="sub">
            Enterprise recovery intelligence layer forecasting operational rebound,
            governance restoration, escalation recovery,
            survivability restoration, and continuity recovery confidence.
        </div>

        <div class="nav">
            <a href="/shift-executive-command-center">Executive Command Center</a>
            <a href="/shift-executive-stability-engine">Stability Engine</a>
            <a href="/shift-executive-assurance-matrix">Assurance Matrix</a>
            <a href="/shift-executive-confidence-fabric">Confidence Fabric</a>
            <a href="/shift-advanced">Advanced Launcher</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Recovery Confidence</div><div class="value">91%</div></div>
        <div class="card"><div class="label">Continuity Restoration</div><div class="value">ACTIVE</div></div>
        <div class="card"><div class="label">Governance Recovery</div><div class="value">STABLE</div></div>
        <div class="card"><div class="label">Operational Rebound</div><div class="value">LIVE</div></div>
    </div>

    <div class="section">
        <h2>Executive Recovery Decision</h2>

        <div class="decision">
            SHIFTTRUST™ CAN FORECAST HOW FAST OPERATIONAL STABILITY CAN BE RESTORED
        </div>

        <p>
            ShiftTrust™ Executive Recovery Intelligence evaluates continuity restoration,
            governance rebound, survivability recovery,
            escalation stabilization, and enterprise recovery confidence as a unified recovery intelligence model.
        </p>
    </div>

    <div class="section">
        <h2>Executive Recovery Matrix</h2>

        <table>
            <tr>
                <th>Governance Domain</th>
                <th>Recovery Velocity</th>
                <th>Recovery Confidence</th>
                <th>Status</th>
            </tr>

            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>

        <div class="decision">
            SHIFTTRUST™ EVOLVES INTO A CONTINUITY RECOVERY INTELLIGENCE PLATFORM
        </div>

        <p>
            Traditional governance systems react after continuity degradation occurs.
            ShiftTrust™ Executive Recovery Intelligence forecasts governance recovery,
            operational rebound, survivability restoration,
            escalation continuity stabilization, and enterprise recovery confidence before disruption escalates further.
        </p>
    </div>
    """

    return rlt_page("ShiftTrust Executive Recovery Intelligence", body)

'''

text = text.replace(insert_before, code + insert_before)

APP.write_text(text, encoding="utf-8")

print("Executive Recovery Intelligence patch applied.")
