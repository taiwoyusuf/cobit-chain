from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_EXECUTIVE_INTERVENTION_SIMULATOR_ACTIVE"

if MARKER in text:
    print("Shift Executive Intervention Simulator already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_EXECUTIVE_COMMAND_CENTER_ACTIVE",
    "SHIFT_CONTINUITY_SHOCK_SIMULATOR_ACTIVE",
    "SHIFT_SURVIVABILITY_INDEX_ACTIVE",
    "SHIFT_RECOVERY_CONFIDENCE_ENGINE_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'

if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_EXECUTIVE_INTERVENTION_SIMULATOR_ACTIVE
# ShiftTrust™ Executive Intervention Simulator
# ============================================================

@app.route("/shift-executive-intervention-simulator")
def shift_executive_intervention_simulator():

    interventions = [
        {
            "decision": "Expand peer overlap coverage",
            "impact": "+11% survivability",
            "effect": "Reduces hidden dependency concentration",
            "delay_risk": "LOW"
        },
        {
            "decision": "Delay escalation inheritance remediation",
            "impact": "-9% survivability",
            "effect": "Escalation orphaning risk increases",
            "delay_risk": "HIGH"
        },
        {
            "decision": "Reduce continuity overlap hours",
            "impact": "-14% survivability",
            "effect": "Operational memory degradation increases",
            "delay_risk": "HIGH"
        },
        {
            "decision": "Increase cross-training redundancy",
            "impact": "+8% recovery confidence",
            "effect": "Improves operational survivability",
            "delay_risk": "LOW"
        }
    ]

    escalation_paths = [
        {
            "risk": "Human dependency concentration",
            "first_cascade": "Recovery instability",
            "executive_exposure": "HIGH"
        },
        {
            "risk": "Governance drift normalization",
            "first_cascade": "Invisible operational erosion",
            "executive_exposure": "WATCH"
        },
        {
            "risk": "Escalation inheritance instability",
            "first_cascade": "Continuity ownership gaps",
            "executive_exposure": "WATCH"
        }
    ]

    rows = ''.join([
        f"""
        <tr>
            <td>{x["decision"]}</td>
            <td>{x["impact"]}</td>
            <td>{x["effect"]}</td>
            <td><span class="pill">{x["delay_risk"]}</span></td>
        </tr>
        """
        for x in interventions
    ])

    cascade_rows = ''.join([
        f"""
        <tr>
            <td>{x["risk"]}</td>
            <td>{x["first_cascade"]}</td>
            <td><span class="pill">{x["executive_exposure"]}</span></td>
        </tr>
        """
        for x in escalation_paths
    ])

    body = f"""
    <div class="hero">
        <h1>ShiftTrust™ Executive Intervention Simulator</h1>

        <div class="sub">
            Simulates how executive actions affect survivability posture,
            governance stability, escalation continuity, operational recovery,
            and continuity resilience.
        </div>

        <div class="nav">
            <a href="/shift-executive-command-center">Executive Command Center</a>
            <a href="/shift-survivability-index">Survivability Index</a>
            <a href="/shift-continuity-shock-simulator">Continuity Shock Simulator</a>
            <a href="/shift-recovery-confidence">Recovery Confidence</a>
            <a href="/shift-advanced">Advanced Launcher</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Leadership Impact Sensitivity</div><div class="value">HIGH</div></div>
        <div class="card"><div class="label">Intervention Stability</div><div class="value">88%</div></div>
        <div class="card"><div class="label">Delay Exposure</div><div class="value">WATCH</div></div>
        <div class="card"><div class="label">Continuity Resilience</div><div class="value">STABLE</div></div>
    </div>

    <div class="section">
        <h2>Executive Intervention Decision</h2>

        <div class="decision">
            LEADERSHIP ACTION TIMING DIRECTLY IMPACTS OPERATIONAL SURVIVABILITY
        </div>

        <p>
            ShiftTrust™ Executive Intervention Simulator demonstrates how leadership decisions
            affect continuity resilience, escalation survivability, recovery realism,
            governance drift, and operational stability.
        </p>
    </div>

    <div class="section">
        <h2>Leadership Intervention Simulation</h2>

        <table>
            <tr>
                <th>Executive Action</th>
                <th>Projected Impact</th>
                <th>Operational Effect</th>
                <th>Delay Risk</th>
            </tr>

            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Risk Cascade Forecast</h2>

        <table>
            <tr>
                <th>Primary Risk</th>
                <th>First Cascade Effect</th>
                <th>Executive Exposure</th>
            </tr>

            {cascade_rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>

        <div class="decision">
            SHIFTTRUST™ SIMULATES THE CONSEQUENCES OF LEADERSHIP DELAY
        </div>

        <p>
            Traditional operational systems display incidents after disruption occurs.
            ShiftTrust™ Executive Intervention Simulator predicts how leadership timing,
            governance decisions, and survivability actions influence operational outcomes
            before continuity failure happens.
        </p>
    </div>
    """

    return rlt_page("ShiftTrust Executive Intervention Simulator", body)

'''

text = text.replace(insert_before, code + insert_before)

APP.write_text(text, encoding="utf-8")

print("Shift Executive Intervention Simulator patch applied.")
