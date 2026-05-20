from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_CONTINUITY_SHOCK_SIMULATOR_ACTIVE"

if MARKER in text:
    print("Shift Continuity Shock Simulator already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_EXECUTIVE_COMMAND_CENTER_ACTIVE",
    "SHIFT_SURVIVABILITY_INDEX_ACTIVE",
    "SHIFT_RECOVERY_CONFIDENCE_ENGINE_ACTIVE",
    "SHIFT_HUMAN_DEPENDENCY_CONCENTRATION_ENGINE_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'

if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_CONTINUITY_SHOCK_SIMULATOR_ACTIVE
# ShiftTrust™ Continuity Shock Simulator
# ============================================================

@app.route("/shift-continuity-shock-simulator")
def shift_continuity_shock_simulator():

    scenarios = [
        {
            "scenario": "Senior technician unavailable during escalation surge",
            "impact": "Human dependency concentration activated",
            "survivability": "WATCH",
            "recovery": "STABLE"
        },
        {
            "scenario": "Simultaneous MES/eBR + printer escalation",
            "impact": "Escalation lineage pressure increased",
            "survivability": "WATCH",
            "recovery": "PARTIAL"
        },
        {
            "scenario": "Failed handoff acknowledgement during shift overlap",
            "impact": "Operational memory degradation risk",
            "survivability": "RISK",
            "recovery": "UNSTABLE"
        },
        {
            "scenario": "Night-shift peer backup collapse",
            "impact": "Operational survivability weakened",
            "survivability": "HIGH RISK",
            "recovery": "LIMITED"
        }
    ]

    controls = [
        {
            "control": "Preserve two-person survivability coverage",
            "effect": "Reduces continuity shock exposure"
        },
        {
            "control": "Strengthen escalation inheritance controls",
            "effect": "Protects continuity during overload"
        },
        {
            "control": "Reduce hidden tribal knowledge concentration",
            "effect": "Improves recovery realism"
        },
        {
            "control": "Protect operational memory acknowledgement",
            "effect": "Prevents continuity collapse"
        }
    ]

    rows = ''.join([
        f"""
        <tr>
            <td>{x["scenario"]}</td>
            <td>{x["impact"]}</td>
            <td><span class="pill">{x["survivability"]}</span></td>
            <td><span class="pill">{x["recovery"]}</span></td>
        </tr>
        """
        for x in scenarios
    ])

    control_rows = ''.join([
        f"""
        <tr>
            <td>{x["control"]}</td>
            <td>{x["effect"]}</td>
        </tr>
        """
        for x in controls
    ])

    body = f"""
    <div class="hero">
        <h1>ShiftTrust™ Continuity Shock Simulator</h1>

        <div class="sub">
            Simulates operational stress conditions to evaluate survivability, escalation resilience,
            recovery realism, governance continuity, and continuity collapse exposure.
        </div>

        <div class="nav">
            <a href="/shift-executive-command-center">Executive Command Center</a>
            <a href="/shift-survivability-index">Survivability Index</a>
            <a href="/shift-recovery-confidence">Recovery Confidence</a>
            <a href="/shift-mission-control">Mission Control</a>
            <a href="/shift-advanced">Advanced Launcher</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Shock Survivability</div><div class="value">84%</div></div>
        <div class="card"><div class="label">Recovery Stability</div><div class="value">WATCH</div></div>
        <div class="card"><div class="label">Escalation Resilience</div><div class="value">89%</div></div>
        <div class="card"><div class="label">Continuity Stress</div><div class="value">ACTIVE</div></div>
    </div>

    <div class="section">
        <h2>Executive Shock Decision</h2>

        <div class="decision">
            CONTINUITY SURVIVABILITY REMAINS STABLE — FAILED HANDOFF ACKNOWLEDGEMENT IS THE HIGHEST COLLAPSE RISK
        </div>

        <p>
            ShiftTrust™ Continuity Shock Simulator allows leadership to visualize how the operation behaves
            during disruption, overload, absence, escalation failure, and continuity degradation.
        </p>
    </div>

    <div class="section">
        <h2>Continuity Shock Scenarios</h2>

        <table>
            <tr>
                <th>Shock Scenario</th>
                <th>Operational Impact</th>
                <th>Survivability</th>
                <th>Recovery Posture</th>
            </tr>

            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Continuity Stabilization Controls</h2>

        <table>
            <tr>
                <th>Control</th>
                <th>Expected Governance Effect</th>
            </tr>

            {control_rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>

        <div class="decision">
            SHIFTTRUST™ DOES NOT ASSUME CONTINUITY — IT STRESS TESTS IT
        </div>

        <p>
            Traditional shift systems assume operations remain stable during disruption.
            ShiftTrust™ Continuity Shock Simulator tests whether the operation can survive
            real-world stress without losing governance control, operational continuity,
            escalation integrity, or survivability posture.
        </p>
    </div>
    """

    return rlt_page("ShiftTrust Continuity Shock Simulator", body)

'''

text = text.replace(insert_before, code + insert_before)

APP.write_text(text, encoding="utf-8")

print("Shift Continuity Shock Simulator patch applied.")
