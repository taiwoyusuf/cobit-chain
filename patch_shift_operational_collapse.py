from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_OPERATIONAL_COLLAPSE_FORECAST_ACTIVE"

if MARKER in text:
    print("Operational Collapse Forecast already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_EXECUTIVE_INTERVENTION_SIMULATOR_ACTIVE",
    "SHIFT_CONTINUITY_SHOCK_SIMULATOR_ACTIVE",
    "SHIFT_SURVIVABILITY_INDEX_ACTIVE",
    "SHIFT_RECOVERY_CONFIDENCE_ENGINE_ACTIVE",
    "SHIFT_GOVERNANCE_DRIFT_INTELLIGENCE_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'

if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_OPERATIONAL_COLLAPSE_FORECAST_ACTIVE
# ShiftTrust™ Operational Collapse Forecast
# ============================================================

@app.route("/shift-operational-collapse-forecast")
def shift_operational_collapse_forecast():

    forecast = [
        {
            "weakness": "Escalation inheritance instability",
            "probability": "41%",
            "first_failure": "Ownership orphaning",
            "severity": "WATCH"
        },
        {
            "weakness": "Human dependency concentration",
            "probability": "63%",
            "first_failure": "Recovery survivability degradation",
            "severity": "HIGH"
        },
        {
            "weakness": "Operational memory erosion",
            "probability": "34%",
            "first_failure": "Handoff continuity degradation",
            "severity": "WATCH"
        },
        {
            "weakness": "Governance drift normalization",
            "probability": "52%",
            "first_failure": "Invisible control erosion",
            "severity": "HIGH"
        }
    ]

    interventions = [
        {
            "control": "Expand peer survivability redundancy",
            "effect": "Reduces collapse acceleration"
        },
        {
            "control": "Protect operational memory acknowledgement",
            "effect": "Stabilizes continuity inheritance"
        },
        {
            "control": "Reduce tribal knowledge concentration",
            "effect": "Improves recovery realism"
        },
        {
            "control": "Increase governance drift monitoring",
            "effect": "Detects early collapse trajectory"
        }
    ]

    rows = ''.join([
        f"""
        <tr>
            <td>{x["weakness"]}</td>
            <td>{x["probability"]}</td>
            <td>{x["first_failure"]}</td>
            <td><span class="pill">{x["severity"]}</span></td>
        </tr>
        """
        for x in forecast
    ])

    intervention_rows = ''.join([
        f"""
        <tr>
            <td>{x["control"]}</td>
            <td>{x["effect"]}</td>
        </tr>
        """
        for x in interventions
    ])

    body = f"""
    <div class="hero">
        <h1>ShiftTrust™ Operational Collapse Forecast</h1>

        <div class="sub">
            Predicts which governance weakness collapses first during operational stress,
            survivability degradation, escalation overload, continuity instability,
            and governance erosion.
        </div>

        <div class="nav">
            <a href="/shift-executive-command-center">Executive Command Center</a>
            <a href="/shift-executive-intervention-simulator">Executive Intervention</a>
            <a href="/shift-continuity-shock-simulator">Continuity Shock</a>
            <a href="/shift-survivability-index">Survivability Index</a>
            <a href="/shift-advanced">Advanced Launcher</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Collapse Exposure</div><div class="value">WATCH</div></div>
        <div class="card"><div class="label">Forecast Stability</div><div class="value">84%</div></div>
        <div class="card"><div class="label">Governance Pressure</div><div class="value">ACTIVE</div></div>
        <div class="card"><div class="label">Survivability Integrity</div><div class="value">STABLE</div></div>
    </div>

    <div class="section">
        <h2>Executive Collapse Decision</h2>

        <div class="decision">
            HUMAN DEPENDENCY CONCENTRATION IS THE MOST LIKELY FIRST COLLAPSE VECTOR
        </div>

        <p>
            ShiftTrust™ Operational Collapse Forecast predicts where operational survivability
            weakens first under continuity pressure and governance instability.
        </p>
    </div>

    <div class="section">
        <h2>Collapse Forecast Matrix</h2>

        <table>
            <tr>
                <th>Governance Weakness</th>
                <th>Failure Probability</th>
                <th>First Collapse Effect</th>
                <th>Severity</th>
            </tr>

            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Collapse Prevention Controls</h2>

        <table>
            <tr>
                <th>Control</th>
                <th>Expected Effect</th>
            </tr>

            {intervention_rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>

        <div class="decision">
            SHIFTTRUST™ PREDICTS CONTINUITY FAILURE TRAJECTORIES BEFORE COLLAPSE OCCURS
        </div>

        <p>
            Traditional operational systems react after disruption becomes visible.
            ShiftTrust™ Operational Collapse Forecast identifies where survivability,
            governance continuity, escalation lineage, and operational recovery are most likely
            to degrade first.
        </p>
    </div>
    """

    return rlt_page("ShiftTrust Operational Collapse Forecast", body)

'''

text = text.replace(insert_before, code + insert_before)

APP.write_text(text, encoding="utf-8")

print("Operational Collapse Forecast patch applied.")
