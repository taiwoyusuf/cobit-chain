from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_EXECUTIVE_DECISION_GRAPH_ACTIVE"

if MARKER in text:
    print("Executive Decision Graph already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_EXECUTIVE_DIGITAL_TWIN_ACTIVE",
    "SHIFT_AUTONOMOUS_GOVERNANCE_ENGINE_ACTIVE",
    "SHIFT_OPERATIONAL_COLLAPSE_FORECAST_ACTIVE",
    "SHIFT_EXECUTIVE_INTERVENTION_SIMULATOR_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'

if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_EXECUTIVE_DECISION_GRAPH_ACTIVE
# ShiftTrust™ Executive Decision Graph
# ============================================================

@app.route("/shift-executive-decision-graph")
def shift_executive_decision_graph():

    graph_nodes = [
        {
            "decision": "Reduce overlap coverage",
            "dependency": "Operational memory stability",
            "impact": "Continuity degradation risk",
            "severity": "HIGH"
        },
        {
            "decision": "Delay escalation remediation",
            "dependency": "Escalation inheritance",
            "impact": "Governance drift acceleration",
            "severity": "WATCH"
        },
        {
            "decision": "Increase cross-training",
            "dependency": "Recovery survivability",
            "impact": "Operational resilience improvement",
            "severity": "POSITIVE"
        },
        {
            "decision": "Expand peer redundancy",
            "dependency": "Human dependency reduction",
            "impact": "Collapse prevention stabilization",
            "severity": "POSITIVE"
        }
    ]

    rows = ''.join([
        f"""
        <tr>
            <td>{x["decision"]}</td>
            <td>{x["dependency"]}</td>
            <td>{x["impact"]}</td>
            <td><span class="pill">{x["severity"]}</span></td>
        </tr>
        """
        for x in graph_nodes
    ])

    body = f"""
    <div class="hero">
        <h1>ShiftTrust™ Executive Decision Graph</h1>

        <div class="sub">
            Visualizes governance dependencies, survivability relationships,
            executive intervention impact chains,
            and operational continuity consequence mapping.
        </div>

        <div class="nav">
            <a href="/shift-executive-command-center">Executive Command Center</a>
            <a href="/shift-executive-digital-twin">Executive Digital Twin</a>
            <a href="/shift-autonomous-governance-engine">Autonomous Governance</a>
            <a href="/shift-operational-collapse-forecast">Collapse Forecast</a>
            <a href="/shift-advanced">Advanced Launcher</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Decision Mapping</div><div class="value">ACTIVE</div></div>
        <div class="card"><div class="label">Dependency Visibility</div><div class="value">91%</div></div>
        <div class="card"><div class="label">Continuity Lineage</div><div class="value">LIVE</div></div>
        <div class="card"><div class="label">Governance Relationships</div><div class="value">STABLE</div></div>
    </div>

    <div class="section">
        <h2>Executive Decision Graph</h2>

        <div class="decision">
            SHIFTTRUST™ MAPS HOW LEADERSHIP DECISIONS CASCADE THROUGH OPERATIONAL GOVERNANCE
        </div>

        <p>
            ShiftTrust™ Executive Decision Graph visualizes how survivability,
            governance stability, escalation continuity,
            and operational resilience are interconnected.
        </p>
    </div>

    <div class="section">
        <h2>Governance Relationship Matrix</h2>

        <table>
            <tr>
                <th>Leadership Decision</th>
                <th>Governance Dependency</th>
                <th>Predicted Operational Impact</th>
                <th>Severity</th>
            </tr>

            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>

        <div class="decision">
            SHIFTTRUST™ VISUALIZES OPERATIONAL CONSEQUENCE CHAINS BEFORE FAILURE OCCURS
        </div>

        <p>
            Traditional operational systems isolate incidents and governance signals.
            ShiftTrust™ Executive Decision Graph exposes the relationships between
            leadership actions, survivability posture,
            escalation stability, governance drift,
            and continuity resilience.
        </p>
    </div>
    """

    return rlt_page("ShiftTrust Executive Decision Graph", body)

'''

text = text.replace(insert_before, code + insert_before)

APP.write_text(text, encoding="utf-8")

print("Executive Decision Graph patch applied.")
