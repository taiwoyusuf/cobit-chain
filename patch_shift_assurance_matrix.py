from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_EXECUTIVE_ASSURANCE_MATRIX_ACTIVE"

if MARKER in text:
    print("Executive Assurance Matrix already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_EXECUTIVE_CONFIDENCE_FABRIC_ACTIVE",
    "SHIFT_EXECUTIVE_RESILIENCE_ORCHESTRATOR_ACTIVE",
    "SHIFT_EXECUTIVE_DECISION_GRAPH_ACTIVE",
    "SHIFT_EXECUTIVE_DIGITAL_TWIN_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'

if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_EXECUTIVE_ASSURANCE_MATRIX_ACTIVE
# ShiftTrust™ Executive Assurance Matrix
# ============================================================

@app.route("/shift-executive-assurance-matrix")
def shift_executive_assurance_matrix():

    assurance_matrix = [
        {
            "domain": "Operational Survivability",
            "assurance": "92%",
            "confidence": "High",
            "trend": "Stable"
        },
        {
            "domain": "Governance Drift Stability",
            "assurance": "87%",
            "confidence": "Moderate",
            "trend": "Improving"
        },
        {
            "domain": "Escalation Continuity",
            "assurance": "91%",
            "confidence": "High",
            "trend": "Stable"
        },
        {
            "domain": "Human Dependency Resilience",
            "assurance": "83%",
            "confidence": "Watch",
            "trend": "Monitoring"
        }
    ]

    rows = ''.join([
        f"""
        <tr>
            <td>{x["domain"]}</td>
            <td>{x["assurance"]}</td>
            <td>{x["confidence"]}</td>
            <td>{x["trend"]}</td>
        </tr>
        """
        for x in assurance_matrix
    ])

    body = f"""
    <div class="hero">
        <h1>ShiftTrust™ Executive Assurance Matrix</h1>

        <div class="sub">
            Unified assurance correlation layer combining operational survivability,
            governance resilience, escalation continuity,
            confidence propagation, and enterprise continuity assurance.
        </div>

        <div class="nav">
            <a href="/shift-executive-command-center">Executive Command Center</a>
            <a href="/shift-executive-confidence-fabric">Confidence Fabric</a>
            <a href="/shift-executive-resilience-orchestrator">Resilience Orchestrator</a>
            <a href="/shift-executive-decision-graph">Decision Graph</a>
            <a href="/shift-advanced">Advanced Launcher</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Assurance Correlation</div><div class="value">ACTIVE</div></div>
        <div class="card"><div class="label">Enterprise Confidence</div><div class="value">91%</div></div>
        <div class="card"><div class="label">Governance Stability</div><div class="value">STABLE</div></div>
        <div class="card"><div class="label">Operational Assurance</div><div class="value">LIVE</div></div>
    </div>

    <div class="section">
        <h2>Executive Assurance Decision</h2>

        <div class="decision">
            SHIFTTRUST™ CAN CORRELATE ENTERPRISE ASSURANCE ACROSS MULTIPLE GOVERNANCE DOMAINS
        </div>

        <p>
            ShiftTrust™ Executive Assurance Matrix correlates survivability confidence,
            governance resilience, escalation continuity,
            operational trust propagation, and enterprise assurance posture into one executive assurance fabric.
        </p>
    </div>

    <div class="section">
        <h2>Executive Assurance Matrix</h2>

        <table>
            <tr>
                <th>Governance Domain</th>
                <th>Assurance Score</th>
                <th>Confidence State</th>
                <th>Trend</th>
            </tr>

            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>

        <div class="decision">
            SHIFTTRUST™ EVOLVES INTO A UNIFIED EXECUTIVE ASSURANCE INTELLIGENCE PLATFORM
        </div>

        <p>
            Traditional governance systems isolate operational metrics and risks.
            ShiftTrust™ Executive Assurance Matrix correlates trust, survivability,
            governance resilience, escalation continuity,
            operational assurance, and confidence propagation into a unified executive assurance model.
        </p>
    </div>
    """

    return rlt_page("ShiftTrust Executive Assurance Matrix", body)

'''

text = text.replace(insert_before, code + insert_before)

APP.write_text(text, encoding="utf-8")

print("Executive Assurance Matrix patch applied.")
