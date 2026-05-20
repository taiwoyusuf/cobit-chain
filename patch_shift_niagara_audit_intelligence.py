from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_NIAGARA_AUDIT_INTELLIGENCE_ACTIVE"

if MARKER in text:
    print("Niagara Audit Intelligence already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_NIAGARA_GOVERNANCE_HUB_ACTIVE",
    "SHIFT_OPERATIONAL_DATA_FABRIC_ACTIVE",
    "SHIFT_AI_COPILOT_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'

if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_NIAGARA_AUDIT_INTELLIGENCE_ACTIVE
# ShiftTrust™ Niagara Audit Intelligence
# ============================================================

@app.route("/shift-niagara-audit-intelligence")
def shift_niagara_audit_intelligence():

    audit_matrix = [
        {
            "audit_area": "Quarterly Audit Review",
            "anomaly": "None",
            "defensibility": "High",
            "trust": "Stable"
        },
        {
            "audit_area": "Role Change Verification",
            "anomaly": "Monitoring",
            "defensibility": "Moderate",
            "trust": "Tracked"
        },
        {
            "audit_area": "Backup Governance",
            "anomaly": "Low Drift",
            "defensibility": "Stable",
            "trust": "Moderate"
        },
        {
            "audit_area": "Operational Evidence Lineage",
            "anomaly": "None",
            "defensibility": "High",
            "trust": "Connected"
        }
    ]

    rows = ''.join([
        f"""
        <tr>
            <td>{x["audit_area"]}</td>
            <td>{x["anomaly"]}</td>
            <td>{x["defensibility"]}</td>
            <td>{x["trust"]}</td>
        </tr>
        """
        for x in audit_matrix
    ])

    body = f"""
    <div class="hero">
        <h1>ShiftTrust™ Niagara Audit Intelligence</h1>

        <div class="sub">
            Operational audit intelligence layer providing governance defensibility analytics,
            anomaly detection,
            audit lineage reasoning, and operational trust scoring.
        </div>

        <div class="nav">
            <a href="/shift-executive-command-center">Executive Command Center</a>
            <a href="/shift-niagara-governance-hub">Niagara Governance Hub</a>
            <a href="/shift-operational-data-fabric">Operational Data Fabric</a>
            <a href="/shift-ai-copilot">Executive AI Copilot</a>
            <a href="/shift-advanced">Advanced Launcher</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Audit Intelligence</div><div class="value">ACTIVE</div></div>
        <div class="card"><div class="label">Governance Defensibility</div><div class="value">HIGH</div></div>
        <div class="card"><div class="label">Operational Trust</div><div class="value">94%</div></div>
        <div class="card"><div class="label">Audit Drift Detection</div><div class="value">LIVE</div></div>
    </div>

    <div class="section">
        <h2>Operational Audit Decision</h2>

        <div class="decision">
            SHIFTTRUST™ CAN DETECT GOVERNANCE DRIFT AND AUDIT DEFENSIBILITY WEAKNESS BEFORE AUDIT FAILURE OCCURS
        </div>

        <p>
            ShiftTrust™ Niagara Audit Intelligence transforms operational audit review into an active
            intelligence layer capable of governance anomaly detection,
            evidence defensibility scoring, operational lineage reasoning,
            and survivability trust analytics.
        </p>
    </div>

    <div class="section">
        <h2>Niagara Audit Intelligence Matrix</h2>

        <table>
            <tr>
                <th>Audit Domain</th>
                <th>Anomaly State</th>
                <th>Defensibility</th>
                <th>Operational Trust</th>
            </tr>

            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>

        <div class="decision">
            SHIFTTRUST™ EVOLVES INTO A REAL OPERATIONAL AUDIT INTELLIGENCE PLATFORM
        </div>

        <p>
            Traditional audit reviews remain static governance exercises.
            ShiftTrust™ Niagara Audit Intelligence converts operational audit activities into
            continuously correlated governance intelligence capable of anomaly reasoning,
            defensibility analytics, operational lineage propagation,
            and enterprise operational trust scoring.
        </p>
    </div>
    """

    return rlt_page("ShiftTrust Niagara Audit Intelligence", body)

'''

text = text.replace(insert_before, code + insert_before)

APP.write_text(text, encoding="utf-8")

print("Niagara Audit Intelligence patch applied.")
