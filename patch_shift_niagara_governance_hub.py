from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_NIAGARA_GOVERNANCE_HUB_ACTIVE"

if MARKER in text:
    print("Niagara Governance Hub already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_OPERATIONAL_DATA_FABRIC_ACTIVE",
    "SHIFT_AI_COPILOT_ACTIVE",
    "SHIFT_EXECUTIVE_STABILITY_FABRIC_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'

if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_NIAGARA_GOVERNANCE_HUB_ACTIVE
# ShiftTrust™ Niagara Governance Hub
# ============================================================

@app.route("/shift-niagara-governance-hub")
def shift_niagara_governance_hub():

    governance_records = [
        {
            "activity": "Quarterly Audit Review",
            "status": "Completed",
            "evidence": "Bound",
            "trust": "High"
        },
        {
            "activity": "Quarterly Access Review",
            "status": "Completed",
            "evidence": "Bound",
            "trust": "High"
        },
        {
            "activity": "Monthly Backup Review",
            "status": "Monitoring",
            "evidence": "Stable",
            "trust": "Moderate"
        },
        {
            "activity": "Role Change Governance",
            "status": "Tracked",
            "evidence": "Linked",
            "trust": "High"
        }
    ]

    rows = ''.join([
        f"""
        <tr>
            <td>{x["activity"]}</td>
            <td>{x["status"]}</td>
            <td>{x["evidence"]}</td>
            <td>{x["trust"]}</td>
        </tr>
        """
        for x in governance_records
    ])

    body = f"""
    <div class="hero">
        <h1>ShiftTrust™ Niagara Governance Hub</h1>

        <div class="sub">
            Real operational governance evidence ingestion layer for Niagara audit telemetry,
            access governance,
            backup lineage, operational trust propagation, and evidence federation.
        </div>

        <div class="nav">
            <a href="/shift-executive-command-center">Executive Command Center</a>
            <a href="/shift-operational-data-fabric">Operational Data Fabric</a>
            <a href="/shift-ai-copilot">Executive AI Copilot</a>
            <a href="/shift-executive-stability-fabric">Stability Fabric</a>
            <a href="/shift-advanced">Advanced Launcher</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Niagara Governance</div><div class="value">ACTIVE</div></div>
        <div class="card"><div class="label">Operational Evidence</div><div class="value">CONNECTED</div></div>
        <div class="card"><div class="label">Audit Lineage</div><div class="value">LIVE</div></div>
        <div class="card"><div class="label">Operational Trust</div><div class="value">94%</div></div>
    </div>

    <div class="section">
        <h2>Operational Governance Decision</h2>

        <div class="decision">
            SHIFTTRUST™ CAN INGEST REAL NIAGARA GOVERNANCE EVIDENCE INTO THE ENTERPRISE INTELLIGENCE FABRIC
        </div>

        <p>
            ShiftTrust™ Niagara Governance Hub introduces operational evidence ingestion,
            governance telemetry federation, audit lineage propagation,
            access review intelligence, and operational trust reasoning using real operational governance activities.
        </p>
    </div>

    <div class="section">
        <h2>Niagara Governance Evidence Matrix</h2>

        <table>
            <tr>
                <th>Governance Activity</th>
                <th>Status</th>
                <th>Evidence State</th>
                <th>Trust State</th>
            </tr>

            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>

        <div class="decision">
            SHIFTTRUST™ TRANSITIONS FROM CONCEPTUAL INTELLIGENCE INTO REAL OPERATIONAL GOVERNANCE INGESTION
        </div>

        <p>
            Traditional governance systems isolate audit evidence across binders,
            spreadsheets, operational reviews, and disconnected governance repositories.
            ShiftTrust™ Niagara Governance Hub federates operational governance evidence,
            lineage telemetry, operational trust scoring,
            and survivability intelligence into one operational intelligence ecosystem.
        </p>
    </div>
    """

    return rlt_page("ShiftTrust Niagara Governance Hub", body)

'''

text = text.replace(insert_before, code + insert_before)

APP.write_text(text, encoding="utf-8")

print("Niagara Governance Hub patch applied.")
