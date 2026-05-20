from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_NIAGARA_ACCESS_INTELLIGENCE_ACTIVE"

if MARKER in text:
    print("Niagara Access Intelligence already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_NIAGARA_AUDIT_INTELLIGENCE_ACTIVE",
    "SHIFT_NIAGARA_GOVERNANCE_HUB_ACTIVE",
    "SHIFT_OPERATIONAL_DATA_FABRIC_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'

if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_NIAGARA_ACCESS_INTELLIGENCE_ACTIVE
# ShiftTrust™ Niagara Access Intelligence
# ============================================================

@app.route("/shift-niagara-access-intelligence")
def shift_niagara_access_intelligence():

    access_matrix = [
        {
            "domain": "Quarterly Access Review",
            "privilege_drift": "None",
            "risk": "Low",
            "trust": "Stable"
        },
        {
            "domain": "Role Change Governance",
            "privilege_drift": "Monitoring",
            "risk": "Moderate",
            "trust": "Tracked"
        },
        {
            "domain": "Operational User Provisioning",
            "privilege_drift": "Low",
            "risk": "Moderate",
            "trust": "Connected"
        },
        {
            "domain": "Administrative Access Validation",
            "privilege_drift": "None",
            "risk": "Low",
            "trust": "High"
        }
    ]

    rows = ''.join([
        f"""
        <tr>
            <td>{x["domain"]}</td>
            <td>{x["privilege_drift"]}</td>
            <td>{x["risk"]}</td>
            <td>{x["trust"]}</td>
        </tr>
        """
        for x in access_matrix
    ])

    body = f"""
    <div class="hero">
        <h1>ShiftTrust™ Niagara Access Intelligence</h1>

        <div class="sub">
            Operational access governance intelligence layer providing privilege drift detection,
            role-risk analytics,
            governance lineage correlation, and operational trust scoring.
        </div>

        <div class="nav">
            <a href="/shift-executive-command-center">Executive Command Center</a>
            <a href="/shift-niagara-audit-intelligence">Niagara Audit Intelligence</a>
            <a href="/shift-niagara-governance-hub">Niagara Governance Hub</a>
            <a href="/shift-operational-data-fabric">Operational Data Fabric</a>
            <a href="/shift-advanced">Advanced Launcher</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Access Intelligence</div><div class="value">ACTIVE</div></div>
        <div class="card"><div class="label">Privilege Drift Detection</div><div class="value">LIVE</div></div>
        <div class="card"><div class="label">Operational Trust</div><div class="value">95%</div></div>
        <div class="card"><div class="label">Role Governance</div><div class="value">CONNECTED</div></div>
    </div>

    <div class="section">
        <h2>Operational Access Decision</h2>

        <div class="decision">
            SHIFTTRUST™ CAN DETECT ACCESS GOVERNANCE WEAKNESS BEFORE OPERATIONAL EXPOSURE OCCURS
        </div>

        <p>
            ShiftTrust™ Niagara Access Intelligence transforms operational access governance
            into a continuously correlated intelligence layer capable of privilege drift detection,
            governance lineage reasoning, role-risk analytics,
            survivability trust scoring, and operational access defensibility.
        </p>
    </div>

    <div class="section">
        <h2>Niagara Access Intelligence Matrix</h2>

        <table>
            <tr>
                <th>Access Governance Domain</th>
                <th>Privilege Drift</th>
                <th>Risk State</th>
                <th>Operational Trust</th>
            </tr>

            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>

        <div class="decision">
            SHIFTTRUST™ EVOLVES INTO A REAL OPERATIONAL ACCESS GOVERNANCE INTELLIGENCE PLATFORM
        </div>

        <p>
            Traditional access reviews remain static governance activities.
            ShiftTrust™ Niagara Access Intelligence converts operational access governance
            into continuously monitored operational intelligence capable of privilege drift reasoning,
            role-risk analytics, operational lineage propagation,
            and survivability trust orchestration.
        </p>
    </div>
    """

    return rlt_page("ShiftTrust Niagara Access Intelligence", body)

'''

text = text.replace(insert_before, code + insert_before)

APP.write_text(text, encoding="utf-8")

print("Niagara Access Intelligence patch applied.")
