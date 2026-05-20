from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_NIAGARA_ROLE_CHANGE_INTELLIGENCE_ACTIVE"

if MARKER in text:
    print("Niagara Role Change Intelligence already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_NIAGARA_BACKUP_RESILIENCE_ACTIVE",
    "SHIFT_NIAGARA_ACCESS_INTELLIGENCE_ACTIVE",
    "SHIFT_NIAGARA_AUDIT_INTELLIGENCE_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'

if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_NIAGARA_ROLE_CHANGE_INTELLIGENCE_ACTIVE
# ShiftTrust™ Niagara Role Change Intelligence
# ============================================================

@app.route("/shift-niagara-role-change-intelligence")
def shift_niagara_role_change_intelligence():

    role_matrix = [
        {
            "activity": "Technician to SuperUser Transition",
            "approval": "Validated",
            "risk": "Controlled",
            "trust": "High"
        },
        {
            "activity": "Privilege Escalation Governance",
            "approval": "Tracked",
            "risk": "Monitoring",
            "trust": "Moderate"
        },
        {
            "activity": "Operational Role Lineage",
            "approval": "Connected",
            "risk": "Low",
            "trust": "Stable"
        },
        {
            "activity": "Segregation of Duty Validation",
            "approval": "Verified",
            "risk": "Controlled",
            "trust": "High"
        }
    ]

    rows = ''.join([
        f"""
        <tr>
            <td>{x["activity"]}</td>
            <td>{x["approval"]}</td>
            <td>{x["risk"]}</td>
            <td>{x["trust"]}</td>
        </tr>
        """
        for x in role_matrix
    ])

    body = f"""
    <div class="hero">
        <h1>ShiftTrust™ Niagara Role Change Intelligence</h1>

        <div class="sub">
            Operational role governance intelligence layer providing privilege escalation analytics,
            approval lineage telemetry,
            segregation-of-duty defensibility, and operational trust orchestration.
        </div>

        <div class="nav">
            <a href="/shift-executive-command-center">Executive Command Center</a>
            <a href="/shift-niagara-backup-resilience">Niagara Backup Resilience</a>
            <a href="/shift-niagara-access-intelligence">Niagara Access Intelligence</a>
            <a href="/shift-niagara-audit-intelligence">Niagara Audit Intelligence</a>
            <a href="/shift-advanced">Advanced Launcher</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Role Governance</div><div class="value">ACTIVE</div></div>
        <div class="card"><div class="label">Privilege Intelligence</div><div class="value">LIVE</div></div>
        <div class="card"><div class="label">Approval Lineage</div><div class="value">CONNECTED</div></div>
        <div class="card"><div class="label">Operational Trust</div><div class="value">96%</div></div>
    </div>

    <div class="section">
        <h2>Operational Role Governance Decision</h2>

        <div class="decision">
            SHIFTTRUST™ CAN DETECT ROLE GOVERNANCE WEAKNESS BEFORE OPERATIONAL EXPOSURE OCCURS
        </div>

        <p>
            ShiftTrust™ Niagara Role Change Intelligence transforms operational role governance
            into continuously correlated operational intelligence capable of privilege escalation analytics,
            approval lineage reasoning, segregation-of-duty defensibility,
            and survivability trust orchestration.
        </p>
    </div>

    <div class="section">
        <h2>Niagara Role Change Intelligence Matrix</h2>

        <table>
            <tr>
                <th>Role Governance Activity</th>
                <th>Approval State</th>
                <th>Risk State</th>
                <th>Operational Trust</th>
            </tr>

            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>

        <div class="decision">
            SHIFTTRUST™ EVOLVES INTO A REAL OPERATIONAL ROLE GOVERNANCE INTELLIGENCE PLATFORM
        </div>

        <p>
            Traditional role changes remain static administrative activities.
            ShiftTrust™ Niagara Role Change Intelligence converts operational role governance
            into continuously monitored operational intelligence capable of privilege escalation reasoning,
            approval lineage analytics, segregation-of-duty defensibility,
            and operational survivability trust scoring.
        </p>
    </div>
    """

    return rlt_page("ShiftTrust Niagara Role Change Intelligence", body)

'''

text = text.replace(insert_before, code + insert_before)

APP.write_text(text, encoding="utf-8")

print("Niagara Role Change Intelligence patch applied.")
