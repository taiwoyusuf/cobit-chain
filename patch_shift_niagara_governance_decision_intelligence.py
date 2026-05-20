from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_NIAGARA_GOVERNANCE_DECISION_INTELLIGENCE_ACTIVE"

if MARKER in text:
    print("Niagara Governance Decision Intelligence already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_NIAGARA_EVIDENCE_LINEAGE_ACTIVE",
    "SHIFT_NIAGARA_ROLE_CHANGE_INTELLIGENCE_ACTIVE",
    "SHIFT_NIAGARA_BACKUP_RESILIENCE_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'

if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_NIAGARA_GOVERNANCE_DECISION_INTELLIGENCE_ACTIVE
# ShiftTrust™ Niagara Governance Decision Intelligence
# ============================================================

@app.route("/shift-niagara-governance-decision-intelligence")
def shift_niagara_governance_decision_intelligence():

    decision_matrix = [
        {
            "domain": "Audit Escalation Governance",
            "decision": "Validated",
            "risk": "Controlled",
            "trust": "High"
        },
        {
            "domain": "Privilege Escalation Review",
            "decision": "Tracked",
            "risk": "Monitoring",
            "trust": "Moderate"
        },
        {
            "domain": "Backup Recovery Governance",
            "decision": "Approved",
            "risk": "Low",
            "trust": "Stable"
        },
        {
            "domain": "Operational Approval Federation",
            "decision": "Connected",
            "risk": "Controlled",
            "trust": "High"
        }
    ]

    rows = ''.join([
        f"""
        <tr>
            <td>{x["domain"]}</td>
            <td>{x["decision"]}</td>
            <td>{x["risk"]}</td>
            <td>{x["trust"]}</td>
        </tr>
        """
        for x in decision_matrix
    ])

    body = f"""
    <div class="hero">
        <h1>ShiftTrust™ Niagara Governance Decision Intelligence</h1>

        <div class="sub">
            Operational governance reasoning layer providing escalation analytics,
            approval defensibility,
            governance intervention intelligence, and operational trust orchestration.
        </div>

        <div class="nav">
            <a href="/shift-executive-command-center">Executive Command Center</a>
            <a href="/shift-niagara-evidence-lineage">Evidence Lineage</a>
            <a href="/shift-niagara-role-change-intelligence">Role Change Intelligence</a>
            <a href="/shift-niagara-backup-resilience">Backup Resilience</a>
            <a href="/shift-advanced">Advanced Launcher</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Decision Intelligence</div><div class="value">ACTIVE</div></div>
        <div class="card"><div class="label">Governance Escalation</div><div class="value">LIVE</div></div>
        <div class="card"><div class="label">Approval Defensibility</div><div class="value">CONNECTED</div></div>
        <div class="card"><div class="label">Operational Trust</div><div class="value">97%</div></div>
    </div>

    <div class="section">
        <h2>Operational Governance Decision</h2>

        <div class="decision">
            SHIFTTRUST™ CAN CORRELATE GOVERNANCE DECISIONS BEFORE OPERATIONAL FAILURE PROPAGATES
        </div>

        <p>
            ShiftTrust™ Niagara Governance Decision Intelligence transforms governance approvals
            into continuously correlated operational intelligence capable of escalation analytics,
            operational intervention reasoning, approval defensibility telemetry,
            and survivability trust orchestration.
        </p>
    </div>

    <div class="section">
        <h2>Niagara Governance Decision Matrix</h2>

        <table>
            <tr>
                <th>Governance Decision Domain</th>
                <th>Decision State</th>
                <th>Risk State</th>
                <th>Operational Trust</th>
            </tr>

            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>

        <div class="decision">
            SHIFTTRUST™ EVOLVES INTO A REAL OPERATIONAL GOVERNANCE REASONING PLATFORM
        </div>

        <p>
            Traditional governance approvals remain fragmented operational checkpoints.
            ShiftTrust™ Niagara Governance Decision Intelligence converts operational governance
            into continuously correlated decision intelligence capable of escalation reasoning,
            approval defensibility analytics, operational intervention orchestration,
            and survivability trust propagation.
        </p>
    </div>
    """

    return rlt_page("ShiftTrust Niagara Governance Decision Intelligence", body)

'''

text = text.replace(insert_before, code + insert_before)

APP.write_text(text, encoding="utf-8")

print("Niagara Governance Decision Intelligence patch applied.")
