from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_NIAGARA_EVIDENCE_LINEAGE_ACTIVE"

if MARKER in text:
    print("Niagara Evidence Lineage already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_NIAGARA_ROLE_CHANGE_INTELLIGENCE_ACTIVE",
    "SHIFT_NIAGARA_BACKUP_RESILIENCE_ACTIVE",
    "SHIFT_NIAGARA_ACCESS_INTELLIGENCE_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'

if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_NIAGARA_EVIDENCE_LINEAGE_ACTIVE
# ShiftTrust™ Niagara Evidence Lineage
# ============================================================

@app.route("/shift-niagara-evidence-lineage")
def shift_niagara_evidence_lineage():

    lineage_matrix = [
        {
            "domain": "Quarterly Audit Evidence",
            "lineage": "Connected",
            "traceability": "High",
            "trust": "Stable"
        },
        {
            "domain": "Role Change Documentation",
            "lineage": "Tracked",
            "traceability": "Moderate",
            "trust": "Controlled"
        },
        {
            "domain": "Backup Governance Records",
            "lineage": "Verified",
            "traceability": "High",
            "trust": "Strong"
        },
        {
            "domain": "Operational Approval Evidence",
            "lineage": "Federated",
            "traceability": "High",
            "trust": "Connected"
        }
    ]

    rows = ''.join([
        f"""
        <tr>
            <td>{x["domain"]}</td>
            <td>{x["lineage"]}</td>
            <td>{x["traceability"]}</td>
            <td>{x["trust"]}</td>
        </tr>
        """
        for x in lineage_matrix
    ])

    body = f"""
    <div class="hero">
        <h1>ShiftTrust™ Niagara Evidence Lineage</h1>

        <div class="sub">
            Operational evidence lineage intelligence layer providing governance traceability,
            approval-chain federation,
            defensibility telemetry, and operational trust propagation.
        </div>

        <div class="nav">
            <a href="/shift-executive-command-center">Executive Command Center</a>
            <a href="/shift-niagara-role-change-intelligence">Role Change Intelligence</a>
            <a href="/shift-niagara-backup-resilience">Backup Resilience</a>
            <a href="/shift-niagara-access-intelligence">Access Intelligence</a>
            <a href="/shift-advanced">Advanced Launcher</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Evidence Lineage</div><div class="value">ACTIVE</div></div>
        <div class="card"><div class="label">Traceability</div><div class="value">LIVE</div></div>
        <div class="card"><div class="label">Approval Federation</div><div class="value">CONNECTED</div></div>
        <div class="card"><div class="label">Operational Trust</div><div class="value">97%</div></div>
    </div>

    <div class="section">
        <h2>Operational Evidence Decision</h2>

        <div class="decision">
            SHIFTTRUST™ CAN MAINTAIN OPERATIONAL TRACEABILITY ACROSS GOVERNANCE EVIDENCE LIFECYCLES
        </div>

        <p>
            ShiftTrust™ Niagara Evidence Lineage transforms operational governance evidence
            into continuously correlated lineage intelligence capable of traceability reasoning,
            approval-chain federation, operational defensibility analytics,
            and survivability trust propagation.
        </p>
    </div>

    <div class="section">
        <h2>Niagara Evidence Lineage Matrix</h2>

        <table>
            <tr>
                <th>Operational Evidence Domain</th>
                <th>Lineage State</th>
                <th>Traceability</th>
                <th>Operational Trust</th>
            </tr>

            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>

        <div class="decision">
            SHIFTTRUST™ EVOLVES INTO A REAL GOVERNANCE TRACEABILITY INTELLIGENCE PLATFORM
        </div>

        <p>
            Traditional governance evidence remains fragmented across binders,
            spreadsheets, approval chains, and operational repositories.
            ShiftTrust™ Niagara Evidence Lineage converts operational evidence
            into continuously federated governance intelligence capable of lineage reasoning,
            traceability analytics, approval defensibility,
            and operational trust orchestration.
        </p>
    </div>
    """

    return rlt_page("ShiftTrust Niagara Evidence Lineage", body)

'''

text = text.replace(insert_before, code + insert_before)

APP.write_text(text, encoding="utf-8")

print("Niagara Evidence Lineage patch applied.")
