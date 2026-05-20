from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_NIAGARA_OPERATIONAL_TRUST_FABRIC_ACTIVE"

if MARKER in text:
    print("Operational Trust Fabric already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_NIAGARA_GOVERNANCE_DECISION_INTELLIGENCE_ACTIVE",
    "SHIFT_NIAGARA_EVIDENCE_LINEAGE_ACTIVE",
    "SHIFT_NIAGARA_ROLE_CHANGE_INTELLIGENCE_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'

if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_NIAGARA_OPERATIONAL_TRUST_FABRIC_ACTIVE
# ShiftTrust™ Niagara Operational Trust Fabric
# ============================================================

@app.route("/shift-niagara-operational-trust-fabric")
def shift_niagara_operational_trust_fabric():

    trust_matrix = [
        {
            "domain": "Audit Trust",
            "state": "Stable",
            "confidence": "High",
            "risk": "Controlled"
        },
        {
            "domain": "Access Governance Trust",
            "state": "Connected",
            "confidence": "Moderate",
            "risk": "Monitoring"
        },
        {
            "domain": "Recovery Survivability Trust",
            "state": "Protected",
            "confidence": "High",
            "risk": "Low"
        },
        {
            "domain": "Approval Lineage Trust",
            "state": "Federated",
            "confidence": "High",
            "risk": "Controlled"
        }
    ]

    rows = ''.join([
        f"""
        <tr>
            <td>{x["domain"]}</td>
            <td>{x["state"]}</td>
            <td>{x["confidence"]}</td>
            <td>{x["risk"]}</td>
        </tr>
        """
        for x in trust_matrix
    ])

    body = f"""
    <div class="hero">
        <h1>ShiftTrust™ Niagara Operational Trust Fabric</h1>

        <div class="sub">
            Enterprise operational-trust intelligence layer providing governance trust propagation,
            survivability confidence telemetry,
            operational defensibility correlation, and trust-orchestration analytics.
        </div>

        <div class="nav">
            <a href="/shift-executive-command-center">Executive Command Center</a>
            <a href="/shift-niagara-governance-decision-intelligence">Governance Decision Intelligence</a>
            <a href="/shift-niagara-evidence-lineage">Evidence Lineage</a>
            <a href="/shift-niagara-role-change-intelligence">Role Change Intelligence</a>
            <a href="/shift-advanced">Advanced Launcher</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Operational Trust</div><div class="value">ACTIVE</div></div>
        <div class="card"><div class="label">Trust Correlation</div><div class="value">LIVE</div></div>
        <div class="card"><div class="label">Governance Confidence</div><div class="value">97%</div></div>
        <div class="card"><div class="label">Operational Survivability</div><div class="value">CONNECTED</div></div>
    </div>

    <div class="section">
        <h2>Operational Trust Decision</h2>

        <div class="decision">
            SHIFTTRUST™ CAN CORRELATE ENTERPRISE GOVERNANCE TRUST BEFORE OPERATIONAL FAILURE PROPAGATES
        </div>

        <p>
            ShiftTrust™ Niagara Operational Trust Fabric transforms fragmented governance telemetry
            into continuously correlated operational trust intelligence capable of survivability reasoning,
            governance defensibility analytics, operational trust propagation,
            and enterprise resilience orchestration.
        </p>
    </div>

    <div class="section">
        <h2>Niagara Operational Trust Matrix</h2>

        <table>
            <tr>
                <th>Operational Trust Domain</th>
                <th>Trust State</th>
                <th>Confidence</th>
                <th>Risk State</th>
            </tr>

            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>

        <div class="decision">
            SHIFTTRUST™ EVOLVES INTO A REAL ENTERPRISE OPERATIONAL TRUST INTELLIGENCE PLATFORM
        </div>

        <p>
            Traditional governance environments separate audit trust,
            operational approvals, backup confidence, and access defensibility.
            ShiftTrust™ Niagara Operational Trust Fabric continuously federates governance trust,
            survivability telemetry, operational defensibility,
            and resilience intelligence into one operational trust ecosystem.
        </p>
    </div>
    """

    return rlt_page("ShiftTrust Niagara Operational Trust Fabric", body)

'''

text = text.replace(insert_before, code + insert_before)

APP.write_text(text, encoding="utf-8")

print("Operational Trust Fabric patch applied.")
