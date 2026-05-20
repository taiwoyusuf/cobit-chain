from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_NIAGARA_DRIFT_FEDERATION_ACTIVE"

if MARKER in text:
    print("Niagara Drift Federation already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_NIAGARA_OPERATIONAL_TRUST_FABRIC_ACTIVE",
    "SHIFT_NIAGARA_GOVERNANCE_DECISION_INTELLIGENCE_ACTIVE",
    "SHIFT_NIAGARA_EVIDENCE_LINEAGE_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'

if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_NIAGARA_DRIFT_FEDERATION_ACTIVE
# ShiftTrust™ Niagara Drift Federation
# ============================================================

@app.route("/shift-niagara-drift-federation")
def shift_niagara_drift_federation():

    federation_matrix = [
        {
            "domain": "Audit Governance Drift",
            "signal": "Stable",
            "severity": "Low",
            "trust": "High"
        },
        {
            "domain": "Access Governance Drift",
            "signal": "Monitoring",
            "severity": "Moderate",
            "trust": "Tracked"
        },
        {
            "domain": "Backup Survivability Drift",
            "signal": "Protected",
            "severity": "Low",
            "trust": "Stable"
        },
        {
            "domain": "Operational Approval Drift",
            "signal": "Federated",
            "severity": "Controlled",
            "trust": "Connected"
        }
    ]

    rows = ''.join([
        f"""
        <tr>
            <td>{x["domain"]}</td>
            <td>{x["signal"]}</td>
            <td>{x["severity"]}</td>
            <td>{x["trust"]}</td>
        </tr>
        """
        for x in federation_matrix
    ])

    body = f"""
    <div class="hero">
        <h1>ShiftTrust™ Niagara Drift Federation</h1>

        <div class="sub">
            Governance drift federation layer correlating operational trust telemetry,
            survivability analytics,
            governance drift reasoning, and operational defensibility propagation.
        </div>

        <div class="nav">
            <a href="/shift-executive-command-center">Executive Command Center</a>
            <a href="/shift-governance-drift-intelligence">Governance Drift Intelligence</a>
            <a href="/shift-niagara-operational-trust-fabric">Operational Trust Fabric</a>
            <a href="/shift-niagara-governance-decision-intelligence">Governance Decision Intelligence</a>
            <a href="/shift-advanced">Advanced Launcher</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Drift Federation</div><div class="value">ACTIVE</div></div>
        <div class="card"><div class="label">Governance Drift</div><div class="value">LIVE</div></div>
        <div class="card"><div class="label">Trust Correlation</div><div class="value">CONNECTED</div></div>
        <div class="card"><div class="label">Operational Survivability</div><div class="value">97%</div></div>
    </div>

    <div class="section">
        <h2>Operational Drift Decision</h2>

        <div class="decision">
            SHIFTTRUST™ CAN FEDERATE GOVERNANCE DRIFT SIGNALS BEFORE ENTERPRISE INSTABILITY PROPAGATES
        </div>

        <p>
            ShiftTrust™ Niagara Drift Federation transforms isolated governance telemetry
            into continuously correlated operational drift intelligence capable of survivability reasoning,
            governance anomaly propagation, operational trust federation,
            and enterprise resilience orchestration.
        </p>
    </div>

    <div class="section">
        <h2>Niagara Drift Federation Matrix</h2>

        <table>
            <tr>
                <th>Governance Drift Domain</th>
                <th>Signal State</th>
                <th>Severity</th>
                <th>Operational Trust</th>
            </tr>

            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>

        <div class="decision">
            SHIFTTRUST™ EVOLVES INTO A REAL ENTERPRISE GOVERNANCE DRIFT FEDERATION PLATFORM
        </div>

        <p>
            Traditional governance environments isolate operational drift signals across
            audit reviews, approvals, survivability checks, and operational trust telemetry.
            ShiftTrust™ Niagara Drift Federation continuously federates governance drift,
            operational defensibility, survivability intelligence,
            and resilience analytics into one enterprise governance ecosystem.
        </p>
    </div>
    """

    return rlt_page("ShiftTrust Niagara Drift Federation", body)

'''

text = text.replace(insert_before, code + insert_before)

APP.write_text(text, encoding="utf-8")

print("Niagara Drift Federation patch applied.")
