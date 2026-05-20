from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_NIAGARA_GOVERNANCE_MESH_FEDERATION_ACTIVE"

if MARKER in text:
    print("Niagara Governance Mesh Federation already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_NIAGARA_DRIFT_FEDERATION_ACTIVE",
    "SHIFT_NIAGARA_OPERATIONAL_TRUST_FABRIC_ACTIVE",
    "SHIFT_NIAGARA_GOVERNANCE_DECISION_INTELLIGENCE_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'

if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_NIAGARA_GOVERNANCE_MESH_FEDERATION_ACTIVE
# ShiftTrust™ Niagara Governance Mesh Federation
# ============================================================

@app.route("/shift-niagara-governance-mesh-federation")
def shift_niagara_governance_mesh_federation():

    federation_matrix = [
        {
            "domain": "Audit Governance Federation",
            "mesh": "Connected",
            "telemetry": "Stable",
            "trust": "High"
        },
        {
            "domain": "Operational Trust Federation",
            "mesh": "Federated",
            "telemetry": "Live",
            "trust": "Strong"
        },
        {
            "domain": "Governance Drift Federation",
            "mesh": "Monitoring",
            "telemetry": "Protected",
            "trust": "Controlled"
        },
        {
            "domain": "Enterprise Survivability Federation",
            "mesh": "Orchestrated",
            "telemetry": "Connected",
            "trust": "High"
        }
    ]

    rows = ''.join([
        f"""
        <tr>
            <td>{x["domain"]}</td>
            <td>{x["mesh"]}</td>
            <td>{x["telemetry"]}</td>
            <td>{x["trust"]}</td>
        </tr>
        """
        for x in federation_matrix
    ])

    body = f"""
    <div class="hero">
        <h1>ShiftTrust™ Niagara Governance Mesh Federation</h1>

        <div class="sub">
            Enterprise governance federation layer correlating operational trust telemetry,
            governance drift analytics,
            survivability orchestration, and enterprise governance topology reasoning.
        </div>

        <div class="nav">
            <a href="/shift-executive-command-center">Executive Command Center</a>
            <a href="/rlt-operations/governance-mesh">Enterprise Governance Mesh</a>
            <a href="/shift-niagara-drift-federation">Drift Federation</a>
            <a href="/shift-niagara-operational-trust-fabric">Operational Trust Fabric</a>
            <a href="/shift-advanced">Advanced Launcher</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Mesh Federation</div><div class="value">ACTIVE</div></div>
        <div class="card"><div class="label">Enterprise Correlation</div><div class="value">LIVE</div></div>
        <div class="card"><div class="label">Governance Telemetry</div><div class="value">CONNECTED</div></div>
        <div class="card"><div class="label">Operational Survivability</div><div class="value">98%</div></div>
    </div>

    <div class="section">
        <h2>Enterprise Federation Decision</h2>

        <div class="decision">
            SHIFTTRUST™ CAN FEDERATE ENTERPRISE GOVERNANCE TOPOLOGY BEFORE OPERATIONAL INSTABILITY PROPAGATES
        </div>

        <p>
            ShiftTrust™ Niagara Governance Mesh Federation transforms isolated operational governance domains
            into continuously correlated enterprise governance topology intelligence capable of survivability reasoning,
            governance drift federation, operational trust propagation,
            and enterprise resilience orchestration.
        </p>
    </div>

    <div class="section">
        <h2>Governance Mesh Federation Matrix</h2>

        <table>
            <tr>
                <th>Governance Federation Domain</th>
                <th>Mesh State</th>
                <th>Telemetry State</th>
                <th>Operational Trust</th>
            </tr>

            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>

        <div class="decision">
            SHIFTTRUST™ EVOLVES INTO A REAL ENTERPRISE GOVERNANCE FEDERATION PLATFORM
        </div>

        <p>
            Traditional governance ecosystems isolate operational telemetry,
            survivability analytics, governance drift, and trust propagation.
            ShiftTrust™ Niagara Governance Mesh Federation continuously federates enterprise governance telemetry,
            operational resilience intelligence, survivability orchestration,
            and governance topology reasoning into one enterprise governance mesh.
        </p>
    </div>
    """

    return rlt_page("ShiftTrust Niagara Governance Mesh Federation", body)

'''

text = text.replace(insert_before, code + insert_before)

APP.write_text(text, encoding="utf-8")

print("Niagara Governance Mesh Federation patch applied.")
