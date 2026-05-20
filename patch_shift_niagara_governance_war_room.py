from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_NIAGARA_GOVERNANCE_WAR_ROOM_ACTIVE"

if MARKER in text:
    print("Governance War Room already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_NIAGARA_GOVERNANCE_MESH_FEDERATION_ACTIVE",
    "SHIFT_NIAGARA_DRIFT_FEDERATION_ACTIVE",
    "SHIFT_NIAGARA_OPERATIONAL_TRUST_FABRIC_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'

if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_NIAGARA_GOVERNANCE_WAR_ROOM_ACTIVE
# ShiftTrust™ Niagara Governance War Room
# ============================================================

@app.route("/shift-niagara-governance-war-room")
def shift_niagara_governance_war_room():

    war_room_matrix = [
        {
            "domain": "Operational Trust",
            "status": "Stable",
            "severity": "Low",
            "confidence": "98%"
        },
        {
            "domain": "Governance Drift",
            "status": "Monitoring",
            "severity": "Moderate",
            "confidence": "94%"
        },
        {
            "domain": "Evidence Lineage",
            "status": "Connected",
            "severity": "Controlled",
            "confidence": "97%"
        },
        {
            "domain": "Enterprise Survivability",
            "status": "Protected",
            "severity": "Low",
            "confidence": "99%"
        }
    ]

    rows = ''.join([
        f"""
        <tr>
            <td>{x["domain"]}</td>
            <td>{x["status"]}</td>
            <td>{x["severity"]}</td>
            <td>{x["confidence"]}</td>
        </tr>
        """
        for x in war_room_matrix
    ])

    body = f"""
    <div class="hero">
        <h1>ShiftTrust™ Niagara Governance War Room</h1>

        <div class="sub">
            Executive governance coordination layer aggregating operational trust telemetry,
            governance drift intelligence,
            survivability analytics, and enterprise governance orchestration.
        </div>

        <div class="nav">
            <a href="/shift-executive-command-center">Executive Command Center</a>
            <a href="/shift-niagara-governance-mesh-federation">Governance Mesh Federation</a>
            <a href="/shift-niagara-drift-federation">Drift Federation</a>
            <a href="/shift-niagara-operational-trust-fabric">Operational Trust Fabric</a>
            <a href="/shift-advanced">Advanced Launcher</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Governance War Room</div><div class="value">ACTIVE</div></div>
        <div class="card"><div class="label">Executive Coordination</div><div class="value">LIVE</div></div>
        <div class="card"><div class="label">Governance Telemetry</div><div class="value">CONNECTED</div></div>
        <div class="card"><div class="label">Operational Survivability</div><div class="value">99%</div></div>
    </div>

    <div class="section">
        <h2>Executive Governance Decision</h2>

        <div class="decision">
            SHIFTTRUST™ CAN ORCHESTRATE ENTERPRISE GOVERNANCE RESPONSE BEFORE OPERATIONAL INSTABILITY PROPAGATES
        </div>

        <p>
            ShiftTrust™ Niagara Governance War Room transforms isolated operational governance telemetry
            into continuously orchestrated executive governance intelligence capable of survivability reasoning,
            governance escalation coordination, operational trust federation,
            and enterprise resilience orchestration.
        </p>
    </div>

    <div class="section">
        <h2>Governance War Room Matrix</h2>

        <table>
            <tr>
                <th>Governance Domain</th>
                <th>Status</th>
                <th>Severity</th>
                <th>Confidence</th>
            </tr>

            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>

        <div class="decision">
            SHIFTTRUST™ EVOLVES INTO A REAL EXECUTIVE GOVERNANCE COORDINATION PLATFORM
        </div>

        <p>
            Traditional governance ecosystems isolate operational telemetry,
            governance escalation, survivability analytics, and resilience coordination.
            ShiftTrust™ Niagara Governance War Room continuously orchestrates governance intelligence,
            operational trust telemetry, survivability reasoning,
            and enterprise resilience federation into one executive coordination environment.
        </p>
    </div>
    """

    return rlt_page("ShiftTrust Niagara Governance War Room", body)

'''

text = text.replace(insert_before, code + insert_before)

APP.write_text(text, encoding="utf-8")

print("Governance War Room patch applied.")
