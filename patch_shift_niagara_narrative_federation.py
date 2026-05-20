from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_NIAGARA_NARRATIVE_FEDERATION_ACTIVE"

if MARKER in text:
    print("Niagara Narrative Federation already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_NIAGARA_GOVERNANCE_WAR_ROOM_ACTIVE",
    "SHIFT_NIAGARA_GOVERNANCE_MESH_FEDERATION_ACTIVE",
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
# SHIFT_NIAGARA_NARRATIVE_FEDERATION_ACTIVE
# ShiftTrust™ Niagara Narrative Federation
# ============================================================

@app.route("/shift-niagara-narrative-federation")
def shift_niagara_narrative_federation():

    federation_matrix = [
        {
            "domain": "Executive Governance Narrative",
            "state": "Connected",
            "telemetry": "Live",
            "confidence": "98%"
        },
        {
            "domain": "Operational Survivability Narrative",
            "state": "Federated",
            "telemetry": "Protected",
            "confidence": "97%"
        },
        {
            "domain": "Governance Drift Narrative",
            "state": "Monitoring",
            "telemetry": "Stable",
            "confidence": "94%"
        },
        {
            "domain": "Enterprise Trust Narrative",
            "state": "Orchestrated",
            "telemetry": "Connected",
            "confidence": "99%"
        }
    ]

    rows = ''.join([
        f"""
        <tr>
            <td>{x["domain"]}</td>
            <td>{x["state"]}</td>
            <td>{x["telemetry"]}</td>
            <td>{x["confidence"]}</td>
        </tr>
        """
        for x in federation_matrix
    ])

    body = f"""
    <div class="hero">
        <h1>ShiftTrust™ Niagara Narrative Federation</h1>

        <div class="sub">
            Enterprise narrative federation layer correlating governance telemetry,
            survivability analytics,
            executive storytelling intelligence, and operational trust orchestration.
        </div>

        <div class="nav">
            <a href="/shift-executive-command-center">Executive Command Center</a>
            <a href="/shift-executive-narrative">Executive Narrative Engine</a>
            <a href="/shift-executive-narrative-generator">Narrative Generator</a>
            <a href="/shift-niagara-governance-war-room">Governance War Room</a>
            <a href="/shift-advanced">Advanced Launcher</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Narrative Federation</div><div class="value">ACTIVE</div></div>
        <div class="card"><div class="label">Executive Storytelling</div><div class="value">LIVE</div></div>
        <div class="card"><div class="label">Governance Telemetry</div><div class="value">CONNECTED</div></div>
        <div class="card"><div class="label">Operational Survivability</div><div class="value">99%</div></div>
    </div>

    <div class="section">
        <h2>Executive Narrative Decision</h2>

        <div class="decision">
            SHIFTTRUST™ CAN FEDERATE ENTERPRISE GOVERNANCE STORYTELLING BEFORE OPERATIONAL INSTABILITY PROPAGATES
        </div>

        <p>
            ShiftTrust™ Niagara Narrative Federation transforms isolated governance telemetry
            into continuously orchestrated executive storytelling intelligence capable of survivability reasoning,
            governance narrative federation, operational trust propagation,
            and enterprise resilience communication orchestration.
        </p>
    </div>

    <div class="section">
        <h2>Narrative Federation Matrix</h2>

        <table>
            <tr>
                <th>Narrative Federation Domain</th>
                <th>Federation State</th>
                <th>Telemetry State</th>
                <th>Executive Confidence</th>
            </tr>

            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>

        <div class="decision">
            SHIFTTRUST™ EVOLVES INTO A REAL ENTERPRISE GOVERNANCE STORYTELLING PLATFORM
        </div>

        <p>
            Traditional governance environments isolate operational telemetry,
            survivability analytics, governance escalation, and executive communication.
            ShiftTrust™ Niagara Narrative Federation continuously federates governance intelligence,
            operational resilience telemetry, survivability analytics,
            and executive storytelling into one enterprise narrative ecosystem.
        </p>
    </div>
    """

    return rlt_page("ShiftTrust Niagara Narrative Federation", body)

'''

text = text.replace(insert_before, code + insert_before)

APP.write_text(text, encoding="utf-8")

print("Niagara Narrative Federation patch applied.")
