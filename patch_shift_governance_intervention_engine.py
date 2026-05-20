from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_GOVERNANCE_INTERVENTION_ENGINE_ACTIVE"

if MARKER in text:
    print("Governance Intervention Engine already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_NIAGARA_GOVERNANCE_WAR_ROOM_ACTIVE",
    "SHIFT_NIAGARA_NARRATIVE_FEDERATION_ACTIVE",
    "SHIFT_NIAGARA_GOVERNANCE_MESH_FEDERATION_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'

if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_GOVERNANCE_INTERVENTION_ENGINE_ACTIVE
# ShiftTrust™ Governance Intervention Engine
# ============================================================

@app.route("/shift-governance-intervention-engine")
def shift_governance_intervention_engine():

    intervention_matrix = [
        {
            "signal": "Governance Drift Escalation",
            "risk": "Moderate",
            "recommended_action": "Stabilize operational ownership alignment",
            "confidence": "94%"
        },
        {
            "signal": "Evidence Lineage Weakening",
            "risk": "High",
            "recommended_action": "Trigger controlled reconciliation review",
            "confidence": "97%"
        },
        {
            "signal": "Operational Trust Degradation",
            "risk": "Moderate",
            "recommended_action": "Increase survivability governance monitoring",
            "confidence": "95%"
        },
        {
            "signal": "Dependency Closure Instability",
            "risk": "Critical",
            "recommended_action": "Suspend release closure pending dependency validation",
            "confidence": "99%"
        }
    ]

    rows = ''.join([
        f"""
        <tr>
            <td>{x["signal"]}</td>
            <td>{x["risk"]}</td>
            <td>{x["recommended_action"]}</td>
            <td>{x["confidence"]}</td>
        </tr>
        """
        for x in intervention_matrix
    ])

    body = f"""
    <div class="hero">
        <h1>ShiftTrust™ Governance Intervention Engine</h1>

        <div class="sub">
            Enterprise governance reasoning layer correlating survivability telemetry,
            governance drift analytics,
            operational trust degradation, and continuity-preserving intervention intelligence.
        </div>

        <div class="nav">
            <a href="/shift-executive-command-center">Executive Command Center</a>
            <a href="/shift-niagara-governance-war-room">Governance War Room</a>
            <a href="/shift-niagara-narrative-federation">Narrative Federation</a>
            <a href="/governance-scenario-simulator">Scenario Simulator</a>
            <a href="/shift-advanced">Advanced Launcher</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Intervention Engine</div><div class="value">ACTIVE</div></div>
        <div class="card"><div class="label">Governance Reasoning</div><div class="value">LIVE</div></div>
        <div class="card"><div class="label">Continuity Intelligence</div><div class="value">CONNECTED</div></div>
        <div class="card"><div class="label">Operational Survivability</div><div class="value">98%</div></div>
    </div>

    <div class="section">
        <h2>Executive Governance Decision</h2>

        <div class="decision">
            SHIFTTRUST™ CAN REASON ABOUT GOVERNANCE STABILIZATION BEFORE OPERATIONAL FAILURE PROPAGATES
        </div>

        <p>
            ShiftTrust™ Governance Intervention Engine transforms governance telemetry
            into continuity-preserving intervention intelligence capable of survivability reasoning,
            governance stabilization orchestration,
            operational trust preservation,
            and executive intervention coordination.
        </p>
    </div>

    <div class="section">
        <h2>Governance Intervention Matrix</h2>

        <table>
            <tr>
                <th>Governance Signal</th>
                <th>Risk State</th>
                <th>Recommended Intervention</th>
                <th>Executive Confidence</th>
            </tr>

            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>

        <div class="decision">
            SHIFTTRUST™ EVOLVES FROM GOVERNANCE VISIBILITY INTO GOVERNANCE REASONING
        </div>

        <p>
            Traditional governance ecosystems display operational state and alert conditions.
            ShiftTrust™ Governance Intervention Engine reasons about survivability stabilization,
            governance intervention sequencing,
            continuity-preserving actions,
            and operational resilience orchestration before instability propagates across regulated operations.
        </p>
    </div>
    """

    return rlt_page("ShiftTrust Governance Intervention Engine", body)

'''

text = text.replace(insert_before, code + insert_before)

APP.write_text(text, encoding="utf-8")

print("Governance Intervention Engine patch applied.")
