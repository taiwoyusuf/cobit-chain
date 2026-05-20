from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_EXECUTIVE_CONTINUITY_MESH_ACTIVE"

if MARKER in text:
    print("Executive Continuity Mesh already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_EXECUTIVE_TRUST_DYNAMICS_ACTIVE",
    "SHIFT_EXECUTIVE_RECOVERY_INTELLIGENCE_ACTIVE",
    "SHIFT_EXECUTIVE_STABILITY_ENGINE_ACTIVE",
    "SHIFT_EXECUTIVE_ASSURANCE_MATRIX_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'

if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_EXECUTIVE_CONTINUITY_MESH_ACTIVE
# ShiftTrust™ Executive Continuity Mesh
# ============================================================

@app.route("/shift-executive-continuity-mesh")
def shift_executive_continuity_mesh():

    mesh_matrix = [
        {
            "domain": "Operational Survivability",
            "mesh_state": "Connected",
            "continuity": "Stable",
            "risk": "Low"
        },
        {
            "domain": "Governance Drift Dependencies",
            "mesh_state": "Monitoring",
            "continuity": "Improving",
            "risk": "Watch"
        },
        {
            "domain": "Escalation Continuity",
            "mesh_state": "Connected",
            "continuity": "Stable",
            "risk": "Low"
        },
        {
            "domain": "Human Dependency Resilience",
            "mesh_state": "Partial",
            "continuity": "Monitoring",
            "risk": "Moderate"
        }
    ]

    rows = ''.join([
        f"""
        <tr>
            <td>{x["domain"]}</td>
            <td>{x["mesh_state"]}</td>
            <td>{x["continuity"]}</td>
            <td>{x["risk"]}</td>
        </tr>
        """
        for x in mesh_matrix
    ])

    body = f"""
    <div class="hero">
        <h1>ShiftTrust™ Executive Continuity Mesh</h1>

        <div class="sub">
            Enterprise continuity mesh intelligence layer modeling operational interdependencies,
            survivability propagation,
            governance continuity relationships, and enterprise resilience connectivity.
        </div>

        <div class="nav">
            <a href="/shift-executive-command-center">Executive Command Center</a>
            <a href="/shift-executive-trust-dynamics">Trust Dynamics</a>
            <a href="/shift-executive-recovery-intelligence">Recovery Intelligence</a>
            <a href="/shift-executive-stability-engine">Stability Engine</a>
            <a href="/shift-advanced">Advanced Launcher</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Continuity Mesh</div><div class="value">ACTIVE</div></div>
        <div class="card"><div class="label">Operational Connectivity</div><div class="value">92%</div></div>
        <div class="card"><div class="label">Governance Interdependence</div><div class="value">LIVE</div></div>
        <div class="card"><div class="label">Resilience Propagation</div><div class="value">STABLE</div></div>
    </div>

    <div class="section">
        <h2>Executive Continuity Decision</h2>

        <div class="decision">
            SHIFTTRUST™ CAN MODEL HOW CONTINUITY PROPAGATES ACROSS ENTERPRISE GOVERNANCE DOMAINS
        </div>

        <p>
            ShiftTrust™ Executive Continuity Mesh evaluates operational interdependencies,
            survivability connectivity, escalation continuity propagation,
            governance resilience relationships, and enterprise continuity equilibrium as a unified mesh intelligence model.
        </p>
    </div>

    <div class="section">
        <h2>Executive Continuity Mesh Matrix</h2>

        <table>
            <tr>
                <th>Governance Domain</th>
                <th>Mesh Connectivity</th>
                <th>Continuity State</th>
                <th>Risk State</th>
            </tr>

            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>

        <div class="decision">
            SHIFTTRUST™ EVOLVES INTO AN ENTERPRISE CONTINUITY MESH INTELLIGENCE PLATFORM
        </div>

        <p>
            Traditional governance systems isolate operational dependencies.
            ShiftTrust™ Executive Continuity Mesh models how survivability,
            operational trust, governance resilience,
            escalation continuity, and enterprise continuity propagate through interconnected operational domains.
        </p>
    </div>
    """

    return rlt_page("ShiftTrust Executive Continuity Mesh", body)

'''

text = text.replace(insert_before, code + insert_before)

APP.write_text(text, encoding="utf-8")

print("Executive Continuity Mesh patch applied.")
