from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_EXECUTIVE_GOVERNANCE_PULSE_ACTIVE"

if MARKER in text:
    print("Executive Governance Pulse already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_EXECUTIVE_CONTINUITY_MESH_ACTIVE",
    "SHIFT_EXECUTIVE_TRUST_DYNAMICS_ACTIVE",
    "SHIFT_EXECUTIVE_RECOVERY_INTELLIGENCE_ACTIVE",
    "SHIFT_EXECUTIVE_STABILITY_ENGINE_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'

if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_EXECUTIVE_GOVERNANCE_PULSE_ACTIVE
# ShiftTrust™ Executive Governance Pulse
# ============================================================

@app.route("/shift-executive-governance-pulse")
def shift_executive_governance_pulse():

    pulse_matrix = [
        {
            "domain": "Operational Survivability",
            "pulse": "Stable",
            "pressure": "Low",
            "trajectory": "Healthy"
        },
        {
            "domain": "Governance Drift Exposure",
            "pulse": "Monitoring",
            "pressure": "Moderate",
            "trajectory": "Improving"
        },
        {
            "domain": "Escalation Continuity",
            "pulse": "Stable",
            "pressure": "Low",
            "trajectory": "Healthy"
        },
        {
            "domain": "Human Dependency Resilience",
            "pulse": "Watch",
            "pressure": "Moderate",
            "trajectory": "Monitoring"
        }
    ]

    rows = ''.join([
        f"""
        <tr>
            <td>{x["domain"]}</td>
            <td>{x["pulse"]}</td>
            <td>{x["pressure"]}</td>
            <td>{x["trajectory"]}</td>
        </tr>
        """
        for x in pulse_matrix
    ])

    body = f"""
    <div class="hero">
        <h1>ShiftTrust™ Executive Governance Pulse</h1>

        <div class="sub">
            Real-time executive governance heartbeat layer monitoring survivability pressure,
            operational assurance pulse,
            governance continuity health, and enterprise resilience trajectory.
        </div>

        <div class="nav">
            <a href="/shift-executive-command-center">Executive Command Center</a>
            <a href="/shift-executive-continuity-mesh">Continuity Mesh</a>
            <a href="/shift-executive-trust-dynamics">Trust Dynamics</a>
            <a href="/shift-executive-recovery-intelligence">Recovery Intelligence</a>
            <a href="/shift-advanced">Advanced Launcher</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Governance Pulse</div><div class="value">ACTIVE</div></div>
        <div class="card"><div class="label">Enterprise Health</div><div class="value">92%</div></div>
        <div class="card"><div class="label">Continuity Pressure</div><div class="value">LOW</div></div>
        <div class="card"><div class="label">Resilience Trajectory</div><div class="value">STABLE</div></div>
    </div>

    <div class="section">
        <h2>Executive Governance Pulse</h2>

        <div class="decision">
            SHIFTTRUST™ CAN DETECT ENTERPRISE GOVERNANCE PRESSURE BEFORE CONTINUITY FAILURE OCCURS
        </div>

        <p>
            ShiftTrust™ Executive Governance Pulse evaluates operational pressure,
            governance continuity health, survivability heartbeat,
            escalation stability, and enterprise resilience trajectory as a unified pulse intelligence layer.
        </p>
    </div>

    <div class="section">
        <h2>Executive Pulse Matrix</h2>

        <table>
            <tr>
                <th>Governance Domain</th>
                <th>Pulse State</th>
                <th>Pressure Level</th>
                <th>Trajectory</th>
            </tr>

            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>

        <div class="decision">
            SHIFTTRUST™ EVOLVES INTO A REAL-TIME GOVERNANCE HEARTBEAT INTELLIGENCE PLATFORM
        </div>

        <p>
            Traditional governance systems react after operational degradation becomes visible.
            ShiftTrust™ Executive Governance Pulse monitors governance heartbeat,
            survivability pressure, escalation continuity,
            operational assurance health, and enterprise resilience trajectory continuously in real time.
        </p>
    </div>
    """

    return rlt_page("ShiftTrust Executive Governance Pulse", body)

'''

text = text.replace(insert_before, code + insert_before)

APP.write_text(text, encoding="utf-8")

print("Executive Governance Pulse patch applied.")
