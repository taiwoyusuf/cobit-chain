from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_EXECUTIVE_COMMAND_CENTER_ACTIVE"

if MARKER in text:
    print("Shift Executive Command Center already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_SURVIVABILITY_INDEX_ACTIVE",
    "SHIFT_RECOVERY_CONFIDENCE_ENGINE_ACTIVE",
    "SHIFT_GOVERNANCE_DRIFT_INTELLIGENCE_ACTIVE",
    "SHIFT_ESCALATION_LINEAGE_ENGINE_ACTIVE",
    "SHIFT_HUMAN_DEPENDENCY_CONCENTRATION_ENGINE_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'

if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_EXECUTIVE_COMMAND_CENTER_ACTIVE
# ShiftTrust™ Executive Command Center
# ============================================================

@app.route("/shift-executive-command-center")
def shift_executive_command_center():

    intervention_matrix = [
        {
            "risk": "Human dependency concentration",
            "severity": "HIGH",
            "owner": "Shift Leadership",
            "action": "Expand peer overlap coverage"
        },
        {
            "risk": "Governance drift normalization",
            "severity": "WATCH",
            "owner": "Operations Governance",
            "action": "Review recurring workaround patterns"
        },
        {
            "risk": "Escalation inheritance instability",
            "severity": "WATCH",
            "owner": "Shift Supervisors",
            "action": "Strengthen acknowledgement controls"
        },
        {
            "risk": "Treatment-window compression pressure",
            "severity": "LOW",
            "owner": "Manufacturing Operations",
            "action": "Continue monitoring"
        }
    ]

    pulse_rows = ''.join([
        f"""
        <tr>
            <td>{x["risk"]}</td>
            <td><span class="pill">{x["severity"]}</span></td>
            <td>{x["owner"]}</td>
            <td>{x["action"]}</td>
        </tr>
        """
        for x in intervention_matrix
    ])

    body = f"""
    <div class="hero">
        <h1>ShiftTrust™ Executive Command Center</h1>

        <div class="sub">
            Executive survivability cockpit for time-critical manufacturing support.
            Aggregates operational continuity posture, governance stability, escalation lineage,
            survivability pressure, recovery realism, and intervention priorities.
        </div>

        <div class="nav">
            <a href="/shift-survivability-index">Survivability Index</a>
            <a href="/shift-recovery-confidence">Recovery Confidence</a>
            <a href="/shift-mission-control">Mission Control</a>
            <a href="/shift-executive-summary">Executive Summary</a>
            <a href="/shift-advanced">Advanced Launcher</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Executive Survivability</div><div class="value">88%</div></div>
        <div class="card"><div class="label">Recovery Confidence</div><div class="value">87%</div></div>
        <div class="card"><div class="label">Governance Stability</div><div class="value">WATCH</div></div>
        <div class="card"><div class="label">Operational Pressure</div><div class="value">CONTROLLED</div></div>
    </div>

    <div class="section">
        <h2>Executive Decision Layer</h2>

        <div class="decision">
            SHIFTTRUST™ CONTINUITY POSTURE REMAINS STABLE — HUMAN DEPENDENCY REDUCTION SHOULD BE PRIORITIZED
        </div>

        <p>
            The Executive Command Center transforms shift operations into a survivability intelligence layer.
            Leadership can see whether the operation remains governable under stress, disruption,
            escalation pressure, or continuity degradation.
        </p>
    </div>

    <div class="section">
        <h2>Executive Intervention Matrix</h2>

        <table>
            <tr>
                <th>Operational Risk</th>
                <th>Severity</th>
                <th>Executive Owner</th>
                <th>Recommended Action</th>
            </tr>

            {pulse_rows}
        </table>
    </div>

    <div class="section">
        <h2>Leadership Signals</h2>

        <div class="grid">
            <div class="card">
                <div class="label">Escalation Integrity</div>
                <div class="value">89%</div>
                <p>Inheritance continuity remains stable.</p>
            </div>

            <div class="card">
                <div class="label">Operational Memory</div>
                <div class="value">92%</div>
                <p>Shift knowledge survivability remains strong.</p>
            </div>

            <div class="card">
                <div class="label">Governance Drift</div>
                <div class="value">18%</div>
                <p>Weak normalization pressure detected.</p>
            </div>

            <div class="card">
                <div class="label">Human Dependency</div>
                <div class="value">WATCH</div>
                <p>Specific operational recovery paths remain concentrated.</p>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>

        <div class="decision">
            SHIFTTRUST™ IS NOW AN EXECUTIVE CONTINUITY INTELLIGENCE PLATFORM
        </div>

        <p>
            Traditional shift systems track staffing and handoff notes.
            ShiftTrust™ Executive Command Center measures whether operations remain resilient,
            governable, recoverable, auditable, and survivable during real-world manufacturing pressure.
        </p>
    </div>
    """

    return rlt_page("ShiftTrust Executive Command Center", body)

'''

text = text.replace(insert_before, code + insert_before)

APP.write_text(text, encoding="utf-8")

print("Shift Executive Command Center patch applied.")
