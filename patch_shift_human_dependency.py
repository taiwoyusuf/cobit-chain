from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_HUMAN_DEPENDENCY_CONCENTRATION_ENGINE_ACTIVE"

if MARKER in text:
    print("Shift Human Dependency Concentration Engine already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_GOVERNANCE_DRIFT_INTELLIGENCE_ACTIVE",
    "SHIFT_OPERATIONAL_MEMORY_ENGINE_ACTIVE",
    "SHIFT_ESCALATION_LINEAGE_ENGINE_ACTIVE",
    "SHIFT_PEER_BACKUP_COVERAGE_RESILIENCE_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_HUMAN_DEPENDENCY_CONCENTRATION_ENGINE_ACTIVE
# ShiftTrust™ Human Dependency Concentration Engine
# ============================================================

@app.route("/shift-human-dependency")
def shift_human_dependency():

    dependencies = [
        {
            "domain": "MES/eBR troubleshooting",
            "dependency": "Single high-experience technician",
            "risk": "HIGH",
            "effect": "Operational survivability weak if unavailable."
        },
        {
            "domain": "Backup review continuity",
            "dependency": "Two-person redundancy exists",
            "risk": "LOW",
            "effect": "Knowledge survivability remains stable."
        },
        {
            "domain": "Printer/labeler escalation recovery",
            "dependency": "Night-shift concentration",
            "risk": "WATCH",
            "effect": "Shift imbalance forming."
        },
        {
            "domain": "Walkaround governance decisions",
            "dependency": "Informal tribal knowledge",
            "risk": "HIGH",
            "effect": "Operational consistency difficult to sustain."
        }
    ]

    controls = [
        {
            "control": "Expand peer-pair operational overlap",
            "effect": "Reduces survivability concentration risk"
        },
        {
            "control": "Force documented escalation inheritance",
            "effect": "Protects continuity during personnel absence"
        },
        {
            "control": "Track recurring single-person dependencies",
            "effect": "Detects tribal-knowledge concentration"
        },
        {
            "control": "Distribute operational recovery ownership",
            "effect": "Prevents hidden operational bottlenecks"
        }
    ]

    rows = ''.join([
        f"""
        <tr>
            <td>{x["domain"]}</td>
            <td>{x["dependency"]}</td>
            <td><span class="pill">{x["risk"]}</span></td>
            <td>{x["effect"]}</td>
        </tr>
        """
        for x in dependencies
    ])

    control_rows = ''.join([
        f"""
        <tr>
            <td>{x["control"]}</td>
            <td>{x["effect"]}</td>
        </tr>
        """
        for x in controls
    ])

    body = f"""
    <div class="hero">
        <h1>ShiftTrust™ Human Dependency Concentration Engine</h1>

        <div class="sub">
            Detects when operational survivability depends too heavily on specific individuals,
            hidden tribal knowledge, or single-person recovery paths.
        </div>

        <div class="nav">
            <a href="/shift-mission-control">Mission Control</a>
            <a href="/shift-governance-drift-intelligence">Governance Drift</a>
            <a href="/shift-operational-memory">Operational Memory</a>
            <a href="/shift-escalation-lineage">Escalation Lineage</a>
            <a href="/shift-advanced">Advanced Launcher</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Human Dependency Risk</div><div class="value">WATCH</div></div>
        <div class="card"><div class="label">Knowledge Survivability</div><div class="value">82%</div></div>
        <div class="card"><div class="label">Tribal Knowledge Exposure</div><div class="value">HIGH</div></div>
        <div class="card"><div class="label">Operational Redundancy</div><div class="value">PARTIAL</div></div>
    </div>

    <div class="section">
        <h2>Dependency Concentration Decision</h2>

        <div class="decision">
            HIDDEN HUMAN DEPENDENCY DETECTED — OPERATIONAL SURVIVABILITY SHOULD NOT DEPEND ON A SINGLE PERSON
        </div>

        <p>
            ShiftTrust™ identifies where operational continuity depends too heavily on specific individuals
            rather than resilient governance structure and inherited operational intelligence.
        </p>
    </div>

    <div class="section">
        <h2>Dependency Concentration Signals</h2>

        <table>
            <tr>
                <th>Operational Domain</th>
                <th>Dependency Pattern</th>
                <th>Risk</th>
                <th>Operational Effect</th>
            </tr>

            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Stabilization Controls</h2>

        <table>
            <tr>
                <th>Governance Control</th>
                <th>Expected Effect</th>
            </tr>

            {control_rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>

        <div class="decision">
            SHIFTTRUST™ DETECTS HIDDEN OPERATIONAL DEPENDENCY BEFORE IT BECOMES A FAILURE POINT
        </div>

        <p>
            Most organizations do not realize operations depend on hidden tribal knowledge until
            a key person is unavailable. ShiftTrust™ makes dependency concentration visible early enough
            for leadership stabilization.
        </p>
    </div>
    """

    return rlt_page("ShiftTrust Human Dependency Concentration Engine", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("Shift Human Dependency Concentration Engine patch applied.")
