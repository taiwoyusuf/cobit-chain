from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_ESCALATION_LINEAGE_ENGINE_ACTIVE"

if MARKER in text:
    print("Shift Escalation Lineage Engine already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_OPERATIONAL_MEMORY_ENGINE_ACTIVE",
    "SHIFT_EXECUTIVE_NARRATIVE_ENGINE_ACTIVE",
    "SHIFT_MISSION_CONTROL_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_ESCALATION_LINEAGE_ENGINE_ACTIVE
# ShiftTrust™ Escalation Lineage Engine
# ============================================================

@app.route("/shift-escalation-lineage")
def shift_escalation_lineage():
    lineage = [
        {
            "issue": "MES/eBR review escalation",
            "origin": "Shift C1",
            "inherited": "Shift A2",
            "status": "ACKNOWLEDGED",
            "risk": "LOW"
        },
        {
            "issue": "Labeler instability watch",
            "origin": "Shift B1",
            "inherited": "No explicit owner",
            "status": "DRIFT",
            "risk": "HIGH"
        },
        {
            "issue": "Backup verification delay",
            "origin": "Shift D2",
            "inherited": "Shift A1",
            "status": "STABLE",
            "risk": "WATCH"
        }
    ]

    controls = [
        {
            "control": "Require named inherited owner",
            "effect": "Prevents invisible escalation drift"
        },
        {
            "control": "Preserve escalation acknowledgement trail",
            "effect": "Maintains audit defensibility"
        },
        {
            "control": "Force unresolved escalation carry-forward",
            "effect": "Protects operational continuity"
        },
        {
            "control": "Detect escalation orphaning",
            "effect": "Prevents silent operational gaps"
        }
    ]

    rows = ''.join([
        f"""
        <tr>
            <td>{x["issue"]}</td>
            <td>{x["origin"]}</td>
            <td>{x["inherited"]}</td>
            <td><span class="pill">{x["status"]}</span></td>
            <td><span class="pill">{x["risk"]}</span></td>
        </tr>
        """
        for x in lineage
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
        <h1>ShiftTrust™ Escalation Lineage Engine</h1>

        <div class="sub">
            Tracks escalation inheritance across shifts. ShiftTrust™ ensures unresolved operational
            issues maintain ownership, acknowledgement, lineage integrity, and governance continuity.
        </div>

        <div class="nav">
            <a href="/shift-operational-memory">Operational Memory</a>
            <a href="/shift-mission-control">Mission Control</a>
            <a href="/shift-executive-summary">Executive Summary</a>
            <a href="/shift-executive-narrative">Executive Narrative</a>
            <a href="/shift-advanced">Advanced Launcher</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Escalation Integrity</div><div class="value">92%</div></div>
        <div class="card"><div class="label">Lineage Stability</div><div class="value">HIGH</div></div>
        <div class="card"><div class="label">Ownership Drift</div><div class="value">WATCH</div></div>
        <div class="card"><div class="label">Orphaned Escalations</div><div class="value">1</div></div>
    </div>

    <div class="section">
        <h2>Escalation Lineage Decision</h2>

        <div class="decision">
            ESCALATION LINEAGE IS MOSTLY STABLE — DETECTED ONE OWNERSHIP DRIFT CONDITION
        </div>

        <p>
            ShiftTrust™ treats escalation inheritance as a governance chain. Escalations should not
            disappear during handoff or lose accountable ownership.
        </p>
    </div>

    <div class="section">
        <h2>Escalation Inheritance Chain</h2>

        <table>
            <tr>
                <th>Operational Escalation</th>
                <th>Origin Shift</th>
                <th>Inherited By</th>
                <th>Lineage State</th>
                <th>Risk</th>
            </tr>

            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Governance Controls</h2>

        <table>
            <tr>
                <th>Control</th>
                <th>Expected Governance Effect</th>
            </tr>

            {control_rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>

        <div class="decision">
            SHIFTTRUST™ PREVENTS ESCALATION HISTORY FROM BREAKING DURING SHIFT HANDOFF
        </div>

        <p>
            Traditional escalation systems track tickets. ShiftTrust™ tracks escalation inheritance,
            operational accountability, continuity lineage, and unresolved governance responsibility
            across permanent shift structures.
        </p>
    </div>
    """

    return rlt_page("ShiftTrust Escalation Lineage Engine", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("Shift Escalation Lineage Engine patch applied.")
