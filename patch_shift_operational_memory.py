from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_OPERATIONAL_MEMORY_ENGINE_ACTIVE"

if MARKER in text:
    print("Shift Operational Memory Engine already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_AUTONOMOUS_CONTINUITY_INTELLIGENCE_ACTIVE",
    "SHIFT_PEER_BACKUP_COVERAGE_RESILIENCE_ACTIVE",
    "SHIFT_MISSION_CONTROL_ACTIVE",
    "SHIFT_EXECUTIVE_NARRATIVE_ENGINE_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_OPERATIONAL_MEMORY_ENGINE_ACTIVE
# ShiftTrust™ Operational Memory Engine
# ============================================================

@app.route("/shift-operational-memory")
def shift_operational_memory():
    memory_chain = [
        {
            "event": "MES/eBR escalation opened",
            "owner": "Night Shift",
            "inheritance": "Transferred to incoming peer pair",
            "risk": "LOW",
            "continuity": "Operational memory preserved"
        },
        {
            "event": "Walkaround deviation watch item",
            "owner": "Shift B2",
            "inheritance": "Escalated with acknowledgement",
            "risk": "WATCH",
            "continuity": "Visibility maintained"
        },
        {
            "event": "Printer/labeler instability",
            "owner": "Shift D1",
            "inheritance": "Not acknowledged before handoff",
            "risk": "HIGH",
            "continuity": "Operational memory degradation risk"
        },
    ]

    recommendations = [
        {
            "control": "Force acknowledgement before shift closure",
            "effect": "Prevents operational memory decay"
        },
        {
            "control": "Require named incoming owner",
            "effect": "Maintains escalation lineage"
        },
        {
            "control": "Track unresolved carryover recurrence",
            "effect": "Detects continuity drift"
        },
        {
            "control": "Preserve peer overlap during rotations",
            "effect": "Protects inherited operational context"
        },
    ]

    rows = ''.join([
        f"""
        <tr>
            <td>{x["event"]}</td>
            <td>{x["owner"]}</td>
            <td>{x["inheritance"]}</td>
            <td><span class="pill">{x["risk"]}</span></td>
            <td>{x["continuity"]}</td>
        </tr>
        """
        for x in memory_chain
    ])

    rec_rows = ''.join([
        f"""
        <tr>
            <td>{x["control"]}</td>
            <td>{x["effect"]}</td>
        </tr>
        """
        for x in recommendations
    ])

    body = f"""
    <div class="hero">
        <h1>ShiftTrust™ Operational Memory Engine</h1>

        <div class="sub">
            Protects operational inheritance across shifts. ShiftTrust™ ensures unresolved issues,
            escalation context, peer intelligence, governance signals, and continuity risk do not
            disappear during handoff.
        </div>

        <div class="nav">
            <a href="/shift-mission-control">Mission Control</a>
            <a href="/shift-executive-summary">Executive Summary</a>
            <a href="/shift-executive-narrative">Executive Narrative</a>
            <a href="/shift-autonomous-continuity">Autonomous Continuity</a>
            <a href="/shift-advanced">Advanced Launcher</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Operational Memory Integrity</div><div class="value">94%</div></div>
        <div class="card"><div class="label">Inheritance Stability</div><div class="value">HIGH</div></div>
        <div class="card"><div class="label">Escalation Continuity</div><div class="value">91%</div></div>
        <div class="card"><div class="label">Knowledge Persistence</div><div class="value">STABLE</div></div>
    </div>

    <div class="section">
        <h2>Operational Memory Decision</h2>

        <div class="decision">
            OPERATIONAL MEMORY IS STABLE — ENFORCE ACKNOWLEDGED HANDOFF BEFORE SHIFT CLOSURE
        </div>

        <p>
            Traditional shift tools assume technicians will remember context manually.
            ShiftTrust™ Operational Memory Engine treats continuity inheritance as a governance control.
        </p>
    </div>

    <div class="section">
        <h2>Operational Inheritance Chain</h2>

        <table>
            <tr>
                <th>Operational Event</th>
                <th>Current Owner</th>
                <th>Inheritance State</th>
                <th>Risk</th>
                <th>Continuity Result</th>
            </tr>

            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Memory Protection Controls</h2>

        <table>
            <tr>
                <th>Governance Control</th>
                <th>Expected Effect</th>
            </tr>

            {rec_rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>

        <div class="decision">
            SHIFTTRUST™ TREATS OPERATIONAL MEMORY AS A GOVERNANCE ASSET
        </div>

        <p>
            In time-critical manufacturing support, operational failure is often caused by lost context,
            invisible escalation history, weak handoff inheritance, or unresolved issues disappearing between shifts.
            ShiftTrust™ Operational Memory Engine prevents continuity intelligence from being lost.
        </p>
    </div>
    """

    return rlt_page("ShiftTrust Operational Memory Engine", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("Shift Operational Memory Engine patch applied.")
