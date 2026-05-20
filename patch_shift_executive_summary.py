from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_EXECUTIVE_SUMMARY_ACTIVE"

if MARKER in text:
    print("ShiftTrust Executive Summary already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_MISSION_CONTROL_ACTIVE",
    "SHIFT_TREATMENT_CONTINUITY_RISK_ENGINE_ACTIVE",
    "SHIFT_PEER_BACKUP_COVERAGE_RESILIENCE_ACTIVE",
    "SHIFT_TOPOLOGY_INTELLIGENCE_ACTIVE",
    "SHIFT_ROTATION_DIGITAL_TWIN_ACTIVE",
    "SHIFT_GOVERNANCE_FATIGUE_HEATMAP_ACTIVE",
    "SHIFT_TREATMENT_WINDOW_COMPRESSION_ACTIVE",
    "SHIFT_OPERATIONAL_GRAVITY_ENGINE_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_EXECUTIVE_SUMMARY_ACTIVE
# ShiftTrust Executive Summary
# Leadership summary page for advanced ShiftTrust™
# ============================================================

@app.route("/shift-executive-summary")
def shift_executive_summary():
    body = """
    <div class="hero">
        <h1>ShiftTrust™ Executive Summary</h1>
        <div class="sub">
            A leadership-ready summary of how the permanent shift model becomes an operational survivability
            architecture for time-critical manufacturing support.
        </div>
        <div class="nav">
            <a href="/shift-mission-control">Mission Control</a>
            <a href="/shift-advanced">Advanced Launcher</a>
            <a href="/shift-treatment-continuity">Treatment Continuity</a>
            <a href="/shift-operational-gravity">Operational Gravity</a>
            <a href="/command-center">Command Center</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Executive Message</div><div class="value" style="font-size:22px;">Operational Survivability</div></div>
        <div class="card"><div class="label">Treatment Continuity</div><div class="value">84%</div></div>
        <div class="card"><div class="label">Coverage Resilience</div><div class="value">92%</div></div>
        <div class="card"><div class="label">Topology Stability</div><div class="value">93%</div></div>
        <div class="card"><div class="label">Window Compression</div><div class="value">18%</div></div>
        <div class="card"><div class="label">Operational Gravity</div><div class="value">31%</div></div>
    </div>

    <div class="section">
        <h2>Plain-English Summary</h2>
        <div class="decision">SHIFTTRUST™ SHOWS WHETHER THE SHIFT STRUCTURE CAN KEEP OPERATIONS GOVERNABLE UNDER PRESSURE</div>
        <p>
            This is not a scheduling tool. It is a governance intelligence layer that helps leadership see whether
            permanent shift assignments, peer backup, handoff continuity, night-shift pressure, unresolved support
            issues, and treatment-window timing remain controlled.
        </p>
    </div>

    <div class="section">
        <h2>What Makes This Different</h2>
        <table>
            <tr><th>Traditional Shift Tool</th><th>ShiftTrust™</th></tr>
            <tr><td>Shows who is working</td><td>Shows whether the operation can survive missed shifts, unresolved issues, and timing pressure.</td></tr>
            <tr><td>Tracks handoff notes</td><td>Preserves operational memory, ownership, escalation, evidence, and treatment-continuity context.</td></tr>
            <tr><td>Lists open issues</td><td>Ranks which issue has the strongest operational gravity and downstream risk pull.</td></tr>
            <tr><td>Shows schedule coverage</td><td>Verifies two-person resilience, backup survivability, and future rotation impact.</td></tr>
        </table>
    </div>

    <div class="section">
        <h2>Leadership Value</h2>
        <p>
            ShiftTrust™ gives leadership a way to see if the shift model is protecting time-critical manufacturing
            continuity. It connects shift assignment, peer redundancy, backup invocation, handoff inheritance,
            governance fatigue, operational gravity, and treatment-window compression into one executive view.
        </p>
    </div>

    <div class="section">
        <h2>Best Demo Flow</h2>
        <table>
            <tr><th>Step</th><th>Page</th><th>What To Say</th></tr>
            <tr><td>1</td><td><a href="/shift-executive-summary">Executive Summary</a></td><td>This explains why ShiftTrust™ is not a schedule app.</td></tr>
            <tr><td>2</td><td><a href="/shift-mission-control">Mission Control</a></td><td>This shows the full operational trust cockpit.</td></tr>
            <tr><td>3</td><td><a href="/shift-treatment-continuity">Treatment Continuity</a></td><td>This connects shift issues to patient-aware timing risk.</td></tr>
            <tr><td>4</td><td><a href="/shift-operational-gravity">Operational Gravity</a></td><td>This shows the issue pulling the operation toward instability.</td></tr>
            <tr><td>5</td><td><a href="/shift-treatment-window-compression">Window Compression</a></td><td>This shows how unresolved support issues consume timing buffer.</td></tr>
        </table>
    </div>
    """

    return rlt_page("ShiftTrust Executive Summary", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("ShiftTrust Executive Summary patch applied.")
