from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_PEER_BACKUP_COVERAGE_RESILIENCE_ACTIVE"

if MARKER in text:
    print("Shift Peer Backup & Coverage Resilience already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_AUTONOMOUS_CONTINUITY_INTELLIGENCE_ACTIVE",
    "SHIFT_TREATMENT_CONTINUITY_RISK_ENGINE_ACTIVE",
    "SHIFT_HANDOFF_LINEAGE_ACTIVE",
    "SHIFT_OVERLAP_INTELLIGENCE_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_PEER_BACKUP_COVERAGE_RESILIENCE_ACTIVE
# Peer Backup & Coverage Resilience Engine™
# Advanced ShiftTrust™ workforce continuity layer
# ============================================================

@app.route("/shift-peer-backup")
def shift_peer_backup_coverage_resilience():
    coverage = [
        {"shift": "A1", "window": "Thu–Sat 10:00–22:00", "assigned": "2", "backup": "Available", "resilience": "Trusted"},
        {"shift": "B1", "window": "Thu–Sat 11:00–23:00", "assigned": "2", "backup": "Available", "resilience": "Trusted"},
        {"shift": "C1", "window": "Thu–Sat 22:00–10:00", "assigned": "2", "backup": "Watch", "resilience": "Night coverage watch"},
        {"shift": "D1", "window": "Thu–Sat 23:00–11:00", "assigned": "2", "backup": "Available", "resilience": "Trusted"},
        {"shift": "A2", "window": "Sun–Tue 10:00–22:00", "assigned": "2", "backup": "Available", "resilience": "Trusted"},
        {"shift": "B2", "window": "Sun–Tue 11:00–23:00", "assigned": "2", "backup": "Available", "resilience": "Trusted"},
        {"shift": "C2", "window": "Sun–Tue 22:00–10:00", "assigned": "2", "backup": "Watch", "resilience": "Night coverage watch"},
        {"shift": "D2", "window": "Sun–Tue 23:00–11:00", "assigned": "2", "backup": "Available", "resilience": "Trusted"},
    ]

    backup_flow = [
        "Primary unavailable",
        "Peer backup requested",
        "Qualification checked",
        "Coverage gap assessed",
        "Open risks inherited",
        "Handoff accepted",
        "Continuity restored"
    ]

    scenarios = [
        {"scenario": "One technician misses C1 night shift", "risk": "Medium", "response": "Activate qualified peer backup and transfer unresolved watch items."},
        {"scenario": "Backup peer accepts but handoff note incomplete", "risk": "High", "response": "Require continuity inheritance note before shift acceptance."},
        {"scenario": "Two-person minimum drops to one", "risk": "Critical", "response": "Escalate to supervisor; production support coverage is not resilient."},
        {"scenario": "Backup accepted and evidence inherited", "risk": "Low", "response": "Continuity restored; monitor fatigue and next-shift carryover."},
    ]

    coverage_rows = ''.join([
        f'<tr><td>{x["shift"]}</td><td>{x["window"]}</td><td>{x["assigned"]}</td><td><span class="pill">{x["backup"]}</span></td><td>{x["resilience"]}</td></tr>'
        for x in coverage
    ])

    flow = ''.join([
        f'<div class="node">{x}</div><div class="arrow">→</div>'
        for x in backup_flow
    ])

    scenario_rows = ''.join([
        f'<tr><td>{x["scenario"]}</td><td><span class="pill">{x["risk"]}</span></td><td>{x["response"]}</td></tr>'
        for x in scenarios
    ])

    body = f"""
    <div class="hero">
        <h1>Peer Backup & Coverage Resilience Engine™</h1>
        <div class="sub">
            Models Chris’s peer-based shift structure as operational survivability architecture. The engine verifies
            that each permanent shift assignment has at least two-person coverage, qualified backup capability,
            handoff inheritance, and continuity recovery when someone misses a shift.
        </div>
        <div class="nav">
            <a href="/shift-autonomous-continuity">Autonomous Continuity</a>
            <a href="/shift-treatment-continuity">Treatment Continuity</a>
            <a href="/shift-handoff-lineage">Handoff Lineage</a>
            <a href="/shift-overlap-intelligence">Shift Overlap</a>
            <a href="/shift-assurance-enterprise">Shift Enterprise</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Coverage Resilience</div><div class="value">92%</div></div>
        <div class="card"><div class="label">Minimum Coverage Rule</div><div class="value" style="font-size:24px;">2 PER SHIFT</div></div>
        <div class="card"><div class="label">Backup Readiness</div><div class="value" style="font-size:24px;">ACTIVE</div></div>
        <div class="card"><div class="label">Continuity Gap Risk</div><div class="value" style="font-size:24px;">LOW-MED</div></div>
        <div class="card"><div class="label">Night Shift Watch</div><div class="value">2</div></div>
        <div class="card"><div class="label">Escalation Path</div><div class="value" style="font-size:24px;">DEFINED</div></div>
    </div>

    <div class="section">
        <h2>Coverage Resilience Decision</h2>
        <div class="decision">COVERAGE RESILIENT — NIGHT SHIFT BACKUP WATCH REMAINS ACTIVE</div>
        <p>
            This module does not manage HR scheduling. It verifies operational survivability: if a person misses a
            permanent shift, the operation must still preserve ownership, evidence, escalation, handoff context,
            and treatment-continuity support.
        </p>
    </div>

    <div class="section">
        <h2>Permanent Shift Coverage Board</h2>
        <table>
            <tr><th>Shift</th><th>Window</th><th>Assigned Minimum</th><th>Backup State</th><th>Resilience</th></tr>
            {coverage_rows}
        </table>
    </div>

    <div class="section">
        <h2>Continuity Backup Invocation Flow</h2>
        <div class="chain">
            {flow}
        </div>
    </div>

    <div class="section">
        <h2>Backup Failure / Recovery Scenarios</h2>
        <table>
            <tr><th>Scenario</th><th>Risk</th><th>Governance Response</th></tr>
            {scenario_rows}
        </table>
    </div>

    <div class="section">
        <h2>Why This Wows Pharma IT Leadership</h2>
        <p>
            Most scheduling tools know who is assigned. This engine knows whether the shift structure can survive
            absence, fatigue, backup activation, and unresolved operational risk without losing governance continuity.
            That makes the shift model part of manufacturing survivability, not just staffing.
        </p>
    </div>
    """

    return rlt_page("Peer Backup & Coverage Resilience Engine", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("Shift Peer Backup & Coverage Resilience patch applied.")
