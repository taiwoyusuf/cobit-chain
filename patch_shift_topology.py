from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_TOPOLOGY_INTELLIGENCE_ACTIVE"

if MARKER in text:
    print("Shift Topology Intelligence already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_AUTONOMOUS_CONTINUITY_INTELLIGENCE_ACTIVE",
    "SHIFT_TREATMENT_CONTINUITY_RISK_ENGINE_ACTIVE",
    "SHIFT_PEER_BACKUP_COVERAGE_RESILIENCE_ACTIVE",
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
# SHIFT_TOPOLOGY_INTELLIGENCE_ACTIVE
# Shift Topology Intelligence™
# Permanent shift-structure governance model
# ============================================================

@app.route("/shift-topology")
def shift_topology_intelligence():
    shifts = [
        {"shift": "A1", "days": "Thu–Sat", "window": "10:00–22:00", "type": "Day", "overlap": "B1 + C1 transition", "risk": "LOW"},
        {"shift": "B1", "days": "Thu–Sat", "window": "11:00–23:00", "type": "Day/Evening", "overlap": "A1 + D1 transition", "risk": "LOW"},
        {"shift": "C1", "days": "Thu–Sat", "window": "22:00–10:00", "type": "Night", "overlap": "A1 recovery window", "risk": "WATCH"},
        {"shift": "D1", "days": "Thu–Sat", "window": "23:00–11:00", "type": "Night/Morning", "overlap": "B1 recovery window", "risk": "WATCH"},
        {"shift": "A2", "days": "Sun–Tue", "window": "10:00–22:00", "type": "Day", "overlap": "B2 + C2 transition", "risk": "LOW"},
        {"shift": "B2", "days": "Sun–Tue", "window": "11:00–23:00", "type": "Day/Evening", "overlap": "A2 + D2 transition", "risk": "LOW"},
        {"shift": "C2", "days": "Sun–Tue", "window": "22:00–10:00", "type": "Night", "overlap": "A2 recovery window", "risk": "WATCH"},
        {"shift": "D2", "days": "Sun–Tue", "window": "23:00–11:00", "type": "Night/Morning", "overlap": "B2 recovery window", "risk": "WATCH"},
    ]

    topology_rules = [
        {"rule": "Permanent assignment becomes operating baseline", "value": "Long-term continuity patterns become measurable."},
        {"rule": "Minimum two-person coverage per shift", "value": "Reduces single-point operational dependency."},
        {"rule": "Overlap is treated as governance control", "value": "Supports huddles, activity handover, and operational memory transfer."},
        {"rule": "Night shifts carry watch weighting", "value": "Models fatigue, escalation, and handoff survivability risk."},
        {"rule": "Backup peers inherit unresolved risks", "value": "Prevents issues from disappearing when someone misses shift."},
    ]

    rows = ''.join([
        f'<tr><td>{x["shift"]}</td><td>{x["days"]}</td><td>{x["window"]}</td><td>{x["type"]}</td><td>{x["overlap"]}</td><td><span class="pill">{x["risk"]}</span></td></tr>'
        for x in shifts
    ])

    rule_rows = ''.join([
        f'<tr><td>{x["rule"]}</td><td>{x["value"]}</td></tr>'
        for x in topology_rules
    ])

    body = f"""
    <div class="hero">
        <h1>Shift Topology Intelligence™</h1>
        <div class="sub">
            Models the permanent A1/B1/C1/D1 and A2/B2/C2/D2 structure as an operational continuity architecture,
            not just a schedule. It evaluates coverage, overlap, night-shift watch, backup survivability,
            and long-term manufacturing support stability.
        </div>
        <div class="nav">
            <a href="/shift-peer-backup">Peer Backup</a>
            <a href="/shift-treatment-continuity">Treatment Continuity</a>
            <a href="/shift-autonomous-continuity">Autonomous Continuity</a>
            <a href="/shift-overlap-intelligence">Shift Overlap</a>
            <a href="/shift-handoff-lineage">Handoff Lineage</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Topology Stability</div><div class="value">93%</div></div>
        <div class="card"><div class="label">Permanent Shifts</div><div class="value">8</div></div>
        <div class="card"><div class="label">Coverage Model</div><div class="value" style="font-size:24px;">2+ PER SHIFT</div></div>
        <div class="card"><div class="label">Night Watch Nodes</div><div class="value">4</div></div>
        <div class="card"><div class="label">Overlap Control</div><div class="value" style="font-size:24px;">ACTIVE</div></div>
        <div class="card"><div class="label">Continuity Baseline</div><div class="value" style="font-size:24px;">DEFINED</div></div>
    </div>

    <div class="section">
        <h2>Topology Decision</h2>
        <div class="decision">PERMANENT SHIFT TOPOLOGY IS GOVERNABLE — NIGHT-SHIFT WATCH CONTROLS REQUIRED</div>
        <p>
            This module treats the shift structure as an operational trust topology. Once assignments become permanent,
            COBIT-Chain™ can monitor whether the structure preserves support continuity, escalation flow,
            backup survivability, and treatment-continuity support over time.
        </p>
    </div>

    <div class="section">
        <h2>Permanent Shift Topology Board</h2>
        <table>
            <tr><th>Shift</th><th>Days</th><th>Window</th><th>Type</th><th>Continuity / Overlap Logic</th><th>Risk</th></tr>
            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Topology Governance Rules</h2>
        <table>
            <tr><th>Rule</th><th>Governance Value</th></tr>
            {rule_rows}
        </table>
    </div>

    <div class="section">
        <h2>Why This Is Advanced</h2>
        <p>
            A normal scheduling system records who works when. Shift Topology Intelligence™ asks whether the permanent
            operating structure can preserve governance continuity during absence, fatigue, handoff pressure,
            support incidents, and time-critical manufacturing windows.
        </p>
    </div>
    """

    return rlt_page("Shift Topology Intelligence", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("Shift Topology Intelligence patch applied.")
