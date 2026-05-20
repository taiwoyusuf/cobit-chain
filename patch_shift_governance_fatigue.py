from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_GOVERNANCE_FATIGUE_HEATMAP_ACTIVE"

if MARKER in text:
    print("Shift Governance Fatigue Heatmap already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_AUTONOMOUS_CONTINUITY_INTELLIGENCE_ACTIVE",
    "SHIFT_TREATMENT_CONTINUITY_RISK_ENGINE_ACTIVE",
    "SHIFT_PEER_BACKUP_COVERAGE_RESILIENCE_ACTIVE",
    "SHIFT_TOPOLOGY_INTELLIGENCE_ACTIVE",
    "SHIFT_ROTATION_DIGITAL_TWIN_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_GOVERNANCE_FATIGUE_HEATMAP_ACTIVE
# Governance Fatigue Heatmap™
# Advanced ShiftTrust™ operational pressure model
# ============================================================

@app.route("/shift-governance-fatigue")
def shift_governance_fatigue_heatmap():
    heatmap = [
        {"area": "Night Shift Burden", "pressure": "HIGH", "score": "76%", "meaning": "Night coverage requires fatigue-aware governance monitoring."},
        {"area": "Carryover Work Orders", "pressure": "MEDIUM", "score": "84%", "meaning": "Repeated carryover may indicate unresolved root-cause pressure."},
        {"area": "Backup Dependency", "pressure": "MEDIUM", "score": "82%", "meaning": "Peer backup paths exist but must not become the normal operating model."},
        {"area": "Overlap Degradation", "pressure": "WATCH", "score": "88%", "meaning": "Overlap remains functional but acknowledgement timing should be monitored."},
        {"area": "Triage Compression", "pressure": "MEDIUM", "score": "81%", "meaning": "30-minute triage expectation is close to stress threshold."},
        {"area": "Walkaround Closure", "pressure": "HIGH", "score": "74%", "meaning": "Open floor-observation items can decay at handoff if not closed."},
        {"area": "Treatment Continuity Pressure", "pressure": "WATCH", "score": "84%", "meaning": "Patient-aware timing remains protected but sensitive to unresolved support risk."},
    ]

    mitigations = [
        {"action": "Force unresolved walkaround item into next-shift acceptance.", "effect": "Prevents silent visibility loss."},
        {"action": "Track repeated carryover across three shift cycles.", "effect": "Detects operational fatigue pattern."},
        {"action": "Escalate if two-person coverage drops to one.", "effect": "Protects operational survivability."},
        {"action": "Monitor night-shift watch items separately from day-shift issues.", "effect": "Prevents hidden night coverage pressure."},
        {"action": "Trigger peer backup readiness review before high-risk production windows.", "effect": "Improves treatment-continuity resilience."},
    ]

    rows = ''.join([
        f'<tr><td>{x["area"]}</td><td><span class="pill">{x["pressure"]}</span></td><td>{x["score"]}</td><td>{x["meaning"]}</td></tr>'
        for x in heatmap
    ])

    mitigation_rows = ''.join([
        f'<tr><td>{x["action"]}</td><td>{x["effect"]}</td></tr>'
        for x in mitigations
    ])

    body = f"""
    <div class="hero">
        <h1>Governance Fatigue Heatmap™</h1>
        <div class="sub">
            Operational pressure model for ShiftTrust™. This does not monitor people personally.
            It monitors whether the shift structure is accumulating governance pressure that could weaken
            continuity, handoff quality, backup resilience, triage response, and treatment-continuity support.
        </div>
        <div class="nav">
            <a href="/shift-advanced">ShiftTrust Launcher</a>
            <a href="/shift-autonomous-continuity">Autonomous Continuity</a>
            <a href="/shift-treatment-continuity">Treatment Continuity</a>
            <a href="/shift-peer-backup">Peer Backup</a>
            <a href="/shift-rotation-digital-twin">Workforce Twin</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Governance Fatigue</div><div class="value" style="font-size:24px;">MED-HIGH</div></div>
        <div class="card"><div class="label">Highest Pressure</div><div class="value" style="font-size:23px;">Walkaround Closure</div></div>
        <div class="card"><div class="label">Night Shift Pressure</div><div class="value">76%</div></div>
        <div class="card"><div class="label">Triage Compression</div><div class="value">81%</div></div>
        <div class="card"><div class="label">Continuity Risk</div><div class="value" style="font-size:24px;">WATCH</div></div>
        <div class="card"><div class="label">Recovery State</div><div class="value" style="font-size:24px;">AVAILABLE</div></div>
    </div>

    <div class="section">
        <h2>Fatigue Decision</h2>
        <div class="decision">GOVERNANCE PRESSURE DETECTED — CLOSE WALKAROUND AND CARRYOVER ITEMS BEFORE PRESSURE SPREADS</div>
        <p>
            This module converts operational strain into governance intelligence. It helps leadership see when shift
            pressure is building before it becomes a missed handoff, delayed triage, unresolved escalation, deviation,
            or treatment-continuity concern.
        </p>
    </div>

    <div class="section">
        <h2>Operational Pressure Heatmap</h2>
        <table>
            <tr><th>Pressure Area</th><th>Pressure</th><th>Score</th><th>Meaning</th></tr>
            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Pressure Reduction Actions</h2>
        <table>
            <tr><th>Action</th><th>Expected Governance Effect</th></tr>
            {mitigation_rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>
        <p>
            Most tools only show staffing and tickets. Governance Fatigue Heatmap™ shows where the operating model is
            accumulating pressure and where leadership should intervene before continuity weakens.
        </p>
    </div>
    """

    return rlt_page("Governance Fatigue Heatmap", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("Shift Governance Fatigue Heatmap patch applied.")
