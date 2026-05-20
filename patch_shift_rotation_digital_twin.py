from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_ROTATION_DIGITAL_TWIN_ACTIVE"

if MARKER in text:
    print("Shift Rotation Digital Twin already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_TOPOLOGY_INTELLIGENCE_ACTIVE",
    "SHIFT_PEER_BACKUP_COVERAGE_RESILIENCE_ACTIVE",
    "SHIFT_TREATMENT_CONTINUITY_RISK_ENGINE_ACTIVE",
    "SHIFT_AUTONOMOUS_CONTINUITY_INTELLIGENCE_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_ROTATION_DIGITAL_TWIN_ACTIVE
# Workforce Continuity Digital Twin™
# Future shift rotation impact simulator
# ============================================================

@app.route("/shift-rotation-digital-twin")
def shift_rotation_digital_twin():
    current_state = [
        {"domain": "Permanent Assignment Baseline", "state": "DEFINED", "confidence": "93%", "meaning": "Current assignment becomes the stable operating baseline."},
        {"domain": "Minimum 2-Person Coverage", "state": "MET", "confidence": "92%", "meaning": "Each shift can maintain peer redundancy."},
        {"domain": "Night Shift Burden", "state": "WATCH", "confidence": "84%", "meaning": "Night coverage requires fatigue and backup monitoring."},
        {"domain": "Backup Survivability", "state": "ACTIVE", "confidence": "90%", "meaning": "Peer backup paths exist for missed shift coverage."},
        {"domain": "Treatment Continuity Protection", "state": "CONTROLLED", "confidence": "88%", "meaning": "Shift structure still protects time-critical manufacturing support."},
    ]

    rotation_scenarios = [
        {"scenario": "Rotate one C-shift technician to day shift", "effect": "Night-shift resilience drops unless backup peer is reassigned.", "risk": "Medium"},
        {"scenario": "Rotate day technician into night coverage", "effect": "Knowledge distribution improves, but fatigue watch increases.", "risk": "Medium"},
        {"scenario": "Rotate without preserving 2-person minimum", "effect": "Coverage survivability becomes non-governable.", "risk": "Critical"},
        {"scenario": "Rotate with peer-pair continuity preserved", "effect": "Operational memory survives and handoff trust remains stable.", "risk": "Low"},
    ]

    recommendations = [
        {"recommendation": "Never rotate below two-person minimum coverage.", "value": "Protects operational survivability."},
        {"recommendation": "Preserve at least one experienced peer per shift during rotation.", "value": "Protects operational memory."},
        {"recommendation": "Run rotation simulation before final assignment change.", "value": "Prevents hidden continuity gaps."},
        {"recommendation": "Track night-shift fatigue as governance risk, not HR judgment.", "value": "Protects treatment-continuity support."},
    ]

    rows = ''.join([
        f'<tr><td>{x["domain"]}</td><td><span class="pill">{x["state"]}</span></td><td>{x["confidence"]}</td><td>{x["meaning"]}</td></tr>'
        for x in current_state
    ])

    scenario_rows = ''.join([
        f'<tr><td>{x["scenario"]}</td><td>{x["effect"]}</td><td><span class="pill">{x["risk"]}</span></td></tr>'
        for x in rotation_scenarios
    ])

    rec_rows = ''.join([
        f'<tr><td>{x["recommendation"]}</td><td>{x["value"]}</td></tr>'
        for x in recommendations
    ])

    body = f"""
    <div class="hero">
        <h1>Workforce Continuity Digital Twin™</h1>
        <div class="sub">
            Future rotation simulator for permanent shift assignments. It models how later rotation could affect
            two-person coverage, peer backup, night-shift burden, operational memory, handoff trust, and treatment-continuity support.
        </div>
        <div class="nav">
            <a href="/shift-topology">Shift Topology</a>
            <a href="/shift-peer-backup">Peer Backup</a>
            <a href="/shift-treatment-continuity">Treatment Continuity</a>
            <a href="/shift-autonomous-continuity">Autonomous Continuity</a>
            <a href="/shift-overlap-intelligence">Shift Overlap</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Rotation Readiness</div><div class="value">86%</div></div>
        <div class="card"><div class="label">Current Baseline</div><div class="value" style="font-size:24px;">STABLE</div></div>
        <div class="card"><div class="label">Future Rotation Risk</div><div class="value" style="font-size:24px;">MEDIUM</div></div>
        <div class="card"><div class="label">Coverage Rule</div><div class="value" style="font-size:24px;">2+ REQUIRED</div></div>
        <div class="card"><div class="label">Night Burden</div><div class="value" style="font-size:24px;">WATCH</div></div>
        <div class="card"><div class="label">Continuity Memory</div><div class="value" style="font-size:24px;">PRESERVE</div></div>
    </div>

    <div class="section">
        <h2>Rotation Simulation Decision</h2>
        <div class="decision">ROTATION POSSIBLE LATER — ONLY IF PEER REDUNDANCY AND OPERATIONAL MEMORY ARE PRESERVED</div>
        <p>
            This module does not manage HR scheduling. It simulates whether a future rotation would weaken operational
            survivability, treatment-continuity support, handoff trust, or backup coverage.
        </p>
    </div>

    <div class="section">
        <h2>Current Permanent Assignment Baseline</h2>
        <table>
            <tr><th>Domain</th><th>State</th><th>Confidence</th><th>Meaning</th></tr>
            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Future Rotation Scenario Simulator</h2>
        <table>
            <tr><th>Scenario</th><th>Predicted Operational Effect</th><th>Risk</th></tr>
            {scenario_rows}
        </table>
    </div>

    <div class="section">
        <h2>Safest Rotation Rules</h2>
        <table>
            <tr><th>Rule</th><th>Governance Value</th></tr>
            {rec_rows}
        </table>
    </div>
    """

    return rlt_page("Workforce Continuity Digital Twin", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("Shift Rotation Digital Twin patch applied.")
