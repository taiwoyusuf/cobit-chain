from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

ACTIVE_MARKER = "# RLT_OPERATIONAL_DIGITAL_TWIN_ACTIVE"

if ACTIVE_MARKER in text:
    print("RLT Operational Digital Twin already exists. No duplicate patch applied.")
    raise SystemExit(0)

required = [
    "RLT_OPERATIONS_VERTICAL_ACTIVE",
    "RLT_CAPA_EFFECTIVENESS_INTELLIGENCE_ACTIVE",
    "RLT_AUTONOMOUS_DEVIATION_PREVENTION_ACTIVE",
    "RLT_EXECUTIVE_WAR_ROOM_ACTIVE",
    "RLT_REAL_TIME_MANUFACTURING_CONFIDENCE_ACTIVE",
    "RLT_BATCH_TRUST_PASSPORT_ACTIVE",
    "RLT_AUTONOMOUS_GMP_TRUST_FABRIC_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required existing marker not found: {item}")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError('Could not find if __name__ == "__main__": insertion point.')

code = r'''

# ============================================================
# RLT_OPERATIONAL_DIGITAL_TWIN_ACTIVE
# RLT Operational Digital Twin™
# Advanced RLT Operations AssuranceLayer™ module
# ============================================================

RLT_OPERATIONAL_DIGITAL_TWIN_DATA = {
    "twin_state": "SYNCHRONIZED WITH WATCH NODES",
    "synchronization": 92,
    "confidence": 91,
    "active_watch_nodes": 3,
    "decision": "DIGITAL TWIN ALIGNED — TARGETED CLOSURE REQUIRED",
    "nodes": [
        {"node": "Production Window", "live_state": "Active", "mirror_state": "Aligned", "confidence": "95%"},
        {"node": "Equipment Readiness", "live_state": "Ready", "mirror_state": "Aligned", "confidence": "95%"},
        {"node": "Operator Qualification", "live_state": "Qualified", "mirror_state": "Aligned", "confidence": "100%"},
        {"node": "SOP State", "live_state": "Current", "mirror_state": "Aligned", "confidence": "98%"},
        {"node": "Shift Handoff", "live_state": "Watch", "mirror_state": "Minor drift", "confidence": "91%"},
        {"node": "Environmental Rationale", "live_state": "Partial", "mirror_state": "Open condition", "confidence": "86%"},
        {"node": "Release Confidence", "live_state": "Conditional", "mirror_state": "Aligned", "confidence": "90%"},
        {"node": "CAPA Effectiveness", "live_state": "Monitoring", "mirror_state": "Aligned", "confidence": "87%"},
    ],
    "scenario_paths": [
        {"scenario": "Environmental rationale closed", "predicted_effect": "Release confidence rises from 90% to 95%", "impact": "Positive"},
        {"scenario": "Handoff delay repeats next run", "predicted_effect": "Shift integrity drops from 91% to 84%", "impact": "Watch"},
        {"scenario": "Secondary reviewer unavailable", "predicted_effect": "Approval bottleneck risk increases", "impact": "Medium"},
        {"scenario": "CAPA recurrence signal improves", "predicted_effect": "Effectiveness confidence increases", "impact": "Positive"},
    ],
    "interventions": [
        {"intervention": "Close environmental rationale condition.", "expected_outcome": "Improves release confidence and trust fabric."},
        {"intervention": "Stabilize backup reviewer coverage.", "expected_outcome": "Reduces approval bottleneck risk."},
        {"intervention": "Monitor handoff recurrence across next run.", "expected_outcome": "Prevents human-process drift from escalating."},
    ]
}

@app.route("/rlt-operations/digital-twin")
def rlt_operational_digital_twin():
    d = RLT_OPERATIONAL_DIGITAL_TWIN_DATA

    node_rows = ''.join([
        f'<tr><td>{x["node"]}</td><td>{x["live_state"]}</td><td><span class="pill">{x["mirror_state"]}</span></td><td>{x["confidence"]}</td></tr>'
        for x in d["nodes"]
    ])

    scenario_rows = ''.join([
        f'<tr><td>{x["scenario"]}</td><td>{x["predicted_effect"]}</td><td><span class="pill">{x["impact"]}</span></td></tr>'
        for x in d["scenario_paths"]
    ])

    intervention_rows = ''.join([
        f'<tr><td>{x["intervention"]}</td><td>{x["expected_outcome"]}</td></tr>'
        for x in d["interventions"]
    ])

    body = f"""
    <div class="hero">
        <h1>RLT Operational Digital Twin™</h1>
        <div class="sub">
            A live governance mirror of RLT manufacturing state. This twin reflects production readiness,
            equipment state, operator qualification, SOP alignment, shift handoff, environmental rationale,
            release confidence, CAPA effectiveness, and trust-fabric signals.
        </div>
        <div class="nav">
            <a href="/rlt-operations/executive-war-room">Executive War Room</a>
            <a href="/rlt-operations/manufacturing-confidence">Manufacturing Confidence</a>
            <a href="/rlt-operations/release-confidence">Release Confidence</a>
            <a href="/rlt-operations/capa-effectiveness">CAPA Effectiveness</a>
            <a href="/rlt-operations/deviation-prevention">Deviation Prevention</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Twin State</div><div class="value" style="font-size:23px;">{d["twin_state"]}</div></div>
        <div class="card"><div class="label">Synchronization</div><div class="value">{d["synchronization"]}%</div></div>
        <div class="card"><div class="label">Confidence</div><div class="value">{d["confidence"]}%</div></div>
        <div class="card"><div class="label">Active Watch Nodes</div><div class="value">{d["active_watch_nodes"]}</div></div>
    </div>

    <div class="section">
        <h2>Digital Twin Decision</h2>
        <div class="decision">{d["decision"]}</div>
        <p>
            This twin does not replace manufacturing systems. It mirrors the governance state across operations
            so leadership can see where the live operating reality matches, drifts from, or partially supports the
            intended controlled state.
        </p>
    </div>

    <div class="section">
        <h2>Live State vs Governance Mirror</h2>
        <table>
            <tr><th>Twin Node</th><th>Live State</th><th>Governance Mirror</th><th>Confidence</th></tr>
            {node_rows}
        </table>
    </div>

    <div class="section">
        <h2>What-If Scenario Paths</h2>
        <table>
            <tr><th>Scenario</th><th>Predicted Effect</th><th>Impact</th></tr>
            {scenario_rows}
        </table>
    </div>

    <div class="section">
        <h2>Recommended Twin Interventions</h2>
        <table>
            <tr><th>Intervention</th><th>Expected Outcome</th></tr>
            {intervention_rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>
        <p>
            The Operational Digital Twin™ gives RLT leadership a living mirror of controlled-state health.
            It turns scattered signals into a synchronized view of what is aligned, what is drifting, and what must
            be closed before assurance becomes fully defensible.
        </p>
    </div>
    """

    return rlt_page("RLT Operational Digital Twin", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("RLT Operational Digital Twin patch applied successfully.")
