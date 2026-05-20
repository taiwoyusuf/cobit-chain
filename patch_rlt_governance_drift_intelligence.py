from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

ACTIVE_MARKER = "# RLT_GOVERNANCE_DRIFT_INTELLIGENCE_ACTIVE"

if ACTIVE_MARKER in text:
    print("RLT Governance Drift Intelligence already exists. No duplicate patch applied.")
    raise SystemExit(0)

required = [
    "RLT_OPERATIONS_VERTICAL_ACTIVE",
    "RLT_SHIFT_INTEGRITY_ENGINE_ACTIVE",
    "RLT_AUTONOMOUS_AUDIT_RECONSTRUCTION_ACTIVE",
    "/predictive-governance-drift",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required existing marker/link not found: {item}")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError('Could not find if __name__ == "__main__": insertion point.')

code = r'''

# ============================================================
# RLT_GOVERNANCE_DRIFT_INTELLIGENCE_ACTIVE
# RLT Governance Drift Intelligence™
# Specialized RLT Operations AssuranceLayer™ module
# ============================================================

RLT_GOVERNANCE_DRIFT_DATA = {
    "drift_score": 18,
    "confidence": 89,
    "trend": "WATCH",
    "decision": "EARLY DRIFT DETECTED — MONITOR BEFORE ESCALATION",
    "signals": [
        {"area": "SOP vs Execution Alignment", "current": "96%", "trend": "Stable", "risk": "Low"},
        {"area": "Shift Handoff Completeness", "current": "91%", "trend": "Slight decline", "risk": "Medium"},
        {"area": "Reviewer Latency", "current": "88%", "trend": "Increasing delay", "risk": "Medium"},
        {"area": "CAPA Exposure", "current": "92%", "trend": "Stable", "risk": "Low"},
        {"area": "Environmental Review Timeliness", "current": "86%", "trend": "Watch", "risk": "Medium"},
        {"area": "Audit Confidence", "current": "89%", "trend": "Slight decline", "risk": "Medium"},
    ],
    "drift_path": [
        "Minor handoff delay",
        "Reviewer dependency",
        "Partial environmental rationale",
        "Audit confidence decline",
        "Potential deviation exposure"
    ],
    "actions": [
        {"action": "Trigger supervisor review of recurring handoff delays", "priority": "High"},
        {"action": "Confirm secondary reviewer availability before next production window", "priority": "High"},
        {"action": "Require environmental rationale closure before final assurance", "priority": "Medium"},
        {"action": "Monitor shift-level documentation fatigue pattern", "priority": "Medium"},
    ]
}

@app.route("/rlt-operations/governance-drift")
def rlt_governance_drift_intelligence():
    d = RLT_GOVERNANCE_DRIFT_DATA

    signal_rows = ''.join([
        f'<tr><td>{s["area"]}</td><td>{s["current"]}</td><td>{s["trend"]}</td><td><span class="pill">{s["risk"]}</span></td></tr>'
        for s in d["signals"]
    ])

    drift_chain = ''.join([
        f'<div class="node">{x}</div><div class="arrow">→</div>'
        for x in d["drift_path"]
    ])

    action_rows = ''.join([
        f'<tr><td>{a["action"]}</td><td><span class="pill">{a["priority"]}</span></td></tr>'
        for a in d["actions"]
    ])

    body = f"""
    <div class="hero">
        <h1>RLT Governance Drift Intelligence™</h1>
        <div class="sub">
            Specialized predictive governance monitoring for Radioligand Manufacturing: detects slow movement
            away from the approved operating state before it becomes a deviation, CAPA repeat issue, or audit finding.
        </div>
        <div class="nav">
            <a href="/rlt-operations">Back to RLT Mission Control</a>
            <a href="/rlt-operations/shift-integrity">Shift Integrity</a>
            <a href="/rlt-operations/audit-reconstruction">Audit Reconstruction</a>
            <a href="/predictive-governance-drift">Enterprise Drift Engine</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Drift Score</div><div class="value">{d["drift_score"]}%</div></div>
        <div class="card"><div class="label">Governance Confidence</div><div class="value">{d["confidence"]}%</div></div>
        <div class="card"><div class="label">Trend</div><div class="value">{d["trend"]}</div></div>
        <div class="card"><div class="label">Decision</div><div class="value" style="font-size:20px;">WATCH</div></div>
    </div>

    <div class="section">
        <h2>Drift Decision</h2>
        <div class="decision">{d["decision"]}</div>
        <p>
            This module does not wait for a deviation to happen. It monitors small governance changes —
            such as handoff weakness, reviewer delay, partial rationale, and evidence-confidence decline —
            before they become visible audit or production problems.
        </p>
    </div>

    <div class="section">
        <h2>RLT Drift Signal Matrix</h2>
        <table>
            <tr><th>Governance Area</th><th>Current State</th><th>Trend</th><th>Risk</th></tr>
            {signal_rows}
        </table>
    </div>

    <div class="section">
        <h2>Potential Drift Pathway</h2>
        <div class="chain">
            {drift_chain}
        </div>
    </div>

    <div class="section">
        <h2>Recommended Governance Interventions</h2>
        <table>
            <tr><th>Intervention</th><th>Priority</th></tr>
            {action_rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>
        <p>
            In RLT operations, problems may not begin as major failures. They often begin as small signs:
            repeated late handoffs, reviewer dependency, environmental review delay, or partial evidence closure.
            Governance Drift Intelligence™ makes those weak signals visible early enough for leadership to intervene.
        </p>
    </div>
    """

    return rlt_page("RLT Governance Drift Intelligence", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("RLT Governance Drift Intelligence patch applied successfully.")
