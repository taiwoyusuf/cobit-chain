from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

ACTIVE_MARKER = "# RLT_CAPA_EFFECTIVENESS_INTELLIGENCE_ACTIVE"

if ACTIVE_MARKER in text:
    print("RLT CAPA Effectiveness Intelligence already exists. No duplicate patch applied.")
    raise SystemExit(0)

required = [
    "RLT_OPERATIONS_VERTICAL_ACTIVE",
    "RLT_AUTONOMOUS_DEVIATION_PREVENTION_ACTIVE",
    "RLT_EXECUTIVE_WAR_ROOM_ACTIVE",
    "RLT_BATCH_TRUST_PASSPORT_ACTIVE",
    "RLT_PRODUCTION_RELEASE_CONFIDENCE_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required existing marker not found: {item}")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError('Could not find if __name__ == "__main__": insertion point.')

code = r'''

# ============================================================
# RLT_CAPA_EFFECTIVENESS_INTELLIGENCE_ACTIVE
# Autonomous CAPA Effectiveness Intelligence™
# Advanced RLT Operations AssuranceLayer™ module
# ============================================================

RLT_CAPA_EFFECTIVENESS_DATA = {
    "effectiveness_score": 87,
    "capa_state": "EFFECTIVE WITH MONITORING",
    "repeat_risk": "LOW-MEDIUM",
    "decision": "CAPA EFFECTIVENESS SUPPORTED — MONITOR RECURRENCE SIGNALS",
    "checks": [
        {"check": "Root Cause Alignment", "status": "PASS", "evidence": "CAPA action addresses identified governance driver."},
        {"check": "Preventive Action Strength", "status": "PASS", "evidence": "Control reduces recurrence probability."},
        {"check": "Shift Behavior Change", "status": "WATCH", "evidence": "Handoff delays reduced but still monitored."},
        {"check": "Reviewer Bottleneck Reduction", "status": "WATCH", "evidence": "Secondary reviewer coverage improved but not fully stabilized."},
        {"check": "Environmental Closure Discipline", "status": "ACTION REQUIRED", "evidence": "Rationale closure must be consistently timely."},
        {"check": "Deviation Recurrence Signal", "status": "LOW-MEDIUM", "evidence": "No repeat deviation yet; weak signals still visible."},
    ],
    "recurrence_indicators": [
        {"indicator": "Similar handoff delay pattern", "trend": "Improving", "risk": "Medium"},
        {"indicator": "Late environmental rationale closure", "trend": "Open", "risk": "Medium"},
        {"indicator": "Reviewer dependency", "trend": "Improving", "risk": "Low-Medium"},
        {"indicator": "Audit reconstruction confidence", "trend": "Improving", "risk": "Low"},
    ],
    "actions": [
        {"action": "Track same-risk recurrence across next two RLT production windows.", "priority": "High"},
        {"action": "Require evidence of environmental rationale closure timeliness.", "priority": "High"},
        {"action": "Confirm reviewer backup coverage remains active.", "priority": "Medium"},
        {"action": "Attach CAPA effectiveness signal to Batch Trust Passport.", "priority": "Medium"},
    ]
}

@app.route("/rlt-operations/capa-effectiveness")
def rlt_capa_effectiveness_intelligence():
    d = RLT_CAPA_EFFECTIVENESS_DATA

    check_rows = ''.join([
        f'<tr><td>{x["check"]}</td><td><span class="pill">{x["status"]}</span></td><td>{x["evidence"]}</td></tr>'
        for x in d["checks"]
    ])

    recurrence_rows = ''.join([
        f'<tr><td>{x["indicator"]}</td><td>{x["trend"]}</td><td><span class="pill">{x["risk"]}</span></td></tr>'
        for x in d["recurrence_indicators"]
    ])

    action_rows = ''.join([
        f'<tr><td>{x["action"]}</td><td><span class="pill">{x["priority"]}</span></td></tr>'
        for x in d["actions"]
    ])

    body = f"""
    <div class="hero">
        <h1>Autonomous CAPA Effectiveness Intelligence™</h1>
        <div class="sub">
            Evaluates whether corrective and preventive actions are actually reducing recurrence risk in RLT operations.
            This module connects CAPA closure to operational behavior, recurrence signals, audit confidence, and release trust.
        </div>
        <div class="nav">
            <a href="/rlt-operations/executive-war-room">Executive War Room</a>
            <a href="/rlt-operations/deviation-prevention">Deviation Prevention</a>
            <a href="/rlt-operations/batch-trust-passport">Batch Passport</a>
            <a href="/rlt-operations/release-confidence">Release Confidence</a>
            <a href="/rlt-operations/manufacturing-confidence">Manufacturing Confidence</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Effectiveness Score</div><div class="value">{d["effectiveness_score"]}%</div></div>
        <div class="card"><div class="label">CAPA State</div><div class="value" style="font-size:23px;">{d["capa_state"]}</div></div>
        <div class="card"><div class="label">Repeat Risk</div><div class="value" style="font-size:24px;">{d["repeat_risk"]}</div></div>
    </div>

    <div class="section">
        <h2>Effectiveness Decision</h2>
        <div class="decision">{d["decision"]}</div>
        <p>
            This engine does not simply mark CAPA as closed. It evaluates whether the action is reducing the
            operational pattern that caused or contributed to the issue.
        </p>
    </div>

    <div class="section">
        <h2>CAPA Effectiveness Check Matrix</h2>
        <table>
            <tr><th>Check</th><th>Status</th><th>Evidence</th></tr>
            {check_rows}
        </table>
    </div>

    <div class="section">
        <h2>Recurrence Signal Monitoring</h2>
        <table>
            <tr><th>Indicator</th><th>Trend</th><th>Risk</th></tr>
            {recurrence_rows}
        </table>
    </div>

    <div class="section">
        <h2>Required Follow-Up Actions</h2>
        <table>
            <tr><th>Action</th><th>Priority</th></tr>
            {action_rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>
        <p>
            CAPA effectiveness is not just whether a form was completed. It is whether the same risk is less likely
            to happen again. This module turns CAPA into a living operational intelligence signal for RLT leadership.
        </p>
    </div>
    """

    return rlt_page("Autonomous CAPA Effectiveness Intelligence", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("RLT CAPA Effectiveness Intelligence patch applied successfully.")
