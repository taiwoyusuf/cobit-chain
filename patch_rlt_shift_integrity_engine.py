from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

ACTIVE_MARKER = "# RLT_SHIFT_INTEGRITY_ENGINE_ACTIVE"

if ACTIVE_MARKER in text:
    print("RLT Shift Integrity module already exists. No duplicate patch applied.")
    raise SystemExit(0)

required = [
    "RLT_OPERATIONS_VERTICAL_ACTIVE",
    "/rlt-operations",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required existing marker/link not found: {item}")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError('Could not find if __name__ == "__main__": insertion point.')

code = r'''

# ============================================================
# RLT_SHIFT_INTEGRITY_ENGINE_ACTIVE
# Shift Integrity & Human Reliability Engine™
# Advanced RLT Operations AssuranceLayer™ module
# ============================================================

RLT_SHIFT_INTEGRITY_DATA = {
    "overall_score": 91,
    "risk_level": "CONTROLLED",
    "handoff_integrity": 94,
    "operator_reliability": 92,
    "review_latency": "LOW",
    "fatigue_signal": "WATCH",
    "decision": "PROCEED WITH MONITORING",
    "signals": [
        {"area": "Shift Handoff Completeness", "status": "PASS", "score": "94%", "meaning": "Required handoff points are documented and traceable."},
        {"area": "Operator Training Validity", "status": "CURRENT", "score": "100%", "meaning": "Assigned personnel remain qualified for current operational scope."},
        {"area": "Reviewer Availability", "status": "STABLE", "score": "92%", "meaning": "Review capacity supports timely GMP decision flow."},
        {"area": "Approval Latency", "status": "LOW", "score": "89%", "meaning": "No material delay pattern detected in approvals."},
        {"area": "Role / Access Fit", "status": "VERIFIED", "score": "96%", "meaning": "Operational role expectations align with access and task ownership."},
        {"area": "Human-Factor Pressure", "status": "WATCH", "score": "82%", "meaning": "Monitor workload concentration and repeated late-stage review pressure."},
    ],
    "risk_events": [
        {"event": "Late handoff note", "impact": "Medium", "response": "Supervisor review required before closeout."},
        {"event": "Repeated reviewer dependency", "impact": "Medium", "response": "Escalate secondary reviewer readiness."},
        {"event": "High task concentration on single operator", "impact": "Watch", "response": "Monitor workload distribution."},
    ]
}

@app.route("/rlt-operations/shift-integrity")
def rlt_shift_integrity_engine():
    d = RLT_SHIFT_INTEGRITY_DATA
    cards = f"""
        <div class="grid">
            <div class="card"><div class="label">Shift Integrity Score</div><div class="value">{d["overall_score"]}%</div></div>
            <div class="card"><div class="label">Risk Level</div><div class="value">{d["risk_level"]}</div></div>
            <div class="card"><div class="label">Handoff Integrity</div><div class="value">{d["handoff_integrity"]}%</div></div>
            <div class="card"><div class="label">Operator Reliability</div><div class="value">{d["operator_reliability"]}%</div></div>
            <div class="card"><div class="label">Review Latency</div><div class="value">{d["review_latency"]}</div></div>
            <div class="card"><div class="label">Fatigue Signal</div><div class="value">{d["fatigue_signal"]}</div></div>
        </div>
    """

    signal_rows = ''.join([
        f'<tr><td>{s["area"]}</td><td><span class="pill">{s["status"]}</span></td><td>{s["score"]}</td><td>{s["meaning"]}</td></tr>'
        for s in d["signals"]
    ])

    event_rows = ''.join([
        f'<tr><td>{e["event"]}</td><td><span class="pill">{e["impact"]}</span></td><td>{e["response"]}</td></tr>'
        for e in d["risk_events"]
    ])

    body = f"""
    <div class="hero">
        <h1>Shift Integrity & Human Reliability Engine™</h1>
        <div class="sub">
            Advanced RLT governance intelligence for shift handoff completeness, operator readiness,
            reviewer capacity, role/access fit, approval latency, and human-factor pressure.
        </div>
        <div class="nav">
            <a href="/rlt-operations">Back to RLT Mission Control</a>
            <a href="/rlt-operations/readiness">Readiness Engine</a>
            <a href="/rlt-operations/blast-radius">Blast Radius</a>
        </div>
    </div>

    {cards}

    <div class="section">
        <h2>Operational Decision</h2>
        <div class="decision">{d["decision"]}</div>
        <p>
            This module does not blame operators. It identifies process pressure, handoff weaknesses,
            reviewer bottlenecks, and role-fit risks before they become deviation drivers.
        </p>
    </div>

    <div class="section">
        <h2>Human Reliability Signal Matrix</h2>
        <table>
            <tr><th>Signal Area</th><th>Status</th><th>Score</th><th>Operational Meaning</th></tr>
            {signal_rows}
        </table>
    </div>

    <div class="section">
        <h2>Potential Shift Risk Events</h2>
        <table>
            <tr><th>Risk Event</th><th>Impact</th><th>Recommended Governance Response</th></tr>
            {event_rows}
        </table>
    </div>

    <div class="section">
        <h2>Why This Matters for RLT Operations</h2>
        <p>
            Radioligand manufacturing is time-sensitive. Small documentation gaps, delayed reviews,
            unclear handoffs, or role-access mismatches can create avoidable operational risk.
            This engine gives leadership early visibility into the human and process signals that
            often sit behind deviations, CAPA repeat findings, batch delays, and audit questions.
        </p>
    </div>
    """

    return rlt_page("Shift Integrity & Human Reliability Engine", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("RLT Shift Integrity & Human Reliability Engine patch applied successfully.")
