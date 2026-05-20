from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

ACTIVE_MARKER = "# RLT_AUTONOMOUS_DEVIATION_PREVENTION_ACTIVE"

if ACTIVE_MARKER in text:
    print("RLT Autonomous Deviation Prevention Engine already exists. No duplicate patch applied.")
    raise SystemExit(0)

required = [
    "RLT_OPERATIONS_VERTICAL_ACTIVE",
    "RLT_EXECUTIVE_WAR_ROOM_ACTIVE",
    "RLT_REAL_TIME_MANUFACTURING_CONFIDENCE_ACTIVE",
    "RLT_BATCH_TRUST_PASSPORT_ACTIVE",
    "RLT_PRODUCTION_RELEASE_CONFIDENCE_ACTIVE",
    "RLT_AUTONOMOUS_GMP_TRUST_FABRIC_ACTIVE",
    "RLT_GOVERNANCE_DRIFT_INTELLIGENCE_ACTIVE",
    "RLT_AUTONOMOUS_AUDIT_RECONSTRUCTION_ACTIVE",
    "RLT_SHIFT_INTEGRITY_ENGINE_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required existing marker not found: {item}")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError('Could not find if __name__ == "__main__": insertion point.')

code = r'''

# ============================================================
# RLT_AUTONOMOUS_DEVIATION_PREVENTION_ACTIVE
# Autonomous Deviation Prevention Engine™
# Advanced RLT Operations AssuranceLayer™ module
# ============================================================

RLT_DEVIATION_PREVENTION_DATA = {
    "prevention_score": 88,
    "risk_state": "PRE-DEVIATION WATCH",
    "predicted_deviation_probability": "LOW-MEDIUM",
    "recommended_decision": "INTERVENE BEFORE FORMAL DEVIATION PATHWAY",
    "top_driver": "Environmental rationale closure delay",
    "drivers": [
        {"driver": "Environmental rationale closure delay", "probability": "Medium", "impact": "Release confidence constraint", "control": "Close rationale before final assurance."},
        {"driver": "Recurring handoff delay", "probability": "Medium", "impact": "Human-process drift", "control": "Supervisor review of handoff pattern."},
        {"driver": "Secondary reviewer dependency", "probability": "Low-Medium", "impact": "Approval bottleneck", "control": "Confirm backup reviewer before next run."},
        {"driver": "Early governance drift", "probability": "Low", "impact": "Audit confidence decline", "control": "Continue drift monitoring."},
    ],
    "prevention_gates": [
        {"gate": "Readiness Gate", "state": "PASS", "reason": "Core readiness remains strong."},
        {"gate": "Human Reliability Gate", "state": "WATCH", "reason": "Handoff pattern requires monitoring."},
        {"gate": "Environmental Review Gate", "state": "ACTION REQUIRED", "reason": "Partial rationale remains open."},
        {"gate": "Audit Storyline Gate", "state": "PASS", "reason": "Timeline is defensible."},
        {"gate": "Release Confidence Gate", "state": "CONDITIONAL", "reason": "Proceed after targeted closure."},
    ],
    "actions": [
        {"action": "Close environmental rationale before final release assurance.", "urgency": "Immediate"},
        {"action": "Review handoff delay pattern with production supervision.", "urgency": "High"},
        {"action": "Assign secondary reviewer coverage for next production window.", "urgency": "High"},
        {"action": "Attach deviation-prevention note to Batch Trust Passport.", "urgency": "Medium"},
    ]
}

@app.route("/rlt-operations/deviation-prevention")
def rlt_autonomous_deviation_prevention():
    d = RLT_DEVIATION_PREVENTION_DATA

    driver_rows = ''.join([
        f'<tr><td>{x["driver"]}</td><td><span class="pill">{x["probability"]}</span></td><td>{x["impact"]}</td><td>{x["control"]}</td></tr>'
        for x in d["drivers"]
    ])

    gate_rows = ''.join([
        f'<tr><td>{x["gate"]}</td><td><span class="pill">{x["state"]}</span></td><td>{x["reason"]}</td></tr>'
        for x in d["prevention_gates"]
    ])

    action_rows = ''.join([
        f'<tr><td>{x["action"]}</td><td><span class="pill">{x["urgency"]}</span></td></tr>'
        for x in d["actions"]
    ])

    body = f"""
    <div class="hero">
        <h1>Autonomous Deviation Prevention Engine™</h1>
        <div class="sub">
            Predicts and explains pre-deviation conditions before they mature into formal deviation pathways.
            This module converts weak governance signals into early intervention logic for RLT operations.
        </div>
        <div class="nav">
            <a href="/rlt-operations/executive-war-room">Executive War Room</a>
            <a href="/rlt-operations/manufacturing-confidence">Manufacturing Confidence</a>
            <a href="/rlt-operations/release-confidence">Release Confidence</a>
            <a href="/rlt-operations/governance-drift">Governance Drift</a>
            <a href="/rlt-operations/batch-trust-passport">Batch Passport</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Prevention Score</div><div class="value">{d["prevention_score"]}%</div></div>
        <div class="card"><div class="label">Risk State</div><div class="value" style="font-size:23px;">{d["risk_state"]}</div></div>
        <div class="card"><div class="label">Deviation Probability</div><div class="value" style="font-size:24px;">{d["predicted_deviation_probability"]}</div></div>
        <div class="card"><div class="label">Top Driver</div><div class="value" style="font-size:22px;">{d["top_driver"]}</div></div>
    </div>

    <div class="section">
        <h2>Prevention Decision</h2>
        <div class="decision">{d["recommended_decision"]}</div>
        <p>
            This engine does not claim deviations can never happen. It gives leadership earlier visibility into
            conditions that could become deviations, so targeted intervention can happen before the formal pathway begins.
        </p>
    </div>

    <div class="section">
        <h2>Predicted Deviation Drivers</h2>
        <table>
            <tr><th>Driver</th><th>Probability</th><th>Potential Impact</th><th>Preventive Control</th></tr>
            {driver_rows}
        </table>
    </div>

    <div class="section">
        <h2>Prevention Gate Register</h2>
        <table>
            <tr><th>Gate</th><th>State</th><th>Reason</th></tr>
            {gate_rows}
        </table>
    </div>

    <div class="section">
        <h2>Immediate Prevention Actions</h2>
        <table>
            <tr><th>Action</th><th>Urgency</th></tr>
            {action_rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>
        <p>
            The strongest governance outcome is not documenting a deviation well after it happens. It is detecting
            pre-deviation pressure early enough to intervene. This module positions COBIT-Chain™ as a prevention layer,
            not only a documentation or audit layer.
        </p>
    </div>
    """

    return rlt_page("Autonomous Deviation Prevention Engine", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("RLT Autonomous Deviation Prevention Engine patch applied successfully.")
