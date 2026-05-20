from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

ACTIVE_MARKER = "# RLT_AI_ANOMALY_REASONING_ACTIVE"

if ACTIVE_MARKER in text:
    print("RLT AI-Assisted Anomaly Reasoning already exists. No duplicate patch applied.")
    raise SystemExit(0)

required = [
    "RLT_OPERATIONS_VERTICAL_ACTIVE",
    "RLT_ENTERPRISE_GOVERNANCE_MESH_ACTIVE",
    "RLT_OPERATIONAL_DIGITAL_TWIN_ACTIVE",
    "RLT_EXECUTIVE_WAR_ROOM_ACTIVE",
    "RLT_AUTONOMOUS_DEVIATION_PREVENTION_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required existing marker not found: {item}")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError('Could not find if __name__ == "__main__": insertion point.')

code = r'''

# ============================================================
# RLT_AI_ANOMALY_REASONING_ACTIVE
# AI-Assisted Anomaly Reasoning Engine™
# Advanced RLT Operations AssuranceLayer™ module
# ============================================================

RLT_ANOMALY_REASONING_DATA = {
    "reasoning_state": "AI-ASSISTED REVIEW REQUIRED",
    "confidence": 88,
    "human_gate": "REQUIRED",
    "decision": "AI FLAGGED ANOMALY PATTERN — HUMAN REVIEW BEFORE CONTROL ACTION",
    "anomalies": [
        {"anomaly": "Environmental rationale delay correlates with release-confidence dip", "severity": "High", "explanation": "Pattern appears across trust fabric, release confidence, and audit reconstruction signals."},
        {"anomaly": "Shift handoff delay repeats near supervisor review window", "severity": "Medium", "explanation": "Human reliability signal may indicate operational pressure rather than isolated documentation delay."},
        {"anomaly": "Reviewer dependency appears across multiple modules", "severity": "Medium", "explanation": "Secondary reviewer coverage may be a latent bottleneck."},
        {"anomaly": "Governance drift remains low but persistent", "severity": "Watch", "explanation": "Weak signal remains visible across confidence layer and CAPA monitoring."},
    ],
    "reasoning_chain": [
        "Signal detected",
        "Pattern correlated",
        "Control impact estimated",
        "Human review required",
        "Decision gate updated"
    ],
    "guardrails": [
        {"guardrail": "AI does not make GMP release decisions.", "status": "ENFORCED"},
        {"guardrail": "AI findings require human review before action.", "status": "ENFORCED"},
        {"guardrail": "AI output is advisory, not source of truth.", "status": "ENFORCED"},
        {"guardrail": "Evidence records remain the authoritative control basis.", "status": "ENFORCED"},
    ]
}

@app.route("/rlt-operations/anomaly-reasoning")
def rlt_ai_anomaly_reasoning():
    d = RLT_ANOMALY_REASONING_DATA

    anomaly_rows = ''.join([
        f'<tr><td>{x["anomaly"]}</td><td><span class="pill">{x["severity"]}</span></td><td>{x["explanation"]}</td></tr>'
        for x in d["anomalies"]
    ])

    chain = ''.join([
        f'<div class="node">{x}</div><div class="arrow">→</div>'
        for x in d["reasoning_chain"]
    ])

    guardrail_rows = ''.join([
        f'<tr><td>{x["guardrail"]}</td><td><span class="pill">{x["status"]}</span></td></tr>'
        for x in d["guardrails"]
    ])

    body = f"""
    <div class="hero">
        <h1>AI-Assisted Anomaly Reasoning Engine™</h1>
        <div class="sub">
            Advisory anomaly reasoning for RLT operations. The AI helps correlate weak signals across trust,
            drift, release confidence, CAPA, audit reconstruction, and shift integrity — while human governance
            remains the required decision gate.
        </div>
        <div class="nav">
            <a href="/rlt-operations/executive-war-room">Executive War Room</a>
            <a href="/rlt-operations/deviation-prevention">Deviation Prevention</a>
            <a href="/rlt-operations/digital-twin">Digital Twin</a>
            <a href="/rlt-operations/governance-mesh">Governance Mesh</a>
            <a href="/rlt-operations/capa-effectiveness">CAPA Effectiveness</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Reasoning State</div><div class="value" style="font-size:23px;">{d["reasoning_state"]}</div></div>
        <div class="card"><div class="label">Reasoning Confidence</div><div class="value">{d["confidence"]}%</div></div>
        <div class="card"><div class="label">Human Gate</div><div class="value">{d["human_gate"]}</div></div>
    </div>

    <div class="section">
        <h2>Reasoning Decision</h2>
        <div class="decision">{d["decision"]}</div>
        <p>
            This engine is intentionally advisory. It does not replace QA, production supervision, or controlled
            records. It explains anomaly patterns and routes them into human governance review.
        </p>
    </div>

    <div class="section">
        <h2>Anomaly Reasoning Board</h2>
        <table>
            <tr><th>Anomaly</th><th>Severity</th><th>Reasoned Explanation</th></tr>
            {anomaly_rows}
        </table>
    </div>

    <div class="section">
        <h2>Reasoning Chain</h2>
        <div class="chain">
            {chain}
        </div>
    </div>

    <div class="section">
        <h2>AI Governance Guardrails</h2>
        <table>
            <tr><th>Guardrail</th><th>Status</th></tr>
            {guardrail_rows}
        </table>
    </div>
    """

    return rlt_page("AI-Assisted Anomaly Reasoning Engine", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("RLT AI-Assisted Anomaly Reasoning patch applied successfully.")
