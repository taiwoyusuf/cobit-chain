from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

ACTIVE_MARKER = "# RLT_EXECUTIVE_WAR_ROOM_ACTIVE"

if ACTIVE_MARKER in text:
    print("RLT Executive War Room already exists. No duplicate patch applied.")
    raise SystemExit(0)

required = [
    "RLT_OPERATIONS_VERTICAL_ACTIVE",
    "RLT_WIDE_ENTERPRISE_UI_ACTIVE",
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
# RLT_EXECUTIVE_WAR_ROOM_ACTIVE
# RLT Executive War Room™
# Premium consolidated RLT Operations AssuranceLayer™ module
# ============================================================

RLT_EXECUTIVE_WAR_ROOM_DATA = {
    "overall_state": "CONTROLLED WITH TARGETED CLOSURE",
    "manufacturing_confidence": 91,
    "release_confidence": 90,
    "trust_fabric": 92,
    "audit_confidence": 93,
    "batch_passport": "CONDITIONALLY DEFENSIBLE",
    "executive_decision": "PROCEED WITH SUPERVISOR / QA TARGETED CLOSURE",
    "command_signals": [
        {"signal": "Live Manufacturing Confidence", "value": "91%", "state": "Stable with watch items"},
        {"signal": "Production Release Confidence", "value": "90%", "state": "Conditional positive"},
        {"signal": "Batch Trust Passport", "value": "RLT-PASS-2026-001", "state": "Conditionally defensible"},
        {"signal": "Audit Reconstruction", "value": "93%", "state": "Defensible"},
        {"signal": "Governance Drift", "value": "18%", "state": "Early drift watch"},
        {"signal": "Shift Integrity", "value": "91%", "state": "Controlled monitoring"},
    ],
    "watchlist": [
        {"item": "Environmental rationale closure", "severity": "High", "owner": "Supervisor / QA Review"},
        {"item": "Recurring shift handoff delay", "severity": "Medium", "owner": "Operations Lead"},
        {"item": "Secondary reviewer availability", "severity": "Medium", "owner": "Production Supervision"},
        {"item": "Governance drift trend", "severity": "Watch", "owner": "Governance Reviewer"},
    ],
    "interventions": [
        {"intervention": "Close environmental rationale before final assurance output.", "impact": "Protects release defensibility"},
        {"intervention": "Confirm secondary reviewer availability before next production window.", "impact": "Reduces review bottleneck risk"},
        {"intervention": "Attach autonomous audit reconstruction to batch trust passport.", "impact": "Improves inspection story readiness"},
        {"intervention": "Monitor handoff delay recurrence across next RLT run.", "impact": "Prevents silent human-process drift"},
    ]
}

@app.route("/rlt-operations/executive-war-room")
def rlt_executive_war_room():
    d = RLT_EXECUTIVE_WAR_ROOM_DATA

    signal_rows = ''.join([
        f'<tr><td>{x["signal"]}</td><td>{x["value"]}</td><td><span class="pill">{x["state"]}</span></td></tr>'
        for x in d["command_signals"]
    ])

    watch_rows = ''.join([
        f'<tr><td>{x["item"]}</td><td><span class="pill">{x["severity"]}</span></td><td>{x["owner"]}</td></tr>'
        for x in d["watchlist"]
    ])

    intervention_rows = ''.join([
        f'<tr><td>{x["intervention"]}</td><td>{x["impact"]}</td></tr>'
        for x in d["interventions"]
    ])

    body = f"""
    <div class="hero">
        <h1>RLT Executive War Room™</h1>
        <div class="sub">
            A consolidated leadership cockpit for Radioligand Manufacturing trust, release confidence,
            batch defensibility, audit readiness, governance drift, shift integrity, and targeted executive intervention.
        </div>
        <div class="nav">
            <a href="/rlt-operations">Mission Control</a>
            <a href="/rlt-operations/manufacturing-confidence">Manufacturing Confidence</a>
            <a href="/rlt-operations/release-confidence">Release Confidence</a>
            <a href="/rlt-operations/batch-trust-passport">Batch Passport</a>
            <a href="/rlt-operations/trust-fabric">Trust Fabric</a>
            <a href="/rlt-operations/audit-reconstruction">Audit Reconstruction</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Overall State</div><div class="value" style="font-size:23px;">{d["overall_state"]}</div></div>
        <div class="card"><div class="label">Manufacturing Confidence</div><div class="value">{d["manufacturing_confidence"]}%</div></div>
        <div class="card"><div class="label">Release Confidence</div><div class="value">{d["release_confidence"]}%</div></div>
        <div class="card"><div class="label">Trust Fabric</div><div class="value">{d["trust_fabric"]}%</div></div>
        <div class="card"><div class="label">Audit Confidence</div><div class="value">{d["audit_confidence"]}%</div></div>
        <div class="card"><div class="label">Batch Passport</div><div class="value" style="font-size:22px;">{d["batch_passport"]}</div></div>
    </div>

    <div class="section">
        <h2>Executive Decision</h2>
        <div class="decision">{d["executive_decision"]}</div>
        <p>
            The War Room consolidates the RLT assurance layer into one leadership view. It does not replace QA,
            MES, batch records, or production systems. It gives leadership a governed operational confidence picture
            before release exposure, deviation escalation, or inspection response becomes harder.
        </p>
    </div>

    <div class="section">
        <h2>Command Signal Board</h2>
        <table>
            <tr><th>Signal</th><th>Value</th><th>State</th></tr>
            {signal_rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Watchlist</h2>
        <table>
            <tr><th>Watch Item</th><th>Severity</th><th>Owner</th></tr>
            {watch_rows}
        </table>
    </div>

    <div class="section">
        <h2>Recommended Executive Interventions</h2>
        <table>
            <tr><th>Intervention</th><th>Business / GMP Impact</th></tr>
            {intervention_rows}
        </table>
    </div>

    <div class="section">
        <h2>Why This Wows RLT Operations Leadership</h2>
        <p>
            This page compresses the entire regulated manufacturing confidence story into one executive cockpit:
            readiness, drift, trust, audit reconstruction, batch passport, release confidence, and intervention.
            It makes COBIT-Chain™ look like an operational trust command system, not a normal dashboard.
        </p>
    </div>
    """

    return rlt_page("RLT Executive War Room", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("RLT Executive War Room patch applied successfully.")
