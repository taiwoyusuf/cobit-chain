from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

ACTIVE_MARKER = "# RLT_REAL_TIME_MANUFACTURING_CONFIDENCE_ACTIVE"

if ACTIVE_MARKER in text:
    print("RLT Real-Time Manufacturing Confidence Layer already exists. No duplicate patch applied.")
    raise SystemExit(0)

required = [
    "RLT_OPERATIONS_VERTICAL_ACTIVE",
    "RLT_WIDE_ENTERPRISE_UI_ACTIVE",
    "RLT_BATCH_TRUST_PASSPORT_ACTIVE",
    "RLT_PRODUCTION_RELEASE_CONFIDENCE_ACTIVE",
    "RLT_AUTONOMOUS_GMP_TRUST_FABRIC_ACTIVE",
    "RLT_GOVERNANCE_DRIFT_INTELLIGENCE_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required existing marker not found: {item}")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError('Could not find if __name__ == "__main__": insertion point.')

code = r'''

# ============================================================
# RLT_REAL_TIME_MANUFACTURING_CONFIDENCE_ACTIVE
# Real-Time Manufacturing Confidence Layer™
# Advanced RLT Operations AssuranceLayer™ module
# ============================================================

RLT_MANUFACTURING_CONFIDENCE_DATA = {
    "live_confidence": 91,
    "confidence_state": "STABLE WITH WATCH ITEMS",
    "operational_mode": "CONTROLLED PRODUCTION WINDOW",
    "trend": "+2%",
    "release_direction": "CONDITIONAL POSITIVE",
    "signals": [
        {"signal": "SOP / Training Confidence", "value": "99%", "movement": "Stable", "state": "Trusted"},
        {"signal": "Equipment Readiness Confidence", "value": "95%", "movement": "Stable", "state": "Trusted"},
        {"signal": "Shift Integrity Confidence", "value": "91%", "movement": "-1%", "state": "Watch"},
        {"signal": "Audit Reconstruction Confidence", "value": "93%", "movement": "+3%", "state": "Defensible"},
        {"signal": "Governance Drift Pressure", "value": "18%", "movement": "-2%", "state": "Improving"},
        {"signal": "Trust Fabric Confidence", "value": "92%", "movement": "+1%", "state": "Trusted with Monitoring"},
        {"signal": "Release Confidence", "value": "90%", "movement": "+2%", "state": "Conditional"},
        {"signal": "Batch Trust Passport", "value": "91%", "movement": "+2%", "state": "Conditionally Defensible"},
    ],
    "timeline": [
        {"time": "06:00", "confidence": "86%", "event": "Pre-shift readiness baseline established"},
        {"time": "06:30", "confidence": "89%", "event": "Training and SOP state verified"},
        {"time": "07:15", "confidence": "92%", "event": "Equipment readiness confirmed"},
        {"time": "08:05", "confidence": "88%", "event": "Environmental rationale entered partial state"},
        {"time": "09:10", "confidence": "90%", "event": "Supervisor review restored trust direction"},
        {"time": "09:45", "confidence": "91%", "event": "Batch Trust Passport conditionally defensible"},
    ],
    "alerts": [
        {"alert": "Environmental rationale still requires closure.", "severity": "High"},
        {"alert": "Shift handoff delay pattern remains under watch.", "severity": "Medium"},
        {"alert": "Release confidence improving after audit reconstruction.", "severity": "Low"},
    ]
}

@app.route("/rlt-operations/manufacturing-confidence")
def rlt_real_time_manufacturing_confidence():
    d = RLT_MANUFACTURING_CONFIDENCE_DATA

    signal_rows = ''.join([
        f'<tr><td>{x["signal"]}</td><td>{x["value"]}</td><td>{x["movement"]}</td><td><span class="pill">{x["state"]}</span></td></tr>'
        for x in d["signals"]
    ])

    timeline_rows = ''.join([
        f'<tr><td>{x["time"]}</td><td>{x["confidence"]}</td><td>{x["event"]}</td></tr>'
        for x in d["timeline"]
    ])

    alert_rows = ''.join([
        f'<tr><td>{x["alert"]}</td><td><span class="pill">{x["severity"]}</span></td></tr>'
        for x in d["alerts"]
    ])

    body = f"""
    <div class="hero">
        <h1>Real-Time Manufacturing Confidence Layer™</h1>
        <div class="sub">
            Live operational confidence streaming for RLT manufacturing. This layer shows how confidence rises,
            degrades, recovers, and propagates across readiness, trust fabric, drift, release confidence, and batch passport signals.
        </div>
        <div class="nav">
            <a href="/rlt-operations">Back to RLT Mission Control</a>
            <a href="/rlt-operations/batch-trust-passport">Batch Passport</a>
            <a href="/rlt-operations/release-confidence">Release Confidence</a>
            <a href="/rlt-operations/trust-fabric">Trust Fabric</a>
            <a href="/rlt-operations/governance-drift">Governance Drift</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Live Manufacturing Confidence</div><div class="value">{d["live_confidence"]}%</div></div>
        <div class="card"><div class="label">Confidence State</div><div class="value" style="font-size:22px;">{d["confidence_state"]}</div></div>
        <div class="card"><div class="label">Operational Mode</div><div class="value" style="font-size:22px;">{d["operational_mode"]}</div></div>
        <div class="card"><div class="label">Confidence Trend</div><div class="value">{d["trend"]}</div></div>
        <div class="card"><div class="label">Release Direction</div><div class="value" style="font-size:22px;">{d["release_direction"]}</div></div>
    </div>

    <div class="section">
        <h2>Live Confidence Decision</h2>
        <div class="decision">{d["confidence_state"]}</div>
        <p>
            This layer behaves like an operational confidence stream. It does not wait until a deviation is raised.
            It monitors whether confidence is increasing, weakening, or recovering while the production window is still active.
        </p>
    </div>

    <div class="section">
        <h2>Manufacturing Confidence Signal Board</h2>
        <table>
            <tr><th>Signal</th><th>Current Value</th><th>Movement</th><th>State</th></tr>
            {signal_rows}
        </table>
    </div>

    <div class="section">
        <h2>Confidence Timeline</h2>
        <table>
            <tr><th>Time</th><th>Confidence</th><th>Event</th></tr>
            {timeline_rows}
        </table>
    </div>

    <div class="section">
        <h2>Live Watch Alerts</h2>
        <table>
            <tr><th>Alert</th><th>Severity</th></tr>
            {alert_rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>
        <p>
            A normal dashboard shows status. This layer shows confidence movement. It gives RLT leadership a live
            view of whether manufacturing trust is strengthening, weakening, or recovering before release exposure,
            deviation escalation, or audit reconstruction becomes more difficult.
        </p>
    </div>
    """

    return rlt_page("Real-Time Manufacturing Confidence Layer", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("RLT Real-Time Manufacturing Confidence Layer patch applied successfully.")
