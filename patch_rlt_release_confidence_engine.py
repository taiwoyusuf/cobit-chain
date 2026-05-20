from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

ACTIVE_MARKER = "# RLT_PRODUCTION_RELEASE_CONFIDENCE_ACTIVE"

if ACTIVE_MARKER in text:
    print("RLT Production Release Confidence Engine already exists. No duplicate patch applied.")
    raise SystemExit(0)

required = [
    "RLT_OPERATIONS_VERTICAL_ACTIVE",
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
# RLT_PRODUCTION_RELEASE_CONFIDENCE_ACTIVE
# Production Release Confidence Engine™
# Advanced RLT Operations AssuranceLayer™ module
# ============================================================

RLT_RELEASE_CONFIDENCE_DATA = {
    "release_confidence": 90,
    "verdict": "CONDITIONAL CONFIDENCE",
    "release_state": "PROCEED AFTER TARGETED CLOSURE",
    "blocker_count": 1,
    "watch_items": 3,
    "domains": [
        {"domain": "SOP Currency", "score": "98%", "state": "Trusted", "effect": "Supports release confidence"},
        {"domain": "Training Validity", "score": "100%", "state": "Trusted", "effect": "No qualification blocker"},
        {"domain": "Equipment Readiness", "score": "95%", "state": "Trusted", "effect": "Supports production continuity"},
        {"domain": "Shift Integrity", "score": "91%", "state": "Watch", "effect": "Monitor handoff recurrence"},
        {"domain": "Audit Reconstruction", "score": "93%", "state": "Defensible", "effect": "Timeline supports audit narrative"},
        {"domain": "Governance Drift", "score": "89%", "state": "Watch", "effect": "Early drift signal requires monitoring"},
        {"domain": "Trust Fabric", "score": "92%", "state": "Trusted with Monitoring", "effect": "Trust chain mostly defensible"},
        {"domain": "Environmental Rationale Closure", "score": "86%", "state": "Partial", "effect": "Targeted closure required before final assurance"},
    ],
    "release_gates": [
        {"gate": "Evidence Completeness Gate", "status": "PASS", "detail": "Core records located and traceable."},
        {"gate": "SOP / Training Gate", "status": "PASS", "detail": "Procedure and personnel qualification align."},
        {"gate": "Shift Governance Gate", "status": "WATCH", "detail": "Minor recurring handoff delay requires monitoring."},
        {"gate": "Audit Reconstruction Gate", "status": "PASS", "detail": "GMP timeline is defensible."},
        {"gate": "Drift Gate", "status": "WATCH", "detail": "Governance drift is early-stage, not critical."},
        {"gate": "Environmental Closure Gate", "status": "CONDITIONAL", "detail": "Partial rationale must be closed before final release assurance."},
    ],
    "actions": [
        {"action": "Close environmental rationale record before final assurance output.", "owner": "Supervisor / QA review", "priority": "High"},
        {"action": "Monitor repeated shift handoff delay in next production window.", "owner": "Operations lead", "priority": "Medium"},
        {"action": "Confirm secondary reviewer availability for next RLT run.", "owner": "Production supervision", "priority": "Medium"},
        {"action": "Attach audit reconstruction summary to release confidence packet.", "owner": "Governance reviewer", "priority": "Medium"},
    ]
}

@app.route("/rlt-operations/release-confidence")
def rlt_production_release_confidence_engine():
    d = RLT_RELEASE_CONFIDENCE_DATA

    domain_rows = ''.join([
        f'<tr><td>{x["domain"]}</td><td>{x["score"]}</td><td><span class="pill">{x["state"]}</span></td><td>{x["effect"]}</td></tr>'
        for x in d["domains"]
    ])

    gate_rows = ''.join([
        f'<tr><td>{x["gate"]}</td><td><span class="pill">{x["status"]}</span></td><td>{x["detail"]}</td></tr>'
        for x in d["release_gates"]
    ])

    action_rows = ''.join([
        f'<tr><td>{x["action"]}</td><td>{x["owner"]}</td><td><span class="pill">{x["priority"]}</span></td></tr>'
        for x in d["actions"]
    ])

    body = f"""
    <div class="hero">
        <h1>Production Release Confidence Engine™</h1>
        <div class="sub">
            Aggregates readiness, trust fabric, audit reconstruction, shift integrity, governance drift,
            SOP state, training validity, equipment readiness, and environmental closure into one release-confidence decision.
        </div>
        <div class="nav">
            <a href="/rlt-operations">Back to RLT Mission Control</a>
            <a href="/rlt-operations/trust-fabric">Trust Fabric</a>
            <a href="/rlt-operations/audit-reconstruction">Audit Reconstruction</a>
            <a href="/rlt-operations/governance-drift">Governance Drift</a>
            <a href="/rlt-operations/shift-integrity">Shift Integrity</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Release Confidence</div><div class="value">{d["release_confidence"]}%</div></div>
        <div class="card"><div class="label">Verdict</div><div class="value" style="font-size:23px;">{d["verdict"]}</div></div>
        <div class="card"><div class="label">Release State</div><div class="value" style="font-size:21px;">{d["release_state"]}</div></div>
        <div class="card"><div class="label">Blockers</div><div class="value">{d["blocker_count"]}</div></div>
        <div class="card"><div class="label">Watch Items</div><div class="value">{d["watch_items"]}</div></div>
    </div>

    <div class="section">
        <h2>Release Confidence Decision</h2>
        <div class="decision">{d["release_state"]}</div>
        <p>
            This engine does not replace QA release authority. It gives leadership a governed confidence view
            of whether the production state is complete, defensible, and trusted enough to support final release decision-making.
        </p>
    </div>

    <div class="section">
        <h2>Release Confidence Domain Register</h2>
        <table>
            <tr><th>Domain</th><th>Score</th><th>State</th><th>Effect on Release Confidence</th></tr>
            {domain_rows}
        </table>
    </div>

    <div class="section">
        <h2>Governed Release Gates</h2>
        <table>
            <tr><th>Gate</th><th>Status</th><th>Detail</th></tr>
            {gate_rows}
        </table>
    </div>

    <div class="section">
        <h2>Targeted Closure Actions</h2>
        <table>
            <tr><th>Action</th><th>Owner</th><th>Priority</th></tr>
            {action_rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>
        <p>
            In RLT operations, release confidence depends on more than whether a record exists. It depends on whether
            the evidence chain, human workflow, environmental rationale, audit narrative, governance drift, and trust fabric
            are defensible together. This module turns those signals into a governed release-confidence view.
        </p>
    </div>
    """

    return rlt_page("Production Release Confidence Engine", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("RLT Production Release Confidence Engine patch applied successfully.")
