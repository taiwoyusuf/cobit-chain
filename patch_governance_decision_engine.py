from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "GOVERNANCE_DECISION_ENGINE_ACTIVE"

if MARKER in text:
    print("Governance Decision Engine already exists. No changes made.")
    raise SystemExit(0)

insert_before = '\nif __name__ == "__main__":'
idx = text.find(insert_before)

if idx == -1:
    raise SystemExit("ERROR: Could not find final if __name__ == \"__main__\" block.")

route_code = r'''

# ============================================================
# GOVERNANCE_DECISION_ENGINE_ACTIVE
# Safe additive route only.
# Adds /governance-decision-engine without modifying protected modules.
# Converts governance signals into recommended control decisions.
# ============================================================

@app.route("/governance-decision-engine")
def governance_decision_engine():

    decision_kpis = {
        "decision_readiness": "82%",
        "recommended_blocks": "3",
        "reopen_required": "2",
        "supervisor_reviews": "4",
        "release_holds": "2",
        "audit_escalations": "3",
        "confidence_threshold": "90%",
        "engine_mode": "Synthetic Decision Intelligence"
    }

    decision_cases = [
        {
            "record": "LAB-RESULT-001",
            "trigger": "Middleware verified but LIS held and downstream not released",
            "governance_truth": "Not Reconciled",
            "confidence": "72%",
            "audit_exposure": "High",
            "decision": "BLOCK RELEASE",
            "reason": "Dependent systems do not support true workflow completion.",
            "priority": "P1"
        },
        {
            "record": "SNOW-ACCESS-044",
            "trigger": "ServiceNow access request closed but myAccess role not provisioned",
            "governance_truth": "False Completion",
            "confidence": "69%",
            "audit_exposure": "High",
            "decision": "REOPEN WORKFLOW",
            "reason": "Ticket closure occurred before IAM provisioning dependency completed.",
            "priority": "P1"
        },
        {
            "record": "DEV-CAPA-018",
            "trigger": "Deviation closed while CAPA effectiveness remains pending",
            "governance_truth": "Reopen Required",
            "confidence": "71%",
            "audit_exposure": "High",
            "decision": "REQUIRE CAPA LINKAGE",
            "reason": "Quality closure is not defensible until CAPA dependency is complete.",
            "priority": "P1"
        },
        {
            "record": "SHIFT-B2C-009",
            "trigger": "Incoming owner acknowledgement missing during B-to-C transition",
            "governance_truth": "Continuity Watch",
            "confidence": "84%",
            "audit_exposure": "Medium",
            "decision": "FORCE SUPERVISOR REVIEW",
            "reason": "Ownership continuity must be confirmed before closure is trusted.",
            "priority": "P2"
        },
        {
            "record": "QC-REL-027",
            "trigger": "QC release chain has second reviewer pending",
            "governance_truth": "Partial",
            "confidence": "81%",
            "audit_exposure": "Medium",
            "decision": "DENY CLOSURE",
            "reason": "QC release is incomplete until second-review dependency is satisfied.",
            "priority": "P2"
        },
    ]

    decision_rules = [
        {
            "rule": "Block Release",
            "condition": "If LIS/LIMS, QA, downstream, or batch disposition dependency remains held, pending, or blocked.",
            "decision_output": "BLOCK RELEASE",
            "control_value": "Prevents false operational release."
        },
        {
            "rule": "Reopen Workflow",
            "condition": "If workflow system says Closed but dependent system is incomplete.",
            "decision_output": "REOPEN WORKFLOW",
            "control_value": "Prevents false closure."
        },
        {
            "rule": "Deny Closure",
            "condition": "If required evidence, review, or dependency chain is incomplete.",
            "decision_output": "DENY CLOSURE",
            "control_value": "Protects audit defensibility."
        },
        {
            "rule": "Force Supervisor Review",
            "condition": "If confidence is below threshold or ownership continuity is weak.",
            "decision_output": "FORCE REVIEW",
            "control_value": "Prevents silent governance drift."
        },
        {
            "rule": "Require CAPA Linkage",
            "condition": "If deviation closure depends on CAPA action or effectiveness check.",
            "decision_output": "REQUIRE CAPA LINKAGE",
            "control_value": "Protects quality closure integrity."
        },
    ]

    decision_flow = [
        {"step": "1", "name": "Read System States", "description": "Collect workflow, evidence, access, release, review, and dependency states."},
        {"step": "2", "name": "Validate Dependencies", "description": "Check whether dependent systems support the claimed completion state."},
        {"step": "3", "name": "Reconcile Truth", "description": "Determine whether the workflow is complete, partial, blocked, or falsely closed."},
        {"step": "4", "name": "Score Governance Risk", "description": "Use confidence, audit exposure, blast radius, and dependency gaps."},
        {"step": "5", "name": "Recommend Decision", "description": "Block, reopen, deny closure, force review, require CAPA, or allow completion."},
    ]

    executive_summary = [
        "The Decision Engine changes COBIT-Chain from visibility into control guidance.",
        "It does not only show that a workflow is weak; it recommends what governance action should happen next.",
        "This supports release decisions, closure decisions, supervisor review decisions, and audit escalation decisions.",
        "The engine is strongest when systems disagree or when completion depends on hidden downstream dependencies.",
        "It gives leadership a defensible reason for blocking, reopening, or requiring review."
    ]

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>COBIT-Chain Governance Decision Engine</title>
        <style>
            body { margin:0; font-family:Arial, Helvetica, sans-serif; background:#f4f7fb; color:#0f172a; }
            .top { background:#0f172a; color:white; padding:14px 24px; display:flex; justify-content:space-between; align-items:center; gap:18px; flex-wrap:wrap; position:sticky; top:0; z-index:10; }
            .brand { font-weight:900; font-size:18px; }
            .brand span { color:#38bdf8; }
            .nav { display:flex; gap:10px; flex-wrap:wrap; }
            .nav a { color:#dbeafe; text-decoration:none; font-size:12px; font-weight:800; padding:8px 10px; border-radius:999px; background:rgba(255,255,255,.08); border:1px solid rgba(255,255,255,.12); }
            .hero { background:linear-gradient(135deg,#111827,#9f1239); color:white; padding:38px 44px 82px; border-bottom-left-radius:28px; border-bottom-right-radius:28px; }
            .hero h1 { margin:0 0 10px; font-size:42px; }
            .hero p { color:#ffe4e6; max-width:1120px; line-height:1.55; font-size:16px; }
            .badge { display:inline-block; background:rgba(255,255,255,.14); border:1px solid rgba(255,255,255,.25); padding:8px 13px; border-radius:999px; margin:10px 8px 0 0; font-size:12px; font-weight:800; }
            .wrap { max-width:1360px; margin:-48px auto 40px; padding:0 24px; }
            .grid4 { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:22px; }
            .kpi, .panel { background:white; border-radius:20px; padding:22px; box-shadow:0 12px 30px rgba(15,23,42,.09); margin-bottom:22px; }
            .kpi span { color:#64748b; font-weight:900; font-size:12px; text-transform:uppercase; letter-spacing:.07em; }
            .kpi strong { display:block; margin-top:9px; font-size:26px; }
            table { width:100%; border-collapse:collapse; }
            th { background:#ffe4e6; color:#9f1239; text-align:left; padding:12px; font-size:13px; }
            td { border-bottom:1px solid #e5e7eb; padding:12px; font-size:13px; vertical-align:top; }
            .pill { display:inline-block; padding:6px 10px; border-radius:999px; font-weight:900; font-size:11px; }
            .P1, .High, .BLOCK, .REOPEN, .REQUIRE { background:#fee2e2; color:#991b1b; }
            .P2, .Medium, .FORCE, .DENY { background:#fef3c7; color:#92400e; }
            .Low, .ALLOW { background:#dcfce7; color:#166534; }
            .flow { display:grid; grid-template-columns:repeat(5,1fr); gap:14px; }
            .flow-card { background:#f8fafc; border:1px solid #fecdd3; border-radius:18px; padding:18px; }
            .flow-card h3 { margin:0 0 8px; color:#9f1239; }
            .flow-card p { color:#334155; font-size:13px; line-height:1.45; }
            .note { background:#fff1f2; border:1px solid #fecdd3; color:#9f1239; padding:16px; border-radius:16px; margin-bottom:22px; }
            ul { line-height:1.8; color:#334155; }
            @media(max-width:1100px){ .grid4,.flow{grid-template-columns:repeat(2,1fr);} }
            @media(max-width:700px){ .grid4,.flow{grid-template-columns:1fr;} .hero h1{font-size:30px;} }
        </style>
    </head>
    <body>
        <div class="top">
            <div class="brand">COBIT-Chain™ <span>Governance Decision Engine</span></div>
            <nav class="nav">
                <a href="/governance-reconciliation-layer">Reconciliation</a>
                <a href="/cross-system-dependency-validation">Dependency Validation</a>
                <a href="/governance-digital-command-center">Command Center</a>
                <a href="/ai-governance-copilot">AI Copilot</a>
                <a href="/audit-simulation-engine">Audit</a>
            </nav>
        </div>

        <section class="hero">
            <h1>Governance Decision Engine™</h1>
            <p>
                Converts reconciliation truth, dependency validation, confidence score, audit exposure,
                and blast radius into recommended governance actions: block release, reopen workflow,
                deny closure, force review, require CAPA linkage, or allow completion.
            </p>
            <span class="badge">CONTROL DECISION INTELLIGENCE</span>
            <span class="badge">BLOCK / REOPEN / DENY</span>
            <span class="badge">RELEASE ASSURANCE</span>
            <span class="badge">AUDIT DEFENSIBILITY</span>
        </section>

        <main class="wrap">
            <div class="note">
                <b>Executive meaning:</b> This does not just identify risk. It recommends the governance decision needed to protect operational truth.
            </div>

            <div class="grid4">
                <div class="kpi"><span>Decision Readiness</span><strong>{{ decision_kpis.decision_readiness }}</strong></div>
                <div class="kpi"><span>Recommended Blocks</span><strong>{{ decision_kpis.recommended_blocks }}</strong></div>
                <div class="kpi"><span>Reopen Required</span><strong>{{ decision_kpis.reopen_required }}</strong></div>
                <div class="kpi"><span>Supervisor Reviews</span><strong>{{ decision_kpis.supervisor_reviews }}</strong></div>
            </div>

            <div class="grid4">
                <div class="kpi"><span>Release Holds</span><strong>{{ decision_kpis.release_holds }}</strong></div>
                <div class="kpi"><span>Audit Escalations</span><strong>{{ decision_kpis.audit_escalations }}</strong></div>
                <div class="kpi"><span>Confidence Threshold</span><strong>{{ decision_kpis.confidence_threshold }}</strong></div>
                <div class="kpi"><span>Engine Mode</span><strong>{{ decision_kpis.engine_mode }}</strong></div>
            </div>

            <section class="panel">
                <h2>1. Decision Cases</h2>
                <table>
                    <tr><th>Record</th><th>Trigger</th><th>Governance Truth</th><th>Confidence</th><th>Audit Exposure</th><th>Decision</th><th>Reason</th><th>Priority</th></tr>
                    {% for d in decision_cases %}
                    <tr>
                        <td><b>{{ d.record }}</b></td>
                        <td>{{ d.trigger }}</td>
                        <td>{{ d.governance_truth }}</td>
                        <td>{{ d.confidence }}</td>
                        <td>{{ d.audit_exposure }}</td>
                        <td><span class="pill {{ d.decision.split()[0] }}">{{ d.decision }}</span></td>
                        <td>{{ d.reason }}</td>
                        <td><span class="pill {{ d.priority }}">{{ d.priority }}</span></td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>2. Decision Rules</h2>
                <table>
                    <tr><th>Rule</th><th>Condition</th><th>Decision Output</th><th>Control Value</th></tr>
                    {% for r in decision_rules %}
                    <tr>
                        <td><b>{{ r.rule }}</b></td>
                        <td>{{ r.condition }}</td>
                        <td>{{ r.decision_output }}</td>
                        <td>{{ r.control_value }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>3. Decision Flow</h2>
                <div class="flow">
                    {% for f in decision_flow %}
                    <div class="flow-card">
                        <h3>{{ f.step }}. {{ f.name }}</h3>
                        <p>{{ f.description }}</p>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="panel">
                <h2>4. Executive Summary</h2>
                <ul>
                    {% for e in executive_summary %}
                    <li>{{ e }}</li>
                    {% endfor %}
                </ul>
            </section>
        </main>
    </body>
    </html>
    """

    return render_template_string(
        html,
        decision_kpis=decision_kpis,
        decision_cases=decision_cases,
        decision_rules=decision_rules,
        decision_flow=decision_flow,
        executive_summary=executive_summary
    )


'''

new_text = text[:idx] + route_code + text[idx:]
APP.write_text(new_text, encoding="utf-8")

required = [
    "GOVERNANCE_DECISION_ENGINE_ACTIVE",
    '@app.route("/governance-decision-engine")',
    "Governance Decision Engine",
    "Decision Cases",
    "Decision Rules"
]

missing = [x for x in required if x not in new_text]
if missing:
    raise SystemExit("ERROR missing expected markers: " + ", ".join(missing))

print("SUCCESS: Governance Decision Engine added safely at /governance-decision-engine")
