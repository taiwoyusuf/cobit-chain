from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CROSS_SYSTEM_DEPENDENCY_VALIDATION_ACTIVE"

if MARKER in text:
    print("Cross-System Dependency Validation already exists. No changes made.")
    raise SystemExit(0)

insert_before = '\nif __name__ == "__main__":'
idx = text.find(insert_before)

if idx == -1:
    raise SystemExit("ERROR: Could not find final if __name__ == \"__main__\" block.")

route_code = r'''

# ============================================================
# CROSS_SYSTEM_DEPENDENCY_VALIDATION_ACTIVE
# Safe additive route only.
# Adds /cross-system-dependency-validation without modifying protected modules.
# Validates whether completion in one system is supported by dependent system completion.
# Inspired by Prakriti's middleware/LIS workflow insight.
# ============================================================

@app.route("/cross-system-dependency-validation")
def cross_system_dependency_validation():

    dependency_kpis = {
        "workflow_truth_score": "76%",
        "systems_checked": "5",
        "dependency_exceptions": "3",
        "false_completion_risk": "HIGH",
        "held_records": "2",
        "release_blockers": "2",
        "audit_exposure": "HIGH",
        "validation_mode": "Synthetic Lab Workflow"
    }

    workflow_cases = [
        {
            "case_id": "LAB-RESULT-001",
            "workflow": "Result verification and release",
            "middleware_state": "Verified",
            "lis_state": "Held",
            "downstream_state": "Not Released",
            "cobitchain_state": "Incomplete",
            "reason": "Middleware shows verification complete, but LIS is holding the result; downstream release has not occurred.",
            "risk": "HIGH"
        },
        {
            "case_id": "LAB-RESULT-002",
            "workflow": "Result verification and release",
            "middleware_state": "Verified",
            "lis_state": "Released",
            "downstream_state": "Available",
            "cobitchain_state": "Complete",
            "reason": "Verification, LIS release, and downstream availability are aligned.",
            "risk": "LOW"
        },
        {
            "case_id": "QC-SAMPLE-014",
            "workflow": "QC sample result disposition",
            "middleware_state": "Processed",
            "lis_state": "Pending Review",
            "downstream_state": "Batch disposition blocked",
            "cobitchain_state": "Blocked",
            "reason": "Processing occurred, but LIS review is incomplete and batch disposition remains blocked.",
            "risk": "HIGH"
        },
        {
            "case_id": "LAB-RESULT-007",
            "workflow": "Corrected result workflow",
            "middleware_state": "Corrected",
            "lis_state": "Pending Approval",
            "downstream_state": "Not Updated",
            "cobitchain_state": "Exception",
            "reason": "Corrected middleware result has not completed LIS approval and downstream update.",
            "risk": "MEDIUM"
        },
    ]

    dependency_rules = [
        {
            "rule": "Middleware verification is not final workflow completion",
            "logic": "If middleware = Verified but LIS != Released, workflow is incomplete.",
            "control_value": "Prevents false completion based on one-system status."
        },
        {
            "rule": "LIS held status blocks downstream truth",
            "logic": "If LIS = Held, downstream availability must be treated as blocked or unreliable.",
            "control_value": "Prevents release assumptions while lab record is still held."
        },
        {
            "rule": "Downstream availability must match source completion",
            "logic": "If source verified and LIS released, downstream system must show available or updated.",
            "control_value": "Confirms end-to-end workflow completion."
        },
        {
            "rule": "Corrected result requires approval chain",
            "logic": "If middleware = Corrected, LIS approval and downstream update must both complete.",
            "control_value": "Protects corrected-result traceability."
        },
    ]

    system_map = [
        {"system": "Middleware", "role": "Instrument/result processing and verification signal", "completion_limit": "May show verified before LIS release is complete"},
        {"system": "LIS", "role": "Lab result control, hold, release, approval, and review state", "completion_limit": "Held or pending review blocks true workflow completion"},
        {"system": "Downstream Consumer", "role": "Batch, report, patient, QC, or operational recipient system", "completion_limit": "Must reflect released or updated result"},
        {"system": "Supervisor / QA Review", "role": "Exception, correction, or release oversight", "completion_limit": "Pending review limits audit defensibility"},
        {"system": "COBIT-Chain™", "role": "Cross-system workflow truth validation and governance assurance", "completion_limit": "Flags incomplete workflow even when one system shows done"},
    ]

    executive_summary = [
        "A task can look complete in one system but still be incomplete across the real workflow.",
        "COBIT-Chain validates cross-system dependency truth, not single-system status.",
        "Middleware verification alone is not enough if LIS is holding the result.",
        "This prevents false completion, weak release assumptions, audit exposure, and downstream operational risk.",
        "The value is strongest in regulated workflows where completion depends on multiple systems agreeing."
    ]

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>COBIT-Chain Cross-System Dependency Validation</title>
        <style>
            body { margin:0; font-family:Arial, Helvetica, sans-serif; background:#f4f7fb; color:#0f172a; }
            .top { background:#0f172a; color:white; padding:14px 24px; display:flex; justify-content:space-between; align-items:center; gap:18px; flex-wrap:wrap; position:sticky; top:0; z-index:10; }
            .brand { font-weight:900; font-size:18px; }
            .brand span { color:#38bdf8; }
            .nav { display:flex; gap:10px; flex-wrap:wrap; }
            .nav a { color:#dbeafe; text-decoration:none; font-size:12px; font-weight:800; padding:8px 10px; border-radius:999px; background:rgba(255,255,255,.08); border:1px solid rgba(255,255,255,.12); }
            .nav a:hover { background:#2563eb; color:white; }
            .hero { background:linear-gradient(135deg,#111827,#0f766e); color:white; padding:38px 44px 82px; border-bottom-left-radius:28px; border-bottom-right-radius:28px; }
            .hero h1 { margin:0 0 10px; font-size:42px; }
            .hero p { color:#ccfbf1; max-width:1120px; line-height:1.55; font-size:16px; }
            .badge { display:inline-block; background:rgba(255,255,255,.14); border:1px solid rgba(255,255,255,.25); padding:8px 13px; border-radius:999px; margin:10px 8px 0 0; font-size:12px; font-weight:800; }
            .wrap { max-width:1360px; margin:-48px auto 40px; padding:0 24px; }
            .grid4 { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:22px; }
            .kpi, .panel { background:white; border-radius:20px; padding:22px; box-shadow:0 12px 30px rgba(15,23,42,.09); margin-bottom:22px; }
            .kpi span { color:#64748b; font-weight:900; font-size:12px; text-transform:uppercase; letter-spacing:.07em; }
            .kpi strong { display:block; margin-top:9px; font-size:26px; }
            table { width:100%; border-collapse:collapse; }
            th { background:#ecfeff; color:#115e59; text-align:left; padding:12px; font-size:13px; }
            td { border-bottom:1px solid #e5e7eb; padding:12px; font-size:13px; vertical-align:top; }
            .pill { display:inline-block; padding:6px 10px; border-radius:999px; font-weight:900; font-size:11px; }
            .LOW, .Complete { background:#dcfce7; color:#166534; }
            .MEDIUM, .Exception { background:#fef3c7; color:#92400e; }
            .HIGH, .Incomplete, .Blocked { background:#fee2e2; color:#991b1b; }
            .truth-chain { display:grid; grid-template-columns:repeat(5,1fr); gap:14px; }
            .node { background:#f8fafc; border:1px solid #ccfbf1; border-radius:18px; padding:18px; }
            .node h3 { margin:0 0 8px; color:#0f766e; }
            .node p { color:#334155; font-size:13px; line-height:1.45; }
            .note { background:#ecfeff; border:1px solid #99f6e4; color:#115e59; padding:16px; border-radius:16px; margin-bottom:22px; }
            ul { line-height:1.8; color:#334155; }
            @media(max-width:1100px){ .grid4,.truth-chain{grid-template-columns:repeat(2,1fr);} }
            @media(max-width:700px){ .grid4,.truth-chain{grid-template-columns:1fr;} .hero h1{font-size:30px;} }
        </style>
    </head>
    <body>
        <div class="top">
            <div class="brand">COBIT-Chain™ <span>Cross-System Dependency Validation</span></div>
            <nav class="nav">
                <a href="/executive-mission-control">Mission Control</a>
                <a href="/governance-digital-command-center">Command Center</a>
                <a href="/ai-governance-copilot">AI Copilot</a>
                <a href="/audit-simulation-engine">Audit</a>
                <a href="/enterprise-workspaces">Workspaces</a>
            </nav>
        </div>

        <section class="hero">
            <h1>Cross-System Dependency Validation Layer</h1>
            <p>
                Validates whether workflow completion in one system is supported by completion in dependent systems.
                Example: if a result is verified in middleware but held in LIS, COBIT-Chain flags the workflow as incomplete
                even though middleware shows the task as done.
            </p>
            <span class="badge">WORKFLOW TRUTH VALIDATION</span>
            <span class="badge">MIDDLEWARE + LIS</span>
            <span class="badge">FALSE COMPLETION DETECTION</span>
            <span class="badge">DEPENDENCY-AWARE GOVERNANCE</span>
        </section>

        <main class="wrap">
            <div class="note">
                <b>Prakriti insight converted into capability:</b> completion must be validated across the workflow chain,
                not only inside the system where the first task appears complete.
            </div>

            <div class="grid4">
                <div class="kpi"><span>Workflow Truth Score</span><strong>{{ dependency_kpis.workflow_truth_score }}</strong></div>
                <div class="kpi"><span>Systems Checked</span><strong>{{ dependency_kpis.systems_checked }}</strong></div>
                <div class="kpi"><span>Dependency Exceptions</span><strong>{{ dependency_kpis.dependency_exceptions }}</strong></div>
                <div class="kpi"><span>False Completion Risk</span><strong>{{ dependency_kpis.false_completion_risk }}</strong></div>
            </div>

            <div class="grid4">
                <div class="kpi"><span>Held Records</span><strong>{{ dependency_kpis.held_records }}</strong></div>
                <div class="kpi"><span>Release Blockers</span><strong>{{ dependency_kpis.release_blockers }}</strong></div>
                <div class="kpi"><span>Audit Exposure</span><strong>{{ dependency_kpis.audit_exposure }}</strong></div>
                <div class="kpi"><span>Validation Mode</span><strong>{{ dependency_kpis.validation_mode }}</strong></div>
            </div>

            <section class="panel">
                <h2>1. System Dependency Map</h2>
                <div class="truth-chain">
                    {% for s in system_map %}
                    <div class="node">
                        <h3>{{ s.system }}</h3>
                        <p><b>Role:</b> {{ s.role }}</p>
                        <p><b>Completion Limit:</b> {{ s.completion_limit }}</p>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="panel">
                <h2>2. Workflow Dependency Validation Cases</h2>
                <table>
                    <tr><th>Case</th><th>Workflow</th><th>Middleware</th><th>LIS</th><th>Downstream</th><th>COBIT-Chain State</th><th>Reason</th><th>Risk</th></tr>
                    {% for c in workflow_cases %}
                    <tr>
                        <td><b>{{ c.case_id }}</b></td>
                        <td>{{ c.workflow }}</td>
                        <td>{{ c.middleware_state }}</td>
                        <td>{{ c.lis_state }}</td>
                        <td>{{ c.downstream_state }}</td>
                        <td><span class="pill {{ c.cobitchain_state }}">{{ c.cobitchain_state }}</span></td>
                        <td>{{ c.reason }}</td>
                        <td><span class="pill {{ c.risk }}">{{ c.risk }}</span></td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>3. Dependency Validation Rules</h2>
                <table>
                    <tr><th>Rule</th><th>Logic</th><th>Control Value</th></tr>
                    {% for r in dependency_rules %}
                    <tr>
                        <td><b>{{ r.rule }}</b></td>
                        <td>{{ r.logic }}</td>
                        <td>{{ r.control_value }}</td>
                    </tr>
                    {% endfor %}
                </table>
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
        dependency_kpis=dependency_kpis,
        workflow_cases=workflow_cases,
        dependency_rules=dependency_rules,
        system_map=system_map,
        executive_summary=executive_summary
    )


'''

new_text = text[:idx] + route_code + text[idx:]
APP.write_text(new_text, encoding="utf-8")

required = [
    "CROSS_SYSTEM_DEPENDENCY_VALIDATION_ACTIVE",
    '@app.route("/cross-system-dependency-validation")',
    "Cross-System Dependency Validation Layer",
    "Workflow Dependency Validation Cases",
    "Dependency Validation Rules"
]

missing = [x for x in required if x not in new_text]
if missing:
    raise SystemExit("ERROR missing expected markers: " + ", ".join(missing))

print("SUCCESS: Cross-System Dependency Validation Layer added safely at /cross-system-dependency-validation")
