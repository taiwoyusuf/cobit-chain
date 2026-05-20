from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "GOVERNANCE_SCENARIO_SIMULATOR_ACTIVE"

if MARKER in text:
    print("Governance Scenario Simulator already exists. No changes made.")
    raise SystemExit(0)

insert_before = '\nif __name__ == "__main__":'
idx = text.find(insert_before)

if idx == -1:
    raise SystemExit("ERROR: Could not find final if __name__ == \"__main__\" block.")

route_code = r'''

# ============================================================
# GOVERNANCE_SCENARIO_SIMULATOR_ACTIVE
# Safe additive route only.
# Adds /governance-scenario-simulator without modifying protected modules.
# Synthetic governance war-gaming for leadership and audit readiness.
# ============================================================

@app.route("/governance-scenario-simulator")
def governance_scenario_simulator():

    scenario_kpis = {
        "scenarios_modeled": "5",
        "highest_impact": "ServiceNow Weak Closure",
        "worst_confidence_drop": "-21",
        "highest_audit_exposure": "Critical",
        "fastest_recovery": "Evidence Fix",
        "recommended_focus": "Ownership + Evidence",
        "model_mode": "Synthetic War-Game",
        "data_boundary": "Demo-Safe"
    }

    scenarios = [
        {
            "scenario": "Evidence Missing at Closure",
            "trigger": "Required audit trail export not attached before ticket closure.",
            "confidence_impact": "-14",
            "audit_exposure": "High",
            "blast_radius": "Evidence → Review → Audit",
            "capa_likelihood": "Medium",
            "recovery_difficulty": "Low",
            "recommended_response": "Attach evidence, verify hash readiness, rerun audit simulation."
        },
        {
            "scenario": "Supervisor Review Delayed",
            "trigger": "Supervisor checkpoint remains incomplete after operational closure.",
            "confidence_impact": "-11",
            "audit_exposure": "Medium",
            "blast_radius": "Review → Audit State → Executive Confidence",
            "capa_likelihood": "Medium",
            "recovery_difficulty": "Medium",
            "recommended_response": "Force supervisor review and document closure rationale."
        },
        {
            "scenario": "Shift Overlap Acknowledgement Fails",
            "trigger": "Incoming B-to-C technician does not acknowledge unresolved issue.",
            "confidence_impact": "-13",
            "audit_exposure": "Medium",
            "blast_radius": "Shift → Technician → Equipment → Evidence",
            "capa_likelihood": "Medium",
            "recovery_difficulty": "Medium",
            "recommended_response": "Require incoming owner acknowledgement and backup assignment."
        },
        {
            "scenario": "ServiceNow Closure Without Governance Validation",
            "trigger": "Ticket moves to closed state before evidence, owner, and review controls are complete.",
            "confidence_impact": "-21",
            "audit_exposure": "Critical",
            "blast_radius": "Workflow → Evidence → Review → Audit → CAPA",
            "capa_likelihood": "High",
            "recovery_difficulty": "High",
            "recommended_response": "Reopen governance review, attach missing records, and block weak closure pattern."
        },
        {
            "scenario": "Audit Happens Today",
            "trigger": "QA/internal/FDA-style inspection asks for complete evidence and ownership trail.",
            "confidence_impact": "-16",
            "audit_exposure": "High",
            "blast_radius": "Audit Questions → Evidence → Lineage → Confidence",
            "capa_likelihood": "Medium",
            "recovery_difficulty": "Medium",
            "recommended_response": "Generate audit package, resolve evidence gaps, and present lineage record."
        },
    ]

    decision_matrix = [
        {
            "decision": "Fix evidence first",
            "confidence_recovery": "+5 to +8",
            "audit_recovery": "High",
            "time_to_value": "Fast",
            "recommended": "YES"
        },
        {
            "decision": "Fix ownership first",
            "confidence_recovery": "+3 to +5",
            "audit_recovery": "Medium",
            "time_to_value": "Fast",
            "recommended": "YES"
        },
        {
            "decision": "Wait for weekly review",
            "confidence_recovery": "-8 projected drift",
            "audit_recovery": "Low",
            "time_to_value": "Slow",
            "recommended": "NO"
        },
        {
            "decision": "Close ticket without governance validation",
            "confidence_recovery": "-21 projected drop",
            "audit_recovery": "Critical exposure",
            "time_to_value": "False closure",
            "recommended": "NO"
        },
    ]

    simulator_story = [
        "This turns governance into war-gaming, not static reporting.",
        "Leadership can test what happens before the real failure occurs.",
        "The strongest risk pattern is closing workflow records before governance controls are complete.",
        "Evidence and ownership are the fastest recovery levers.",
        "The simulator supports executive decision-making, audit preparation, and pre-deviation control."
    ]

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>COBIT-Chain Governance Scenario Simulator</title>
        <style>
            body { margin:0; font-family:Arial, Helvetica, sans-serif; background:#f4f7fb; color:#0f172a; }
            .top { background:#0f172a; color:white; padding:14px 24px; display:flex; justify-content:space-between; align-items:center; gap:18px; flex-wrap:wrap; position:sticky; top:0; z-index:10; }
            .brand { font-weight:900; font-size:18px; }
            .brand span { color:#38bdf8; }
            .nav { display:flex; gap:10px; flex-wrap:wrap; }
            .nav a { color:#dbeafe; text-decoration:none; font-size:12px; font-weight:800; padding:8px 10px; border-radius:999px; background:rgba(255,255,255,.08); border:1px solid rgba(255,255,255,.12); }
            .nav a:hover { background:#2563eb; color:white; }
            .hero { background:linear-gradient(135deg,#111827,#7f1d1d); color:white; padding:38px 44px 82px; border-bottom-left-radius:28px; border-bottom-right-radius:28px; }
            .hero h1 { margin:0 0 10px; font-size:42px; }
            .hero p { color:#fee2e2; max-width:1120px; line-height:1.55; font-size:16px; }
            .badge { display:inline-block; background:rgba(255,255,255,.14); border:1px solid rgba(255,255,255,.25); padding:8px 13px; border-radius:999px; margin:10px 8px 0 0; font-size:12px; font-weight:800; }
            .wrap { max-width:1360px; margin:-48px auto 40px; padding:0 24px; }
            .grid4 { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:22px; }
            .kpi, .panel { background:white; border-radius:20px; padding:22px; box-shadow:0 12px 30px rgba(15,23,42,.09); margin-bottom:22px; }
            .kpi span { color:#64748b; font-weight:900; font-size:12px; text-transform:uppercase; letter-spacing:.07em; }
            .kpi strong { display:block; margin-top:9px; font-size:26px; }
            table { width:100%; border-collapse:collapse; }
            th { background:#fee2e2; color:#991b1b; text-align:left; padding:12px; font-size:13px; }
            td { border-bottom:1px solid #e5e7eb; padding:12px; font-size:13px; vertical-align:top; }
            .scenario-grid { display:grid; grid-template-columns:repeat(2,1fr); gap:16px; }
            .scenario-card { background:#f8fafc; border:1px solid #fecaca; border-radius:18px; padding:18px; }
            .scenario-card h3 { margin:0 0 8px; color:#991b1b; }
            .scenario-card p { color:#334155; line-height:1.45; font-size:13px; }
            .pill { display:inline-block; padding:6px 10px; border-radius:999px; font-weight:900; font-size:11px; }
            .YES, .Low { background:#dcfce7; color:#166534; }
            .NO, .High, .Critical { background:#fee2e2; color:#991b1b; }
            .Medium { background:#fef3c7; color:#92400e; }
            .note { background:#fef2f2; border:1px solid #fecaca; color:#991b1b; padding:16px; border-radius:16px; margin-bottom:22px; }
            ul { line-height:1.8; color:#334155; }
            @media(max-width:1000px){ .grid4,.scenario-grid{grid-template-columns:repeat(2,1fr);} }
            @media(max-width:700px){ .grid4,.scenario-grid{grid-template-columns:1fr;} .hero h1{font-size:30px;} }
        </style>
    </head>
    <body>
        <div class="top">
            <div class="brand">COBIT-Chain™ <span>Scenario Simulator</span></div>
            <nav class="nav">
                <a href="/executive-mission-control">Mission Control</a>
                <a href="/predictive-governance-drift">Predictive Drift</a>
                <a href="/governance-recovery-simulator">Recovery</a>
                <a href="/ai-governance-copilot">AI Copilot</a>
                <a href="/audit-simulation-engine">Audit</a>
            </nav>
        </div>

        <section class="hero">
            <h1>Governance Scenario Simulator™</h1>
            <p>
                Synthetic governance war-gaming for leadership: test what happens when evidence is missing,
                review is delayed, shift acknowledgement fails, ServiceNow closes too early, or audit happens today.
            </p>
            <span class="badge">SCENARIO WAR-GAMING</span>
            <span class="badge">WHAT-IF GOVERNANCE</span>
            <span class="badge">AUDIT EXPOSURE MODELING</span>
            <span class="badge">PRE-DEVIATION CONTROL</span>
        </section>

        <main class="wrap">
            <div class="note">
                <b>Executive meaning:</b> This lets leadership ask “what if?” before the issue becomes a deviation, audit finding, or CAPA trigger.
            </div>

            <div class="grid4">
                <div class="kpi"><span>Scenarios Modeled</span><strong>{{ scenario_kpis.scenarios_modeled }}</strong></div>
                <div class="kpi"><span>Highest Impact</span><strong>{{ scenario_kpis.highest_impact }}</strong></div>
                <div class="kpi"><span>Worst Confidence Drop</span><strong>{{ scenario_kpis.worst_confidence_drop }}</strong></div>
                <div class="kpi"><span>Highest Audit Exposure</span><strong>{{ scenario_kpis.highest_audit_exposure }}</strong></div>
            </div>

            <div class="grid4">
                <div class="kpi"><span>Fastest Recovery</span><strong>{{ scenario_kpis.fastest_recovery }}</strong></div>
                <div class="kpi"><span>Recommended Focus</span><strong>{{ scenario_kpis.recommended_focus }}</strong></div>
                <div class="kpi"><span>Model Mode</span><strong>{{ scenario_kpis.model_mode }}</strong></div>
                <div class="kpi"><span>Data Boundary</span><strong>{{ scenario_kpis.data_boundary }}</strong></div>
            </div>

            <section class="panel">
                <h2>1. Scenario War-Gaming Cards</h2>
                <div class="scenario-grid">
                    {% for s in scenarios %}
                    <div class="scenario-card">
                        <h3>{{ s.scenario }}</h3>
                        <p><b>Trigger:</b> {{ s.trigger }}</p>
                        <p><b>Confidence Impact:</b> {{ s.confidence_impact }}</p>
                        <p><b>Audit Exposure:</b> {{ s.audit_exposure }}</p>
                        <p><b>Blast Radius:</b> {{ s.blast_radius }}</p>
                        <p><b>CAPA Likelihood:</b> {{ s.capa_likelihood }}</p>
                        <p><b>Recovery Difficulty:</b> {{ s.recovery_difficulty }}</p>
                        <p><b>Recommended Response:</b> {{ s.recommended_response }}</p>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="panel">
                <h2>2. Decision Matrix</h2>
                <table>
                    <tr><th>Decision</th><th>Confidence Recovery</th><th>Audit Recovery</th><th>Time to Value</th><th>Recommended</th></tr>
                    {% for d in decision_matrix %}
                    <tr>
                        <td><b>{{ d.decision }}</b></td>
                        <td>{{ d.confidence_recovery }}</td>
                        <td>{{ d.audit_recovery }}</td>
                        <td>{{ d.time_to_value }}</td>
                        <td><span class="pill {{ d.recommended }}">{{ d.recommended }}</span></td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>3. Simulator Story</h2>
                <ul>
                    {% for s in simulator_story %}
                    <li>{{ s }}</li>
                    {% endfor %}
                </ul>
            </section>
        </main>
    </body>
    </html>
    """

    return render_template_string(
        html,
        scenario_kpis=scenario_kpis,
        scenarios=scenarios,
        decision_matrix=decision_matrix,
        simulator_story=simulator_story
    )


'''

new_text = text[:idx] + route_code + text[idx:]
APP.write_text(new_text, encoding="utf-8")

required = [
    "GOVERNANCE_SCENARIO_SIMULATOR_ACTIVE",
    '@app.route("/governance-scenario-simulator")',
    "Governance Scenario Simulator",
    "Scenario War-Gaming Cards",
    "Decision Matrix"
]

missing = [x for x in required if x not in new_text]
if missing:
    raise SystemExit("ERROR missing expected markers: " + ", ".join(missing))

print("SUCCESS: Governance Scenario Simulator added safely at /governance-scenario-simulator")
