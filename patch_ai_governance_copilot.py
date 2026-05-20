from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AI_GOVERNANCE_COPILOT_ACTIVE"

if MARKER in text:
    print("AI Governance Copilot already exists. No changes made.")
    raise SystemExit(0)

insert_before = '\nif __name__ == "__main__":'
idx = text.find(insert_before)

if idx == -1:
    raise SystemExit("ERROR: Could not find final if __name__ == \"__main__\" block.")

route_code = r'''

# ============================================================
# AI_GOVERNANCE_COPILOT_ACTIVE
# Safe additive route only.
# Adds /ai-governance-copilot without modifying protected modules.
# Synthetic advisory copilot only; no external AI/API dependency.
# ============================================================

@app.route("/ai-governance-copilot")
def ai_governance_copilot():
    copilot_kpis = {
        "governance_confidence": "89%",
        "top_risk": "Evidence Gap",
        "audit_readiness": "84%",
        "recommended_priority": "P1",
        "open_actions": "4",
        "confidence_recovery": "+12",
        "copilot_mode": "Synthetic Advisory",
        "data_boundary": "Demo-Safe"
    }

    executive_answer = {
        "question": "Can leadership trust the current operational state?",
        "answer": "Conditionally yes. The operation is broadly governed, but trust is limited by one missing audit trail export, one pending B-to-C acknowledgement, and an incomplete supervisor checkpoint.",
        "why": "Governance confidence is 89%, audit readiness is 84%, and the blast radius remains HIGH until the evidence and ownership gaps are closed.",
        "next_best_action": "Close the missing evidence and capture incoming owner acknowledgement before allowing audit-ready closure."
    }

    copilot_insights = [
        {
            "prompt": "Why did governance confidence drop?",
            "response": "Confidence dropped because evidence completeness declined and incoming shift ownership is not yet confirmed. These two signals affect audit readiness, handoff integrity, and supervisor review confidence.",
            "linked_route": "/governance-confidence-engine",
            "priority": "P1"
        },
        {
            "prompt": "What should be fixed first?",
            "response": "Attach the missing audit trail export first because it has the largest audit-readiness impact. Then capture the B-to-C incoming owner acknowledgement.",
            "linked_route": "/audit-simulation-engine",
            "priority": "P1"
        },
        {
            "prompt": "What is the blast radius?",
            "response": "The weakness impacts shift continuity, equipment ownership, evidence integrity, supervisor review, audit readiness, and potential CAPA/deviation exposure.",
            "linked_route": "/governance-blast-radius",
            "priority": "P2"
        },
        {
            "prompt": "What would an auditor ask?",
            "response": "An auditor would likely ask for the complete evidence trail, ownership during transition, supervisor review decision, and proof the evidence was not modified after upload.",
            "linked_route": "/audit-simulation-engine",
            "priority": "P2"
        },
        {
            "prompt": "Is ServiceNow enough?",
            "response": "ServiceNow tracks workflow state. COBIT-Chain evaluates whether the workflow is governed, evidenced, reviewed, and audit-defensible.",
            "linked_route": "/servicenow-governance-overlay",
            "priority": "P2"
        },
    ]

    remediation_playbook = [
        {"step": "1", "action": "Attach missing audit trail export", "owner": "Technician / Equipment Support", "expected_gain": "+5 confidence", "status": "Open"},
        {"step": "2", "action": "Capture incoming owner acknowledgement", "owner": "Shift Supervisor", "expected_gain": "+3 confidence", "status": "Open"},
        {"step": "3", "action": "Complete supervisor review checkpoint", "owner": "Supervisor", "expected_gain": "+4 confidence", "status": "Open"},
        {"step": "4", "action": "Recalculate governance confidence", "owner": "Governance Platform", "expected_gain": "Trust state updated", "status": "Ready After Steps 1-3"},
    ]

    advisory_modes = [
        {
            "mode": "Executive Advisor",
            "question": "What does leadership need to know?",
            "answer": "The operation is controlled but under watch. Two actions are blocking full trust: evidence completion and incoming owner acknowledgement."
        },
        {
            "mode": "Audit Advisor",
            "question": "What would fail first in inspection?",
            "answer": "The missing audit trail export would be the first weakness, followed by incomplete ownership evidence during the shift transition."
        },
        {
            "mode": "Operations Advisor",
            "question": "What should the supervisor do now?",
            "answer": "Force the acknowledgement checkpoint, require evidence attachment, and prevent weak closure until review is complete."
        },
        {
            "mode": "ServiceNow Advisor",
            "question": "What does the ticket state not show?",
            "answer": "It may show assignment or progress, but not whether the record is trusted, complete, reviewed, or audit-defensible."
        },
    ]

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>COBIT-Chain AI Governance Copilot</title>
        <style>
            body { margin:0; font-family:Arial, Helvetica, sans-serif; background:#f4f7fb; color:#0f172a; }
            .top { background:#0f172a; color:white; padding:14px 24px; display:flex; justify-content:space-between; align-items:center; gap:18px; flex-wrap:wrap; position:sticky; top:0; z-index:10; }
            .brand { font-weight:900; font-size:18px; }
            .brand span { color:#38bdf8; }
            .nav { display:flex; gap:10px; flex-wrap:wrap; }
            .nav a { color:#dbeafe; text-decoration:none; font-size:12px; font-weight:800; padding:8px 10px; border-radius:999px; background:rgba(255,255,255,.08); border:1px solid rgba(255,255,255,.12); }
            .nav a:hover { background:#2563eb; color:white; }
            .hero { background:linear-gradient(135deg,#111827,#6d28d9); color:white; padding:38px 44px 82px; border-bottom-left-radius:28px; border-bottom-right-radius:28px; }
            .hero h1 { margin:0 0 10px; font-size:42px; }
            .hero p { color:#ede9fe; max-width:1120px; line-height:1.55; font-size:16px; }
            .badge { display:inline-block; background:rgba(255,255,255,.14); border:1px solid rgba(255,255,255,.25); padding:8px 13px; border-radius:999px; margin:10px 8px 0 0; font-size:12px; font-weight:800; }
            .wrap { max-width:1360px; margin:-48px auto 40px; padding:0 24px; }
            .grid4 { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:22px; }
            .kpi, .panel { background:white; border-radius:20px; padding:22px; box-shadow:0 12px 30px rgba(15,23,42,.09); margin-bottom:22px; }
            .kpi span { color:#64748b; font-weight:900; font-size:12px; text-transform:uppercase; letter-spacing:.07em; }
            .kpi strong { display:block; margin-top:9px; font-size:28px; }
            .answer-box { background:#f5f3ff; border:1px solid #ddd6fe; color:#4c1d95; border-radius:22px; padding:24px; box-shadow:0 12px 30px rgba(15,23,42,.08); margin-bottom:22px; }
            .answer-box h2 { margin-top:0; }
            .insight-grid { display:grid; grid-template-columns:repeat(2,1fr); gap:16px; }
            .insight { background:#f8fafc; border:1px solid #e2e8f0; border-radius:18px; padding:18px; }
            .insight h3 { margin:0 0 8px; color:#5b21b6; }
            .insight p { color:#334155; line-height:1.5; }
            .insight a { display:inline-block; text-decoration:none; background:#0f172a; color:white; padding:9px 12px; border-radius:10px; font-weight:800; font-size:13px; margin-top:8px; }
            table { width:100%; border-collapse:collapse; }
            th { background:#f5f3ff; color:#5b21b6; text-align:left; padding:12px; font-size:13px; }
            td { border-bottom:1px solid #e5e7eb; padding:12px; font-size:13px; vertical-align:top; }
            .pill { display:inline-block; padding:6px 10px; border-radius:999px; font-weight:900; font-size:11px; }
            .P1, .Open { background:#fee2e2; color:#991b1b; }
            .P2 { background:#fef3c7; color:#92400e; }
            .Ready { background:#dcfce7; color:#166534; }
            .note { background:#ecfeff; border:1px solid #a5f3fc; color:#155e75; padding:16px; border-radius:16px; margin-bottom:22px; }
            @media(max-width:1000px){ .grid4,.insight-grid{grid-template-columns:repeat(2,1fr);} }
            @media(max-width:700px){ .grid4,.insight-grid{grid-template-columns:1fr;} .hero h1{font-size:30px;} }
        </style>
    </head>
    <body>
        <div class="top">
            <div class="brand">COBIT-Chain™ <span>AI Governance Copilot</span></div>
            <nav class="nav">
                <a href="/executive-mission-control">Mission Control</a>
                <a href="/live-governance-ticker">Live Ticker</a>
                <a href="/governance-confidence-engine">Confidence</a>
                <a href="/audit-simulation-engine">Audit</a>
                <a href="/servicenow-governance-overlay">ServiceNow</a>
            </nav>
        </div>

        <section class="hero">
            <h1>AI Governance Copilot™</h1>
            <p>
                A synthetic advisory copilot that explains governance confidence, audit risk, blast radius,
                ServiceNow trust gaps, and recovery actions without using confidential data or external AI APIs.
            </p>
            <span class="badge">SYNTHETIC ADVISORY</span>
            <span class="badge">NO EXTERNAL API</span>
            <span class="badge">EXECUTIVE REASONING</span>
            <span class="badge">REMEDIATION GUIDANCE</span>
        </section>

        <main class="wrap">
            <div class="note">
                <b>Boundary:</b> This is a safe demo copilot. It uses synthetic rule-based advisory content only.
                It does not call OpenAI, ServiceNow, Lilly systems, or any external service.
            </div>

            <div class="grid4">
                <div class="kpi"><span>Governance Confidence</span><strong>{{ copilot_kpis.governance_confidence }}</strong></div>
                <div class="kpi"><span>Top Risk</span><strong>{{ copilot_kpis.top_risk }}</strong></div>
                <div class="kpi"><span>Audit Readiness</span><strong>{{ copilot_kpis.audit_readiness }}</strong></div>
                <div class="kpi"><span>Recommended Priority</span><strong>{{ copilot_kpis.recommended_priority }}</strong></div>
            </div>

            <div class="grid4">
                <div class="kpi"><span>Open Actions</span><strong>{{ copilot_kpis.open_actions }}</strong></div>
                <div class="kpi"><span>Confidence Recovery</span><strong>{{ copilot_kpis.confidence_recovery }}</strong></div>
                <div class="kpi"><span>Copilot Mode</span><strong>{{ copilot_kpis.copilot_mode }}</strong></div>
                <div class="kpi"><span>Data Boundary</span><strong>{{ copilot_kpis.data_boundary }}</strong></div>
            </div>

            <section class="answer-box">
                <h2>{{ executive_answer.question }}</h2>
                <p><b>Answer:</b> {{ executive_answer.answer }}</p>
                <p><b>Why:</b> {{ executive_answer.why }}</p>
                <p><b>Next Best Action:</b> {{ executive_answer.next_best_action }}</p>
            </section>

            <section class="panel">
                <h2>1. Copilot Governance Insights</h2>
                <div class="insight-grid">
                    {% for i in copilot_insights %}
                    <div class="insight">
                        <span class="pill {{ i.priority }}">{{ i.priority }}</span>
                        <h3>{{ i.prompt }}</h3>
                        <p>{{ i.response }}</p>
                        <a href="{{ i.linked_route }}">Open Evidence</a>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="panel">
                <h2>2. Remediation Playbook</h2>
                <table>
                    <tr><th>Step</th><th>Action</th><th>Owner</th><th>Expected Gain</th><th>Status</th></tr>
                    {% for r in remediation_playbook %}
                    <tr>
                        <td><b>{{ r.step }}</b></td>
                        <td><b>{{ r.action }}</b></td>
                        <td>{{ r.owner }}</td>
                        <td>{{ r.expected_gain }}</td>
                        <td><span class="pill {{ r.status.split()[0] }}">{{ r.status }}</span></td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>3. Advisory Modes</h2>
                <table>
                    <tr><th>Mode</th><th>Question</th><th>Copilot Answer</th></tr>
                    {% for a in advisory_modes %}
                    <tr>
                        <td><b>{{ a.mode }}</b></td>
                        <td>{{ a.question }}</td>
                        <td>{{ a.answer }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </section>
        </main>
    </body>
    </html>
    """

    return render_template_string(
        html,
        copilot_kpis=copilot_kpis,
        executive_answer=executive_answer,
        copilot_insights=copilot_insights,
        remediation_playbook=remediation_playbook,
        advisory_modes=advisory_modes
    )


'''

new_text = text[:idx] + route_code + text[idx:]
APP.write_text(new_text, encoding="utf-8")

required = [
    "AI_GOVERNANCE_COPILOT_ACTIVE",
    '@app.route("/ai-governance-copilot")',
    "AI Governance Copilot",
    "Copilot Governance Insights",
    "Remediation Playbook"
]

missing = [x for x in required if x not in new_text]
if missing:
    raise SystemExit("ERROR missing expected markers: " + ", ".join(missing))

print("SUCCESS: AI Governance Copilot added safely at /ai-governance-copilot")
