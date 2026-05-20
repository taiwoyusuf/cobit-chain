from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AUDIT_SIMULATION_ENGINE_ACTIVE"

if MARKER in text:
    print("Audit Simulation Engine already exists. No changes made.")
    raise SystemExit(0)

insert_before = '\nif __name__ == "__main__":'
idx = text.find(insert_before)

if idx == -1:
    raise SystemExit("ERROR: Could not find final if __name__ == \"__main__\" block.")

route_code = r'''

# ============================================================
# AUDIT_SIMULATION_ENGINE_ACTIVE
# Safe additive route only.
# Adds /audit-simulation-engine without modifying protected modules.
# Simulates audit readiness questions and likely inspection weak points.
# ============================================================

@app.route("/audit-simulation-engine")
def audit_simulation_engine():
    audit_kpis = {
        "overall_readiness": "84%",
        "evidence_completeness": "82%",
        "lineage_strength": "91%",
        "review_readiness": "78%",
        "critical_findings": "1",
        "major_observations": "3",
        "minor_observations": "5",
        "remediation_priority": "HIGH"
    }

    simulated_questions = [
        {
            "question": "Show the complete evidence trail for the open equipment issue.",
            "expected_evidence": "Ticket, shift owner, equipment state, audit trail export, supervisor review, closure rationale.",
            "current_state": "Partially Ready",
            "gap": "Audit trail export missing.",
            "risk": "HIGH"
        },
        {
            "question": "Who owned the issue during the B-to-C transition?",
            "expected_evidence": "Incoming technician acknowledgement and backup ownership.",
            "current_state": "Review Needed",
            "gap": "Incoming acknowledgement not yet confirmed.",
            "risk": "MEDIUM"
        },
        {
            "question": "Was the issue reviewed before closure?",
            "expected_evidence": "Supervisor review checkpoint and exception disposition.",
            "current_state": "Pending",
            "gap": "Supervisor review required before closure.",
            "risk": "MEDIUM"
        },
        {
            "question": "Can you prove the evidence was not modified after upload?",
            "expected_evidence": "Hash baseline, verification status, evidence register, immutable or controlled log.",
            "current_state": "Ready",
            "gap": "No critical gap detected in simulated evidence structure.",
            "risk": "LOW"
        },
        {
            "question": "What would be impacted if this issue repeated?",
            "expected_evidence": "Blast radius, affected equipment, shifts, evidence, CAPA exposure, and remediation plan.",
            "current_state": "Ready",
            "gap": "Blast radius model available.",
            "risk": "LOW"
        }
    ]

    likely_findings = [
        {
            "finding": "Missing audit trail evidence before closure",
            "classification": "Critical",
            "why_it_matters": "A record may not be defensible if required evidence is missing.",
            "linked_module": "Governance Blast Radius / Confidence Engine",
            "risk": "HIGH"
        },
        {
            "finding": "Incomplete shift transition acknowledgement",
            "classification": "Major",
            "why_it_matters": "Ownership continuity is unclear during operational handoff.",
            "linked_module": "Shift Overlap Intelligence",
            "risk": "MEDIUM"
        },
        {
            "finding": "Supervisor review checkpoint not completed",
            "classification": "Major",
            "why_it_matters": "Operational closure may occur without governance oversight.",
            "linked_module": "Operational Lineage",
            "risk": "MEDIUM"
        },
        {
            "finding": "Evidence package not fully export-ready",
            "classification": "Minor",
            "why_it_matters": "Audit response may be delayed by incomplete packaging.",
            "linked_module": "Platform Health / Sterile Evidence",
            "risk": "LOW"
        },
    ]

    remediation_plan = [
        {
            "priority": "P1",
            "action": "Attach missing audit trail export",
            "owner": "Technician / Equipment Support",
            "due": "Before closure",
            "confidence_gain": "+5"
        },
        {
            "priority": "P1",
            "action": "Capture incoming owner acknowledgement",
            "owner": "Shift Supervisor",
            "due": "Before B-to-C transition closes",
            "confidence_gain": "+3"
        },
        {
            "priority": "P2",
            "action": "Complete supervisor review checkpoint",
            "owner": "Supervisor",
            "due": "Before audit package export",
            "confidence_gain": "+4"
        },
        {
            "priority": "P2",
            "action": "Recalculate governance confidence score",
            "owner": "Governance Platform",
            "due": "After remediation",
            "confidence_gain": "+2"
        },
        {
            "priority": "P3",
            "action": "Monitor recurrence trend across overlap windows",
            "owner": "Operational Excellence",
            "due": "Weekly",
            "confidence_gain": "+1"
        },
    ]

    audit_pack_sections = [
        {"section": "Operational Trigger", "status": "Ready", "content": "Ticket, priority, event time, equipment area, current state"},
        {"section": "Ownership Timeline", "status": "Review Needed", "content": "Outgoing owner, incoming owner, backup, handoff acknowledgement"},
        {"section": "Evidence Register", "status": "Gap Detected", "content": "Uploaded files, missing evidence, hash readiness, verification state"},
        {"section": "Supervisor Review", "status": "Pending", "content": "Review decision, exception notes, closure readiness"},
        {"section": "Blast Radius", "status": "Ready", "content": "Impacted shifts, equipment, evidence, audit posture, CAPA exposure"},
        {"section": "Confidence Recovery", "status": "Ready", "content": "Remediation actions and expected score improvement"},
    ]

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>COBIT-Chain Audit Simulation Engine</title>
        <style>
            body { margin:0; font-family:Arial, Helvetica, sans-serif; background:#f4f7fb; color:#0f172a; }
            .hero { background:linear-gradient(135deg,#111827,#0369a1); color:white; padding:36px 44px 78px; border-bottom-left-radius:28px; border-bottom-right-radius:28px; }
            .hero h1 { margin:0 0 10px; font-size:40px; }
            .hero p { color:#e0f2fe; max-width:1080px; line-height:1.55; font-size:16px; }
            .badge { display:inline-block; background:rgba(255,255,255,.14); border:1px solid rgba(255,255,255,.25); padding:8px 13px; border-radius:999px; margin:10px 8px 0 0; font-size:12px; font-weight:800; }
            .wrap { max-width:1320px; margin:-46px auto 40px; padding:0 24px; }
            .grid4 { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:22px; }
            .kpi, .panel { background:white; border-radius:20px; padding:22px; box-shadow:0 12px 30px rgba(15,23,42,.09); margin-bottom:22px; }
            .kpi span { color:#64748b; font-weight:900; font-size:12px; text-transform:uppercase; letter-spacing:.07em; }
            .kpi strong { display:block; margin-top:9px; font-size:30px; }
            table { width:100%; border-collapse:collapse; }
            th { background:#e0f2fe; color:#075985; text-align:left; padding:12px; font-size:13px; }
            td { border-bottom:1px solid #e5e7eb; padding:12px; font-size:13px; vertical-align:top; }
            .pill { display:inline-block; padding:6px 10px; border-radius:999px; font-weight:900; font-size:11px; }
            .LOW, .Ready { background:#dcfce7; color:#166534; }
            .MEDIUM, .Pending, .Review { background:#fef3c7; color:#92400e; }
            .HIGH, .Critical, .Gap { background:#fee2e2; color:#991b1b; }
            .Major { background:#fef3c7; color:#92400e; }
            .Minor { background:#e0e7ff; color:#3730a3; }
            .P1 { background:#fee2e2; color:#991b1b; }
            .P2 { background:#fef3c7; color:#92400e; }
            .P3 { background:#e0e7ff; color:#3730a3; }
            .note { background:#e0f2fe; border:1px solid #7dd3fc; color:#075985; padding:16px; border-radius:16px; margin-bottom:22px; }
            .toplinks { margin-top:18px; }
            .toplinks a { color:white; text-decoration:none; font-weight:800; margin-right:16px; }
            @media(max-width:1000px){ .grid4{grid-template-columns:repeat(2,1fr);} }
            @media(max-width:680px){ .grid4{grid-template-columns:1fr;} .hero h1{font-size:30px;} }
        </style>
    </head>
    <body>
        <section class="hero">
            <h1>COBIT-Chain™ Audit Simulation Engine</h1>
            <p>
                Simulates what an FDA, QA, or internal auditor may ask tomorrow and identifies what would fail first:
                missing evidence, weak lineage, incomplete handoff, supervisor review gaps, and audit package readiness.
            </p>
            <span class="badge">AUDIT READINESS</span>
            <span class="badge">INSPECTION QUESTIONS</span>
            <span class="badge">REMEDIATION PLAN</span>
            <span class="badge">EVIDENCE DEFENSIBILITY</span>
            <div class="toplinks">
                <a href="/enterprise-workspaces">Enterprise Workspaces</a>
                <a href="/governance-confidence-engine">Governance Confidence</a>
                <a href="/governance-blast-radius">Blast Radius</a>
                <a href="/operational-lineage">Operational Lineage</a>
            </div>
        </section>

        <main class="wrap">
            <div class="note">
                <b>Executive meaning:</b> This gives leadership a pre-audit view of what needs fixing before a real inspection or internal audit.
            </div>

            <div class="grid4">
                <div class="kpi"><span>Overall Readiness</span><strong>{{ audit_kpis.overall_readiness }}</strong></div>
                <div class="kpi"><span>Evidence Completeness</span><strong>{{ audit_kpis.evidence_completeness }}</strong></div>
                <div class="kpi"><span>Lineage Strength</span><strong>{{ audit_kpis.lineage_strength }}</strong></div>
                <div class="kpi"><span>Review Readiness</span><strong>{{ audit_kpis.review_readiness }}</strong></div>
            </div>

            <div class="grid4">
                <div class="kpi"><span>Critical Findings</span><strong>{{ audit_kpis.critical_findings }}</strong></div>
                <div class="kpi"><span>Major Observations</span><strong>{{ audit_kpis.major_observations }}</strong></div>
                <div class="kpi"><span>Minor Observations</span><strong>{{ audit_kpis.minor_observations }}</strong></div>
                <div class="kpi"><span>Remediation Priority</span><strong>{{ audit_kpis.remediation_priority }}</strong></div>
            </div>

            <section class="panel">
                <h2>1. Simulated Auditor Questions</h2>
                <table>
                    <tr><th>Question</th><th>Expected Evidence</th><th>Current State</th><th>Gap</th><th>Risk</th></tr>
                    {% for q in simulated_questions %}
                    <tr>
                        <td><b>{{ q.question }}</b></td>
                        <td>{{ q.expected_evidence }}</td>
                        <td>{{ q.current_state }}</td>
                        <td>{{ q.gap }}</td>
                        <td><span class="pill {{ q.risk }}">{{ q.risk }}</span></td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>2. Likely Findings If Audited Today</h2>
                <table>
                    <tr><th>Finding</th><th>Classification</th><th>Why It Matters</th><th>Linked Module</th><th>Risk</th></tr>
                    {% for f in likely_findings %}
                    <tr>
                        <td><b>{{ f.finding }}</b></td>
                        <td><span class="pill {{ f.classification }}">{{ f.classification }}</span></td>
                        <td>{{ f.why_it_matters }}</td>
                        <td>{{ f.linked_module }}</td>
                        <td><span class="pill {{ f.risk }}">{{ f.risk }}</span></td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>3. Remediation Plan</h2>
                <table>
                    <tr><th>Priority</th><th>Action</th><th>Owner</th><th>Due</th><th>Confidence Gain</th></tr>
                    {% for r in remediation_plan %}
                    <tr>
                        <td><span class="pill {{ r.priority }}">{{ r.priority }}</span></td>
                        <td><b>{{ r.action }}</b></td>
                        <td>{{ r.owner }}</td>
                        <td>{{ r.due }}</td>
                        <td>{{ r.confidence_gain }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>4. Audit Pack Readiness</h2>
                <table>
                    <tr><th>Section</th><th>Status</th><th>Content</th></tr>
                    {% for a in audit_pack_sections %}
                    <tr>
                        <td><b>{{ a.section }}</b></td>
                        <td><span class="pill {{ a.status.split()[0] }}">{{ a.status }}</span></td>
                        <td>{{ a.content }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>5. Why This Is Revolutionary</h2>
                <p>
                    Most systems help teams respond after an audit finding. This engine simulates audit pressure before the audit happens,
                    showing what would fail first and how to recover governance confidence before inspection risk becomes real.
                </p>
            </section>
        </main>
    </body>
    </html>
    """

    return render_template_string(
        html,
        audit_kpis=audit_kpis,
        simulated_questions=simulated_questions,
        likely_findings=likely_findings,
        remediation_plan=remediation_plan,
        audit_pack_sections=audit_pack_sections
    )


'''

new_text = text[:idx] + route_code + text[idx:]
APP.write_text(new_text, encoding="utf-8")

required = [
    "AUDIT_SIMULATION_ENGINE_ACTIVE",
    '@app.route("/audit-simulation-engine")',
    "Audit Simulation Engine",
    "Simulated Auditor Questions",
    "Likely Findings If Audited Today"
]

missing = [x for x in required if x not in new_text]
if missing:
    raise SystemExit("ERROR missing expected markers: " + ", ".join(missing))

print("SUCCESS: Audit Simulation Engine added safely at /audit-simulation-engine")
