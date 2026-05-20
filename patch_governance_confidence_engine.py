from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "GOVERNANCE_CONFIDENCE_ENGINE_ACTIVE"

if MARKER in text:
    print("Governance Confidence Engine already exists. No changes made.")
    raise SystemExit(0)

insert_before = '\nif __name__ == "__main__":'
idx = text.find(insert_before)

if idx == -1:
    raise SystemExit("ERROR: Could not find final if __name__ == \"__main__\" block.")

route_code = r'''

# ============================================================
# GOVERNANCE_CONFIDENCE_ENGINE_ACTIVE
# Safe additive route only.
# Adds /governance-confidence-engine without modifying protected modules.
# ============================================================

@app.route("/governance-confidence-engine")
def governance_confidence_engine():
    confidence_inputs = [
        {"factor": "Overlap Integrity", "score": 94, "weight": "15%", "signal": "A/B and C/D overlap windows provide redundancy", "risk": "LOW"},
        {"factor": "Handoff Integrity", "score": 87, "weight": "15%", "signal": "One B-to-C transition requires incoming acknowledgement", "risk": "MEDIUM"},
        {"factor": "Evidence Completeness", "score": 82, "weight": "20%", "signal": "Two evidence gaps remain open before audit-ready closure", "risk": "MEDIUM"},
        {"factor": "Escalation Ownership", "score": 85, "weight": "15%", "signal": "One escalation needs supervisor confirmation", "risk": "MEDIUM"},
        {"factor": "Audit Readiness", "score": 88, "weight": "15%", "signal": "Audit export structure ready; missing evidence blocks full readiness", "risk": "MEDIUM"},
        {"factor": "Lineage Continuity", "score": 96, "weight": "10%", "signal": "Ticket-to-evidence chain is connected through operational lineage", "risk": "LOW"},
        {"factor": "Platform Health", "score": 92, "weight": "10%", "signal": "Core routes and registers are visible through platform health", "risk": "LOW"},
    ]

    weighted_score = 89

    confidence_bands = [
        {"band": "95-100", "label": "Trusted / Audit-Ready", "meaning": "Evidence, ownership, review, and lineage are complete enough for executive confidence.", "color": "green"},
        {"band": "85-94", "label": "Governed / Review Minor Gaps", "meaning": "Operation is controlled, but some evidence or review gaps require attention.", "color": "yellow"},
        {"band": "70-84", "label": "At Risk / Governance Weakness", "meaning": "Open gaps could become audit findings, deviation triggers, or continuity failures.", "color": "orange"},
        {"band": "<70", "label": "Critical / Not Defensible", "meaning": "Records are not ready for audit or leadership reliance without remediation.", "color": "red"},
    ]

    recommendations = [
        {
            "priority": "P1",
            "title": "Close missing evidence before shift closure",
            "action": "Attach or verify required audit trail export before supervisor signoff.",
            "impact": "+5 confidence points"
        },
        {
            "priority": "P1",
            "title": "Force incoming owner acknowledgement",
            "action": "Require B-to-C incoming technician acknowledgement for unresolved items.",
            "impact": "+3 confidence points"
        },
        {
            "priority": "P2",
            "title": "Confirm escalation owner",
            "action": "Assign named escalation owner and backup before closure.",
            "impact": "+2 confidence points"
        },
        {
            "priority": "P2",
            "title": "Link evidence to lineage package",
            "action": "Ensure evidence nodes connect to ticket, shift, equipment, and review records.",
            "impact": "+4 confidence points"
        },
    ]

    executive_summary = [
        {"question": "Can leadership rely on the operational record?", "answer": "Mostly yes, with minor gaps", "basis": "Governance confidence is 89%, with evidence and handoff items still open."},
        {"question": "Is the record audit-ready?", "answer": "Conditionally", "basis": "Audit package is structurally ready, but missing evidence must be closed."},
        {"question": "Is there pre-deviation risk?", "answer": "Yes", "basis": "Evidence gap plus incomplete B-to-C handoff could become a governance failure."},
        {"question": "What does COBIT-Chain add?", "answer": "Trust layer", "basis": "It calculates whether work is governed, not merely whether work exists."},
    ]

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>COBIT-Chain Governance Confidence Engine</title>
        <style>
            body { margin:0; font-family:Arial, Helvetica, sans-serif; background:#f4f7fb; color:#0f172a; }
            .hero { background:linear-gradient(135deg,#111827,#7c3aed); color:white; padding:36px 44px 78px; border-bottom-left-radius:28px; border-bottom-right-radius:28px; }
            .hero h1 { margin:0 0 10px; font-size:40px; }
            .hero p { color:#ede9fe; max-width:1080px; line-height:1.55; font-size:16px; }
            .badge { display:inline-block; background:rgba(255,255,255,.14); border:1px solid rgba(255,255,255,.25); padding:8px 13px; border-radius:999px; margin:10px 8px 0 0; font-size:12px; font-weight:800; }
            .wrap { max-width:1320px; margin:-46px auto 40px; padding:0 24px; }
            .score-card { background:white; border-radius:24px; padding:30px; box-shadow:0 14px 34px rgba(15,23,42,.12); margin-bottom:24px; display:grid; grid-template-columns:280px 1fr; gap:28px; align-items:center; }
            .score-circle { width:220px; height:220px; border-radius:50%; background:conic-gradient(#7c3aed 0 89%, #e2e8f0 89% 100%); display:flex; align-items:center; justify-content:center; margin:auto; }
            .score-inner { width:160px; height:160px; border-radius:50%; background:white; display:flex; flex-direction:column; align-items:center; justify-content:center; box-shadow:inset 0 0 0 1px #e5e7eb; }
            .score-inner strong { font-size:46px; color:#5b21b6; }
            .score-inner span { color:#64748b; font-size:12px; font-weight:900; text-transform:uppercase; }
            .panel { background:white; border-radius:20px; padding:22px; box-shadow:0 12px 30px rgba(15,23,42,.09); margin-bottom:22px; }
            .grid4 { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:22px; }
            table { width:100%; border-collapse:collapse; }
            th { background:#f5f3ff; color:#5b21b6; text-align:left; padding:12px; font-size:13px; }
            td { border-bottom:1px solid #e5e7eb; padding:12px; font-size:13px; vertical-align:top; }
            .pill { display:inline-block; padding:6px 10px; border-radius:999px; font-weight:900; font-size:11px; }
            .LOW { background:#dcfce7; color:#166534; }
            .MEDIUM { background:#fef3c7; color:#92400e; }
            .HIGH { background:#fee2e2; color:#991b1b; }
            .P1 { background:#fee2e2; color:#991b1b; }
            .P2 { background:#fef3c7; color:#92400e; }
            .green { background:#dcfce7; color:#166534; }
            .yellow { background:#fef3c7; color:#92400e; }
            .orange { background:#ffedd5; color:#9a3412; }
            .red { background:#fee2e2; color:#991b1b; }
            .mini { background:white; border-radius:20px; padding:20px; box-shadow:0 12px 30px rgba(15,23,42,.09); }
            .mini h3 { margin:0 0 8px; }
            .mini p { color:#475569; line-height:1.5; }
            .bar { height:12px; background:#e2e8f0; border-radius:999px; overflow:hidden; }
            .fill { height:12px; background:#7c3aed; border-radius:999px; }
            .note { background:#f5f3ff; border:1px solid #ddd6fe; color:#4c1d95; padding:16px; border-radius:16px; margin-bottom:22px; }
            .toplinks { margin-top:18px; }
            .toplinks a { color:white; text-decoration:none; font-weight:800; margin-right:16px; }
            @media(max-width:1000px){ .score-card{grid-template-columns:1fr;} .grid4{grid-template-columns:repeat(2,1fr);} }
            @media(max-width:680px){ .grid4{grid-template-columns:1fr;} .hero h1{font-size:30px;} }
        </style>
    </head>
    <body>
        <section class="hero">
            <h1>COBIT-Chain™ Governance Confidence Engine</h1>
            <p>
                A cross-platform trust layer that converts overlap integrity, evidence completeness, escalation ownership,
                audit readiness, lineage continuity, and platform health into one leadership-friendly confidence score.
            </p>
            <span class="badge">EXECUTIVE TRUST SCORE</span>
            <span class="badge">PRE-DEVIATION SIGNALS</span>
            <span class="badge">AUDIT READINESS</span>
            <span class="badge">LINEAGE CONFIDENCE</span>
            <div class="toplinks">
                <a href="/enterprise-workspaces">Enterprise Workspaces</a>
                <a href="/shift-overlap-intelligence">Shift Overlap Intelligence</a>
                <a href="/operational-lineage">Operational Lineage</a>
                <a href="/platform-health">Platform Health</a>
            </div>
        </section>

        <main class="wrap">
            <section class="score-card">
                <div class="score-circle">
                    <div class="score-inner">
                        <strong>{{ weighted_score }}%</strong>
                        <span>Confidence</span>
                    </div>
                </div>
                <div>
                    <h2>Current Governance Confidence: Governed / Review Minor Gaps</h2>
                    <p>
                        The operation is broadly controlled, but evidence completion and B-to-C handoff acknowledgement remain the key confidence limiters.
                        This score is designed for leadership review, audit posture assessment, and pre-deviation risk visibility.
                    </p>
                    <div class="bar"><div class="fill" style="width:{{ weighted_score }}%;"></div></div>
                </div>
            </section>

            <div class="note">
                <b>Executive meaning:</b> ServiceNow can show the work exists. COBIT-Chain shows whether the work is reliable enough to trust.
            </div>

            <section class="panel">
                <h2>1. Confidence Score Inputs</h2>
                <table>
                    <tr><th>Factor</th><th>Score</th><th>Weight</th><th>Signal</th><th>Risk</th></tr>
                    {% for c in confidence_inputs %}
                    <tr>
                        <td><b>{{ c.factor }}</b></td>
                        <td>{{ c.score }}%</td>
                        <td>{{ c.weight }}</td>
                        <td>{{ c.signal }}</td>
                        <td><span class="pill {{ c.risk }}">{{ c.risk }}</span></td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>2. Confidence Bands</h2>
                <table>
                    <tr><th>Score Band</th><th>Label</th><th>Meaning</th></tr>
                    {% for b in confidence_bands %}
                    <tr>
                        <td><b>{{ b.band }}</b></td>
                        <td><span class="pill {{ b.color }}">{{ b.label }}</span></td>
                        <td>{{ b.meaning }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>3. Confidence Recovery Recommendations</h2>
                <table>
                    <tr><th>Priority</th><th>Recommendation</th><th>Action</th><th>Expected Impact</th></tr>
                    {% for r in recommendations %}
                    <tr>
                        <td><span class="pill {{ r.priority }}">{{ r.priority }}</span></td>
                        <td><b>{{ r.title }}</b></td>
                        <td>{{ r.action }}</td>
                        <td>{{ r.impact }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>4. Executive Trust Questions</h2>
                <table>
                    <tr><th>Question</th><th>Answer</th><th>Basis</th></tr>
                    {% for e in executive_summary %}
                    <tr>
                        <td><b>{{ e.question }}</b></td>
                        <td>{{ e.answer }}</td>
                        <td>{{ e.basis }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="grid4">
                <div class="mini">
                    <h3>Pre-Deviation Use</h3>
                    <p>Highlights weak signals before they become deviations, audit findings, or unresolved operational failures.</p>
                </div>
                <div class="mini">
                    <h3>Audit Use</h3>
                    <p>Shows whether evidence, lineage, ownership, and review state are strong enough for audit reliance.</p>
                </div>
                <div class="mini">
                    <h3>Leadership Use</h3>
                    <p>Turns complex operational governance into one explainable confidence score.</p>
                </div>
                <div class="mini">
                    <h3>Platform Use</h3>
                    <p>Connects sterile compounding, shift overlap, operational lineage, and platform health into one trust layer.</p>
                </div>
            </section>
        </main>
    </body>
    </html>
    """

    return render_template_string(
        html,
        confidence_inputs=confidence_inputs,
        confidence_bands=confidence_bands,
        recommendations=recommendations,
        executive_summary=executive_summary,
        weighted_score=weighted_score
    )


'''

new_text = text[:idx] + route_code + text[idx:]
APP.write_text(new_text, encoding="utf-8")

required = [
    "GOVERNANCE_CONFIDENCE_ENGINE_ACTIVE",
    '@app.route("/governance-confidence-engine")',
    "Governance Confidence Engine",
    "Confidence Score Inputs",
    "Confidence Recovery Recommendations"
]

missing = [x for x in required if x not in new_text]
if missing:
    raise SystemExit("ERROR missing expected markers: " + ", ".join(missing))

print("SUCCESS: Governance Confidence Engine added safely at /governance-confidence-engine")
