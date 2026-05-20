from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "GOVERNANCE_BLAST_RADIUS_ENGINE_ACTIVE"

if MARKER in text:
    print("Governance Blast Radius Engine already exists. No changes made.")
    raise SystemExit(0)

insert_before = '\nif __name__ == "__main__":'
idx = text.find(insert_before)

if idx == -1:
    raise SystemExit("ERROR: Could not find final if __name__ == \"__main__\" block.")

route_code = r'''

# ============================================================
# GOVERNANCE_BLAST_RADIUS_ENGINE_ACTIVE
# Safe additive route only.
# Adds /governance-blast-radius without modifying protected modules.
# Shows downstream governance impact when one control weakness appears.
# ============================================================

@app.route("/governance-blast-radius")
def governance_blast_radius():
    scenario = {
        "trigger": "Missing B-to-C handoff acknowledgement",
        "source": "Shift Overlap Intelligence",
        "initial_risk": "MEDIUM",
        "current_blast_radius": "HIGH",
        "confidence_impact": "-8 points",
        "audit_readiness_impact": "-6 points",
        "recommended_response": "Require incoming owner acknowledgement, attach missing evidence, and force supervisor checkpoint before closure."
    }

    blast_chain = [
        {
            "level": "1",
            "domain": "Shift Continuity",
            "impact": "Incoming owner not confirmed during B-to-C transition.",
            "severity": "MEDIUM",
            "control_response": "Force acknowledgement before shift transition closes."
        },
        {
            "level": "2",
            "domain": "Equipment Ownership",
            "impact": "Equipment issue may become orphaned if no incoming owner accepts it.",
            "severity": "HIGH",
            "control_response": "Assign named primary and backup owner."
        },
        {
            "level": "3",
            "domain": "Evidence Integrity",
            "impact": "Required evidence may not be attached before closure.",
            "severity": "HIGH",
            "control_response": "Block audit-ready status until evidence is attached."
        },
        {
            "level": "4",
            "domain": "Supervisor Review",
            "impact": "Supervisor may approve incomplete operational record.",
            "severity": "MEDIUM",
            "control_response": "Trigger mandatory review checkpoint."
        },
        {
            "level": "5",
            "domain": "Audit Readiness",
            "impact": "Record becomes weak during inspection or internal audit.",
            "severity": "HIGH",
            "control_response": "Generate audit gap warning and remediation note."
        },
        {
            "level": "6",
            "domain": "Deviation / CAPA Exposure",
            "impact": "If repeated, weak handoff pattern may become deviation or CAPA signal.",
            "severity": "MEDIUM",
            "control_response": "Track recurrence and route to governance review."
        },
    ]

    impacted_assets = [
        {"asset": "Shift B to C Transition", "type": "Coverage Window", "impact": "Handoff integrity reduced", "severity": "MEDIUM"},
        {"asset": "Environmental Monitoring Device", "type": "Equipment", "impact": "Ownership risk increased", "severity": "HIGH"},
        {"asset": "Audit Trail Export", "type": "Evidence", "impact": "Audit package incomplete", "severity": "HIGH"},
        {"asset": "Supervisor Review Queue", "type": "Review Control", "impact": "Review required before closure", "severity": "MEDIUM"},
        {"asset": "Governance Confidence Score", "type": "Executive KPI", "impact": "Confidence reduced by 8 points", "severity": "MEDIUM"},
        {"asset": "Audit Readiness Score", "type": "Audit KPI", "impact": "Readiness reduced by 6 points", "severity": "HIGH"},
    ]

    containment_actions = [
        {"priority": "P1", "action": "Lock closure until incoming owner acknowledgement is captured", "owner": "Shift Supervisor", "expected_result": "Prevents orphaned ownership"},
        {"priority": "P1", "action": "Attach missing audit trail evidence", "owner": "Technician / Equipment Support", "expected_result": "Restores evidence integrity"},
        {"priority": "P2", "action": "Trigger supervisor review checkpoint", "owner": "Supervisor", "expected_result": "Prevents silent approval of weak record"},
        {"priority": "P2", "action": "Update governance confidence score after remediation", "owner": "Platform / Governance", "expected_result": "Shows recovery path to leadership"},
        {"priority": "P3", "action": "Monitor recurrence across overlap windows", "owner": "Operational Excellence", "expected_result": "Detects systemic shift-transition weakness"},
    ]

    heatmap = [
        {"domain": "Shift", "before": "LOW", "after": "MEDIUM", "delta": "+1"},
        {"domain": "Equipment", "before": "MEDIUM", "after": "HIGH", "delta": "+1"},
        {"domain": "Evidence", "before": "MEDIUM", "after": "HIGH", "delta": "+1"},
        {"domain": "Review", "before": "LOW", "after": "MEDIUM", "delta": "+1"},
        {"domain": "Audit", "before": "MEDIUM", "after": "HIGH", "delta": "+1"},
        {"domain": "CAPA Exposure", "before": "LOW", "after": "MEDIUM", "delta": "+1"},
    ]

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>COBIT-Chain Governance Blast Radius Engine</title>
        <style>
            body { margin:0; font-family:Arial, Helvetica, sans-serif; background:#f4f7fb; color:#0f172a; }
            .hero { background:linear-gradient(135deg,#111827,#b91c1c); color:white; padding:36px 44px 78px; border-bottom-left-radius:28px; border-bottom-right-radius:28px; }
            .hero h1 { margin:0 0 10px; font-size:40px; }
            .hero p { color:#fee2e2; max-width:1080px; line-height:1.55; font-size:16px; }
            .badge { display:inline-block; background:rgba(255,255,255,.14); border:1px solid rgba(255,255,255,.25); padding:8px 13px; border-radius:999px; margin:10px 8px 0 0; font-size:12px; font-weight:800; }
            .wrap { max-width:1320px; margin:-46px auto 40px; padding:0 24px; }
            .scenario { background:white; border-radius:24px; padding:28px; box-shadow:0 14px 34px rgba(15,23,42,.12); margin-bottom:24px; }
            .scenario-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-top:18px; }
            .metric { background:#f8fafc; border:1px solid #e2e8f0; border-radius:16px; padding:16px; }
            .metric span { color:#64748b; font-size:12px; font-weight:900; text-transform:uppercase; }
            .metric strong { display:block; font-size:24px; margin-top:8px; }
            .panel { background:white; border-radius:20px; padding:22px; box-shadow:0 12px 30px rgba(15,23,42,.09); margin-bottom:22px; }
            table { width:100%; border-collapse:collapse; }
            th { background:#fee2e2; color:#991b1b; text-align:left; padding:12px; font-size:13px; }
            td { border-bottom:1px solid #e5e7eb; padding:12px; font-size:13px; vertical-align:top; }
            .pill { display:inline-block; padding:6px 10px; border-radius:999px; font-weight:900; font-size:11px; }
            .LOW { background:#dcfce7; color:#166534; }
            .MEDIUM { background:#fef3c7; color:#92400e; }
            .HIGH { background:#fee2e2; color:#991b1b; }
            .P1 { background:#fee2e2; color:#991b1b; }
            .P2 { background:#fef3c7; color:#92400e; }
            .P3 { background:#e0e7ff; color:#3730a3; }
            .chain { display:grid; grid-template-columns:repeat(6,1fr); gap:12px; margin-top:16px; }
            .node { background:#fff7ed; border:1px solid #fed7aa; border-radius:16px; padding:15px; min-height:170px; }
            .node b { color:#9a3412; display:block; margin-bottom:8px; }
            .node small { color:#64748b; font-weight:800; }
            .toplinks { margin-top:18px; }
            .toplinks a { color:white; text-decoration:none; font-weight:800; margin-right:16px; }
            .note { background:#fff7ed; border:1px solid #fed7aa; color:#9a3412; padding:16px; border-radius:16px; margin-bottom:22px; }
            @media(max-width:1100px){ .chain{grid-template-columns:repeat(3,1fr);} .scenario-grid{grid-template-columns:repeat(2,1fr);} }
            @media(max-width:700px){ .chain,.scenario-grid{grid-template-columns:1fr;} .hero h1{font-size:30px;} }
        </style>
    </head>
    <body>
        <section class="hero">
            <h1>COBIT-Chain™ Governance Blast Radius Engine</h1>
            <p>
                Shows how one governance weakness spreads across shift continuity, equipment ownership,
                evidence integrity, supervisor review, audit readiness, and deviation/CAPA exposure.
            </p>
            <span class="badge">IMPACT ANALYSIS</span>
            <span class="badge">CONTROL RESPONSE</span>
            <span class="badge">AUDIT EXPOSURE</span>
            <span class="badge">CAPA SIGNAL</span>
            <div class="toplinks">
                <a href="/enterprise-workspaces">Enterprise Workspaces</a>
                <a href="/shift-overlap-intelligence">Shift Overlap Intelligence</a>
                <a href="/governance-confidence-engine">Governance Confidence</a>
                <a href="/operational-lineage">Operational Lineage</a>
            </div>
        </section>

        <main class="wrap">
            <section class="scenario">
                <h2>Active Blast Radius Scenario</h2>
                <p><b>Trigger:</b> {{ scenario.trigger }}</p>
                <p><b>Recommended Response:</b> {{ scenario.recommended_response }}</p>
                <div class="scenario-grid">
                    <div class="metric"><span>Source</span><strong>{{ scenario.source }}</strong></div>
                    <div class="metric"><span>Initial Risk</span><strong>{{ scenario.initial_risk }}</strong></div>
                    <div class="metric"><span>Current Radius</span><strong>{{ scenario.current_blast_radius }}</strong></div>
                    <div class="metric"><span>Confidence Impact</span><strong>{{ scenario.confidence_impact }}</strong></div>
                </div>
            </section>

            <div class="note">
                <b>Executive meaning:</b> A small missing handoff is not just an admin issue. It can weaken ownership,
                evidence integrity, audit readiness, and deviation defensibility if not contained.
            </div>

            <section class="panel">
                <h2>1. Visual Blast Radius Chain</h2>
                <div class="chain">
                    {% for b in blast_chain %}
                    <div class="node">
                        <small>Level {{ b.level }}</small>
                        <b>{{ b.domain }}</b>
                        <p>{{ b.impact }}</p>
                        <span class="pill {{ b.severity }}">{{ b.severity }}</span>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="panel">
                <h2>2. Blast Radius Detail</h2>
                <table>
                    <tr><th>Level</th><th>Domain</th><th>Impact</th><th>Severity</th><th>Control Response</th></tr>
                    {% for b in blast_chain %}
                    <tr>
                        <td><b>{{ b.level }}</b></td>
                        <td><b>{{ b.domain }}</b></td>
                        <td>{{ b.impact }}</td>
                        <td><span class="pill {{ b.severity }}">{{ b.severity }}</span></td>
                        <td>{{ b.control_response }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>3. Impacted Assets</h2>
                <table>
                    <tr><th>Asset</th><th>Type</th><th>Impact</th><th>Severity</th></tr>
                    {% for a in impacted_assets %}
                    <tr>
                        <td><b>{{ a.asset }}</b></td>
                        <td>{{ a.type }}</td>
                        <td>{{ a.impact }}</td>
                        <td><span class="pill {{ a.severity }}">{{ a.severity }}</span></td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>4. Containment Actions</h2>
                <table>
                    <tr><th>Priority</th><th>Action</th><th>Owner</th><th>Expected Result</th></tr>
                    {% for c in containment_actions %}
                    <tr>
                        <td><span class="pill {{ c.priority }}">{{ c.priority }}</span></td>
                        <td><b>{{ c.action }}</b></td>
                        <td>{{ c.owner }}</td>
                        <td>{{ c.expected_result }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>5. Risk Heatmap Delta</h2>
                <table>
                    <tr><th>Domain</th><th>Before</th><th>After</th><th>Delta</th></tr>
                    {% for h in heatmap %}
                    <tr>
                        <td><b>{{ h.domain }}</b></td>
                        <td><span class="pill {{ h.before }}">{{ h.before }}</span></td>
                        <td><span class="pill {{ h.after }}">{{ h.after }}</span></td>
                        <td>{{ h.delta }}</td>
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
        scenario=scenario,
        blast_chain=blast_chain,
        impacted_assets=impacted_assets,
        containment_actions=containment_actions,
        heatmap=heatmap
    )


'''

new_text = text[:idx] + route_code + text[idx:]
APP.write_text(new_text, encoding="utf-8")

required = [
    "GOVERNANCE_BLAST_RADIUS_ENGINE_ACTIVE",
    '@app.route("/governance-blast-radius")',
    "Governance Blast Radius Engine",
    "Visual Blast Radius Chain",
    "Containment Actions"
]

missing = [x for x in required if x not in new_text]
if missing:
    raise SystemExit("ERROR missing expected markers: " + ", ".join(missing))

print("SUCCESS: Governance Blast Radius Engine added safely at /governance-blast-radius")
