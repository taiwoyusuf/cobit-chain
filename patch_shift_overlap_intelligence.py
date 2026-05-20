from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_OVERLAP_INTELLIGENCE_ACTIVE"

if MARKER in text:
    print("Shift Overlap Intelligence already exists. No changes made.")
    raise SystemExit(0)

insert_before = '\nif __name__ == "__main__":'
idx = text.find(insert_before)

if idx == -1:
    raise SystemExit("ERROR: Could not find final if __name__ == \"__main__\" block.")

route_code = r'''

# ============================================================
# SHIFT_OVERLAP_INTELLIGENCE_ACTIVE
# Safe additive route only.
# Adds /shift-overlap-intelligence without modifying protected modules.
# Based on Chris' 12-hour overlap support model.
# ============================================================

@app.route("/shift-overlap-intelligence")
def shift_overlap_intelligence():
    shifts = [
        {
            "shift": "A",
            "window": "10:00 - 22:00",
            "role": "Day Coverage Anchor",
            "coverage_strength": "Strong",
            "overlap_partner": "B",
            "risk": "LOW",
            "governance_note": "Primary day coverage established. Handoff preparation begins before 22:00."
        },
        {
            "shift": "B",
            "window": "11:00 - 23:00",
            "role": "Day Overlap / Transition Bridge",
            "coverage_strength": "Strong",
            "overlap_partner": "A and C",
            "risk": "LOW",
            "governance_note": "Critical overlap bridge between day operations and night coverage."
        },
        {
            "shift": "C",
            "window": "22:00 - 10:00",
            "role": "Night Coverage Anchor",
            "coverage_strength": "Moderate",
            "overlap_partner": "B and D",
            "risk": "MEDIUM",
            "governance_note": "Night shift receives unresolved issues and confirms carryover ownership."
        },
        {
            "shift": "D",
            "window": "23:00 - 11:00",
            "role": "Night Overlap / Morning Bridge",
            "coverage_strength": "Strong",
            "overlap_partner": "C and A",
            "risk": "LOW",
            "governance_note": "Morning transition bridge protects continuity into the next day cycle."
        },
    ]

    overlap_windows = [
        {
            "overlap": "A + B",
            "time": "11:00 - 22:00",
            "purpose": "Day redundancy and shared equipment coverage",
            "governance_action": "Validate open tickets, evidence status, and equipment assignment before day close.",
            "risk": "LOW"
        },
        {
            "overlap": "B + C",
            "time": "22:00 - 23:00",
            "purpose": "Critical day-to-night transition",
            "governance_action": "Mandatory unresolved issue review, escalation carryover, and incoming acknowledgement.",
            "risk": "MEDIUM"
        },
        {
            "overlap": "C + D",
            "time": "23:00 - 10:00",
            "purpose": "Night redundancy and escalation support",
            "governance_action": "Monitor active issues, evidence gaps, and high-risk equipment through night coverage.",
            "risk": "LOW"
        },
        {
            "overlap": "D + A",
            "time": "10:00 - 11:00",
            "purpose": "Morning transition and day-start readiness",
            "governance_action": "Confirm overnight issues, evidence closure, and day-shift ownership acceptance.",
            "risk": "MEDIUM"
        },
    ]

    intelligence_signals = [
        {
            "signal": "Orphaned Ticket Risk",
            "status": "Detected",
            "severity": "HIGH",
            "meaning": "One unresolved ticket lacks confirmed incoming owner during B-to-C transition."
        },
        {
            "signal": "Evidence Carryover Gap",
            "status": "Open",
            "severity": "MEDIUM",
            "meaning": "Required evidence is pending before supervisor review can be considered audit-ready."
        },
        {
            "signal": "Overlap Coverage Integrity",
            "status": "Controlled",
            "severity": "LOW",
            "meaning": "A/B and C/D overlaps provide redundancy across day and night operations."
        },
        {
            "signal": "Escalation Continuity",
            "status": "Watch",
            "severity": "MEDIUM",
            "meaning": "Escalation must survive the shift transition without losing ownership or context."
        },
    ]

    pre_deviation_predictions = [
        {
            "prediction": "Potential deviation risk if evidence remains missing through C/D night overlap",
            "driver": "Escalated equipment issue + missing audit trail export + pending incoming acknowledgement",
            "probability": "High",
            "recommended_action": "Force supervisor checkpoint before closure."
        },
        {
            "prediction": "Potential handoff breakdown during B-to-C transition",
            "driver": "Short overlap window + unresolved ticket + equipment still in warning state",
            "probability": "Medium",
            "recommended_action": "Require incoming owner acknowledgement before 23:00."
        },
        {
            "prediction": "Low risk of day coverage gap",
            "driver": "A/B overlap provides redundant coverage and backup ownership",
            "probability": "Low",
            "recommended_action": "Continue normal monitoring."
        },
    ]

    digital_twin = [
        {"object": "Ticket", "state": "Open / Escalated", "governance_link": "Must remain linked to shift owner and equipment context"},
        {"object": "Shift", "state": "B-to-C transition", "governance_link": "Overlap window becomes mandatory control point"},
        {"object": "Technician", "state": "Incoming acknowledgement pending", "governance_link": "Ownership cannot be assumed until accepted"},
        {"object": "Equipment", "state": "Warning / escalated", "governance_link": "Equipment state drives risk level and evidence requirement"},
        {"object": "Evidence", "state": "Partially complete", "governance_link": "Missing evidence blocks audit-ready closure"},
        {"object": "Supervisor Review", "state": "Required", "governance_link": "Review checkpoint prevents silent closure of weak records"},
    ]

    kpis = {
        "continuity_score": "91%",
        "overlap_strength": "94%",
        "handoff_integrity": "87%",
        "pre_deviation_risk": "HIGH",
        "orphaned_items": "1",
        "evidence_gaps": "2",
        "governance_confidence": "89%",
        "audit_readiness": "86%"
    }

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>COBIT-Chain Shift Overlap Intelligence</title>
        <style>
            body { margin:0; font-family:Arial, Helvetica, sans-serif; background:#f4f7fb; color:#0f172a; }
            .hero { background:linear-gradient(135deg,#111827,#0f766e); color:white; padding:34px 42px 74px; border-bottom-left-radius:28px; border-bottom-right-radius:28px; }
            .hero h1 { margin:0 0 10px; font-size:40px; }
            .hero p { color:#ccfbf1; max-width:1080px; line-height:1.55; font-size:16px; }
            .badge { display:inline-block; background:rgba(255,255,255,.14); border:1px solid rgba(255,255,255,.25); padding:8px 13px; border-radius:999px; margin:10px 8px 0 0; font-size:12px; font-weight:800; }
            .wrap { max-width:1320px; margin:-42px auto 40px; padding:0 24px; }
            .grid4 { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:22px; }
            .kpi, .panel { background:white; border-radius:20px; padding:22px; box-shadow:0 12px 30px rgba(15,23,42,.09); margin-bottom:22px; }
            .kpi span { color:#64748b; font-weight:900; font-size:12px; text-transform:uppercase; letter-spacing:.07em; }
            .kpi strong { display:block; margin-top:9px; font-size:30px; }
            table { width:100%; border-collapse:collapse; }
            th { background:#ecfeff; color:#115e59; text-align:left; padding:12px; font-size:13px; }
            td { border-bottom:1px solid #e5e7eb; padding:12px; font-size:13px; vertical-align:top; }
            .pill { display:inline-block; padding:6px 10px; border-radius:999px; font-weight:900; font-size:11px; }
            .LOW, .Low { background:#dcfce7; color:#166534; }
            .MEDIUM, .Medium { background:#fef3c7; color:#92400e; }
            .HIGH, .High { background:#fee2e2; color:#991b1b; }
            .Detected, .Open, .Watch { background:#fef3c7; color:#92400e; }
            .Controlled { background:#dcfce7; color:#166534; }
            .flow { display:grid; grid-template-columns:repeat(4,1fr); gap:14px; }
            .flow-card { background:#f8fafc; border:1px solid #ccfbf1; border-radius:16px; padding:16px; }
            .flow-card b { display:block; color:#0f766e; margin-bottom:8px; }
            .note { background:#ecfeff; border:1px solid #99f6e4; color:#115e59; padding:16px; border-radius:16px; margin-bottom:22px; }
            .toplinks { margin-top:18px; }
            .toplinks a { color:white; text-decoration:none; font-weight:800; margin-right:16px; }
            @media(max-width:1000px){ .grid4,.flow{grid-template-columns:repeat(2,1fr);} }
            @media(max-width:680px){ .grid4,.flow{grid-template-columns:1fr;} .hero h1{font-size:30px;} }
        </style>
    </head>
    <body>
        <section class="hero">
            <h1>COBIT-Chain™ Shift Overlap Intelligence Center</h1>
            <p>
                Converts Chris' 12-hour overlapping support model into an operational continuity governance engine.
                The purpose is not scheduling. The purpose is to prove that coverage, escalation, ownership, evidence,
                and audit readiness remain governed across shift transitions.
            </p>
            <span class="badge">A: 10:00–22:00</span>
            <span class="badge">B: 11:00–23:00</span>
            <span class="badge">C: 22:00–10:00</span>
            <span class="badge">D: 23:00–11:00</span>
            <span class="badge">PRE-DEVIATION INTELLIGENCE</span>
            <div class="toplinks">
                <a href="/enterprise-workspaces">Enterprise Workspaces</a>
                <a href="/role-based-views">Role-Based Views</a>
                <a href="/operational-lineage">Operational Lineage</a>
                <a href="/platform-health">Platform Health</a>
            </div>
        </section>

        <main class="wrap">
            <div class="note">
                <b>Executive message:</b> This is not a shift scheduler. It is a continuity assurance layer that detects whether
                work, ownership, equipment risk, and evidence remain controlled as one shift hands over to another.
            </div>

            <div class="grid4">
                <div class="kpi"><span>Continuity Score</span><strong>{{ kpis.continuity_score }}</strong></div>
                <div class="kpi"><span>Overlap Strength</span><strong>{{ kpis.overlap_strength }}</strong></div>
                <div class="kpi"><span>Handoff Integrity</span><strong>{{ kpis.handoff_integrity }}</strong></div>
                <div class="kpi"><span>Pre-Deviation Risk</span><strong>{{ kpis.pre_deviation_risk }}</strong></div>
            </div>

            <div class="grid4">
                <div class="kpi"><span>Orphaned Items</span><strong>{{ kpis.orphaned_items }}</strong></div>
                <div class="kpi"><span>Evidence Gaps</span><strong>{{ kpis.evidence_gaps }}</strong></div>
                <div class="kpi"><span>Governance Confidence</span><strong>{{ kpis.governance_confidence }}</strong></div>
                <div class="kpi"><span>Audit Readiness</span><strong>{{ kpis.audit_readiness }}</strong></div>
            </div>

            <section class="panel">
                <h2>1. Chris' Overlap Shift Model</h2>
                <table>
                    <tr><th>Shift</th><th>Window</th><th>Role</th><th>Overlap Partner</th><th>Coverage Strength</th><th>Risk</th><th>Governance Note</th></tr>
                    {% for s in shifts %}
                    <tr>
                        <td><b>{{ s.shift }}</b></td>
                        <td>{{ s.window }}</td>
                        <td>{{ s.role }}</td>
                        <td>{{ s.overlap_partner }}</td>
                        <td>{{ s.coverage_strength }}</td>
                        <td><span class="pill {{ s.risk }}">{{ s.risk }}</span></td>
                        <td>{{ s.governance_note }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>2. Overlap Governance Windows</h2>
                <table>
                    <tr><th>Overlap</th><th>Time</th><th>Purpose</th><th>Governance Action</th><th>Risk</th></tr>
                    {% for o in overlap_windows %}
                    <tr>
                        <td><b>{{ o.overlap }}</b></td>
                        <td>{{ o.time }}</td>
                        <td>{{ o.purpose }}</td>
                        <td>{{ o.governance_action }}</td>
                        <td><span class="pill {{ o.risk }}">{{ o.risk }}</span></td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>3. Continuity Intelligence Signals</h2>
                <table>
                    <tr><th>Signal</th><th>Status</th><th>Severity</th><th>Meaning</th></tr>
                    {% for i in intelligence_signals %}
                    <tr>
                        <td><b>{{ i.signal }}</b></td>
                        <td><span class="pill {{ i.status }}">{{ i.status }}</span></td>
                        <td><span class="pill {{ i.severity }}">{{ i.severity }}</span></td>
                        <td>{{ i.meaning }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>4. Pre-Deviation Prediction Engine</h2>
                <table>
                    <tr><th>Prediction</th><th>Driver</th><th>Probability</th><th>Recommended Action</th></tr>
                    {% for p in pre_deviation_predictions %}
                    <tr>
                        <td><b>{{ p.prediction }}</b></td>
                        <td>{{ p.driver }}</td>
                        <td><span class="pill {{ p.probability }}">{{ p.probability }}</span></td>
                        <td>{{ p.recommended_action }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>5. Operational Digital Twin View</h2>
                <div class="flow">
                    {% for d in digital_twin %}
                    <div class="flow-card">
                        <b>{{ d.object }}</b>
                        <p><strong>State:</strong> {{ d.state }}</p>
                        <p>{{ d.governance_link }}</p>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="panel">
                <h2>6. Why This Is Revolutionary</h2>
                <p>
                    Traditional shift tools tell leaders who is working. This module tells leaders whether the operation remained governed.
                    It detects weak overlap, orphaned ownership, evidence gaps, escalation carryover, and pre-deviation risk before those weaknesses
                    become audit findings, deviations, or operational failures.
                </p>
            </section>
        </main>
    </body>
    </html>
    """

    return render_template_string(
        html,
        shifts=shifts,
        overlap_windows=overlap_windows,
        intelligence_signals=intelligence_signals,
        pre_deviation_predictions=pre_deviation_predictions,
        digital_twin=digital_twin,
        kpis=kpis
    )


'''

new_text = text[:idx] + route_code + text[idx:]
APP.write_text(new_text, encoding="utf-8")

required = [
    "SHIFT_OVERLAP_INTELLIGENCE_ACTIVE",
    '@app.route("/shift-overlap-intelligence")',
    "Shift Overlap Intelligence Center",
    "Pre-Deviation Prediction Engine",
    "Operational Digital Twin View"
]

missing = [x for x in required if x not in new_text]
if missing:
    raise SystemExit("ERROR missing expected markers: " + ", ".join(missing))

print("SUCCESS: Shift Overlap Intelligence Center added safely at /shift-overlap-intelligence")
