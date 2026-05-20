from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "GOVERNANCE_RECOVERY_SIMULATOR_ACTIVE"

if MARKER in text:
    print("Governance Recovery Simulator already exists. No changes made.")
    raise SystemExit(0)

insert_before = '\nif __name__ == "__main__":'
idx = text.find(insert_before)

if idx == -1:
    raise SystemExit("ERROR: Could not find final if __name__ == \"__main__\" block.")

route_code = r'''

# ============================================================
# GOVERNANCE_RECOVERY_SIMULATOR_ACTIVE
# Safe additive route only.
# Adds /governance-recovery-simulator without modifying protected modules.
# Simulates recovery from governance drift to restored audit confidence.
# ============================================================

@app.route("/governance-recovery-simulator")
def governance_recovery_simulator():

    recovery_kpis = {
        "starting_confidence": "68%",
        "current_confidence": "89%",
        "target_confidence": "96%",
        "recoverable_points": "+28",
        "audit_readiness_before": "71%",
        "audit_readiness_after": "92%",
        "blast_radius_before": "HIGH",
        "blast_radius_after": "CONTROLLED"
    }

    recovery_steps = [
        {
            "step": "1",
            "intervention": "Attach missing audit trail export",
            "before": "Evidence gap blocks audit-ready closure",
            "after": "Evidence package becomes defensible",
            "confidence_gain": "+5",
            "audit_gain": "+6",
            "status": "P1"
        },
        {
            "step": "2",
            "intervention": "Capture incoming B-to-C owner acknowledgement",
            "before": "Ownership continuity unclear",
            "after": "Handoff chain becomes accountable",
            "confidence_gain": "+3",
            "audit_gain": "+2",
            "status": "P1"
        },
        {
            "step": "3",
            "intervention": "Complete supervisor review checkpoint",
            "before": "Closure lacks governance review",
            "after": "Closure becomes review-supported",
            "confidence_gain": "+4",
            "audit_gain": "+5",
            "status": "P2"
        },
        {
            "step": "4",
            "intervention": "Recalculate governance confidence",
            "before": "Mission status remains Watch",
            "after": "Mission status can move toward Governed",
            "confidence_gain": "+2",
            "audit_gain": "+1",
            "status": "P2"
        },
        {
            "step": "5",
            "intervention": "Export audit-ready package",
            "before": "Audit response would be fragmented",
            "after": "Inspection response becomes organized",
            "confidence_gain": "+1",
            "audit_gain": "+7",
            "status": "P3"
        },
    ]

    recovery_paths = [
        {
            "path": "Fast Recovery",
            "actions": "Close evidence + owner acknowledgement",
            "time": "Same shift",
            "confidence_result": "89% → 94%",
            "audit_result": "84% → 90%",
            "recommended": "YES"
        },
        {
            "path": "Full Recovery",
            "actions": "Evidence + owner + supervisor review + export pack",
            "time": "24 hours",
            "confidence_result": "89% → 96%",
            "audit_result": "84% → 92%",
            "recommended": "YES"
        },
        {
            "path": "Delayed Recovery",
            "actions": "Wait for weekly review",
            "time": "5-7 days",
            "confidence_result": "89% → 77%",
            "audit_result": "84% → 74%",
            "recommended": "NO"
        },
    ]

    executive_recovery_summary = [
        "The fastest trust recovery comes from closing evidence and ownership gaps first.",
        "Supervisor review adds closure defensibility and prevents weak signoff.",
        "Audit readiness improves fastest when evidence and export packaging are completed together.",
        "Delayed remediation allows governance drift to continue and increases deviation/CAPA exposure.",
        "Recovery simulation gives leadership a practical action plan, not only a risk report."
    ]

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>COBIT-Chain Governance Recovery Simulator</title>
        <style>
            body { margin:0; font-family:Arial, Helvetica, sans-serif; background:#f4f7fb; color:#0f172a; }
            .top { background:#0f172a; color:white; padding:14px 24px; display:flex; justify-content:space-between; align-items:center; gap:18px; flex-wrap:wrap; position:sticky; top:0; z-index:10; }
            .brand { font-weight:900; font-size:18px; }
            .brand span { color:#38bdf8; }
            .nav { display:flex; gap:10px; flex-wrap:wrap; }
            .nav a { color:#dbeafe; text-decoration:none; font-size:12px; font-weight:800; padding:8px 10px; border-radius:999px; background:rgba(255,255,255,.08); border:1px solid rgba(255,255,255,.12); }
            .nav a:hover { background:#2563eb; color:white; }
            .hero { background:linear-gradient(135deg,#111827,#047857); color:white; padding:38px 44px 82px; border-bottom-left-radius:28px; border-bottom-right-radius:28px; }
            .hero h1 { margin:0 0 10px; font-size:42px; }
            .hero p { color:#d1fae5; max-width:1120px; line-height:1.55; font-size:16px; }
            .badge { display:inline-block; background:rgba(255,255,255,.14); border:1px solid rgba(255,255,255,.25); padding:8px 13px; border-radius:999px; margin:10px 8px 0 0; font-size:12px; font-weight:800; }
            .wrap { max-width:1360px; margin:-48px auto 40px; padding:0 24px; }
            .grid4 { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:22px; }
            .kpi, .panel { background:white; border-radius:20px; padding:22px; box-shadow:0 12px 30px rgba(15,23,42,.09); margin-bottom:22px; }
            .kpi span { color:#64748b; font-weight:900; font-size:12px; text-transform:uppercase; letter-spacing:.07em; }
            .kpi strong { display:block; margin-top:9px; font-size:28px; }
            .recovery-flow { display:grid; grid-template-columns:repeat(5,1fr); gap:14px; }
            .step-card { background:#f8fafc; border:1px solid #bbf7d0; border-radius:18px; padding:16px; }
            .step-card h3 { margin:0 0 8px; color:#047857; }
            .step-card p { font-size:13px; color:#334155; line-height:1.45; }
            table { width:100%; border-collapse:collapse; }
            th { background:#dcfce7; color:#166534; text-align:left; padding:12px; font-size:13px; }
            td { border-bottom:1px solid #e5e7eb; padding:12px; font-size:13px; vertical-align:top; }
            .pill { display:inline-block; padding:6px 10px; border-radius:999px; font-weight:900; font-size:11px; }
            .P1, .NO { background:#fee2e2; color:#991b1b; }
            .P2 { background:#fef3c7; color:#92400e; }
            .P3, .YES { background:#dcfce7; color:#166534; }
            .note { background:#ecfdf5; border:1px solid #bbf7d0; color:#065f46; padding:16px; border-radius:16px; margin-bottom:22px; }
            ul { line-height:1.8; color:#334155; }
            @media(max-width:1200px){ .recovery-flow{grid-template-columns:repeat(2,1fr);} .grid4{grid-template-columns:repeat(2,1fr);} }
            @media(max-width:700px){ .recovery-flow,.grid4{grid-template-columns:1fr;} .hero h1{font-size:30px;} }
        </style>
    </head>
    <body>
        <div class="top">
            <div class="brand">COBIT-Chain™ <span>Recovery Simulator</span></div>
            <nav class="nav">
                <a href="/executive-mission-control">Mission Control</a>
                <a href="/predictive-governance-drift">Predictive Drift</a>
                <a href="/ai-governance-copilot">AI Copilot</a>
                <a href="/audit-simulation-engine">Audit</a>
                <a href="/governance-confidence-engine">Confidence</a>
            </nav>
        </div>

        <section class="hero">
            <h1>Governance Drift Recovery Simulator™</h1>
            <p>
                Simulates how targeted remediation restores governance confidence, audit readiness,
                ownership continuity, and blast-radius containment after drift is detected.
            </p>
            <span class="badge">RECOVERY MODELING</span>
            <span class="badge">CONFIDENCE RESTORATION</span>
            <span class="badge">AUDIT READINESS RECOVERY</span>
            <span class="badge">REMEDIATION SIMULATION</span>
        </section>

        <main class="wrap">
            <div class="note">
                <b>Executive meaning:</b> This does not only show risk. It shows the fastest path to restore trust.
            </div>

            <div class="grid4">
                <div class="kpi"><span>Starting Confidence</span><strong>{{ recovery_kpis.starting_confidence }}</strong></div>
                <div class="kpi"><span>Current Confidence</span><strong>{{ recovery_kpis.current_confidence }}</strong></div>
                <div class="kpi"><span>Target Confidence</span><strong>{{ recovery_kpis.target_confidence }}</strong></div>
                <div class="kpi"><span>Recoverable Points</span><strong>{{ recovery_kpis.recoverable_points }}</strong></div>
            </div>

            <div class="grid4">
                <div class="kpi"><span>Audit Before</span><strong>{{ recovery_kpis.audit_readiness_before }}</strong></div>
                <div class="kpi"><span>Audit After</span><strong>{{ recovery_kpis.audit_readiness_after }}</strong></div>
                <div class="kpi"><span>Blast Before</span><strong>{{ recovery_kpis.blast_radius_before }}</strong></div>
                <div class="kpi"><span>Blast After</span><strong>{{ recovery_kpis.blast_radius_after }}</strong></div>
            </div>

            <section class="panel">
                <h2>1. Recovery Flow</h2>
                <div class="recovery-flow">
                    {% for r in recovery_steps %}
                    <div class="step-card">
                        <span class="pill {{ r.status }}">{{ r.status }}</span>
                        <h3>{{ r.step }}. {{ r.intervention }}</h3>
                        <p><b>Before:</b> {{ r.before }}</p>
                        <p><b>After:</b> {{ r.after }}</p>
                        <p><b>Gain:</b> Confidence {{ r.confidence_gain }}, Audit {{ r.audit_gain }}</p>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="panel">
                <h2>2. Recovery Path Options</h2>
                <table>
                    <tr><th>Path</th><th>Actions</th><th>Time</th><th>Confidence Result</th><th>Audit Result</th><th>Recommended</th></tr>
                    {% for p in recovery_paths %}
                    <tr>
                        <td><b>{{ p.path }}</b></td>
                        <td>{{ p.actions }}</td>
                        <td>{{ p.time }}</td>
                        <td>{{ p.confidence_result }}</td>
                        <td>{{ p.audit_result }}</td>
                        <td><span class="pill {{ p.recommended }}">{{ p.recommended }}</span></td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>3. Executive Recovery Summary</h2>
                <ul>
                    {% for s in executive_recovery_summary %}
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
        recovery_kpis=recovery_kpis,
        recovery_steps=recovery_steps,
        recovery_paths=recovery_paths,
        executive_recovery_summary=executive_recovery_summary
    )


'''

new_text = text[:idx] + route_code + text[idx:]
APP.write_text(new_text, encoding="utf-8")

required = [
    "GOVERNANCE_RECOVERY_SIMULATOR_ACTIVE",
    '@app.route("/governance-recovery-simulator")',
    "Governance Drift Recovery Simulator",
    "Recovery Flow",
    "Recovery Path Options"
]

missing = [x for x in required if x not in new_text]
if missing:
    raise SystemExit("ERROR missing expected markers: " + ", ".join(missing))

print("SUCCESS: Governance Recovery Simulator added safely at /governance-recovery-simulator")
