from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "EXECUTIVE_DEMO_FLOW_ACTIVE"

if MARKER in text:
    print("Executive Demo Flow already exists. No changes made.")
    raise SystemExit(0)

insert_before = '\nif __name__ == "__main__":'
idx = text.find(insert_before)

if idx == -1:
    raise SystemExit("ERROR: Could not find final if __name__ == \"__main__\" block.")

route_code = r'''

# ============================================================
# EXECUTIVE_DEMO_FLOW_ACTIVE
# Safe additive route only.
# Adds /executive-demo-flow without modifying protected modules.
# Provides a guided leadership demo path.
# ============================================================

@app.route("/executive-demo-flow")
def executive_demo_flow():
    demo_steps = [
        {
            "step": "1",
            "title": "Start with the Enterprise Workspace Hub",
            "route": "/enterprise-workspaces",
            "talk_track": "This is no longer a single-purpose app. It is becoming a modular governance platform where each operational domain has its own controlled workspace.",
            "what_to_show": "Show the workspace categories and explain that protected modules remain separate but connected."
        },
        {
            "step": "2",
            "title": "Show Role-Based Enterprise Views",
            "route": "/role-based-views",
            "talk_track": "Different stakeholders do not need the same screen. Executives need risk and readiness; supervisors need handoff and evidence; technicians need clarity on what to do; QA needs audit defensibility.",
            "what_to_show": "Show Executive, Supervisor, Technician, QA/Audit, and Platform Admin views."
        },
        {
            "step": "3",
            "title": "Explain Chris' Shift Overlap Model",
            "route": "/shift-overlap-intelligence",
            "talk_track": "The shift model is not just about who is working. The overlap windows become governance control points where ownership, evidence, escalation, and continuity are verified.",
            "what_to_show": "Show A/B, B/C, C/D, and D/A overlap windows plus pre-deviation signals."
        },
        {
            "step": "4",
            "title": "Connect ServiceNow to Governance Trust",
            "route": "/servicenow-governance-overlay",
            "talk_track": "ServiceNow tracks workflow state. COBIT-Chain adds the governance trust state: whether the work is owned, evidenced, reviewed, and audit-defensible.",
            "what_to_show": "Show ticket trust score, evidence gaps, orphaned ownership, and audit exposure."
        },
        {
            "step": "5",
            "title": "Show Governance Confidence Engine",
            "route": "/governance-confidence-engine",
            "talk_track": "A ticket being closed does not automatically mean the record is trustworthy. The confidence engine converts governance signals into an executive trust score.",
            "what_to_show": "Show confidence score, score inputs, confidence bands, and recovery recommendations."
        },
        {
            "step": "6",
            "title": "Show Blast Radius",
            "route": "/governance-blast-radius",
            "talk_track": "One weak handoff can impact equipment ownership, evidence integrity, supervisor review, audit readiness, and CAPA/deviation exposure.",
            "what_to_show": "Show visual blast chain, impacted assets, and containment actions."
        },
        {
            "step": "7",
            "title": "Run Audit Simulation",
            "route": "/audit-simulation-engine",
            "talk_track": "Instead of waiting for an audit finding, the platform simulates what an auditor may ask and what would fail first if audited today.",
            "what_to_show": "Show simulated auditor questions, likely findings, remediation plan, and audit pack readiness."
        },
        {
            "step": "8",
            "title": "Close with Governance Digital Twin",
            "route": "/governance-digital-twin",
            "talk_track": "This is the long-term direction: a connected operational trust graph across ticket, shift, technician, equipment, evidence, review, confidence, and audit state.",
            "what_to_show": "Show connected nodes, governance relationships, scenario questions, and recovery path."
        },
    ]

    executive_messages = [
        "This is not replacing ServiceNow, Blue Mountain, Veeva, or myAccess.",
        "It is a governance assurance layer above operational systems.",
        "The platform shows whether work stayed governed, not just whether work happened.",
        "It supports pre-deviation intelligence, audit readiness, operational continuity, and leadership confidence.",
        "The strongest value is converting scattered operational activity into defensible governance intelligence."
    ]

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>COBIT-Chain Executive Demo Flow</title>
        <style>
            body { margin:0; font-family:Arial, Helvetica, sans-serif; background:#f4f7fb; color:#0f172a; }
            .hero { background:linear-gradient(135deg,#0f172a,#4338ca); color:white; padding:38px 44px 82px; border-bottom-left-radius:28px; border-bottom-right-radius:28px; }
            .hero h1 { margin:0 0 10px; font-size:42px; }
            .hero p { color:#e0e7ff; max-width:1100px; line-height:1.55; font-size:16px; }
            .badge { display:inline-block; background:rgba(255,255,255,.14); border:1px solid rgba(255,255,255,.25); padding:8px 13px; border-radius:999px; margin:10px 8px 0 0; font-size:12px; font-weight:800; }
            .wrap { max-width:1320px; margin:-46px auto 40px; padding:0 24px; }
            .panel { background:white; border-radius:22px; padding:24px; box-shadow:0 12px 30px rgba(15,23,42,.09); margin-bottom:24px; }
            .step-card { display:grid; grid-template-columns:80px 1.2fr 1.8fr 1fr; gap:18px; align-items:start; border-bottom:1px solid #e5e7eb; padding:20px 0; }
            .step-card:last-child { border-bottom:none; }
            .num { width:54px; height:54px; border-radius:18px; background:#4338ca; color:white; display:flex; align-items:center; justify-content:center; font-size:24px; font-weight:900; }
            h2 { margin:0 0 10px; }
            h3 { margin:0 0 8px; color:#312e81; }
            p { line-height:1.55; color:#334155; }
            .open { display:inline-block; text-decoration:none; background:#0f172a; color:white; padding:10px 14px; border-radius:11px; font-weight:800; }
            .note { background:#eef2ff; border:1px solid #c7d2fe; color:#3730a3; padding:16px; border-radius:16px; margin-bottom:22px; }
            ul { line-height:1.8; }
            .toplinks { margin-top:18px; }
            .toplinks a { color:white; text-decoration:none; font-weight:800; margin-right:16px; }
            @media(max-width:1000px){ .step-card{grid-template-columns:1fr;} }
        </style>
    </head>
    <body>
        <section class="hero">
            <h1>COBIT-Chain™ Executive Demo Flow</h1>
            <p>
                A guided leadership path for presenting the platform clearly: workspace model, role views,
                shift overlap intelligence, ServiceNow governance overlay, confidence scoring, blast radius,
                audit simulation, and governance digital twin.
            </p>
            <span class="badge">CHRIS DEMO PATH</span>
            <span class="badge">LEADERSHIP STORY</span>
            <span class="badge">NO CONFIDENTIAL DATA REQUIRED</span>
            <span class="badge">ENTERPRISE POSITIONING</span>
            <div class="toplinks">
                <a href="/enterprise-workspaces">Enterprise Workspaces</a>
                <a href="/role-based-views">Role-Based Views</a>
                <a href="/platform-health">Platform Health</a>
            </div>
        </section>

        <main class="wrap">
            <div class="note">
                <b>Opening line:</b> “This evolved from a shift-support idea into a modular governance assurance platform.
                ServiceNow tracks workflow state; COBIT-Chain evaluates governance trust state.”
            </div>

            <section class="panel">
                <h2>Recommended Demo Sequence</h2>
                {% for s in demo_steps %}
                <div class="step-card">
                    <div class="num">{{ s.step }}</div>
                    <div>
                        <h3>{{ s.title }}</h3>
                        <a class="open" href="{{ s.route }}">Open</a>
                    </div>
                    <div>
                        <b>Talk Track</b>
                        <p>{{ s.talk_track }}</p>
                    </div>
                    <div>
                        <b>What To Show</b>
                        <p>{{ s.what_to_show }}</p>
                    </div>
                </div>
                {% endfor %}
            </section>

            <section class="panel">
                <h2>Core Executive Messages</h2>
                <ul>
                    {% for m in executive_messages %}
                    <li>{{ m }}</li>
                    {% endfor %}
                </ul>
            </section>
        </main>
    </body>
    </html>
    """

    return render_template_string(
        html,
        demo_steps=demo_steps,
        executive_messages=executive_messages
    )


'''

new_text = text[:idx] + route_code + text[idx:]
APP.write_text(new_text, encoding="utf-8")

required = [
    "EXECUTIVE_DEMO_FLOW_ACTIVE",
    '@app.route("/executive-demo-flow")',
    "Executive Demo Flow",
    "Recommended Demo Sequence",
    "Core Executive Messages"
]

missing = [x for x in required if x not in new_text]
if missing:
    raise SystemExit("ERROR missing expected markers: " + ", ".join(missing))

print("SUCCESS: Executive Demo Flow added safely at /executive-demo-flow")
