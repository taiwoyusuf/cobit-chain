from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "OPERATIONAL_PAIN_POINT_FRAMEWORK_ACTIVE"

if MARKER in text:
    print("Operational Pain Point Framework already exists. No changes made.")
    raise SystemExit(0)

insert_before = '\nif __name__ == "__main__":'
idx = text.find(insert_before)

if idx == -1:
    raise SystemExit("ERROR: Could not find final if __name__ == \"__main__\" block.")

route_code = r'''

# ============================================================
# OPERATIONAL_PAIN_POINT_FRAMEWORK_ACTIVE
# Safe additive route only.
# Adds /operational-pain-point-framework without modifying protected modules.
# Standardizes Pain Point → Risk → COBIT-Chain Response → Governance Outcome → Demo Scenario.
# ============================================================

@app.route("/operational-pain-point-framework")
def operational_pain_point_framework():

    pain_points = [
        {
            "module": "Cross-System Dependency Validation",
            "pain_point": "One system may show work as complete while a dependent system is still holding, pending, blocked, or unreleased.",
            "enterprise_risk": "False completion, weak release assumption, audit exposure, and downstream operational confusion.",
            "cobitchain_response": "Validates workflow completion across dependent systems before treating the record as truly complete.",
            "governance_outcome": "Prevents one-system completion from being mistaken for end-to-end workflow truth.",
            "demo_scenario": "Middleware = Verified, LIS = Held, Downstream = Not Released, COBIT-Chain = Incomplete."
        },
        {
            "module": "Governance Reconciliation Layer",
            "pain_point": "Enterprise systems can disagree on operational truth across Veeva, Blue Mountain, ServiceNow, myAccess, MES, ERP, LIMS, CAPA, and downstream systems.",
            "enterprise_risk": "False closure, incomplete dependency chains, weak GMP defensibility, and unreliable audit posture.",
            "cobitchain_response": "Reconciles conflicting system states and flags workflows that are not fully aligned.",
            "governance_outcome": "Creates an enterprise operational truth layer across systems.",
            "demo_scenario": "ServiceNow = Closed, myAccess = Not Provisioned, COBIT-Chain = False Completion."
        },
        {
            "module": "ServiceNow Governance Overlay",
            "pain_point": "A ServiceNow ticket can be assigned, resolved, or closed without proving evidence, ownership, review, or audit defensibility.",
            "enterprise_risk": "Workflow closure may not equal governed closure.",
            "cobitchain_response": "Adds governance trust state above ServiceNow workflow state.",
            "governance_outcome": "Separates process status from governance confidence.",
            "demo_scenario": "Ticket = Closed, Evidence = Missing, Owner = Unclear, COBIT-Chain = Governance Exception."
        },
        {
            "module": "Shift Overlap Intelligence",
            "pain_point": "Shift overlap can exist on paper, but unresolved issues may lose ownership during handoff.",
            "enterprise_risk": "Orphaned work, weak escalation continuity, evidence gaps, and pre-deviation risk.",
            "cobitchain_response": "Treats overlap windows as governance control points.",
            "governance_outcome": "Ensures handoff, ownership, evidence, and escalation continuity remain controlled.",
            "demo_scenario": "B-to-C transition active, incoming owner not acknowledged, COBIT-Chain = Continuity Watch."
        },
        {
            "module": "Governance Confidence Engine",
            "pain_point": "Leaders often see many system statuses but lack a simple trust score showing whether the operation is governance-ready.",
            "enterprise_risk": "Leadership may rely on incomplete or misleading operational records.",
            "cobitchain_response": "Calculates confidence based on evidence, ownership, review, audit readiness, lineage, and platform health.",
            "governance_outcome": "Turns complex governance posture into an executive trust score.",
            "demo_scenario": "Confidence = 89%, Evidence Gap = Open, Audit Readiness = 84%."
        },
        {
            "module": "Audit Simulation Engine",
            "pain_point": "Teams often discover evidence or lineage gaps only when audit pressure arrives.",
            "enterprise_risk": "Audit findings, delayed response, weak inspection readiness, and remediation scramble.",
            "cobitchain_response": "Simulates likely auditor questions and identifies what would fail first.",
            "governance_outcome": "Enables pre-audit readiness correction before real inspection pressure.",
            "demo_scenario": "Auditor asks for complete evidence trail; system flags missing audit trail export."
        },
        {
            "module": "Governance Digital Command Center",
            "pain_point": "Governance signals are scattered across multiple pages, systems, records, and dashboards.",
            "enterprise_risk": "Leadership lacks one operational picture of confidence, risk, audit readiness, and remediation status.",
            "cobitchain_response": "Combines mission status, live alerts, confidence, drift, recovery, and command modules in one boardroom view.",
            "governance_outcome": "Creates a single-pane governance operating center.",
            "demo_scenario": "Mission Status = WATCH, Blast Radius = HIGH, Recovery Potential = +28."
        }
    ]

    framework_steps = [
        {"step": "1", "name": "Pain Point", "meaning": "What real operational problem exists?"},
        {"step": "2", "name": "Enterprise Risk", "meaning": "What can go wrong if the pain point is ignored?"},
        {"step": "3", "name": "COBIT-Chain Response", "meaning": "What does the platform do differently?"},
        {"step": "4", "name": "Governance Outcome", "meaning": "What control, assurance, or audit value is created?"},
        {"step": "5", "name": "Demo Scenario", "meaning": "What practical example makes the value obvious?"}
    ]

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>COBIT-Chain Operational Pain Point Framework</title>
        <style>
            body { margin:0; font-family:Arial, Helvetica, sans-serif; background:#f4f7fb; color:#0f172a; }
            .top { background:#0f172a; color:white; padding:14px 24px; display:flex; justify-content:space-between; align-items:center; gap:18px; flex-wrap:wrap; position:sticky; top:0; z-index:10; }
            .brand { font-weight:900; font-size:18px; }
            .brand span { color:#38bdf8; }
            .nav { display:flex; gap:10px; flex-wrap:wrap; }
            .nav a { color:#dbeafe; text-decoration:none; font-size:12px; font-weight:800; padding:8px 10px; border-radius:999px; background:rgba(255,255,255,.08); border:1px solid rgba(255,255,255,.12); }
            .hero { background:linear-gradient(135deg,#111827,#1d4ed8); color:white; padding:38px 44px 82px; border-bottom-left-radius:28px; border-bottom-right-radius:28px; }
            .hero h1 { margin:0 0 10px; font-size:42px; }
            .hero p { color:#dbeafe; max-width:1120px; line-height:1.55; font-size:16px; }
            .badge { display:inline-block; background:rgba(255,255,255,.14); border:1px solid rgba(255,255,255,.25); padding:8px 13px; border-radius:999px; margin:10px 8px 0 0; font-size:12px; font-weight:800; }
            .wrap { max-width:1360px; margin:-48px auto 40px; padding:0 24px; }
            .panel { background:white; border-radius:20px; padding:22px; box-shadow:0 12px 30px rgba(15,23,42,.09); margin-bottom:22px; }
            .step-grid { display:grid; grid-template-columns:repeat(5,1fr); gap:14px; }
            .step-card { background:#eff6ff; border:1px solid #bfdbfe; border-radius:18px; padding:18px; }
            .step-card h3 { margin:0 0 8px; color:#1e3a8a; }
            .module-card { background:#f8fafc; border:1px solid #e2e8f0; border-radius:20px; padding:20px; margin-bottom:18px; }
            .module-card h3 { margin:0 0 10px; color:#1e3a8a; }
            .grid5 { display:grid; grid-template-columns:repeat(5,1fr); gap:12px; }
            .cell { background:white; border:1px solid #e5e7eb; border-radius:14px; padding:14px; }
            .cell b { display:block; color:#334155; margin-bottom:7px; font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
            .cell p { margin:0; color:#334155; font-size:13px; line-height:1.45; }
            .note { background:#ecfeff; border:1px solid #99f6e4; color:#115e59; padding:16px; border-radius:16px; margin-bottom:22px; }
            @media(max-width:1200px){ .grid5{grid-template-columns:1fr;} .step-grid{grid-template-columns:repeat(2,1fr);} }
            @media(max-width:700px){ .step-grid{grid-template-columns:1fr;} .hero h1{font-size:30px;} }
        </style>
    </head>
    <body>
        <div class="top">
            <div class="brand">COBIT-Chain™ <span>Operational Pain Point Framework</span></div>
            <nav class="nav">
                <a href="/enterprise-workspaces">Workspaces</a>
                <a href="/governance-reconciliation-layer">Reconciliation</a>
                <a href="/cross-system-dependency-validation">Dependency Validation</a>
                <a href="/executive-mission-control">Mission Control</a>
            </nav>
        </div>

        <section class="hero">
            <h1>Operational Pain Point Framework™</h1>
            <p>
                Standardizes how every COBIT-Chain module is explained:
                Pain Point → Enterprise Risk → COBIT-Chain Response → Governance Outcome → Demo Scenario.
            </p>
            <span class="badge">EXECUTIVE STORYTELLING</span>
            <span class="badge">MODULE VALUE CLARITY</span>
            <span class="badge">PAIN POINT FIRST</span>
            <span class="badge">DEMO-READY STRUCTURE</span>
        </section>

        <main class="wrap">
            <div class="note">
                <b>Why this matters:</b> Each module must clearly explain the operational pain it solves.
                This helps leadership understand the value before they see the technical screen.
            </div>

            <section class="panel">
                <h2>1. Standard Module Framing</h2>
                <div class="step-grid">
                    {% for s in framework_steps %}
                    <div class="step-card">
                        <h3>{{ s.step }}. {{ s.name }}</h3>
                        <p>{{ s.meaning }}</p>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="panel">
                <h2>2. Module Pain Point Matrix</h2>
                {% for p in pain_points %}
                <div class="module-card">
                    <h3>{{ p.module }}</h3>
                    <div class="grid5">
                        <div class="cell"><b>Pain Point</b><p>{{ p.pain_point }}</p></div>
                        <div class="cell"><b>Enterprise Risk</b><p>{{ p.enterprise_risk }}</p></div>
                        <div class="cell"><b>COBIT-Chain Response</b><p>{{ p.cobitchain_response }}</p></div>
                        <div class="cell"><b>Governance Outcome</b><p>{{ p.governance_outcome }}</p></div>
                        <div class="cell"><b>Demo Scenario</b><p>{{ p.demo_scenario }}</p></div>
                    </div>
                </div>
                {% endfor %}
            </section>
        </main>
    </body>
    </html>
    """

    return render_template_string(
        html,
        pain_points=pain_points,
        framework_steps=framework_steps
    )


'''

new_text = text[:idx] + route_code + text[idx:]
APP.write_text(new_text, encoding="utf-8")

required = [
    "OPERATIONAL_PAIN_POINT_FRAMEWORK_ACTIVE",
    '@app.route("/operational-pain-point-framework")',
    "Operational Pain Point Framework",
    "Module Pain Point Matrix"
]

missing = [x for x in required if x not in new_text]
if missing:
    raise SystemExit("ERROR missing expected markers: " + ", ".join(missing))

print("SUCCESS: Operational Pain Point Framework added safely at /operational-pain-point-framework")
