from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "ENTERPRISE_WORKSPACE_HUB_ACTIVE"

if MARKER in text:
    print("Enterprise Workspace Hub already exists. No changes made.")
    raise SystemExit(0)

insert_before = '\nif __name__ == "__main__":'
idx = text.find(insert_before)

if idx == -1:
    raise SystemExit("ERROR: Could not find final if __name__ == \"__main__\" block.")

hub_code = r'''

# ============================================================
# ENTERPRISE_WORKSPACE_HUB_ACTIVE
# Safe navigation layer only.
# Adds /enterprise-workspaces without modifying protected routes.
# Protected routes not overwritten:
# /command-center, /monday-demo, /operational-lineage, /platform-health,
# sterile compounding vertical routes, Power BI sterile routes.
# ============================================================

@app.route("/enterprise-workspaces")
def enterprise_workspace_hub():
    workspace_groups = [
        {
            "group": "Executive & Platform Control",
            "description": "Leadership-facing views, presentation routes, module health, and architecture navigation.",
            "items": [
                {
                    "name": "Command Center",
                    "route": "/command-center",
                    "status": "LIVE",
                    "tag": "EXECUTIVE",
                    "summary": "Enterprise-level command view across governance modules and platform direction."
                },
                {
                    "name": "Monday Demo",
                    "route": "/monday-demo",
                    "status": "LIVE",
                    "tag": "PRESENTATION",
                    "summary": "Guided leadership demo path with talking points and controlled presentation flow."
                },
                {
                    "name": "Platform Health",
                    "route": "/platform-health",
                    "status": "LIVE",
                    "tag": "SYSTEM HEALTH",
                    "summary": "Route registry, register health, module availability, and evidence register status."
                },
                {
                    "name": "Operational Lineage",
                    "route": "/operational-lineage",
                    "status": "LIVE",
                    "tag": "LINEAGE",
                    "summary": "Full governed chain from service event to technician, evidence, review, and audit lineage."
                },
            ],
        },
        {
            "group": "Sterile Compounding Vertical",
            "description": "Advanced sterile compounding assurance, evidence, inspection, control mapping, and Power BI readiness ecosystem.",
            "items": [
                {
                    "name": "Sterile Compounding Control Center",
                    "route": "/sterile-compounding",
                    "status": "LIVE",
                    "tag": "VERTICAL",
                    "summary": "Primary sterile compounding governance vertical and control center."
                },
                {
                    "name": "Sterile Evidence Vault",
                    "route": "/sterile-compounding/evidence-vault",
                    "status": "LIVE",
                    "tag": "EVIDENCE",
                    "summary": "Evidence vault and traceability register for sterile compounding governance artifacts."
                },
                {
                    "name": "Sterile Power BI Readiness",
                    "route": "/sterile-compounding/powerbi-readiness-blueprint",
                    "status": "LIVE",
                    "tag": "POWER BI",
                    "summary": "Power BI dataset contract and readiness blueprint for sterile compounding analytics."
                },
                {
                    "name": "Sterile Power BI Export Pack",
                    "route": "/sterile-compounding/powerbi-export-pack",
                    "status": "LIVE",
                    "tag": "POWER BI",
                    "summary": "Export pack structure for Power BI build, relationship mapping, and executive reporting."
                },
                {
                    "name": "Sterile DAX Blueprint",
                    "route": "/sterile-compounding/powerbi-dax-blueprint",
                    "status": "LIVE",
                    "tag": "DAX",
                    "summary": "DAX measures and visual interaction blueprint for Power BI implementation."
                },
            ],
        },
        {
            "group": "Operational Governance & Service Assurance",
            "description": "ServiceNow-aware governance, CI readiness, knowledge governance, shift handoff, and operational chain-of-custody views.",
            "items": [
                {
                    "name": "ServiceNow Live Integration",
                    "route": "/servicenow-live",
                    "status": "CHECK",
                    "tag": "SERVICENOW",
                    "summary": "ServiceNow-style live integration area if enabled in the current build."
                },
                {
                    "name": "CI Candidate Factory",
                    "route": "/ci-candidate-factory",
                    "status": "CHECK",
                    "tag": "CMDB",
                    "summary": "Candidate CI governance readiness and structured intake path."
                },
                {
                    "name": "Knowledge Governance",
                    "route": "/knowledge-governance",
                    "status": "CHECK",
                    "tag": "KNOWLEDGE",
                    "summary": "Knowledge article governance, review flow, and operational knowledge assurance."
                },
                {
                    "name": "Shift Handoff Lineage",
                    "route": "/shift-handoff-lineage",
                    "status": "CHECK",
                    "tag": "SHIFT",
                    "summary": "Shift handoff and technician continuity lineage if enabled in this build."
                },
            ],
        },
        {
            "group": "Future Clean Executive Demo Spaces",
            "description": "Reserved sanitized demo concepts for leadership review without exposing confidential records.",
            "items": [
                {
                    "name": "Lilly Operational Governance Demo",
                    "route": "/lilly-operational-governance",
                    "status": "ROADMAP",
                    "tag": "SANITIZED DEMO",
                    "summary": "Clean executive demo concept for shift, equipment, ServiceNow-aware governance, lineage, and audit posture."
                },
                {
                    "name": "General Power BI Command Center",
                    "route": "/powerbi-command-center",
                    "status": "ROADMAP",
                    "tag": "ANALYTICS",
                    "summary": "General platform-wide Power BI command center concept separate from sterile compounding-specific Power BI routes."
                },
            ],
        },
    ]

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>COBIT-Chain Enterprise Workspace Hub</title>
        <style>
            body {
                margin:0;
                font-family:Arial, Helvetica, sans-serif;
                background:#eef4fb;
                color:#0f172a;
            }
            .hero {
                background:linear-gradient(135deg,#0f172a,#1d4ed8);
                color:white;
                padding:36px 44px 70px;
                border-bottom-left-radius:28px;
                border-bottom-right-radius:28px;
            }
            .hero h1 {
                margin:0 0 10px;
                font-size:40px;
            }
            .hero p {
                color:#dbeafe;
                max-width:1050px;
                line-height:1.55;
                font-size:16px;
            }
            .badge {
                display:inline-block;
                background:rgba(255,255,255,.14);
                border:1px solid rgba(255,255,255,.25);
                color:white;
                padding:8px 13px;
                border-radius:999px;
                margin:10px 8px 0 0;
                font-size:12px;
                font-weight:800;
            }
            .wrap {
                max-width:1320px;
                margin:-40px auto 40px;
                padding:0 24px;
            }
            .panel {
                background:white;
                border-radius:22px;
                padding:24px;
                box-shadow:0 12px 30px rgba(15,23,42,.10);
                margin-bottom:24px;
            }
            .panel h2 {
                margin:0 0 6px;
            }
            .panel-desc {
                color:#475569;
                margin:0 0 20px;
                line-height:1.5;
            }
            .grid {
                display:grid;
                grid-template-columns:repeat(4, 1fr);
                gap:16px;
            }
            .card {
                background:#f8fafc;
                border:1px solid #e2e8f0;
                border-radius:18px;
                padding:18px;
                min-height:205px;
                display:flex;
                flex-direction:column;
                justify-content:space-between;
            }
            .card h3 {
                margin:8px 0 8px;
                font-size:18px;
            }
            .card p {
                color:#475569;
                line-height:1.45;
                font-size:13px;
            }
            .tag {
                display:inline-block;
                padding:5px 9px;
                border-radius:999px;
                font-size:10px;
                font-weight:900;
                background:#dbeafe;
                color:#1e40af;
                margin-right:6px;
            }
            .status {
                display:inline-block;
                padding:5px 9px;
                border-radius:999px;
                font-size:10px;
                font-weight:900;
            }
            .live { background:#dcfce7; color:#166534; }
            .check { background:#fef3c7; color:#92400e; }
            .roadmap { background:#e0e7ff; color:#3730a3; }
            .open {
                display:inline-block;
                text-decoration:none;
                background:#0f172a;
                color:white;
                padding:10px 13px;
                border-radius:11px;
                font-weight:800;
                font-size:13px;
                margin-top:12px;
            }
            .toplinks {
                margin-top:18px;
            }
            .toplinks a {
                color:white;
                text-decoration:none;
                font-weight:800;
                margin-right:16px;
            }
            .note {
                background:#ecfeff;
                border:1px solid #a5f3fc;
                color:#155e75;
                border-radius:16px;
                padding:16px;
                margin-bottom:24px;
                box-shadow:0 8px 22px rgba(15,23,42,.06);
            }
            @media (max-width:1100px) {
                .grid { grid-template-columns:repeat(2,1fr); }
            }
            @media (max-width:700px) {
                .grid { grid-template-columns:1fr; }
                .hero h1 { font-size:30px; }
            }
        </style>
    </head>
    <body>
        <section class="hero">
            <h1>COBIT-Chain™ Enterprise Workspace Hub</h1>
            <p>
                A safe navigation layer for the enterprise governance platform. This hub does not overwrite protected modules.
                It organizes existing live routes, sterile compounding vertical routes, operational governance routes, and future
                clean executive demo spaces in one leadership-friendly view.
            </p>
            <span class="badge">SAFE NAVIGATION ONLY</span>
            <span class="badge">NO ROUTE OVERWRITE</span>
            <span class="badge">PROTECTED MODULES PRESERVED</span>
            <span class="badge">ENTERPRISE WORKSPACE MODEL</span>
            <div class="toplinks">
                <a href="/command-center">Command Center</a>
                <a href="/monday-demo">Monday Demo</a>
                <a href="/operational-lineage">Operational Lineage</a>
                <a href="/platform-health">Platform Health</a>
            </div>
        </section>

        <main class="wrap">
            <div class="note">
                <b>Positioning:</b> ServiceNow, Blue Mountain, Veeva, myAccess, and other systems remain systems of record.
                COBIT-Chain provides a modular governance assurance layer for continuity, evidence integrity, lineage, audit readiness,
                and executive operational intelligence.
            </div>

            {% for group in workspace_groups %}
            <section class="panel">
                <h2>{{ group.group }}</h2>
                <p class="panel-desc">{{ group.description }}</p>
                <div class="grid">
                    {% for item in group.items %}
                    <div class="card">
                        <div>
                            <span class="tag">{{ item.tag }}</span>
                            {% if item.status == "LIVE" %}
                                <span class="status live">{{ item.status }}</span>
                            {% elif item.status == "CHECK" %}
                                <span class="status check">{{ item.status }}</span>
                            {% else %}
                                <span class="status roadmap">{{ item.status }}</span>
                            {% endif %}
                            <h3>{{ item.name }}</h3>
                            <p>{{ item.summary }}</p>
                        </div>
                        <a class="open" href="{{ item.route }}">Open Workspace</a>
                    </div>
                    {% endfor %}
                </div>
            </section>
            {% endfor %}
        </main>
    </body>
    </html>
    """

    return render_template_string(html, workspace_groups=workspace_groups)


'''

new_text = text[:idx] + hub_code + text[idx:]
APP.write_text(new_text, encoding="utf-8")

required = [
    "ENTERPRISE_WORKSPACE_HUB_ACTIVE",
    '@app.route("/enterprise-workspaces")',
    "COBIT-Chain™ Enterprise Workspace Hub",
    "/sterile-compounding/powerbi-readiness-blueprint",
    "/operational-lineage",
    "/platform-health"
]

missing = [x for x in required if x not in new_text]
if missing:
    raise SystemExit("ERROR missing expected markers: " + ", ".join(missing))

print("SUCCESS: Enterprise Workspace Hub added safely at /enterprise-workspaces")
