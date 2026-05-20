from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "ROLE_BASED_ENTERPRISE_VIEWS_ACTIVE"

if MARKER in text:
    print("Role-Based Enterprise Views already exists. No changes made.")
    raise SystemExit(0)

insert_before = '\nif __name__ == "__main__":'
idx = text.find(insert_before)

if idx == -1:
    raise SystemExit("ERROR: Could not find final if __name__ == \"__main__\" block.")

role_code = r'''

# ============================================================
# ROLE_BASED_ENTERPRISE_VIEWS_ACTIVE
# Safe additive route only.
# Adds /role-based-views without modifying protected modules.
# ============================================================

@app.route("/role-based-views")
def role_based_enterprise_views():
    roles = [
        {
            "role": "Executive View",
            "persona": "Chris / leadership / site stakeholders",
            "focus": "Operational readiness, governance confidence, audit posture, open risk, and platform-level visibility.",
            "kpis": ["Governance Confidence", "Audit Readiness", "Critical Risks", "Coverage Integrity"],
            "primary_actions": [
                "Open Enterprise Workspace Hub",
                "Review Power BI readiness routes",
                "View Platform Health",
                "Open Monday Demo",
            ],
            "routes": [
                {"label": "Enterprise Workspace Hub", "url": "/enterprise-workspaces"},
                {"label": "Command Center", "url": "/command-center"},
                {"label": "Monday Demo", "url": "/monday-demo"},
                {"label": "Platform Health", "url": "/platform-health"},
            ],
            "value": "Gives leadership a clean view of what the platform can do without exposing operational detail too early.",
        },
        {
            "role": "Supervisor View",
            "persona": "Operations supervisor / system owner / team lead",
            "focus": "Shift handoff, unresolved issues, equipment continuity, evidence readiness, and escalation ownership.",
            "kpis": ["Open Handoffs", "Evidence Pending", "Escalations", "Equipment Risk"],
            "primary_actions": [
                "Review operational lineage",
                "Check unresolved tickets",
                "Validate evidence readiness",
                "Confirm supervisor review checkpoints",
            ],
            "routes": [
                {"label": "Operational Lineage", "url": "/operational-lineage"},
                {"label": "Platform Health", "url": "/platform-health"},
                {"label": "Sterile Compounding", "url": "/sterile-compounding"},
                {"label": "Sterile Audit Lineage", "url": "/sterile-compounding/audit-lineage"},
            ],
            "value": "Turns supervision into governed continuity instead of informal follow-up across email, Excel, Teams, and tickets.",
        },
        {
            "role": "Technician View",
            "persona": "Technician / analyst / equipment support user",
            "focus": "Assigned work, required evidence, equipment state, handoff notes, and task closure readiness.",
            "kpis": ["Assigned Tasks", "Evidence Required", "Open Equipment Issues", "Handoff Status"],
            "primary_actions": [
                "Review assigned equipment context",
                "Upload or prepare evidence",
                "Acknowledge handoff",
                "Confirm task closure requirements",
            ],
            "routes": [
                {"label": "Sterile Compounding", "url": "/sterile-compounding"},
                {"label": "Sterile Review", "url": "/sterile-compounding/review"},
                {"label": "Sterile Evidence Vault", "url": "/sterile-compounding/evidence-vault"},
                {"label": "Operational Lineage", "url": "/operational-lineage"},
            ],
            "value": "Makes the technician experience clearer by showing exactly what evidence and accountability are expected.",
        },
        {
            "role": "QA / Audit View",
            "persona": "QA reviewer / auditor / compliance stakeholder",
            "focus": "Audit-ready lineage, evidence completeness, control mapping, inspection readiness, and exception handling.",
            "kpis": ["Audit Readiness", "Evidence Completeness", "Open Exceptions", "Control Coverage"],
            "primary_actions": [
                "Review evidence vault",
                "Open audit lineage",
                "Check inspection readiness",
                "Export audit-ready registers",
            ],
            "routes": [
                {"label": "Sterile Audit Lineage", "url": "/sterile-compounding/audit-lineage"},
                {"label": "Sterile Evidence Vault", "url": "/sterile-compounding/evidence-vault"},
                {"label": "Sterile Inspection Readiness", "url": "/sterile-compounding/inspection-readiness"},
                {"label": "Platform Health", "url": "/platform-health"},
            ],
            "value": "Creates defensible audit visibility by connecting records, evidence, control posture, and lineage.",
        },
        {
            "role": "Platform Admin View",
            "persona": "Platform owner / developer / governance architect",
            "focus": "Route health, module registry, protected routes, CSV registers, export packs, and integration readiness.",
            "kpis": ["Route Health", "Register Count", "Module Status", "Export Readiness"],
            "primary_actions": [
                "Check platform health",
                "Review workspace hub",
                "Validate Power BI dataset routes",
                "Confirm protected modules remain intact",
            ],
            "routes": [
                {"label": "Platform Health", "url": "/platform-health"},
                {"label": "Enterprise Workspace Hub", "url": "/enterprise-workspaces"},
                {"label": "Sterile Power BI Readiness", "url": "/sterile-compounding/powerbi-readiness-blueprint"},
                {"label": "Sterile Power BI Export Pack", "url": "/sterile-compounding/powerbi-export-pack"},
            ],
            "value": "Provides a governance architecture view for maintaining, extending, and protecting the platform.",
        },
    ]

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>COBIT-Chain Role-Based Enterprise Views</title>
        <style>
            body {
                margin:0;
                font-family:Arial, Helvetica, sans-serif;
                background:#f4f7fb;
                color:#0f172a;
            }
            .hero {
                background:linear-gradient(135deg,#111827,#4338ca);
                color:white;
                padding:36px 44px 72px;
                border-bottom-left-radius:28px;
                border-bottom-right-radius:28px;
            }
            .hero h1 {
                margin:0 0 10px;
                font-size:40px;
            }
            .hero p {
                color:#e0e7ff;
                max-width:1040px;
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
                margin:-42px auto 40px;
                padding:0 24px;
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
            .role-card {
                background:white;
                border-radius:22px;
                padding:24px;
                box-shadow:0 12px 30px rgba(15,23,42,.09);
                margin-bottom:24px;
            }
            .role-head {
                display:flex;
                justify-content:space-between;
                gap:18px;
                align-items:flex-start;
                flex-wrap:wrap;
            }
            .role-card h2 {
                margin:0 0 8px;
                font-size:26px;
            }
            .persona {
                color:#64748b;
                font-weight:800;
                margin-bottom:10px;
            }
            .focus {
                color:#334155;
                line-height:1.55;
                max-width:900px;
            }
            .grid {
                display:grid;
                grid-template-columns:repeat(4,1fr);
                gap:14px;
                margin-top:18px;
            }
            .mini {
                background:#f8fafc;
                border:1px solid #e2e8f0;
                border-radius:16px;
                padding:16px;
            }
            .mini b {
                display:block;
                color:#1e3a8a;
                margin-bottom:8px;
            }
            .pill {
                display:inline-block;
                background:#e0e7ff;
                color:#3730a3;
                padding:7px 10px;
                border-radius:999px;
                font-size:12px;
                font-weight:900;
                margin:0 6px 7px 0;
            }
            .action-list {
                margin:0;
                padding-left:18px;
                line-height:1.7;
                color:#334155;
            }
            .route-link {
                display:inline-block;
                text-decoration:none;
                background:#0f172a;
                color:white;
                padding:9px 12px;
                border-radius:10px;
                margin:0 8px 8px 0;
                font-size:13px;
                font-weight:800;
            }
            .value {
                background:#f5f3ff;
                border:1px solid #ddd6fe;
                color:#4c1d95;
                border-radius:16px;
                padding:14px;
                margin-top:18px;
                line-height:1.5;
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
            @media(max-width:1000px) {
                .grid { grid-template-columns:repeat(2,1fr); }
            }
            @media(max-width:680px) {
                .grid { grid-template-columns:1fr; }
                .hero h1 { font-size:30px; }
            }
        </style>
    </head>
    <body>
        <section class="hero">
            <h1>COBIT-Chain™ Role-Based Enterprise Views</h1>
            <p>
                A leadership-friendly role model showing how different stakeholders would experience the same governance platform.
                This is not a login/security implementation yet; it is a controlled presentation layer for explaining enterprise value by role.
            </p>
            <span class="badge">EXECUTIVE</span>
            <span class="badge">SUPERVISOR</span>
            <span class="badge">TECHNICIAN</span>
            <span class="badge">QA / AUDIT</span>
            <span class="badge">PLATFORM ADMIN</span>
            <div class="toplinks">
                <a href="/enterprise-workspaces">Enterprise Workspaces</a>
                <a href="/command-center">Command Center</a>
                <a href="/operational-lineage">Operational Lineage</a>
                <a href="/platform-health">Platform Health</a>
            </div>
        </section>

        <main class="wrap">
            <div class="note">
                <b>Positioning:</b> Role-based views help leadership understand that COBIT-Chain can serve different users
                without changing the core platform. Each role sees the governance information relevant to their responsibility.
            </div>

            {% for role in roles %}
            <section class="role-card">
                <div class="role-head">
                    <div>
                        <h2>{{ role.role }}</h2>
                        <div class="persona">{{ role.persona }}</div>
                        <div class="focus">{{ role.focus }}</div>
                    </div>
                </div>

                <div class="grid">
                    <div class="mini">
                        <b>Key KPIs</b>
                        {% for kpi in role.kpis %}
                            <span class="pill">{{ kpi }}</span>
                        {% endfor %}
                    </div>

                    <div class="mini">
                        <b>Primary Actions</b>
                        <ul class="action-list">
                            {% for action in role.primary_actions %}
                                <li>{{ action }}</li>
                            {% endfor %}
                        </ul>
                    </div>

                    <div class="mini">
                        <b>Relevant Routes</b>
                        {% for route in role.routes %}
                            <a class="route-link" href="{{ route.url }}">{{ route.label }}</a>
                        {% endfor %}
                    </div>

                    <div class="mini">
                        <b>Enterprise Value</b>
                        <p>{{ role.value }}</p>
                    </div>
                </div>
            </section>
            {% endfor %}
        </main>
    </body>
    </html>
    """

    return render_template_string(html, roles=roles)


'''

new_text = text[:idx] + role_code + text[idx:]
APP.write_text(new_text, encoding="utf-8")

required = [
    "ROLE_BASED_ENTERPRISE_VIEWS_ACTIVE",
    '@app.route("/role-based-views")',
    "COBIT-Chain™ Role-Based Enterprise Views",
    "Executive View",
    "Supervisor View",
    "Technician View",
    "QA / Audit View",
    "Platform Admin View"
]

missing = [x for x in required if x not in new_text]
if missing:
    raise SystemExit("ERROR missing expected markers: " + ", ".join(missing))

print("SUCCESS: Role-Based Enterprise Views added safely at /role-based-views")
