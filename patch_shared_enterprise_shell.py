from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHARED_ENTERPRISE_SHELL_ACTIVE"

if MARKER in text:
    print("Shared Enterprise Shell already exists. No changes made.")
    raise SystemExit(0)

insert_before = '\nif __name__ == "__main__":'
idx = text.find(insert_before)

if idx == -1:
    raise SystemExit("ERROR: Could not find final if __name__ == \"__main__\" block.")

route_code = r'''

# ============================================================
# SHARED_ENTERPRISE_SHELL_ACTIVE
# Safe additive route only.
# Adds /enterprise-shell-preview without modifying protected modules.
# Demonstrates unified navigation, status banner, and executive links.
# ============================================================

@app.route("/enterprise-shell-preview")
def enterprise_shell_preview():
    nav_links = [
        {"label": "Workspace Hub", "url": "/enterprise-workspaces"},
        {"label": "Executive Demo", "url": "/executive-demo-flow"},
        {"label": "Role Views", "url": "/role-based-views"},
        {"label": "Shift Overlap", "url": "/shift-overlap-intelligence"},
        {"label": "ServiceNow Overlay", "url": "/servicenow-governance-overlay"},
        {"label": "Confidence", "url": "/governance-confidence-engine"},
        {"label": "Audit Simulation", "url": "/audit-simulation-engine"},
        {"label": "Digital Twin", "url": "/governance-digital-twin"},
        {"label": "Platform Health", "url": "/platform-health"},
    ]

    platform_status = [
        {"metric": "Platform State", "value": "Governed", "state": "good"},
        {"metric": "Confidence", "value": "89%", "state": "watch"},
        {"metric": "Audit Readiness", "value": "84%", "state": "watch"},
        {"metric": "Open Governance Gaps", "value": "3", "state": "risk"},
        {"metric": "Protected Routes", "value": "Preserved", "state": "good"},
    ]

    shell_features = [
        {
            "feature": "Unified Navigation",
            "meaning": "All major governance intelligence modules become reachable from one consistent top navigation.",
            "value": "Makes the platform feel cohesive and enterprise-ready."
        },
        {
            "feature": "Governance Status Banner",
            "meaning": "Every executive-facing page can show platform confidence, audit readiness, and open governance gaps.",
            "value": "Gives leaders instant context before they inspect details."
        },
        {
            "feature": "Module Identity Bar",
            "meaning": "Each page can clearly state whether it is Operations, Audit, ServiceNow, Digital Twin, or Executive layer.",
            "value": "Improves storytelling and reduces confusion during demos."
        },
        {
            "feature": "Executive Quick Links",
            "meaning": "Fast access to the demo flow, workspace hub, operational lineage, platform health, and trust engines.",
            "value": "Supports smooth leadership navigation."
        },
        {
            "feature": "Protected Route Boundary",
            "meaning": "The shell can wrap or link to modules without overwriting validated or protected route logic.",
            "value": "Keeps architecture safe while improving UX."
        },
    ]

    recommended_rollout = [
        {"phase": "1", "scope": "Preview shell", "status": "Current step", "risk": "Low"},
        {"phase": "2", "scope": "Add shell links to Enterprise Workspace Hub", "status": "Next", "risk": "Low"},
        {"phase": "3", "scope": "Add shared header to new intelligence modules only", "status": "Planned", "risk": "Medium"},
        {"phase": "4", "scope": "Avoid touching sterile protected modules unless explicitly requested", "status": "Protected", "risk": "Controlled"},
    ]

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>COBIT-Chain Shared Enterprise Shell Preview</title>
        <style>
            body { margin:0; font-family:Arial, Helvetica, sans-serif; background:#f4f7fb; color:#0f172a; }
            .shell-top {
                background:#0f172a;
                color:white;
                padding:14px 24px;
                display:flex;
                justify-content:space-between;
                align-items:center;
                gap:20px;
                flex-wrap:wrap;
                position:sticky;
                top:0;
                z-index:10;
            }
            .brand { font-weight:900; font-size:18px; }
            .brand span { color:#38bdf8; }
            .nav { display:flex; gap:10px; flex-wrap:wrap; }
            .nav a {
                color:#dbeafe;
                text-decoration:none;
                font-size:12px;
                font-weight:800;
                padding:8px 10px;
                border-radius:999px;
                background:rgba(255,255,255,.08);
                border:1px solid rgba(255,255,255,.12);
            }
            .nav a:hover { background:#2563eb; color:white; }
            .hero {
                background:linear-gradient(135deg,#1e3a8a,#0f172a);
                color:white;
                padding:36px 44px 76px;
                border-bottom-left-radius:28px;
                border-bottom-right-radius:28px;
            }
            .hero h1 { margin:0 0 10px; font-size:42px; }
            .hero p { color:#dbeafe; max-width:1120px; line-height:1.55; font-size:16px; }
            .badge {
                display:inline-block;
                background:rgba(255,255,255,.14);
                border:1px solid rgba(255,255,255,.25);
                padding:8px 13px;
                border-radius:999px;
                margin:10px 8px 0 0;
                font-size:12px;
                font-weight:800;
            }
            .wrap { max-width:1320px; margin:-46px auto 40px; padding:0 24px; }
            .status-bar {
                display:grid;
                grid-template-columns:repeat(5,1fr);
                gap:14px;
                margin-bottom:24px;
            }
            .status-card {
                background:white;
                border-radius:18px;
                padding:18px;
                box-shadow:0 12px 30px rgba(15,23,42,.09);
                border-top:5px solid #94a3b8;
            }
            .status-card.good { border-top-color:#16a34a; }
            .status-card.watch { border-top-color:#f59e0b; }
            .status-card.risk { border-top-color:#dc2626; }
            .status-card span {
                display:block;
                color:#64748b;
                font-size:12px;
                font-weight:900;
                text-transform:uppercase;
                letter-spacing:.06em;
            }
            .status-card strong { display:block; margin-top:8px; font-size:24px; }
            .panel {
                background:white;
                border-radius:22px;
                padding:24px;
                box-shadow:0 12px 30px rgba(15,23,42,.09);
                margin-bottom:24px;
            }
            table { width:100%; border-collapse:collapse; }
            th { background:#eff6ff; color:#1e3a8a; text-align:left; padding:12px; font-size:13px; }
            td { border-bottom:1px solid #e5e7eb; padding:12px; font-size:13px; vertical-align:top; }
            .pill {
                display:inline-block;
                padding:6px 10px;
                border-radius:999px;
                font-size:11px;
                font-weight:900;
            }
            .Low { background:#dcfce7; color:#166534; }
            .Medium { background:#fef3c7; color:#92400e; }
            .Controlled { background:#e0e7ff; color:#3730a3; }
            .quick-grid {
                display:grid;
                grid-template-columns:repeat(3,1fr);
                gap:16px;
            }
            .quick-card {
                background:#f8fafc;
                border:1px solid #e2e8f0;
                border-radius:18px;
                padding:18px;
            }
            .quick-card h3 { margin:0 0 8px; color:#1e3a8a; }
            .quick-card a {
                display:inline-block;
                text-decoration:none;
                background:#0f172a;
                color:white;
                padding:9px 12px;
                border-radius:10px;
                font-weight:800;
                font-size:13px;
                margin-top:8px;
            }
            @media(max-width:1100px){ .status-bar{grid-template-columns:repeat(2,1fr);} .quick-grid{grid-template-columns:repeat(2,1fr);} }
            @media(max-width:700px){ .status-bar,.quick-grid{grid-template-columns:1fr;} .hero h1{font-size:30px;} }
        </style>
    </head>
    <body>
        <div class="shell-top">
            <div class="brand">COBIT-Chain™ <span>Enterprise Governance Shell</span></div>
            <nav class="nav">
                {% for n in nav_links %}
                <a href="{{ n.url }}">{{ n.label }}</a>
                {% endfor %}
            </nav>
        </div>

        <section class="hero">
            <h1>Shared Enterprise Navigation Shell Preview</h1>
            <p>
                This preview shows how COBIT-Chain can present as one unified enterprise governance platform:
                consistent navigation, governance status banner, executive quick links, module identity, and protected-route boundaries.
            </p>
            <span class="badge">UNIFIED UX</span>
            <span class="badge">GOVERNANCE STATUS BAR</span>
            <span class="badge">EXECUTIVE QUICK LINKS</span>
            <span class="badge">PROTECTED ROUTES PRESERVED</span>
        </section>

        <main class="wrap">
            <section class="status-bar">
                {% for s in platform_status %}
                <div class="status-card {{ s.state }}">
                    <span>{{ s.metric }}</span>
                    <strong>{{ s.value }}</strong>
                </div>
                {% endfor %}
            </section>

            <section class="panel">
                <h2>1. Shell Capabilities</h2>
                <table>
                    <tr><th>Capability</th><th>Meaning</th><th>Enterprise Value</th></tr>
                    {% for f in shell_features %}
                    <tr>
                        <td><b>{{ f.feature }}</b></td>
                        <td>{{ f.meaning }}</td>
                        <td>{{ f.value }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>2. Executive Quick Access</h2>
                <div class="quick-grid">
                    {% for n in nav_links[:6] %}
                    <div class="quick-card">
                        <h3>{{ n.label }}</h3>
                        <p>Open this module from the shared enterprise shell navigation.</p>
                        <a href="{{ n.url }}">Open</a>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="panel">
                <h2>3. Recommended Rollout</h2>
                <table>
                    <tr><th>Phase</th><th>Scope</th><th>Status</th><th>Risk</th></tr>
                    {% for r in recommended_rollout %}
                    <tr>
                        <td><b>{{ r.phase }}</b></td>
                        <td>{{ r.scope }}</td>
                        <td>{{ r.status }}</td>
                        <td>{{ r.risk }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>4. Why This Matters</h2>
                <p>
                    Enterprise users judge maturity partly by navigation consistency and storytelling flow.
                    A shared shell makes COBIT-Chain feel like a platform rather than a set of disconnected experimental routes.
                    The safe approach is to preview first, then gradually apply the shell to new intelligence modules before touching any protected sterile or operational routes.
                </p>
            </section>
        </main>
    </body>
    </html>
    """

    return render_template_string(
        html,
        nav_links=nav_links,
        platform_status=platform_status,
        shell_features=shell_features,
        recommended_rollout=recommended_rollout
    )


'''

new_text = text[:idx] + route_code + text[idx:]
APP.write_text(new_text, encoding="utf-8")

required = [
    "SHARED_ENTERPRISE_SHELL_ACTIVE",
    '@app.route("/enterprise-shell-preview")',
    "Shared Enterprise Navigation Shell Preview",
    "Shell Capabilities",
    "Recommended Rollout"
]

missing = [x for x in required if x not in new_text]
if missing:
    raise SystemExit("ERROR missing expected markers: " + ", ".join(missing))

print("SUCCESS: Shared Enterprise Shell Preview added safely at /enterprise-shell-preview")
