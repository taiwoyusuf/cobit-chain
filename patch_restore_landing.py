from pathlib import Path

p = Path("app.py")
text = p.read_text(encoding="utf-8")

old_home = '''@app.route("/")
def home():
    return redirect("/workspace/manufacturing-assurance")
'''

new_home = '''@app.route("/")
def home():
    return render_executive_platform_landing()
'''

if old_home in text:
    text = text.replace(old_home, new_home)
elif "def home():\n    return render_executive_platform_landing()" in text:
    print("Home route already points to executive landing.")
else:
    raise SystemExit("ERROR: Could not find expected home route.")

if "def render_executive_platform_landing():" not in text:
    marker = '@app.route("/workspace/<workspace_slug>", methods=["GET", "POST"])'
    k = text.find(marker)
    if k == -1:
        raise SystemExit("ERROR: Could not find workspace router marker.")

    fn = r'''
def render_executive_platform_landing():
    kpis = {
        "workspaces": len(WORKSPACES),
        "live_modules": len([w for w in WORKSPACES if w.get("status") == "LIVE"]),
        "demo_modules": len([w for w in WORKSPACES if w.get("status") == "DEMO"]),
        "assurance_domains": "6"
    }

    platform_layers = [
        {"layer": "Operational Systems", "examples": "ServiceNow, Blue Mountain, Veeva, myAccess, Excel/Planner", "role": "Systems of record and operational execution sources"},
        {"layer": "COBIT-Chain Governance Layer", "examples": "Evidence hashing, continuity checks, risk scoring, lineage, pre-execution validation", "role": "Governance assurance and evidence integrity overlay"},
        {"layer": "Analytics & Audit Layer", "examples": "Power BI dashboards, audit exports, risk heatmaps, executive scorecards", "role": "Leadership visibility, audit readiness, and operational intelligence"}
    ]

    value_points = [
        "ServiceNow tracks work; COBIT-Chain verifies whether work remained governed.",
        "The platform supports modular workspaces instead of one-off demo screens.",
        "Operational activity is connected to evidence integrity, accountability, audit posture, lineage, and analytics.",
        "Sanitized demo workspaces allow leadership review without exposing confidential production records.",
        "The architecture can scale by adding new modules without replacing the existing interface."
    ]

    template = """
<!DOCTYPE html>
<html>
<head>
<title>COBIT-Chain Executive Platform Overview</title>
<style>
body{margin:0;font-family:Arial,Helvetica,sans-serif;background:#eef4fb;color:#0f172a}
.hero{background:linear-gradient(135deg,#1d4ed8,#0f172a);color:white;padding:38px 44px 90px;border-bottom-left-radius:28px;border-bottom-right-radius:28px}
.brand{display:flex;align-items:center;gap:14px}.logo{width:58px;height:58px;border-radius:18px;background:#2dd4bf;display:flex;align-items:center;justify-content:center;font-weight:900;font-size:22px}
.hero h1{margin:18px 0 8px;font-size:42px}.hero p{color:#dbeafe;font-size:17px;max-width:950px;line-height:1.55}
.badge{display:inline-block;background:rgba(255,255,255,.14);border:1px solid rgba(255,255,255,.25);padding:10px 16px;border-radius:999px;margin-right:10px;margin-top:16px;font-weight:700}
.wrap{max-width:1280px;margin:-58px auto 40px;padding:0 24px}.grid4{display:grid;grid-template-columns:repeat(4,1fr);gap:18px;margin-bottom:24px}
.kpi{background:white;border-radius:18px;padding:22px;box-shadow:0 12px 30px rgba(15,23,42,.10)}.kpi span{color:#64748b;font-size:13px;text-transform:uppercase;letter-spacing:.08em;font-weight:800}.kpi strong{display:block;margin-top:12px;font-size:34px}
.panel{background:white;border-radius:22px;padding:26px;box-shadow:0 12px 30px rgba(15,23,42,.09);margin-bottom:24px}.panel h2{margin-top:0}
.modules{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}.card{border:1px solid #e2e8f0;border-radius:18px;padding:20px;background:#f8fafc}
.card h3{margin:0 0 8px}.card p{color:#475569;line-height:1.5;min-height:78px}.card a{display:inline-block;text-decoration:none;background:#0f172a;color:white;padding:10px 14px;border-radius:10px;font-weight:800}
.status{display:inline-block;padding:6px 10px;border-radius:999px;font-size:11px;font-weight:900;margin-bottom:10px}.live{background:#dcfce7;color:#166534}.demo{background:#dbeafe;color:#1e40af}.roadmap{background:#fef3c7;color:#92400e}
.arch{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}.arch-card{background:#f8fafc;border:1px solid #e2e8f0;border-radius:18px;padding:20px}.arch-card b{display:block;font-size:18px;margin-bottom:8px}.arch-card span{display:block;color:#2563eb;font-weight:800;margin-bottom:10px}
ul{line-height:1.8}.footer{text-align:center;color:#64748b;padding:24px}
</style>
</head>
<body>
<section class="hero">
<div class="brand">
<div class="logo">CC</div>
<div>
<h2 style="margin:0;">COBIT-Chain™</h2>
<div style="color:#bfdbfe;">Enterprise Governance Platform • Evidence Integrity • Audit Readiness</div>
</div>
</div>

<h1>Executive Platform Overview</h1>
<p>
COBIT-Chain is presented as a modular operational governance assurance platform.
It does not replace enterprise systems of record; it verifies continuity, accountability,
evidence integrity, audit posture, lineage, and governance readiness across operational workflows.
</p>

<span class="badge">Governance Assurance Engine</span>
<span class="badge">Modular Workspaces</span>
<span class="badge">Power BI Ready</span>
<span class="badge">Sanitized Demo Mode</span>
</section>

<div class="wrap">
<div class="grid4">
<div class="kpi"><span>Workspaces</span><strong>{{ kpis.workspaces }}</strong></div>
<div class="kpi"><span>Live Modules</span><strong>{{ kpis.live_modules }}</strong></div>
<div class="kpi"><span>Demo Modules</span><strong>{{ kpis.demo_modules }}</strong></div>
<div class="kpi"><span>Assurance Domains</span><strong>{{ kpis.assurance_domains }}</strong></div>
</div>

<div class="panel">
<h2>Governance Architecture</h2>
<div class="arch">
{% for a in platform_layers %}
<div class="arch-card">
<b>{{ a.layer }}</b>
<span>{{ a.examples }}</span>
<p>{{ a.role }}</p>
</div>
{% endfor %}
</div>
</div>

<div class="panel">
<h2>Available Governance Workspaces</h2>
<div class="modules">
{% for w in workspaces %}
<div class="card">
{% if w.status == "LIVE" %}
<div class="status live">{{ w.status }}</div>
{% elif w.status == "DEMO" %}
<div class="status demo">{{ w.status }}</div>
{% else %}
<div class="status roadmap">{{ w.status }}</div>
{% endif %}
<h3>{{ w.name }}</h3>
<p>{{ w.description }}</p>
<a href="{{ w.route }}">Open Workspace</a>
</div>
{% endfor %}
</div>
</div>

<div class="panel">
<h2>Executive Value Proposition</h2>
<ul>
{% for v in value_points %}
<li>{{ v }}</li>
{% endfor %}
</ul>
</div>

<div class="panel">
<h2>Positioning Boundary</h2>
<p><b>Do not position as:</b> a replacement for ServiceNow, Blue Mountain, Veeva, myAccess, or validated systems.</p>
<p><b>Position as:</b> a governance assurance and evidence integrity layer above operational systems.</p>
</div>
</div>

<div class="footer">COBIT-Chain™ Executive Platform Overview</div>
</body>
</html>
"""
    return render_template_string(
        template,
        kpis=kpis,
        platform_layers=platform_layers,
        value_points=value_points,
        workspaces=WORKSPACES
    )


'''
    text = text[:k] + fn + text[k:]

required = [
    "def render_executive_platform_landing():",
    "return render_executive_platform_landing()",
    "Executive Platform Overview",
    "Available Governance Workspaces"
]
missing = [x for x in required if x not in text]
if missing:
    raise SystemExit("ERROR missing: " + ", ".join(missing))

p.write_text(text, encoding="utf-8")
print("SUCCESS: Executive Platform Landing Page restored.")
