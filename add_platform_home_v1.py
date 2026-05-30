from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_PLATFORM_HOME_V1_ACTIVE"

if MARKER in text:
    print("Platform Home already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# COBITCHAIN_PLATFORM_HOME_V1_ACTIVE
# ============================================================

@app.route("/platform-home")
@app.route("/cobit-chain")
def cobitchain_platform_home_v1():

    html = """
    <html>
    <head>
        <title>COBIT-Chain Platform Home</title>
        <style>
            body{margin:0;padding:38px;background:linear-gradient(135deg,#050608,#11151f,#050608);color:white;font-family:Arial,Segoe UI,sans-serif}
            h1{font-size:82px;color:#ff9f1c;margin:0 0 14px;letter-spacing:-0.05em}
            h2{color:#ff9f1c;margin-top:0}
            p{color:#c6cfdb;line-height:1.7}
            .hero,.panel{background:#151c27;border-radius:28px;padding:30px;margin-bottom:24px;border:1px solid rgba(255,255,255,.08)}
            .grid{display:grid;grid-template-columns:repeat(3,1fr);gap:22px}
            .card{background:rgba(255,255,255,.04);border-radius:22px;padding:24px;border:1px solid rgba(255,255,255,.08)}
            .card strong{display:block;font-size:30px;color:#ff9f1c;margin-bottom:10px}
            a{color:#ff9f1c;text-decoration:none;font-weight:bold}
            .tag{display:inline-block;padding:8px 14px;border-radius:999px;background:rgba(255,122,24,.15);color:#ffd7ad;margin-right:8px;margin-bottom:8px}
            @media(max-width:1200px){.grid{grid-template-columns:1fr}h1{font-size:44px}}
        </style>
    </head>
    <body>

        <section class="hero">
            <h1>COBIT-Chain™ / AssuranceLayer™</h1>
            <p>
                Enterprise Governance Assurance and Operational Trust Platform for regulated operations.
                COBIT-Chain™ is not a replacement for ServiceNow, Veeva, MES, LIMS, ERP, CTMS, IAM, or quality systems.
                It is a governance assurance overlay that converts fragmented operational evidence into defensible trust, readiness, lineage, and inspection intelligence.
            </p>

            <span class="tag">Governance Assurance</span>
            <span class="tag">Evidence Lineage</span>
            <span class="tag">Operational Trust</span>
            <span class="tag">Inspection Readiness</span>
            <span class="tag">Human-Governed AI</span>
        </section>

        <section class="panel">
            <h2>Platform Modules</h2>

            <div class="grid">
                <div class="card">
                    <strong>RLTTrust™ / IRLTTrust™</strong>
                    IRLT commercialization readiness, radiopharma governance, chain-of-custody assurance, release defensibility, and inspection survivability.
                    <p><a href="/irlt-commercial-readiness/mission-control">Open Mission Control</a></p>
                </div>

                <div class="card">
                    <strong>Governance Passport™</strong>
                    Portable readiness certification based on evidence completeness, trust scoring, dependency health, and inspection defensibility.
                    <p><a href="/irlt-commercial-readiness/passport">Open Passport</a></p>
                </div>

                <div class="card">
                    <strong>AuditVault™</strong>
                    Immutable governance evidence, audit survivability, evidence verification, and inspection response readiness.
                    <p><a href="/irlt-commercial-readiness/audit-simulation">Open Audit Simulation</a></p>
                </div>

                <div class="card">
                    <strong>IntegrityLens™</strong>
                    Operational trust analytics, risk heatmaps, governance intelligence, anomaly visibility, and executive scoring.
                    <p><a href="/irlt-commercial-readiness/risk-heatmap">Open Risk Heatmap</a></p>
                </div>

                <div class="card">
                    <strong>Dependency Engine™</strong>
                    Cross-system dependency validation across quality, release, shipment, treatment, audit, and commercialization readiness.
                    <p><a href="/irlt-commercial-readiness/dependency-validation">Open Dependency Validation</a></p>
                </div>

                <div class="card">
                    <strong>AI Governance Copilot™</strong>
                    Advisory-only governance analysis while human governance remains the authoritative control layer.
                    <p><a href="/irlt-commercial-readiness/copilot">Open Copilot</a></p>
                </div>
            </div>
        </section>

        <section class="panel">
            <h2>Executive Screenshot Path</h2>

            <div class="grid">
                <div class="card">
                    <strong>Executive Mission Control</strong>
                    <a href="/irlt-commercial-readiness/mission-control">/irlt-commercial-readiness/mission-control</a>
                </div>

                <div class="card">
                    <strong>Commercial Readiness Dashboard</strong>
                    <a href="/irlt-commercial-readiness/commercial-dashboard">/irlt-commercial-readiness/commercial-dashboard</a>
                </div>

                <div class="card">
                    <strong>Evidence Lineage Intelligence</strong>
                    <a href="/irlt-commercial-readiness/evidence-lineage">/irlt-commercial-readiness/evidence-lineage</a>
                </div>
            </div>
        </section>

    </body>
    </html>
    """

    return html

# ============================================================
# END COBITCHAIN_PLATFORM_HOME_V1
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("COBIT-Chain Platform Home installed.")
