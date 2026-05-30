from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_MASTER_NAVIGATION_HUB_V1_ACTIVE"

if MARKER in text:
    print("IRLT Master Navigation Hub already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_MASTER_NAVIGATION_HUB_V1_ACTIVE
# ============================================================

IRLT_MASTER_ROUTES_V1 = [
    {"name": "Governance Omega", "url": "/irlt-commercial-readiness/governance-omega"},
    {"name": "Governance Titan", "url": "/irlt-commercial-readiness/governance-titan"},
    {"name": "Governance Citadel", "url": "/irlt-commercial-readiness/governance-citadel"},
    {"name": "Governance Omniverse", "url": "/irlt-commercial-readiness/governance-omniverse"},
    {"name": "Governance Infinity", "url": "/irlt-commercial-readiness/governance-infinity"},
    {"name": "Governance Genesis", "url": "/irlt-commercial-readiness/governance-genesis"},
    {"name": "Governance Origin", "url": "/irlt-commercial-readiness/governance-origin"},
    {"name": "Governance Nebula", "url": "/irlt-commercial-readiness/governance-nebula"},
    {"name": "Governance Cosmos", "url": "/irlt-commercial-readiness/governance-cosmos"},
    {"name": "Governance Beacon", "url": "/irlt-commercial-readiness/governance-beacon"},
    {"name": "Governance HyperGrid", "url": "/irlt-commercial-readiness/governance-hypergrid"},
    {"name": "Operational Nexus", "url": "/irlt-commercial-readiness/operational-nexus"},
    {"name": "Operational Singularity", "url": "/irlt-commercial-readiness/operational-singularity"},
    {"name": "Trust Fusion Core", "url": "/irlt-commercial-readiness/trust-fusion-core"},
    {"name": "Inspection Radar", "url": "/irlt-commercial-readiness/inspection-radar"},
    {"name": "Survivability Matrix", "url": "/irlt-commercial-readiness/survivability-matrix"},
    {"name": "Command Singularity", "url": "/irlt-commercial-readiness/command-singularity"}
]

@app.route("/irlt-commercial-readiness/navigation-hub")
def irlt_master_navigation_hub():

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Master Navigation Hub</title>

        <style>

            body{
                margin:0;
                padding:40px;
                background:
                    radial-gradient(circle at top left, rgba(255,122,24,0.18), transparent 30%),
                    linear-gradient(135deg,#050608,#10151d,#050608);
                color:white;
                font-family:Arial;
            }

            h1{
                color:#ff9f1c;
                font-size:72px;
                margin-bottom:10px;
            }

            p{
                color:#bfc7d4;
                line-height:1.7;
                max-width:1100px;
            }

            .grid{
                display:grid;
                grid-template-columns:repeat(3,1fr);
                gap:20px;
                margin-top:30px;
            }

            .card{
                background:#161d28;
                border-radius:20px;
                padding:24px;
                border:1px solid rgba(255,255,255,0.08);
            }

            .card h2{
                color:#ff9f1c;
                margin-top:0;
            }

            a{
                color:#ffd7ad;
                text-decoration:none;
                font-weight:bold;
            }

            .pill{
                display:inline-block;
                padding:8px 14px;
                border-radius:999px;
                background:rgba(255,122,24,0.15);
                border:1px solid rgba(255,122,24,0.35);
                margin-top:12px;
            }

        </style>

    </head>

    <body>

        <h1>IRLT Master Navigation Hub</h1>

        <p>
            Central access layer for the IRLT Commercial Readiness Governance Command Center.
            This hub links the governance intelligence engines, survivability layers,
            inspection defense environments, and operational trust modules in one place.
        </p>

        <div class="grid">

            {% for row in routes %}

            <div class="card">

                <h2>{{ row.name }}</h2>

                <a href="{{ row.url }}">Open Module</a>

                <br>

                <div class="pill">
                    Active Governance Engine
                </div>

            </div>

            {% endfor %}

        </div>

    </body>

    </html>

    ''', routes=IRLT_MASTER_ROUTES_V1)


@app.route("/irlt-commercial-readiness/navigation-hub/api")
def irlt_master_navigation_hub_api():

    return jsonify({
        "total_modules": len(IRLT_MASTER_ROUTES_V1),
        "routes": IRLT_MASTER_ROUTES_V1
    })

# ============================================================
# END IRLT_MASTER_NAVIGATION_HUB_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Master Navigation Hub appended successfully.")
