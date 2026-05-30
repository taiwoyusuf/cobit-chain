from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_EXECUTIVE_DEMO_STORYBOARD_V1_ACTIVE"

if MARKER in text:
    print("IRLT Executive Demo Storyboard already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_EXECUTIVE_DEMO_STORYBOARD_V1_ACTIVE
# ============================================================

IRLT_DEMO_STORYBOARD_V1 = [
    {
        "step": "1",
        "title": "Executive Launchpad",
        "message": "Start with the unified readiness score and executive access points.",
        "route": "/irlt-commercial-readiness/executive-launchpad"
    },
    {
        "step": "2",
        "title": "Navigation Hub",
        "message": "Show all active governance engines in one controlled access layer.",
        "route": "/irlt-commercial-readiness/navigation-hub"
    },
    {
        "step": "3",
        "title": "Governance Omega",
        "message": "Demonstrate top-level commercialization governance readiness.",
        "route": "/irlt-commercial-readiness/governance-omega"
    },
    {
        "step": "4",
        "title": "Inspection Radar",
        "message": "Show inspection surveillance, audit readiness, and evidence visibility.",
        "route": "/irlt-commercial-readiness/inspection-radar"
    },
    {
        "step": "5",
        "title": "Survivability Matrix",
        "message": "Explain operational survivability and commercialization resilience.",
        "route": "/irlt-commercial-readiness/survivability-matrix"
    },
    {
        "step": "6",
        "title": "Trust Fusion Core",
        "message": "Close with the operational trust and evidence integrity layer.",
        "route": "/irlt-commercial-readiness/trust-fusion-core"
    }
]

@app.route("/irlt-commercial-readiness/demo-storyboard")
def irlt_demo_storyboard():

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Executive Demo Storyboard</title>

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
                font-size:76px;
                margin-bottom:10px;
            }

            p{
                color:#bfc7d4;
                line-height:1.7;
                max-width:1150px;
            }

            .timeline{
                margin-top:34px;
                display:grid;
                grid-template-columns:1fr;
                gap:18px;
            }

            .step{
                background:#161d28;
                border-radius:22px;
                padding:24px;
                border:1px solid rgba(255,255,255,0.08);
                display:grid;
                grid-template-columns:100px 1fr 160px;
                gap:20px;
                align-items:center;
            }

            .num{
                font-size:56px;
                color:#ff9f1c;
                font-weight:bold;
            }

            h2{
                color:#ff9f1c;
                margin:0 0 10px 0;
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
            }

        </style>

    </head>

    <body>

        <h1>IRLT Executive Demo Storyboard</h1>

        <p>
            Guided executive demo path for Nicole and IRLT leadership.
            This storyboard explains the recommended sequence for presenting the platform:
            launchpad, navigation, commercialization governance, inspection intelligence,
            survivability, and operational trust.
        </p>

        <div class="timeline">

            {% for row in storyboard %}

            <div class="step">

                <div class="num">{{ row.step }}</div>

                <div>
                    <h2>{{ row.title }}</h2>
                    <p>{{ row.message }}</p>
                </div>

                <div>
                    <a href="{{ row.route }}">Open View</a>
                    <br><br>
                    <span class="pill">Demo Step</span>
                </div>

            </div>

            {% endfor %}

        </div>

    </body>

    </html>

    ''', storyboard=IRLT_DEMO_STORYBOARD_V1)


@app.route("/irlt-commercial-readiness/demo-storyboard/api")
def irlt_demo_storyboard_api():

    return jsonify({
        "total_steps": len(IRLT_DEMO_STORYBOARD_V1),
        "storyboard": IRLT_DEMO_STORYBOARD_V1
    })

# ============================================================
# END IRLT_EXECUTIVE_DEMO_STORYBOARD_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Executive Demo Storyboard appended successfully.")
