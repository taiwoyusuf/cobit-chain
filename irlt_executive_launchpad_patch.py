from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_EXECUTIVE_LAUNCHPAD_V1_ACTIVE"

if MARKER in text:
    print("IRLT Executive Launchpad already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_EXECUTIVE_LAUNCHPAD_V1_ACTIVE
# ============================================================

IRLT_EXECUTIVE_LAUNCHPAD_V1 = [
    {
        "area": "Commercialization Readiness",
        "score": 98,
        "route": "/irlt-commercial-readiness/governance-omega"
    },
    {
        "area": "Inspection Defense",
        "score": 97,
        "route": "/irlt-commercial-readiness/inspection-radar"
    },
    {
        "area": "Evidence Integrity",
        "score": 99,
        "route": "/irlt-commercial-readiness/trust-fusion-core"
    },
    {
        "area": "Operational Survivability",
        "score": 96,
        "route": "/irlt-commercial-readiness/survivability-matrix"
    },
    {
        "area": "Governance Navigation",
        "score": 100,
        "route": "/irlt-commercial-readiness/navigation-hub"
    },
    {
        "area": "Executive Command",
        "score": 98,
        "route": "/irlt-commercial-readiness/command-singularity"
    }
]

@app.route("/irlt-commercial-readiness/executive-launchpad")
def irlt_executive_launchpad():

    launchpad_score = round(
        sum(x["score"] for x in IRLT_EXECUTIVE_LAUNCHPAD_V1)
        / len(IRLT_EXECUTIVE_LAUNCHPAD_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Executive Launchpad</title>

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

            .score{
                font-size:120px;
                color:#ff9f1c;
                margin:30px 0;
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

        <h1>IRLT Executive Launchpad</h1>

        <p>
            Executive landing page for the IRLT Commercial Readiness Governance Command Center.
            This view gives leadership a fast entry point into commercialization readiness,
            inspection defense, evidence integrity, operational survivability, and governance navigation.
        </p>

        <div class="score">
            {{ launchpad_score }}%
        </div>

        <p>
            Unified Executive Readiness Score
        </p>

        <div class="grid">

            {% for row in launchpad %}

            <div class="card">

                <h2>{{ row.area }}</h2>

                <p>Score: {{ row.score }}%</p>

                <a href="{{ row.route }}">Open View</a>

                <br>

                <div class="pill">
                    Executive Access Point
                </div>

            </div>

            {% endfor %}

        </div>

    </body>

    </html>

    ''',
    launchpad=IRLT_EXECUTIVE_LAUNCHPAD_V1,
    launchpad_score=launchpad_score
    )


@app.route("/irlt-commercial-readiness/executive-launchpad/api")
def irlt_executive_launchpad_api():

    return jsonify({
        "launchpad_score": round(
            sum(x["score"] for x in IRLT_EXECUTIVE_LAUNCHPAD_V1)
            / len(IRLT_EXECUTIVE_LAUNCHPAD_V1)
        ),
        "launchpad": IRLT_EXECUTIVE_LAUNCHPAD_V1
    })

# ============================================================
# END IRLT_EXECUTIVE_LAUNCHPAD_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Executive Launchpad appended successfully.")
