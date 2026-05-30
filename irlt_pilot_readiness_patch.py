from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_PILOT_READINESS_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Pilot Readiness View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_PILOT_READINESS_VIEW_V1_ACTIVE
# ============================================================

IRLT_PILOT_READINESS_V1 = [
    {
        "pilot": "Executive Demo Readiness",
        "readiness": 98,
        "status": "Ready"
    },
    {
        "pilot": "Cloud Deployment Readiness",
        "readiness": 95,
        "status": "Validate After Push"
    },
    {
        "pilot": "Governance Storyline Readiness",
        "readiness": 99,
        "status": "Ready"
    },
    {
        "pilot": "Buyer Value Narrative",
        "readiness": 98,
        "status": "Ready"
    },
    {
        "pilot": "Technical Stability",
        "readiness": 94,
        "status": "Local Verified"
    },
    {
        "pilot": "Integration Roadmap",
        "readiness": 90,
        "status": "Planned"
    }
]

@app.route("/irlt-commercial-readiness/pilot-readiness")
def irlt_pilot_readiness():

    pilot_score = round(
        sum(x["readiness"] for x in IRLT_PILOT_READINESS_V1)
        / len(IRLT_PILOT_READINESS_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Pilot Readiness</title>

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
                border-radius:22px;
                padding:26px;
                border:1px solid rgba(255,255,255,0.08);
            }

            h2{
                color:#ff9f1c;
                margin-top:0;
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

        <h1>IRLT Pilot Readiness</h1>

        <p>
            Pilot readiness view showing whether the IRLT Commercial Readiness Governance Command Center
            is ready for executive demonstration, cloud validation, buyer storytelling, and next-stage integration planning.
        </p>

        <div class="score">{{ pilot_score }}%</div>

        <p>Overall Pilot Readiness Score</p>

        <div class="grid">

            {% for row in pilots %}

            <div class="card">

                <h2>{{ row.pilot }}</h2>

                <p>Readiness: {{ row.readiness }}%</p>

                <div class="pill">{{ row.status }}</div>

            </div>

            {% endfor %}

        </div>

    </body>

    </html>

    ''',
    pilots=IRLT_PILOT_READINESS_V1,
    pilot_score=pilot_score
    )


@app.route("/irlt-commercial-readiness/pilot-readiness/api")
def irlt_pilot_readiness_api():

    return jsonify({
        "pilot_score": round(
            sum(x["readiness"] for x in IRLT_PILOT_READINESS_V1)
            / len(IRLT_PILOT_READINESS_V1)
        ),
        "pilots": IRLT_PILOT_READINESS_V1
    })

# ============================================================
# END IRLT_PILOT_READINESS_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Pilot Readiness View appended successfully.")
