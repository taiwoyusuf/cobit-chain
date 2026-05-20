from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_STRATEGIC_INTELLIGENCE_GRID_V1_ACTIVE"

if MARKER in text:
    print("Strategic Intelligence Grid already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_STRATEGIC_INTELLIGENCE_GRID_V1_ACTIVE
# ============================================================

IRLT_STRATEGIC_GRID_V1 = [
    {
        "domain": "Commercial Scale-Up",
        "confidence": 96,
        "state": "Stable"
    },
    {
        "domain": "Inspection Readiness",
        "confidence": 95,
        "state": "Defensible"
    },
    {
        "domain": "Dose Integrity",
        "confidence": 99,
        "state": "Verified"
    },
    {
        "domain": "Cold Chain Stability",
        "confidence": 91,
        "state": "Controlled"
    },
    {
        "domain": "CAPA Pressure",
        "confidence": 82,
        "state": "Observed"
    },
    {
        "domain": "Evidence Survivability",
        "confidence": 97,
        "state": "Protected"
    }
]

@app.route("/irlt-commercial-readiness/strategic-grid")
def irlt_strategic_grid():

    strategic_score = round(
        sum(x["confidence"] for x in IRLT_STRATEGIC_GRID_V1)
        / len(IRLT_STRATEGIC_GRID_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>Strategic Intelligence Grid</title>

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

        <h1>Strategic Intelligence Grid</h1>

        <p>
            Executive strategic governance intelligence environment
            for commercialization readiness,
            operational survivability,
            radiopharma trust continuity,
            and inspection defense orchestration.
        </p>

        <div class="score">
            {{ strategic_score }}%
        </div>

        <div class="grid">

            {% for row in grid %}

            <div class="card">

                <h2>{{ row.domain }}</h2>

                <p>
                    Confidence: {{ row.confidence }}%
                </p>

                <div class="pill">
                    {{ row.state }}
                </div>

            </div>

            {% endfor %}

        </div>

    </body>

    </html>

    ''',
    grid=IRLT_STRATEGIC_GRID_V1,
    strategic_score=strategic_score
    )


@app.route("/irlt-commercial-readiness/strategic-grid/api")
def irlt_strategic_grid_api():

    return jsonify({
        "strategic_score": round(
            sum(x["confidence"] for x in IRLT_STRATEGIC_GRID_V1)
            / len(IRLT_STRATEGIC_GRID_V1)
        ),
        "grid": IRLT_STRATEGIC_GRID_V1
    })

# ============================================================
# END IRLT_STRATEGIC_INTELLIGENCE_GRID_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("Strategic Intelligence Grid appended successfully.")
