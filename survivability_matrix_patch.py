from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_SURVIVABILITY_MATRIX_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Survivability Matrix Engine already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_SURVIVABILITY_MATRIX_ENGINE_V1_ACTIVE
# ============================================================

IRLT_SURVIVABILITY_MATRIX_V1 = [
    {
        "matrix": "Commercial Continuity",
        "survivability": 97,
        "state": "Operational"
    },
    {
        "matrix": "Inspection Defense",
        "survivability": 96,
        "state": "Protected"
    },
    {
        "matrix": "Evidence Preservation",
        "survivability": 99,
        "state": "Verified"
    },
    {
        "matrix": "Cold Chain Resilience",
        "survivability": 92,
        "state": "Stable"
    },
    {
        "matrix": "CAPA Recovery Intelligence",
        "survivability": 86,
        "state": "Observed"
    },
    {
        "matrix": "Dose Governance",
        "survivability": 99,
        "state": "Certified"
    }
]

@app.route("/irlt-commercial-readiness/survivability-matrix")
def irlt_survivability_matrix():

    survivability_score = round(
        sum(x["survivability"] for x in IRLT_SURVIVABILITY_MATRIX_V1)
        / len(IRLT_SURVIVABILITY_MATRIX_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>Survivability Matrix Engine</title>

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

        <h1>Survivability Matrix Engine</h1>

        <p>
            Enterprise survivability intelligence environment for
            commercialization resilience synchronization,
            governance continuity preservation,
            inspection survivability coordination,
            and radiopharma operational defense orchestration.
        </p>

        <div class="score">
            {{ survivability_score }}%
        </div>

        <div class="grid">

            {% for row in survivability %}

            <div class="card">

                <h2>{{ row.matrix }}</h2>

                <p>
                    Survivability Index: {{ row.survivability }}%
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
    survivability=IRLT_SURVIVABILITY_MATRIX_V1,
    survivability_score=survivability_score
    )


@app.route("/irlt-commercial-readiness/survivability-matrix/api")
def irlt_survivability_matrix_api():

    return jsonify({
        "survivability_score": round(
            sum(x["survivability"] for x in IRLT_SURVIVABILITY_MATRIX_V1)
            / len(IRLT_SURVIVABILITY_MATRIX_V1)
        ),
        "survivability": IRLT_SURVIVABILITY_MATRIX_V1
    })

# ============================================================
# END IRLT_SURVIVABILITY_MATRIX_ENGINE_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("Survivability Matrix Engine appended successfully.")
