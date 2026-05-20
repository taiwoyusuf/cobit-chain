from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_OPERATIONAL_DIGITAL_TWIN_GRID_V1_ACTIVE"

if MARKER in text:
    print("Operational Digital Twin already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_OPERATIONAL_DIGITAL_TWIN_GRID_V1_ACTIVE
# ============================================================

IRLT_OPERATIONAL_TWIN_V1 = [
    {
        "system": "Commercial Release",
        "health": 96,
        "state": "Stable"
    },
    {
        "system": "Inspection Defense",
        "health": 94,
        "state": "Protected"
    },
    {
        "system": "Dose Traceability",
        "health": 99,
        "state": "Verified"
    },
    {
        "system": "Cold Chain Governance",
        "health": 91,
        "state": "Controlled"
    },
    {
        "system": "CAPA Governance",
        "health": 82,
        "state": "Observed"
    },
    {
        "system": "Evidence Integrity",
        "health": 97,
        "state": "Strong"
    }
]

@app.route("/irlt-commercial-readiness/operational-twin")
def irlt_operational_twin():

    twin_score = round(
        sum(x["health"] for x in IRLT_OPERATIONAL_TWIN_V1)
        / len(IRLT_OPERATIONAL_TWIN_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>Operational Digital Twin</title>

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

        <h1>Operational Digital Twin</h1>

        <p>
            Enterprise operational twin intelligence environment
            for commercialization readiness monitoring,
            governance survivability visibility,
            radiopharma operational cognition,
            and inspection defense synchronization.
        </p>

        <div class="score">
            {{ twin_score }}%
        </div>

        <div class="grid">

            {% for row in twin %}

            <div class="card">

                <h2>{{ row.system }}</h2>

                <p>
                    Health: {{ row.health }}%
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
    twin=IRLT_OPERATIONAL_TWIN_V1,
    twin_score=twin_score
    )


@app.route("/irlt-commercial-readiness/operational-twin/api")
def irlt_operational_twin_api():

    return jsonify({
        "twin_score": round(
            sum(x["health"] for x in IRLT_OPERATIONAL_TWIN_V1)
            / len(IRLT_OPERATIONAL_TWIN_V1)
        ),
        "twin": IRLT_OPERATIONAL_TWIN_V1
    })

# ============================================================
# END IRLT_OPERATIONAL_DIGITAL_TWIN_GRID_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("Operational Digital Twin appended successfully.")
