from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_OPERATIONAL_CONSTELLATION_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Operational Constellation already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_OPERATIONAL_CONSTELLATION_ENGINE_V1_ACTIVE
# ============================================================

IRLT_CONSTELLATION_V1 = [
    {
        "node": "Commercial Readiness",
        "stability": 96,
        "state": "Operational"
    },
    {
        "node": "Inspection Defense",
        "stability": 95,
        "state": "Protected"
    },
    {
        "node": "Evidence Intelligence",
        "stability": 98,
        "state": "Verified"
    },
    {
        "node": "Cold Chain Governance",
        "stability": 92,
        "state": "Stable"
    },
    {
        "node": "CAPA Recovery",
        "stability": 85,
        "state": "Observed"
    },
    {
        "node": "Dose Traceability",
        "stability": 99,
        "state": "Certified"
    }
]

@app.route("/irlt-commercial-readiness/operational-constellation")
def irlt_operational_constellation():

    constellation_score = round(
        sum(x["stability"] for x in IRLT_CONSTELLATION_V1)
        / len(IRLT_CONSTELLATION_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>Operational Constellation Engine</title>

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

        <h1>Operational Constellation Engine</h1>

        <p>
            Enterprise constellation intelligence environment for
            commercialization synchronization,
            operational survivability mapping,
            governance coordination visibility,
            and inspection readiness orchestration.
        </p>

        <div class="score">
            {{ constellation_score }}%
        </div>

        <div class="grid">

            {% for row in constellation %}

            <div class="card">

                <h2>{{ row.node }}</h2>

                <p>
                    Stability: {{ row.stability }}%
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
    constellation=IRLT_CONSTELLATION_V1,
    constellation_score=constellation_score
    )


@app.route("/irlt-commercial-readiness/operational-constellation/api")
def irlt_operational_constellation_api():

    return jsonify({
        "constellation_score": round(
            sum(x["stability"] for x in IRLT_CONSTELLATION_V1)
            / len(IRLT_CONSTELLATION_V1)
        ),
        "constellation": IRLT_CONSTELLATION_V1
    })

# ============================================================
# END IRLT_OPERATIONAL_CONSTELLATION_ENGINE_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("Operational Constellation Engine appended successfully.")
