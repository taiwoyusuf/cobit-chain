from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_INSPECTION_WARROOM_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Inspection Warroom already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_INSPECTION_WARROOM_ENGINE_V1_ACTIVE
# ============================================================

IRLT_INSPECTION_WARROOM_V1 = [
    {
        "zone": "Audit Defense",
        "integrity": 96,
        "state": "Defensible"
    },
    {
        "zone": "Evidence Verification",
        "integrity": 98,
        "state": "Protected"
    },
    {
        "zone": "CAPA Exposure",
        "integrity": 82,
        "state": "Observed"
    },
    {
        "zone": "Training Governance",
        "integrity": 91,
        "state": "Controlled"
    },
    {
        "zone": "Environmental Monitoring",
        "integrity": 89,
        "state": "Stable"
    },
    {
        "zone": "Dose Traceability",
        "integrity": 99,
        "state": "Verified"
    }
]

@app.route("/irlt-commercial-readiness/inspection-warroom")
def irlt_inspection_warroom():

    warroom_score = round(
        sum(x["integrity"] for x in IRLT_INSPECTION_WARROOM_V1)
        / len(IRLT_INSPECTION_WARROOM_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>Inspection Warroom</title>

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

        <h1>Inspection Warroom</h1>

        <p>
            Enterprise inspection defense environment for
            regulatory survivability,
            operational governance escalation,
            audit defense intelligence,
            and evidence integrity coordination.
        </p>

        <div class="score">
            {{ warroom_score }}%
        </div>

        <div class="grid">

            {% for row in warroom %}

            <div class="card">

                <h2>{{ row.zone }}</h2>

                <p>
                    Integrity: {{ row.integrity }}%
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
    warroom=IRLT_INSPECTION_WARROOM_V1,
    warroom_score=warroom_score
    )


@app.route("/irlt-commercial-readiness/inspection-warroom/api")
def irlt_inspection_warroom_api():

    return jsonify({
        "warroom_score": round(
            sum(x["integrity"] for x in IRLT_INSPECTION_WARROOM_V1)
            / len(IRLT_INSPECTION_WARROOM_V1)
        ),
        "warroom": IRLT_INSPECTION_WARROOM_V1
    })

# ============================================================
# END IRLT_INSPECTION_WARROOM_ENGINE_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("Inspection Warroom appended successfully.")
