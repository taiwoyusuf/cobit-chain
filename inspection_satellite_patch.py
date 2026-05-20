from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_INSPECTION_SATELLITE_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Inspection Satellite Engine already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_INSPECTION_SATELLITE_ENGINE_V1_ACTIVE
# ============================================================

IRLT_INSPECTION_SATELLITE_V1 = [
    {
        "satellite": "Audit Defense Monitoring",
        "coverage": 96,
        "state": "Protected"
    },
    {
        "satellite": "Evidence Surveillance",
        "coverage": 98,
        "state": "Verified"
    },
    {
        "satellite": "CAPA Escalation Visibility",
        "coverage": 84,
        "state": "Observed"
    },
    {
        "satellite": "Cold Chain Monitoring",
        "coverage": 92,
        "state": "Stable"
    },
    {
        "satellite": "Training Governance Tracking",
        "coverage": 90,
        "state": "Controlled"
    },
    {
        "satellite": "Dose Traceability Oversight",
        "coverage": 99,
        "state": "Certified"
    }
]

@app.route("/irlt-commercial-readiness/inspection-satellite")
def irlt_inspection_satellite():

    satellite_score = round(
        sum(x["coverage"] for x in IRLT_INSPECTION_SATELLITE_V1)
        / len(IRLT_INSPECTION_SATELLITE_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>Inspection Satellite Engine</title>

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

        <h1>Inspection Satellite Engine</h1>

        <p>
            Enterprise inspection surveillance environment for
            regulatory visibility synchronization,
            governance monitoring continuity,
            operational inspection awareness,
            and evidence oversight orchestration.
        </p>

        <div class="score">
            {{ satellite_score }}%
        </div>

        <div class="grid">

            {% for row in satellite %}

            <div class="card">

                <h2>{{ row.satellite }}</h2>

                <p>
                    Coverage: {{ row.coverage }}%
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
    satellite=IRLT_INSPECTION_SATELLITE_V1,
    satellite_score=satellite_score
    )


@app.route("/irlt-commercial-readiness/inspection-satellite/api")
def irlt_inspection_satellite_api():

    return jsonify({
        "satellite_score": round(
            sum(x["coverage"] for x in IRLT_INSPECTION_SATELLITE_V1)
            / len(IRLT_INSPECTION_SATELLITE_V1)
        ),
        "satellite": IRLT_INSPECTION_SATELLITE_V1
    })

# ============================================================
# END IRLT_INSPECTION_SATELLITE_ENGINE_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("Inspection Satellite Engine appended successfully.")
