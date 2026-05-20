from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_INSPECTION_RADAR_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Inspection Radar Engine already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_INSPECTION_RADAR_ENGINE_V1_ACTIVE
# ============================================================

IRLT_INSPECTION_RADAR_V1 = [
    {
        "radar": "Audit Defense Coverage",
        "signal": 97,
        "state": "Protected"
    },
    {
        "radar": "Evidence Integrity Tracking",
        "signal": 99,
        "state": "Verified"
    },
    {
        "radar": "CAPA Escalation Monitoring",
        "signal": 86,
        "state": "Observed"
    },
    {
        "radar": "Cold Chain Surveillance",
        "signal": 92,
        "state": "Stable"
    },
    {
        "radar": "Training Governance Detection",
        "signal": 91,
        "state": "Controlled"
    },
    {
        "radar": "Dose Traceability Monitoring",
        "signal": 99,
        "state": "Certified"
    }
]

@app.route("/irlt-commercial-readiness/inspection-radar")
def irlt_inspection_radar():

    radar_score = round(
        sum(x["signal"] for x in IRLT_INSPECTION_RADAR_V1)
        / len(IRLT_INSPECTION_RADAR_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>Inspection Radar Engine</title>

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

        <h1>Inspection Radar Engine</h1>

        <p>
            Enterprise inspection radar environment for
            operational surveillance synchronization,
            governance defense visibility,
            regulatory monitoring continuity,
            and radiopharma inspection intelligence.
        </p>

        <div class="score">
            {{ radar_score }}%
        </div>

        <div class="grid">

            {% for row in radar %}

            <div class="card">

                <h2>{{ row.radar }}</h2>

                <p>
                    Signal Strength: {{ row.signal }}%
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
    radar=IRLT_INSPECTION_RADAR_V1,
    radar_score=radar_score
    )


@app.route("/irlt-commercial-readiness/inspection-radar/api")
def irlt_inspection_radar_api():

    return jsonify({
        "radar_score": round(
            sum(x["signal"] for x in IRLT_INSPECTION_RADAR_V1)
            / len(IRLT_INSPECTION_RADAR_V1)
        ),
        "radar": IRLT_INSPECTION_RADAR_V1
    })

# ============================================================
# END IRLT_INSPECTION_RADAR_ENGINE_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("Inspection Radar Engine appended successfully.")
