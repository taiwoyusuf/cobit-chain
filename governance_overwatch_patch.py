from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_GOVERNANCE_OVERWATCH_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Governance Overwatch Engine already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_GOVERNANCE_OVERWATCH_ENGINE_V1_ACTIVE
# ============================================================

IRLT_GOVERNANCE_OVERWATCH_V1 = [
    {
        "watchtower": "Commercial Launch Oversight",
        "awareness": 97,
        "state": "Operational"
    },
    {
        "watchtower": "Inspection Defense Visibility",
        "awareness": 96,
        "state": "Protected"
    },
    {
        "watchtower": "Evidence Governance Tracking",
        "awareness": 99,
        "state": "Verified"
    },
    {
        "watchtower": "Cold Chain Monitoring",
        "awareness": 93,
        "state": "Stable"
    },
    {
        "watchtower": "CAPA Escalation Surveillance",
        "awareness": 87,
        "state": "Observed"
    },
    {
        "watchtower": "Dose Traceability Intelligence",
        "awareness": 99,
        "state": "Certified"
    }
]

@app.route("/irlt-commercial-readiness/governance-overwatch")
def irlt_governance_overwatch():

    overwatch_score = round(
        sum(x["awareness"] for x in IRLT_GOVERNANCE_OVERWATCH_V1)
        / len(IRLT_GOVERNANCE_OVERWATCH_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>Governance Overwatch Engine</title>

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

        <h1>Governance Overwatch Engine</h1>

        <p>
            Enterprise governance overwatch environment for
            commercialization surveillance synchronization,
            operational survivability visibility,
            inspection defense awareness,
            and radiopharma governance intelligence.
        </p>

        <div class="score">
            {{ overwatch_score }}%
        </div>

        <div class="grid">

            {% for row in overwatch %}

            <div class="card">

                <h2>{{ row.watchtower }}</h2>

                <p>
                    Awareness Index: {{ row.awareness }}%
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
    overwatch=IRLT_GOVERNANCE_OVERWATCH_V1,
    overwatch_score=overwatch_score
    )


@app.route("/irlt-commercial-readiness/governance-overwatch/api")
def irlt_governance_overwatch_api():

    return jsonify({
        "overwatch_score": round(
            sum(x["awareness"] for x in IRLT_GOVERNANCE_OVERWATCH_V1)
            / len(IRLT_GOVERNANCE_OVERWATCH_V1)
        ),
        "overwatch": IRLT_GOVERNANCE_OVERWATCH_V1
    })

# ============================================================
# END IRLT_GOVERNANCE_OVERWATCH_ENGINE_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("Governance Overwatch Engine appended successfully.")
