from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_GOVERNANCE_BEACON_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Governance Beacon Engine already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_GOVERNANCE_BEACON_ENGINE_V1_ACTIVE
# ============================================================

IRLT_GOVERNANCE_BEACON_V1 = [
    {
        "beacon": "Commercial Launch Readiness",
        "signal": 97,
        "state": "Operational"
    },
    {
        "beacon": "Inspection Defense",
        "signal": 96,
        "state": "Protected"
    },
    {
        "beacon": "Evidence Integrity",
        "signal": 99,
        "state": "Verified"
    },
    {
        "beacon": "Cold Chain Governance",
        "signal": 92,
        "state": "Stable"
    },
    {
        "beacon": "CAPA Recovery Tracking",
        "signal": 86,
        "state": "Observed"
    },
    {
        "beacon": "Dose Traceability",
        "signal": 99,
        "state": "Certified"
    }
]

@app.route("/irlt-commercial-readiness/governance-beacon")
def irlt_governance_beacon():

    beacon_score = round(
        sum(x["signal"] for x in IRLT_GOVERNANCE_BEACON_V1)
        / len(IRLT_GOVERNANCE_BEACON_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>Governance Beacon Engine</title>

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

        <h1>Governance Beacon Engine</h1>

        <p>
            Enterprise governance beacon environment for
            commercialization visibility synchronization,
            operational survivability signaling,
            inspection readiness coordination,
            and radiopharma trust intelligence.
        </p>

        <div class="score">
            {{ beacon_score }}%
        </div>

        <div class="grid">

            {% for row in beacon %}

            <div class="card">

                <h2>{{ row.beacon }}</h2>

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
    beacon=IRLT_GOVERNANCE_BEACON_V1,
    beacon_score=beacon_score
    )


@app.route("/irlt-commercial-readiness/governance-beacon/api")
def irlt_governance_beacon_api():

    return jsonify({
        "beacon_score": round(
            sum(x["signal"] for x in IRLT_GOVERNANCE_BEACON_V1)
            / len(IRLT_GOVERNANCE_BEACON_V1)
        ),
        "beacon": IRLT_GOVERNANCE_BEACON_V1
    })

# ============================================================
# END IRLT_GOVERNANCE_BEACON_ENGINE_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("Governance Beacon Engine appended successfully.")
