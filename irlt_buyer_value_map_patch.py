from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_BUYER_VALUE_MAP_V1_ACTIVE"

if MARKER in text:
    print("IRLT Buyer Value Map already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_BUYER_VALUE_MAP_V1_ACTIVE
# ============================================================

IRLT_BUYER_VALUE_MAP_V1 = [
    {
        "buyer": "QA Leadership",
        "value": "Inspection defensibility and evidence readiness",
        "score": 98
    },
    {
        "buyer": "Operations Leadership",
        "value": "Commercial readiness and operational survivability visibility",
        "score": 97
    },
    {
        "buyer": "Compliance Leadership",
        "value": "Governed evidence, audit traceability, and risk visibility",
        "score": 98
    },
    {
        "buyer": "Radiopharma Leadership",
        "value": "Dose traceability, cold-chain governance, and treatment continuity assurance",
        "score": 99
    },
    {
        "buyer": "IT / Digital Leadership",
        "value": "Governance overlay above existing enterprise systems",
        "score": 96
    },
    {
        "buyer": "Executive Sponsors",
        "value": "One operational trust picture for commercialization readiness",
        "score": 99
    }
]

@app.route("/irlt-commercial-readiness/buyer-value-map")
def irlt_buyer_value_map():

    value_score = round(
        sum(x["score"] for x in IRLT_BUYER_VALUE_MAP_V1)
        / len(IRLT_BUYER_VALUE_MAP_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Buyer Value Map</title>

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
                padding:24px;
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

        <h1>IRLT Buyer Value Map</h1>

        <p>
            Executive buyer-value map showing how the IRLT Commercial Readiness
            Governance Command Center creates value for QA, Operations, Compliance,
            Radiopharma Leadership, IT/Digital, and Executive Sponsors.
        </p>

        <div class="score">{{ value_score }}%</div>

        <p>Buyer Value Alignment Score</p>

        <div class="grid">

            {% for row in buyers %}

            <div class="card">

                <h2>{{ row.buyer }}</h2>

                <p>{{ row.value }}</p>

                <div class="pill">Value Score {{ row.score }}%</div>

            </div>

            {% endfor %}

        </div>

    </body>

    </html>

    ''',
    buyers=IRLT_BUYER_VALUE_MAP_V1,
    value_score=value_score
    )


@app.route("/irlt-commercial-readiness/buyer-value-map/api")
def irlt_buyer_value_map_api():

    return jsonify({
        "value_score": round(
            sum(x["score"] for x in IRLT_BUYER_VALUE_MAP_V1)
            / len(IRLT_BUYER_VALUE_MAP_V1)
        ),
        "buyers": IRLT_BUYER_VALUE_MAP_V1
    })

# ============================================================
# END IRLT_BUYER_VALUE_MAP_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Buyer Value Map appended successfully.")
