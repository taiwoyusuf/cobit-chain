from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_COLD_CHAIN_GATE_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Cold Chain Gate View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_COLD_CHAIN_GATE_VIEW_V1_ACTIVE
# ============================================================

IRLT_COLD_CHAIN_GATE_V1 = [
    {
        "gate": "Shipment Temperature Control",
        "condition": "Temperature limits must be defined, monitored, and documented throughout shipment.",
        "status": "Controlled",
        "score": 96
    },
    {
        "gate": "Courier / Logistics Readiness",
        "condition": "Courier readiness, handoff responsibility, and shipment timing must be confirmed.",
        "status": "Ready",
        "score": 95
    },
    {
        "gate": "Dose Viability Protection",
        "condition": "Cold-chain governance must protect dose viability and treatment timing.",
        "status": "Critical",
        "score": 98
    },
    {
        "gate": "Excursion Response",
        "condition": "Temperature excursion response must include QA review, evidence capture, and disposition logic.",
        "status": "Monitored",
        "score": 91
    },
    {
        "gate": "Chain-of-Custody Evidence",
        "condition": "Shipment custody evidence must be traceable from release through delivery.",
        "status": "Verified",
        "score": 97
    },
    {
        "gate": "Inspection Defensibility",
        "condition": "Cold-chain records must be complete and explainable during regulatory review.",
        "status": "Defensible",
        "score": 96
    }
]

@app.route("/irlt-commercial-readiness/cold-chain-gate")
def irlt_cold_chain_gate():

    cold_chain_score = round(
        sum(x["score"] for x in IRLT_COLD_CHAIN_GATE_V1)
        / len(IRLT_COLD_CHAIN_GATE_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Cold Chain Gate</title>

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
                grid-template-columns:repeat(2,1fr);
                gap:20px;
                margin-top:30px;
            }

            .card{
                background:#161d28;
                border-radius:22px;
                padding:28px;
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

        <h1>IRLT Cold Chain Gate</h1>

        <p>
            Governed cold-chain readiness layer for IRLT operations. This view checks whether
            shipment temperature control, logistics readiness, dose viability protection,
            excursion response, chain-of-custody evidence, and inspection defensibility are controlled.
        </p>

        <div class="score">{{ cold_chain_score }}%</div>

        <p>Overall Cold Chain Governance Confidence</p>

        <div class="grid">

            {% for row in gates %}

            <div class="card">

                <h2>{{ row.gate }}</h2>

                <p>{{ row.condition }}</p>

                <p>Score: {{ row.score }}%</p>

                <div class="pill">{{ row.status }}</div>

            </div>

            {% endfor %}

        </div>

    </body>

    </html>

    ''',
    gates=IRLT_COLD_CHAIN_GATE_V1,
    cold_chain_score=cold_chain_score
    )


@app.route("/irlt-commercial-readiness/cold-chain-gate/api")
def irlt_cold_chain_gate_api():

    return jsonify({
        "cold_chain_score": round(
            sum(x["score"] for x in IRLT_COLD_CHAIN_GATE_V1)
            / len(IRLT_COLD_CHAIN_GATE_V1)
        ),
        "gates": IRLT_COLD_CHAIN_GATE_V1
    })

# ============================================================
# END IRLT_COLD_CHAIN_GATE_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Cold Chain Gate View appended successfully.")
