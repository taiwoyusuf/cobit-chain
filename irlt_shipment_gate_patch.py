from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_SHIPMENT_GATE_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Shipment Gate View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_SHIPMENT_GATE_VIEW_V1_ACTIVE
# ============================================================

IRLT_SHIPMENT_GATE_V1 = [
    {
        "gate": "Shipment Authorization",
        "condition": "Shipment must be authorized only after QA release, logistics confirmation, and dose readiness validation.",
        "status": "Controlled",
        "score": 96
    },
    {
        "gate": "Courier Handoff Governance",
        "condition": "Courier handoff must be documented with custody owner, timestamp, route, and shipment condition.",
        "status": "Verified",
        "score": 97
    },
    {
        "gate": "Route and Timing Assurance",
        "condition": "Shipment route and timing must align with dose viability, treatment schedule, and operational constraints.",
        "status": "Critical",
        "score": 98
    },
    {
        "gate": "Shipment Evidence Capture",
        "condition": "Shipment records, temperature data, handoff logs, and exception records must be captured and traceable.",
        "status": "Evidence Required",
        "score": 95
    },
    {
        "gate": "Exception Escalation",
        "condition": "Shipment delay, temperature excursion, custody issue, or delivery exception must trigger governance review.",
        "status": "Monitored",
        "score": 92
    },
    {
        "gate": "Delivery Confirmation",
        "condition": "Delivery confirmation must be linked to receiving evidence, treatment coordination, and inspection defensibility.",
        "status": "Defensible",
        "score": 96
    }
]

@app.route("/irlt-commercial-readiness/shipment-gate")
def irlt_shipment_gate():

    shipment_score = round(
        sum(x["score"] for x in IRLT_SHIPMENT_GATE_V1)
        / len(IRLT_SHIPMENT_GATE_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Shipment Gate</title>

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

        <h1>IRLT Shipment Gate</h1>

        <p>
            Governed shipment readiness layer for IRLT operations. This view checks whether shipment
            authorization, courier handoff, route timing, evidence capture, exception escalation,
            and delivery confirmation are controlled before treatment-impacting risk occurs.
        </p>

        <div class="score">{{ shipment_score }}%</div>

        <p>Overall Shipment Governance Confidence</p>

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
    gates=IRLT_SHIPMENT_GATE_V1,
    shipment_score=shipment_score
    )


@app.route("/irlt-commercial-readiness/shipment-gate/api")
def irlt_shipment_gate_api():

    return jsonify({
        "shipment_score": round(
            sum(x["score"] for x in IRLT_SHIPMENT_GATE_V1)
            / len(IRLT_SHIPMENT_GATE_V1)
        ),
        "gates": IRLT_SHIPMENT_GATE_V1
    })

# ============================================================
# END IRLT_SHIPMENT_GATE_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Shipment Gate View appended successfully.")
