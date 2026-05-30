from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_TREATMENT_COORDINATION_GATE_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Treatment Coordination Gate View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_TREATMENT_COORDINATION_GATE_VIEW_V1_ACTIVE
# ============================================================

IRLT_TREATMENT_COORDINATION_GATE_V1 = [
    {
        "gate": "Patient Schedule Alignment",
        "condition": "Treatment schedule must align with dose production, release, shipment, and receiving readiness.",
        "status": "Critical",
        "score": 98
    },
    {
        "gate": "Site Readiness Confirmation",
        "condition": "Treatment site must confirm receiving capacity, handling readiness, and administration preparation.",
        "status": "Ready",
        "score": 96
    },
    {
        "gate": "Dose Arrival Verification",
        "condition": "Dose arrival must be verified against identity, shipment record, timing window, and custody evidence.",
        "status": "Verified",
        "score": 97
    },
    {
        "gate": "Clinical Coordination Handoff",
        "condition": "Operational handoff between manufacturing, logistics, QA, and treatment team must be documented.",
        "status": "Controlled",
        "score": 95
    },
    {
        "gate": "Exception Escalation",
        "condition": "Any delay, mismatch, handling issue, or schedule conflict must trigger governance escalation.",
        "status": "Monitored",
        "score": 92
    },
    {
        "gate": "Treatment Readiness Defensibility",
        "condition": "Treatment coordination evidence must be complete, explainable, and inspection-defensible.",
        "status": "Defensible",
        "score": 96
    }
]

@app.route("/irlt-commercial-readiness/treatment-coordination-gate")
def irlt_treatment_coordination_gate():

    treatment_score = round(
        sum(x["score"] for x in IRLT_TREATMENT_COORDINATION_GATE_V1)
        / len(IRLT_TREATMENT_COORDINATION_GATE_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Treatment Coordination Gate</title>

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

        <h1>IRLT Treatment Coordination Gate</h1>

        <p>
            Governed treatment coordination readiness layer for IRLT operations. This view checks whether
            patient schedule alignment, site readiness, dose arrival verification, clinical handoff,
            exception escalation, and treatment readiness defensibility are controlled.
        </p>

        <div class="score">{{ treatment_score }}%</div>

        <p>Overall Treatment Coordination Governance Confidence</p>

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
    gates=IRLT_TREATMENT_COORDINATION_GATE_V1,
    treatment_score=treatment_score
    )


@app.route("/irlt-commercial-readiness/treatment-coordination-gate/api")
def irlt_treatment_coordination_gate_api():

    return jsonify({
        "treatment_score": round(
            sum(x["score"] for x in IRLT_TREATMENT_COORDINATION_GATE_V1)
            / len(IRLT_TREATMENT_COORDINATION_GATE_V1)
        ),
        "gates": IRLT_TREATMENT_COORDINATION_GATE_V1
    })

# ============================================================
# END IRLT_TREATMENT_COORDINATION_GATE_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Treatment Coordination Gate View appended successfully.")
