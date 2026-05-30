from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_DOSE_TRACEABILITY_GATE_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Dose Traceability Gate View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_DOSE_TRACEABILITY_GATE_VIEW_V1_ACTIVE
# ============================================================

IRLT_DOSE_TRACEABILITY_GATE_V1 = [
    {
        "gate": "Dose Identity Confirmation",
        "condition": "Each dose must have a unique identity connected to batch, release, shipment, and treatment coordination.",
        "status": "Certified",
        "score": 99
    },
    {
        "gate": "Chain-of-Custody Lineage",
        "condition": "Custody must be traceable from manufacturing through shipment, receipt, and administration readiness.",
        "status": "Verified",
        "score": 98
    },
    {
        "gate": "Treatment Timing Alignment",
        "condition": "Dose readiness must align with patient schedule, delivery timing, and radioactive decay constraints.",
        "status": "Critical",
        "score": 97
    },
    {
        "gate": "Release-to-Administration Evidence",
        "condition": "Evidence must connect QA release, logistics, receiving, and treatment coordination.",
        "status": "Controlled",
        "score": 96
    },
    {
        "gate": "Exception / Deviation Linkage",
        "condition": "Any exception affecting dose movement, timing, or quality must be linked to deviation governance.",
        "status": "Monitored",
        "score": 92
    },
    {
        "gate": "Inspection Defensibility",
        "condition": "Dose traceability records must be complete, explainable, and inspection-defensible.",
        "status": "Defensible",
        "score": 98
    }
]

@app.route("/irlt-commercial-readiness/dose-traceability-gate")
def irlt_dose_traceability_gate():

    dose_score = round(
        sum(x["score"] for x in IRLT_DOSE_TRACEABILITY_GATE_V1)
        / len(IRLT_DOSE_TRACEABILITY_GATE_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Dose Traceability Gate</title>

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

        <h1>IRLT Dose Traceability Gate</h1>

        <p>
            Governed dose traceability layer for IRLT operations. This view checks whether dose identity,
            custody lineage, treatment timing, release-to-administration evidence, deviation linkage,
            and inspection defensibility are controlled.
        </p>

        <div class="score">{{ dose_score }}%</div>

        <p>Overall Dose Traceability Governance Confidence</p>

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
    gates=IRLT_DOSE_TRACEABILITY_GATE_V1,
    dose_score=dose_score
    )


@app.route("/irlt-commercial-readiness/dose-traceability-gate/api")
def irlt_dose_traceability_gate_api():

    return jsonify({
        "dose_score": round(
            sum(x["score"] for x in IRLT_DOSE_TRACEABILITY_GATE_V1)
            / len(IRLT_DOSE_TRACEABILITY_GATE_V1)
        ),
        "gates": IRLT_DOSE_TRACEABILITY_GATE_V1
    })

# ============================================================
# END IRLT_DOSE_TRACEABILITY_GATE_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Dose Traceability Gate View appended successfully.")
