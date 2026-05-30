from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_BATCH_RECORD_GATE_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Batch Record Gate View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_BATCH_RECORD_GATE_VIEW_V1_ACTIVE
# ============================================================

IRLT_BATCH_RECORD_GATE_V1 = [
    {
        "gate": "Batch Record Completeness",
        "condition": "Batch record must include required manufacturing, QC, release, deviation, and approval evidence.",
        "status": "Verified",
        "score": 98
    },
    {
        "gate": "Manufacturing Execution Evidence",
        "condition": "Execution evidence must support that the batch was produced according to approved process requirements.",
        "status": "Controlled",
        "score": 96
    },
    {
        "gate": "Review By Exception",
        "condition": "Any exception, deviation, or unexplained gap must be identified before QA disposition.",
        "status": "Monitored",
        "score": 93
    },
    {
        "gate": "QA Review Readiness",
        "condition": "QA must have complete evidence, traceability, and decision context before batch release.",
        "status": "Ready",
        "score": 97
    },
    {
        "gate": "Release Dependency Check",
        "condition": "Batch record readiness must align with cold chain, dose traceability, shipment, and treatment readiness.",
        "status": "Active Control",
        "score": 95
    },
    {
        "gate": "Inspection Defensibility",
        "condition": "Batch record must be complete, explainable, and defensible during inspection review.",
        "status": "Defensible",
        "score": 98
    }
]

@app.route("/irlt-commercial-readiness/batch-record-gate")
def irlt_batch_record_gate():

    batch_score = round(
        sum(x["score"] for x in IRLT_BATCH_RECORD_GATE_V1)
        / len(IRLT_BATCH_RECORD_GATE_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Batch Record Gate</title>

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

        <h1>IRLT Batch Record Gate</h1>

        <p>
            Governed batch record readiness layer for IRLT operations. This view checks whether
            batch record completeness, manufacturing evidence, exception review, QA review,
            release dependency alignment, and inspection defensibility are controlled.
        </p>

        <div class="score">{{ batch_score }}%</div>

        <p>Overall Batch Record Governance Confidence</p>

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
    gates=IRLT_BATCH_RECORD_GATE_V1,
    batch_score=batch_score
    )


@app.route("/irlt-commercial-readiness/batch-record-gate/api")
def irlt_batch_record_gate_api():

    return jsonify({
        "batch_score": round(
            sum(x["score"] for x in IRLT_BATCH_RECORD_GATE_V1)
            / len(IRLT_BATCH_RECORD_GATE_V1)
        ),
        "gates": IRLT_BATCH_RECORD_GATE_V1
    })

# ============================================================
# END IRLT_BATCH_RECORD_GATE_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Batch Record Gate View appended successfully.")
