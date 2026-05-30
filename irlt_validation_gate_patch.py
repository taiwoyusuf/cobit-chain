from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_VALIDATION_GATE_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Validation Gate View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_VALIDATION_GATE_VIEW_V1_ACTIVE
# ============================================================

IRLT_VALIDATION_GATE_V1 = [
    {
        "gate": "Validation Scope Confirmation",
        "condition": "System, process, equipment, or workflow validation scope must be clearly defined before operational use.",
        "status": "Defined",
        "score": 95
    },
    {
        "gate": "GMP Impact Classification",
        "condition": "Validation impact must be classified based on GMP relevance, release impact, data integrity, and patient risk.",
        "status": "Required",
        "score": 97
    },
    {
        "gate": "Protocol / Test Evidence",
        "condition": "Validation protocol, executed test evidence, deviations, and acceptance outcomes must be complete.",
        "status": "Evidence Ready",
        "score": 96
    },
    {
        "gate": "Deviation During Validation",
        "condition": "Any validation deviation must be assessed, justified, approved, and linked to governance evidence.",
        "status": "Monitored",
        "score": 92
    },
    {
        "gate": "Approval and Release to Use",
        "condition": "Validation approval must be complete before system/process release to GMP operational use.",
        "status": "Controlled",
        "score": 96
    },
    {
        "gate": "Inspection Defensibility",
        "condition": "Validation package must be complete, explainable, traceable, and inspection-defensible.",
        "status": "Defensible",
        "score": 97
    }
]

@app.route("/irlt-commercial-readiness/validation-gate")
def irlt_validation_gate():

    validation_score = round(
        sum(x["score"] for x in IRLT_VALIDATION_GATE_V1)
        / len(IRLT_VALIDATION_GATE_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Validation Gate</title>

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

        <h1>IRLT Validation Gate</h1>

        <p>
            Governed validation readiness layer for IRLT operations. This view checks whether validation scope,
            GMP impact, protocol evidence, validation deviations, approval-to-use, and inspection defensibility
            are controlled before regulated operational reliance.
        </p>

        <div class="score">{{ validation_score }}%</div>

        <p>Overall Validation Governance Confidence</p>

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
    gates=IRLT_VALIDATION_GATE_V1,
    validation_score=validation_score
    )


@app.route("/irlt-commercial-readiness/validation-gate/api")
def irlt_validation_gate_api():

    return jsonify({
        "validation_score": round(
            sum(x["score"] for x in IRLT_VALIDATION_GATE_V1)
            / len(IRLT_VALIDATION_GATE_V1)
        ),
        "gates": IRLT_VALIDATION_GATE_V1
    })

# ============================================================
# END IRLT_VALIDATION_GATE_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Validation Gate View appended successfully.")
