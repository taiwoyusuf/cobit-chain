from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_TRAINING_GATE_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Training Gate View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_TRAINING_GATE_VIEW_V1_ACTIVE
# ============================================================

IRLT_TRAINING_GATE_V1 = [
    {
        "gate": "Role-Based Training Assignment",
        "condition": "Operators, QA reviewers, release approvers, and support teams must have assigned role-based training.",
        "status": "Controlled",
        "score": 95
    },
    {
        "gate": "Training Completion Evidence",
        "condition": "Training completion must be traceable, current, and linked to operational responsibilities.",
        "status": "Verified",
        "score": 96
    },
    {
        "gate": "GMP Readiness",
        "condition": "Personnel involved in GMP activities must have active and relevant GMP training evidence.",
        "status": "Ready",
        "score": 97
    },
    {
        "gate": "System Access Alignment",
        "condition": "System access must align with completed training and approved operational role.",
        "status": "Monitored",
        "score": 91
    },
    {
        "gate": "Inspection Defensibility",
        "condition": "Training records must be explainable and defensible during regulatory inspection.",
        "status": "Defensible",
        "score": 96
    },
    {
        "gate": "Training Drift Detection",
        "condition": "Expired, missing, or misaligned training must be flagged before operational execution risk emerges.",
        "status": "Observed",
        "score": 89
    }
]

@app.route("/irlt-commercial-readiness/training-gate")
def irlt_training_gate():

    training_score = round(
        sum(x["score"] for x in IRLT_TRAINING_GATE_V1)
        / len(IRLT_TRAINING_GATE_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Training Gate</title>

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

        <h1>IRLT Training Gate</h1>

        <p>
            Governed training readiness layer for IRLT commercialization. This view checks whether
            role-based training, GMP readiness, system access alignment, and inspection defensibility
            are sufficiently controlled before operational execution.
        </p>

        <div class="score">{{ training_score }}%</div>

        <p>Overall Training Governance Confidence</p>

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
    gates=IRLT_TRAINING_GATE_V1,
    training_score=training_score
    )


@app.route("/irlt-commercial-readiness/training-gate/api")
def irlt_training_gate_api():

    return jsonify({
        "training_score": round(
            sum(x["score"] for x in IRLT_TRAINING_GATE_V1)
            / len(IRLT_TRAINING_GATE_V1)
        ),
        "gates": IRLT_TRAINING_GATE_V1
    })

# ============================================================
# END IRLT_TRAINING_GATE_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Training Gate View appended successfully.")
