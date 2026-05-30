from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_CAPA_GATE_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT CAPA Gate View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_CAPA_GATE_VIEW_V1_ACTIVE
# ============================================================

IRLT_CAPA_GATE_V1 = [
    {
        "gate": "CAPA Initiation",
        "condition": "CAPA must be linked to deviation, audit finding, inspection risk, or operational failure mode.",
        "status": "Controlled",
        "score": 94
    },
    {
        "gate": "Root Cause Governance",
        "condition": "Root cause must be documented, reviewed, and defensible with supporting evidence.",
        "status": "Required",
        "score": 95
    },
    {
        "gate": "Action Effectiveness",
        "condition": "Corrective and preventive actions must be measurable, assigned, and linked to outcomes.",
        "status": "Monitored",
        "score": 91
    },
    {
        "gate": "Operational Dependency Review",
        "condition": "CAPA impact must be checked against release, training, equipment, cold chain, and inspection readiness.",
        "status": "Active",
        "score": 92
    },
    {
        "gate": "Evidence Closure Pack",
        "condition": "Closure evidence must be complete, approved, traceable, and inspection-ready.",
        "status": "Evidence Required",
        "score": 89
    },
    {
        "gate": "QA Closure Defensibility",
        "condition": "Final CAPA closure must be explainable and defensible under regulatory review.",
        "status": "Defensible",
        "score": 96
    }
]

@app.route("/irlt-commercial-readiness/capa-gate")
def irlt_capa_gate():

    capa_score = round(
        sum(x["score"] for x in IRLT_CAPA_GATE_V1)
        / len(IRLT_CAPA_GATE_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>IRLT CAPA Gate</title>

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

        <h1>IRLT CAPA Gate</h1>

        <p>
            Governed CAPA readiness layer for IRLT operations. This view checks whether CAPA initiation,
            root cause, effectiveness, dependency impact, evidence closure, and QA defensibility are ready
            for commercialization and inspection pressure.
        </p>

        <div class="score">{{ capa_score }}%</div>

        <p>Overall CAPA Governance Confidence</p>

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
    gates=IRLT_CAPA_GATE_V1,
    capa_score=capa_score
    )


@app.route("/irlt-commercial-readiness/capa-gate/api")
def irlt_capa_gate_api():

    return jsonify({
        "capa_score": round(
            sum(x["score"] for x in IRLT_CAPA_GATE_V1)
            / len(IRLT_CAPA_GATE_V1)
        ),
        "gates": IRLT_CAPA_GATE_V1
    })

# ============================================================
# END IRLT_CAPA_GATE_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT CAPA Gate View appended successfully.")
