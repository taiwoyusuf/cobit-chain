from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_DEVIATION_GATE_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Deviation Gate View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_DEVIATION_GATE_VIEW_V1_ACTIVE
# ============================================================

IRLT_DEVIATION_GATE_V1 = [
    {
        "gate": "Deviation Identification",
        "condition": "Deviation must be logged, categorized, and linked to impacted IRLT process.",
        "status": "Controlled",
        "score": 94
    },
    {
        "gate": "Impact Assessment",
        "condition": "Operational, quality, release, patient-treatment, and inspection impact must be assessed.",
        "status": "Required",
        "score": 96
    },
    {
        "gate": "Evidence Linkage",
        "condition": "Supporting evidence must be attached, traceable, and inspection-ready.",
        "status": "Verified",
        "score": 97
    },
    {
        "gate": "CAPA Dependency Review",
        "condition": "CAPA dependency must be reviewed before deviation closure or release decision.",
        "status": "Monitored",
        "score": 90
    },
    {
        "gate": "QA Disposition",
        "condition": "QA decision must be documented, approved, and governance-defensible.",
        "status": "Pending Governance",
        "score": 88
    },
    {
        "gate": "Closure Defensibility",
        "condition": "Closure must be explainable under inspection review with complete evidence lineage.",
        "status": "Defensible",
        "score": 95
    }
]

@app.route("/irlt-commercial-readiness/deviation-gate")
def irlt_deviation_gate():

    deviation_score = round(
        sum(x["score"] for x in IRLT_DEVIATION_GATE_V1)
        / len(IRLT_DEVIATION_GATE_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Deviation Gate</title>

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

        <h1>IRLT Deviation Gate</h1>

        <p>
            Governed deviation review layer for IRLT operations. This view shows the required
            governance checkpoints before a deviation can be considered operationally understood,
            evidence-backed, QA-dispositioned, and inspection-defensible.
        </p>

        <div class="score">{{ deviation_score }}%</div>

        <p>Overall Deviation Governance Confidence</p>

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
    gates=IRLT_DEVIATION_GATE_V1,
    deviation_score=deviation_score
    )


@app.route("/irlt-commercial-readiness/deviation-gate/api")
def irlt_deviation_gate_api():

    return jsonify({
        "deviation_score": round(
            sum(x["score"] for x in IRLT_DEVIATION_GATE_V1)
            / len(IRLT_DEVIATION_GATE_V1)
        ),
        "gates": IRLT_DEVIATION_GATE_V1
    })

# ============================================================
# END IRLT_DEVIATION_GATE_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Deviation Gate View appended successfully.")
