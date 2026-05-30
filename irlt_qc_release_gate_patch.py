from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_QC_RELEASE_GATE_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT QC Release Gate View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_QC_RELEASE_GATE_VIEW_V1_ACTIVE
# ============================================================

IRLT_QC_RELEASE_GATE_V1 = [
    {
        "gate": "QC Result Availability",
        "condition": "Required QC results must be available, reviewed, and linked to batch release readiness.",
        "status": "Verified",
        "score": 97
    },
    {
        "gate": "Specification Confirmation",
        "condition": "QC results must be assessed against approved specifications and acceptance criteria.",
        "status": "Controlled",
        "score": 96
    },
    {
        "gate": "Out-of-Specification Check",
        "condition": "Any OOS, OOT, atypical, or questionable result must trigger investigation governance.",
        "status": "Monitored",
        "score": 92
    },
    {
        "gate": "QC Review Evidence",
        "condition": "QC review evidence must show reviewer, timestamp, decision context, and approval lineage.",
        "status": "Evidence Ready",
        "score": 95
    },
    {
        "gate": "Release Dependency Alignment",
        "condition": "QC readiness must align with QA release, batch record review, cold chain, and shipment timing.",
        "status": "Active Control",
        "score": 94
    },
    {
        "gate": "Inspection Defensibility",
        "condition": "QC release evidence must be complete, explainable, and inspection-defensible.",
        "status": "Defensible",
        "score": 97
    }
]

@app.route("/irlt-commercial-readiness/qc-release-gate")
def irlt_qc_release_gate():

    qc_score = round(
        sum(x["score"] for x in IRLT_QC_RELEASE_GATE_V1)
        / len(IRLT_QC_RELEASE_GATE_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>IRLT QC Release Gate</title>

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

        <h1>IRLT QC Release Gate</h1>

        <p>
            Governed QC release readiness layer for IRLT operations. This view checks whether
            QC results, specifications, OOS/OOT review, QC evidence, release dependency alignment,
            and inspection defensibility are controlled before commercial release.
        </p>

        <div class="score">{{ qc_score }}%</div>

        <p>Overall QC Release Governance Confidence</p>

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
    gates=IRLT_QC_RELEASE_GATE_V1,
    qc_score=qc_score
    )


@app.route("/irlt-commercial-readiness/qc-release-gate/api")
def irlt_qc_release_gate_api():

    return jsonify({
        "qc_score": round(
            sum(x["score"] for x in IRLT_QC_RELEASE_GATE_V1)
            / len(IRLT_QC_RELEASE_GATE_V1)
        ),
        "gates": IRLT_QC_RELEASE_GATE_V1
    })

# ============================================================
# END IRLT_QC_RELEASE_GATE_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT QC Release Gate View appended successfully.")
