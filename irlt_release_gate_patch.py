from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_RELEASE_GATE_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Release Gate View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_RELEASE_GATE_VIEW_V1_ACTIVE
# ============================================================

IRLT_RELEASE_GATE_V1 = [
    {
        "gate": "QA Release Approval",
        "condition": "Batch record, deviation review, and QA signoff must be complete.",
        "status": "Ready",
        "score": 97
    },
    {
        "gate": "Evidence Completeness",
        "condition": "Required evidence must be traceable, complete, and inspection-ready.",
        "status": "Verified",
        "score": 99
    },
    {
        "gate": "Cold Chain Confirmation",
        "condition": "Shipment path, temperature control, and logistics evidence must be stable.",
        "status": "Stable",
        "score": 94
    },
    {
        "gate": "Dose Traceability",
        "condition": "Dose lineage must be connected from production through treatment coordination.",
        "status": "Certified",
        "score": 99
    },
    {
        "gate": "CAPA / Deviation Check",
        "condition": "Open quality issues must not block release defensibility.",
        "status": "Monitored",
        "score": 89
    },
    {
        "gate": "Inspection Defensibility",
        "condition": "Release decision must be defendable under audit or inspection review.",
        "status": "Defensible",
        "score": 96
    }
]

@app.route("/irlt-commercial-readiness/release-gate")
def irlt_release_gate():

    gate_score = round(
        sum(x["score"] for x in IRLT_RELEASE_GATE_V1)
        / len(IRLT_RELEASE_GATE_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Release Gate</title>

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

        <h1>IRLT Release Gate</h1>

        <p>
            Governed release decision layer showing the required gates before an IRLT commercial
            release can be considered operationally defensible, evidence-backed, and inspection-ready.
        </p>

        <div class="score">{{ gate_score }}%</div>

        <p>Overall Release Gate Confidence</p>

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
    gates=IRLT_RELEASE_GATE_V1,
    gate_score=gate_score
    )


@app.route("/irlt-commercial-readiness/release-gate/api")
def irlt_release_gate_api():

    return jsonify({
        "gate_score": round(
            sum(x["score"] for x in IRLT_RELEASE_GATE_V1)
            / len(IRLT_RELEASE_GATE_V1)
        ),
        "gates": IRLT_RELEASE_GATE_V1
    })

# ============================================================
# END IRLT_RELEASE_GATE_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Release Gate View appended successfully.")
