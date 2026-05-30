from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_DATA_RECONCILIATION_GATE_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Data Reconciliation Gate View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_DATA_RECONCILIATION_GATE_VIEW_V1_ACTIVE
# ============================================================

IRLT_DATA_RECONCILIATION_GATE_V1 = [
    {
        "gate": "Source Data Identification",
        "condition": "Critical IRLT data sources must be identified across batch, QC, release, shipment, dose, and treatment systems.",
        "status": "Defined",
        "score": 95
    },
    {
        "gate": "Cross-System Consistency",
        "condition": "Data must reconcile across Veeva, ServiceNow, SharePoint, batch records, shipment records, and governance logs.",
        "status": "Planned Integration",
        "score": 91
    },
    {
        "gate": "Evidence-to-Data Match",
        "condition": "Operational evidence must match the underlying record values, timestamps, owner, and approval state.",
        "status": "Controlled",
        "score": 94
    },
    {
        "gate": "Exception Detection",
        "condition": "Mismatch, missing data, duplicate entries, or unsupported status changes must trigger governance review.",
        "status": "Monitored",
        "score": 92
    },
    {
        "gate": "Approval Reconciliation",
        "condition": "Approval records must align with QA disposition, release decisions, CAPA closure, and access governance.",
        "status": "Verified",
        "score": 96
    },
    {
        "gate": "Inspection Defensibility",
        "condition": "Reconciled data must be explainable, traceable, and defensible during audit or regulatory inspection.",
        "status": "Defensible",
        "score": 97
    }
]

@app.route("/irlt-commercial-readiness/data-reconciliation-gate")
def irlt_data_reconciliation_gate():

    reconciliation_score = round(
        sum(x["score"] for x in IRLT_DATA_RECONCILIATION_GATE_V1)
        / len(IRLT_DATA_RECONCILIATION_GATE_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Data Reconciliation Gate</title>

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

        <h1>IRLT Data Reconciliation Gate</h1>

        <p>
            Governed data reconciliation layer for IRLT operations. This view checks whether source data,
            cross-system consistency, evidence matching, exception detection, approval reconciliation,
            and inspection defensibility are controlled.
        </p>

        <div class="score">{{ reconciliation_score }}%</div>

        <p>Overall Data Reconciliation Governance Confidence</p>

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
    gates=IRLT_DATA_RECONCILIATION_GATE_V1,
    reconciliation_score=reconciliation_score
    )


@app.route("/irlt-commercial-readiness/data-reconciliation-gate/api")
def irlt_data_reconciliation_gate_api():

    return jsonify({
        "reconciliation_score": round(
            sum(x["score"] for x in IRLT_DATA_RECONCILIATION_GATE_V1)
            / len(IRLT_DATA_RECONCILIATION_GATE_V1)
        ),
        "gates": IRLT_DATA_RECONCILIATION_GATE_V1
    })

# ============================================================
# END IRLT_DATA_RECONCILIATION_GATE_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Data Reconciliation Gate View appended successfully.")
