from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_SUPPLIER_READINESS_GATE_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Supplier Readiness Gate View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_SUPPLIER_READINESS_GATE_VIEW_V1_ACTIVE
# ============================================================

IRLT_SUPPLIER_READINESS_GATE_V1 = [
    {
        "gate": "Supplier Qualification",
        "condition": "Critical suppliers must be qualified, approved, and aligned with GMP or operational requirements.",
        "status": "Controlled",
        "score": 95
    },
    {
        "gate": "Supplier Quality Status",
        "condition": "Supplier quality status, audit standing, deviations, and risk profile must support continued use.",
        "status": "Verified",
        "score": 94
    },
    {
        "gate": "Material / Service Dependency",
        "condition": "Supplier dependencies must be mapped to manufacturing, QC, release, shipment, and treatment continuity.",
        "status": "Mapped",
        "score": 93
    },
    {
        "gate": "Supply Disruption Risk",
        "condition": "Supplier delay, shortage, or quality issue must trigger governance escalation before operational impact.",
        "status": "Monitored",
        "score": 91
    },
    {
        "gate": "Alternative Supplier Readiness",
        "condition": "Critical supplier pathways should include backup sourcing, contingency, or recovery governance.",
        "status": "Planned Control",
        "score": 89
    },
    {
        "gate": "Inspection Defensibility",
        "condition": "Supplier readiness evidence must be complete, traceable, and inspection-defensible.",
        "status": "Defensible",
        "score": 96
    }
]

@app.route("/irlt-commercial-readiness/supplier-readiness-gate")
def irlt_supplier_readiness_gate():

    supplier_score = round(
        sum(x["score"] for x in IRLT_SUPPLIER_READINESS_GATE_V1)
        / len(IRLT_SUPPLIER_READINESS_GATE_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Supplier Readiness Gate</title>

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

        <h1>IRLT Supplier Readiness Gate</h1>

        <p>
            Governed supplier readiness layer for IRLT operations. This view checks whether supplier
            qualification, quality status, material or service dependency, disruption risk,
            alternative supplier readiness, and inspection defensibility are controlled.
        </p>

        <div class="score">{{ supplier_score }}%</div>

        <p>Overall Supplier Readiness Governance Confidence</p>

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
    gates=IRLT_SUPPLIER_READINESS_GATE_V1,
    supplier_score=supplier_score
    )


@app.route("/irlt-commercial-readiness/supplier-readiness-gate/api")
def irlt_supplier_readiness_gate_api():

    return jsonify({
        "supplier_score": round(
            sum(x["score"] for x in IRLT_SUPPLIER_READINESS_GATE_V1)
            / len(IRLT_SUPPLIER_READINESS_GATE_V1)
        ),
        "gates": IRLT_SUPPLIER_READINESS_GATE_V1
    })

# ============================================================
# END IRLT_SUPPLIER_READINESS_GATE_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Supplier Readiness Gate View appended successfully.")
