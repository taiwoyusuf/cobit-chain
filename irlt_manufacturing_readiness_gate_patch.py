from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_MANUFACTURING_READINESS_GATE_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Manufacturing Readiness Gate View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_MANUFACTURING_READINESS_GATE_VIEW_V1_ACTIVE
# ============================================================

IRLT_MANUFACTURING_READINESS_GATE_V1 = [
    {
        "gate": "Manufacturing Schedule Readiness",
        "condition": "Manufacturing schedule must align with batch planning, equipment readiness, staffing, QC timing, and release expectations.",
        "status": "Ready",
        "score": 96
    },
    {
        "gate": "Material Availability",
        "condition": "Critical raw materials, consumables, isotope-related dependencies, and controlled materials must be available and documented.",
        "status": "Controlled",
        "score": 95
    },
    {
        "gate": "Operator Readiness",
        "condition": "Operators must have training, access, gowning readiness, and role authorization aligned with production activity.",
        "status": "Verified",
        "score": 96
    },
    {
        "gate": "Manufacturing Evidence Capture",
        "condition": "Manufacturing evidence must capture execution records, timestamps, deviations, approvals, and batch lineage.",
        "status": "Evidence Ready",
        "score": 97
    },
    {
        "gate": "Process Deviation Monitoring",
        "condition": "Any process drift, equipment issue, hold time concern, or production exception must trigger deviation governance.",
        "status": "Monitored",
        "score": 92
    },
    {
        "gate": "Commercial Scale-Up Defensibility",
        "condition": "Manufacturing readiness must be explainable and defensible for commercial launch, inspection, and operational scale-up.",
        "status": "Defensible",
        "score": 97
    }
]

@app.route("/irlt-commercial-readiness/manufacturing-readiness-gate")
def irlt_manufacturing_readiness_gate():

    manufacturing_score = round(
        sum(x["score"] for x in IRLT_MANUFACTURING_READINESS_GATE_V1)
        / len(IRLT_MANUFACTURING_READINESS_GATE_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Manufacturing Readiness Gate</title>

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

        <h1>IRLT Manufacturing Readiness Gate</h1>

        <p>
            Governed manufacturing readiness layer for IRLT operations. This view checks whether
            production schedule, material availability, operator readiness, manufacturing evidence,
            process deviation monitoring, and commercial scale-up defensibility are controlled.
        </p>

        <div class="score">{{ manufacturing_score }}%</div>

        <p>Overall Manufacturing Readiness Governance Confidence</p>

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
    gates=IRLT_MANUFACTURING_READINESS_GATE_V1,
    manufacturing_score=manufacturing_score
    )


@app.route("/irlt-commercial-readiness/manufacturing-readiness-gate/api")
def irlt_manufacturing_readiness_gate_api():

    return jsonify({
        "manufacturing_score": round(
            sum(x["score"] for x in IRLT_MANUFACTURING_READINESS_GATE_V1)
            / len(IRLT_MANUFACTURING_READINESS_GATE_V1)
        ),
        "gates": IRLT_MANUFACTURING_READINESS_GATE_V1
    })

# ============================================================
# END IRLT_MANUFACTURING_READINESS_GATE_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Manufacturing Readiness Gate View appended successfully.")
