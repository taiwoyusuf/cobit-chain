from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_EQUIPMENT_READINESS_GATE_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Equipment Readiness Gate View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_EQUIPMENT_READINESS_GATE_VIEW_V1_ACTIVE
# ============================================================

IRLT_EQUIPMENT_READINESS_GATE_V1 = [
    {
        "gate": "Equipment Qualification Status",
        "condition": "Critical equipment must have current qualification or validation status before GMP operational use.",
        "status": "Controlled",
        "score": 96
    },
    {
        "gate": "Calibration Readiness",
        "condition": "Calibration status must be current, documented, and linked to equipment readiness evidence.",
        "status": "Verified",
        "score": 97
    },
    {
        "gate": "Preventive Maintenance Status",
        "condition": "PM activities must be current with no overdue or release-impacting maintenance gaps.",
        "status": "Ready",
        "score": 95
    },
    {
        "gate": "Equipment Deviation Linkage",
        "condition": "Equipment failures, alarms, or excursions must be linked to deviation or CAPA governance where required.",
        "status": "Monitored",
        "score": 92
    },
    {
        "gate": "Backup / Redundancy Readiness",
        "condition": "Critical equipment must have documented contingency, backup, or operational recovery pathway.",
        "status": "Planned Control",
        "score": 90
    },
    {
        "gate": "Inspection Defensibility",
        "condition": "Equipment readiness evidence must be complete, traceable, and inspection-defensible.",
        "status": "Defensible",
        "score": 96
    }
]

@app.route("/irlt-commercial-readiness/equipment-readiness-gate")
def irlt_equipment_readiness_gate():

    equipment_score = round(
        sum(x["score"] for x in IRLT_EQUIPMENT_READINESS_GATE_V1)
        / len(IRLT_EQUIPMENT_READINESS_GATE_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Equipment Readiness Gate</title>

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

        <h1>IRLT Equipment Readiness Gate</h1>

        <p>
            Governed equipment readiness layer for IRLT operations. This view checks whether qualification,
            calibration, preventive maintenance, equipment deviation linkage, redundancy readiness,
            and inspection defensibility are controlled before operational reliance.
        </p>

        <div class="score">{{ equipment_score }}%</div>

        <p>Overall Equipment Readiness Governance Confidence</p>

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
    gates=IRLT_EQUIPMENT_READINESS_GATE_V1,
    equipment_score=equipment_score
    )


@app.route("/irlt-commercial-readiness/equipment-readiness-gate/api")
def irlt_equipment_readiness_gate_api():

    return jsonify({
        "equipment_score": round(
            sum(x["score"] for x in IRLT_EQUIPMENT_READINESS_GATE_V1)
            / len(IRLT_EQUIPMENT_READINESS_GATE_V1)
        ),
        "gates": IRLT_EQUIPMENT_READINESS_GATE_V1
    })

# ============================================================
# END IRLT_EQUIPMENT_READINESS_GATE_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Equipment Readiness Gate View appended successfully.")
