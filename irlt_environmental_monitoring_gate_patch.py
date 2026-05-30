from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_ENVIRONMENTAL_MONITORING_GATE_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Environmental Monitoring Gate View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_ENVIRONMENTAL_MONITORING_GATE_VIEW_V1_ACTIVE
# ============================================================

IRLT_ENVIRONMENTAL_MONITORING_GATE_V1 = [
    {
        "gate": "EM Data Availability",
        "condition": "Required environmental monitoring data must be available, reviewed, and linked to batch/release readiness.",
        "status": "Verified",
        "score": 96
    },
    {
        "gate": "Alert / Action Limit Review",
        "condition": "Any alert or action limit excursion must be reviewed and dispositioned before release defensibility.",
        "status": "Controlled",
        "score": 94
    },
    {
        "gate": "Cleanroom State Confirmation",
        "condition": "Cleanroom operating state must support GMP manufacturing and inspection readiness.",
        "status": "Ready",
        "score": 95
    },
    {
        "gate": "Deviation Linkage",
        "condition": "Any EM excursion must be linked to deviation, CAPA, QA review, and evidence lineage where required.",
        "status": "Monitored",
        "score": 91
    },
    {
        "gate": "Trend Review",
        "condition": "EM trend signals must be reviewed for recurring contamination, drift, or operational weakness.",
        "status": "Observed",
        "score": 90
    },
    {
        "gate": "Inspection Defensibility",
        "condition": "EM records must be complete, explainable, and inspection-defensible.",
        "status": "Defensible",
        "score": 96
    }
]

@app.route("/irlt-commercial-readiness/environmental-monitoring-gate")
def irlt_environmental_monitoring_gate():

    em_score = round(
        sum(x["score"] for x in IRLT_ENVIRONMENTAL_MONITORING_GATE_V1)
        / len(IRLT_ENVIRONMENTAL_MONITORING_GATE_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Environmental Monitoring Gate</title>

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

        <h1>IRLT Environmental Monitoring Gate</h1>

        <p>
            Governed environmental monitoring readiness layer for IRLT operations. This view checks whether
            EM data availability, alert/action limit review, cleanroom state, deviation linkage, trend review,
            and inspection defensibility are controlled before release or inspection pressure.
        </p>

        <div class="score">{{ em_score }}%</div>

        <p>Overall Environmental Monitoring Governance Confidence</p>

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
    gates=IRLT_ENVIRONMENTAL_MONITORING_GATE_V1,
    em_score=em_score
    )


@app.route("/irlt-commercial-readiness/environmental-monitoring-gate/api")
def irlt_environmental_monitoring_gate_api():

    return jsonify({
        "em_score": round(
            sum(x["score"] for x in IRLT_ENVIRONMENTAL_MONITORING_GATE_V1)
            / len(IRLT_ENVIRONMENTAL_MONITORING_GATE_V1)
        ),
        "gates": IRLT_ENVIRONMENTAL_MONITORING_GATE_V1
    })

# ============================================================
# END IRLT_ENVIRONMENTAL_MONITORING_GATE_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Environmental Monitoring Gate View appended successfully.")
