from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_EVIDENCE_GATE_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Evidence Gate View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_EVIDENCE_GATE_VIEW_V1_ACTIVE
# ============================================================

IRLT_EVIDENCE_GATE_V1 = [
    {
        "gate": "Evidence Completeness",
        "condition": "Required operational, quality, release, training, access, and inspection evidence must be complete.",
        "status": "Verified",
        "score": 98
    },
    {
        "gate": "Evidence Traceability",
        "condition": "Evidence must be traceable to owner, system, process, timestamp, and governance decision.",
        "status": "Controlled",
        "score": 97
    },
    {
        "gate": "Evidence Integrity",
        "condition": "Evidence must be protected from unauthorized change and validated for authenticity.",
        "status": "Protected",
        "score": 99
    },
    {
        "gate": "Inspection Readiness",
        "condition": "Evidence must be organized and explainable during audit or regulatory inspection.",
        "status": "Defensible",
        "score": 96
    },
    {
        "gate": "Cross-System Linkage",
        "condition": "Evidence must connect across systems such as Veeva, ServiceNow, MyAccess, SharePoint, and CMDB.",
        "status": "Planned Integration",
        "score": 91
    },
    {
        "gate": "Governance Approval Lineage",
        "condition": "Evidence must show approval history, review ownership, and governance decision context.",
        "status": "Governed",
        "score": 97
    }
]

@app.route("/irlt-commercial-readiness/evidence-gate")
def irlt_evidence_gate():

    evidence_score = round(
        sum(x["score"] for x in IRLT_EVIDENCE_GATE_V1)
        / len(IRLT_EVIDENCE_GATE_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Evidence Gate</title>

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

        <h1>IRLT Evidence Gate</h1>

        <p>
            Governed evidence readiness layer for IRLT commercialization. This view checks whether
            evidence is complete, traceable, authentic, inspection-ready, cross-system linked, and
            supported by governance approval lineage.
        </p>

        <div class="score">{{ evidence_score }}%</div>

        <p>Overall Evidence Governance Confidence</p>

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
    gates=IRLT_EVIDENCE_GATE_V1,
    evidence_score=evidence_score
    )


@app.route("/irlt-commercial-readiness/evidence-gate/api")
def irlt_evidence_gate_api():

    return jsonify({
        "evidence_score": round(
            sum(x["score"] for x in IRLT_EVIDENCE_GATE_V1)
            / len(IRLT_EVIDENCE_GATE_V1)
        ),
        "gates": IRLT_EVIDENCE_GATE_V1
    })

# ============================================================
# END IRLT_EVIDENCE_GATE_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Evidence Gate View appended successfully.")
