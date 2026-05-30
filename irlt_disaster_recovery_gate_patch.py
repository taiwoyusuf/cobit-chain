from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_DISASTER_RECOVERY_GATE_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Disaster Recovery Gate View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_DISASTER_RECOVERY_GATE_VIEW_V1_ACTIVE
# ============================================================

IRLT_DISASTER_RECOVERY_GATE_V1 = [
    {
        "gate": "DR Activation Criteria",
        "condition": "Activation criteria must define when system, site, process, or operational recovery governance is triggered.",
        "status": "Defined",
        "score": 94
    },
    {
        "gate": "RTO / RPO Governance",
        "condition": "Recovery time and recovery point expectations must be defined for GMP and IRLT-critical systems.",
        "status": "Controlled",
        "score": 93
    },
    {
        "gate": "Recovery Role Assignment",
        "condition": "Recovery roles, approvers, system owners, QA reviewers, and escalation owners must be documented.",
        "status": "Ready",
        "score": 95
    },
    {
        "gate": "Dependency Recovery Mapping",
        "condition": "Recovery dependencies across infrastructure, applications, users, evidence, and operations must be mapped.",
        "status": "Planned Integration",
        "score": 90
    },
    {
        "gate": "GMP Restart Gate",
        "condition": "GMP operations must not restart until recovery evidence, system readiness, and QA approval are confirmed.",
        "status": "Critical",
        "score": 97
    },
    {
        "gate": "Recovery Evidence Lineage",
        "condition": "Recovery actions must produce evidence that is traceable, reviewable, and inspection-defensible.",
        "status": "Defensible",
        "score": 96
    }
]

@app.route("/irlt-commercial-readiness/disaster-recovery-gate")
def irlt_disaster_recovery_gate():

    dr_score = round(
        sum(x["score"] for x in IRLT_DISASTER_RECOVERY_GATE_V1)
        / len(IRLT_DISASTER_RECOVERY_GATE_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Disaster Recovery Gate</title>

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

        <h1>IRLT Disaster Recovery Gate</h1>

        <p>
            Governed disaster recovery readiness layer for IRLT operations. This view checks whether
            DR activation criteria, RTO/RPO governance, recovery roles, dependency mapping,
            GMP restart gates, and recovery evidence lineage are controlled and inspection-defensible.
        </p>

        <div class="score">{{ dr_score }}%</div>

        <p>Overall Disaster Recovery Governance Confidence</p>

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
    gates=IRLT_DISASTER_RECOVERY_GATE_V1,
    dr_score=dr_score
    )


@app.route("/irlt-commercial-readiness/disaster-recovery-gate/api")
def irlt_disaster_recovery_gate_api():

    return jsonify({
        "dr_score": round(
            sum(x["score"] for x in IRLT_DISASTER_RECOVERY_GATE_V1)
            / len(IRLT_DISASTER_RECOVERY_GATE_V1)
        ),
        "gates": IRLT_DISASTER_RECOVERY_GATE_V1
    })

# ============================================================
# END IRLT_DISASTER_RECOVERY_GATE_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Disaster Recovery Gate View appended successfully.")
