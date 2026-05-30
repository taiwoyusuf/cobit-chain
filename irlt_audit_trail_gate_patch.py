from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_AUDIT_TRAIL_GATE_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Audit Trail Gate View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_AUDIT_TRAIL_GATE_VIEW_V1_ACTIVE
# ============================================================

IRLT_AUDIT_TRAIL_GATE_V1 = [
    {
        "gate": "Audit Trail Availability",
        "condition": "Audit trail records must be available for GMP-impacting systems, release activities, access changes, and evidence events.",
        "status": "Verified",
        "score": 96
    },
    {
        "gate": "Reviewer Accountability",
        "condition": "Audit review must show reviewer identity, review date, scope, and decision outcome.",
        "status": "Controlled",
        "score": 95
    },
    {
        "gate": "Critical Event Detection",
        "condition": "Critical events such as admin changes, deleted records, failed logins, data edits, and release-impacting actions must be flagged.",
        "status": "Active Control",
        "score": 94
    },
    {
        "gate": "Change Control Linkage",
        "condition": "Audit trail changes must be linked to approved change control, deviation, CAPA, or documented operational justification.",
        "status": "Monitored",
        "score": 92
    },
    {
        "gate": "Periodic Review Evidence",
        "condition": "Monthly or quarterly audit trail review evidence must be retained and inspection-ready.",
        "status": "Evidence Ready",
        "score": 96
    },
    {
        "gate": "Inspection Defensibility",
        "condition": "Audit trail review must be complete, explainable, and defensible during regulatory inspection.",
        "status": "Defensible",
        "score": 97
    }
]

@app.route("/irlt-commercial-readiness/audit-trail-gate")
def irlt_audit_trail_gate():

    audit_score = round(
        sum(x["score"] for x in IRLT_AUDIT_TRAIL_GATE_V1)
        / len(IRLT_AUDIT_TRAIL_GATE_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Audit Trail Gate</title>

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

        <h1>IRLT Audit Trail Gate</h1>

        <p>
            Governed audit trail readiness layer for IRLT operations. This view checks whether audit trail
            availability, reviewer accountability, critical event detection, change-control linkage,
            periodic review evidence, and inspection defensibility are controlled.
        </p>

        <div class="score">{{ audit_score }}%</div>

        <p>Overall Audit Trail Governance Confidence</p>

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
    gates=IRLT_AUDIT_TRAIL_GATE_V1,
    audit_score=audit_score
    )


@app.route("/irlt-commercial-readiness/audit-trail-gate/api")
def irlt_audit_trail_gate_api():

    return jsonify({
        "audit_score": round(
            sum(x["score"] for x in IRLT_AUDIT_TRAIL_GATE_V1)
            / len(IRLT_AUDIT_TRAIL_GATE_V1)
        ),
        "gates": IRLT_AUDIT_TRAIL_GATE_V1
    })

# ============================================================
# END IRLT_AUDIT_TRAIL_GATE_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Audit Trail Gate View appended successfully.")
