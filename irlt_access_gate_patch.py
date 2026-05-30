from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_ACCESS_GATE_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Access Gate View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_ACCESS_GATE_VIEW_V1_ACTIVE
# ============================================================

IRLT_ACCESS_GATE_V1 = [
    {
        "gate": "Role-Based Access Validation",
        "condition": "Access must match approved operational role, system responsibility, and training readiness.",
        "status": "Controlled",
        "score": 95
    },
    {
        "gate": "Privileged Access Review",
        "condition": "Admin or elevated access must have owner approval, justification, and review evidence.",
        "status": "Monitored",
        "score": 92
    },
    {
        "gate": "Joiner / Mover / Leaver Alignment",
        "condition": "User access must stay aligned with onboarding, transfer, and termination workflows.",
        "status": "Observed",
        "score": 90
    },
    {
        "gate": "GMP System Access Traceability",
        "condition": "Access to GMP-impacting systems must be traceable and inspection-defensible.",
        "status": "Defensible",
        "score": 96
    },
    {
        "gate": "Orphaned Access Detection",
        "condition": "Inactive, duplicate, or unsupported accounts must be identified before audit exposure.",
        "status": "Active Control",
        "score": 91
    },
    {
        "gate": "Access Governance Evidence",
        "condition": "Approval, review, and access-change evidence must be complete and linked to governance records.",
        "status": "Verified",
        "score": 97
    }
]

@app.route("/irlt-commercial-readiness/access-gate")
def irlt_access_gate():

    access_score = round(
        sum(x["score"] for x in IRLT_ACCESS_GATE_V1)
        / len(IRLT_ACCESS_GATE_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Access Gate</title>

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

        <h1>IRLT Access Gate</h1>

        <p>
            Governed identity and access readiness layer for IRLT operations. This view checks whether
            system access, privileged roles, user lifecycle governance, and GMP system accountability
            are controlled, traceable, and inspection-defensible.
        </p>

        <div class="score">{{ access_score }}%</div>

        <p>Overall Access Governance Confidence</p>

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
    gates=IRLT_ACCESS_GATE_V1,
    access_score=access_score
    )


@app.route("/irlt-commercial-readiness/access-gate/api")
def irlt_access_gate_api():

    return jsonify({
        "access_score": round(
            sum(x["score"] for x in IRLT_ACCESS_GATE_V1)
            / len(IRLT_ACCESS_GATE_V1)
        ),
        "gates": IRLT_ACCESS_GATE_V1
    })

# ============================================================
# END IRLT_ACCESS_GATE_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Access Gate View appended successfully.")
