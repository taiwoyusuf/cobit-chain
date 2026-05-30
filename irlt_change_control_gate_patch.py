from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_CHANGE_CONTROL_GATE_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Change Control Gate View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_CHANGE_CONTROL_GATE_VIEW_V1_ACTIVE
# ============================================================

IRLT_CHANGE_CONTROL_GATE_V1 = [
    {
        "gate": "Change Request Definition",
        "condition": "Change must be clearly defined with scope, system/process impact, owner, and business justification.",
        "status": "Defined",
        "score": 95
    },
    {
        "gate": "GMP Impact Assessment",
        "condition": "Potential GMP, validation, release, quality, training, and inspection impact must be assessed before execution.",
        "status": "Required",
        "score": 97
    },
    {
        "gate": "Approval Lineage",
        "condition": "Approvals must be traceable to system owner, QA, IT, validation, and affected business stakeholders.",
        "status": "Controlled",
        "score": 96
    },
    {
        "gate": "Implementation Evidence",
        "condition": "Implementation evidence must show what changed, when it changed, who performed it, and verification outcome.",
        "status": "Evidence Ready",
        "score": 95
    },
    {
        "gate": "Rollback / Recovery Plan",
        "condition": "Change must include rollback, recovery, or mitigation plan for failed implementation or operational instability.",
        "status": "Monitored",
        "score": 92
    },
    {
        "gate": "Post-Change Verification",
        "condition": "Post-change verification must confirm operational readiness, evidence completeness, and inspection defensibility.",
        "status": "Defensible",
        "score": 96
    }
]

@app.route("/irlt-commercial-readiness/change-control-gate")
def irlt_change_control_gate():

    change_score = round(
        sum(x["score"] for x in IRLT_CHANGE_CONTROL_GATE_V1)
        / len(IRLT_CHANGE_CONTROL_GATE_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Change Control Gate</title>

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

        <h1>IRLT Change Control Gate</h1>

        <p>
            Governed change-control readiness layer for IRLT operations. This view checks whether
            change scope, GMP impact, approval lineage, implementation evidence, rollback planning,
            and post-change verification are controlled before regulated operational impact occurs.
        </p>

        <div class="score">{{ change_score }}%</div>

        <p>Overall Change Control Governance Confidence</p>

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
    gates=IRLT_CHANGE_CONTROL_GATE_V1,
    change_score=change_score
    )


@app.route("/irlt-commercial-readiness/change-control-gate/api")
def irlt_change_control_gate_api():

    return jsonify({
        "change_score": round(
            sum(x["score"] for x in IRLT_CHANGE_CONTROL_GATE_V1)
            / len(IRLT_CHANGE_CONTROL_GATE_V1)
        ),
        "gates": IRLT_CHANGE_CONTROL_GATE_V1
    })

# ============================================================
# END IRLT_CHANGE_CONTROL_GATE_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Change Control Gate View appended successfully.")
