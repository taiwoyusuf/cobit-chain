from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_AUTONOMOUS_RECOVERY_GRID_V1_ACTIVE"

if MARKER in text:
    print("Autonomous Recovery Grid already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_AUTONOMOUS_RECOVERY_GRID_V1_ACTIVE
# ============================================================

IRLT_RECOVERY_GRID_V1 = [
    {
        "recovery": "CAPA Recovery",
        "score": 84,
        "state": "Recovering"
    },
    {
        "recovery": "Inspection Recovery",
        "score": 95,
        "state": "Protected"
    },
    {
        "recovery": "Cold Chain Recovery",
        "score": 91,
        "state": "Stable"
    },
    {
        "recovery": "Evidence Restoration",
        "score": 98,
        "state": "Verified"
    },
    {
        "recovery": "Commercial Continuity",
        "score": 94,
        "state": "Operational"
    },
    {
        "recovery": "Dose Traceability",
        "score": 99,
        "state": "Certified"
    }
]

@app.route("/irlt-commercial-readiness/autonomous-recovery")
def irlt_autonomous_recovery():

    recovery_score = round(
        sum(x["score"] for x in IRLT_RECOVERY_GRID_V1)
        / len(IRLT_RECOVERY_GRID_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>Autonomous Recovery Grid</title>

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
                font-size:72px;
                margin-bottom:10px;
            }

            p{
                color:#bfc7d4;
                line-height:1.7;
            }

            .score{
                font-size:120px;
                color:#ff9f1c;
                margin:30px 0;
            }

            .grid{
                display:grid;
                grid-template-columns:repeat(3,1fr);
                gap:20px;
                margin-top:30px;
            }

            .card{
                background:#161d28;
                border-radius:20px;
                padding:24px;
                border:1px solid rgba(255,255,255,0.08);
            }

            .card h2{
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

        <h1>Autonomous Recovery Grid</h1>

        <p>
            Enterprise recovery governance environment for
            operational survivability restoration,
            commercialization continuity stabilization,
            inspection resilience coordination,
            and evidence recovery intelligence.
        </p>

        <div class="score">
            {{ recovery_score }}%
        </div>

        <div class="grid">

            {% for row in recovery %}

            <div class="card">

                <h2>{{ row.recovery }}</h2>

                <p>
                    Recovery Score: {{ row.score }}%
                </p>

                <div class="pill">
                    {{ row.state }}
                </div>

            </div>

            {% endfor %}

        </div>

    </body>

    </html>

    ''',
    recovery=IRLT_RECOVERY_GRID_V1,
    recovery_score=recovery_score
    )


@app.route("/irlt-commercial-readiness/autonomous-recovery/api")
def irlt_autonomous_recovery_api():

    return jsonify({
        "recovery_score": round(
            sum(x["score"] for x in IRLT_RECOVERY_GRID_V1)
            / len(IRLT_RECOVERY_GRID_V1)
        ),
        "recovery": IRLT_RECOVERY_GRID_V1
    })

# ============================================================
# END IRLT_AUTONOMOUS_RECOVERY_GRID_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("Autonomous Recovery Grid appended successfully.")
