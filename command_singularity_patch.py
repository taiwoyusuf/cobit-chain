from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_COMMAND_SINGULARITY_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Command Singularity Engine already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_COMMAND_SINGULARITY_ENGINE_V1_ACTIVE
# ============================================================

IRLT_COMMAND_SINGULARITY_V1 = [
    {
        "command": "Commercial Release Governance",
        "command_score": 98,
        "state": "Operational"
    },
    {
        "command": "Inspection Defense Intelligence",
        "command_score": 97,
        "state": "Protected"
    },
    {
        "command": "Evidence Integrity Correlation",
        "command_score": 99,
        "state": "Verified"
    },
    {
        "command": "Cold Chain Continuity",
        "command_score": 93,
        "state": "Stable"
    },
    {
        "command": "CAPA Recovery Synchronization",
        "command_score": 88,
        "state": "Observed"
    },
    {
        "command": "Dose Governance Assurance",
        "command_score": 99,
        "state": "Certified"
    }
]

@app.route("/irlt-commercial-readiness/command-singularity")
def irlt_command_singularity():

    singularity_score = round(
        sum(x["command_score"] for x in IRLT_COMMAND_SINGULARITY_V1)
        / len(IRLT_COMMAND_SINGULARITY_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>Command Singularity Engine</title>

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

        <h1>Command Singularity Engine</h1>

        <p>
            Enterprise command singularity environment for
            commercialization governance convergence,
            operational survivability orchestration,
            inspection intelligence synchronization,
            and radiopharma command continuity.
        </p>

        <div class="score">
            {{ singularity_score }}%
        </div>

        <div class="grid">

            {% for row in command %}

            <div class="card">

                <h2>{{ row.command }}</h2>

                <p>
                    Command Score: {{ row.command_score }}%
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
    command=IRLT_COMMAND_SINGULARITY_V1,
    singularity_score=singularity_score
    )


@app.route("/irlt-commercial-readiness/command-singularity/api")
def irlt_command_singularity_api():

    return jsonify({
        "singularity_score": round(
            sum(x["command_score"] for x in IRLT_COMMAND_SINGULARITY_V1)
            / len(IRLT_COMMAND_SINGULARITY_V1)
        ),
        "command": IRLT_COMMAND_SINGULARITY_V1
    })

# ============================================================
# END IRLT_COMMAND_SINGULARITY_ENGINE_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("Command Singularity Engine appended successfully.")
