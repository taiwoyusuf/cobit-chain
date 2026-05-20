from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_GOVERNANCE_TRANSCENDENCE_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Governance Transcendence Engine already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_GOVERNANCE_TRANSCENDENCE_ENGINE_V1_ACTIVE
# ============================================================

IRLT_GOVERNANCE_TRANSCENDENCE_V1 = [
    {
        "transcendence": "Commercial Governance Intelligence",
        "elevation": 99,
        "state": "Operational"
    },
    {
        "transcendence": "Inspection Survivability",
        "elevation": 98,
        "state": "Protected"
    },
    {
        "transcendence": "Evidence Integrity Correlation",
        "elevation": 100,
        "state": "Verified"
    },
    {
        "transcendence": "Cold Chain Governance",
        "elevation": 95,
        "state": "Stable"
    },
    {
        "transcendence": "CAPA Recovery Synchronization",
        "elevation": 89,
        "state": "Observed"
    },
    {
        "transcendence": "Dose Traceability Assurance",
        "elevation": 100,
        "state": "Certified"
    }
]

@app.route("/irlt-commercial-readiness/governance-transcendence")
def irlt_governance_transcendence():

    transcendence_score = round(
        sum(x["elevation"] for x in IRLT_GOVERNANCE_TRANSCENDENCE_V1)
        / len(IRLT_GOVERNANCE_TRANSCENDENCE_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>Governance Transcendence Engine</title>

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

        <h1>Governance Transcendence Engine</h1>

        <p>
            Enterprise governance transcendence environment for
            commercialization intelligence elevation,
            operational survivability orchestration,
            inspection defense synchronization,
            and radiopharma trust convergence.
        </p>

        <div class="score">
            {{ transcendence_score }}%
        </div>

        <div class="grid">

            {% for row in transcendence %}

            <div class="card">

                <h2>{{ row.transcendence }}</h2>

                <p>
                    Elevation Index: {{ row.elevation }}%
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
    transcendence=IRLT_GOVERNANCE_TRANSCENDENCE_V1,
    transcendence_score=transcendence_score
    )


@app.route("/irlt-commercial-readiness/governance-transcendence/api")
def irlt_governance_transcendence_api():

    return jsonify({
        "transcendence_score": round(
            sum(x["elevation"] for x in IRLT_GOVERNANCE_TRANSCENDENCE_V1)
            / len(IRLT_GOVERNANCE_TRANSCENDENCE_V1)
        ),
        "transcendence": IRLT_GOVERNANCE_TRANSCENDENCE_V1
    })

# ============================================================
# END IRLT_GOVERNANCE_TRANSCENDENCE_ENGINE_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("Governance Transcendence Engine appended successfully.")
