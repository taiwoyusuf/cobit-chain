from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_GOVERNANCE_HYPERGRID_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Governance HyperGrid already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_GOVERNANCE_HYPERGRID_ENGINE_V1_ACTIVE
# ============================================================

IRLT_HYPERGRID_V1 = [
    {
        "grid": "Commercial Operations",
        "velocity": 97,
        "state": "Operational"
    },
    {
        "grid": "Inspection Defense",
        "velocity": 95,
        "state": "Protected"
    },
    {
        "grid": "Evidence Intelligence",
        "velocity": 99,
        "state": "Verified"
    },
    {
        "grid": "Cold Chain Continuity",
        "velocity": 92,
        "state": "Stable"
    },
    {
        "grid": "CAPA Recovery Mapping",
        "velocity": 86,
        "state": "Observed"
    },
    {
        "grid": "Dose Governance",
        "velocity": 99,
        "state": "Certified"
    }
]

@app.route("/irlt-commercial-readiness/governance-hypergrid")
def irlt_governance_hypergrid():

    hypergrid_score = round(
        sum(x["velocity"] for x in IRLT_HYPERGRID_V1)
        / len(IRLT_HYPERGRID_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>Governance HyperGrid Engine</title>

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

        <h1>Governance HyperGrid Engine</h1>

        <p>
            Enterprise hypergrid intelligence environment for
            commercialization governance acceleration,
            operational survivability synchronization,
            inspection defense coordination,
            and radiopharma trust orchestration.
        </p>

        <div class="score">
            {{ hypergrid_score }}%
        </div>

        <div class="grid">

            {% for row in hypergrid %}

            <div class="card">

                <h2>{{ row.grid }}</h2>

                <p>
                    Velocity Index: {{ row.velocity }}%
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
    hypergrid=IRLT_HYPERGRID_V1,
    hypergrid_score=hypergrid_score
    )


@app.route("/irlt-commercial-readiness/governance-hypergrid/api")
def irlt_governance_hypergrid_api():

    return jsonify({
        "hypergrid_score": round(
            sum(x["velocity"] for x in IRLT_HYPERGRID_V1)
            / len(IRLT_HYPERGRID_V1)
        ),
        "hypergrid": IRLT_HYPERGRID_V1
    })

# ============================================================
# END IRLT_GOVERNANCE_HYPERGRID_ENGINE_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("Governance HyperGrid Engine appended successfully.")
