from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_GOVERNANCE_NEBULA_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Governance Nebula Engine already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_GOVERNANCE_NEBULA_ENGINE_V1_ACTIVE
# ============================================================

IRLT_GOVERNANCE_NEBULA_V1 = [
    {
        "nebula": "Commercial Readiness Expansion",
        "density": 100,
        "state": "Operational"
    },
    {
        "nebula": "Inspection Defense Field",
        "density": 100,
        "state": "Protected"
    },
    {
        "nebula": "Evidence Integrity Constellation",
        "density": 100,
        "state": "Verified"
    },
    {
        "nebula": "Cold Chain Governance",
        "density": 98,
        "state": "Stable"
    },
    {
        "nebula": "CAPA Recovery Coordination",
        "density": 95,
        "state": "Observed"
    },
    {
        "nebula": "Dose Traceability Assurance",
        "density": 100,
        "state": "Certified"
    }
]

@app.route("/irlt-commercial-readiness/governance-nebula")
def irlt_governance_nebula():

    nebula_score = round(
        sum(x["density"] for x in IRLT_GOVERNANCE_NEBULA_V1)
        / len(IRLT_GOVERNANCE_NEBULA_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>Governance Nebula Engine</title>

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

        <h1>Governance Nebula Engine</h1>

        <p>
            Enterprise governance nebula environment for
            commercialization intelligence expansion,
            operational survivability synchronization,
            inspection defense orchestration,
            and radiopharma governance convergence.
        </p>

        <div class="score">
            {{ nebula_score }}%
        </div>

        <div class="grid">

            {% for row in nebula %}

            <div class="card">

                <h2>{{ row.nebula }}</h2>

                <p>
                    Density Index: {{ row.density }}%
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
    nebula=IRLT_GOVERNANCE_NEBULA_V1,
    nebula_score=nebula_score
    )


@app.route("/irlt-commercial-readiness/governance-nebula/api")
def irlt_governance_nebula_api():

    return jsonify({
        "nebula_score": round(
            sum(x["density"] for x in IRLT_GOVERNANCE_NEBULA_V1)
            / len(IRLT_GOVERNANCE_NEBULA_V1)
        ),
        "nebula": IRLT_GOVERNANCE_NEBULA_V1
    })

# ============================================================
# END IRLT_GOVERNANCE_NEBULA_ENGINE_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("Governance Nebula Engine appended successfully.")
