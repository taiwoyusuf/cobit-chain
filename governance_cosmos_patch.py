from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_GOVERNANCE_COSMOS_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Governance Cosmos already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_GOVERNANCE_COSMOS_ENGINE_V1_ACTIVE
# ============================================================

IRLT_GOVERNANCE_COSMOS_V1 = [
    {
        "cluster": "Commercial Operations",
        "gravity": 96,
        "state": "Stable"
    },
    {
        "cluster": "Inspection Defense",
        "gravity": 95,
        "state": "Protected"
    },
    {
        "cluster": "Evidence Intelligence",
        "gravity": 98,
        "state": "Verified"
    },
    {
        "cluster": "Cold Chain Governance",
        "gravity": 92,
        "state": "Controlled"
    },
    {
        "cluster": "CAPA Stabilization",
        "gravity": 85,
        "state": "Observed"
    },
    {
        "cluster": "Dose Traceability",
        "gravity": 99,
        "state": "Certified"
    }
]

@app.route("/irlt-commercial-readiness/governance-cosmos")
def irlt_governance_cosmos():

    cosmos_score = round(
        sum(x["gravity"] for x in IRLT_GOVERNANCE_COSMOS_V1)
        / len(IRLT_GOVERNANCE_COSMOS_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>Governance Cosmos Engine</title>

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

        <h1>Governance Cosmos Engine</h1>

        <p>
            Enterprise governance cosmos environment for
            commercialization intelligence orchestration,
            operational survivability synchronization,
            inspection resilience visibility,
            and radiopharma governance convergence.
        </p>

        <div class="score">
            {{ cosmos_score }}%
        </div>

        <div class="grid">

            {% for row in cosmos %}

            <div class="card">

                <h2>{{ row.cluster }}</h2>

                <p>
                    Gravity Index: {{ row.gravity }}%
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
    cosmos=IRLT_GOVERNANCE_COSMOS_V1,
    cosmos_score=cosmos_score
    )


@app.route("/irlt-commercial-readiness/governance-cosmos/api")
def irlt_governance_cosmos_api():

    return jsonify({
        "cosmos_score": round(
            sum(x["gravity"] for x in IRLT_GOVERNANCE_COSMOS_V1)
            / len(IRLT_GOVERNANCE_COSMOS_V1)
        ),
        "cosmos": IRLT_GOVERNANCE_COSMOS_V1
    })

# ============================================================
# END IRLT_GOVERNANCE_COSMOS_ENGINE_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("Governance Cosmos Engine appended successfully.")
