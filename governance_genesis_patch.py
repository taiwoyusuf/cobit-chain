from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_GOVERNANCE_GENESIS_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Governance Genesis Engine already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_GOVERNANCE_GENESIS_ENGINE_V1_ACTIVE
# ============================================================

IRLT_GOVERNANCE_GENESIS_V1 = [
    {
        "genesis": "Commercial Readiness Foundation",
        "origin_score": 100,
        "state": "Operational"
    },
    {
        "genesis": "Inspection Defense Core",
        "origin_score": 100,
        "state": "Protected"
    },
    {
        "genesis": "Evidence Integrity Genesis",
        "origin_score": 100,
        "state": "Verified"
    },
    {
        "genesis": "Cold Chain Governance",
        "origin_score": 97,
        "state": "Stable"
    },
    {
        "genesis": "CAPA Recovery Intelligence",
        "origin_score": 94,
        "state": "Observed"
    },
    {
        "genesis": "Dose Traceability Assurance",
        "origin_score": 100,
        "state": "Certified"
    }
]

@app.route("/irlt-commercial-readiness/governance-genesis")
def irlt_governance_genesis():

    genesis_score = round(
        sum(x["origin_score"] for x in IRLT_GOVERNANCE_GENESIS_V1)
        / len(IRLT_GOVERNANCE_GENESIS_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>Governance Genesis Engine</title>

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

        <h1>Governance Genesis Engine</h1>

        <p>
            Enterprise governance genesis environment for
            commercialization foundation orchestration,
            operational survivability continuity,
            inspection defense synchronization,
            and radiopharma governance origin intelligence.
        </p>

        <div class="score">
            {{ genesis_score }}%
        </div>

        <div class="grid">

            {% for row in genesis %}

            <div class="card">

                <h2>{{ row.genesis }}</h2>

                <p>
                    Origin Index: {{ row.origin_score }}%
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
    genesis=IRLT_GOVERNANCE_GENESIS_V1,
    genesis_score=genesis_score
    )


@app.route("/irlt-commercial-readiness/governance-genesis/api")
def irlt_governance_genesis_api():

    return jsonify({
        "genesis_score": round(
            sum(x["origin_score"] for x in IRLT_GOVERNANCE_GENESIS_V1)
            / len(IRLT_GOVERNANCE_GENESIS_V1)
        ),
        "genesis": IRLT_GOVERNANCE_GENESIS_V1
    })

# ============================================================
# END IRLT_GOVERNANCE_GENESIS_ENGINE_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("Governance Genesis Engine appended successfully.")
