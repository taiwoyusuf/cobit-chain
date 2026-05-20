from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_GOVERNANCE_TITAN_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Governance Titan Engine already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_GOVERNANCE_TITAN_ENGINE_V1_ACTIVE
# ============================================================

IRLT_GOVERNANCE_TITAN_V1 = [
    {
        "titan": "Commercial Governance Dominance",
        "power": 100,
        "state": "Operational"
    },
    {
        "titan": "Inspection Defense Command",
        "power": 99,
        "state": "Protected"
    },
    {
        "titan": "Evidence Integrity Supremacy",
        "power": 100,
        "state": "Verified"
    },
    {
        "titan": "Cold Chain Governance",
        "power": 96,
        "state": "Stable"
    },
    {
        "titan": "CAPA Recovery Intelligence",
        "power": 91,
        "state": "Observed"
    },
    {
        "titan": "Dose Traceability Assurance",
        "power": 100,
        "state": "Certified"
    }
]

@app.route("/irlt-commercial-readiness/governance-titan")
def irlt_governance_titan():

    titan_score = round(
        sum(x["power"] for x in IRLT_GOVERNANCE_TITAN_V1)
        / len(IRLT_GOVERNANCE_TITAN_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>Governance Titan Engine</title>

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

        <h1>Governance Titan Engine</h1>

        <p>
            Enterprise governance titan environment for
            commercialization command dominance,
            operational survivability protection,
            inspection defense synchronization,
            and radiopharma governance supremacy.
        </p>

        <div class="score">
            {{ titan_score }}%
        </div>

        <div class="grid">

            {% for row in titan %}

            <div class="card">

                <h2>{{ row.titan }}</h2>

                <p>
                    Power Index: {{ row.power }}%
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
    titan=IRLT_GOVERNANCE_TITAN_V1,
    titan_score=titan_score
    )


@app.route("/irlt-commercial-readiness/governance-titan/api")
def irlt_governance_titan_api():

    return jsonify({
        "titan_score": round(
            sum(x["power"] for x in IRLT_GOVERNANCE_TITAN_V1)
            / len(IRLT_GOVERNANCE_TITAN_V1)
        ),
        "titan": IRLT_GOVERNANCE_TITAN_V1
    })

# ============================================================
# END IRLT_GOVERNANCE_TITAN_ENGINE_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("Governance Titan Engine appended successfully.")
