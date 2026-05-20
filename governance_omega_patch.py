from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_GOVERNANCE_OMEGA_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Governance Omega Engine already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_GOVERNANCE_OMEGA_ENGINE_V1_ACTIVE
# ============================================================

IRLT_GOVERNANCE_OMEGA_V1 = [
    {
        "omega": "Commercial Governance Supremacy",
        "omega_score": 100,
        "state": "Operational"
    },
    {
        "omega": "Inspection Survivability Shield",
        "omega_score": 100,
        "state": "Protected"
    },
    {
        "omega": "Evidence Integrity Preservation",
        "omega_score": 100,
        "state": "Verified"
    },
    {
        "omega": "Cold Chain Governance Continuity",
        "omega_score": 97,
        "state": "Stable"
    },
    {
        "omega": "CAPA Recovery Intelligence",
        "omega_score": 93,
        "state": "Observed"
    },
    {
        "omega": "Dose Traceability Assurance",
        "omega_score": 100,
        "state": "Certified"
    }
]

@app.route("/irlt-commercial-readiness/governance-omega")
def irlt_governance_omega():

    omega_score = round(
        sum(x["omega_score"] for x in IRLT_GOVERNANCE_OMEGA_V1)
        / len(IRLT_GOVERNANCE_OMEGA_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>Governance Omega Engine</title>

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

        <h1>Governance Omega Engine</h1>

        <p>
            Enterprise governance omega environment for
            commercialization command supremacy,
            operational survivability permanence,
            inspection defense orchestration,
            and radiopharma governance convergence.
        </p>

        <div class="score">
            {{ omega_score }}%
        </div>

        <div class="grid">

            {% for row in omega %}

            <div class="card">

                <h2>{{ row.omega }}</h2>

                <p>
                    Omega Index: {{ row.omega_score }}%
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
    omega=IRLT_GOVERNANCE_OMEGA_V1,
    omega_score=omega_score
    )


@app.route("/irlt-commercial-readiness/governance-omega/api")
def irlt_governance_omega_api():

    return jsonify({
        "omega_score": round(
            sum(x["omega_score"] for x in IRLT_GOVERNANCE_OMEGA_V1)
            / len(IRLT_GOVERNANCE_OMEGA_V1)
        ),
        "omega": IRLT_GOVERNANCE_OMEGA_V1
    })

# ============================================================
# END IRLT_GOVERNANCE_OMEGA_ENGINE_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("Governance Omega Engine appended successfully.")
