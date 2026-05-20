from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_GOVERNANCE_CITADEL_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Governance Citadel Engine already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_GOVERNANCE_CITADEL_ENGINE_V1_ACTIVE
# ============================================================

IRLT_GOVERNANCE_CITADEL_V1 = [
    {
        "citadel": "Commercial Readiness Fortress",
        "fortification": 99,
        "state": "Operational"
    },
    {
        "citadel": "Inspection Defense Shield",
        "fortification": 98,
        "state": "Protected"
    },
    {
        "citadel": "Evidence Integrity Vault",
        "fortification": 100,
        "state": "Verified"
    },
    {
        "citadel": "Cold Chain Governance",
        "fortification": 95,
        "state": "Stable"
    },
    {
        "citadel": "CAPA Recovery Intelligence",
        "fortification": 90,
        "state": "Observed"
    },
    {
        "citadel": "Dose Traceability Command",
        "fortification": 100,
        "state": "Certified"
    }
]

@app.route("/irlt-commercial-readiness/governance-citadel")
def irlt_governance_citadel():

    citadel_score = round(
        sum(x["fortification"] for x in IRLT_GOVERNANCE_CITADEL_V1)
        / len(IRLT_GOVERNANCE_CITADEL_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>Governance Citadel Engine</title>

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

        <h1>Governance Citadel Engine</h1>

        <p>
            Enterprise governance citadel environment for
            commercialization defense orchestration,
            operational survivability protection,
            inspection resilience synchronization,
            and radiopharma governance fortification.
        </p>

        <div class="score">
            {{ citadel_score }}%
        </div>

        <div class="grid">

            {% for row in citadel %}

            <div class="card">

                <h2>{{ row.citadel }}</h2>

                <p>
                    Fortification Index: {{ row.fortification }}%
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
    citadel=IRLT_GOVERNANCE_CITADEL_V1,
    citadel_score=citadel_score
    )


@app.route("/irlt-commercial-readiness/governance-citadel/api")
def irlt_governance_citadel_api():

    return jsonify({
        "citadel_score": round(
            sum(x["fortification"] for x in IRLT_GOVERNANCE_CITADEL_V1)
            / len(IRLT_GOVERNANCE_CITADEL_V1)
        ),
        "citadel": IRLT_GOVERNANCE_CITADEL_V1
    })

# ============================================================
# END IRLT_GOVERNANCE_CITADEL_ENGINE_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("Governance Citadel Engine appended successfully.")
