from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_GOVERNANCE_APEX_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Governance Apex Engine already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_GOVERNANCE_APEX_ENGINE_V1_ACTIVE
# ============================================================

IRLT_GOVERNANCE_APEX_V1 = [
    {
        "apex": "Commercial Readiness Command",
        "apex_score": 99,
        "state": "Operational"
    },
    {
        "apex": "Inspection Survivability",
        "apex_score": 98,
        "state": "Protected"
    },
    {
        "apex": "Evidence Integrity Assurance",
        "apex_score": 100,
        "state": "Verified"
    },
    {
        "apex": "Cold Chain Governance",
        "apex_score": 95,
        "state": "Stable"
    },
    {
        "apex": "CAPA Recovery Intelligence",
        "apex_score": 90,
        "state": "Observed"
    },
    {
        "apex": "Dose Traceability Coordination",
        "apex_score": 100,
        "state": "Certified"
    }
]

@app.route("/irlt-commercial-readiness/governance-apex")
def irlt_governance_apex():

    apex_score = round(
        sum(x["apex_score"] for x in IRLT_GOVERNANCE_APEX_V1)
        / len(IRLT_GOVERNANCE_APEX_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>Governance Apex Engine</title>

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

        <h1>Governance Apex Engine</h1>

        <p>
            Enterprise governance apex environment for
            commercialization intelligence leadership,
            operational survivability orchestration,
            inspection defense synchronization,
            and radiopharma governance convergence.
        </p>

        <div class="score">
            {{ apex_score }}%
        </div>

        <div class="grid">

            {% for row in apex %}

            <div class="card">

                <h2>{{ row.apex }}</h2>

                <p>
                    Apex Score: {{ row.apex_score }}%
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
    apex=IRLT_GOVERNANCE_APEX_V1,
    apex_score=apex_score
    )


@app.route("/irlt-commercial-readiness/governance-apex/api")
def irlt_governance_apex_api():

    return jsonify({
        "apex_score": round(
            sum(x["apex_score"] for x in IRLT_GOVERNANCE_APEX_V1)
            / len(IRLT_GOVERNANCE_APEX_V1)
        ),
        "apex": IRLT_GOVERNANCE_APEX_V1
    })

# ============================================================
# END IRLT_GOVERNANCE_APEX_ENGINE_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("Governance Apex Engine appended successfully.")
