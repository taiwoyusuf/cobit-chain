from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_GOVERNANCE_ETERNITY_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Governance Eternity Engine already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_GOVERNANCE_ETERNITY_ENGINE_V1_ACTIVE
# ============================================================

IRLT_GOVERNANCE_ETERNITY_V1 = [
    {
        "eternity": "Commercial Governance Continuity",
        "eternity_score": 100,
        "state": "Operational"
    },
    {
        "eternity": "Inspection Survivability Shield",
        "eternity_score": 99,
        "state": "Protected"
    },
    {
        "eternity": "Evidence Integrity Preservation",
        "eternity_score": 100,
        "state": "Verified"
    },
    {
        "eternity": "Cold Chain Governance Stability",
        "eternity_score": 96,
        "state": "Stable"
    },
    {
        "eternity": "CAPA Recovery Synchronization",
        "eternity_score": 92,
        "state": "Observed"
    },
    {
        "eternity": "Dose Traceability Assurance",
        "eternity_score": 100,
        "state": "Certified"
    }
]

@app.route("/irlt-commercial-readiness/governance-eternity")
def irlt_governance_eternity():

    eternity_score = round(
        sum(x["eternity_score"] for x in IRLT_GOVERNANCE_ETERNITY_V1)
        / len(IRLT_GOVERNANCE_ETERNITY_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>Governance Eternity Engine</title>

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

        <h1>Governance Eternity Engine</h1>

        <p>
            Enterprise governance eternity environment for
            commercialization continuity preservation,
            operational survivability orchestration,
            inspection defense permanence,
            and radiopharma governance assurance longevity.
        </p>

        <div class="score">
            {{ eternity_score }}%
        </div>

        <div class="grid">

            {% for row in eternity %}

            <div class="card">

                <h2>{{ row.eternity }}</h2>

                <p>
                    Eternity Index: {{ row.eternity_score }}%
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
    eternity=IRLT_GOVERNANCE_ETERNITY_V1,
    eternity_score=eternity_score
    )


@app.route("/irlt-commercial-readiness/governance-eternity/api")
def irlt_governance_eternity_api():

    return jsonify({
        "eternity_score": round(
            sum(x["eternity_score"] for x in IRLT_GOVERNANCE_ETERNITY_V1)
            / len(IRLT_GOVERNANCE_ETERNITY_V1)
        ),
        "eternity": IRLT_GOVERNANCE_ETERNITY_V1
    })

# ============================================================
# END IRLT_GOVERNANCE_ETERNITY_ENGINE_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("Governance Eternity Engine appended successfully.")
