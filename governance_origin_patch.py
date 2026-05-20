from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_GOVERNANCE_ORIGIN_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Governance Origin Engine already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_GOVERNANCE_ORIGIN_ENGINE_V1_ACTIVE
# ============================================================

IRLT_GOVERNANCE_ORIGIN_V1 = [
    {
        "origin": "Commercial Governance Foundation",
        "origin_index": 100,
        "state": "Operational"
    },
    {
        "origin": "Inspection Defense Framework",
        "origin_index": 100,
        "state": "Protected"
    },
    {
        "origin": "Evidence Integrity Architecture",
        "origin_index": 100,
        "state": "Verified"
    },
    {
        "origin": "Cold Chain Governance",
        "origin_index": 98,
        "state": "Stable"
    },
    {
        "origin": "CAPA Recovery Synchronization",
        "origin_index": 94,
        "state": "Observed"
    },
    {
        "origin": "Dose Traceability Assurance",
        "origin_index": 100,
        "state": "Certified"
    }
]

@app.route("/irlt-commercial-readiness/governance-origin")
def irlt_governance_origin():

    origin_score = round(
        sum(x["origin_index"] for x in IRLT_GOVERNANCE_ORIGIN_V1)
        / len(IRLT_GOVERNANCE_ORIGIN_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>Governance Origin Engine</title>

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

        <h1>Governance Origin Engine</h1>

        <p>
            Enterprise governance origin environment for
            commercialization foundation intelligence,
            operational survivability orchestration,
            inspection defense continuity,
            and radiopharma governance synchronization.
        </p>

        <div class="score">
            {{ origin_score }}%
        </div>

        <div class="grid">

            {% for row in origin %}

            <div class="card">

                <h2>{{ row.origin }}</h2>

                <p>
                    Origin Index: {{ row.origin_index }}%
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
    origin=IRLT_GOVERNANCE_ORIGIN_V1,
    origin_score=origin_score
    )


@app.route("/irlt-commercial-readiness/governance-origin/api")
def irlt_governance_origin_api():

    return jsonify({
        "origin_score": round(
            sum(x["origin_index"] for x in IRLT_GOVERNANCE_ORIGIN_V1)
            / len(IRLT_GOVERNANCE_ORIGIN_V1)
        ),
        "origin": IRLT_GOVERNANCE_ORIGIN_V1
    })

# ============================================================
# END IRLT_GOVERNANCE_ORIGIN_ENGINE_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("Governance Origin Engine appended successfully.")
