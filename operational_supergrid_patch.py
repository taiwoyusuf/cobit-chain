from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_OPERATIONAL_SUPERGRID_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Operational SuperGrid Engine already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_OPERATIONAL_SUPERGRID_ENGINE_V1_ACTIVE
# ============================================================

IRLT_OPERATIONAL_SUPERGRID_V1 = [
    {
        "supergrid": "Commercial Release Governance",
        "capacity": 97,
        "state": "Operational"
    },
    {
        "supergrid": "Inspection Defense Intelligence",
        "capacity": 96,
        "state": "Protected"
    },
    {
        "supergrid": "Evidence Correlation",
        "capacity": 99,
        "state": "Verified"
    },
    {
        "supergrid": "Cold Chain Continuity",
        "capacity": 93,
        "state": "Stable"
    },
    {
        "supergrid": "CAPA Recovery Synchronization",
        "capacity": 87,
        "state": "Observed"
    },
    {
        "supergrid": "Dose Governance Assurance",
        "capacity": 99,
        "state": "Certified"
    }
]

@app.route("/irlt-commercial-readiness/operational-supergrid")
def irlt_operational_supergrid():

    supergrid_score = round(
        sum(x["capacity"] for x in IRLT_OPERATIONAL_SUPERGRID_V1)
        / len(IRLT_OPERATIONAL_SUPERGRID_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>Operational SuperGrid Engine</title>

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

        <h1>Operational SuperGrid Engine</h1>

        <p>
            Enterprise operational supergrid environment for
            commercialization synchronization,
            governance survivability orchestration,
            inspection continuity intelligence,
            and radiopharma operational coordination.
        </p>

        <div class="score">
            {{ supergrid_score }}%
        </div>

        <div class="grid">

            {% for row in supergrid %}

            <div class="card">

                <h2>{{ row.supergrid }}</h2>

                <p>
                    Capacity Index: {{ row.capacity }}%
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
    supergrid=IRLT_OPERATIONAL_SUPERGRID_V1,
    supergrid_score=supergrid_score
    )


@app.route("/irlt-commercial-readiness/operational-supergrid/api")
def irlt_operational_supergrid_api():

    return jsonify({
        "supergrid_score": round(
            sum(x["capacity"] for x in IRLT_OPERATIONAL_SUPERGRID_V1)
            / len(IRLT_OPERATIONAL_SUPERGRID_V1)
        ),
        "supergrid": IRLT_OPERATIONAL_SUPERGRID_V1
    })

# ============================================================
# END IRLT_OPERATIONAL_SUPERGRID_ENGINE_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("Operational SuperGrid Engine appended successfully.")
