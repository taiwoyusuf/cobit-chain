from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_RESILIENCE_FABRIC_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Resilience Fabric Engine already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_RESILIENCE_FABRIC_ENGINE_V1_ACTIVE
# ============================================================

IRLT_RESILIENCE_FABRIC_V1 = [
    {
        "fabric": "Commercial Continuity",
        "strength": 96,
        "state": "Operational"
    },
    {
        "fabric": "Inspection Survivability",
        "strength": 95,
        "state": "Protected"
    },
    {
        "fabric": "Evidence Preservation",
        "strength": 98,
        "state": "Verified"
    },
    {
        "fabric": "Cold Chain Assurance",
        "strength": 92,
        "state": "Stable"
    },
    {
        "fabric": "CAPA Stabilization",
        "strength": 84,
        "state": "Recovering"
    },
    {
        "fabric": "Dose Governance",
        "strength": 99,
        "state": "Certified"
    }
]

@app.route("/irlt-commercial-readiness/resilience-fabric")
def irlt_resilience_fabric():

    resilience_score = round(
        sum(x["strength"] for x in IRLT_RESILIENCE_FABRIC_V1)
        / len(IRLT_RESILIENCE_FABRIC_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>Resilience Fabric Engine</title>

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

        <h1>Resilience Fabric Engine</h1>

        <p>
            Enterprise operational resilience environment for
            commercialization survivability preservation,
            governance continuity orchestration,
            radiopharma operational stabilization,
            and inspection resilience synchronization.
        </p>

        <div class="score">
            {{ resilience_score }}%
        </div>

        <div class="grid">

            {% for row in resilience %}

            <div class="card">

                <h2>{{ row.fabric }}</h2>

                <p>
                    Strength: {{ row.strength }}%
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
    resilience=IRLT_RESILIENCE_FABRIC_V1,
    resilience_score=resilience_score
    )


@app.route("/irlt-commercial-readiness/resilience-fabric/api")
def irlt_resilience_fabric_api():

    return jsonify({
        "resilience_score": round(
            sum(x["strength"] for x in IRLT_RESILIENCE_FABRIC_V1)
            / len(IRLT_RESILIENCE_FABRIC_V1)
        ),
        "resilience": IRLT_RESILIENCE_FABRIC_V1
    })

# ============================================================
# END IRLT_RESILIENCE_FABRIC_ENGINE_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("Resilience Fabric Engine appended successfully.")
