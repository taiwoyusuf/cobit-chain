from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_COMMERCIALIZATION_READINESS_FUSION_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Commercialization Readiness Fusion already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_COMMERCIALIZATION_READINESS_FUSION_ENGINE_V1_ACTIVE
# ============================================================

IRLT_READINESS_FUSION_V1 = [
    {
        "pillar": "Manufacturing Readiness",
        "readiness": 95,
        "state": "Launch Ready"
    },
    {
        "pillar": "Inspection Defense",
        "readiness": 94,
        "state": "Defensible"
    },
    {
        "pillar": "Dose Governance",
        "readiness": 99,
        "state": "Verified"
    },
    {
        "pillar": "Cold Chain Stability",
        "readiness": 91,
        "state": "Stable"
    },
    {
        "pillar": "CAPA Recovery",
        "readiness": 83,
        "state": "Observed"
    },
    {
        "pillar": "Evidence Continuity",
        "readiness": 97,
        "state": "Protected"
    }
]

@app.route("/irlt-commercial-readiness/readiness-fusion")
def irlt_readiness_fusion():

    fusion_score = round(
        sum(x["readiness"] for x in IRLT_READINESS_FUSION_V1)
        / len(IRLT_READINESS_FUSION_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>Commercialization Readiness Fusion</title>

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

        <h1>Commercialization Readiness Fusion</h1>

        <p>
            Enterprise commercialization governance fusion environment
            for operational readiness synchronization,
            radiopharma survivability alignment,
            inspection readiness convergence,
            and executive trust orchestration.
        </p>

        <div class="score">
            {{ fusion_score }}%
        </div>

        <div class="grid">

            {% for row in fusion %}

            <div class="card">

                <h2>{{ row.pillar }}</h2>

                <p>
                    Readiness: {{ row.readiness }}%
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
    fusion=IRLT_READINESS_FUSION_V1,
    fusion_score=fusion_score
    )


@app.route("/irlt-commercial-readiness/readiness-fusion/api")
def irlt_readiness_fusion_api():

    return jsonify({
        "fusion_score": round(
            sum(x["readiness"] for x in IRLT_READINESS_FUSION_V1)
            / len(IRLT_READINESS_FUSION_V1)
        ),
        "fusion": IRLT_READINESS_FUSION_V1
    })

# ============================================================
# END IRLT_COMMERCIALIZATION_READINESS_FUSION_ENGINE_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("Commercialization Readiness Fusion appended successfully.")
