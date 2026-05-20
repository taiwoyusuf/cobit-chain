from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_TRUST_FUSION_CORE_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Trust Fusion Core already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_TRUST_FUSION_CORE_ENGINE_V1_ACTIVE
# ============================================================

IRLT_TRUST_FUSION_CORE_V1 = [
    {
        "fusion": "Commercial Readiness Intelligence",
        "fusion_score": 98,
        "state": "Operational"
    },
    {
        "fusion": "Inspection Survivability",
        "fusion_score": 96,
        "state": "Protected"
    },
    {
        "fusion": "Evidence Correlation",
        "fusion_score": 99,
        "state": "Verified"
    },
    {
        "fusion": "Cold Chain Governance",
        "fusion_score": 93,
        "state": "Stable"
    },
    {
        "fusion": "CAPA Recovery Synchronization",
        "fusion_score": 88,
        "state": "Observed"
    },
    {
        "fusion": "Dose Governance Integrity",
        "fusion_score": 99,
        "state": "Certified"
    }
]

@app.route("/irlt-commercial-readiness/trust-fusion-core")
def irlt_trust_fusion_core():

    fusion_score = round(
        sum(x["fusion_score"] for x in IRLT_TRUST_FUSION_CORE_V1)
        / len(IRLT_TRUST_FUSION_CORE_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>Trust Fusion Core Engine</title>

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

        <h1>Trust Fusion Core Engine</h1>

        <p>
            Enterprise trust fusion environment for
            commercialization intelligence convergence,
            governance survivability orchestration,
            inspection defense synchronization,
            and radiopharma operational trust continuity.
        </p>

        <div class="score">
            {{ fusion_score }}%
        </div>

        <div class="grid">

            {% for row in fusion %}

            <div class="card">

                <h2>{{ row.fusion }}</h2>

                <p>
                    Fusion Score: {{ row.fusion_score }}%
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
    fusion=IRLT_TRUST_FUSION_CORE_V1,
    fusion_score=fusion_score
    )


@app.route("/irlt-commercial-readiness/trust-fusion-core/api")
def irlt_trust_fusion_core_api():

    return jsonify({
        "fusion_score": round(
            sum(x["fusion_score"] for x in IRLT_TRUST_FUSION_CORE_V1)
            / len(IRLT_TRUST_FUSION_CORE_V1)
        ),
        "fusion": IRLT_TRUST_FUSION_CORE_V1
    })

# ============================================================
# END IRLT_TRUST_FUSION_CORE_ENGINE_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("Trust Fusion Core Engine appended successfully.")
