from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_BUSINESS_CASE_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Business Case View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_BUSINESS_CASE_VIEW_V1_ACTIVE
# ============================================================

IRLT_BUSINESS_CASE_V1 = [
    {
        "case": "Commercial Readiness Defense",
        "value": "Provides leadership with a governed readiness picture before commercial launch.",
        "impact": 98
    },
    {
        "case": "Inspection Survivability",
        "value": "Improves ability to defend evidence, workflows, and readiness during inspection.",
        "impact": 97
    },
    {
        "case": "Operational Risk Visibility",
        "value": "Connects risk signals across release, cold chain, CAPA, training, and evidence domains.",
        "impact": 96
    },
    {
        "case": "Evidence Integrity",
        "value": "Creates a governance layer for evidence completeness, traceability, and defensibility.",
        "impact": 99
    },
    {
        "case": "Executive Decision Support",
        "value": "Gives sponsors a clear operational trust view instead of fragmented system reports.",
        "impact": 98
    },
    {
        "case": "Scalable Platform Potential",
        "value": "Can extend into SOP, access, audit, DSCSA, clinical trial, and compounding governance.",
        "impact": 97
    }
]

@app.route("/irlt-commercial-readiness/business-case")
def irlt_business_case():

    business_score = round(
        sum(x["impact"] for x in IRLT_BUSINESS_CASE_V1)
        / len(IRLT_BUSINESS_CASE_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Business Case</title>

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
                font-size:76px;
                margin-bottom:10px;
            }

            p{
                color:#bfc7d4;
                line-height:1.7;
                max-width:1150px;
            }

            .score{
                font-size:120px;
                color:#ff9f1c;
                margin:30px 0;
            }

            .grid{
                display:grid;
                grid-template-columns:repeat(2,1fr);
                gap:20px;
                margin-top:30px;
            }

            .card{
                background:#161d28;
                border-radius:22px;
                padding:26px;
                border:1px solid rgba(255,255,255,0.08);
            }

            h2{
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

        <h1>IRLT Business Case</h1>

        <p>
            Executive business-case view showing why the IRLT Commercial Readiness
            Governance Command Center creates operational, regulatory, and commercial value.
        </p>

        <div class="score">{{ business_score }}%</div>

        <p>Business Value Confidence</p>

        <div class="grid">

            {% for row in cases %}

            <div class="card">

                <h2>{{ row.case }}</h2>

                <p>{{ row.value }}</p>

                <div class="pill">Impact {{ row.impact }}%</div>

            </div>

            {% endfor %}

        </div>

    </body>

    </html>

    ''',
    cases=IRLT_BUSINESS_CASE_V1,
    business_score=business_score
    )


@app.route("/irlt-commercial-readiness/business-case/api")
def irlt_business_case_api():

    return jsonify({
        "business_score": round(
            sum(x["impact"] for x in IRLT_BUSINESS_CASE_V1)
            / len(IRLT_BUSINESS_CASE_V1)
        ),
        "cases": IRLT_BUSINESS_CASE_V1
    })

# ============================================================
# END IRLT_BUSINESS_CASE_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Business Case View appended successfully.")
