from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_GOVERNANCE_PASSPORT_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Governance Passport View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_GOVERNANCE_PASSPORT_VIEW_V1_ACTIVE
# ============================================================

IRLT_GOVERNANCE_PASSPORT_V1 = [
    {
        "passport": "Commercial Readiness Passport",
        "certification": "Ready",
        "score": 97
    },
    {
        "passport": "Inspection Defense Passport",
        "certification": "Defensible",
        "score": 96
    },
    {
        "passport": "Evidence Integrity Passport",
        "certification": "Verified",
        "score": 99
    },
    {
        "passport": "Cold Chain Governance Passport",
        "certification": "Stable",
        "score": 93
    },
    {
        "passport": "CAPA Recovery Passport",
        "certification": "Observed",
        "score": 88
    },
    {
        "passport": "Dose Traceability Passport",
        "certification": "Certified",
        "score": 99
    }
]

@app.route("/irlt-commercial-readiness/governance-passport-view")
def irlt_governance_passport_view():

    passport_score = round(
        sum(x["score"] for x in IRLT_GOVERNANCE_PASSPORT_V1)
        / len(IRLT_GOVERNANCE_PASSPORT_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Governance Passport View</title>

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
                grid-template-columns:repeat(3,1fr);
                gap:20px;
                margin-top:30px;
            }

            .card{
                background:#161d28;
                border-radius:22px;
                padding:28px;
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

        <h1>IRLT Governance Passport View</h1>

        <p>
            Portable governance readiness certification view for IRLT commercialization.
            This page shows how operational domains can be certified through readiness,
            defensibility, evidence integrity, and trust scoring.
        </p>

        <div class="score">{{ passport_score }}%</div>

        <p>Overall Governance Passport Readiness</p>

        <div class="grid">

            {% for row in passports %}

            <div class="card">

                <h2>{{ row.passport }}</h2>

                <p>Score: {{ row.score }}%</p>

                <div class="pill">{{ row.certification }}</div>

            </div>

            {% endfor %}

        </div>

    </body>

    </html>

    ''',
    passports=IRLT_GOVERNANCE_PASSPORT_V1,
    passport_score=passport_score
    )


@app.route("/irlt-commercial-readiness/governance-passport-view/api")
def irlt_governance_passport_view_api():

    return jsonify({
        "passport_score": round(
            sum(x["score"] for x in IRLT_GOVERNANCE_PASSPORT_V1)
            / len(IRLT_GOVERNANCE_PASSPORT_V1)
        ),
        "passports": IRLT_GOVERNANCE_PASSPORT_V1
    })

# ============================================================
# END IRLT_GOVERNANCE_PASSPORT_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Governance Passport View appended successfully.")
