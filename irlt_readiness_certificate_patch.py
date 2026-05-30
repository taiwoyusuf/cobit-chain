from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_READINESS_CERTIFICATE_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Readiness Certificate View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_READINESS_CERTIFICATE_VIEW_V1_ACTIVE
# ============================================================

IRLT_READINESS_CERTIFICATE_V1 = [
    {
        "certificate": "Commercialization Readiness",
        "status": "Certified Ready",
        "score": 97
    },
    {
        "certificate": "Inspection Survivability",
        "status": "Inspection Defensible",
        "score": 96
    },
    {
        "certificate": "Evidence Integrity",
        "status": "Evidence Verified",
        "score": 99
    },
    {
        "certificate": "Cold Chain Governance",
        "status": "Operationally Stable",
        "score": 93
    },
    {
        "certificate": "CAPA Governance",
        "status": "Monitored",
        "score": 88
    },
    {
        "certificate": "Dose Traceability",
        "status": "Traceability Certified",
        "score": 99
    }
]

@app.route("/irlt-commercial-readiness/readiness-certificate")
def irlt_readiness_certificate():

    certificate_score = round(
        sum(x["score"] for x in IRLT_READINESS_CERTIFICATE_V1)
        / len(IRLT_READINESS_CERTIFICATE_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Readiness Certificate</title>

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

        <h1>IRLT Readiness Certificate</h1>

        <p>
            Executive certification-style view showing whether the major IRLT commercialization
            governance domains are ready, defensible, verified, stable, or still under monitoring.
        </p>

        <div class="score">{{ certificate_score }}%</div>

        <p>Overall Readiness Certification Score</p>

        <div class="grid">

            {% for row in certificates %}

            <div class="card">

                <h2>{{ row.certificate }}</h2>

                <p>Score: {{ row.score }}%</p>

                <div class="pill">{{ row.status }}</div>

            </div>

            {% endfor %}

        </div>

    </body>

    </html>

    ''',
    certificates=IRLT_READINESS_CERTIFICATE_V1,
    certificate_score=certificate_score
    )


@app.route("/irlt-commercial-readiness/readiness-certificate/api")
def irlt_readiness_certificate_api():

    return jsonify({
        "certificate_score": round(
            sum(x["score"] for x in IRLT_READINESS_CERTIFICATE_V1)
            / len(IRLT_READINESS_CERTIFICATE_V1)
        ),
        "certificates": IRLT_READINESS_CERTIFICATE_V1
    })

# ============================================================
# END IRLT_READINESS_CERTIFICATE_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Readiness Certificate View appended successfully.")
