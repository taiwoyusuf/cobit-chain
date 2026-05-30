from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_INVESTOR_DEMO_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Investor Demo View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_INVESTOR_DEMO_VIEW_V1_ACTIVE
# ============================================================

IRLT_INVESTOR_DEMO_V1 = [
    {
        "signal": "Market Relevance",
        "score": 98,
        "message": "IRLT commercialization creates a strong need for operational governance assurance."
    },
    {
        "signal": "Enterprise Differentiation",
        "score": 97,
        "message": "COBIT-Chain is positioned as a governance assurance layer, not a replacement system."
    },
    {
        "signal": "Inspection Defensibility",
        "score": 96,
        "message": "The platform supports evidence-backed inspection readiness and survivability."
    },
    {
        "signal": "Scalability",
        "score": 95,
        "message": "The modular architecture can expand across IRLT, SOP, access, audit, and manufacturing governance."
    },
    {
        "signal": "Commercial Story",
        "score": 98,
        "message": "Leadership can see readiness, risk, evidence, and trust in one operational command environment."
    },
    {
        "signal": "Platform Potential",
        "score": 97,
        "message": "The architecture supports future SaaS-style governance intelligence expansion."
    }
]

@app.route("/irlt-commercial-readiness/investor-demo")
def irlt_investor_demo():

    investor_score = round(
        sum(x["score"] for x in IRLT_INVESTOR_DEMO_V1)
        / len(IRLT_INVESTOR_DEMO_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Investor Demo View</title>

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
                padding:24px;
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

        <h1>IRLT Investor Demo View</h1>

        <p>
            Investor and executive-facing strategic view showing why the IRLT Commercial Readiness
            Governance Command Center has enterprise value, market relevance, differentiation,
            and scalable governance assurance potential.
        </p>

        <div class="score">{{ investor_score }}%</div>

        <p>Strategic Demo Confidence</p>

        <div class="grid">

            {% for row in demo %}

            <div class="card">

                <h2>{{ row.signal }}</h2>

                <p>{{ row.message }}</p>

                <div class="pill">Score {{ row.score }}%</div>

            </div>

            {% endfor %}

        </div>

    </body>

    </html>

    ''',
    demo=IRLT_INVESTOR_DEMO_V1,
    investor_score=investor_score
    )


@app.route("/irlt-commercial-readiness/investor-demo/api")
def irlt_investor_demo_api():

    return jsonify({
        "investor_score": round(
            sum(x["score"] for x in IRLT_INVESTOR_DEMO_V1)
            / len(IRLT_INVESTOR_DEMO_V1)
        ),
        "demo": IRLT_INVESTOR_DEMO_V1
    })

# ============================================================
# END IRLT_INVESTOR_DEMO_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Investor Demo View appended successfully.")
