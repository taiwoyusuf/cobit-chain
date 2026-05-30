from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_NICOLE_BRIEFING_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Nicole Briefing View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_NICOLE_BRIEFING_VIEW_V1_ACTIVE
# ============================================================

IRLT_NICOLE_BRIEFING_V1 = [
    {
        "section": "What We Built",
        "summary": "A governance assurance command center for IRLT commercialization readiness, inspection defense, evidence integrity, and operational trust.",
        "score": 98
    },
    {
        "section": "Why It Matters",
        "summary": "IRLT operations require governed visibility across release, cold chain, dose traceability, CAPA, evidence, and inspection readiness.",
        "score": 97
    },
    {
        "section": "Strategic Difference",
        "summary": "The platform is not replacing Veeva, ServiceNow, MES, LIMS, or ERP. It acts as the governance trust layer above them.",
        "score": 99
    },
    {
        "section": "Current Demo Value",
        "summary": "Leadership can navigate readiness views, buyer value, business case, pilot readiness, and executive demo storyline.",
        "score": 96
    },
    {
        "section": "Next Build Direction",
        "summary": "Next steps include live integrations, Power BI dashboards, Governance Passport, dependency mapping, and inspection simulation.",
        "score": 94
    },
    {
        "section": "Executive Ask",
        "summary": "Use this as a pilot conversation starter for IRLT governance assurance, operational readiness visibility, and commercialization trust.",
        "score": 98
    }
]

@app.route("/irlt-commercial-readiness/nicole-briefing")
def irlt_nicole_briefing():

    briefing_score = round(
        sum(x["score"] for x in IRLT_NICOLE_BRIEFING_V1)
        / len(IRLT_NICOLE_BRIEFING_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Nicole Briefing View</title>

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

        <h1>Nicole Briefing View</h1>

        <p>
            Executive briefing page for presenting the IRLT Commercial Readiness Governance Command Center
            to Nicole. This view summarizes what has been built, why it matters, how it is different,
            and what the next phase should focus on.
        </p>

        <div class="score">{{ briefing_score }}%</div>

        <p>Briefing Readiness Score</p>

        <div class="grid">

            {% for row in briefing %}

            <div class="card">

                <h2>{{ row.section }}</h2>

                <p>{{ row.summary }}</p>

                <div class="pill">Readiness {{ row.score }}%</div>

            </div>

            {% endfor %}

        </div>

    </body>

    </html>

    ''',
    briefing=IRLT_NICOLE_BRIEFING_V1,
    briefing_score=briefing_score
    )


@app.route("/irlt-commercial-readiness/nicole-briefing/api")
def irlt_nicole_briefing_api():

    return jsonify({
        "briefing_score": round(
            sum(x["score"] for x in IRLT_NICOLE_BRIEFING_V1)
            / len(IRLT_NICOLE_BRIEFING_V1)
        ),
        "briefing": IRLT_NICOLE_BRIEFING_V1
    })

# ============================================================
# END IRLT_NICOLE_BRIEFING_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Nicole Briefing View appended successfully.")
