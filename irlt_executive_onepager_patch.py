from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_EXECUTIVE_ONEPAGER_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Executive One-Pager View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_EXECUTIVE_ONEPAGER_VIEW_V1_ACTIVE
# ============================================================

IRLT_EXECUTIVE_ONEPAGER_V1 = [
    {
        "title": "Problem",
        "summary": "IRLT commercialization readiness is spread across systems, evidence sources, operational workflows, and governance owners."
    },
    {
        "title": "Gap",
        "summary": "Existing systems manage records and transactions, but leadership lacks one governed operational trust view."
    },
    {
        "title": "Solution",
        "summary": "COBIT-Chain provides a governance assurance layer above existing systems for readiness, evidence, inspection, and survivability."
    },
    {
        "title": "Value",
        "summary": "The platform helps leadership defend commercialization readiness with governed evidence and operational trust intelligence."
    },
    {
        "title": "Current Build",
        "summary": "The IRLT command center now includes launchpad, navigation hub, demo storyboard, buyer value map, business case, and Nicole briefing views."
    },
    {
        "title": "Next Step",
        "summary": "Move from demo foundation into live integrations, Power BI dashboards, Governance Passport, dependency mapping, and pilot validation."
    }
]

@app.route("/irlt-commercial-readiness/executive-onepager")
def irlt_executive_onepager():

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Executive One-Pager</title>

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

            .grid{
                display:grid;
                grid-template-columns:repeat(2,1fr);
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

            .footer{
                margin-top:36px;
                padding:24px;
                border-radius:22px;
                background:rgba(255,122,24,0.10);
                border:1px solid rgba(255,122,24,0.25);
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

        <h1>IRLT Executive One-Pager</h1>

        <p>
            One-page executive summary for presenting the COBIT-Chain IRLT Commercial Readiness
            Governance Command Center as a governance assurance and operational trust platform.
        </p>

        <div class="grid">

            {% for row in onepager %}

            <div class="card">

                <h2>{{ row.title }}</h2>

                <p>{{ row.summary }}</p>

                <div class="pill">Executive Summary Layer</div>

            </div>

            {% endfor %}

        </div>

        <div class="footer">

            <h2>Final Message</h2>

            <p>
                COBIT-Chain does not replace Veeva, ServiceNow, MES, LIMS, ERP, or quality systems.
                It becomes the governance assurance layer above them, helping IRLT leadership defend
                commercialization readiness through governed evidence, operational trust intelligence,
                and inspection survivability.
            </p>

        </div>

    </body>

    </html>

    ''', onepager=IRLT_EXECUTIVE_ONEPAGER_V1)


@app.route("/irlt-commercial-readiness/executive-onepager/api")
def irlt_executive_onepager_api():

    return jsonify({
        "onepager": IRLT_EXECUTIVE_ONEPAGER_V1
    })

# ============================================================
# END IRLT_EXECUTIVE_ONEPAGER_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Executive One-Pager View appended successfully.")
