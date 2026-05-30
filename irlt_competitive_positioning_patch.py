from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_COMPETITIVE_POSITIONING_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Competitive Positioning View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_COMPETITIVE_POSITIONING_VIEW_V1_ACTIVE
# ============================================================

IRLT_COMPETITIVE_POSITIONING_V1 = [
    {
        "category": "Traditional Systems",
        "description": "Veeva, ServiceNow, MES, ERP, LIMS, and quality systems manage records and workflows.",
        "gap": "They do not provide one unified governance trust layer."
    },
    {
        "category": "COBIT-Chain Position",
        "description": "COBIT-Chain operates above existing systems as a governance assurance overlay.",
        "gap": "It connects readiness, evidence, inspection, and survivability intelligence."
    },
    {
        "category": "Differentiation",
        "description": "Evidence integrity, operational trust scoring, governance lineage, and inspection survivability.",
        "gap": "This creates defensibility beyond dashboards and workflow tracking."
    },
    {
        "category": "IRLT Relevance",
        "description": "Designed around radiopharma complexity, cold-chain coordination, dose traceability, and release defensibility.",
        "gap": "Supports commercialization readiness in high-risk regulated environments."
    },
    {
        "category": "Executive Value",
        "description": "Provides one readiness and governance view for leadership decision-making.",
        "gap": "Helps answer whether commercialization readiness can be defended."
    },
    {
        "category": "Commercial Potential",
        "description": "Can expand into SOPTrust, AccessTrust, AuditVault, IntegrityLens, DSCSATrust, and CompoundTrust.",
        "gap": "Creates a modular governance assurance product family."
    }
]

@app.route("/irlt-commercial-readiness/competitive-positioning")
def irlt_competitive_positioning():

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Competitive Positioning</title>

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

        <h1>IRLT Competitive Positioning</h1>

        <p>
            Strategic positioning view explaining why COBIT-Chain is not another system of record,
            but a governance assurance and operational trust layer above existing enterprise systems.
        </p>

        <div class="grid">

            {% for row in positioning %}

            <div class="card">

                <h2>{{ row.category }}</h2>

                <p>{{ row.description }}</p>

                <p><b>Strategic Gap:</b> {{ row.gap }}</p>

                <div class="pill">Positioning Layer</div>

            </div>

            {% endfor %}

        </div>

    </body>

    </html>

    ''', positioning=IRLT_COMPETITIVE_POSITIONING_V1)


@app.route("/irlt-commercial-readiness/competitive-positioning/api")
def irlt_competitive_positioning_api():

    return jsonify({
        "positioning": IRLT_COMPETITIVE_POSITIONING_V1
    })

# ============================================================
# END IRLT_COMPETITIVE_POSITIONING_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Competitive Positioning View appended successfully.")
