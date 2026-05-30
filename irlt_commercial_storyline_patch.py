from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_COMMERCIAL_STORYLINE_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Commercial Storyline View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_COMMERCIAL_STORYLINE_VIEW_V1_ACTIVE
# ============================================================

IRLT_COMMERCIAL_STORYLINE_V1 = [
    {
        "chapter": "1. IRLT Commercialization Pressure",
        "story": "Radiopharma commercialization creates operational pressure across manufacturing, release, cold-chain, treatment timing, evidence, and inspection readiness."
    },
    {
        "chapter": "2. Fragmented Enterprise Systems",
        "story": "Existing systems manage records and workflows, but leadership still lacks one governed view of operational trust and readiness."
    },
    {
        "chapter": "3. Governance Assurance Gap",
        "story": "The gap is not data capture. The gap is whether readiness can be defended with governed, traceable, inspection-ready evidence."
    },
    {
        "chapter": "4. COBIT-Chain Overlay",
        "story": "COBIT-Chain sits above existing systems as a governance assurance and operational trust layer."
    },
    {
        "chapter": "5. Executive Readiness Intelligence",
        "story": "The platform gives leadership a clear view of readiness, risk, survivability, evidence integrity, and commercialization defensibility."
    },
    {
        "chapter": "6. Future Enterprise Expansion",
        "story": "The IRLT command center becomes the foundation for broader governance products such as SOPTrust, AccessTrust, AuditVault, and IntegrityLens."
    }
]

@app.route("/irlt-commercial-readiness/commercial-storyline")
def irlt_commercial_storyline():

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Commercial Storyline</title>

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

            .story{
                margin-top:30px;
                display:grid;
                grid-template-columns:1fr;
                gap:18px;
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

        <h1>IRLT Commercial Storyline</h1>

        <p>
            Executive narrative view explaining why the IRLT Commercial Readiness Governance Command Center matters,
            what problem it solves, and how it becomes a governance assurance layer for commercial radiopharma scale-up.
        </p>

        <div class="story">

            {% for row in storyline %}

            <div class="card">

                <h2>{{ row.chapter }}</h2>

                <p>{{ row.story }}</p>

                <div class="pill">Executive Story Layer</div>

            </div>

            {% endfor %}

        </div>

    </body>

    </html>

    ''', storyline=IRLT_COMMERCIAL_STORYLINE_V1)


@app.route("/irlt-commercial-readiness/commercial-storyline/api")
def irlt_commercial_storyline_api():

    return jsonify({
        "storyline": IRLT_COMMERCIAL_STORYLINE_V1
    })

# ============================================================
# END IRLT_COMMERCIAL_STORYLINE_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Commercial Storyline View appended successfully.")
