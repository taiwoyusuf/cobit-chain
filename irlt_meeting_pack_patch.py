from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_MEETING_PACK_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Meeting Pack View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_MEETING_PACK_VIEW_V1_ACTIVE
# ============================================================

IRLT_MEETING_PACK_V1 = [
    {
        "item": "Opening Story",
        "detail": "Explain that COBIT-Chain is a governance assurance layer for IRLT commercialization readiness."
    },
    {
        "item": "Problem Statement",
        "detail": "IRLT readiness is fragmented across systems, workflows, evidence owners, and operational teams."
    },
    {
        "item": "Demo Flow",
        "detail": "Start with Executive Launchpad, then Navigation Hub, Demo Storyboard, Buyer Value Map, and Business Case."
    },
    {
        "item": "Leadership Value",
        "detail": "Shows readiness, inspection defense, evidence integrity, survivability, and operational trust in one place."
    },
    {
        "item": "What Is Next",
        "detail": "Power BI, ServiceNow, Veeva, MyAccess, Governance Passport, dependency mapping, and pilot validation."
    },
    {
        "item": "Executive Ask",
        "detail": "Position this as a pilot-ready IRLT governance assurance concept for leadership feedback."
    }
]

@app.route("/irlt-commercial-readiness/meeting-pack")
def irlt_meeting_pack():

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Meeting Pack</title>

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

        <h1>IRLT Meeting Pack</h1>

        <p>
            Executive meeting pack for presenting the IRLT Commercial Readiness Governance Command Center.
            This view gives a simple meeting structure, talking points, and recommended demo sequence.
        </p>

        <div class="grid">

            {% for row in pack %}

            <div class="card">

                <h2>{{ row.item }}</h2>

                <p>{{ row.detail }}</p>

                <div class="pill">Meeting Talking Point</div>

            </div>

            {% endfor %}

        </div>

    </body>

    </html>

    ''', pack=IRLT_MEETING_PACK_V1)


@app.route("/irlt-commercial-readiness/meeting-pack/api")
def irlt_meeting_pack_api():

    return jsonify({
        "meeting_pack": IRLT_MEETING_PACK_V1
    })

# ============================================================
# END IRLT_MEETING_PACK_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Meeting Pack View appended successfully.")
