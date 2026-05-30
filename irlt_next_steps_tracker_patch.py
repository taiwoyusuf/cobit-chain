from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_NEXT_STEPS_TRACKER_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Next Steps Tracker View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_NEXT_STEPS_TRACKER_VIEW_V1_ACTIVE
# ============================================================

IRLT_NEXT_STEPS_TRACKER_V1 = [
    {
        "step": "Cloud Deployment Validation",
        "owner": "Platform / Technical",
        "status": "Next"
    },
    {
        "step": "Executive Demo Walkthrough",
        "owner": "Yusuf / IRLT Stakeholders",
        "status": "Ready"
    },
    {
        "step": "Power BI Readiness Dashboard",
        "owner": "Analytics",
        "status": "Planned"
    },
    {
        "step": "ServiceNow Integration Mapping",
        "owner": "ITSM / Governance",
        "status": "Planned"
    },
    {
        "step": "Veeva / Quality Evidence Mapping",
        "owner": "QA / Compliance",
        "status": "Planned"
    },
    {
        "step": "Governance Passport Prototype",
        "owner": "COBIT-Chain",
        "status": "Planned"
    }
]

@app.route("/irlt-commercial-readiness/next-steps")
def irlt_next_steps_tracker():

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Next Steps Tracker</title>

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

        <h1>IRLT Next Steps Tracker</h1>

        <p>
            Roadmap tracker for moving the IRLT Commercial Readiness Governance Command Center
            from demo foundation into validated cloud deployment, executive walkthrough,
            analytics integration, system mapping, and pilot readiness.
        </p>

        <div class="grid">

            {% for row in steps %}

            <div class="card">

                <h2>{{ row.step }}</h2>

                <p><b>Owner:</b> {{ row.owner }}</p>

                <div class="pill">{{ row.status }}</div>

            </div>

            {% endfor %}

        </div>

    </body>

    </html>

    ''', steps=IRLT_NEXT_STEPS_TRACKER_V1)


@app.route("/irlt-commercial-readiness/next-steps/api")
def irlt_next_steps_tracker_api():

    return jsonify({
        "next_steps": IRLT_NEXT_STEPS_TRACKER_V1
    })

# ============================================================
# END IRLT_NEXT_STEPS_TRACKER_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Next Steps Tracker View appended successfully.")
