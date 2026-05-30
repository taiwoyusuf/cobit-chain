from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_BLAST_RADIUS_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Blast Radius View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_BLAST_RADIUS_VIEW_V1_ACTIVE
# ============================================================

IRLT_BLAST_RADIUS_V1 = [
    {
        "trigger": "Cold Chain Excursion",
        "affected": "Dose release, shipment timing, patient administration, QA review",
        "radius": "Enterprise Critical"
    },
    {
        "trigger": "CAPA Delay",
        "affected": "Inspection readiness, release defensibility, quality governance",
        "radius": "High"
    },
    {
        "trigger": "Training Gap",
        "affected": "Operator readiness, batch execution, audit defense",
        "radius": "High"
    },
    {
        "trigger": "Evidence Missing",
        "affected": "Inspection response, audit survivability, governance confidence",
        "radius": "Critical"
    },
    {
        "trigger": "Access Drift",
        "affected": "Privileged activity, system accountability, compliance posture",
        "radius": "Medium"
    },
    {
        "trigger": "Release Governance Failure",
        "affected": "Commercial shipment, QA approval, patient treatment continuity",
        "radius": "Enterprise Critical"
    }
]

@app.route("/irlt-commercial-readiness/blast-radius")
def irlt_blast_radius():

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Blast Radius Intelligence</title>

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

        <h1>IRLT Blast Radius Intelligence</h1>

        <p>
            Operational blast-radius view showing how one governance failure can propagate
            across release, cold chain, dose traceability, inspection readiness, QA governance,
            and commercial continuity.
        </p>

        <div class="grid">

            {% for row in blast %}

            <div class="card">

                <h2>{{ row.trigger }}</h2>

                <p><b>Affected Areas:</b> {{ row.affected }}</p>

                <div class="pill">Blast Radius: {{ row.radius }}</div>

            </div>

            {% endfor %}

        </div>

    </body>

    </html>

    ''', blast=IRLT_BLAST_RADIUS_V1)


@app.route("/irlt-commercial-readiness/blast-radius/api")
def irlt_blast_radius_api():

    return jsonify({
        "blast_radius": IRLT_BLAST_RADIUS_V1
    })

# ============================================================
# END IRLT_BLAST_RADIUS_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Blast Radius View appended successfully.")
