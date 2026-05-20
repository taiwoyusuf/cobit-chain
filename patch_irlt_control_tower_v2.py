from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_OPERATIONAL_TRUST_CONTROL_TOWER_V2_ACTIVE"

if MARKER in text:
    print("IRLT Control Tower already exists.")
    raise SystemExit()

# collision protection
if 'def irlt_operational_trust_control_tower_v2(' in text:
    print("Function already exists.")
    raise SystemExit()

if '/irlt-commercial-readiness/control-tower' in text:
    print("Route already exists.")
    raise SystemExit()

INSERT = r"""

# ============================================================
# IRLT_OPERATIONAL_TRUST_CONTROL_TOWER_V2_ACTIVE
# ============================================================

from flask import jsonify

IRLT_CONTROL_TOWER_KPIS_V2 = [
    {
        "domain": "Release Defensibility",
        "score": 92,
        "status": "Strong"
    },
    {
        "domain": "Dose Lineage",
        "score": 95,
        "status": "Verified"
    },
    {
        "domain": "Environmental Monitoring",
        "score": 88,
        "status": "Review"
    },
    {
        "domain": "CAPA Governance",
        "score": 84,
        "status": "Attention"
    },
    {
        "domain": "Inspection Survivability",
        "score": 93,
        "status": "Ready"
    },
    {
        "domain": "Operational Trust",
        "score": 91,
        "status": "Strong"
    }
]


@app.route("/irlt-commercial-readiness/control-tower")
@app.route("/rlttrust/control-tower")
def irlt_operational_trust_control_tower_v2():

    overall_score = round(
        sum(x["score"] for x in IRLT_CONTROL_TOWER_KPIS_V2)
        / len(IRLT_CONTROL_TOWER_KPIS_V2)
    )

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>IRLT Operational Trust Control Tower</title>

        <style>

            body {
                margin:0;
                background:
                    radial-gradient(circle at top left, rgba(255,122,24,0.18), transparent 34%),
                    linear-gradient(135deg,#050608 0%,#11151f 48%,#06070b 100%);
                color:white;
                font-family:Arial,sans-serif;
            }

            .wrap {
                max-width:1900px;
                margin:auto;
                padding:34px;
            }

            .hero,.panel {
                border-radius:28px;
                padding:28px;
                margin-bottom:24px;
                border:1px solid rgba(255,255,255,0.08);
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02)),
                    rgba(20,24,33,0.88);
            }

            h1 {
                margin:0 0 12px;
                font-size:72px;
                color:#ff9f1c;
            }

            h2 {
                color:#ff9f1c;
            }

            p {
                color:#b4bcc9;
                line-height:1.7;
            }

            .grid {
                display:grid;
                grid-template-columns:repeat(3,1fr);
                gap:18px;
                margin-top:24px;
            }

            .kpi {
                padding:22px;
                border-radius:18px;
                background:rgba(255,255,255,0.04);
                border:1px solid rgba(255,255,255,0.08);
            }

            .kpi strong {
                display:block;
                font-size:48px;
                color:#ff9f1c;
            }

            .overall {
                margin-top:24px;
                text-align:center;
                padding:24px;
                border-radius:20px;
                background:rgba(255,255,255,0.04);
            }

            .overall strong {
                display:block;
                font-size:110px;
                color:#ff9f1c;
            }

            table {
                width:100%;
                border-collapse:collapse;
            }

            th,td {
                padding:14px;
                border-bottom:1px solid rgba(255,255,255,0.08);
                text-align:left;
            }

            th {
                color:#ff9f1c;
                font-size:12px;
                text-transform:uppercase;
            }

            .pill {
                display:inline-block;
                padding:7px 12px;
                border-radius:999px;
                background:rgba(255,122,24,0.12);
                border:1px solid rgba(255,122,24,0.25);
                color:#ffd7ad;
                font-size:12px;
                font-weight:800;
            }

            @media (max-width:1200px) {

                .grid {
                    grid-template-columns:1fr;
                }

                h1 {
                    font-size:42px;
                }

            }

        </style>

    </head>

    <body>

        <div class="wrap">

            <section class="hero">

                <h1>IRLT Operational Trust Control Tower</h1>

                <p>
                    Executive operational governance cockpit for commercialization readiness,
                    inspection survivability, release defensibility, and radiopharma trust assurance.
                </p>

                <div class="overall">

                    <strong>{{ overall_score }}%</strong>

                    Enterprise Operational Trust Score

                </div>

                <div class="grid">

                    {% for row in kpis %}

                    <div class="kpi">

                        <strong>{{ row.score }}%</strong>

                        {{ row.domain }}

                        <br><br>

                        <span class="pill">

                            {{ row.status }}

                        </span>

                    </div>

                    {% endfor %}

                </div>

            </section>

            <section class="panel">

                <h2>Dependency Propagation Intelligence</h2>

                <table>

                    <thead>

                        <tr>
                            <th>Dependency</th>
                            <th>Risk</th>
                            <th>Impact</th>
                            <th>Status</th>
                        </tr>

                    </thead>

                    <tbody>

                        <tr>
                            <td>CAPA Closure Delay</td>
                            <td>Moderate</td>
                            <td>Inspection Readiness</td>
                            <td><span class="pill">Monitoring</span></td>
                        </tr>

                        <tr>
                            <td>Environmental Review Lag</td>
                            <td>Medium</td>
                            <td>Release Governance</td>
                            <td><span class="pill">Escalated</span></td>
                        </tr>

                        <tr>
                            <td>Training Recertification</td>
                            <td>Low</td>
                            <td>Operational Readiness</td>
                            <td><span class="pill">Controlled</span></td>
                        </tr>

                        <tr>
                            <td>Shipment Coordination</td>
                            <td>Low</td>
                            <td>Treatment Coordination</td>
                            <td><span class="pill">Stable</span></td>
                        </tr>

                    </tbody>

                </table>

            </section>

        </div>

    </body>

    </html>

    '''

    return render_template_string(
        html,
        kpis=IRLT_CONTROL_TOWER_KPIS_V2,
        overall_score=overall_score
    )


@app.route("/irlt-commercial-readiness/control-tower/api")
@app.route("/rlttrust/control-tower/api")
def irlt_control_tower_api_v2():

    return jsonify({
        "overall_score": round(
            sum(x["score"] for x in IRLT_CONTROL_TOWER_KPIS_V2)
            / len(IRLT_CONTROL_TOWER_KPIS_V2)
        ),
        "domains": IRLT_CONTROL_TOWER_KPIS_V2
    })

# ============================================================
# END IRLT_OPERATIONAL_TRUST_CONTROL_TOWER_V2
# ============================================================

"""

needle = '\nif __name__ == "__main__":'

if needle not in text:
    needle = "\nif __name__ == '__main__':"

if needle not in text:
    raise RuntimeError("Could not find Flask entry point.")

text = text.replace(
    needle,
    "\n" + INSERT + "\n" + needle,
    1
)

APP.write_text(text, encoding="utf-8")

print("Inserted IRLT Control Tower successfully.")
