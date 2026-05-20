from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_AUTONOMOUS_INSPECTION_DEFENSE_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Inspection Defense Engine already exists.")
    raise SystemExit()

anchor = "# END IRLT_GOVERNANCE_RESILIENCE_FORECAST_ENGINE_V1"

if anchor not in text:
    print("Could not locate safe insertion anchor.")
    raise SystemExit()

block = r"""

# ============================================================
# IRLT_AUTONOMOUS_INSPECTION_DEFENSE_ENGINE_V1_ACTIVE
# ============================================================

IRLT_INSPECTION_DEFENSE_V1 = [
    {
        "domain": "QA Release Evidence",
        "score": 96,
        "state": "Strong",
        "risk": "Low"
    },
    {
        "domain": "Dose Lineage Integrity",
        "score": 95,
        "state": "Verified",
        "risk": "Low"
    },
    {
        "domain": "Environmental Monitoring",
        "score": 84,
        "state": "Review",
        "risk": "Moderate"
    },
    {
        "domain": "CAPA Closure Velocity",
        "score": 79,
        "state": "Pressure",
        "risk": "Elevated"
    },
    {
        "domain": "Access Governance",
        "score": 90,
        "state": "Controlled",
        "risk": "Low"
    },
    {
        "domain": "Backup Governance",
        "score": 82,
        "state": "Observed",
        "risk": "Moderate"
    }
]


@app.route("/irlt-commercial-readiness/inspection-defense")
def irlt_inspection_defense():

    overall_score = round(
        sum(x["score"] for x in IRLT_INSPECTION_DEFENSE_V1)
        / len(IRLT_INSPECTION_DEFENSE_V1)
    )

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Inspection Defense Engine</title>

        <style>

            body{
                margin:0;
                background:
                    radial-gradient(circle at top left, rgba(255,122,24,0.20), transparent 34%),
                    linear-gradient(135deg,#050608 0%,#11151f 48%,#06070b 100%);
                color:white;
                font-family:Arial;
            }

            .wrap{
                max-width:1900px;
                margin:auto;
                padding:34px;
            }

            .hero,.panel{
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02)),
                    rgba(20,24,33,0.88);
                border-radius:28px;
                padding:28px;
                margin-bottom:24px;
                border:1px solid rgba(255,255,255,0.08);
            }

            h1{
                color:#ff9f1c;
                font-size:74px;
                margin:0 0 12px;
                letter-spacing:-0.05em;
            }

            h2{
                color:#ff9f1c;
            }

            p{
                color:#c0c7d2;
                line-height:1.7;
            }

            .hero-grid{
                display:grid;
                grid-template-columns:1.2fr .8fr;
                gap:24px;
            }

            .overall{
                height:320px;
                border-radius:24px;
                display:flex;
                flex-direction:column;
                justify-content:center;
                align-items:center;
                background:
                    radial-gradient(circle, rgba(255,159,28,0.20), transparent 70%),
                    rgba(255,255,255,0.03);
                border:1px solid rgba(255,159,28,0.18);
            }

            .overall strong{
                font-size:110px;
                color:#ff9f1c;
            }

            .grid{
                display:grid;
                grid-template-columns:repeat(3,1fr);
                gap:18px;
                margin-top:22px;
            }

            .card{
                background:rgba(255,255,255,0.04);
                border-radius:18px;
                padding:20px;
                border:1px solid rgba(255,255,255,0.08);
            }

            .card strong{
                display:block;
                color:#ff9f1c;
                font-size:42px;
            }

            .pill{
                display:inline-block;
                margin-top:12px;
                padding:7px 12px;
                border-radius:999px;
                background:rgba(255,122,24,0.12);
                border:1px solid rgba(255,122,24,0.25);
                color:#ffd7ad;
                font-size:12px;
                font-weight:bold;
            }

            .ops-grid{
                display:grid;
                grid-template-columns:1fr 1fr;
                gap:22px;
            }

            table{
                width:100%;
                border-collapse:collapse;
            }

            th,td{
                padding:14px;
                border-bottom:1px solid rgba(255,255,255,0.08);
                text-align:left;
            }

            th{
                color:#ff9f1c;
                font-size:12px;
                text-transform:uppercase;
            }

            ul li{
                margin-bottom:12px;
                color:#c6cfdb;
            }

            @media (max-width:1200px){

                .hero-grid,
                .ops-grid,
                .grid{
                    grid-template-columns:1fr;
                }

                h1{
                    font-size:44px;
                }

            }

        </style>

    </head>

    <body>

        <div class="wrap">

            <section class="hero">

                <h1>Inspection Defense Engine</h1>

                <p>
                    Enterprise operational inspection survivability intelligence
                    layer for radiopharma commercialization readiness,
                    audit defensibility, governance resilience,
                    evidence survivability, and operational trust protection.
                </p>

                <div class="hero-grid">

                    <div class="panel">

                        <h2>Inspection Defense Domains</h2>

                        <div class="grid">

                            {% for row in defense %}

                            <div class="card">

                                <strong>{{ row.score }}%</strong>

                                {{ row.domain }}

                                <br>

                                <span class="pill">
                                    {{ row.state }}
                                </span>

                            </div>

                            {% endfor %}

                        </div>

                    </div>

                    <div class="overall">

                        <strong>{{ overall_score }}%</strong>

                        Inspection Survivability

                    </div>

                </div>

            </section>

            <div class="ops-grid">

                <section class="panel">

                    <h2>Inspection Survivability Intelligence</h2>

                    <ul>

                        <li>
                            QA release evidence remains operationally defensible under simulated inspection pressure.
                        </li>

                        <li>
                            Dose lineage integrity remains highly survivable across commercialization workflows.
                        </li>

                        <li>
                            Environmental monitoring governance remains the highest observation-sensitive domain.
                        </li>

                        <li>
                            CAPA closure velocity remains the primary projected inspection escalation vector.
                        </li>

                        <li>
                            Governance integrity remains stable across operational trust pathways.
                        </li>

                        <li>
                            Audit defensibility posture remains commercially sustainable.
                        </li>

                    </ul>

                </section>

                <section class="panel">

                    <h2>Inspection Defense Matrix</h2>

                    <table>

                        <thead>

                            <tr>
                                <th>Governance Domain</th>
                                <th>Score</th>
                                <th>Risk</th>
                                <th>State</th>
                            </tr>

                        </thead>

                        <tbody>

                            {% for row in defense %}

                            <tr>

                                <td>{{ row.domain }}</td>

                                <td>{{ row.score }}%</td>

                                <td>{{ row.risk }}</td>

                                <td>{{ row.state }}</td>

                            </tr>

                            {% endfor %}

                        </tbody>

                    </table>

                </section>

            </div>

        </div>

    </body>

    </html>

    '''

    return render_template_string(
        html,
        defense=IRLT_INSPECTION_DEFENSE_V1,
        overall_score=overall_score
    )


@app.route("/irlt-commercial-readiness/inspection-defense/api")
def irlt_inspection_defense_api():

    return jsonify({
        "overall_score": round(
            sum(x["score"] for x in IRLT_INSPECTION_DEFENSE_V1)
            / len(IRLT_INSPECTION_DEFENSE_V1)
        ),
        "domains": IRLT_INSPECTION_DEFENSE_V1
    })

# ============================================================
# END IRLT_AUTONOMOUS_INSPECTION_DEFENSE_ENGINE_V1
# ============================================================

"""

text = text.replace(anchor, anchor + block)

APP.write_text(text, encoding="utf-8")

print("Inspection Defense Engine inserted successfully.")
