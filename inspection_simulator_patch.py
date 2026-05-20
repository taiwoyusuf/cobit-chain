from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_INSPECTION_SIMULATION_CHAMBER_V1_ACTIVE"

if MARKER in text:
    print("Inspection Simulation Chamber already exists.")
    raise SystemExit()

anchor = "# END IRLT_OPERATIONAL_WARROOM_COMMAND_CENTER_V1"

if anchor not in text:
    print("Could not locate safe insertion anchor.")
    raise SystemExit()

block = r"""

# ============================================================
# IRLT_INSPECTION_SIMULATION_CHAMBER_V1_ACTIVE
# ============================================================

IRLT_INSPECTION_SCENARIOS_V1 = [
    {
        "scenario": "FDA Commercialization Inspection",
        "exposure": "Moderate",
        "survivability": 93,
        "state": "Defensible"
    },
    {
        "scenario": "Environmental Monitoring Escalation",
        "exposure": "Elevated",
        "survivability": 81,
        "state": "Observed"
    },
    {
        "scenario": "CAPA Closure Backlog",
        "exposure": "Critical",
        "survivability": 76,
        "state": "Pressure"
    },
    {
        "scenario": "Cold Chain Deviation",
        "exposure": "High",
        "survivability": 84,
        "state": "Controlled"
    },
    {
        "scenario": "Dose Traceability Review",
        "exposure": "Low",
        "survivability": 97,
        "state": "Verified"
    },
    {
        "scenario": "Multi-Site Governance Audit",
        "exposure": "Moderate",
        "survivability": 88,
        "state": "Stable"
    }
]


@app.route("/irlt-commercial-readiness/inspection-simulator")
def irlt_inspection_simulator():

    survivability_score = round(
        sum(x["survivability"] for x in IRLT_INSPECTION_SCENARIOS_V1)
        / len(IRLT_INSPECTION_SCENARIOS_V1)
    )

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Inspection Simulation Chamber</title>

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

            .scenario{
                margin-top:18px;
                padding:22px;
                border-radius:18px;
                background:rgba(255,255,255,0.04);
                border:1px solid rgba(255,255,255,0.08);
            }

            .scenario strong{
                display:block;
                color:#ff9f1c;
                font-size:28px;
            }

            .pill{
                display:inline-block;
                margin-top:12px;
                margin-right:8px;
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
                .ops-grid{
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

                <h1>Inspection Simulation Chamber</h1>

                <p>
                    Enterprise governance survivability simulation environment
                    for radiopharma inspection rehearsal,
                    commercialization defense testing,
                    operational exposure simulation,
                    and audit survivability cognition.
                </p>

                <div class="hero-grid">

                    <div class="panel">

                        <h2>Inspection Simulation Scenarios</h2>

                        {% for row in scenarios %}

                        <div class="scenario">

                            <strong>{{ row.scenario }}</strong>

                            <p>
                                Inspection exposure:
                                <b>{{ row.exposure }}</b>
                            </p>

                            <span class="pill">
                                Survivability {{ row.survivability }}%
                            </span>

                            <span class="pill">
                                {{ row.state }}
                            </span>

                        </div>

                        {% endfor %}

                    </div>

                    <div class="overall">

                        <strong>{{ survivability_score }}%</strong>

                        Inspection Survivability

                    </div>

                </div>

            </section>

            <div class="ops-grid">

                <section class="panel">

                    <h2>Simulation Chamber Intelligence</h2>

                    <ul>

                        <li>
                            FDA commercialization inspection survivability remains operationally defensible.
                        </li>

                        <li>
                            CAPA backlog accumulation remains the highest projected inspection destabilization pathway.
                        </li>

                        <li>
                            Cold-chain governance remains commercially survivable under simulated deviation conditions.
                        </li>

                        <li>
                            Dose traceability integrity remains the strongest audit survivability control layer.
                        </li>

                        <li>
                            Multi-site governance federation remains stable under projected inspection load.
                        </li>

                        <li>
                            Simulation cognition remains aligned with commercialization governance defense objectives.
                        </li>

                    </ul>

                </section>

                <section class="panel">

                    <h2>Inspection Survivability Matrix</h2>

                    <table>

                        <thead>

                            <tr>
                                <th>Scenario</th>
                                <th>Exposure</th>
                                <th>Survivability</th>
                                <th>State</th>
                            </tr>

                        </thead>

                        <tbody>

                            {% for row in scenarios %}

                            <tr>

                                <td>{{ row.scenario }}</td>

                                <td>{{ row.exposure }}</td>

                                <td>{{ row.survivability }}%</td>

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
        scenarios=IRLT_INSPECTION_SCENARIOS_V1,
        survivability_score=survivability_score
    )


@app.route("/irlt-commercial-readiness/inspection-simulator/api")
def irlt_inspection_simulator_api():

    return jsonify({
        "survivability_score": round(
            sum(x["survivability"] for x in IRLT_INSPECTION_SCENARIOS_V1)
            / len(IRLT_INSPECTION_SCENARIOS_V1)
        ),
        "scenarios": IRLT_INSPECTION_SCENARIOS_V1
    })

# ============================================================
# END IRLT_INSPECTION_SIMULATION_CHAMBER_V1
# ============================================================

"""

text = text.replace(anchor, anchor + block)

APP.write_text(text, encoding="utf-8")

print("Inspection Simulation Chamber inserted successfully.")
