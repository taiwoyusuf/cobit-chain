from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_GOVERNANCE_DIGITAL_TWIN_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Governance Digital Twin already exists.")
    raise SystemExit()

anchor = "# END IRLT_AUTONOMOUS_GOVERNANCE_COORDINATION_ENGINE_V1"

if anchor not in text:
    print("Could not locate safe insertion anchor.")
    raise SystemExit()

block = r"""

# ============================================================
# IRLT_GOVERNANCE_DIGITAL_TWIN_ENGINE_V1_ACTIVE
# ============================================================

IRLT_DIGITAL_TWIN_STATE_V1 = [
    {
        "domain": "Operational Trust",
        "score": 94,
        "state": "Stable"
    },
    {
        "domain": "Commercialization Readiness",
        "score": 91,
        "state": "Controlled"
    },
    {
        "domain": "Inspection Survivability",
        "score": 95,
        "state": "Strong"
    },
    {
        "domain": "Governance Drift",
        "score": 18,
        "state": "Contained"
    },
    {
        "domain": "Escalation Pressure",
        "score": 27,
        "state": "Observed"
    },
    {
        "domain": "Evidence Coherence",
        "score": 96,
        "state": "Verified"
    }
]


@app.route("/irlt-commercial-readiness/digital-twin")
def irlt_digital_twin():

    trust_score = round(
        sum(x["score"] for x in IRLT_DIGITAL_TWIN_STATE_V1)
        / len(IRLT_DIGITAL_TWIN_STATE_V1)
    )

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Governance Digital Twin Engine</title>

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
                padding:22px;
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

            .pulse{
                margin-top:20px;
                height:14px;
                border-radius:999px;
                overflow:hidden;
                background:rgba(255,255,255,0.08);
            }

            .pulse-fill{
                height:100%;
                background:linear-gradient(90deg,#ff9f1c,#ffb347);
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

                <h1>Governance Digital Twin</h1>

                <p>
                    Enterprise governance-operational cognition twin for
                    commercialization readiness state modeling,
                    operational trust synchronization,
                    governance drift intelligence,
                    and inspection survivability simulation.
                </p>

                <div class="hero-grid">

                    <div class="panel">

                        <h2>Governance Twin State Model</h2>

                        <div class="grid">

                            {% for row in twin %}

                            <div class="card">

                                <strong>{{ row.score }}%</strong>

                                {{ row.domain }}

                                <div class="pulse">

                                    <div class="pulse-fill"
                                         style="width:{{ row.score }}%">
                                    </div>

                                </div>

                                <span class="pill">
                                    {{ row.state }}
                                </span>

                            </div>

                            {% endfor %}

                        </div>

                    </div>

                    <div class="overall">

                        <strong>{{ trust_score }}%</strong>

                        Governance Twin Stability

                    </div>

                </div>

            </section>

            <div class="ops-grid">

                <section class="panel">

                    <h2>Governance Twin Intelligence</h2>

                    <ul>

                        <li>
                            Operational trust synchronization remains commercially stable across governance pathways.
                        </li>

                        <li>
                            Commercialization readiness posture remains operationally defensible under projected scale conditions.
                        </li>

                        <li>
                            Governance drift exposure remains contained within enterprise tolerance thresholds.
                        </li>

                        <li>
                            Escalation pressure remains observable but operationally survivable.
                        </li>

                        <li>
                            Evidence coherence remains highly aligned across operational lineage domains.
                        </li>

                        <li>
                            Governance twin cognition remains synchronized with commercialization readiness objectives.
                        </li>

                    </ul>

                </section>

                <section class="panel">

                    <h2>Governance Twin Matrix</h2>

                    <table>

                        <thead>

                            <tr>
                                <th>Governance Domain</th>
                                <th>Score</th>
                                <th>State</th>
                            </tr>

                        </thead>

                        <tbody>

                            {% for row in twin %}

                            <tr>

                                <td>{{ row.domain }}</td>

                                <td>{{ row.score }}%</td>

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
        twin=IRLT_DIGITAL_TWIN_STATE_V1,
        trust_score=trust_score
    )


@app.route("/irlt-commercial-readiness/digital-twin/api")
def irlt_digital_twin_api():

    return jsonify({
        "trust_score": round(
            sum(x["score"] for x in IRLT_DIGITAL_TWIN_STATE_V1)
            / len(IRLT_DIGITAL_TWIN_STATE_V1)
        ),
        "twin_state": IRLT_DIGITAL_TWIN_STATE_V1
    })

# ============================================================
# END IRLT_GOVERNANCE_DIGITAL_TWIN_ENGINE_V1
# ============================================================

"""

text = text.replace(anchor, anchor + block)

APP.write_text(text, encoding="utf-8")

print("Governance Digital Twin Engine inserted successfully.")
