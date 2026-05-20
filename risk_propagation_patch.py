from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_GOVERNANCE_RISK_PROPAGATION_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Risk Propagation Engine already exists.")
    raise SystemExit()

anchor = "# END IRLT_AUTONOMOUS_INSPECTION_DEFENSE_ENGINE_V1"

if anchor not in text:
    print("Could not locate safe insertion anchor.")
    raise SystemExit()

block = r"""

# ============================================================
# IRLT_GOVERNANCE_RISK_PROPAGATION_ENGINE_V1_ACTIVE
# ============================================================

IRLT_RISK_PROPAGATION_V1 = [
    {
        "source": "CAPA Closure Delay",
        "impact": "Inspection Survivability",
        "severity": 88,
        "state": "Escalating"
    },
    {
        "source": "Environmental Excursion",
        "impact": "Release Defensibility",
        "severity": 92,
        "state": "Critical"
    },
    {
        "source": "Training Governance Gap",
        "impact": "Operational Readiness",
        "severity": 74,
        "state": "Observed"
    },
    {
        "source": "Backup Verification Failure",
        "impact": "Evidence Survivability",
        "severity": 81,
        "state": "Elevated"
    },
    {
        "source": "Shipment Delay",
        "impact": "Treatment Coordination",
        "severity": 79,
        "state": "Monitoring"
    },
    {
        "source": "Access Governance Drift",
        "impact": "Audit Defensibility",
        "severity": 76,
        "state": "Observed"
    }
]


@app.route("/irlt-commercial-readiness/risk-propagation")
def irlt_risk_propagation():

    overall_risk = round(
        sum(x["severity"] for x in IRLT_RISK_PROPAGATION_V1)
        / len(IRLT_RISK_PROPAGATION_V1)
    )

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Governance Risk Propagation Engine</title>

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

            .risk-line{
                margin-top:18px;
                padding:16px;
                border-radius:16px;
                background:rgba(255,255,255,0.03);
                border:1px solid rgba(255,255,255,0.06);
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

                <h1>Risk Propagation Engine</h1>

                <p>
                    Enterprise governance blast-radius intelligence engine
                    for commercialization readiness deterioration modeling,
                    dependency propagation analysis, inspection survivability
                    exposure, and operational trust degradation forecasting.
                </p>

                <div class="hero-grid">

                    <div class="panel">

                        <h2>Governance Blast Radius Intelligence</h2>

                        {% for row in risks %}

                        <div class="risk-line">

                            <strong style="font-size:26px;color:#ff9f1c;">
                                {{ row.source }}
                            </strong>

                            <p>
                                Propagates operationally into:
                                <b>{{ row.impact }}</b>
                            </p>

                            <span class="pill">
                                Severity {{ row.severity }}%
                            </span>

                            <span class="pill">
                                {{ row.state }}
                            </span>

                        </div>

                        {% endfor %}

                    </div>

                    <div class="overall">

                        <strong>{{ overall_risk }}%</strong>

                        Governance Blast Radius

                    </div>

                </div>

            </section>

            <div class="ops-grid">

                <section class="panel">

                    <h2>Operational Governance Propagation Analysis</h2>

                    <ul>

                        <li>
                            CAPA closure degradation remains the strongest projected inspection destabilization pathway.
                        </li>

                        <li>
                            Environmental monitoring excursions create the highest release defensibility exposure.
                        </li>

                        <li>
                            Backup governance instability directly weakens audit evidence survivability posture.
                        </li>

                        <li>
                            Shipment coordination instability propagates into treatment timing governance exposure.
                        </li>

                        <li>
                            Governance dependency chains remain commercially survivable but require active monitoring.
                        </li>

                        <li>
                            Operational trust degradation remains controllable under current escalation conditions.
                        </li>

                    </ul>

                </section>

                <section class="panel">

                    <h2>Propagation Dependency Matrix</h2>

                    <table>

                        <thead>

                            <tr>
                                <th>Source Event</th>
                                <th>Propagation Impact</th>
                                <th>Severity</th>
                                <th>State</th>
                            </tr>

                        </thead>

                        <tbody>

                            {% for row in risks %}

                            <tr>

                                <td>{{ row.source }}</td>

                                <td>{{ row.impact }}</td>

                                <td>{{ row.severity }}%</td>

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
        risks=IRLT_RISK_PROPAGATION_V1,
        overall_risk=overall_risk
    )


@app.route("/irlt-commercial-readiness/risk-propagation/api")
def irlt_risk_propagation_api():

    return jsonify({
        "overall_risk": round(
            sum(x["severity"] for x in IRLT_RISK_PROPAGATION_V1)
            / len(IRLT_RISK_PROPAGATION_V1)
        ),
        "propagation": IRLT_RISK_PROPAGATION_V1
    })

# ============================================================
# END IRLT_GOVERNANCE_RISK_PROPAGATION_ENGINE_V1
# ============================================================

"""

text = text.replace(anchor, anchor + block)

APP.write_text(text, encoding="utf-8")

print("Risk Propagation Engine inserted successfully.")
