from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_GOVERNANCE_RECOVERY_ORCHESTRATOR_V1_ACTIVE"

if MARKER in text:
    print("Recovery Orchestrator already exists.")
    raise SystemExit()

anchor = "# END IRLT_INSPECTION_SIMULATION_CHAMBER_V1"

if anchor not in text:
    print("Could not locate safe insertion anchor.")
    raise SystemExit()

block = r"""

# ============================================================
# IRLT_GOVERNANCE_RECOVERY_ORCHESTRATOR_V1_ACTIVE
# ============================================================

IRLT_RECOVERY_STREAMS_V1 = [
    {
        "incident": "Environmental Monitoring Excursion",
        "recovery": "Controlled Recovery Sequence",
        "confidence": 89,
        "state": "Stabilizing"
    },
    {
        "incident": "CAPA Escalation Surge",
        "recovery": "Governance Intervention Pathway",
        "confidence": 83,
        "state": "Observed"
    },
    {
        "incident": "Cold Chain Disruption",
        "recovery": "Distribution Recovery Workflow",
        "confidence": 91,
        "state": "Controlled"
    },
    {
        "incident": "Backup Validation Failure",
        "recovery": "Evidence Restoration Sequence",
        "confidence": 87,
        "state": "Recovering"
    },
    {
        "incident": "Shipment Coordination Breakdown",
        "recovery": "Treatment Continuity Recovery",
        "confidence": 86,
        "state": "Active"
    },
    {
        "incident": "Inspection Escalation Event",
        "recovery": "Inspection Defense Stabilization",
        "confidence": 93,
        "state": "Strong"
    }
]


@app.route("/irlt-commercial-readiness/recovery-orchestrator")
def irlt_recovery_orchestrator():

    recovery_score = round(
        sum(x["confidence"] for x in IRLT_RECOVERY_STREAMS_V1)
        / len(IRLT_RECOVERY_STREAMS_V1)
    )

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Governance Recovery Orchestrator</title>

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

            .recovery{
                margin-top:18px;
                padding:22px;
                border-radius:18px;
                background:rgba(255,255,255,0.04);
                border:1px solid rgba(255,255,255,0.08);
            }

            .recovery strong{
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

                <h1>Governance Recovery Orchestrator</h1>

                <p>
                    Enterprise governance recovery intelligence engine for
                    commercialization stabilization,
                    operational survivability restoration,
                    governance recovery sequencing,
                    and inspection resilience orchestration.
                </p>

                <div class="hero-grid">

                    <div class="panel">

                        <h2>Recovery Orchestration Streams</h2>

                        {% for row in recovery %}

                        <div class="recovery">

                            <strong>{{ row.incident }}</strong>

                            <p>
                                {{ row.recovery }}
                            </p>

                            <span class="pill">
                                {{ row.state }}
                            </span>

                            <span class="pill">
                                Confidence {{ row.confidence }}%
                            </span>

                        </div>

                        {% endfor %}

                    </div>

                    <div class="overall">

                        <strong>{{ recovery_score }}%</strong>

                        Recovery Survivability

                    </div>

                </div>

            </section>

            <div class="ops-grid">

                <section class="panel">

                    <h2>Recovery Intelligence Analysis</h2>

                    <ul>

                        <li>
                            Environmental monitoring recovery sequencing remains operationally stable under escalation pressure.
                        </li>

                        <li>
                            CAPA recovery orchestration remains the primary enterprise stabilization dependency.
                        </li>

                        <li>
                            Cold-chain recovery survivability remains commercially defensible.
                        </li>

                        <li>
                            Evidence restoration governance remains aligned with audit survivability expectations.
                        </li>

                        <li>
                            Shipment continuity recovery remains operationally manageable under projected disruption conditions.
                        </li>

                        <li>
                            Governance recovery orchestration remains synchronized with commercialization continuity objectives.
                        </li>

                    </ul>

                </section>

                <section class="panel">

                    <h2>Recovery Governance Matrix</h2>

                    <table>

                        <thead>

                            <tr>
                                <th>Incident</th>
                                <th>Recovery Pathway</th>
                                <th>Confidence</th>
                                <th>State</th>
                            </tr>

                        </thead>

                        <tbody>

                            {% for row in recovery %}

                            <tr>

                                <td>{{ row.incident }}</td>

                                <td>{{ row.recovery }}</td>

                                <td>{{ row.confidence }}%</td>

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
        recovery=IRLT_RECOVERY_STREAMS_V1,
        recovery_score=recovery_score
    )


@app.route("/irlt-commercial-readiness/recovery-orchestrator/api")
def irlt_recovery_orchestrator_api():

    return jsonify({
        "recovery_score": round(
            sum(x["confidence"] for x in IRLT_RECOVERY_STREAMS_V1)
            / len(IRLT_RECOVERY_STREAMS_V1)
        ),
        "recovery_streams": IRLT_RECOVERY_STREAMS_V1
    })

# ============================================================
# END IRLT_GOVERNANCE_RECOVERY_ORCHESTRATOR_V1
# ============================================================

"""

text = text.replace(anchor, anchor + block)

APP.write_text(text, encoding="utf-8")

print("Governance Recovery Orchestrator inserted successfully.")
