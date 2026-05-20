from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_AUTONOMOUS_GOVERNANCE_COORDINATION_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Governance Coordination Engine already exists.")
    raise SystemExit()

anchor = "# END IRLT_MULTI_SITE_COMMERCIALIZATION_FEDERATION_ENGINE_V1"

if anchor not in text:
    print("Could not locate safe insertion anchor.")
    raise SystemExit()

block = r"""

# ============================================================
# IRLT_AUTONOMOUS_GOVERNANCE_COORDINATION_ENGINE_V1_ACTIVE
# ============================================================

IRLT_COORDINATION_ACTIONS_V1 = [
    {
        "condition": "CAPA Closure Delay",
        "coordination": "Prioritize QA escalation review",
        "priority": "Critical",
        "confidence": 94
    },
    {
        "condition": "Environmental Excursion",
        "coordination": "Isolate release chain and trigger investigation",
        "priority": "High",
        "confidence": 92
    },
    {
        "condition": "Shipment Delay",
        "coordination": "Coordinate treatment timing stabilization",
        "priority": "Elevated",
        "confidence": 88
    },
    {
        "condition": "Backup Verification Failure",
        "coordination": "Escalate evidence survivability review",
        "priority": "High",
        "confidence": 90
    },
    {
        "condition": "Training Governance Gap",
        "coordination": "Freeze impacted approval workflow",
        "priority": "Moderate",
        "confidence": 84
    },
    {
        "condition": "Access Governance Drift",
        "coordination": "Restrict privileged governance actions",
        "priority": "Observed",
        "confidence": 82
    }
]


@app.route("/irlt-commercial-readiness/governance-coordination")
def irlt_governance_coordination():

    coordination_score = round(
        sum(x["confidence"] for x in IRLT_COORDINATION_ACTIONS_V1)
        / len(IRLT_COORDINATION_ACTIONS_V1)
    )

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Governance Coordination Engine</title>

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

            .action{
                margin-top:18px;
                padding:20px;
                border-radius:18px;
                background:rgba(255,255,255,0.04);
                border:1px solid rgba(255,255,255,0.08);
            }

            .action strong{
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

                <h1>Governance Coordination Engine</h1>

                <p>
                    Enterprise operational governance coordination intelligence
                    layer for commercialization stabilization,
                    escalation orchestration,
                    operational trust recovery sequencing,
                    and governed remediation pathway intelligence.
                </p>

                <div class="hero-grid">

                    <div class="panel">

                        <h2>Governance Coordination Actions</h2>

                        {% for row in actions %}

                        <div class="action">

                            <strong>{{ row.condition }}</strong>

                            <p>
                                {{ row.coordination }}
                            </p>

                            <span class="pill">
                                {{ row.priority }}
                            </span>

                            <span class="pill">
                                Confidence {{ row.confidence }}%
                            </span>

                        </div>

                        {% endfor %}

                    </div>

                    <div class="overall">

                        <strong>{{ coordination_score }}%</strong>

                        Coordination Confidence

                    </div>

                </div>

            </section>

            <div class="ops-grid">

                <section class="panel">

                    <h2>Governance Coordination Intelligence</h2>

                    <ul>

                        <li>
                            CAPA governance stabilization remains the highest enterprise coordination priority.
                        </li>

                        <li>
                            Environmental governance excursions require immediate release defensibility isolation sequencing.
                        </li>

                        <li>
                            Shipment coordination stabilization remains critical for treatment continuity assurance.
                        </li>

                        <li>
                            Backup governance failures materially impact evidence survivability confidence pathways.
                        </li>

                        <li>
                            Training governance drift remains operationally manageable under controlled intervention sequencing.
                        </li>

                        <li>
                            Governance coordination intelligence remains aligned with commercialization stabilization objectives.
                        </li>

                    </ul>

                </section>

                <section class="panel">

                    <h2>Governance Coordination Matrix</h2>

                    <table>

                        <thead>

                            <tr>
                                <th>Condition</th>
                                <th>Coordination Action</th>
                                <th>Priority</th>
                                <th>Confidence</th>
                            </tr>

                        </thead>

                        <tbody>

                            {% for row in actions %}

                            <tr>

                                <td>{{ row.condition }}</td>

                                <td>{{ row.coordination }}</td>

                                <td>{{ row.priority }}</td>

                                <td>{{ row.confidence }}%</td>

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
        actions=IRLT_COORDINATION_ACTIONS_V1,
        coordination_score=coordination_score
    )


@app.route("/irlt-commercial-readiness/governance-coordination/api")
def irlt_governance_coordination_api():

    return jsonify({
        "coordination_score": round(
            sum(x["confidence"] for x in IRLT_COORDINATION_ACTIONS_V1)
            / len(IRLT_COORDINATION_ACTIONS_V1)
        ),
        "actions": IRLT_COORDINATION_ACTIONS_V1
    })

# ============================================================
# END IRLT_AUTONOMOUS_GOVERNANCE_COORDINATION_ENGINE_V1
# ============================================================

"""

text = text.replace(anchor, anchor + block)

APP.write_text(text, encoding="utf-8")

print("Governance Coordination Engine inserted successfully.")
