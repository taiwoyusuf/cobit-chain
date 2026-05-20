from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_DEPENDENCY_COGNITION_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Dependency Cognition Engine already exists.")
    raise SystemExit()

anchor = "# END IRLT_GOVERNANCE_RECOVERY_ORCHESTRATOR_V1"

if anchor not in text:
    print("Could not locate safe insertion anchor.")
    raise SystemExit()

block = r"""

# ============================================================
# IRLT_DEPENDENCY_COGNITION_ENGINE_V1_ACTIVE
# ============================================================

IRLT_DEPENDENCY_CHAINS_V1 = [
    {
        "source": "Environmental Monitoring",
        "dependency": "Commercial Batch Release",
        "criticality": 94,
        "state": "High Coupling"
    },
    {
        "source": "CAPA Governance",
        "dependency": "Inspection Survivability",
        "criticality": 96,
        "state": "Critical"
    },
    {
        "source": "Dose Lineage",
        "dependency": "Patient Treatment Integrity",
        "criticality": 98,
        "state": "Verified"
    },
    {
        "source": "Cold Chain Monitoring",
        "dependency": "Shipment Release Stability",
        "criticality": 89,
        "state": "Controlled"
    },
    {
        "source": "Access Governance",
        "dependency": "Operational Defensibility",
        "criticality": 83,
        "state": "Observed"
    },
    {
        "source": "Backup Survivability",
        "dependency": "Audit Evidence Continuity",
        "criticality": 91,
        "state": "Stable"
    }
]


@app.route("/irlt-commercial-readiness/dependency-cognition")
def irlt_dependency_cognition():

    cognition_score = round(
        sum(x["criticality"] for x in IRLT_DEPENDENCY_CHAINS_V1)
        / len(IRLT_DEPENDENCY_CHAINS_V1)
    )

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Dependency Cognition Engine</title>

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

            .dependency{
                margin-top:18px;
                padding:22px;
                border-radius:18px;
                background:rgba(255,255,255,0.04);
                border:1px solid rgba(255,255,255,0.08);
            }

            .dependency strong{
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

                <h1>Dependency Cognition Engine</h1>

                <p>
                    Enterprise governance dependency intelligence engine for
                    commercialization readiness dependency mapping,
                    operational trust propagation analysis,
                    governance coupling visibility,
                    and inspection survivability dependency cognition.
                </p>

                <div class="hero-grid">

                    <div class="panel">

                        <h2>Operational Dependency Chains</h2>

                        {% for row in dependencies %}

                        <div class="dependency">

                            <strong>{{ row.source }}</strong>

                            <p>
                                Operationally coupled to:
                                <b>{{ row.dependency }}</b>
                            </p>

                            <span class="pill">
                                Criticality {{ row.criticality }}%
                            </span>

                            <span class="pill">
                                {{ row.state }}
                            </span>

                        </div>

                        {% endfor %}

                    </div>

                    <div class="overall">

                        <strong>{{ cognition_score }}%</strong>

                        Dependency Stability

                    </div>

                </div>

            </section>

            <div class="ops-grid">

                <section class="panel">

                    <h2>Dependency Intelligence Analysis</h2>

                    <ul>

                        <li>
                            CAPA governance remains the strongest inspection survivability dependency driver.
                        </li>

                        <li>
                            Environmental monitoring stability remains directly coupled to release defensibility posture.
                        </li>

                        <li>
                            Dose lineage governance remains foundational to treatment integrity assurance.
                        </li>

                        <li>
                            Backup survivability remains operationally critical for evidence continuity preservation.
                        </li>

                        <li>
                            Access governance drift remains observable but commercially manageable.
                        </li>

                        <li>
                            Dependency cognition intelligence remains aligned with commercialization governance survivability objectives.
                        </li>

                    </ul>

                </section>

                <section class="panel">

                    <h2>Dependency Coupling Matrix</h2>

                    <table>

                        <thead>

                            <tr>
                                <th>Governance Source</th>
                                <th>Dependency Target</th>
                                <th>Criticality</th>
                                <th>State</th>
                            </tr>

                        </thead>

                        <tbody>

                            {% for row in dependencies %}

                            <tr>

                                <td>{{ row.source }}</td>

                                <td>{{ row.dependency }}</td>

                                <td>{{ row.criticality }}%</td>

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
        dependencies=IRLT_DEPENDENCY_CHAINS_V1,
        cognition_score=cognition_score
    )


@app.route("/irlt-commercial-readiness/dependency-cognition/api")
def irlt_dependency_cognition_api():

    return jsonify({
        "cognition_score": round(
            sum(x["criticality"] for x in IRLT_DEPENDENCY_CHAINS_V1)
            / len(IRLT_DEPENDENCY_CHAINS_V1)
        ),
        "dependencies": IRLT_DEPENDENCY_CHAINS_V1
    })

# ============================================================
# END IRLT_DEPENDENCY_COGNITION_ENGINE_V1
# ============================================================

"""

text = text.replace(anchor, anchor + block)

APP.write_text(text, encoding="utf-8")

print("Dependency Cognition Engine inserted successfully.")
