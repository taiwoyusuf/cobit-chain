from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_RELEASE_DEFENSIBILITY_COMMAND_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Release Defensibility Command Engine already exists.")
    raise SystemExit()

anchor = "# END IRLT_GOVERNANCE_DIGITAL_TWIN_ENGINE_V1"

if anchor not in text:
    print("Could not locate safe insertion anchor.")
    raise SystemExit()

block = r"""

# ============================================================
# IRLT_RELEASE_DEFENSIBILITY_COMMAND_ENGINE_V1_ACTIVE
# ============================================================

IRLT_RELEASE_DEFENSE_V1 = [
    {
        "domain": "Batch Release Governance",
        "score": 96,
        "state": "Defensible",
        "owner": "QA Release"
    },
    {
        "domain": "Environmental Monitoring",
        "score": 84,
        "state": "Observed",
        "owner": "EM Governance"
    },
    {
        "domain": "Dose Lineage Integrity",
        "score": 97,
        "state": "Verified",
        "owner": "Radiopharma Operations"
    },
    {
        "domain": "CAPA Readiness",
        "score": 81,
        "state": "Pressure",
        "owner": "Quality Systems"
    },
    {
        "domain": "Shipment Governance",
        "score": 92,
        "state": "Stable",
        "owner": "Distribution Operations"
    },
    {
        "domain": "Evidence Survivability",
        "score": 95,
        "state": "Strong",
        "owner": "Governance Assurance"
    }
]


@app.route("/irlt-commercial-readiness/release-defensibility")
def irlt_release_defensibility():

    defensibility_score = round(
        sum(x["score"] for x in IRLT_RELEASE_DEFENSE_V1)
        / len(IRLT_RELEASE_DEFENSE_V1)
    )

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Release Defensibility Command Engine</title>

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
                font-size:40px;
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

                <h1>Release Defensibility Command</h1>

                <p>
                    Enterprise commercialization release governance intelligence
                    layer for inspection survivability,
                    operational release defensibility,
                    audit-ready batch governance,
                    and enterprise trust certification orchestration.
                </p>

                <div class="hero-grid">

                    <div class="panel">

                        <h2>Release Governance Domains</h2>

                        <div class="grid">

                            {% for row in defense %}

                            <div class="card">

                                <strong>{{ row.score }}%</strong>

                                {{ row.domain }}

                                <br>

                                <span class="pill">
                                    {{ row.state }}
                                </span>

                                <br><br>

                                <small style="color:#b8c1cd;">
                                    {{ row.owner }}
                                </small>

                            </div>

                            {% endfor %}

                        </div>

                    </div>

                    <div class="overall">

                        <strong>{{ defensibility_score }}%</strong>

                        Release Defensibility

                    </div>

                </div>

            </section>

            <div class="ops-grid">

                <section class="panel">

                    <h2>Release Governance Intelligence</h2>

                    <ul>

                        <li>
                            Batch release governance remains commercially defensible under projected inspection pressure.
                        </li>

                        <li>
                            Dose lineage verification remains the strongest operational release survivability domain.
                        </li>

                        <li>
                            CAPA readiness remains the highest projected release governance escalation vector.
                        </li>

                        <li>
                            Environmental monitoring governance remains operationally observable but manageable.
                        </li>

                        <li>
                            Shipment governance alignment remains stable across commercialization pathways.
                        </li>

                        <li>
                            Enterprise evidence survivability remains highly aligned with audit defensibility expectations.
                        </li>

                    </ul>

                </section>

                <section class="panel">

                    <h2>Release Defensibility Matrix</h2>

                    <table>

                        <thead>

                            <tr>
                                <th>Governance Domain</th>
                                <th>Score</th>
                                <th>State</th>
                                <th>Owner</th>
                            </tr>

                        </thead>

                        <tbody>

                            {% for row in defense %}

                            <tr>

                                <td>{{ row.domain }}</td>

                                <td>{{ row.score }}%</td>

                                <td>{{ row.state }}</td>

                                <td>{{ row.owner }}</td>

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
        defense=IRLT_RELEASE_DEFENSE_V1,
        defensibility_score=defensibility_score
    )


@app.route("/irlt-commercial-readiness/release-defensibility/api")
def irlt_release_defensibility_api():

    return jsonify({
        "defensibility_score": round(
            sum(x["score"] for x in IRLT_RELEASE_DEFENSE_V1)
            / len(IRLT_RELEASE_DEFENSE_V1)
        ),
        "domains": IRLT_RELEASE_DEFENSE_V1
    })

# ============================================================
# END IRLT_RELEASE_DEFENSIBILITY_COMMAND_ENGINE_V1
# ============================================================

"""

text = text.replace(anchor, anchor + block)

APP.write_text(text, encoding="utf-8")

print("Release Defensibility Command Engine inserted successfully.")
