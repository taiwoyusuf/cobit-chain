from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_MULTI_SITE_COMMERCIALIZATION_FEDERATION_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Federation Command Engine already exists.")
    raise SystemExit()

anchor = "# END IRLT_OPERATIONAL_TRUST_TIMELINE_REPLAY_ENGINE_V1"

if anchor not in text:
    print("Could not locate safe insertion anchor.")
    raise SystemExit()

block = r"""

# ============================================================
# IRLT_MULTI_SITE_COMMERCIALIZATION_FEDERATION_ENGINE_V1_ACTIVE
# ============================================================

IRLT_FEDERATION_SITES_V1 = [
    {
        "site": "Indianapolis IRLT Hub",
        "trust": 94,
        "inspection": "Strong",
        "release": "Ready",
        "state": "Stable"
    },
    {
        "site": "Europe Radiopharma Node",
        "trust": 89,
        "inspection": "Moderate",
        "release": "Review",
        "state": "Observed"
    },
    {
        "site": "West Coast Treatment Network",
        "trust": 92,
        "inspection": "Strong",
        "release": "Ready",
        "state": "Controlled"
    },
    {
        "site": "Partner Manufacturing Site",
        "trust": 81,
        "inspection": "Elevated",
        "release": "Escalated",
        "state": "Monitoring"
    },
    {
        "site": "Cold Chain Logistics Federation",
        "trust": 90,
        "inspection": "Stable",
        "release": "Ready",
        "state": "Aligned"
    },
    {
        "site": "Commercial Packaging Network",
        "trust": 87,
        "inspection": "Observed",
        "release": "Review",
        "state": "Review"
    }
]


@app.route("/irlt-commercial-readiness/federation-command")
def irlt_federation_command():

    federation_score = round(
        sum(x["trust"] for x in IRLT_FEDERATION_SITES_V1)
        / len(IRLT_FEDERATION_SITES_V1)
    )

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Federation Command Engine</title>

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
                grid-template-columns:repeat(2,1fr);
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
                font-size:34px;
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

                <h1>Federation Command Engine</h1>

                <p>
                    Enterprise multi-site governance federation intelligence
                    layer for radiopharma commercialization scaling,
                    federated operational trust alignment,
                    inspection survivability orchestration,
                    and distributed governance readiness coordination.
                </p>

                <div class="hero-grid">

                    <div class="panel">

                        <h2>Federated Operational Trust Sites</h2>

                        <div class="grid">

                            {% for row in sites %}

                            <div class="card">

                                <strong>{{ row.trust }}%</strong>

                                {{ row.site }}

                                <br>

                                <span class="pill">
                                    {{ row.inspection }}
                                </span>

                                <span class="pill">
                                    {{ row.release }}
                                </span>

                                <span class="pill">
                                    {{ row.state }}
                                </span>

                            </div>

                            {% endfor %}

                        </div>

                    </div>

                    <div class="overall">

                        <strong>{{ federation_score }}%</strong>

                        Federated Governance Trust

                    </div>

                </div>

            </section>

            <div class="ops-grid">

                <section class="panel">

                    <h2>Federated Commercialization Intelligence</h2>

                    <ul>

                        <li>
                            Indianapolis governance readiness remains the strongest commercialization trust anchor across the federation.
                        </li>

                        <li>
                            Partner manufacturing operations remain the highest projected inspection survivability exposure point.
                        </li>

                        <li>
                            Cold-chain governance alignment remains operationally stable across distributed logistics pathways.
                        </li>

                        <li>
                            European radiopharma readiness requires additional governance stabilization review.
                        </li>

                        <li>
                            Multi-site operational trust coherence remains commercially sustainable under projected scale conditions.
                        </li>

                        <li>
                            Federated governance intelligence remains aligned with enterprise commercialization objectives.
                        </li>

                    </ul>

                </section>

                <section class="panel">

                    <h2>Federation Governance Matrix</h2>

                    <table>

                        <thead>

                            <tr>
                                <th>Site</th>
                                <th>Trust</th>
                                <th>Inspection</th>
                                <th>Release</th>
                            </tr>

                        </thead>

                        <tbody>

                            {% for row in sites %}

                            <tr>

                                <td>{{ row.site }}</td>

                                <td>{{ row.trust }}%</td>

                                <td>{{ row.inspection }}</td>

                                <td>{{ row.release }}</td>

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
        sites=IRLT_FEDERATION_SITES_V1,
        federation_score=federation_score
    )


@app.route("/irlt-commercial-readiness/federation-command/api")
def irlt_federation_command_api():

    return jsonify({
        "federation_score": round(
            sum(x["trust"] for x in IRLT_FEDERATION_SITES_V1)
            / len(IRLT_FEDERATION_SITES_V1)
        ),
        "sites": IRLT_FEDERATION_SITES_V1
    })

# ============================================================
# END IRLT_MULTI_SITE_COMMERCIALIZATION_FEDERATION_ENGINE_V1
# ============================================================

"""

text = text.replace(anchor, anchor + block)

APP.write_text(text, encoding="utf-8")

print("Federation Command Engine inserted successfully.")
