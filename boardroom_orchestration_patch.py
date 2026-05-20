from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_BOARDROOM_ORCHESTRATION_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Boardroom Orchestration Engine already exists.")
    raise SystemExit()

anchor = "# END IRLT_EXECUTIVE_COMMAND_MATRIX_ENGINE_V1"

if anchor not in text:
    print("Could not locate safe insertion anchor.")
    raise SystemExit()

block = r"""

# ============================================================
# IRLT_BOARDROOM_ORCHESTRATION_ENGINE_V1_ACTIVE
# ============================================================

IRLT_BOARDROOM_STREAMS_V1 = [
    {
        "pillar": "Commercialization Readiness",
        "score": 96,
        "state": "Board Ready",
        "owner": "Executive Operations"
    },
    {
        "pillar": "Inspection Defense",
        "score": 94,
        "state": "Defensible",
        "owner": "Compliance Leadership"
    },
    {
        "pillar": "Dose Traceability",
        "score": 99,
        "state": "Verified",
        "owner": "Radiopharma Governance"
    },
    {
        "pillar": "Cold Chain Continuity",
        "score": 91,
        "state": "Stable",
        "owner": "Distribution Operations"
    },
    {
        "pillar": "CAPA Stabilization",
        "score": 82,
        "state": "Observed",
        "owner": "Quality Systems"
    },
    {
        "pillar": "Evidence Survivability",
        "score": 97,
        "state": "Protected",
        "owner": "Governance Assurance"
    }
]


@app.route("/irlt-commercial-readiness/boardroom")
def irlt_boardroom_orchestration():

    boardroom_score = round(
        sum(x["score"] for x in IRLT_BOARDROOM_STREAMS_V1)
        / len(IRLT_BOARDROOM_STREAMS_V1)
    )

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Boardroom Orchestration Engine</title>

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

                <h1>Boardroom Orchestration</h1>

                <p>
                    Executive governance orchestration environment for
                    commercialization board readiness,
                    enterprise operational trust alignment,
                    inspection survivability leadership visibility,
                    and governance decision synchronization.
                </p>

                <div class="hero-grid">

                    <div class="panel">

                        <h2>Executive Governance Pillars</h2>

                        <div class="grid">

                            {% for row in streams %}

                            <div class="card">

                                <strong>{{ row.score }}%</strong>

                                {{ row.pillar }}

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

                        <strong>{{ boardroom_score }}%</strong>

                        Executive Readiness

                    </div>

                </div>

            </section>

            <div class="ops-grid">

                <section class="panel">

                    <h2>Boardroom Governance Intelligence</h2>

                    <ul>

                        <li>
                            Commercialization governance remains strongly aligned with executive launch expectations.
                        </li>

                        <li>
                            Evidence survivability governance remains highly defensible under projected regulatory scrutiny.
                        </li>

                        <li>
                            Dose traceability governance remains the strongest operational trust pillar.
                        </li>

                        <li>
                            CAPA stabilization governance remains the primary executive intervention focus area.
                        </li>

                        <li>
                            Cold-chain continuity governance remains commercially stable across treatment distribution pathways.
                        </li>

                        <li>
                            Boardroom orchestration cognition remains synchronized with enterprise commercialization objectives.
                        </li>

                    </ul>

                </section>

                <section class="panel">

                    <h2>Boardroom Governance Matrix</h2>

                    <table>

                        <thead>

                            <tr>
                                <th>Pillar</th>
                                <th>Owner</th>
                                <th>State</th>
                                <th>Score</th>
                            </tr>

                        </thead>

                        <tbody>

                            {% for row in streams %}

                            <tr>

                                <td>{{ row.pillar }}</td>

                                <td>{{ row.owner }}</td>

                                <td>{{ row.state }}</td>

                                <td>{{ row.score }}%</td>

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
        streams=IRLT_BOARDROOM_STREAMS_V1,
        boardroom_score=boardroom_score
    )


@app.route("/irlt-commercial-readiness/boardroom/api")
def irlt_boardroom_orchestration_api():

    return jsonify({
        "boardroom_score": round(
            sum(x["score"] for x in IRLT_BOARDROOM_STREAMS_V1)
            / len(IRLT_BOARDROOM_STREAMS_V1)
        ),
        "streams": IRLT_BOARDROOM_STREAMS_V1
    })

# ============================================================
# END IRLT_BOARDROOM_ORCHESTRATION_ENGINE_V1
# ============================================================

"""

text = text.replace(anchor, anchor + block)

APP.write_text(text, encoding="utf-8")

print("Boardroom Orchestration Engine inserted successfully.")
