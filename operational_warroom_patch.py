from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_OPERATIONAL_WARROOM_COMMAND_CENTER_V1_ACTIVE"

if MARKER in text:
    print("Operational Warroom already exists.")
    raise SystemExit()

anchor = "# END IRLT_RELEASE_DEFENSIBILITY_COMMAND_ENGINE_V1"

if anchor not in text:
    print("Could not locate safe insertion anchor.")
    raise SystemExit()

block = r"""

# ============================================================
# IRLT_OPERATIONAL_WARROOM_COMMAND_CENTER_V1_ACTIVE
# ============================================================

IRLT_WARROOM_STREAMS_V1 = [
    {
        "stream": "Commercial Release",
        "status": "Stable",
        "severity": "Low",
        "score": 95
    },
    {
        "stream": "Environmental Monitoring",
        "status": "Observed",
        "severity": "Moderate",
        "score": 84
    },
    {
        "stream": "CAPA Escalation",
        "status": "Pressure",
        "severity": "Elevated",
        "score": 79
    },
    {
        "stream": "Dose Lineage Integrity",
        "status": "Verified",
        "severity": "Low",
        "score": 97
    },
    {
        "stream": "Cold Chain Governance",
        "status": "Controlled",
        "severity": "Low",
        "score": 91
    },
    {
        "stream": "Inspection Readiness",
        "status": "Strong",
        "severity": "Low",
        "score": 94
    }
]


@app.route("/irlt-commercial-readiness/warroom")
def irlt_operational_warroom():

    warroom_score = round(
        sum(x["score"] for x in IRLT_WARROOM_STREAMS_V1)
        / len(IRLT_WARROOM_STREAMS_V1)
    )

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Operational Warroom Command Center</title>

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

            .alert{
                margin-top:16px;
                padding:16px;
                border-radius:16px;
                background:rgba(255,255,255,0.04);
                border-left:5px solid orange;
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

                <h1>Operational Warroom</h1>

                <p>
                    Enterprise commercialization command center for
                    radiopharma operational escalation visibility,
                    inspection survivability monitoring,
                    governance stabilization coordination,
                    and operational trust defense orchestration.
                </p>

                <div class="hero-grid">

                    <div class="panel">

                        <h2>Operational Governance Streams</h2>

                        <div class="grid">

                            {% for row in streams %}

                            <div class="card">

                                <strong>{{ row.score }}%</strong>

                                {{ row.stream }}

                                <br>

                                <span class="pill">
                                    {{ row.status }}
                                </span>

                                <span class="pill">
                                    {{ row.severity }}
                                </span>

                            </div>

                            {% endfor %}

                        </div>

                    </div>

                    <div class="overall">

                        <strong>{{ warroom_score }}%</strong>

                        Operational Stability

                    </div>

                </div>

            </section>

            <div class="ops-grid">

                <section class="panel">

                    <h2>Active Governance Escalations</h2>

                    <div class="alert">
                        CAPA closure acceleration required for inspection stability preservation.
                    </div>

                    <div class="alert">
                        Environmental monitoring governance requires enhanced observation review.
                    </div>

                    <div class="alert">
                        Commercial release governance remains operationally stable.
                    </div>

                    <div class="alert">
                        Dose lineage survivability remains highly defensible.
                    </div>

                </section>

                <section class="panel">

                    <h2>Warroom Governance Matrix</h2>

                    <table>

                        <thead>

                            <tr>
                                <th>Operational Stream</th>
                                <th>Status</th>
                                <th>Severity</th>
                                <th>Score</th>
                            </tr>

                        </thead>

                        <tbody>

                            {% for row in streams %}

                            <tr>

                                <td>{{ row.stream }}</td>

                                <td>{{ row.status }}</td>

                                <td>{{ row.severity }}</td>

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
        streams=IRLT_WARROOM_STREAMS_V1,
        warroom_score=warroom_score
    )


@app.route("/irlt-commercial-readiness/warroom/api")
def irlt_operational_warroom_api():

    return jsonify({
        "warroom_score": round(
            sum(x["score"] for x in IRLT_WARROOM_STREAMS_V1)
            / len(IRLT_WARROOM_STREAMS_V1)
        ),
        "streams": IRLT_WARROOM_STREAMS_V1
    })

# ============================================================
# END IRLT_OPERATIONAL_WARROOM_COMMAND_CENTER_V1
# ============================================================

"""

text = text.replace(anchor, anchor + block)

APP.write_text(text, encoding="utf-8")

print("Operational Warroom Command Center inserted successfully.")
