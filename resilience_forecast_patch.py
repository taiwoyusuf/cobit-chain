from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_GOVERNANCE_RESILIENCE_FORECAST_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Resilience Forecast Engine already exists.")
    raise SystemExit()

anchor = "# END IRLT_GOVERNANCE_SINGULARITY_LAYER_V2"

if anchor not in text:
    print("Could not locate safe insertion anchor.")
    raise SystemExit()

block = r"""

# ============================================================
# IRLT_GOVERNANCE_RESILIENCE_FORECAST_ENGINE_V1_ACTIVE
# ============================================================

IRLT_RESILIENCE_FORECAST_V1 = [
    {
        "domain": "Operational Trust",
        "current": 92,
        "forecast": 89,
        "state": "Stable"
    },
    {
        "domain": "Inspection Survivability",
        "current": 95,
        "forecast": 93,
        "state": "Strong"
    },
    {
        "domain": "Commercialization Readiness",
        "current": 91,
        "forecast": 87,
        "state": "Controlled"
    },
    {
        "domain": "CAPA Stability",
        "current": 82,
        "forecast": 76,
        "state": "Pressure"
    },
    {
        "domain": "Environmental Monitoring",
        "current": 88,
        "forecast": 83,
        "state": "Monitoring"
    },
    {
        "domain": "Governance Integrity",
        "current": 93,
        "forecast": 91,
        "state": "Aligned"
    }
]


@app.route("/irlt-commercial-readiness/resilience-forecast")
def irlt_resilience_forecast():

    current_avg = round(
        sum(x["current"] for x in IRLT_RESILIENCE_FORECAST_V1)
        / len(IRLT_RESILIENCE_FORECAST_V1)
    )

    forecast_avg = round(
        sum(x["forecast"] for x in IRLT_RESILIENCE_FORECAST_V1)
        / len(IRLT_RESILIENCE_FORECAST_V1)
    )

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Governance Resilience Forecast Engine</title>

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

            .forecast-bar{
                height:12px;
                border-radius:999px;
                background:rgba(255,255,255,0.08);
                overflow:hidden;
                margin-top:8px;
            }

            .forecast-fill{
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

                <h1>Governance Resilience Forecast</h1>

                <p>
                    Enterprise governance resilience forecasting engine for
                    commercialization readiness sustainability, inspection survivability,
                    operational trust durability, governance drift forecasting,
                    and future operational defensibility modeling.
                </p>

                <div class="hero-grid">

                    <div class="panel">

                        <h2>Governance Resilience Domains</h2>

                        <div class="grid">

                            {% for row in forecast %}

                            <div class="card">

                                <strong>{{ row.forecast }}%</strong>

                                {{ row.domain }}

                                <div class="forecast-bar">

                                    <div class="forecast-fill"
                                         style="width:{{ row.forecast }}%">
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

                        <strong>{{ forecast_avg }}%</strong>

                        Forecast Governance Resilience

                        <br><br>

                        Current State: {{ current_avg }}%

                    </div>

                </div>

            </section>

            <div class="ops-grid">

                <section class="panel">

                    <h2>Commercialization Resilience Forecast</h2>

                    <ul>

                        <li>
                            Operational trust resilience remains stable under projected commercialization pressure.
                        </li>

                        <li>
                            Inspection survivability posture remains highly defensible over the forecast horizon.
                        </li>

                        <li>
                            CAPA accumulation pressure remains the highest projected destabilization vector.
                        </li>

                        <li>
                            Environmental monitoring governance may experience moderate resilience degradation under scale-up conditions.
                        </li>

                        <li>
                            Governance integrity posture remains operationally aligned across enterprise readiness pathways.
                        </li>

                        <li>
                            Commercialization readiness sustainability remains within enterprise governance tolerance thresholds.
                        </li>

                    </ul>

                </section>

                <section class="panel">

                    <h2>Governance Sustainability Matrix</h2>

                    <table>

                        <thead>

                            <tr>
                                <th>Governance Domain</th>
                                <th>Current</th>
                                <th>Forecast</th>
                                <th>State</th>
                            </tr>

                        </thead>

                        <tbody>

                            {% for row in forecast %}

                            <tr>

                                <td>{{ row.domain }}</td>

                                <td>{{ row.current }}%</td>

                                <td>{{ row.forecast }}%</td>

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
        forecast=IRLT_RESILIENCE_FORECAST_V1,
        current_avg=current_avg,
        forecast_avg=forecast_avg
    )


@app.route("/irlt-commercial-readiness/resilience-forecast/api")
def irlt_resilience_forecast_api():

    return jsonify({
        "forecast": IRLT_RESILIENCE_FORECAST_V1,
        "forecast_average": round(
            sum(x["forecast"] for x in IRLT_RESILIENCE_FORECAST_V1)
            / len(IRLT_RESILIENCE_FORECAST_V1)
        )
    })

# ============================================================
# END IRLT_GOVERNANCE_RESILIENCE_FORECAST_ENGINE_V1
# ============================================================

"""

text = text.replace(anchor, anchor + block)

APP.write_text(text, encoding="utf-8")

print("Governance Resilience Forecast Engine inserted successfully.")
