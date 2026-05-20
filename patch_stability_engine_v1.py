from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "AUTONOMOUS_GOVERNANCE_STABILITY_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Governance Stability Engine already exists.")
    raise SystemExit()

if 'def governance_stability_engine_v1(' in text:
    print("Function already exists.")
    raise SystemExit()

INSERT = r"""

# ============================================================
# AUTONOMOUS_GOVERNANCE_STABILITY_ENGINE_V1_ACTIVE
# ============================================================

from flask import jsonify

GOVERNANCE_STABILITY_SIGNALS_V1 = [
    {
        "signal": "Escalation Accumulation",
        "pressure": 91,
        "trend": "Increasing",
        "risk": "High",
        "forecast": "Inspection survivability degradation risk emerging."
    },
    {
        "signal": "CAPA Fatigue Indicators",
        "pressure": 84,
        "trend": "Monitoring",
        "risk": "Medium",
        "forecast": "Operational remediation velocity slowing."
    },
    {
        "signal": "Environmental Governance Strain",
        "pressure": 89,
        "trend": "Increasing",
        "risk": "High",
        "forecast": "Release defensibility destabilization possible."
    },
    {
        "signal": "Operational Coordination Pressure",
        "pressure": 78,
        "trend": "Stable",
        "risk": "Low",
        "forecast": "Commercial coordination posture remains stable."
    },
    {
        "signal": "Backup Governance Drift",
        "pressure": 82,
        "trend": "Monitoring",
        "risk": "Medium",
        "forecast": "Audit survivability resilience weakening slowly."
    }
]

STABILIZATION_RECOMMENDATIONS_V1 = [
    "Accelerate unresolved CAPA governance closure workflows.",
    "Increase environmental governance review frequency.",
    "Reduce governance escalation backlog accumulation.",
    "Strengthen operational survivability validation cadence.",
    "Expand preventive inspection readiness simulation coverage."
]


def calculate_stability_index_v1():

    total = 0

    for row in GOVERNANCE_STABILITY_SIGNALS_V1:
        total += row["pressure"]

    return round(total / len(GOVERNANCE_STABILITY_SIGNALS_V1))


@app.route("/governance/stability-engine")
def governance_stability_engine_v1():

    stability_index = calculate_stability_index_v1()

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Autonomous Governance Stability Engine</title>

        <style>

            body {
                margin:0;
                background:
                    radial-gradient(circle at top left, rgba(255,122,24,0.18), transparent 34%),
                    linear-gradient(135deg,#050608 0%,#11151f 48%,#06070b 100%);
                color:white;
                font-family:Arial,sans-serif;
            }

            .wrap {
                max-width:1980px;
                margin:auto;
                padding:34px;
            }

            .hero,.panel {
                border-radius:28px;
                padding:28px;
                margin-bottom:24px;
                border:1px solid rgba(255,255,255,0.08);
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02)),
                    rgba(20,24,33,0.88);
            }

            h1 {
                margin:0 0 12px;
                font-size:74px;
                color:#ff9f1c;
            }

            h2 {
                color:#ff9f1c;
            }

            p {
                color:#b4bcc9;
                line-height:1.7;
            }

            .overall {
                margin-top:24px;
                text-align:center;
                padding:26px;
                border-radius:22px;
                background:rgba(255,255,255,0.04);
            }

            .overall strong {
                display:block;
                font-size:130px;
                color:#ff9f1c;
            }

            .signal-grid {
                display:grid;
                grid-template-columns:repeat(2,1fr);
                gap:22px;
                margin-top:24px;
            }

            .signal-card {
                border-radius:22px;
                padding:24px;
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02)),
                    rgba(255,255,255,0.03);
                border:1px solid rgba(255,255,255,0.08);
            }

            .signal-card strong {
                display:block;
                font-size:40px;
                color:#ff9f1c;
                margin-bottom:12px;
            }

            .pill {
                display:inline-block;
                padding:7px 12px;
                border-radius:999px;
                background:rgba(255,122,24,0.12);
                border:1px solid rgba(255,122,24,0.24);
                color:#ffd7ad;
                font-size:12px;
                font-weight:800;
                margin-top:12px;
                margin-right:10px;
            }

            table {
                width:100%;
                border-collapse:collapse;
                margin-top:24px;
            }

            th,td {
                padding:14px;
                border-bottom:1px solid rgba(255,255,255,0.08);
                text-align:left;
            }

            th {
                color:#ff9f1c;
                text-transform:uppercase;
                font-size:12px;
            }

            ul li {
                margin-bottom:14px;
                color:#c6cfdb;
            }

            @media (max-width:1200px) {

                .signal-grid {
                    grid-template-columns:1fr;
                }

                h1 {
                    font-size:44px;
                }

            }

        </style>

    </head>

    <body>

        <div class="wrap">

            <section class="hero">

                <h1>Autonomous Governance Stability Engine</h1>

                <p>
                    Preventive governance stabilization intelligence infrastructure
                    for operational survivability preservation, commercialization
                    continuity protection, and governance destabilization forecasting.
                </p>

                <div class="overall">

                    <strong>{{ stability_index }}%</strong>

                    Governance Stability Pressure Index

                </div>

            </section>

            <section class="panel">

                <h2>Governance Stability Signal Network</h2>

                <div class="signal-grid">

                    {% for row in signals %}

                    <div class="signal-card">

                        <strong>{{ row.pressure }}%</strong>

                        <h3>{{ row.signal }}</h3>

                        <p>
                            Forecast:
                            {{ row.forecast }}
                        </p>

                        <span class="pill">
                            Trend: {{ row.trend }}
                        </span>

                        <span class="pill">
                            Risk: {{ row.risk }}
                        </span>

                    </div>

                    {% endfor %}

                </div>

            </section>

            <section class="panel">

                <h2>Preventive Governance Stabilization Queue</h2>

                <table>

                    <thead>

                        <tr>
                            <th>Stabilization Recommendation</th>
                            <th>Strategic Objective</th>
                        </tr>

                    </thead>

                    <tbody>

                        {% for item in recommendations %}

                        <tr>

                            <td>{{ item }}</td>

                            <td>Operational governance preservation</td>

                        </tr>

                        {% endfor %}

                    </tbody>

                </table>

            </section>

            <section class="panel">

                <h2>Preventive Governance Intelligence Vision</h2>

                <p>
                    The Autonomous Governance Stability Engine enables preventive
                    governance stabilization intelligence across all COBIT-Chain
                    AssuranceLayer operational verticals.
                </p>

                <p>
                    This architecture supports:
                </p>

                <ul>

                    <li>Governance instability forecasting</li>

                    <li>Operational survivability preservation</li>

                    <li>Escalation accumulation intelligence</li>

                    <li>Control fatigue detection</li>

                    <li>Commercialization destabilization forecasting</li>

                    <li>Preventive inspection survivability</li>

                    <li>Governance stabilization orchestration</li>

                    <li>Enterprise governance nervous system intelligence</li>

                </ul>

            </section>

        </div>

    </body>

    </html>

    '''

    return render_template_string(
        html,
        signals=GOVERNANCE_STABILITY_SIGNALS_V1,
        recommendations=STABILIZATION_RECOMMENDATIONS_V1,
        stability_index=stability_index
    )


@app.route("/governance/stability-engine/api")
def governance_stability_engine_api_v1():

    return jsonify({
        "stability_index": calculate_stability_index_v1(),
        "signals": GOVERNANCE_STABILITY_SIGNALS_V1,
        "recommendations": STABILIZATION_RECOMMENDATIONS_V1
    })

# ============================================================
# END AUTONOMOUS_GOVERNANCE_STABILITY_ENGINE_V1
# ============================================================

"""

needle = '\nif __name__ == "__main__":'

if needle not in text:
    needle = "\nif __name__ == '__main__':"

if needle not in text:
    raise RuntimeError("Could not find Flask entry point.")

text = text.replace(
    needle,
    "\n" + INSERT + "\n" + needle,
    1
)

APP.write_text(text, encoding="utf-8")

print("Inserted Autonomous Governance Stability Engine successfully.")
