from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "GOVERNANCE_DIGITAL_TWIN_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Governance Digital Twin Engine already exists.")
    raise SystemExit()

if 'def governance_digital_twin_engine_v1(' in text:
    print("Function already exists.")
    raise SystemExit()

INSERT = r"""

# ============================================================
# GOVERNANCE_DIGITAL_TWIN_ENGINE_V1_ACTIVE
# ============================================================

from flask import jsonify

DIGITAL_TWIN_SCENARIOS_V1 = [
    {
        "scenario": "Inspection Disruption",
        "projected_score": 81,
        "impact": "Inspection Survivability",
        "severity": "High",
        "recommendation": "Accelerate CAPA remediation and evidence reconciliation."
    },
    {
        "scenario": "Environmental Monitoring Drift",
        "projected_score": 84,
        "impact": "Release Defensibility",
        "severity": "Medium",
        "recommendation": "Increase environmental governance review cadence."
    },
    {
        "scenario": "Training Readiness Degradation",
        "projected_score": 86,
        "impact": "Operational Readiness",
        "severity": "Medium",
        "recommendation": "Escalate recertification governance workflow."
    },
    {
        "scenario": "Backup Governance Failure",
        "projected_score": 78,
        "impact": "Audit Defensibility",
        "severity": "High",
        "recommendation": "Initiate recovery governance validation immediately."
    },
    {
        "scenario": "Shipment Coordination Failure",
        "projected_score": 80,
        "impact": "Treatment Coordination",
        "severity": "High",
        "recommendation": "Activate operational continuity escalation pathway."
    }
]


def calculate_digital_twin_resilience_v1():

    total = 0

    for row in DIGITAL_TWIN_SCENARIOS_V1:
        total += row["projected_score"]

    return round(total / len(DIGITAL_TWIN_SCENARIOS_V1))


@app.route("/governance/digital-twin")
def governance_digital_twin_engine_v1():

    resilience_score = calculate_digital_twin_resilience_v1()

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Governance Digital Twin Engine</title>

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
                max-width:1950px;
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
                font-size:76px;
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

            .scenario-grid {
                display:grid;
                grid-template-columns:repeat(2,1fr);
                gap:22px;
                margin-top:24px;
            }

            .scenario-card {
                border-radius:22px;
                padding:24px;
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02)),
                    rgba(255,255,255,0.03);
                border:1px solid rgba(255,255,255,0.08);
            }

            .scenario-card strong {
                display:block;
                font-size:34px;
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

            @media (max-width:1200px) {

                .scenario-grid {
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

                <h1>Governance Digital Twin Engine</h1>

                <p>
                    Predictive operational governance simulation infrastructure
                    for commercialization readiness, inspection survivability,
                    governance stress testing, and operational resilience forecasting.
                </p>

                <div class="overall">

                    <strong>{{ resilience_score }}%</strong>

                    Governance Resilience Forecast

                </div>

            </section>

            <section class="panel">

                <h2>Operational Governance Simulation Scenarios</h2>

                <div class="scenario-grid">

                    {% for row in scenarios %}

                    <div class="scenario-card">

                        <strong>{{ row.projected_score }}%</strong>

                        <h3>{{ row.scenario }}</h3>

                        <p>
                            Impact Area:
                            {{ row.impact }}
                        </p>

                        <p>
                            {{ row.recommendation }}
                        </p>

                        <span class="pill">
                            Severity: {{ row.severity }}
                        </span>

                    </div>

                    {% endfor %}

                </div>

            </section>

            <section class="panel">

                <h2>Governance Simulation Intelligence</h2>

                <table>

                    <thead>

                        <tr>
                            <th>Simulation Area</th>
                            <th>Purpose</th>
                            <th>Strategic Value</th>
                        </tr>

                    </thead>

                    <tbody>

                        <tr>
                            <td>Inspection Stress Simulation</td>
                            <td>Forecast inspection survivability degradation</td>
                            <td>Inspection defensibility</td>
                        </tr>

                        <tr>
                            <td>Operational Readiness Modeling</td>
                            <td>Predict readiness degradation pathways</td>
                            <td>Commercialization resilience</td>
                        </tr>

                        <tr>
                            <td>Dependency Cascade Simulation</td>
                            <td>Model governance blast radius propagation</td>
                            <td>Operational foresight</td>
                        </tr>

                        <tr>
                            <td>Release Governance Forecasting</td>
                            <td>Predict release defensibility degradation</td>
                            <td>Operational assurance</td>
                        </tr>

                        <tr>
                            <td>Governance Recovery Prioritization</td>
                            <td>Recommend stabilization actions</td>
                            <td>Executive orchestration</td>
                        </tr>

                    </tbody>

                </table>

            </section>

            <section class="panel">

                <h2>Enterprise Governance Foresight Vision</h2>

                <p>
                    The Governance Digital Twin Engine enables predictive operational
                    governance intelligence across all COBIT-Chain AssuranceLayer verticals.
                </p>

                <p>
                    This architecture supports:
                </p>

                <ul>

                    <li>Governance stress testing</li>

                    <li>Operational survivability forecasting</li>

                    <li>Dependency cascade simulation</li>

                    <li>Inspection disruption modeling</li>

                    <li>Commercialization resilience analysis</li>

                    <li>Governance stabilization prioritization</li>

                    <li>Predictive operational trust intelligence</li>

                    <li>Executive governance foresight orchestration</li>

                </ul>

            </section>

        </div>

    </body>

    </html>

    '''

    return render_template_string(
        html,
        scenarios=DIGITAL_TWIN_SCENARIOS_V1,
        resilience_score=resilience_score
    )


@app.route("/governance/digital-twin/api")
def governance_digital_twin_engine_api_v1():

    return jsonify({
        "resilience_score": calculate_digital_twin_resilience_v1(),
        "scenarios": DIGITAL_TWIN_SCENARIOS_V1
    })

# ============================================================
# END GOVERNANCE_DIGITAL_TWIN_ENGINE_V1
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

print("Inserted Governance Digital Twin Engine successfully.")
