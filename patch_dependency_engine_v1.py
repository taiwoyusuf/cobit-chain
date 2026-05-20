from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "SHARED_DEPENDENCY_PROPAGATION_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Dependency Propagation Engine already exists.")
    raise SystemExit()

if 'def governance_dependency_propagation_engine_v1(' in text:
    print("Function already exists.")
    raise SystemExit()

INSERT = r"""

# ============================================================
# SHARED_DEPENDENCY_PROPAGATION_ENGINE_V1_ACTIVE
# ============================================================

from flask import jsonify

DEPENDENCY_PROPAGATION_DATA_V1 = [
    {
        "trigger": "CAPA Closure Delay",
        "impacted_area": "Inspection Survivability",
        "severity": "High",
        "trust_impact": -7,
        "status": "Escalated"
    },
    {
        "trigger": "Environmental Monitoring Review Delay",
        "impacted_area": "Release Defensibility",
        "severity": "Medium",
        "trust_impact": -5,
        "status": "Monitoring"
    },
    {
        "trigger": "Training Recertification Gap",
        "impacted_area": "Operational Readiness",
        "severity": "Medium",
        "trust_impact": -4,
        "status": "Controlled"
    },
    {
        "trigger": "Shipment Coordination Failure",
        "impacted_area": "Treatment Coordination",
        "severity": "High",
        "trust_impact": -8,
        "status": "Escalated"
    },
    {
        "trigger": "Backup Governance Drift",
        "impacted_area": "Audit Defensibility",
        "severity": "Low",
        "trust_impact": -2,
        "status": "Review"
    }
]


def calculate_dependency_engine_score_v1():

    base_score = 100

    for row in DEPENDENCY_PROPAGATION_DATA_V1:
        base_score += row["trust_impact"]

    if base_score < 0:
        base_score = 0

    return round(base_score)


@app.route("/governance/dependency-propagation-engine")
def governance_dependency_propagation_engine_v1():

    overall_score = calculate_dependency_engine_score_v1()

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Dependency Propagation Engine</title>

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
                max-width:1900px;
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
                font-size:72px;
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
                padding:24px;
                border-radius:22px;
                background:rgba(255,255,255,0.04);
            }

            .overall strong {
                display:block;
                font-size:120px;
                color:#ff9f1c;
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

            .pill {
                display:inline-block;
                padding:7px 12px;
                border-radius:999px;
                background:rgba(255,122,24,0.12);
                border:1px solid rgba(255,122,24,0.24);
                color:#ffd7ad;
                font-size:12px;
                font-weight:800;
            }

            .flow-grid {
                display:grid;
                grid-template-columns:repeat(3,1fr);
                gap:20px;
                margin-top:24px;
            }

            .flow-card {
                border-radius:22px;
                padding:24px;
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02)),
                    rgba(255,255,255,0.03);
                border:1px solid rgba(255,255,255,0.08);
            }

            .flow-card strong {
                display:block;
                font-size:34px;
                color:#ff9f1c;
                margin-bottom:10px;
            }

            @media (max-width:1200px) {

                .flow-grid {
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

                <h1>Dependency Propagation Engine</h1>

                <p>
                    Enterprise governance dependency reasoning and operational
                    blast radius intelligence engine for commercialization readiness,
                    inspection survivability, and operational trust assurance.
                </p>

                <div class="overall">

                    <strong>{{ overall_score }}%</strong>

                    Dependency Governance Stability Score

                </div>

            </section>

            <section class="panel">

                <h2>Governance Blast Radius Intelligence</h2>

                <table>

                    <thead>

                        <tr>
                            <th>Trigger Event</th>
                            <th>Impacted Area</th>
                            <th>Severity</th>
                            <th>Trust Impact</th>
                            <th>Status</th>
                        </tr>

                    </thead>

                    <tbody>

                        {% for row in dependencies %}

                        <tr>

                            <td>{{ row.trigger }}</td>

                            <td>{{ row.impacted_area }}</td>

                            <td>{{ row.severity }}</td>

                            <td>{{ row.trust_impact }}</td>

                            <td>

                                <span class="pill">
                                    {{ row.status }}
                                </span>

                            </td>

                        </tr>

                        {% endfor %}

                    </tbody>

                </table>

            </section>

            <section class="panel">

                <h2>Operational Governance Propagation Flows</h2>

                <div class="flow-grid">

                    <div class="flow-card">

                        <strong>Inspection Survivability</strong>

                        CAPA closure delays propagate into inspection readiness,
                        evidence defensibility, and operational trust posture.

                    </div>

                    <div class="flow-card">

                        <strong>Release Defensibility</strong>

                        Environmental review gaps propagate into release governance
                        and commercialization readiness degradation.

                    </div>

                    <div class="flow-card">

                        <strong>Operational Readiness</strong>

                        Training and coordination failures propagate into treatment
                        continuity and operational governance instability.

                    </div>

                </div>

            </section>

            <section class="panel">

                <h2>Enterprise Governance Intelligence Vision</h2>

                <p>
                    The Dependency Propagation Engine enables explainable governance
                    reasoning across all AssuranceLayer operational verticals.
                </p>

                <p>
                    This architecture supports:
                </p>

                <ul>

                    <li>Operational blast radius analysis</li>

                    <li>Governance dependency intelligence</li>

                    <li>Inspection survivability modeling</li>

                    <li>Commercialization readiness impact analysis</li>

                    <li>Cross-domain trust degradation reasoning</li>

                    <li>Executive escalation orchestration</li>

                    <li>Dependency-aware operational trust scoring</li>

                    <li>Governance propagation intelligence APIs</li>

                </ul>

            </section>

        </div>

    </body>

    </html>

    '''

    return render_template_string(
        html,
        dependencies=DEPENDENCY_PROPAGATION_DATA_V1,
        overall_score=overall_score
    )


@app.route("/governance/dependency-propagation-engine/api")
def governance_dependency_propagation_engine_api_v1():

    return jsonify({
        "overall_score": calculate_dependency_engine_score_v1(),
        "dependencies": DEPENDENCY_PROPAGATION_DATA_V1
    })

# ============================================================
# END SHARED_DEPENDENCY_PROPAGATION_ENGINE_V1
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

print("Inserted Dependency Propagation Engine successfully.")
