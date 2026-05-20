from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "EXECUTIVE_GOVERNANCE_DECISION_INTELLIGENCE_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Executive Governance Decision Intelligence already exists.")
    raise SystemExit()

if 'def executive_governance_decision_intelligence_v1(' in text:
    print("Function already exists.")
    raise SystemExit()

INSERT = r"""

# ============================================================
# EXECUTIVE_GOVERNANCE_DECISION_INTELLIGENCE_ENGINE_V1_ACTIVE
# ============================================================

from flask import jsonify

EXECUTIVE_PRIORITY_QUEUE_V1 = [
    {
        "priority": 1,
        "risk": "Environmental Governance Escalation",
        "impact": "Release Defensibility",
        "severity": "Critical",
        "recommended_action": "Accelerate environmental review governance resolution.",
        "executive_pressure": 96
    },
    {
        "priority": 2,
        "risk": "CAPA Closure Backlog",
        "impact": "Inspection Survivability",
        "severity": "High",
        "recommended_action": "Escalate unresolved CAPA remediation workflow.",
        "executive_pressure": 92
    },
    {
        "priority": 3,
        "risk": "Backup Governance Drift",
        "impact": "Audit Survivability",
        "severity": "Medium",
        "recommended_action": "Validate operational restoration defensibility.",
        "executive_pressure": 84
    },
    {
        "priority": 4,
        "risk": "Training Recertification Window",
        "impact": "Operational Readiness",
        "severity": "Medium",
        "recommended_action": "Increase recertification governance cadence.",
        "executive_pressure": 80
    },
    {
        "priority": 5,
        "risk": "Shipment Coordination Delay",
        "impact": "Treatment Coordination",
        "severity": "Low",
        "recommended_action": "Maintain coordination governance monitoring.",
        "executive_pressure": 73
    }
]


def calculate_executive_decision_score_v1():

    total = 0

    for row in EXECUTIVE_PRIORITY_QUEUE_V1:
        total += row["executive_pressure"]

    return round(total / len(EXECUTIVE_PRIORITY_QUEUE_V1))


@app.route("/governance/executive-decision-intelligence")
def executive_governance_decision_intelligence_v1():

    executive_score = calculate_executive_decision_score_v1()

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Executive Governance Decision Intelligence</title>

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

            .decision-grid {
                display:grid;
                grid-template-columns:repeat(2,1fr);
                gap:22px;
                margin-top:24px;
            }

            .decision-card {
                border-radius:22px;
                padding:24px;
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02)),
                    rgba(255,255,255,0.03);
                border:1px solid rgba(255,255,255,0.08);
            }

            .decision-card strong {
                display:block;
                font-size:42px;
                color:#ff9f1c;
                margin-bottom:14px;
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
                margin-top:14px;
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

                .decision-grid {
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

                <h1>Executive Governance Decision Intelligence</h1>

                <p>
                    Executive operational governance prioritization infrastructure
                    for commercialization readiness, inspection survivability,
                    governance escalation ranking, and operational decision intelligence.
                </p>

                <div class="overall">

                    <strong>{{ executive_score }}%</strong>

                    Executive Governance Pressure Index

                </div>

            </section>

            <section class="panel">

                <h2>Executive Governance Priority Queue</h2>

                <div class="decision-grid">

                    {% for row in priorities %}

                    <div class="decision-card">

                        <strong>#{{ row.priority }}</strong>

                        <h3>{{ row.risk }}</h3>

                        <p>
                            Impact Area:
                            {{ row.impact }}
                        </p>

                        <p>
                            Executive Recommendation:
                            {{ row.recommended_action }}
                        </p>

                        <p>
                            Executive Pressure:
                            {{ row.executive_pressure }}%
                        </p>

                        <span class="pill">
                            Severity: {{ row.severity }}
                        </span>

                    </div>

                    {% endfor %}

                </div>

            </section>

            <section class="panel">

                <h2>Executive Governance Intelligence Matrix</h2>

                <table>

                    <thead>

                        <tr>
                            <th>Capability</th>
                            <th>Purpose</th>
                            <th>Executive Value</th>
                        </tr>

                    </thead>

                    <tbody>

                        <tr>
                            <td>Governance Prioritization</td>
                            <td>Rank operational governance threats</td>
                            <td>Executive decision clarity</td>
                        </tr>

                        <tr>
                            <td>Commercialization Threat Intelligence</td>
                            <td>Identify readiness destabilization risks</td>
                            <td>Commercialization protection</td>
                        </tr>

                        <tr>
                            <td>Inspection Risk Ranking</td>
                            <td>Prioritize inspection survivability threats</td>
                            <td>Audit defensibility</td>
                        </tr>

                        <tr>
                            <td>Operational Pressure Analysis</td>
                            <td>Measure governance instability pressure</td>
                            <td>Operational resilience</td>
                        </tr>

                        <tr>
                            <td>Governance Stabilization Sequencing</td>
                            <td>Recommend remediation ordering</td>
                            <td>Executive orchestration</td>
                        </tr>

                    </tbody>

                </table>

            </section>

            <section class="panel">

                <h2>Enterprise Governance Decision Vision</h2>

                <p>
                    Executive Governance Decision Intelligence enables operational
                    governance prioritization across all COBIT-Chain AssuranceLayer
                    operational verticals.
                </p>

                <p>
                    This architecture supports:
                </p>

                <ul>

                    <li>Executive governance prioritization</li>

                    <li>Commercialization risk intelligence</li>

                    <li>Operational pressure visibility</li>

                    <li>Governance escalation ranking</li>

                    <li>Release defensibility prioritization</li>

                    <li>Inspection survivability intelligence</li>

                    <li>Governance stabilization orchestration</li>

                    <li>Executive operational trust preservation</li>

                </ul>

            </section>

        </div>

    </body>

    </html>

    '''

    return render_template_string(
        html,
        priorities=EXECUTIVE_PRIORITY_QUEUE_V1,
        executive_score=executive_score
    )


@app.route("/governance/executive-decision-intelligence/api")
def executive_governance_decision_intelligence_api_v1():

    return jsonify({
        "executive_score": calculate_executive_decision_score_v1(),
        "priorities": EXECUTIVE_PRIORITY_QUEUE_V1
    })

# ============================================================
# END EXECUTIVE_GOVERNANCE_DECISION_INTELLIGENCE_ENGINE_V1
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

print("Inserted Executive Governance Decision Intelligence successfully.")
