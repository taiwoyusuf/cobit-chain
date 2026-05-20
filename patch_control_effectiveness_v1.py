from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "GOVERNANCE_CONTROL_EFFECTIVENESS_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Governance Control Effectiveness Engine already exists.")
    raise SystemExit()

if 'def governance_control_effectiveness_engine_v1(' in text:
    print("Function already exists.")
    raise SystemExit()

INSERT = r"""

# ============================================================
# GOVERNANCE_CONTROL_EFFECTIVENESS_ENGINE_V1_ACTIVE
# ============================================================

from flask import jsonify

CONTROL_EFFECTIVENESS_REGISTRY_V1 = [
    {
        "control_id": "CTRL-IRLT-001",
        "control_name": "Environmental Monitoring Governance",
        "effectiveness": 92,
        "drift": "Stable",
        "inspection_status": "Defensible",
        "risk": "Low"
    },
    {
        "control_id": "CTRL-IRLT-002",
        "control_name": "CAPA Escalation Governance",
        "effectiveness": 84,
        "drift": "Monitoring",
        "inspection_status": "Attention",
        "risk": "Medium"
    },
    {
        "control_id": "CTRL-IRLT-003",
        "control_name": "Backup Governance Validation",
        "effectiveness": 81,
        "drift": "Degrading",
        "inspection_status": "Review",
        "risk": "Medium"
    },
    {
        "control_id": "CTRL-IRLT-004",
        "control_name": "Release Defensibility Control",
        "effectiveness": 94,
        "drift": "Stable",
        "inspection_status": "Operationally Defensible",
        "risk": "Low"
    },
    {
        "control_id": "CTRL-IRLT-005",
        "control_name": "Treatment Coordination Governance",
        "effectiveness": 89,
        "drift": "Stable",
        "inspection_status": "Controlled",
        "risk": "Low"
    }
]


def calculate_control_effectiveness_score_v1():

    total = 0

    for row in CONTROL_EFFECTIVENESS_REGISTRY_V1:
        total += row["effectiveness"]

    return round(total / len(CONTROL_EFFECTIVENESS_REGISTRY_V1))


@app.route("/governance/control-effectiveness")
def governance_control_effectiveness_engine_v1():

    effectiveness_score = calculate_control_effectiveness_score_v1()

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Governance Control Effectiveness Engine</title>

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

            .control-grid {
                display:grid;
                grid-template-columns:repeat(2,1fr);
                gap:22px;
                margin-top:24px;
            }

            .control-card {
                border-radius:22px;
                padding:24px;
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02)),
                    rgba(255,255,255,0.03);
                border:1px solid rgba(255,255,255,0.08);
            }

            .control-card strong {
                display:block;
                font-size:38px;
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

                .control-grid {
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

                <h1>Governance Control Effectiveness Engine</h1>

                <p>
                    Operational governance control intelligence infrastructure
                    for control survivability, governance drift detection,
                    inspection defensibility, and commercialization readiness assurance.
                </p>

                <div class="overall">

                    <strong>{{ effectiveness_score }}%</strong>

                    Governance Control Effectiveness Score

                </div>

            </section>

            <section class="panel">

                <h2>Governance Control Intelligence Registry</h2>

                <div class="control-grid">

                    {% for row in controls %}

                    <div class="control-card">

                        <strong>{{ row.effectiveness }}%</strong>

                        <h3>{{ row.control_name }}</h3>

                        <p>
                            Control ID:
                            {{ row.control_id }}
                        </p>

                        <p>
                            Operational Risk:
                            {{ row.risk }}
                        </p>

                        <span class="pill">
                            Drift: {{ row.drift }}
                        </span>

                        <span class="pill">
                            {{ row.inspection_status }}
                        </span>

                    </div>

                    {% endfor %}

                </div>

            </section>

            <section class="panel">

                <h2>Governance Control Intelligence Matrix</h2>

                <table>

                    <thead>

                        <tr>
                            <th>Capability</th>
                            <th>Purpose</th>
                            <th>Strategic Value</th>
                        </tr>

                    </thead>

                    <tbody>

                        <tr>
                            <td>Control Effectiveness Scoring</td>
                            <td>Measure operational governance control strength</td>
                            <td>Operational defensibility</td>
                        </tr>

                        <tr>
                            <td>Governance Drift Detection</td>
                            <td>Detect weakening governance controls</td>
                            <td>Inspection survivability</td>
                        </tr>

                        <tr>
                            <td>Control Dependency Intelligence</td>
                            <td>Map operational control relationships</td>
                            <td>Commercialization resilience</td>
                        </tr>

                        <tr>
                            <td>Governance Stabilization Recommendations</td>
                            <td>Recommend control hardening actions</td>
                            <td>Executive governance orchestration</td>
                        </tr>

                        <tr>
                            <td>Operational Control Survivability</td>
                            <td>Assess long-term governance stability</td>
                            <td>Enterprise trust assurance</td>
                        </tr>

                    </tbody>

                </table>

            </section>

            <section class="panel">

                <h2>Enterprise Governance Control Vision</h2>

                <p>
                    The Governance Control Effectiveness Engine enables
                    operational governance control intelligence across all
                    COBIT-Chain AssuranceLayer operational verticals.
                </p>

                <p>
                    This architecture supports:
                </p>

                <ul>

                    <li>Governance control survivability</li>

                    <li>Operational drift detection</li>

                    <li>Inspection control defensibility</li>

                    <li>Control dependency intelligence</li>

                    <li>Commercialization readiness stabilization</li>

                    <li>Governance hardening orchestration</li>

                    <li>Operational control trust preservation</li>

                    <li>Enterprise governance resilience intelligence</li>

                </ul>

            </section>

        </div>

    </body>

    </html>

    '''

    return render_template_string(
        html,
        controls=CONTROL_EFFECTIVENESS_REGISTRY_V1,
        effectiveness_score=effectiveness_score
    )


@app.route("/governance/control-effectiveness/api")
def governance_control_effectiveness_api_v1():

    return jsonify({
        "effectiveness_score": calculate_control_effectiveness_score_v1(),
        "controls": CONTROL_EFFECTIVENESS_REGISTRY_V1
    })

# ============================================================
# END GOVERNANCE_CONTROL_EFFECTIVENESS_ENGINE_V1
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

print("Inserted Governance Control Effectiveness Engine successfully.")
