from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "GOVERNANCE_RECOVERY_RESILIENCE_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Recovery Resilience Engine already exists.")
    raise SystemExit()

if 'def governance_recovery_resilience_engine_v1(' in text:
    print("Function already exists.")
    raise SystemExit()

INSERT = r"""

# ============================================================
# GOVERNANCE_RECOVERY_RESILIENCE_ENGINE_V1_ACTIVE
# ============================================================

from flask import jsonify

RECOVERY_RESILIENCE_SCENARIOS_V1 = [
    {
        "system": "Radiopharma Manufacturing",
        "rto": "4 Hours",
        "rpo": "15 Minutes",
        "readiness": 92,
        "status": "Recoverable",
        "risk": "Low"
    },
    {
        "system": "Environmental Monitoring",
        "rto": "2 Hours",
        "rpo": "5 Minutes",
        "readiness": 88,
        "status": "Monitoring",
        "risk": "Medium"
    },
    {
        "system": "Dose Coordination",
        "rto": "1 Hour",
        "rpo": "5 Minutes",
        "readiness": 91,
        "status": "Stable",
        "risk": "Low"
    },
    {
        "system": "Backup Governance",
        "rto": "6 Hours",
        "rpo": "30 Minutes",
        "readiness": 82,
        "status": "Attention",
        "risk": "Medium"
    },
    {
        "system": "Release Governance",
        "rto": "3 Hours",
        "rpo": "10 Minutes",
        "readiness": 90,
        "status": "Controlled",
        "risk": "Low"
    }
]


def calculate_recovery_resilience_score_v1():

    total = 0

    for row in RECOVERY_RESILIENCE_SCENARIOS_V1:
        total += row["readiness"]

    return round(total / len(RECOVERY_RESILIENCE_SCENARIOS_V1))


@app.route("/governance/recovery-resilience")
def governance_recovery_resilience_engine_v1():

    resilience_score = calculate_recovery_resilience_score_v1()

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Governance Recovery and Resilience Engine</title>

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
                padding:26px;
                border-radius:22px;
                background:rgba(255,255,255,0.04);
            }

            .overall strong {
                display:block;
                font-size:130px;
                color:#ff9f1c;
            }

            .resilience-grid {
                display:grid;
                grid-template-columns:repeat(2,1fr);
                gap:22px;
                margin-top:24px;
            }

            .resilience-card {
                border-radius:22px;
                padding:24px;
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02)),
                    rgba(255,255,255,0.03);
                border:1px solid rgba(255,255,255,0.08);
            }

            .resilience-card strong {
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

            ul li {
                margin-bottom:14px;
                color:#c6cfdb;
            }

            @media (max-width:1200px) {

                .resilience-grid {
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

                <h1>Governance Recovery and Resilience Engine</h1>

                <p>
                    Operational governance survivability and recovery orchestration
                    infrastructure for GMP operations, radiopharma continuity,
                    inspection survivability, and commercialization resilience assurance.
                </p>

                <div class="overall">

                    <strong>{{ resilience_score }}%</strong>

                    Operational Recovery Resilience Score

                </div>

            </section>

            <section class="panel">

                <h2>Recovery Governance Command Center</h2>

                <div class="resilience-grid">

                    {% for row in scenarios %}

                    <div class="resilience-card">

                        <strong>{{ row.readiness }}%</strong>

                        <h3>{{ row.system }}</h3>

                        <p>
                            RTO:
                            {{ row.rto }}
                        </p>

                        <p>
                            RPO:
                            {{ row.rpo }}
                        </p>

                        <p>
                            Operational Risk:
                            {{ row.risk }}
                        </p>

                        <span class="pill">
                            {{ row.status }}
                        </span>

                    </div>

                    {% endfor %}

                </div>

            </section>

            <section class="panel">

                <h2>Recovery Governance Intelligence</h2>

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
                            <td>RTO/RPO Governance Intelligence</td>
                            <td>Track operational recovery objectives</td>
                            <td>Operational survivability</td>
                        </tr>

                        <tr>
                            <td>Dependency-Aware Recovery</td>
                            <td>Prioritize recovery based on governance dependencies</td>
                            <td>Commercialization resilience</td>
                        </tr>

                        <tr>
                            <td>Recovery Evidence Lineage</td>
                            <td>Track restoration defensibility pathways</td>
                            <td>Inspection readiness</td>
                        </tr>

                        <tr>
                            <td>Operational Restart Governance</td>
                            <td>Validate GMP restart defensibility</td>
                            <td>Operational assurance</td>
                        </tr>

                        <tr>
                            <td>Governance Survivability Modeling</td>
                            <td>Forecast resilience degradation scenarios</td>
                            <td>Executive resilience intelligence</td>
                        </tr>

                    </tbody>

                </table>

            </section>

            <section class="panel">

                <h2>Enterprise Recovery Governance Vision</h2>

                <p>
                    The Governance Recovery and Resilience Engine enables
                    operational governance survivability orchestration across
                    all COBIT-Chain AssuranceLayer operational verticals.
                </p>

                <p>
                    This architecture supports:
                </p>

                <ul>

                    <li>Recovery governance orchestration</li>

                    <li>Operational survivability intelligence</li>

                    <li>Dependency-aware recovery prioritization</li>

                    <li>Inspection survivability preservation</li>

                    <li>Commercialization continuity assurance</li>

                    <li>Operational restart defensibility</li>

                    <li>Evidence-backed recovery governance</li>

                    <li>Enterprise resilience trust intelligence</li>

                </ul>

            </section>

        </div>

    </body>

    </html>

    '''

    return render_template_string(
        html,
        scenarios=RECOVERY_RESILIENCE_SCENARIOS_V1,
        resilience_score=resilience_score
    )


@app.route("/governance/recovery-resilience/api")
def governance_recovery_resilience_api_v1():

    return jsonify({
        "resilience_score": calculate_recovery_resilience_score_v1(),
        "scenarios": RECOVERY_RESILIENCE_SCENARIOS_V1
    })

# ============================================================
# END GOVERNANCE_RECOVERY_RESILIENCE_ENGINE_V1
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

print("Inserted Governance Recovery and Resilience Engine successfully.")
