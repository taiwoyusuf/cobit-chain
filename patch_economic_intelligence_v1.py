from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "GOVERNANCE_ECONOMIC_INTELLIGENCE_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Governance Economic Intelligence Engine already exists.")
    raise SystemExit()

if 'def governance_economic_intelligence_engine_v1(' in text:
    print("Function already exists.")
    raise SystemExit()

INSERT = r"""

# ============================================================
# GOVERNANCE_ECONOMIC_INTELLIGENCE_ENGINE_V1_ACTIVE
# ============================================================

from flask import jsonify

GOVERNANCE_ECONOMIC_EXPOSURE_V1 = [
    {
        "domain": "Environmental Governance Delay",
        "estimated_exposure": "$4.2M",
        "impact_area": "Commercial Batch Release",
        "severity": "Critical",
        "trend": "Increasing"
    },
    {
        "domain": "CAPA Escalation Backlog",
        "estimated_exposure": "$2.8M",
        "impact_area": "Inspection Survivability",
        "severity": "High",
        "trend": "Monitoring"
    },
    {
        "domain": "Operational Downtime Risk",
        "estimated_exposure": "$5.1M",
        "impact_area": "Treatment Coordination",
        "severity": "Critical",
        "trend": "Increasing"
    },
    {
        "domain": "Backup Governance Degradation",
        "estimated_exposure": "$1.6M",
        "impact_area": "Audit Defensibility",
        "severity": "Medium",
        "trend": "Stable"
    },
    {
        "domain": "Release Governance Disruption",
        "estimated_exposure": "$3.7M",
        "impact_area": "Commercialization Readiness",
        "severity": "High",
        "trend": "Monitoring"
    }
]

ECONOMIC_RECOMMENDATIONS_V1 = [
    "Prioritize environmental governance stabilization to reduce commercialization exposure.",
    "Reduce CAPA escalation backlog to preserve inspection survivability economics.",
    "Increase operational continuity validation for treatment coordination resilience.",
    "Expand preventive governance simulation coverage to reduce disruption costs.",
    "Strengthen release governance defensibility before commercialization scale-up."
]


def calculate_governance_economic_index_v1():

    return 91


@app.route("/governance/economic-intelligence")
def governance_economic_intelligence_engine_v1():

    economic_index = calculate_governance_economic_index_v1()

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Governance Economic Intelligence Engine</title>

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

            .economics-grid {
                display:grid;
                grid-template-columns:repeat(2,1fr);
                gap:22px;
                margin-top:24px;
            }

            .economics-card {
                border-radius:22px;
                padding:24px;
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02)),
                    rgba(255,255,255,0.03);
                border:1px solid rgba(255,255,255,0.08);
            }

            .economics-card strong {
                display:block;
                font-size:42px;
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

                .economics-grid {
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

                <h1>Governance Economic Intelligence Engine</h1>

                <p>
                    Executive governance economics and commercialization exposure
                    intelligence infrastructure for operational survivability,
                    disruption costing, remediation prioritization,
                    and commercialization resilience assurance.
                </p>

                <div class="overall">

                    <strong>{{ economic_index }}%</strong>

                    Governance Economic Resilience Index

                </div>

            </section>

            <section class="panel">

                <h2>Governance Economic Exposure Matrix</h2>

                <div class="economics-grid">

                    {% for row in exposures %}

                    <div class="economics-card">

                        <strong>{{ row.estimated_exposure }}</strong>

                        <h3>{{ row.domain }}</h3>

                        <p>
                            Impact Area:
                            {{ row.impact_area }}
                        </p>

                        <span class="pill">
                            Severity: {{ row.severity }}
                        </span>

                        <span class="pill">
                            Trend: {{ row.trend }}
                        </span>

                    </div>

                    {% endfor %}

                </div>

            </section>

            <section class="panel">

                <h2>Executive Governance Economic Stabilization Queue</h2>

                <table>

                    <thead>

                        <tr>
                            <th>Recommendation</th>
                            <th>Strategic Objective</th>
                        </tr>

                    </thead>

                    <tbody>

                        {% for item in recommendations %}

                        <tr>

                            <td>{{ item }}</td>

                            <td>Operational governance economic preservation</td>

                        </tr>

                        {% endfor %}

                    </tbody>

                </table>

            </section>

            <section class="panel">

                <h2>Enterprise Governance Economic Vision</h2>

                <p>
                    The Governance Economic Intelligence Engine enables executive
                    governance economic intelligence across all COBIT-Chain
                    AssuranceLayer operational verticals.
                </p>

                <p>
                    This architecture supports:
                </p>

                <ul>

                    <li>Governance disruption costing</li>

                    <li>Commercialization exposure intelligence</li>

                    <li>Operational downtime economics</li>

                    <li>Inspection risk financial visibility</li>

                    <li>Remediation burn-rate forecasting</li>

                    <li>Operational survivability economics</li>

                    <li>Governance ROI intelligence</li>

                    <li>Executive resilience economics orchestration</li>

                </ul>

            </section>

        </div>

    </body>

    </html>

    '''

    return render_template_string(
        html,
        exposures=GOVERNANCE_ECONOMIC_EXPOSURE_V1,
        recommendations=ECONOMIC_RECOMMENDATIONS_V1,
        economic_index=economic_index
    )


@app.route("/governance/economic-intelligence/api")
def governance_economic_intelligence_api_v1():

    return jsonify({
        "economic_index": calculate_governance_economic_index_v1(),
        "exposures": GOVERNANCE_ECONOMIC_EXPOSURE_V1,
        "recommendations": ECONOMIC_RECOMMENDATIONS_V1
    })

# ============================================================
# END GOVERNANCE_ECONOMIC_INTELLIGENCE_ENGINE_V1
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

print("Inserted Governance Economic Intelligence Engine successfully.")
