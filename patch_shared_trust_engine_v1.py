from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "SHARED_GOVERNANCE_TRUST_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Shared Trust Engine already exists.")
    raise SystemExit()

if 'def governance_shared_trust_engine_v1(' in text:
    print("Function already exists.")
    raise SystemExit()

INSERT = r"""

# ============================================================
# SHARED_GOVERNANCE_TRUST_ENGINE_V1_ACTIVE
# ============================================================

from flask import jsonify

SHARED_TRUST_DOMAINS_V1 = [
    {
        "domain": "Evidence Integrity",
        "weight": 0.20,
        "score": 94
    },
    {
        "domain": "Inspection Survivability",
        "weight": 0.18,
        "score": 91
    },
    {
        "domain": "Release Defensibility",
        "weight": 0.18,
        "score": 92
    },
    {
        "domain": "Operational Readiness",
        "weight": 0.15,
        "score": 89
    },
    {
        "domain": "Dependency Governance",
        "weight": 0.12,
        "score": 85
    },
    {
        "domain": "CAPA Governance",
        "weight": 0.10,
        "score": 84
    },
    {
        "domain": "Access Governance",
        "weight": 0.07,
        "score": 88
    }
]


def calculate_shared_governance_trust_score_v1():

    total = 0

    for row in SHARED_TRUST_DOMAINS_V1:
        total += row["score"] * row["weight"]

    return round(total)


@app.route("/governance/shared-trust-engine")
def governance_shared_trust_engine_v1():

    overall_score = calculate_shared_governance_trust_score_v1()

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Shared Governance Trust Engine</title>

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
                max-width:1850px;
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

        </style>

    </head>

    <body>

        <div class="wrap">

            <section class="hero">

                <h1>Shared Governance Trust Engine</h1>

                <p>
                    Centralized governance scoring and operational trust intelligence
                    engine reusable across all AssuranceLayer verticals.
                </p>

                <div class="overall">

                    <strong>{{ overall_score }}%</strong>

                    Enterprise Governance Trust Score

                </div>

            </section>

            <section class="panel">

                <h2>Shared Governance Scoring Domains</h2>

                <table>

                    <thead>

                        <tr>
                            <th>Governance Domain</th>
                            <th>Weight</th>
                            <th>Score</th>
                            <th>Status</th>
                        </tr>

                    </thead>

                    <tbody>

                        {% for row in domains %}

                        <tr>

                            <td>{{ row.domain }}</td>

                            <td>{{ row.weight }}</td>

                            <td>{{ row.score }}%</td>

                            <td>

                                <span class="pill">

                                    {% if row.score >= 90 %}
                                        Strong
                                    {% elif row.score >= 85 %}
                                        Stable
                                    {% else %}
                                        Attention
                                    {% endif %}

                                </span>

                            </td>

                        </tr>

                        {% endfor %}

                    </tbody>

                </table>

            </section>

            <section class="panel">

                <h2>Enterprise Governance Engine Vision</h2>

                <p>
                    This engine provides centralized governance trust scoring
                    across all COBIT-Chain AssuranceLayer operational verticals.
                </p>

                <p>
                    Shared governance scoring enables:
                </p>

                <ul>

                    <li>Cross-platform trust normalization</li>

                    <li>Operational readiness scoring consistency</li>

                    <li>Inspection survivability calculations</li>

                    <li>Release defensibility intelligence</li>

                    <li>Governance maturity alignment</li>

                    <li>Shared dependency propagation logic</li>

                    <li>Reusable governance intelligence APIs</li>

                    <li>Executive governance orchestration</li>

                </ul>

            </section>

        </div>

    </body>

    </html>

    '''

    return render_template_string(
        html,
        domains=SHARED_TRUST_DOMAINS_V1,
        overall_score=overall_score
    )


@app.route("/governance/shared-trust-engine/api")
def governance_shared_trust_engine_api_v1():

    return jsonify({
        "overall_score": calculate_shared_governance_trust_score_v1(),
        "domains": SHARED_TRUST_DOMAINS_V1
    })

# ============================================================
# END SHARED_GOVERNANCE_TRUST_ENGINE_V1
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

print("Inserted Shared Governance Trust Engine successfully.")
