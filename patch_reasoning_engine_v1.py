from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "SHARED_GOVERNANCE_REASONING_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Governance Reasoning Engine already exists.")
    raise SystemExit()

if 'def governance_reasoning_engine_v1(' in text:
    print("Function already exists.")
    raise SystemExit()

INSERT = r"""

# ============================================================
# SHARED_GOVERNANCE_REASONING_ENGINE_V1_ACTIVE
# ============================================================

from flask import jsonify

GOVERNANCE_REASONING_STREAM_V1 = [
    {
        "domain": "Inspection Survivability",
        "reasoning": "CAPA closure delays are beginning to propagate into inspection defensibility posture.",
        "priority": "High",
        "recommendation": "Accelerate unresolved CAPA governance review."
    },
    {
        "domain": "Release Defensibility",
        "reasoning": "Environmental review dependencies remain partially unresolved.",
        "priority": "Medium",
        "recommendation": "Escalate environmental governance review workflow."
    },
    {
        "domain": "Operational Trust",
        "reasoning": "Backup governance maturity improved after evidence reconciliation validation.",
        "priority": "Stable",
        "recommendation": "Continue monthly governance verification cadence."
    },
    {
        "domain": "Treatment Coordination",
        "reasoning": "Shipment coordination governance remains operationally stable.",
        "priority": "Low",
        "recommendation": "Maintain current coordination controls."
    }
]


def calculate_reasoning_confidence_v1():

    base = 92

    return round(base)


@app.route("/governance/reasoning-engine")
def governance_reasoning_engine_v1():

    confidence = calculate_reasoning_confidence_v1()

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Governance Reasoning Engine</title>

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

            .confidence {
                margin-top:24px;
                text-align:center;
                padding:24px;
                border-radius:22px;
                background:rgba(255,255,255,0.04);
            }

            .confidence strong {
                display:block;
                font-size:120px;
                color:#ff9f1c;
            }

            .reason-grid {
                display:grid;
                grid-template-columns:repeat(2,1fr);
                gap:22px;
                margin-top:24px;
            }

            .reason-card {
                border-radius:22px;
                padding:24px;
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02)),
                    rgba(255,255,255,0.03);
                border:1px solid rgba(255,255,255,0.08);
            }

            .reason-card strong {
                display:block;
                font-size:28px;
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

                .reason-grid {
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

                <h1>Governance Reasoning Engine</h1>

                <p>
                    Explainable operational governance reasoning infrastructure
                    for commercialization readiness, inspection survivability,
                    release defensibility, and operational trust intelligence.
                </p>

                <div class="confidence">

                    <strong>{{ confidence }}%</strong>

                    Governance Reasoning Confidence

                </div>

            </section>

            <section class="panel">

                <h2>Operational Governance Reasoning Stream</h2>

                <div class="reason-grid">

                    {% for row in reasoning %}

                    <div class="reason-card">

                        <strong>{{ row.domain }}</strong>

                        <p>
                            {{ row.reasoning }}
                        </p>

                        <p>
                            Recommendation:
                            {{ row.recommendation }}
                        </p>

                        <span class="pill">
                            Priority: {{ row.priority }}
                        </span>

                    </div>

                    {% endfor %}

                </div>

            </section>

            <section class="panel">

                <h2>Governance Explainability Principles</h2>

                <table>

                    <thead>

                        <tr>
                            <th>Principle</th>
                            <th>Description</th>
                            <th>Governance Position</th>
                        </tr>

                    </thead>

                    <tbody>

                        <tr>
                            <td>Evidence Authoritativeness</td>
                            <td>Governed evidence remains the source of truth.</td>
                            <td>Mandatory</td>
                        </tr>

                        <tr>
                            <td>Human Governance Control</td>
                            <td>Humans remain the authoritative decision-makers.</td>
                            <td>Mandatory</td>
                        </tr>

                        <tr>
                            <td>Explainable Reasoning</td>
                            <td>Operational trust calculations remain explainable.</td>
                            <td>Required</td>
                        </tr>

                        <tr>
                            <td>Dependency Awareness</td>
                            <td>Governance reasoning includes operational dependency analysis.</td>
                            <td>Enabled</td>
                        </tr>

                        <tr>
                            <td>Inspection Defensibility</td>
                            <td>Reasoning outputs support audit defensibility posture.</td>
                            <td>Critical</td>
                        </tr>

                    </tbody>

                </table>

            </section>

            <section class="panel">

                <h2>Enterprise Governance Intelligence Vision</h2>

                <p>
                    The Governance Reasoning Engine provides explainable operational
                    governance intelligence across all COBIT-Chain AssuranceLayer verticals.
                </p>

                <p>
                    This architecture supports:
                </p>

                <ul>

                    <li>Operational governance explainability</li>

                    <li>Inspection survivability reasoning</li>

                    <li>Executive governance prioritization</li>

                    <li>Commercialization readiness justification</li>

                    <li>Dependency-aware governance analysis</li>

                    <li>Evidence gap explainability</li>

                    <li>Operational trust narrative generation</li>

                    <li>Human-governed advisory intelligence</li>

                </ul>

            </section>

        </div>

    </body>

    </html>

    '''

    return render_template_string(
        html,
        reasoning=GOVERNANCE_REASONING_STREAM_V1,
        confidence=confidence
    )


@app.route("/governance/reasoning-engine/api")
def governance_reasoning_engine_api_v1():

    return jsonify({
        "confidence": calculate_reasoning_confidence_v1(),
        "reasoning_stream": GOVERNANCE_REASONING_STREAM_V1
    })

# ============================================================
# END SHARED_GOVERNANCE_REASONING_ENGINE_V1
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

print("Inserted Governance Reasoning Engine successfully.")
