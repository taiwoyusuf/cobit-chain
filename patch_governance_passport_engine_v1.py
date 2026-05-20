from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "SHARED_GOVERNANCE_PASSPORT_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Shared Governance Passport Engine already exists.")
    raise SystemExit()

if 'def governance_passport_engine_v1(' in text:
    print("Function already exists.")
    raise SystemExit()

INSERT = r"""

# ============================================================
# SHARED_GOVERNANCE_PASSPORT_ENGINE_V1_ACTIVE
# ============================================================

from flask import jsonify

GOVERNANCE_PASSPORTS_V1 = [
    {
        "passport_id": "PASS-IRLT-001",
        "module": "IRLTTrust",
        "passport_type": "Release Defensibility",
        "trust_score": 94,
        "status": "Certified",
        "inspection": "Ready"
    },
    {
        "passport_id": "PASS-IRLT-002",
        "module": "IRLTTrust",
        "passport_type": "Dose Journey",
        "trust_score": 96,
        "status": "Verified",
        "inspection": "Ready"
    },
    {
        "passport_id": "PASS-COMP-001",
        "module": "CompoundTrust",
        "passport_type": "Sterile Governance",
        "trust_score": 91,
        "status": "Certified",
        "inspection": "Controlled"
    },
    {
        "passport_id": "PASS-TRIAL-001",
        "module": "TrialTrust",
        "passport_type": "Clinical Governance",
        "trust_score": 89,
        "status": "Review",
        "inspection": "Monitoring"
    },
    {
        "passport_id": "PASS-DSCSA-001",
        "module": "DSCSATrust",
        "passport_type": "Chain of Custody",
        "trust_score": 93,
        "status": "Certified",
        "inspection": "Ready"
    }
]


def calculate_passport_engine_score_v1():

    total = 0

    for row in GOVERNANCE_PASSPORTS_V1:
        total += row["trust_score"]

    return round(total / len(GOVERNANCE_PASSPORTS_V1))


@app.route("/governance/passport-engine")
def governance_passport_engine_v1():

    overall_score = calculate_passport_engine_score_v1()

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Shared Governance Passport Engine</title>

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

            .passport-grid {
                display:grid;
                grid-template-columns:repeat(3,1fr);
                gap:20px;
                margin-top:24px;
            }

            .passport-card {
                border-radius:22px;
                padding:24px;
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02)),
                    rgba(255,255,255,0.03);
                border:1px solid rgba(255,255,255,0.08);
            }

            .passport-card strong {
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

            @media (max-width:1200px) {

                .passport-grid {
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

                <h1>Shared Governance Passport Engine</h1>

                <p>
                    Portable governance certification and operational trust passport
                    infrastructure reusable across all AssuranceLayer operational verticals.
                </p>

                <div class="overall">

                    <strong>{{ overall_score }}%</strong>

                    Enterprise Governance Passport Trust Score

                </div>

            </section>

            <section class="panel">

                <h2>Governance Passport Registry</h2>

                <div class="passport-grid">

                    {% for row in passports %}

                    <div class="passport-card">

                        <strong>{{ row.trust_score }}%</strong>

                        <h3>{{ row.passport_type }}</h3>

                        <p>
                            Module:
                            <strong style="font-size:18px;color:white;">
                                {{ row.module }}
                            </strong>
                        </p>

                        <p>
                            Passport ID:
                            {{ row.passport_id }}
                        </p>

                        <span class="pill">
                            {{ row.status }}
                        </span>

                        <br>

                        <span class="pill">
                            Inspection: {{ row.inspection }}
                        </span>

                    </div>

                    {% endfor %}

                </div>

            </section>

            <section class="panel">

                <h2>Enterprise Governance Certification Vision</h2>

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
                            <td>Operational Trust Certification</td>
                            <td>Portable readiness validation</td>
                            <td>Cross-platform defensibility</td>
                        </tr>

                        <tr>
                            <td>Inspection Survivability Passports</td>
                            <td>Inspection readiness certification</td>
                            <td>Audit defensibility</td>
                        </tr>

                        <tr>
                            <td>Release Governance Passports</td>
                            <td>Release readiness validation</td>
                            <td>Commercialization assurance</td>
                        </tr>

                        <tr>
                            <td>Evidence Completeness Certification</td>
                            <td>Governed evidence verification</td>
                            <td>Operational trust assurance</td>
                        </tr>

                        <tr>
                            <td>Cross-Module Governance Portability</td>
                            <td>Reusable governance intelligence</td>
                            <td>Enterprise orchestration</td>
                        </tr>

                    </tbody>

                </table>

            </section>

        </div>

    </body>

    </html>

    '''

    return render_template_string(
        html,
        passports=GOVERNANCE_PASSPORTS_V1,
        overall_score=overall_score
    )


@app.route("/governance/passport-engine/api")
def governance_passport_engine_api_v1():

    return jsonify({
        "overall_score": calculate_passport_engine_score_v1(),
        "passports": GOVERNANCE_PASSPORTS_V1
    })

# ============================================================
# END SHARED_GOVERNANCE_PASSPORT_ENGINE_V1
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

print("Inserted Shared Governance Passport Engine successfully.")
