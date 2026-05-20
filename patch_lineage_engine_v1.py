from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "GOVERNANCE_EVIDENCE_LINEAGE_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Governance Evidence Lineage Engine already exists.")
    raise SystemExit()

if 'def governance_evidence_lineage_engine_v1(' in text:
    print("Function already exists.")
    raise SystemExit()

INSERT = r"""

# ============================================================
# GOVERNANCE_EVIDENCE_LINEAGE_ENGINE_V1_ACTIVE
# ============================================================

from flask import jsonify

EVIDENCE_LINEAGE_CHAINS_V1 = [
    {
        "chain_id": "LINEAGE-001",
        "trigger": "Environmental Monitoring Alert",
        "evidence": "EM Review Packet",
        "approval": "QA Approval",
        "release": "Commercial Batch Release",
        "inspection": "Inspection Defensible",
        "trust_score": 95
    },
    {
        "chain_id": "LINEAGE-002",
        "trigger": "Dose Preparation Verification",
        "evidence": "Dose Journey Evidence",
        "approval": "Radiopharma QA Review",
        "release": "Treatment Coordination Authorization",
        "inspection": "Operationally Traceable",
        "trust_score": 96
    },
    {
        "chain_id": "LINEAGE-003",
        "trigger": "Backup Governance Review",
        "evidence": "Backup Verification Log",
        "approval": "Infrastructure Governance",
        "release": "Operational Continuity Validation",
        "inspection": "Audit Survivable",
        "trust_score": 89
    },
    {
        "chain_id": "LINEAGE-004",
        "trigger": "CAPA Escalation",
        "evidence": "CAPA Evidence Bundle",
        "approval": "Compliance Governance",
        "release": "Remediation Verification",
        "inspection": "Monitoring Required",
        "trust_score": 84
    }
]


def calculate_lineage_integrity_v1():

    total = 0

    for row in EVIDENCE_LINEAGE_CHAINS_V1:
        total += row["trust_score"]

    return round(total / len(EVIDENCE_LINEAGE_CHAINS_V1))


@app.route("/governance/evidence-lineage")
def governance_evidence_lineage_engine_v1():

    lineage_score = calculate_lineage_integrity_v1()

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Governance Evidence Lineage Engine</title>

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

            .lineage-grid {
                display:grid;
                grid-template-columns:repeat(2,1fr);
                gap:22px;
                margin-top:24px;
            }

            .lineage-card {
                border-radius:22px;
                padding:24px;
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02)),
                    rgba(255,255,255,0.03);
                border:1px solid rgba(255,255,255,0.08);
            }

            .lineage-card strong {
                display:block;
                font-size:34px;
                color:#ff9f1c;
                margin-bottom:14px;
            }

            .flow {
                margin-top:16px;
                padding:14px;
                border-radius:14px;
                background:rgba(255,255,255,0.03);
                border:1px solid rgba(255,255,255,0.05);
            }

            .arrow {
                color:#ff9f1c;
                font-weight:bold;
                margin:10px 0;
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

            @media (max-width:1200px) {

                .lineage-grid {
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

                <h1>Governance Evidence Lineage Engine</h1>

                <p>
                    Operational governance provenance and cryptographic traceability
                    infrastructure for inspection survivability, release defensibility,
                    operational auditability, and commercialization readiness assurance.
                </p>

                <div class="overall">

                    <strong>{{ lineage_score }}%</strong>

                    Governance Lineage Integrity Score

                </div>

            </section>

            <section class="panel">

                <h2>Operational Governance Lineage Chains</h2>

                <div class="lineage-grid">

                    {% for row in chains %}

                    <div class="lineage-card">

                        <strong>{{ row.chain_id }}</strong>

                        <div class="flow">

                            {{ row.trigger }}

                            <div class="arrow">
                                ↓
                            </div>

                            {{ row.evidence }}

                            <div class="arrow">
                                ↓
                            </div>

                            {{ row.approval }}

                            <div class="arrow">
                                ↓
                            </div>

                            {{ row.release }}

                            <div class="arrow">
                                ↓
                            </div>

                            {{ row.inspection }}

                        </div>

                        <span class="pill">
                            Trust Score: {{ row.trust_score }}%
                        </span>

                    </div>

                    {% endfor %}

                </div>

            </section>

            <section class="panel">

                <h2>Governance Provenance Intelligence</h2>

                <table>

                    <thead>

                        <tr>
                            <th>Capability</th>
                            <th>Purpose</th>
                            <th>Operational Value</th>
                        </tr>

                    </thead>

                    <tbody>

                        <tr>
                            <td>Evidence Provenance Tracking</td>
                            <td>Track governance evidence origins and flows</td>
                            <td>Inspection defensibility</td>
                        </tr>

                        <tr>
                            <td>Approval Lineage Mapping</td>
                            <td>Visualize governance approval chains</td>
                            <td>Operational traceability</td>
                        </tr>

                        <tr>
                            <td>Release Governance Lineage</td>
                            <td>Track release defensibility pathways</td>
                            <td>Commercialization assurance</td>
                        </tr>

                        <tr>
                            <td>Operational Audit Replay</td>
                            <td>Reconstruct governance evidence pathways</td>
                            <td>Audit survivability</td>
                        </tr>

                        <tr>
                            <td>Cryptographic Governance Traceability</td>
                            <td>Support immutable governance provenance</td>
                            <td>Enterprise trust assurance</td>
                        </tr>

                    </tbody>

                </table>

            </section>

            <section class="panel">

                <h2>Enterprise Governance Provenance Vision</h2>

                <p>
                    The Governance Evidence Lineage Engine provides operational
                    governance provenance intelligence across all COBIT-Chain
                    AssuranceLayer operational verticals.
                </p>

                <p>
                    This architecture supports:
                </p>

                <ul>

                    <li>Operational governance traceability</li>

                    <li>Inspection replay intelligence</li>

                    <li>Cryptographic evidence lineage</li>

                    <li>Governance provenance reconstruction</li>

                    <li>Operational audit survivability</li>

                    <li>Release defensibility lineage</li>

                    <li>Cross-domain evidence dependency mapping</li>

                    <li>Enterprise governance trust preservation</li>

                </ul>

            </section>

        </div>

    </body>

    </html>

    '''

    return render_template_string(
        html,
        chains=EVIDENCE_LINEAGE_CHAINS_V1,
        lineage_score=lineage_score
    )


@app.route("/governance/evidence-lineage/api")
def governance_evidence_lineage_engine_api_v1():

    return jsonify({
        "lineage_score": calculate_lineage_integrity_v1(),
        "chains": EVIDENCE_LINEAGE_CHAINS_V1
    })

# ============================================================
# END GOVERNANCE_EVIDENCE_LINEAGE_ENGINE_V1
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

print("Inserted Governance Evidence Lineage Engine successfully.")
