from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_VERTICAL_EVIDENCE_VAULT_INTEGRATION_V1_ACTIVE"

if MARKER in text:
    print("IRLT Evidence Vault vertical already exists.")
    raise SystemExit()

INSERT = r"""

# ============================================================
# IRLT_VERTICAL_EVIDENCE_VAULT_INTEGRATION_V1_ACTIVE
# ============================================================

IRLT_EVIDENCE_VERTICAL_RECORDS = [
    {
        "evidence_id": "IRLT-EVI-001",
        "classification": "QA Release",
        "title": "Final Dose Release Packet",
        "owner": "QA Release",
        "trust_score": 96,
        "status": "Integrity Verified",
        "passport": "Release Defensibility Passport™"
    },
    {
        "evidence_id": "IRLT-EVI-002",
        "classification": "Dose Journey",
        "title": "Isotope-to-Patient Chain",
        "owner": "Treatment Coordination",
        "trust_score": 94,
        "status": "Integrity Verified",
        "passport": "Dose Journey Passport™"
    },
    {
        "evidence_id": "IRLT-EVI-003",
        "classification": "Radioactive Material",
        "title": "Material Accountability Ledger",
        "owner": "Radiation Safety",
        "trust_score": 95,
        "status": "Integrity Verified",
        "passport": "Radioactive Material Passport™"
    },
    {
        "evidence_id": "IRLT-EVI-004",
        "classification": "Environmental Monitoring",
        "title": "Hot Cell Environmental Monitoring",
        "owner": "Manufacturing QA",
        "trust_score": 90,
        "status": "Review Required",
        "passport": "EM Governance Passport™"
    },
    {
        "evidence_id": "IRLT-EVI-005",
        "classification": "Inspection",
        "title": "Inspection Readiness Evidence Matrix",
        "owner": "Compliance",
        "trust_score": 92,
        "status": "Inspection Ready",
        "passport": "Inspection Survivability Passport™"
    }
]


@app.route("/irlt-commercial-readiness/evidence-vault")
@app.route("/rlttrust/evidence-vault")
def irlt_vertical_evidence_vault():

    html = """

    <!doctype html>
    <html>
    <head>

        <title>IRLTTrust™ Evidence Vault</title>

        <style>

            body {
                margin:0;
                background:
                    radial-gradient(circle at top left, rgba(255,122,24,0.22), transparent 32%),
                    linear-gradient(135deg,#050608 0%,#11151f 48%,#06070b 100%);
                color:white;
                font-family:Inter,Segoe UI,Arial,sans-serif;
            }

            .wrap {
                max-width:1850px;
                margin:auto;
                padding:38px;
            }

            .hero,.panel {
                border:1px solid rgba(255,255,255,0.1);
                border-radius:28px;
                padding:28px;
                margin-bottom:24px;
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02)),
                    rgba(20,24,33,0.88);
            }

            h1 {
                font-size:72px;
                color:#ff9f1c;
                margin:0 0 10px;
                letter-spacing:-0.05em;
            }

            h2 {
                color:#ff9f1c;
            }

            p {
                color:#aeb6c6;
                line-height:1.6;
            }

            .grid {
                display:grid;
                grid-template-columns:1.2fr .8fr;
                gap:22px;
            }

            .metric-grid {
                display:grid;
                grid-template-columns:repeat(4,1fr);
                gap:18px;
                margin-top:24px;
            }

            .metric {
                background:rgba(255,255,255,0.04);
                border:1px solid rgba(255,255,255,0.08);
                border-radius:18px;
                padding:18px;
            }

            .metric strong {
                display:block;
                font-size:34px;
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
                font-size:12px;
                text-transform:uppercase;
            }

            .pill {
                display:inline-block;
                padding:7px 12px;
                border-radius:999px;
                background:rgba(255,122,24,0.12);
                border:1px solid rgba(255,122,24,0.28);
                color:#ffd7ad;
                font-size:12px;
                font-weight:800;
            }

            .nav {
                margin-top:22px;
            }

            .nav a {
                display:inline-block;
                margin-right:12px;
                margin-bottom:12px;
                text-decoration:none;
                color:white;
                padding:12px 16px;
                border-radius:14px;
                background:rgba(255,255,255,0.05);
                border:1px solid rgba(255,122,24,0.25);
            }

            @media (max-width:1200px) {
                .grid,.metric-grid {
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

                <h1>IRLTTrust™ Evidence Vault</h1>

                <p>
                    Governance evidence control tower for radiopharma operations,
                    release defensibility, isotope lineage, treatment coordination,
                    radioactive material accountability, and inspection survivability.
                </p>

                <div class="nav">
                    <a href="/irlt-commercial-readiness">Command Center</a>
                    <a href="/irlt-commercial-readiness/release-defensibility">Release Defensibility</a>
                    <a href="/irlt-commercial-readiness/isotope-to-patient">Dose Journey</a>
                    <a href="/irlt-commercial-readiness/inspection-tomorrow">Inspection Readiness</a>
                    <a href="/irlt-commercial-readiness/passport-factory">Passport Factory</a>
                </div>

                <div class="metric-grid">

                    <div class="metric">
                        <strong>96%</strong>
                        Evidence Integrity
                    </div>

                    <div class="metric">
                        <strong>94%</strong>
                        Dose Lineage Readiness
                    </div>

                    <div class="metric">
                        <strong>92%</strong>
                        Inspection Survivability
                    </div>

                    <div class="metric">
                        <strong>91%</strong>
                        Release Defensibility
                    </div>

                </div>

            </section>

            <div class="grid">

                <section class="panel">

                    <h2>IRLT Governance Evidence Registry</h2>

                    <table>

                        <thead>

                            <tr>
                                <th>Evidence ID</th>
                                <th>Classification</th>
                                <th>Title</th>
                                <th>Owner</th>
                                <th>Trust Score</th>
                                <th>Status</th>
                                <th>Passport</th>
                            </tr>

                        </thead>

                        <tbody>

                            {% for row in records %}

                            <tr>

                                <td>{{ row.evidence_id }}</td>

                                <td>{{ row.classification }}</td>

                                <td>{{ row.title }}</td>

                                <td>{{ row.owner }}</td>

                                <td>{{ row.trust_score }}%</td>

                                <td>
                                    <span class="pill">
                                        {{ row.status }}
                                    </span>
                                </td>

                                <td>{{ row.passport }}</td>

                            </tr>

                            {% endfor %}

                        </tbody>

                    </table>

                </section>

                <section class="panel">

                    <h2>Executive Governance Intelligence</h2>

                    <p>
                        RLTTrust™ Evidence Vault extends the enterprise governance
                        evidence architecture already used by the sterile compounding platform.
                    </p>

                    <p>
                        This vertical specializes evidence governance for:
                    </p>

                    <ul>

                        <li>Radiopharma release governance</li>

                        <li>Isotope-to-patient lineage</li>

                        <li>Radioactive material accountability</li>

                        <li>Treatment coordination governance</li>

                        <li>Commercialization readiness assurance</li>

                        <li>Inspection survivability intelligence</li>

                        <li>Governance passport generation</li>

                        <li>Operational trust defensibility</li>

                    </ul>

                    <p>
                        The platform does NOT replace MES, LIMS, ERP,
                        CTMS, ServiceNow, or manufacturing systems.
                    </p>

                    <p>
                        It operates as a governance assurance and operational
                        trust overlay layer.
                    </p>

                </section>

            </div>

        </div>

    </body>

    </html>

    """

    return render_template_string(
        html,
        records=IRLT_EVIDENCE_VERTICAL_RECORDS
    )


@app.route("/irlt-commercial-readiness/evidence-vault/api")
@app.route("/rlttrust/evidence-vault/api")
def irlt_vertical_evidence_vault_api():

    return jsonify(IRLT_EVIDENCE_VERTICAL_RECORDS)

# ============================================================
# END IRLT_VERTICAL_EVIDENCE_VAULT_INTEGRATION
# ============================================================

"""

needle = '\nif __name__ == "__main__":'

if needle not in text:
    needle = "\nif __name__ == '__main__':"

text = text.replace(
    needle,
    "\n" + INSERT + "\n" + needle,
    1
)

APP.write_text(text, encoding="utf-8")

print("Inserted IRLT vertical Evidence Vault successfully.")
