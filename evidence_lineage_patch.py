from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_EVIDENCE_LINEAGE_INTELLIGENCE_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Evidence Lineage Intelligence Engine already exists.")
    raise SystemExit()

anchor = "# END IRLT_DEPENDENCY_COGNITION_ENGINE_V1"

if anchor not in text:
    print("Could not locate safe insertion anchor.")
    raise SystemExit()

block = r"""

# ============================================================
# IRLT_EVIDENCE_LINEAGE_INTELLIGENCE_ENGINE_V1_ACTIVE
# ============================================================

IRLT_EVIDENCE_LINEAGE_V1 = [
    {
        "evidence": "Batch Release Packet",
        "origin": "QA Governance",
        "destination": "Commercial Release",
        "integrity": 97,
        "state": "Verified"
    },
    {
        "evidence": "Environmental Monitoring Records",
        "origin": "EM Operations",
        "destination": "Inspection Readiness",
        "integrity": 86,
        "state": "Observed"
    },
    {
        "evidence": "Dose Traceability Chain",
        "origin": "Radiopharma Manufacturing",
        "destination": "Patient Administration",
        "integrity": 99,
        "state": "Strong"
    },
    {
        "evidence": "Shipment Governance Logs",
        "origin": "Distribution Operations",
        "destination": "Cold Chain Verification",
        "integrity": 91,
        "state": "Stable"
    },
    {
        "evidence": "Backup Verification Records",
        "origin": "Infrastructure Governance",
        "destination": "Audit Survivability",
        "integrity": 89,
        "state": "Controlled"
    },
    {
        "evidence": "CAPA Closure Evidence",
        "origin": "Quality Systems",
        "destination": "Inspection Defensibility",
        "integrity": 82,
        "state": "Monitoring"
    }
]


@app.route("/irlt-commercial-readiness/evidence-lineage")
def irlt_evidence_lineage():

    lineage_score = round(
        sum(x["integrity"] for x in IRLT_EVIDENCE_LINEAGE_V1)
        / len(IRLT_EVIDENCE_LINEAGE_V1)
    )

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Evidence Lineage Intelligence Engine</title>

        <style>

            body{
                margin:0;
                background:
                    radial-gradient(circle at top left, rgba(255,122,24,0.20), transparent 34%),
                    linear-gradient(135deg,#050608 0%,#11151f 48%,#06070b 100%);
                color:white;
                font-family:Arial;
            }

            .wrap{
                max-width:1900px;
                margin:auto;
                padding:34px;
            }

            .hero,.panel{
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02)),
                    rgba(20,24,33,0.88);
                border-radius:28px;
                padding:28px;
                margin-bottom:24px;
                border:1px solid rgba(255,255,255,0.08);
            }

            h1{
                color:#ff9f1c;
                font-size:74px;
                margin:0 0 12px;
                letter-spacing:-0.05em;
            }

            h2{
                color:#ff9f1c;
            }

            p{
                color:#c0c7d2;
                line-height:1.7;
            }

            .hero-grid{
                display:grid;
                grid-template-columns:1.2fr .8fr;
                gap:24px;
            }

            .overall{
                height:320px;
                border-radius:24px;
                display:flex;
                flex-direction:column;
                justify-content:center;
                align-items:center;
                background:
                    radial-gradient(circle, rgba(255,159,28,0.20), transparent 70%),
                    rgba(255,255,255,0.03);
                border:1px solid rgba(255,159,28,0.18);
            }

            .overall strong{
                font-size:110px;
                color:#ff9f1c;
            }

            .lineage{
                margin-top:18px;
                padding:22px;
                border-radius:18px;
                background:rgba(255,255,255,0.04);
                border:1px solid rgba(255,255,255,0.08);
            }

            .lineage strong{
                display:block;
                color:#ff9f1c;
                font-size:28px;
            }

            .pill{
                display:inline-block;
                margin-top:12px;
                margin-right:8px;
                padding:7px 12px;
                border-radius:999px;
                background:rgba(255,122,24,0.12);
                border:1px solid rgba(255,122,24,0.25);
                color:#ffd7ad;
                font-size:12px;
                font-weight:bold;
            }

            .ops-grid{
                display:grid;
                grid-template-columns:1fr 1fr;
                gap:22px;
            }

            table{
                width:100%;
                border-collapse:collapse;
            }

            th,td{
                padding:14px;
                border-bottom:1px solid rgba(255,255,255,0.08);
                text-align:left;
            }

            th{
                color:#ff9f1c;
                font-size:12px;
                text-transform:uppercase;
            }

            ul li{
                margin-bottom:12px;
                color:#c6cfdb;
            }

            @media (max-width:1200px){

                .hero-grid,
                .ops-grid{
                    grid-template-columns:1fr;
                }

                h1{
                    font-size:44px;
                }

            }

        </style>

    </head>

    <body>

        <div class="wrap">

            <section class="hero">

                <h1>Evidence Lineage Intelligence</h1>

                <p>
                    Enterprise evidence survivability and lineage intelligence
                    engine for commercialization defensibility,
                    audit-ready traceability,
                    governance integrity preservation,
                    and operational trust continuity.
                </p>

                <div class="hero-grid">

                    <div class="panel">

                        <h2>Evidence Lineage Streams</h2>

                        {% for row in lineage %}

                        <div class="lineage">

                            <strong>{{ row.evidence }}</strong>

                            <p>
                                {{ row.origin }}
                                →
                                <b>{{ row.destination }}</b>
                            </p>

                            <span class="pill">
                                Integrity {{ row.integrity }}%
                            </span>

                            <span class="pill">
                                {{ row.state }}
                            </span>

                        </div>

                        {% endfor %}

                    </div>

                    <div class="overall">

                        <strong>{{ lineage_score }}%</strong>

                        Evidence Integrity

                    </div>

                </div>

            </section>

            <div class="ops-grid">

                <section class="panel">

                    <h2>Evidence Survivability Intelligence</h2>

                    <ul>

                        <li>
                            Dose traceability lineage remains the strongest operational trust preservation pathway.
                        </li>

                        <li>
                            Environmental monitoring evidence requires continued governance observation.
                        </li>

                        <li>
                            Commercial release lineage remains operationally defensible under inspection scrutiny.
                        </li>

                        <li>
                            Backup verification continuity remains critical for audit survivability preservation.
                        </li>

                        <li>
                            CAPA evidence integrity remains commercially manageable but operationally sensitive.
                        </li>

                        <li>
                            Evidence lineage cognition remains aligned with enterprise commercialization defensibility objectives.
                        </li>

                    </ul>

                </section>

                <section class="panel">

                    <h2>Evidence Lineage Matrix</h2>

                    <table>

                        <thead>

                            <tr>
                                <th>Evidence</th>
                                <th>Origin</th>
                                <th>Destination</th>
                                <th>Integrity</th>
                            </tr>

                        </thead>

                        <tbody>

                            {% for row in lineage %}

                            <tr>

                                <td>{{ row.evidence }}</td>

                                <td>{{ row.origin }}</td>

                                <td>{{ row.destination }}</td>

                                <td>{{ row.integrity }}%</td>

                            </tr>

                            {% endfor %}

                        </tbody>

                    </table>

                </section>

            </div>

        </div>

    </body>

    </html>

    '''

    return render_template_string(
        html,
        lineage=IRLT_EVIDENCE_LINEAGE_V1,
        lineage_score=lineage_score
    )


@app.route("/irlt-commercial-readiness/evidence-lineage/api")
def irlt_evidence_lineage_api():

    return jsonify({
        "lineage_score": round(
            sum(x["integrity"] for x in IRLT_EVIDENCE_LINEAGE_V1)
            / len(IRLT_EVIDENCE_LINEAGE_V1)
        ),
        "lineage": IRLT_EVIDENCE_LINEAGE_V1
    })

# ============================================================
# END IRLT_EVIDENCE_LINEAGE_INTELLIGENCE_ENGINE_V1
# ============================================================

"""

text = text.replace(anchor, anchor + block)

APP.write_text(text, encoding="utf-8")

print("Evidence Lineage Intelligence Engine inserted successfully.")
