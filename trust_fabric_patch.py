from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_OPERATIONAL_TRUST_FABRIC_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Operational Trust Fabric Engine already exists.")
    raise SystemExit()

anchor = "# END IRLT_EVIDENCE_LINEAGE_INTELLIGENCE_ENGINE_V1"

if anchor not in text:
    print("Could not locate safe insertion anchor.")
    raise SystemExit()

block = r"""

# ============================================================
# IRLT_OPERATIONAL_TRUST_FABRIC_ENGINE_V1_ACTIVE
# ============================================================

IRLT_TRUST_FABRIC_V1 = [
    {
        "fabric": "Commercial Release Fabric",
        "trust": 96,
        "state": "Strong",
        "governance": "Aligned"
    },
    {
        "fabric": "Inspection Survivability Fabric",
        "trust": 94,
        "state": "Defensible",
        "governance": "Verified"
    },
    {
        "fabric": "Cold Chain Trust Fabric",
        "trust": 89,
        "state": "Stable",
        "governance": "Controlled"
    },
    {
        "fabric": "Dose Traceability Fabric",
        "trust": 98,
        "state": "Verified",
        "governance": "Certified"
    },
    {
        "fabric": "Evidence Integrity Fabric",
        "trust": 93,
        "state": "Protected",
        "governance": "Stable"
    },
    {
        "fabric": "CAPA Governance Fabric",
        "trust": 82,
        "state": "Observed",
        "governance": "Monitoring"
    }
]


@app.route("/irlt-commercial-readiness/trust-fabric")
def irlt_trust_fabric():

    trust_score = round(
        sum(x["trust"] for x in IRLT_TRUST_FABRIC_V1)
        / len(IRLT_TRUST_FABRIC_V1)
    )

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Operational Trust Fabric Engine</title>

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

            .grid{
                display:grid;
                grid-template-columns:repeat(3,1fr);
                gap:18px;
                margin-top:22px;
            }

            .card{
                background:rgba(255,255,255,0.04);
                border-radius:18px;
                padding:22px;
                border:1px solid rgba(255,255,255,0.08);
            }

            .card strong{
                display:block;
                color:#ff9f1c;
                font-size:40px;
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
                .ops-grid,
                .grid{
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

                <h1>Operational Trust Fabric</h1>

                <p>
                    Enterprise operational trust orchestration fabric for
                    commercialization survivability,
                    governance continuity preservation,
                    evidence integrity synchronization,
                    and inspection defense alignment.
                </p>

                <div class="hero-grid">

                    <div class="panel">

                        <h2>Governance Trust Fabric Layers</h2>

                        <div class="grid">

                            {% for row in fabric %}

                            <div class="card">

                                <strong>{{ row.trust }}%</strong>

                                {{ row.fabric }}

                                <br>

                                <span class="pill">
                                    {{ row.state }}
                                </span>

                                <span class="pill">
                                    {{ row.governance }}
                                </span>

                            </div>

                            {% endfor %}

                        </div>

                    </div>

                    <div class="overall">

                        <strong>{{ trust_score }}%</strong>

                        Trust Fabric Stability

                    </div>

                </div>

            </section>

            <div class="ops-grid">

                <section class="panel">

                    <h2>Operational Trust Intelligence</h2>

                    <ul>

                        <li>
                            Dose traceability governance remains the strongest operational trust preservation fabric.
                        </li>

                        <li>
                            Commercial release governance remains inspection-defensible under projected scale conditions.
                        </li>

                        <li>
                            CAPA governance pressure remains observable but commercially survivable.
                        </li>

                        <li>
                            Evidence integrity continuity remains strongly synchronized across governance domains.
                        </li>

                        <li>
                            Cold-chain governance alignment remains operationally stable across commercialization pathways.
                        </li>

                        <li>
                            Trust fabric cognition remains aligned with enterprise operational survivability objectives.
                        </li>

                    </ul>

                </section>

                <section class="panel">

                    <h2>Trust Fabric Matrix</h2>

                    <table>

                        <thead>

                            <tr>
                                <th>Fabric Domain</th>
                                <th>Trust</th>
                                <th>State</th>
                                <th>Governance</th>
                            </tr>

                        </thead>

                        <tbody>

                            {% for row in fabric %}

                            <tr>

                                <td>{{ row.fabric }}</td>

                                <td>{{ row.trust }}%</td>

                                <td>{{ row.state }}</td>

                                <td>{{ row.governance }}</td>

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
        fabric=IRLT_TRUST_FABRIC_V1,
        trust_score=trust_score
    )


@app.route("/irlt-commercial-readiness/trust-fabric/api")
def irlt_trust_fabric_api():

    return jsonify({
        "trust_score": round(
            sum(x["trust"] for x in IRLT_TRUST_FABRIC_V1)
            / len(IRLT_TRUST_FABRIC_V1)
        ),
        "fabric": IRLT_TRUST_FABRIC_V1
    })

# ============================================================
# END IRLT_OPERATIONAL_TRUST_FABRIC_ENGINE_V1
# ============================================================

"""

text = text.replace(anchor, anchor + block)

APP.write_text(text, encoding="utf-8")

print("Operational Trust Fabric Engine inserted successfully.")
