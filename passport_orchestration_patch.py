from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_GOVERNANCE_PASSPORT_ORCHESTRATION_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Governance Passport Orchestration already exists.")
    raise SystemExit()

anchor = "# END IRLT_GOVERNANCE_RISK_PROPAGATION_ENGINE_V1"

if anchor not in text:
    print("Could not locate safe insertion anchor.")
    raise SystemExit()

block = r"""

# ============================================================
# IRLT_GOVERNANCE_PASSPORT_ORCHESTRATION_ENGINE_V1_ACTIVE
# ============================================================

IRLT_GOVERNANCE_PASSPORTS_V1 = [
    {
        "passport": "Release Passport",
        "trust": 95,
        "state": "Certified",
        "scope": "Commercial Release"
    },
    {
        "passport": "Inspection Passport",
        "trust": 93,
        "state": "Verified",
        "scope": "Inspection Survivability"
    },
    {
        "passport": "Dose Journey Passport",
        "trust": 96,
        "state": "Aligned",
        "scope": "Isotope Lineage"
    },
    {
        "passport": "Shipment Passport",
        "trust": 91,
        "state": "Stable",
        "scope": "Chain of Custody"
    },
    {
        "passport": "Environmental Passport",
        "trust": 84,
        "state": "Observed",
        "scope": "EM Governance"
    },
    {
        "passport": "Operational Readiness Passport",
        "trust": 92,
        "state": "Controlled",
        "scope": "Commercialization Readiness"
    }
]


@app.route("/irlt-commercial-readiness/passport-orchestration")
def irlt_passport_orchestration():

    overall_trust = round(
        sum(x["trust"] for x in IRLT_GOVERNANCE_PASSPORTS_V1)
        / len(IRLT_GOVERNANCE_PASSPORTS_V1)
    )

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Governance Passport Orchestration</title>

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
                padding:20px;
                border:1px solid rgba(255,255,255,0.08);
            }

            .card strong{
                display:block;
                color:#ff9f1c;
                font-size:38px;
            }

            .pill{
                display:inline-block;
                margin-top:12px;
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

                <h1>Governance Passport Orchestration</h1>

                <p>
                    Enterprise operational trust certification layer for
                    commercialization readiness assurance,
                    governance survivability certification,
                    inspection defensibility orchestration,
                    and portable operational trust intelligence.
                </p>

                <div class="hero-grid">

                    <div class="panel">

                        <h2>Governance Passport Certifications</h2>

                        <div class="grid">

                            {% for row in passports %}

                            <div class="card">

                                <strong>{{ row.trust }}%</strong>

                                {{ row.passport }}

                                <br>

                                <span class="pill">
                                    {{ row.state }}
                                </span>

                                <br><br>

                                <small style="color:#b8c1cd;">
                                    {{ row.scope }}
                                </small>

                            </div>

                            {% endfor %}

                        </div>

                    </div>

                    <div class="overall">

                        <strong>{{ overall_trust }}%</strong>

                        Operational Trust Certification

                    </div>

                </div>

            </section>

            <div class="ops-grid">

                <section class="panel">

                    <h2>Operational Trust Certification Intelligence</h2>

                    <ul>

                        <li>
                            Release governance certification remains commercially defensible across operational readiness pathways.
                        </li>

                        <li>
                            Dose lineage governance certification remains highly survivable under inspection scrutiny.
                        </li>

                        <li>
                            Shipment governance trust alignment remains operationally stable across chain-of-custody workflows.
                        </li>

                        <li>
                            Environmental governance certification remains observable but commercially manageable.
                        </li>

                        <li>
                            Operational readiness certification remains aligned with commercialization governance expectations.
                        </li>

                        <li>
                            Governance passport orchestration maintains enterprise operational trust coherence.
                        </li>

                    </ul>

                </section>

                <section class="panel">

                    <h2>Governance Passport Matrix</h2>

                    <table>

                        <thead>

                            <tr>
                                <th>Passport</th>
                                <th>Trust</th>
                                <th>State</th>
                                <th>Scope</th>
                            </tr>

                        </thead>

                        <tbody>

                            {% for row in passports %}

                            <tr>

                                <td>{{ row.passport }}</td>

                                <td>{{ row.trust }}%</td>

                                <td>{{ row.state }}</td>

                                <td>{{ row.scope }}</td>

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
        passports=IRLT_GOVERNANCE_PASSPORTS_V1,
        overall_trust=overall_trust
    )


@app.route("/irlt-commercial-readiness/passport-orchestration/api")
def irlt_passport_orchestration_api():

    return jsonify({
        "overall_trust": round(
            sum(x["trust"] for x in IRLT_GOVERNANCE_PASSPORTS_V1)
            / len(IRLT_GOVERNANCE_PASSPORTS_V1)
        ),
        "passports": IRLT_GOVERNANCE_PASSPORTS_V1
    })

# ============================================================
# END IRLT_GOVERNANCE_PASSPORT_ORCHESTRATION_ENGINE_V1
# ============================================================

"""

text = text.replace(anchor, anchor + block)

APP.write_text(text, encoding="utf-8")

print("Governance Passport Orchestration inserted successfully.")
