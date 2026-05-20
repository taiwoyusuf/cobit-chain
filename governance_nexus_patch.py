from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_GOVERNANCE_NEXUS_COMMAND_CORE_V1_ACTIVE"

if MARKER in text:
    print("Governance Nexus Command Core already exists.")
    raise SystemExit()

anchor = "# END IRLT_OPERATIONAL_TRUST_FABRIC_ENGINE_V1"

if anchor not in text:
    print("Could not locate safe insertion anchor.")
    raise SystemExit()

block = r"""

# ============================================================
# IRLT_GOVERNANCE_NEXUS_COMMAND_CORE_V1_ACTIVE
# ============================================================

IRLT_GOVERNANCE_NEXUS_V1 = [
    {
        "nexus": "Inspection Defense Nexus",
        "stability": 95,
        "state": "Strong",
        "impact": "Inspection Survivability"
    },
    {
        "nexus": "Commercial Readiness Nexus",
        "stability": 92,
        "state": "Controlled",
        "impact": "Operational Launch"
    },
    {
        "nexus": "Evidence Integrity Nexus",
        "stability": 97,
        "state": "Verified",
        "impact": "Audit Defense"
    },
    {
        "nexus": "CAPA Escalation Nexus",
        "stability": 79,
        "state": "Observed",
        "impact": "Quality Governance"
    },
    {
        "nexus": "Cold Chain Governance Nexus",
        "stability": 90,
        "state": "Stable",
        "impact": "Treatment Continuity"
    },
    {
        "nexus": "Dose Traceability Nexus",
        "stability": 99,
        "state": "Certified",
        "impact": "Patient Integrity"
    }
]


@app.route("/irlt-commercial-readiness/governance-nexus")
def irlt_governance_nexus():

    nexus_score = round(
        sum(x["stability"] for x in IRLT_GOVERNANCE_NEXUS_V1)
        / len(IRLT_GOVERNANCE_NEXUS_V1)
    )

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Governance Nexus Command Core</title>

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

                <h1>Governance Nexus Core</h1>

                <p>
                    Enterprise governance nexus intelligence layer for
                    operational trust synchronization,
                    commercialization survivability alignment,
                    evidence coherence orchestration,
                    and inspection defense convergence.
                </p>

                <div class="hero-grid">

                    <div class="panel">

                        <h2>Governance Nexus Domains</h2>

                        <div class="grid">

                            {% for row in nexus %}

                            <div class="card">

                                <strong>{{ row.stability }}%</strong>

                                {{ row.nexus }}

                                <br>

                                <span class="pill">
                                    {{ row.state }}
                                </span>

                                <br><br>

                                <small style="color:#b8c1cd;">
                                    {{ row.impact }}
                                </small>

                            </div>

                            {% endfor %}

                        </div>

                    </div>

                    <div class="overall">

                        <strong>{{ nexus_score }}%</strong>

                        Nexus Stability

                    </div>

                </div>

            </section>

            <div class="ops-grid">

                <section class="panel">

                    <h2>Nexus Intelligence Analysis</h2>

                    <ul>

                        <li>
                            Dose traceability governance remains the strongest enterprise trust nexus.
                        </li>

                        <li>
                            CAPA escalation governance remains the largest projected operational destabilization vector.
                        </li>

                        <li>
                            Evidence integrity synchronization remains highly aligned with inspection defensibility objectives.
                        </li>

                        <li>
                            Commercial readiness governance remains operationally survivable under projected scale conditions.
                        </li>

                        <li>
                            Cold-chain governance continuity remains commercially stable.
                        </li>

                        <li>
                            Governance nexus cognition remains synchronized with enterprise operational trust objectives.
                        </li>

                    </ul>

                </section>

                <section class="panel">

                    <h2>Governance Nexus Matrix</h2>

                    <table>

                        <thead>

                            <tr>
                                <th>Nexus Domain</th>
                                <th>Stability</th>
                                <th>State</th>
                                <th>Impact</th>
                            </tr>

                        </thead>

                        <tbody>

                            {% for row in nexus %}

                            <tr>

                                <td>{{ row.nexus }}</td>

                                <td>{{ row.stability }}%</td>

                                <td>{{ row.state }}</td>

                                <td>{{ row.impact }}</td>

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
        nexus=IRLT_GOVERNANCE_NEXUS_V1,
        nexus_score=nexus_score
    )


@app.route("/irlt-commercial-readiness/governance-nexus/api")
def irlt_governance_nexus_api():

    return jsonify({
        "nexus_score": round(
            sum(x["stability"] for x in IRLT_GOVERNANCE_NEXUS_V1)
            / len(IRLT_GOVERNANCE_NEXUS_V1)
        ),
        "nexus": IRLT_GOVERNANCE_NEXUS_V1
    })

# ============================================================
# END IRLT_GOVERNANCE_NEXUS_COMMAND_CORE_V1
# ============================================================

"""

text = text.replace(anchor, anchor + block)

APP.write_text(text, encoding="utf-8")

print("Governance Nexus Command Core inserted successfully.")
