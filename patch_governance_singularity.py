from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_GOVERNANCE_SINGULARITY_LAYER_V1_ACTIVE"

if MARKER in text:
    print("Governance Singularity Layer already exists.")
    raise SystemExit()

INSERT = r"""

# ============================================================
# IRLT_GOVERNANCE_SINGULARITY_LAYER_V1_ACTIVE
# ============================================================

IRLT_SINGULARITY_DOMAINS = [
    {
        "domain": "Operational Trust",
        "score": 92,
        "state": "Unified"
    },
    {
        "domain": "Inspection Survivability",
        "score": 94,
        "state": "Stable"
    },
    {
        "domain": "Governance Integrity",
        "score": 91,
        "state": "Aligned"
    },
    {
        "domain": "Evidence Coherence",
        "score": 93,
        "state": "Verified"
    },
    {
        "domain": "Commercialization Readiness",
        "score": 90,
        "state": "Controlled"
    },
    {
        "domain": "Dependency Stability",
        "score": 88,
        "state": "Monitoring"
    },
    {
        "domain": "Escalation Pressure",
        "score": 81,
        "state": "Elevated"
    },
    {
        "domain": "Operational Cognition",
        "score": 95,
        "state": "Synchronized"
    }
]


@app.route("/irlt-commercial-readiness/governance-singularity")
@app.route("/rlttrust/governance-singularity")
def irlt_governance_singularity():

    overall_score = round(
        sum(x["score"] for x in IRLT_SINGULARITY_DOMAINS)
        / len(IRLT_SINGULARITY_DOMAINS)
    )

    html = """

    <!doctype html>

    <html>

    <head>

        <title>IRLT Governance Singularity Layer</title>

        <style>

            body {
                margin:0;
                background:
                    radial-gradient(circle at top left, rgba(255,122,24,0.22), transparent 34%),
                    linear-gradient(135deg,#040507 0%,#11151f 48%,#06070b 100%);
                color:white;
                font-family:Inter,Segoe UI,Arial,sans-serif;
            }

            .wrap {
                max-width:1900px;
                margin:auto;
                padding:34px;
            }

            .hero,.panel {
                border-radius:28px;
                padding:30px;
                margin-bottom:24px;
                border:1px solid rgba(255,255,255,0.08);
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02)),
                    rgba(20,24,33,0.88);
            }

            h1 {
                margin:0 0 12px;
                font-size:78px;
                color:#ff9f1c;
                letter-spacing:-0.05em;
            }

            h2 {
                color:#ff9f1c;
                margin-top:0;
            }

            p {
                color:#b8c1cd;
                line-height:1.7;
            }

            .hero-grid {
                display:grid;
                grid-template-columns:1.2fr .8fr;
                gap:24px;
            }

            .overall {
                height:340px;
                display:flex;
                flex-direction:column;
                justify-content:center;
                align-items:center;
                border-radius:24px;
                background:
                    radial-gradient(circle, rgba(255,159,28,0.22), transparent 70%),
                    rgba(255,255,255,0.03);
                border:1px solid rgba(255,159,28,0.18);
            }

            .overall strong {
                font-size:112px;
                color:#ff9f1c;
            }

            .overall span {
                font-size:18px;
                color:#d8dee8;
            }

            .grid {
                display:grid;
                grid-template-columns:repeat(4,1fr);
                gap:18px;
                margin-top:24px;
            }

            .card {
                border-radius:18px;
                padding:20px;
                background:rgba(255,255,255,0.04);
                border:1px solid rgba(255,255,255,0.08);
            }

            .card strong {
                display:block;
                font-size:42px;
                color:#ff9f1c;
            }

            .ops-grid {
                display:grid;
                grid-template-columns:1fr 1fr;
                gap:22px;
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
                border:1px solid rgba(255,122,24,0.25);
                color:#ffd7ad;
                font-size:12px;
                font-weight:800;
            }

            .nav {
                margin-top:22px;
            }

            .nav a {
                display:inline-block;
                text-decoration:none;
                margin-right:12px;
                margin-bottom:12px;
                color:white;
                padding:12px 16px;
                border-radius:14px;
                background:rgba(255,255,255,0.05);
                border:1px solid rgba(255,122,24,0.20);
            }

            ul li {
                margin-bottom:12px;
                color:#c6cfdb;
            }

            @media (max-width:1200px) {

                .hero-grid,
                .ops-grid,
                .grid {
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

                <h1>Governance Singularity Layer</h1>

                <p>
                    Unified operational governance cognition layer for enterprise
                    radiopharma commercialization readiness, operational trust,
                    inspection survivability, governance coherence, and
                    executive defensibility intelligence.
                </p>

                <div class="nav">

                    <a href="/irlt-commercial-readiness">
                        Command Center
                    </a>

                    <a href="/irlt-commercial-readiness/control-tower">
                        Control Tower
                    </a>

                    <a href="/irlt-commercial-readiness/evidence-vault">
                        Evidence Vault
                    </a>

                    <a href="/irlt-commercial-readiness/risk-propagation">
                        Risk Propagation
                    </a>

                    <a href="/irlt-commercial-readiness/inspection-defense">
                        Inspection Defense
                    </a>

                </div>

                <div class="hero-grid">

                    <div class="panel">

                        <h2>Unified Governance Cognition Domains</h2>

                        <div class="grid">

                            {% for row in domains %}

                            <div class="card">

                                <strong>{{ row.score }}%</strong>

                                {{ row.domain }}

                                <br><br>

                                <span class="pill">
                                    {{ row.state }}
                                </span>

                            </div>

                            {% endfor %}

                        </div>

                    </div>

                    <div class="overall">

                        <strong>{{ overall_score }}%</strong>

                        <span>
                            Unified Governance Cognition State
                        </span>

                    </div>

                </div>

            </section>

            <div class="ops-grid">

                <section class="panel">

                    <h2>Operational Governance Reality Synthesis</h2>

                    <ul>

                        <li>
                            Operational governance cognition remains synchronized across commercialization domains.
                        </li>

                        <li>
                            Evidence coherence integrity remains stable under current inspection survivability conditions.
                        </li>

                        <li>
                            Governance drift exposure is currently concentrated within escalation-dependent operational pathways.
                        </li>

                        <li>
                            Commercialization readiness posture remains operationally defensible.
                        </li>

                        <li>
                            Cross-domain governance integrity remains aligned across release, lineage, and coordination layers.
                        </li>

                        <li>
                            Operational trust cognition confidence remains within enterprise readiness tolerance thresholds.
                        </li>

                        <li>
                            Escalation pressure accumulation remains observable but operationally contained.
                        </li>

                    </ul>

                </section>

                <section class="panel">

                    <h2>Unified Governance Coherence Matrix</h2>

                    <table>

                        <thead>

                            <tr>
                                <th>Governance Layer</th>
                                <th>Coherence State</th>
                                <th>Operational Impact</th>
                                <th>Confidence</th>
                            </tr>

                        </thead>

                        <tbody>

                            <tr>
                                <td>Release Governance</td>
                                <td>Aligned</td>
                                <td>Commercialization Ready</td>
                                <td><span class="pill">Strong</span></td>
                            </tr>

                            <tr>
                                <td>Inspection Defensibility</td>
                                <td>Stable</td>
                                <td>Inspection Survivable</td>
                                <td><span class="pill">Verified</span></td>
                            </tr>

                            <tr>
                                <td>Evidence Lineage</td>
                                <td>Unified</td>
                                <td>Audit Defensible</td>
                                <td><span class="pill">Controlled</span></td>
                            </tr>

                            <tr>
                                <td>Operational Trust</td>
                                <td>Synchronized</td>
                                <td>Operationally Stable</td>
                                <td><span class="pill">Strong</span></td>
                            </tr>

                            <tr>
                                <td>Governance Escalation</td>
                                <td>Elevated</td>
                                <td>Monitoring Required</td>
                                <td><span class="pill">Observed</span></td>
                            </tr>

                        </tbody>

                    </table>

                </section>

            </div>

        </div>

    </body>

    </html>

    """

    return render_template_string(
        html,
        domains=IRLT_SINGULARITY_DOMAINS,
        overall_score=overall_score
    )


@app.route("/irlt-commercial-readiness/governance-singularity/api")
@app.route("/rlttrust/governance-singularity/api")
def irlt_governance_singularity_api():

    return jsonify({
        "overall_score": round(
            sum(x["score"] for x in IRLT_SINGULARITY_DOMAINS)
            / len(IRLT_SINGULARITY_DOMAINS)
        ),
        "domains": IRLT_SINGULARITY_DOMAINS
    })

# ============================================================
# END IRLT_GOVERNANCE_SINGULARITY_LAYER
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

print("Inserted Governance Singularity Layer successfully.")
