from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_OPERATIONAL_TRUST_CONTROL_TOWER_V1_ACTIVE"

if MARKER in text:
    print("IRLT Operational Trust Control Tower already exists.")
    raise SystemExit()

INSERT = r"""

# ============================================================
# IRLT_OPERATIONAL_TRUST_CONTROL_TOWER_V1_ACTIVE
# ============================================================

IRLT_CONTROL_TOWER_KPIS = [
    {
        "domain": "Release Defensibility",
        "score": 92,
        "status": "Strong"
    },
    {
        "domain": "Dose Lineage",
        "score": 95,
        "status": "Verified"
    },
    {
        "domain": "Environmental Monitoring",
        "score": 88,
        "status": "Review"
    },
    {
        "domain": "CAPA Risk",
        "score": 81,
        "status": "Attention"
    },
    {
        "domain": "Inspection Survivability",
        "score": 93,
        "status": "Ready"
    },
    {
        "domain": "Access Governance",
        "score": 89,
        "status": "Controlled"
    },
    {
        "domain": "Backup Governance",
        "score": 84,
        "status": "Review"
    },
    {
        "domain": "Operational Trust",
        "score": 91,
        "status": "Strong"
    }
]


@app.route("/irlt-commercial-readiness/control-tower")
@app.route("/rlttrust/control-tower")
def irlt_operational_trust_control_tower():

    overall_score = round(
        sum(x["score"] for x in IRLT_CONTROL_TOWER_KPIS)
        / len(IRLT_CONTROL_TOWER_KPIS)
    )

    html = """

    <!doctype html>

    <html>

    <head>

        <title>IRLT Operational Trust Control Tower</title>

        <style>

            body {
                margin:0;
                background:
                    radial-gradient(circle at top left, rgba(255,122,24,0.20), transparent 34%),
                    linear-gradient(135deg,#050608 0%,#11151f 48%,#06070b 100%);
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
                padding:28px;
                margin-bottom:24px;
                border:1px solid rgba(255,255,255,0.08);
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02)),
                    rgba(20,24,33,0.88);
            }

            h1 {
                margin:0 0 12px;
                font-size:76px;
                color:#ff9f1c;
                letter-spacing:-0.05em;
            }

            h2 {
                color:#ff9f1c;
                margin-top:0;
            }

            p {
                color:#b4bcc9;
                line-height:1.7;
            }

            .hero-grid {
                display:grid;
                grid-template-columns:1.2fr .8fr;
                gap:24px;
            }

            .overall {
                height:320px;
                display:flex;
                flex-direction:column;
                align-items:center;
                justify-content:center;
                border-radius:24px;
                background:
                    radial-gradient(circle, rgba(255,159,28,0.22), transparent 70%),
                    rgba(255,255,255,0.03);
                border:1px solid rgba(255,159,28,0.16);
            }

            .overall strong {
                font-size:108px;
                color:#ff9f1c;
            }

            .overall span {
                font-size:18px;
                color:#d5dce8;
            }

            .kpi-grid {
                display:grid;
                grid-template-columns:repeat(4,1fr);
                gap:18px;
                margin-top:26px;
            }

            .kpi {
                padding:20px;
                border-radius:18px;
                background:rgba(255,255,255,0.04);
                border:1px solid rgba(255,255,255,0.08);
            }

            .kpi strong {
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
                .kpi-grid {
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

                <h1>IRLT Operational Trust Control Tower</h1>

                <p>
                    Executive commercialization readiness cockpit for radiopharma governance,
                    operational trust assurance, inspection survivability, release defensibility,
                    dose lineage integrity, and enterprise governance orchestration.
                </p>

                <div class="nav">

                    <a href="/irlt-commercial-readiness">
                        Command Center
                    </a>

                    <a href="/irlt-commercial-readiness/evidence-vault">
                        Evidence Vault
                    </a>

                    <a href="/irlt-commercial-readiness/passport-factory">
                        Passport Factory
                    </a>

                    <a href="/irlt-commercial-readiness/release-defensibility">
                        Release Defensibility
                    </a>

                    <a href="/irlt-commercial-readiness/inspection-tomorrow">
                        Inspection Readiness
                    </a>

                </div>

                <div class="hero-grid">

                    <div class="panel">

                        <h2>Operational Governance Domains</h2>

                        <div class="kpi-grid">

                            {% for row in kpis %}

                            <div class="kpi">

                                <strong>{{ row.score }}%</strong>

                                {{ row.domain }}

                                <br><br>

                                <span class="pill">
                                    {{ row.status }}
                                </span>

                            </div>

                            {% endfor %}

                        </div>

                    </div>

                    <div class="overall">

                        <strong>{{ overall_score }}%</strong>

                        <span>
                            Enterprise Operational Trust Score
                        </span>

                    </div>

                </div>

            </section>

            <div class="ops-grid">

                <section class="panel">

                    <h2>Executive Governance Intelligence</h2>

                    <ul>

                        <li>
                            Release governance readiness remains operationally defensible.
                        </li>

                        <li>
                            Dose lineage integrity is fully traceable from isotope preparation to treatment coordination.
                        </li>

                        <li>
                            Inspection survivability posture is stable but dependent on CAPA closure velocity.
                        </li>

                        <li>
                            Environmental monitoring governance remains partially dependent on unresolved escalation review.
                        </li>

                        <li>
                            Backup governance maturity improved after recent evidence reconciliation validation.
                        </li>

                        <li>
                            Access governance alignment remains within acceptable commercialization thresholds.
                        </li>

                        <li>
                            Operational trust posture supports controlled commercialization scale-up readiness.
                        </li>

                    </ul>

                </section>

                <section class="panel">

                    <h2>Dependency Propagation Matrix</h2>

                    <table>

                        <thead>

                            <tr>
                                <th>Dependency</th>
                                <th>Current Risk</th>
                                <th>Impact Area</th>
                                <th>Status</th>
                            </tr>

                        </thead>

                        <tbody>

                            <tr>
                                <td>CAPA Closure Lag</td>
                                <td>Medium</td>
                                <td>Inspection Readiness</td>
                                <td><span class="pill">Monitoring</span></td>
                            </tr>

                            <tr>
                                <td>Environmental Review Delay</td>
                                <td>Moderate</td>
                                <td>Release Governance</td>
                                <td><span class="pill">Escalated</span></td>
                            </tr>

                            <tr>
                                <td>Training Recertification Window</td>
                                <td>Low</td>
                                <td>Operational Readiness</td>
                                <td><span class="pill">Controlled</span></td>
                            </tr>

                            <tr>
                                <td>Shipment Coordination Alignment</td>
                                <td>Low</td>
                                <td>Treatment Coordination</td>
                                <td><span class="pill">Stable</span></td>
                            </tr>

                            <tr>
                                <td>Radioactive Material Governance</td>
                                <td>Low</td>
                                <td>Audit Defensibility</td>
                                <td><span class="pill">Verified</span></td>
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
        kpis=IRLT_CONTROL_TOWER_KPIS,
        overall_score=overall_score
    )


@app.route("/irlt-commercial-readiness/control-tower/api")
@app.route("/rlttrust/control-tower/api")
def irlt_control_tower_api():

    return jsonify({
        "overall_score": round(
            sum(x["score"] for x in IRLT_CONTROL_TOWER_KPIS)
            / len(IRLT_CONTROL_TOWER_KPIS)
        ),
        "domains": IRLT_CONTROL_TOWER_KPIS
    })

# ============================================================
# END IRLT_OPERATIONAL_TRUST_CONTROL_TOWER
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

print("Inserted IRLT Operational Trust Control Tower successfully.")
