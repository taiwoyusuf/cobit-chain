from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

old_marker = "IRLT_GOVERNANCE_SINGULARITY_SMALL_SAFE_V1"

if old_marker not in text:
    print("Could not locate small safe Singularity block.")
    raise SystemExit()

start = text.find("# ============================================================\n# IRLT_GOVERNANCE_SINGULARITY_SMALL_SAFE_V1")

end = text.find("# END IRLT_GOVERNANCE_SINGULARITY_SMALL_SAFE_V1\n# ============================================================")

if start == -1 or end == -1:
    print("Could not determine replacement boundaries.")
    raise SystemExit()

end = end + len("# END IRLT_GOVERNANCE_SINGULARITY_SMALL_SAFE_V1\n# ============================================================")

new_block = r"""

# ============================================================
# IRLT_GOVERNANCE_SINGULARITY_LAYER_V2_ACTIVE
# ============================================================

IRLT_SINGULARITY_DOMAINS_V2 = [
    {
        "domain": "Operational Trust",
        "score": 92,
        "state": "Stable"
    },
    {
        "domain": "Inspection Survivability",
        "score": 95,
        "state": "Strong"
    },
    {
        "domain": "Evidence Coherence",
        "score": 94,
        "state": "Verified"
    },
    {
        "domain": "Commercialization Readiness",
        "score": 91,
        "state": "Controlled"
    },
    {
        "domain": "Dependency Stability",
        "score": 88,
        "state": "Monitoring"
    },
    {
        "domain": "Governance Integrity",
        "score": 93,
        "state": "Aligned"
    }
]


@app.route("/irlt-commercial-readiness/governance-singularity")
def irlt_governance_singularity():

    overall_score = round(
        sum(x["score"] for x in IRLT_SINGULARITY_DOMAINS_V2)
        / len(IRLT_SINGULARITY_DOMAINS_V2)
    )

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Governance Singularity Layer</title>

        <style>

            body{
                margin:0;
                background:
                    radial-gradient(circle at top left, rgba(255,122,24,0.22), transparent 34%),
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
                font-size:76px;
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
                font-size:42px;
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

            ul li{
                margin-bottom:12px;
                color:#c6cfdb;
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

                <h1>Governance Singularity Layer</h1>

                <p>
                    Unified operational governance cognition layer for
                    enterprise radiopharma commercialization readiness,
                    operational trust assurance, inspection survivability,
                    governance coherence, and executive defensibility.
                </p>

                <div class="hero-grid">

                    <div class="panel">

                        <h2>Unified Governance Cognition Domains</h2>

                        <div class="grid">

                            {% for row in domains %}

                            <div class="card">

                                <strong>{{ row.score }}%</strong>

                                {{ row.domain }}

                                <br>

                                <span class="pill">
                                    {{ row.state }}
                                </span>

                            </div>

                            {% endfor %}

                        </div>

                    </div>

                    <div class="overall">

                        <strong>{{ overall_score }}%</strong>

                        Unified Governance State

                    </div>

                </div>

            </section>

            <div class="ops-grid">

                <section class="panel">

                    <h2>Operational Governance Cognition</h2>

                    <ul>

                        <li>
                            Operational trust posture remains stable across commercialization domains.
                        </li>

                        <li>
                            Evidence coherence remains aligned across governance pathways.
                        </li>

                        <li>
                            Inspection survivability posture remains operationally defensible.
                        </li>

                        <li>
                            Governance integrity remains synchronized across release, QA, and operational readiness domains.
                        </li>

                        <li>
                            Escalation pressure remains observable but controlled.
                        </li>

                        <li>
                            Commercialization readiness cognition remains within enterprise tolerance thresholds.
                        </li>

                    </ul>

                </section>

                <section class="panel">

                    <h2>Governance Coherence Matrix</h2>

                    <table>

                        <thead>

                            <tr>
                                <th>Governance Layer</th>
                                <th>State</th>
                                <th>Operational Impact</th>
                            </tr>

                        </thead>

                        <tbody>

                            <tr>
                                <td>Release Governance</td>
                                <td>Aligned</td>
                                <td>Commercialization Ready</td>
                            </tr>

                            <tr>
                                <td>Inspection Survivability</td>
                                <td>Stable</td>
                                <td>Inspection Defensible</td>
                            </tr>

                            <tr>
                                <td>Evidence Lineage</td>
                                <td>Verified</td>
                                <td>Audit Survivable</td>
                            </tr>

                            <tr>
                                <td>Operational Trust</td>
                                <td>Synchronized</td>
                                <td>Operationally Stable</td>
                            </tr>

                            <tr>
                                <td>Governance Escalation</td>
                                <td>Observed</td>
                                <td>Monitoring Required</td>
                            </tr>

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
        domains=IRLT_SINGULARITY_DOMAINS_V2,
        overall_score=overall_score
    )


@app.route("/irlt-commercial-readiness/governance-singularity/api")
def irlt_governance_singularity_api():

    return jsonify({
        "overall_score": round(
            sum(x["score"] for x in IRLT_SINGULARITY_DOMAINS_V2)
            / len(IRLT_SINGULARITY_DOMAINS_V2)
        ),
        "domains": IRLT_SINGULARITY_DOMAINS_V2
    })

# ============================================================
# END IRLT_GOVERNANCE_SINGULARITY_LAYER_V2
# ============================================================

"""

text = text[:start] + new_block + text[end:]

APP.write_text(text, encoding="utf-8")

print("Governance Singularity upgraded successfully.")
