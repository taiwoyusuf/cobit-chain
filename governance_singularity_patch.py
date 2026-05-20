from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_GOVERNANCE_SINGULARITY_ENGINE_V2_ACTIVE"

if MARKER in text:
    print("Governance Singularity Engine already exists.")
    raise SystemExit()

anchor = "# END IRLT_AUTONOMOUS_GOVERNANCE_REASONING_ENGINE_V1"

if anchor not in text:
    print("Could not locate safe insertion anchor.")
    raise SystemExit()

block = r"""

# ============================================================
# IRLT_GOVERNANCE_SINGULARITY_ENGINE_V2_ACTIVE
# ============================================================

IRLT_SINGULARITY_STREAMS_V2 = [
    {
        "domain": "Commercialization Governance",
        "fusion": "Unified Operational Readiness",
        "stability": 96,
        "state": "Converged"
    },
    {
        "domain": "Inspection Survivability",
        "fusion": "Enterprise Audit Defense",
        "stability": 95,
        "state": "Protected"
    },
    {
        "domain": "Dose Traceability",
        "fusion": "Patient Trust Continuity",
        "stability": 99,
        "state": "Verified"
    },
    {
        "domain": "Evidence Integrity",
        "fusion": "Immutable Governance Lineage",
        "stability": 97,
        "state": "Certified"
    },
    {
        "domain": "CAPA Governance",
        "fusion": "Escalation Stabilization",
        "stability": 81,
        "state": "Observed"
    },
    {
        "domain": "Cold Chain Assurance",
        "fusion": "Treatment Coordination Stability",
        "stability": 92,
        "state": "Aligned"
    }
]


@app.route("/irlt-commercial-readiness/governance-singularity")
def irlt_governance_singularity():

    singularity_score = round(
        sum(x["stability"] for x in IRLT_SINGULARITY_STREAMS_V2)
        / len(IRLT_SINGULARITY_STREAMS_V2)
    )

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Governance Singularity Engine</title>

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

                <h1>Governance Singularity</h1>

                <p>
                    Enterprise governance convergence engine for
                    operational trust unification,
                    commercialization survivability synchronization,
                    evidence integrity convergence,
                    and inspection defense orchestration.
                </p>

                <div class="hero-grid">

                    <div class="panel">

                        <h2>Governance Convergence Domains</h2>

                        <div class="grid">

                            {% for row in streams %}

                            <div class="card">

                                <strong>{{ row.stability }}%</strong>

                                {{ row.domain }}

                                <br>

                                <span class="pill">
                                    {{ row.state }}
                                </span>

                                <br><br>

                                <small style="color:#b8c1cd;">
                                    {{ row.fusion }}
                                </small>

                            </div>

                            {% endfor %}

                        </div>

                    </div>

                    <div class="overall">

                        <strong>{{ singularity_score }}%</strong>

                        Governance Convergence

                    </div>

                </div>

            </section>

            <div class="ops-grid">

                <section class="panel">

                    <h2>Governance Convergence Intelligence</h2>

                    <ul>

                        <li>
                            Dose traceability governance remains the strongest enterprise convergence anchor.
                        </li>

                        <li>
                            Evidence integrity convergence remains highly aligned with audit survivability expectations.
                        </li>

                        <li>
                            Commercialization governance synchronization remains operationally defensible under projected scale conditions.
                        </li>

                        <li>
                            CAPA governance convergence remains the primary operational instability vector.
                        </li>

                        <li>
                            Cold-chain governance continuity remains commercially stable across treatment coordination pathways.
                        </li>

                        <li>
                            Governance singularity cognition remains synchronized with enterprise operational trust objectives.
                        </li>

                    </ul>

                </section>

                <section class="panel">

                    <h2>Governance Singularity Matrix</h2>

                    <table>

                        <thead>

                            <tr>
                                <th>Governance Domain</th>
                                <th>Fusion Layer</th>
                                <th>Stability</th>
                                <th>State</th>
                            </tr>

                        </thead>

                        <tbody>

                            {% for row in streams %}

                            <tr>

                                <td>{{ row.domain }}</td>

                                <td>{{ row.fusion }}</td>

                                <td>{{ row.stability }}%</td>

                                <td>{{ row.state }}</td>

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
        streams=IRLT_SINGULARITY_STREAMS_V2,
        singularity_score=singularity_score
    )


@app.route("/irlt-commercial-readiness/governance-singularity/api")
def irlt_governance_singularity_api():

    return jsonify({
        "singularity_score": round(
            sum(x["stability"] for x in IRLT_SINGULARITY_STREAMS_V2)
            / len(IRLT_SINGULARITY_STREAMS_V2)
        ),
        "streams": IRLT_SINGULARITY_STREAMS_V2
    })

# ============================================================
# END IRLT_GOVERNANCE_SINGULARITY_ENGINE_V2
# ============================================================

"""

text = text.replace(anchor, anchor + block)

APP.write_text(text, encoding="utf-8")

print("Governance Singularity Engine inserted successfully.")
