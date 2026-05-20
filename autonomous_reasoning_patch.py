from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_AUTONOMOUS_GOVERNANCE_REASONING_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Autonomous Governance Reasoning Engine already exists.")
    raise SystemExit()

anchor = "# END IRLT_GOVERNANCE_NEXUS_COMMAND_CORE_V1"

if anchor not in text:
    print("Could not locate safe insertion anchor.")
    raise SystemExit()

block = r"""

# ============================================================
# IRLT_AUTONOMOUS_GOVERNANCE_REASONING_ENGINE_V1_ACTIVE
# ============================================================

IRLT_REASONING_STREAMS_V1 = [
    {
        "signal": "Environmental Monitoring Drift",
        "reasoning": "Potential inspection exposure propagation detected",
        "confidence": 91,
        "state": "Escalating"
    },
    {
        "signal": "CAPA Closure Delay",
        "reasoning": "Commercial release defensibility degradation risk increasing",
        "confidence": 94,
        "state": "Critical"
    },
    {
        "signal": "Dose Traceability Alignment",
        "reasoning": "Operational trust survivability remains stable",
        "confidence": 98,
        "state": "Verified"
    },
    {
        "signal": "Cold Chain Stability",
        "reasoning": "Treatment continuity risk remains controlled",
        "confidence": 89,
        "state": "Stable"
    },
    {
        "signal": "Evidence Integrity Validation",
        "reasoning": "Audit survivability confidence remains strong",
        "confidence": 96,
        "state": "Protected"
    },
    {
        "signal": "Access Governance Drift",
        "reasoning": "Privileged governance exposure becoming observable",
        "confidence": 83,
        "state": "Observed"
    }
]


@app.route("/irlt-commercial-readiness/autonomous-reasoning")
def irlt_autonomous_reasoning():

    reasoning_score = round(
        sum(x["confidence"] for x in IRLT_REASONING_STREAMS_V1)
        / len(IRLT_REASONING_STREAMS_V1)
    )

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Autonomous Governance Reasoning Engine</title>

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

            .reasoning{
                margin-top:18px;
                padding:22px;
                border-radius:18px;
                background:rgba(255,255,255,0.04);
                border:1px solid rgba(255,255,255,0.08);
            }

            .reasoning strong{
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

                <h1>Autonomous Governance Reasoning</h1>

                <p>
                    Enterprise governance cognition and reasoning intelligence
                    layer for commercialization survivability prediction,
                    inspection exposure reasoning,
                    operational trust inference,
                    and governance escalation analysis.
                </p>

                <div class="hero-grid">

                    <div class="panel">

                        <h2>Governance Reasoning Streams</h2>

                        {% for row in reasoning %}

                        <div class="reasoning">

                            <strong>{{ row.signal }}</strong>

                            <p>
                                {{ row.reasoning }}
                            </p>

                            <span class="pill">
                                Confidence {{ row.confidence }}%
                            </span>

                            <span class="pill">
                                {{ row.state }}
                            </span>

                        </div>

                        {% endfor %}

                    </div>

                    <div class="overall">

                        <strong>{{ reasoning_score }}%</strong>

                        Governance Cognition

                    </div>

                </div>

            </section>

            <div class="ops-grid">

                <section class="panel">

                    <h2>Governance Reasoning Intelligence</h2>

                    <ul>

                        <li>
                            CAPA governance deterioration remains the strongest projected release defensibility destabilizer.
                        </li>

                        <li>
                            Environmental monitoring drift continues propagating inspection survivability exposure.
                        </li>

                        <li>
                            Dose lineage reasoning confirms strong operational trust preservation pathways.
                        </li>

                        <li>
                            Evidence survivability cognition remains highly aligned with audit defense expectations.
                        </li>

                        <li>
                            Access governance drift remains observable but commercially survivable.
                        </li>

                        <li>
                            Autonomous governance reasoning remains synchronized with enterprise commercialization objectives.
                        </li>

                    </ul>

                </section>

                <section class="panel">

                    <h2>Governance Reasoning Matrix</h2>

                    <table>

                        <thead>

                            <tr>
                                <th>Signal</th>
                                <th>Reasoning</th>
                                <th>Confidence</th>
                                <th>State</th>
                            </tr>

                        </thead>

                        <tbody>

                            {% for row in reasoning %}

                            <tr>

                                <td>{{ row.signal }}</td>

                                <td>{{ row.reasoning }}</td>

                                <td>{{ row.confidence }}%</td>

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
        reasoning=IRLT_REASONING_STREAMS_V1,
        reasoning_score=reasoning_score
    )


@app.route("/irlt-commercial-readiness/autonomous-reasoning/api")
def irlt_autonomous_reasoning_api():

    return jsonify({
        "reasoning_score": round(
            sum(x["confidence"] for x in IRLT_REASONING_STREAMS_V1)
            / len(IRLT_REASONING_STREAMS_V1)
        ),
        "reasoning": IRLT_REASONING_STREAMS_V1
    })

# ============================================================
# END IRLT_AUTONOMOUS_GOVERNANCE_REASONING_ENGINE_V1
# ============================================================

"""

text = text.replace(anchor, anchor + block)

APP.write_text(text, encoding="utf-8")

print("Autonomous Governance Reasoning Engine inserted successfully.")
