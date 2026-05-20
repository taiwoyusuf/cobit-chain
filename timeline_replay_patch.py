from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_OPERATIONAL_TRUST_TIMELINE_REPLAY_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Timeline Replay Engine already exists.")
    raise SystemExit()

anchor = "# END IRLT_GOVERNANCE_PASSPORT_ORCHESTRATION_ENGINE_V1"

if anchor not in text:
    print("Could not locate safe insertion anchor.")
    raise SystemExit()

block = r"""

# ============================================================
# IRLT_OPERATIONAL_TRUST_TIMELINE_REPLAY_ENGINE_V1_ACTIVE
# ============================================================

IRLT_TIMELINE_EVENTS_V1 = [
    {
        "time": "2026-05-01",
        "event": "Commercialization Readiness Review",
        "impact": "Operational Trust Increased",
        "trust": 88
    },
    {
        "time": "2026-05-03",
        "event": "Environmental Monitoring Escalation",
        "impact": "Inspection Exposure Increased",
        "trust": 82
    },
    {
        "time": "2026-05-06",
        "event": "CAPA Governance Intervention",
        "impact": "Operational Stability Restored",
        "trust": 86
    },
    {
        "time": "2026-05-09",
        "event": "Dose Lineage Verification",
        "impact": "Audit Defensibility Improved",
        "trust": 91
    },
    {
        "time": "2026-05-12",
        "event": "Backup Governance Reconciliation",
        "impact": "Evidence Survivability Strengthened",
        "trust": 93
    },
    {
        "time": "2026-05-15",
        "event": "Shipment Coordination Validation",
        "impact": "Treatment Governance Stabilized",
        "trust": 95
    }
]


@app.route("/irlt-commercial-readiness/timeline-replay")
def irlt_timeline_replay():

    current_trust = IRLT_TIMELINE_EVENTS_V1[-1]["trust"]

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Operational Trust Timeline Replay</title>

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

            .timeline{
                margin-top:24px;
            }

            .event{
                position:relative;
                padding:24px;
                margin-bottom:18px;
                border-radius:18px;
                background:rgba(255,255,255,0.04);
                border:1px solid rgba(255,255,255,0.08);
            }

            .event:before{
                content:"";
                position:absolute;
                left:-10px;
                top:30px;
                width:20px;
                height:20px;
                border-radius:50%;
                background:#ff9f1c;
                box-shadow:0 0 18px rgba(255,159,28,0.8);
            }

            .event strong{
                display:block;
                color:#ff9f1c;
                font-size:28px;
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

                <h1>Operational Trust Timeline Replay</h1>

                <p>
                    Enterprise operational governance replay engine for
                    commercialization trust evolution,
                    inspection survivability reconstruction,
                    governance intervention analysis,
                    and operational readiness history cognition.
                </p>

                <div class="hero-grid">

                    <div class="panel">

                        <h2>Governance Timeline Evolution</h2>

                        <div class="timeline">

                            {% for row in timeline %}

                            <div class="event">

                                <strong>{{ row.event }}</strong>

                                <p>
                                    {{ row.impact }}
                                </p>

                                <span class="pill">
                                    {{ row.time }}
                                </span>

                                <span class="pill">
                                    Trust {{ row.trust }}%
                                </span>

                            </div>

                            {% endfor %}

                        </div>

                    </div>

                    <div class="overall">

                        <strong>{{ current_trust }}%</strong>

                        Operational Trust State

                    </div>

                </div>

            </section>

            <div class="ops-grid">

                <section class="panel">

                    <h2>Governance Evolution Intelligence</h2>

                    <ul>

                        <li>
                            Commercialization readiness governance evolved toward higher operational defensibility over the replay horizon.
                        </li>

                        <li>
                            Environmental governance instability created the largest temporary trust degradation event.
                        </li>

                        <li>
                            CAPA governance intervention successfully stabilized operational readiness exposure.
                        </li>

                        <li>
                            Dose lineage verification significantly strengthened audit defensibility posture.
                        </li>

                        <li>
                            Backup governance reconciliation materially improved evidence survivability confidence.
                        </li>

                        <li>
                            Shipment governance validation restored treatment coordination trust alignment.
                        </li>

                    </ul>

                </section>

                <section class="panel">

                    <h2>Operational Trust Replay Matrix</h2>

                    <table>

                        <thead>

                            <tr>
                                <th>Date</th>
                                <th>Governance Event</th>
                                <th>Impact</th>
                                <th>Trust</th>
                            </tr>

                        </thead>

                        <tbody>

                            {% for row in timeline %}

                            <tr>

                                <td>{{ row.time }}</td>

                                <td>{{ row.event }}</td>

                                <td>{{ row.impact }}</td>

                                <td>{{ row.trust }}%</td>

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
        timeline=IRLT_TIMELINE_EVENTS_V1,
        current_trust=current_trust
    )


@app.route("/irlt-commercial-readiness/timeline-replay/api")
def irlt_timeline_replay_api():

    return jsonify({
        "timeline": IRLT_TIMELINE_EVENTS_V1,
        "current_trust": IRLT_TIMELINE_EVENTS_V1[-1]["trust"]
    })

# ============================================================
# END IRLT_OPERATIONAL_TRUST_TIMELINE_REPLAY_ENGINE_V1
# ============================================================

"""

text = text.replace(anchor, anchor + block)

APP.write_text(text, encoding="utf-8")

print("Timeline Replay Engine inserted successfully.")
