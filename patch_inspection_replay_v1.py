from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "GOVERNANCE_INSPECTION_REPLAY_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Governance Inspection Replay Engine already exists.")
    raise SystemExit()

if 'def governance_inspection_replay_engine_v1(' in text:
    print("Function already exists.")
    raise SystemExit()

INSERT = r"""

# ============================================================
# GOVERNANCE_INSPECTION_REPLAY_ENGINE_V1_ACTIVE
# ============================================================

from flask import jsonify

INSPECTION_REPLAY_EVENTS_V1 = [
    {
        "timestamp": "2026-05-10 08:15",
        "event": "Environmental Monitoring Alert Triggered",
        "actor": "QC Operations",
        "evidence": "EM Review Packet",
        "governance_status": "Escalated"
    },
    {
        "timestamp": "2026-05-10 09:40",
        "event": "CAPA Investigation Opened",
        "actor": "Quality Assurance",
        "evidence": "CAPA Evidence Bundle",
        "governance_status": "Under Review"
    },
    {
        "timestamp": "2026-05-10 11:05",
        "event": "Governance Evidence Reconciliation",
        "actor": "Compliance Governance",
        "evidence": "Evidence Integrity Validation",
        "governance_status": "Validated"
    },
    {
        "timestamp": "2026-05-10 13:10",
        "event": "Release Defensibility Review",
        "actor": "Release Governance",
        "evidence": "Release Decision Packet",
        "governance_status": "Approved"
    },
    {
        "timestamp": "2026-05-10 14:45",
        "event": "Commercialization Readiness Confirmation",
        "actor": "Executive Governance",
        "evidence": "Operational Readiness Passport",
        "governance_status": "Operationally Defensible"
    }
]


def calculate_replay_defensibility_score_v1():

    return 94


@app.route("/governance/inspection-replay")
def governance_inspection_replay_engine_v1():

    replay_score = calculate_replay_defensibility_score_v1()

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Governance Inspection Replay Engine</title>

        <style>

            body {
                margin:0;
                background:
                    radial-gradient(circle at top left, rgba(255,122,24,0.18), transparent 34%),
                    linear-gradient(135deg,#050608 0%,#11151f 48%,#06070b 100%);
                color:white;
                font-family:Arial,sans-serif;
            }

            .wrap {
                max-width:1980px;
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
            }

            h2 {
                color:#ff9f1c;
            }

            p {
                color:#b4bcc9;
                line-height:1.7;
            }

            .overall {
                margin-top:24px;
                text-align:center;
                padding:26px;
                border-radius:22px;
                background:rgba(255,255,255,0.04);
            }

            .overall strong {
                display:block;
                font-size:130px;
                color:#ff9f1c;
            }

            .timeline {
                position:relative;
                margin-top:24px;
                padding-left:40px;
            }

            .timeline:before {
                content:'';
                position:absolute;
                left:15px;
                top:0;
                bottom:0;
                width:3px;
                background:#ff9f1c;
            }

            .event {
                position:relative;
                margin-bottom:28px;
                padding:22px;
                border-radius:20px;
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02)),
                    rgba(255,255,255,0.03);
                border:1px solid rgba(255,255,255,0.08);
            }

            .event:before {
                content:'';
                position:absolute;
                left:-33px;
                top:28px;
                width:18px;
                height:18px;
                border-radius:50%;
                background:#ff9f1c;
            }

            .event strong {
                display:block;
                font-size:24px;
                color:#ff9f1c;
                margin-bottom:10px;
            }

            .pill {
                display:inline-block;
                padding:7px 12px;
                border-radius:999px;
                background:rgba(255,122,24,0.12);
                border:1px solid rgba(255,122,24,0.24);
                color:#ffd7ad;
                font-size:12px;
                font-weight:800;
                margin-top:14px;
            }

            table {
                width:100%;
                border-collapse:collapse;
                margin-top:24px;
            }

            th,td {
                padding:14px;
                border-bottom:1px solid rgba(255,255,255,0.08);
                text-align:left;
            }

            th {
                color:#ff9f1c;
                text-transform:uppercase;
                font-size:12px;
            }

            ul li {
                margin-bottom:14px;
                color:#c6cfdb;
            }

            @media (max-width:1200px) {

                h1 {
                    font-size:44px;
                }

            }

        </style>

    </head>

    <body>

        <div class="wrap">

            <section class="hero">

                <h1>Governance Inspection Replay Engine</h1>

                <p>
                    Inspection survivability replay and operational governance
                    reconstruction infrastructure for audit defensibility,
                    evidence provenance playback, and commercialization traceability intelligence.
                </p>

                <div class="overall">

                    <strong>{{ replay_score }}%</strong>

                    Inspection Replay Defensibility Score

                </div>

            </section>

            <section class="panel">

                <h2>Operational Governance Replay Timeline</h2>

                <div class="timeline">

                    {% for row in events %}

                    <div class="event">

                        <strong>{{ row.event }}</strong>

                        <p>
                            Timestamp:
                            {{ row.timestamp }}
                        </p>

                        <p>
                            Governance Actor:
                            {{ row.actor }}
                        </p>

                        <p>
                            Evidence Source:
                            {{ row.evidence }}
                        </p>

                        <span class="pill">
                            {{ row.governance_status }}
                        </span>

                    </div>

                    {% endfor %}

                </div>

            </section>

            <section class="panel">

                <h2>Inspection Replay Intelligence Matrix</h2>

                <table>

                    <thead>

                        <tr>
                            <th>Capability</th>
                            <th>Purpose</th>
                            <th>Strategic Value</th>
                        </tr>

                    </thead>

                    <tbody>

                        <tr>
                            <td>Governance Reconstruction</td>
                            <td>Replay operational governance history</td>
                            <td>Inspection survivability</td>
                        </tr>

                        <tr>
                            <td>Evidence Playback</td>
                            <td>Reconstruct evidence lineage pathways</td>
                            <td>Audit defensibility</td>
                        </tr>

                        <tr>
                            <td>Approval Replay</td>
                            <td>Replay governance approval decisions</td>
                            <td>Operational traceability</td>
                        </tr>

                        <tr>
                            <td>Operational Storyline Reconstruction</td>
                            <td>Narrate inspection-grade governance history</td>
                            <td>Executive audit readiness</td>
                        </tr>

                        <tr>
                            <td>Governance Provenance Playback</td>
                            <td>Replay operational provenance pathways</td>
                            <td>Enterprise trust assurance</td>
                        </tr>

                    </tbody>

                </table>

            </section>

            <section class="panel">

                <h2>Enterprise Inspection Replay Vision</h2>

                <p>
                    The Governance Inspection Replay Engine enables operational
                    governance replay intelligence across all COBIT-Chain
                    AssuranceLayer operational verticals.
                </p>

                <p>
                    This architecture supports:
                </p>

                <ul>

                    <li>Inspection replay orchestration</li>

                    <li>Operational governance reconstruction</li>

                    <li>Evidence lineage playback</li>

                    <li>Approval chain replay</li>

                    <li>Audit storyline intelligence</li>

                    <li>Governance provenance reconstruction</li>

                    <li>Operational defensibility replay</li>

                    <li>Enterprise inspection survivability intelligence</li>

                </ul>

            </section>

        </div>

    </body>

    </html>

    '''

    return render_template_string(
        html,
        events=INSPECTION_REPLAY_EVENTS_V1,
        replay_score=replay_score
    )


@app.route("/governance/inspection-replay/api")
def governance_inspection_replay_api_v1():

    return jsonify({
        "replay_score": calculate_replay_defensibility_score_v1(),
        "events": INSPECTION_REPLAY_EVENTS_V1
    })

# ============================================================
# END GOVERNANCE_INSPECTION_REPLAY_ENGINE_V1
# ============================================================

"""

needle = '\nif __name__ == "__main__":'

if needle not in text:
    needle = "\nif __name__ == '__main__':"

if needle not in text:
    raise RuntimeError("Could not find Flask entry point.")

text = text.replace(
    needle,
    "\n" + INSERT + "\n" + needle,
    1
)

APP.write_text(text, encoding="utf-8")

print("Inserted Governance Inspection Replay Engine successfully.")
