from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "GOVERNANCE_TIME_NEXUS_V1_ACTIVE"

if MARKER in text:
    print("Governance Time Nexus already exists.")
    raise SystemExit()

if 'def governance_time_nexus_v1(' in text:
    print("Function already exists.")
    raise SystemExit()

INSERT = r"""

# ============================================================
# GOVERNANCE_TIME_NEXUS_V1_ACTIVE
# ============================================================

from flask import jsonify

TIME_NEXUS_EVENTS_V1 = [
    {
        "epoch": "Q1",
        "event": "Commercialization Stabilization",
        "trajectory": "Increasing",
        "survivability": 88,
        "status": "Stable"
    },
    {
        "epoch": "Q2",
        "event": "Environmental Governance Drift",
        "trajectory": "Escalating",
        "survivability": 81,
        "status": "Monitoring"
    },
    {
        "epoch": "Q3",
        "event": "Inspection Readiness Recovery",
        "trajectory": "Recovering",
        "survivability": 92,
        "status": "Operational"
    },
    {
        "epoch": "Q4",
        "event": "CAPA Pressure Accumulation",
        "trajectory": "Increasing",
        "survivability": 79,
        "status": "Attention"
    },
    {
        "epoch": "Q5",
        "event": "Enterprise Governance Synchronization",
        "trajectory": "Synchronized",
        "survivability": 95,
        "status": "Optimized"
    }
]

TIME_NEXUS_MEMORY_STREAM_V1 = [
    "Governance survivability remained commercially stable during operational escalation periods.",
    "Environmental governance degradation accumulated gradually before release defensibility destabilization.",
    "Inspection survivability recovered following governance stabilization orchestration.",
    "Operational resilience synchronization improved after continuity hardening workflows.",
    "Enterprise governance cognition remained synchronized across commercialization timelines."
]


def calculate_time_nexus_index_v1():

    total = 0

    for row in TIME_NEXUS_EVENTS_V1:
        total += row["survivability"]

    return round(total / len(TIME_NEXUS_EVENTS_V1))


@app.route("/governance/time-nexus")
def governance_time_nexus_v1():

    nexus_index = calculate_time_nexus_index_v1()

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Governance Time Nexus</title>

        <style>

            body {
                margin:0;
                overflow:hidden;
                background:
                    radial-gradient(circle at top left, rgba(255,122,24,0.18), transparent 32%),
                    radial-gradient(circle at bottom right, rgba(255,159,28,0.10), transparent 26%),
                    linear-gradient(135deg,#040507 0%,#0c1018 45%,#050608 100%);
                color:white;
                font-family:Arial,sans-serif;
            }

            .timeline-grid {
                position:fixed;
                width:100%;
                height:100%;
                opacity:0.08;
                background-image:
                    linear-gradient(rgba(255,159,28,0.16) 1px, transparent 1px),
                    linear-gradient(90deg, rgba(255,159,28,0.16) 1px, transparent 1px);
                background-size:44px 44px;
                animation:timemove 18s linear infinite;
            }

            @keyframes timemove {

                from {
                    transform:translateY(0px);
                }

                to {
                    transform:translateY(44px);
                }

            }

            .timeline-beams span {
                position:absolute;
                display:block;
                width:2px;
                height:220px;
                background:linear-gradient(
                    to bottom,
                    rgba(255,159,28,0),
                    rgba(255,159,28,0.55),
                    rgba(255,159,28,0)
                );
                animation:beamflow linear infinite;
            }

            .timeline-beams span:nth-child(1){
                left:12%;
                animation-duration:9s;
            }

            .timeline-beams span:nth-child(2){
                left:28%;
                animation-duration:11s;
            }

            .timeline-beams span:nth-child(3){
                left:48%;
                animation-duration:8s;
            }

            .timeline-beams span:nth-child(4){
                left:70%;
                animation-duration:12s;
            }

            .timeline-beams span:nth-child(5){
                left:88%;
                animation-duration:10s;
            }

            @keyframes beamflow {

                0% {
                    top:-240px;
                    opacity:0;
                }

                20% {
                    opacity:1;
                }

                100% {
                    top:120%;
                    opacity:0;
                }

            }

            .chrono-orbs span {
                position:absolute;
                display:block;
                border-radius:50%;
                background:rgba(255,159,28,0.20);
                box-shadow:0 0 30px rgba(255,159,28,0.35);
                animation:orbitpulse linear infinite;
            }

            .chrono-orbs span:nth-child(1){
                width:14px;
                height:14px;
                left:10%;
                top:88%;
                animation-duration:20s;
            }

            .chrono-orbs span:nth-child(2){
                width:22px;
                height:22px;
                left:30%;
                top:92%;
                animation-duration:26s;
            }

            .chrono-orbs span:nth-child(3){
                width:16px;
                height:16px;
                left:54%;
                top:90%;
                animation-duration:22s;
            }

            .chrono-orbs span:nth-child(4){
                width:28px;
                height:28px;
                left:76%;
                top:95%;
                animation-duration:30s;
            }

            .chrono-orbs span:nth-child(5){
                width:18px;
                height:18px;
                left:92%;
                top:86%;
                animation-duration:24s;
            }

            @keyframes orbitpulse {

                0% {
                    transform:translateY(0px) scale(1);
                    opacity:0;
                }

                20% {
                    opacity:1;
                }

                50% {
                    transform:translateY(-420px) scale(1.45);
                }

                100% {
                    transform:translateY(-920px) scale(0.7);
                    opacity:0;
                }

            }

            .wrap {
                position:relative;
                z-index:2;
                max-width:1980px;
                margin:auto;
                padding:34px;
                height:100vh;
                overflow-y:auto;
            }

            .hero,.panel {
                position:relative;
                overflow:hidden;
                border-radius:30px;
                padding:30px;
                margin-bottom:24px;
                border:1px solid rgba(255,255,255,0.08);
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.015)),
                    rgba(20,24,33,0.82);
                backdrop-filter:blur(12px);
            }

            .hero:before,
            .panel:before {
                content:'';
                position:absolute;
                width:220%;
                height:220%;
                top:-60%;
                left:-60%;
                background:
                    radial-gradient(circle, rgba(255,159,28,0.08), transparent 60%);
                animation:timefield 32s linear infinite;
            }

            @keyframes timefield {

                from {
                    transform:rotate(0deg);
                }

                to {
                    transform:rotate(360deg);
                }

            }

            .hero *,
            .panel * {
                position:relative;
                z-index:2;
            }

            h1 {
                margin:0 0 12px;
                font-size:84px;
                color:#ff9f1c;
                letter-spacing:-3px;
                text-shadow:0 0 28px rgba(255,159,28,0.25);
            }

            h2 {
                color:#ff9f1c;
            }

            p {
                color:#b4bcc9;
                line-height:1.8;
            }

            .overall {
                margin-top:28px;
                text-align:center;
                padding:30px;
                border-radius:24px;
                background:rgba(255,255,255,0.04);
            }

            .overall strong {
                display:block;
                font-size:150px;
                color:#ff9f1c;
                text-shadow:0 0 35px rgba(255,159,28,0.35);
            }

            .timeline-cards {
                display:grid;
                grid-template-columns:repeat(2,1fr);
                gap:24px;
                margin-top:24px;
            }

            .timeline-card {
                position:relative;
                overflow:hidden;
                border-radius:24px;
                padding:26px;
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02)),
                    rgba(255,255,255,0.03);
                border:1px solid rgba(255,255,255,0.08);
            }

            .timeline-card:after {
                content:'';
                position:absolute;
                width:180%;
                height:180%;
                top:-40%;
                left:-40%;
                background:
                    radial-gradient(circle, rgba(255,159,28,0.08), transparent 65%);
                animation:chronofield 20s linear infinite;
            }

            @keyframes chronofield {

                from {
                    transform:rotate(0deg);
                }

                to {
                    transform:rotate(-360deg);
                }

            }

            .timeline-card * {
                position:relative;
                z-index:2;
            }

            .timeline-card strong {
                display:block;
                font-size:54px;
                color:#ff9f1c;
                margin-bottom:12px;
            }

            .pill {
                display:inline-block;
                padding:8px 14px;
                border-radius:999px;
                background:rgba(255,122,24,0.12);
                border:1px solid rgba(255,122,24,0.24);
                color:#ffd7ad;
                font-size:12px;
                font-weight:800;
                margin-top:12px;
                margin-right:10px;
            }

            table {
                width:100%;
                border-collapse:collapse;
                margin-top:24px;
            }

            th,td {
                padding:15px;
                border-bottom:1px solid rgba(255,255,255,0.08);
                text-align:left;
            }

            th {
                color:#ff9f1c;
                text-transform:uppercase;
                font-size:12px;
            }

            @media (max-width:1200px) {

                .timeline-cards {
                    grid-template-columns:1fr;
                }

                h1 {
                    font-size:46px;
                }

                .overall strong {
                    font-size:92px;
                }

            }

        </style>

    </head>

    <body>

        <div class="timeline-grid"></div>

        <div class="timeline-beams">
            <span></span>
            <span></span>
            <span></span>
            <span></span>
            <span></span>
        </div>

        <div class="chrono-orbs">
            <span></span>
            <span></span>
            <span></span>
            <span></span>
            <span></span>
        </div>

        <div class="wrap">

            <section class="hero">

                <h1>Governance Time Nexus</h1>

                <p>
                    Enterprise temporal governance intelligence infrastructure
                    for survivability chronology awareness,
                    governance evolution cognition,
                    commercialization trajectory intelligence,
                    and operational governance memory orchestration.
                </p>

                <div class="overall">

                    <strong>{{ nexus_index }}%</strong>

                    Enterprise Temporal Governance Index

                </div>

            </section>

            <section class="panel">

                <h2>Governance Evolution Timeline</h2>

                <div class="timeline-cards">

                    {% for row in events %}

                    <div class="timeline-card">

                        <strong>{{ row.survivability }}%</strong>

                        <h3>{{ row.event }}</h3>

                        <p>
                            Governance Epoch:
                            {{ row.epoch }}
                        </p>

                        <span class="pill">
                            Trajectory: {{ row.trajectory }}
                        </span>

                        <span class="pill">
                            Status: {{ row.status }}
                        </span>

                    </div>

                    {% endfor %}

                </div>

            </section>

            <section class="panel">

                <h2>Enterprise Governance Memory Streams</h2>

                <table>

                    <thead>

                        <tr>
                            <th>Temporal Cognition Stream</th>
                            <th>Enterprise Interpretation</th>
                        </tr>

                    </thead>

                    <tbody>

                        {% for item in memory %}

                        <tr>

                            <td>{{ item }}</td>

                            <td>Temporal governance intelligence</td>

                        </tr>

                        {% endfor %}

                    </tbody>

                </table>

            </section>

            <section class="panel">

                <h2>Governance Time Nexus Vision</h2>

                <p>
                    The Governance Time Nexus enables enterprise temporal
                    governance cognition across all COBIT-Chain AssuranceLayer
                    operational verticals.
                </p>

                <p>
                    This architecture supports:
                </p>

                <ul>

                    <li>Governance timeline intelligence</li>

                    <li>Operational survivability chronology</li>

                    <li>Commercialization trajectory cognition</li>

                    <li>Governance memory orchestration</li>

                    <li>Temporal stabilization awareness</li>

                    <li>Inspection evolution intelligence</li>

                    <li>Enterprise governance chronology mapping</li>

                    <li>Temporal governance intelligence infrastructure</li>

                </ul>

            </section>

        </div>

    </body>

    </html>

    '''

    return render_template_string(
        html,
        events=TIME_NEXUS_EVENTS_V1,
        memory=TIME_NEXUS_MEMORY_STREAM_V1,
        nexus_index=nexus_index
    )


@app.route("/governance/time-nexus/api")
def governance_time_nexus_api_v1():

    return jsonify({
        "nexus_index": calculate_time_nexus_index_v1(),
        "events": TIME_NEXUS_EVENTS_V1,
        "memory": TIME_NEXUS_MEMORY_STREAM_V1
    })

# ============================================================
# END GOVERNANCE_TIME_NEXUS_V1
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

print("Inserted Governance Time Nexus successfully.")
