from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "GOVERNANCE_AUTONOMOUS_MISSION_CONTROL_V1_ACTIVE"

if MARKER in text:
    print("Governance Autonomous Mission Control already exists.")
    raise SystemExit()

if 'def governance_mission_control_v1(' in text:
    print("Function already exists.")
    raise SystemExit()

INSERT = r"""

# ============================================================
# GOVERNANCE_AUTONOMOUS_MISSION_CONTROL_V1_ACTIVE
# ============================================================

from flask import jsonify

MISSION_CONTROL_SIGNALS_V1 = [
    {
        "command_domain": "Commercialization Continuity",
        "command_strength": 97,
        "intervention": "Synchronized",
        "priority": "Critical",
        "status": "Operational"
    },
    {
        "command_domain": "Inspection Survivability",
        "command_strength": 92,
        "intervention": "Adaptive",
        "priority": "High",
        "status": "Resilient"
    },
    {
        "command_domain": "Governance Stabilization",
        "command_strength": 86,
        "intervention": "Deploying",
        "priority": "Elevated",
        "status": "Monitoring"
    },
    {
        "command_domain": "Operational Continuity",
        "command_strength": 95,
        "intervention": "Aligned",
        "priority": "Critical",
        "status": "Stable"
    },
    {
        "command_domain": "Enterprise Trust Synchronization",
        "command_strength": 94,
        "intervention": "Converging",
        "priority": "Strategic",
        "status": "Unified"
    }
]

MISSION_CONTROL_STREAMS_V1 = [
    "Commercialization continuity command streams remain operationally synchronized.",
    "Governance stabilization deployments are reducing survivability turbulence exposure.",
    "Inspection survivability interventions remain strategically resilient.",
    "Operational continuity orchestration remains aligned across enterprise pathways.",
    "Enterprise governance command harmonics remain commercially stable."
]


def calculate_mission_control_index_v1():

    total = 0

    for row in MISSION_CONTROL_SIGNALS_V1:
        total += row["command_strength"]

    return round(total / len(MISSION_CONTROL_SIGNALS_V1))


@app.route("/governance/mission-control")
def governance_mission_control_v1():

    mission_index = calculate_mission_control_index_v1()

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Governance Autonomous Mission Control</title>

        <style>

            body {
                margin:0;
                overflow:hidden;
                background:
                    radial-gradient(circle at center, rgba(255,159,28,0.16), transparent 18%),
                    radial-gradient(circle at top left, rgba(255,122,24,0.10), transparent 28%),
                    radial-gradient(circle at bottom right, rgba(255,159,28,0.08), transparent 24%),
                    linear-gradient(135deg,#010203 0%,#070b12 45%,#020304 100%);
                color:white;
                font-family:Arial,sans-serif;
            }

            .command-grid {
                position:fixed;
                width:100%;
                height:100%;
                opacity:0.06;
                background-image:
                    linear-gradient(rgba(255,159,28,0.12) 1px, transparent 1px),
                    linear-gradient(90deg, rgba(255,159,28,0.12) 1px, transparent 1px);
                background-size:56px 56px;
                animation:gridflow 26s linear infinite;
            }

            @keyframes gridflow {

                from {
                    transform:translateY(0px);
                }

                to {
                    transform:translateY(56px);
                }

            }

            .mission-radar {
                position:fixed;
                top:50%;
                left:50%;
                transform:translate(-50%, -50%);
                width:760px;
                height:760px;
                border-radius:50%;
                border:1px solid rgba(255,159,28,0.14);
                box-shadow:
                    0 0 60px rgba(255,159,28,0.10),
                    inset 0 0 80px rgba(255,159,28,0.06);
                animation:radarrotate 54s linear infinite;
            }

            .mission-radar:before,
            .mission-radar:after {
                content:'';
                position:absolute;
                inset:70px;
                border-radius:50%;
                border:1px solid rgba(255,159,28,0.10);
            }

            .mission-radar:after {
                inset:180px;
            }

            @keyframes radarrotate {

                from {
                    transform:translate(-50%, -50%) rotate(0deg);
                }

                to {
                    transform:translate(-50%, -50%) rotate(360deg);
                }

            }

            .radar-sweep {
                position:fixed;
                top:50%;
                left:50%;
                width:420px;
                height:4px;
                background:
                    linear-gradient(
                        to right,
                        rgba(255,159,28,0),
                        rgba(255,159,28,0.75)
                    );
                transform-origin:left center;
                animation:radarsweep 8s linear infinite;
            }

            @keyframes radarsweep {

                from {
                    transform:rotate(0deg);
                }

                to {
                    transform:rotate(360deg);
                }

            }

            .alert-waves span {
                position:absolute;
                width:260%;
                height:2px;
                background:
                    linear-gradient(
                        to right,
                        rgba(255,159,28,0),
                        rgba(255,159,28,0.58),
                        rgba(255,159,28,0)
                    );
                animation:wavepulse linear infinite;
            }

            .alert-waves span:nth-child(1){
                top:18%;
                animation-duration:12s;
            }

            .alert-waves span:nth-child(2){
                top:38%;
                animation-duration:16s;
            }

            .alert-waves span:nth-child(3){
                top:58%;
                animation-duration:20s;
            }

            .alert-waves span:nth-child(4){
                top:78%;
                animation-duration:24s;
            }

            @keyframes wavepulse {

                0% {
                    left:-180%;
                    opacity:0;
                    transform:rotate(-2deg);
                }

                30% {
                    opacity:1;
                }

                100% {
                    left:20%;
                    opacity:0;
                    transform:rotate(2deg);
                }

            }

            .command-particles span {
                position:absolute;
                display:block;
                border-radius:50%;
                background:rgba(255,159,28,0.20);
                box-shadow:0 0 42px rgba(255,159,28,0.46);
                animation:particlefloat linear infinite;
            }

            .command-particles span:nth-child(1){
                width:18px;
                height:18px;
                left:10%;
                top:88%;
                animation-duration:18s;
            }

            .command-particles span:nth-child(2){
                width:30px;
                height:30px;
                left:28%;
                top:94%;
                animation-duration:24s;
            }

            .command-particles span:nth-child(3){
                width:20px;
                height:20px;
                left:50%;
                top:86%;
                animation-duration:20s;
            }

            .command-particles span:nth-child(4){
                width:38px;
                height:38px;
                left:72%;
                top:95%;
                animation-duration:28s;
            }

            .command-particles span:nth-child(5){
                width:22px;
                height:22px;
                left:90%;
                top:84%;
                animation-duration:22s;
            }

            @keyframes particlefloat {

                0% {
                    transform:translateY(0px) scale(1);
                    opacity:0;
                }

                20% {
                    opacity:1;
                }

                50% {
                    transform:translateY(-360px) scale(1.7);
                }

                100% {
                    transform:translateY(-920px) scale(0.5);
                    opacity:0;
                }

            }

            .wrap {
                position:relative;
                z-index:3;
                max-width:1980px;
                margin:auto;
                padding:34px;
                height:100vh;
                overflow-y:auto;
            }

            .hero,.panel {
                position:relative;
                overflow:hidden;
                border-radius:38px;
                padding:38px;
                margin-bottom:24px;
                border:1px solid rgba(255,255,255,0.08);
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.015)),
                    rgba(18,22,30,0.84);
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
                    radial-gradient(circle, rgba(255,159,28,0.06), transparent 60%);
                animation:fieldrotate 46s linear infinite;
            }

            @keyframes fieldrotate {

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
                font-size:102px;
                color:#ff9f1c;
                letter-spacing:-5px;
                text-shadow:0 0 46px rgba(255,159,28,0.36);
            }

            h2 {
                color:#ff9f1c;
            }

            p {
                color:#b4bcc9;
                line-height:1.8;
            }

            .overall {
                margin-top:36px;
                text-align:center;
                padding:42px;
                border-radius:34px;
                background:rgba(255,255,255,0.04);
            }

            .overall strong {
                display:block;
                font-size:200px;
                color:#ff9f1c;
                text-shadow:0 0 62px rgba(255,159,28,0.48);
            }

            .signal-grid {
                display:grid;
                grid-template-columns:repeat(2,1fr);
                gap:24px;
                margin-top:24px;
            }

            .signal-card {
                position:relative;
                overflow:hidden;
                border-radius:32px;
                padding:34px;
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02)),
                    rgba(255,255,255,0.03);
                border:1px solid rgba(255,255,255,0.08);
            }

            .signal-card:after {
                content:'';
                position:absolute;
                width:180%;
                height:180%;
                top:-40%;
                left:-40%;
                background:
                    radial-gradient(circle, rgba(255,159,28,0.08), transparent 65%);
                animation:signalrotate 18s linear infinite;
            }

            @keyframes signalrotate {

                from {
                    transform:rotate(0deg);
                }

                to {
                    transform:rotate(-360deg);
                }

            }

            .signal-card * {
                position:relative;
                z-index:2;
            }

            .signal-card strong {
                display:block;
                font-size:70px;
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

                .signal-grid {
                    grid-template-columns:1fr;
                }

                h1 {
                    font-size:54px;
                }

                .overall strong {
                    font-size:110px;
                }

                .mission-radar {
                    width:340px;
                    height:340px;
                }

            }

        </style>

    </head>

    <body>

        <div class="command-grid"></div>

        <div class="mission-radar"></div>

        <div class="radar-sweep"></div>

        <div class="alert-waves">
            <span></span>
            <span></span>
            <span></span>
            <span></span>
        </div>

        <div class="command-particles">
            <span></span>
            <span></span>
            <span></span>
            <span></span>
            <span></span>
        </div>

        <div class="wrap">

            <section class="hero">

                <h1>Governance Autonomous Mission Control</h1>

                <p>
                    Executive governance mission orchestration infrastructure
                    for survivability intervention coordination,
                    commercialization continuity command,
                    stabilization deployment synchronization,
                    and enterprise operational governance control.
                </p>

                <div class="overall">

                    <strong>{{ mission_index }}%</strong>

                    Governance Mission Command Index

                </div>

            </section>

            <section class="panel">

                <h2>Enterprise Governance Command Grid</h2>

                <div class="signal-grid">

                    {% for row in signals %}

                    <div class="signal-card">

                        <strong>{{ row.command_strength }}%</strong>

                        <h3>{{ row.command_domain }}</h3>

                        <p>
                            Intervention State:
                            {{ row.intervention }}
                        </p>

                        <span class="pill">
                            Priority: {{ row.priority }}
                        </span>

                        <span class="pill">
                            Status: {{ row.status }}
                        </span>

                    </div>

                    {% endfor %}

                </div>

            </section>

            <section class="panel">

                <h2>Governance Mission Coordination Streams</h2>

                <table>

                    <thead>

                        <tr>
                            <th>Mission Coordination Stream</th>
                            <th>Executive Interpretation</th>
                        </tr>

                    </thead>

                    <tbody>

                        {% for item in cognition %}

                        <tr>

                            <td>{{ item }}</td>

                            <td>Enterprise governance mission orchestration intelligence</td>

                        </tr>

                        {% endfor %}

                    </tbody>

                </table>

            </section>

            <section class="panel">

                <h2>Governance Autonomous Mission Vision</h2>

                <p>
                    The Governance Autonomous Mission Control infrastructure enables
                    enterprise governance command orchestration across all
                    COBIT-Chain AssuranceLayer operational domains.
                </p>

                <p>
                    This architecture supports:
                </p>

                <ul>

                    <li>Governance intervention coordination</li>

                    <li>Commercialization continuity command</li>

                    <li>Operational survivability orchestration</li>

                    <li>Enterprise stabilization deployment</li>

                    <li>Executive escalation synchronization</li>

                    <li>Strategic continuity preservation</li>

                    <li>Operational governance harmonization</li>

                    <li>Mission governance intelligence infrastructure</li>

                </ul>

            </section>

        </div>

    </body>

    </html>

    '''

    return render_template_string(
        html,
        signals=MISSION_CONTROL_SIGNALS_V1,
        cognition=MISSION_CONTROL_STREAMS_V1,
        mission_index=mission_index
    )


@app.route("/governance/mission-control/api")
def governance_mission_control_api_v1():

    return jsonify({
        "mission_index": calculate_mission_control_index_v1(),
        "signals": MISSION_CONTROL_SIGNALS_V1,
        "cognition": MISSION_CONTROL_STREAMS_V1
    })

# ============================================================
# END GOVERNANCE_AUTONOMOUS_MISSION_CONTROL_V1
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

print("Inserted Governance Autonomous Mission Control successfully.")
