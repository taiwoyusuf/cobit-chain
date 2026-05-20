from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "GOVERNANCE_REALITY_FABRIC_V1_ACTIVE"

if MARKER in text:
    print("Governance Reality Fabric already exists.")
    raise SystemExit()

if 'def governance_reality_fabric_v1(' in text:
    print("Function already exists.")
    raise SystemExit()

INSERT = r"""

# ============================================================
# GOVERNANCE_REALITY_FABRIC_V1_ACTIVE
# ============================================================

from flask import jsonify

REALITY_FABRIC_NODES_V1 = [
    {
        "node": "Commercialization Continuity",
        "energy": 96,
        "orbit": "Enterprise Readiness",
        "status": "Synchronized"
    },
    {
        "node": "Inspection Survivability",
        "energy": 91,
        "orbit": "Operational Trust",
        "status": "Stable"
    },
    {
        "node": "Environmental Governance",
        "energy": 87,
        "orbit": "Release Defensibility",
        "status": "Monitoring"
    },
    {
        "node": "CAPA Governance",
        "energy": 82,
        "orbit": "Governance Stabilization",
        "status": "Strained"
    },
    {
        "node": "Operational Resilience",
        "energy": 94,
        "orbit": "Recovery Survivability",
        "status": "Operational"
    }
]

REALITY_FABRIC_STREAMS_V1 = [
    "Enterprise governance cognition remains synchronized across commercialization pathways.",
    "Environmental governance energy fluctuations are propagating into release defensibility posture.",
    "Operational resilience stabilization remains commercially survivable.",
    "CAPA governance pressure fields are increasing inspection survivability strain.",
    "Governance trust synchronization remains stable across enterprise continuity domains."
]


def calculate_reality_fabric_index_v1():

    total = 0

    for row in REALITY_FABRIC_NODES_V1:
        total += row["energy"]

    return round(total / len(REALITY_FABRIC_NODES_V1))


@app.route("/governance/reality-fabric")
def governance_reality_fabric_v1():

    fabric_index = calculate_reality_fabric_index_v1()

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Governance Reality Fabric</title>

        <style>

            body {
                margin:0;
                overflow:hidden;
                background:
                    radial-gradient(circle at top left, rgba(255,122,24,0.18), transparent 34%),
                    radial-gradient(circle at bottom right, rgba(255,159,28,0.12), transparent 28%),
                    linear-gradient(135deg,#040507 0%,#0f141d 45%,#050608 100%);
                color:white;
                font-family:Arial,sans-serif;
            }

            .grid-bg {
                position:fixed;
                width:100%;
                height:100%;
                opacity:0.08;
                background-image:
                    linear-gradient(rgba(255,159,28,0.18) 1px, transparent 1px),
                    linear-gradient(90deg, rgba(255,159,28,0.18) 1px, transparent 1px);
                background-size:42px 42px;
                animation:gridmove 20s linear infinite;
            }

            @keyframes gridmove {
                from {
                    transform:translateY(0px);
                }
                to {
                    transform:translateY(42px);
                }
            }

            .particles span {
                position:absolute;
                display:block;
                border-radius:50%;
                background:rgba(255,159,28,0.18);
                box-shadow:0 0 25px rgba(255,159,28,0.45);
                animation:floatpulse linear infinite;
            }

            .particles span:nth-child(1){
                width:10px;
                height:10px;
                left:10%;
                animation-duration:18s;
                top:90%;
            }

            .particles span:nth-child(2){
                width:18px;
                height:18px;
                left:28%;
                animation-duration:24s;
                top:85%;
            }

            .particles span:nth-child(3){
                width:12px;
                height:12px;
                left:50%;
                animation-duration:20s;
                top:92%;
            }

            .particles span:nth-child(4){
                width:22px;
                height:22px;
                left:72%;
                animation-duration:28s;
                top:88%;
            }

            .particles span:nth-child(5){
                width:14px;
                height:14px;
                left:88%;
                animation-duration:22s;
                top:95%;
            }

            @keyframes floatpulse {

                0% {
                    transform:translateY(0px) scale(1);
                    opacity:0;
                }

                20% {
                    opacity:1;
                }

                50% {
                    transform:translateY(-450px) scale(1.4);
                }

                100% {
                    transform:translateY(-950px) scale(0.8);
                    opacity:0;
                }

            }

            .wrap {
                position:relative;
                z-index:2;
                max-width:1980px;
                margin:auto;
                padding:34px;
                overflow-y:auto;
                height:100vh;
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
                animation:rotatefield 30s linear infinite;
            }

            @keyframes rotatefield {

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

            .fabric-grid {
                display:grid;
                grid-template-columns:repeat(2,1fr);
                gap:24px;
                margin-top:24px;
            }

            .fabric-card {
                position:relative;
                overflow:hidden;
                border-radius:24px;
                padding:26px;
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02)),
                    rgba(255,255,255,0.03);
                border:1px solid rgba(255,255,255,0.08);
            }

            .fabric-card:after {
                content:'';
                position:absolute;
                width:180%;
                height:180%;
                top:-40%;
                left:-40%;
                background:
                    radial-gradient(circle, rgba(255,159,28,0.08), transparent 65%);
                animation:fieldrotate 18s linear infinite;
            }

            @keyframes fieldrotate {

                from {
                    transform:rotate(0deg);
                }

                to {
                    transform:rotate(-360deg);
                }

            }

            .fabric-card * {
                position:relative;
                z-index:2;
            }

            .fabric-card strong {
                display:block;
                font-size:52px;
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

                .fabric-grid {
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

        <div class="grid-bg"></div>

        <div class="particles">
            <span></span>
            <span></span>
            <span></span>
            <span></span>
            <span></span>
        </div>

        <div class="wrap">

            <section class="hero">

                <h1>Governance Reality Fabric</h1>

                <p>
                    Enterprise governance spatial intelligence infrastructure
                    for commercialization continuity cognition,
                    survivability synchronization,
                    governance constellation awareness,
                    and operational reality orchestration.
                </p>

                <div class="overall">

                    <strong>{{ fabric_index }}%</strong>

                    Enterprise Governance Reality Index

                </div>

            </section>

            <section class="panel">

                <h2>Governance Constellation Field</h2>

                <div class="fabric-grid">

                    {% for row in nodes %}

                    <div class="fabric-card">

                        <strong>{{ row.energy }}%</strong>

                        <h3>{{ row.node }}</h3>

                        <p>
                            Governance Orbit:
                            {{ row.orbit }}
                        </p>

                        <span class="pill">
                            Status: {{ row.status }}
                        </span>

                    </div>

                    {% endfor %}

                </div>

            </section>

            <section class="panel">

                <h2>Enterprise Governance Cognition Streams</h2>

                <table>

                    <thead>

                        <tr>
                            <th>Cognition Stream</th>
                            <th>Enterprise Interpretation</th>
                        </tr>

                    </thead>

                    <tbody>

                        {% for item in cognition %}

                        <tr>

                            <td>{{ item }}</td>

                            <td>Spatial governance synchronization intelligence</td>

                        </tr>

                        {% endfor %}

                    </tbody>

                </table>

            </section>

            <section class="panel">

                <h2>Governance Reality Fabric Vision</h2>

                <p>
                    The Governance Reality Fabric enables enterprise governance
                    spatial intelligence across all COBIT-Chain AssuranceLayer
                    operational verticals.
                </p>

                <p>
                    This architecture supports:
                </p>

                <ul>

                    <li>Governance constellation intelligence</li>

                    <li>Operational cognition fields</li>

                    <li>Commercialization continuity synchronization</li>

                    <li>Systemic survivability awareness</li>

                    <li>Governance spatial orchestration</li>

                    <li>Enterprise trust stabilization fields</li>

                    <li>Operational nervous-system visualization</li>

                    <li>Spatial governance intelligence infrastructure</li>

                </ul>

            </section>

        </div>

    </body>

    </html>

    '''

    return render_template_string(
        html,
        nodes=REALITY_FABRIC_NODES_V1,
        cognition=REALITY_FABRIC_STREAMS_V1,
        fabric_index=fabric_index
    )


@app.route("/governance/reality-fabric/api")
def governance_reality_fabric_api_v1():

    return jsonify({
        "fabric_index": calculate_reality_fabric_index_v1(),
        "nodes": REALITY_FABRIC_NODES_V1,
        "cognition": REALITY_FABRIC_STREAMS_V1
    })

# ============================================================
# END GOVERNANCE_REALITY_FABRIC_V1
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

print("Inserted Governance Reality Fabric successfully.")
