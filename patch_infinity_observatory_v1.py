from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "GOVERNANCE_INFINITY_OBSERVATORY_V1_ACTIVE"

if MARKER in text:
    print("Governance Infinity Observatory already exists.")
    raise SystemExit()

if 'def governance_infinity_observatory_v1(' in text:
    print("Function already exists.")
    raise SystemExit()

INSERT = r"""

# ============================================================
# GOVERNANCE_INFINITY_OBSERVATORY_V1_ACTIVE
# ============================================================

from flask import jsonify

INFINITY_OBSERVATORY_SIGNALS_V1 = [
    {
        "sector": "Commercialization Continuity",
        "trajectory": 97,
        "wave": "Stable",
        "gravity": "Strong",
        "status": "Operational"
    },
    {
        "sector": "Inspection Survivability",
        "trajectory": 92,
        "wave": "Synchronizing",
        "gravity": "Connected",
        "status": "Resilient"
    },
    {
        "sector": "Governance Stabilization",
        "trajectory": 86,
        "wave": "Adaptive",
        "gravity": "Dynamic",
        "status": "Monitoring"
    },
    {
        "sector": "Operational Trust",
        "trajectory": 95,
        "wave": "Unified",
        "gravity": "Aligned",
        "status": "Stable"
    },
    {
        "sector": "Temporal Governance",
        "trajectory": 93,
        "wave": "Flowing",
        "gravity": "Synchronized",
        "status": "Optimized"
    }
]

INFINITY_OBSERVATORY_STREAMS_V1 = [
    "Enterprise governance trajectories remain commercially synchronized across operational continuity pathways.",
    "Inspection survivability gravity fields remain operationally resilient.",
    "Governance stabilization harmonics are adapting to commercialization acceleration.",
    "Temporal governance cognition remains synchronized with enterprise trust fields.",
    "Operational governance observability remains strategically aligned."
]


def calculate_infinity_observatory_index_v1():

    total = 0

    for row in INFINITY_OBSERVATORY_SIGNALS_V1:
        total += row["trajectory"]

    return round(total / len(INFINITY_OBSERVATORY_SIGNALS_V1))


@app.route("/governance/infinity-observatory")
def governance_infinity_observatory_v1():

    observatory_index = calculate_infinity_observatory_index_v1()

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Governance Infinity Observatory</title>

        <style>

            body {
                margin:0;
                overflow:hidden;
                background:
                    radial-gradient(circle at center, rgba(255,159,28,0.10), transparent 18%),
                    radial-gradient(circle at top left, rgba(255,122,24,0.08), transparent 30%),
                    radial-gradient(circle at bottom right, rgba(255,159,28,0.08), transparent 24%),
                    linear-gradient(135deg,#020304 0%,#090d15 45%,#040506 100%);
                color:white;
                font-family:Arial,sans-serif;
            }

            .starfield span {
                position:absolute;
                display:block;
                border-radius:50%;
                background:rgba(255,255,255,0.8);
                animation:starfloat linear infinite;
            }

            .starfield span:nth-child(1){
                width:2px;
                height:2px;
                left:8%;
                top:10%;
                animation-duration:20s;
            }

            .starfield span:nth-child(2){
                width:4px;
                height:4px;
                left:22%;
                top:28%;
                animation-duration:24s;
            }

            .starfield span:nth-child(3){
                width:3px;
                height:3px;
                left:42%;
                top:16%;
                animation-duration:18s;
            }

            .starfield span:nth-child(4){
                width:5px;
                height:5px;
                left:66%;
                top:34%;
                animation-duration:28s;
            }

            .starfield span:nth-child(5){
                width:3px;
                height:3px;
                left:84%;
                top:20%;
                animation-duration:22s;
            }

            .starfield span:nth-child(6){
                width:2px;
                height:2px;
                left:92%;
                top:42%;
                animation-duration:26s;
            }

            @keyframes starfloat {

                0% {
                    transform:translateY(0px);
                    opacity:0.2;
                }

                50% {
                    opacity:1;
                }

                100% {
                    transform:translateY(40px);
                    opacity:0.2;
                }

            }

            .observatory-rings {
                position:fixed;
                top:50%;
                left:50%;
                transform:translate(-50%, -50%);
                width:520px;
                height:520px;
                border-radius:50%;
                border:1px solid rgba(255,159,28,0.16);
                animation:ringrotate 28s linear infinite;
            }

            .observatory-rings:before,
            .observatory-rings:after {
                content:'';
                position:absolute;
                inset:38px;
                border-radius:50%;
                border:1px solid rgba(255,159,28,0.14);
            }

            .observatory-rings:after {
                inset:92px;
            }

            @keyframes ringrotate {

                from {
                    transform:translate(-50%, -50%) rotate(0deg);
                }

                to {
                    transform:translate(-50%, -50%) rotate(360deg);
                }

            }

            .wave-layer {
                position:fixed;
                width:100%;
                height:100%;
                overflow:hidden;
            }

            .wave-layer span {
                position:absolute;
                width:200%;
                height:2px;
                background:
                    linear-gradient(
                        to right,
                        rgba(255,159,28,0),
                        rgba(255,159,28,0.45),
                        rgba(255,159,28,0)
                    );
                animation:waveflow linear infinite;
            }

            .wave-layer span:nth-child(1){
                top:22%;
                animation-duration:12s;
            }

            .wave-layer span:nth-child(2){
                top:48%;
                animation-duration:15s;
            }

            .wave-layer span:nth-child(3){
                top:72%;
                animation-duration:18s;
            }

            @keyframes waveflow {

                0% {
                    left:-120%;
                    opacity:0;
                }

                20% {
                    opacity:1;
                }

                100% {
                    left:20%;
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
                border-radius:34px;
                padding:34px;
                margin-bottom:24px;
                border:1px solid rgba(255,255,255,0.08);
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.015)),
                    rgba(18,22,30,0.82);
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
                animation:fieldrotate 36s linear infinite;
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
                font-size:92px;
                color:#ff9f1c;
                letter-spacing:-4px;
                text-shadow:0 0 34px rgba(255,159,28,0.25);
            }

            h2 {
                color:#ff9f1c;
            }

            p {
                color:#b4bcc9;
                line-height:1.8;
            }

            .overall {
                margin-top:32px;
                text-align:center;
                padding:36px;
                border-radius:30px;
                background:rgba(255,255,255,0.04);
            }

            .overall strong {
                display:block;
                font-size:170px;
                color:#ff9f1c;
                text-shadow:0 0 48px rgba(255,159,28,0.40);
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
                border-radius:28px;
                padding:28px;
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
                font-size:60px;
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
                    font-size:48px;
                }

                .overall strong {
                    font-size:96px;
                }

                .observatory-rings {
                    width:260px;
                    height:260px;
                }

            }

        </style>

    </head>

    <body>

        <div class="starfield">
            <span></span>
            <span></span>
            <span></span>
            <span></span>
            <span></span>
            <span></span>
        </div>

        <div class="observatory-rings"></div>

        <div class="wave-layer">
            <span></span>
            <span></span>
            <span></span>
        </div>

        <div class="wrap">

            <section class="hero">

                <h1>Governance Infinity Observatory</h1>

                <p>
                    Executive governance observability infrastructure
                    for enterprise survivability horizon intelligence,
                    commercialization continuity oversight,
                    operational gravity visualization,
                    and governance trajectory cognition.
                </p>

                <div class="overall">

                    <strong>{{ observatory_index }}%</strong>

                    Enterprise Governance Observatory Index

                </div>

            </section>

            <section class="panel">

                <h2>Governance Horizon Observation Grid</h2>

                <div class="signal-grid">

                    {% for row in signals %}

                    <div class="signal-card">

                        <strong>{{ row.trajectory }}%</strong>

                        <h3>{{ row.sector }}</h3>

                        <p>
                            Gravity Field:
                            {{ row.gravity }}
                        </p>

                        <span class="pill">
                            Wave: {{ row.wave }}
                        </span>

                        <span class="pill">
                            Status: {{ row.status }}
                        </span>

                    </div>

                    {% endfor %}

                </div>

            </section>

            <section class="panel">

                <h2>Enterprise Governance Horizon Streams</h2>

                <table>

                    <thead>

                        <tr>
                            <th>Observatory Stream</th>
                            <th>Executive Interpretation</th>
                        </tr>

                    </thead>

                    <tbody>

                        {% for item in cognition %}

                        <tr>

                            <td>{{ item }}</td>

                            <td>Enterprise governance observability intelligence</td>

                        </tr>

                        {% endfor %}

                    </tbody>

                </table>

            </section>

            <section class="panel">

                <h2>Governance Infinity Observatory Vision</h2>

                <p>
                    The Governance Infinity Observatory enables enterprise governance
                    observability across all COBIT-Chain AssuranceLayer operational domains.
                </p>

                <p>
                    This architecture supports:
                </p>

                <ul>

                    <li>Governance horizon intelligence</li>

                    <li>Enterprise survivability observability</li>

                    <li>Commercialization continuity oversight</li>

                    <li>Operational gravity visualization</li>

                    <li>Governance trajectory cognition</li>

                    <li>Enterprise synchronization observability</li>

                    <li>Systemic governance awareness</li>

                    <li>Executive governance observatory infrastructure</li>

                </ul>

            </section>

        </div>

    </body>

    </html>

    '''

    return render_template_string(
        html,
        signals=INFINITY_OBSERVATORY_SIGNALS_V1,
        cognition=INFINITY_OBSERVATORY_STREAMS_V1,
        observatory_index=observatory_index
    )


@app.route("/governance/infinity-observatory/api")
def governance_infinity_observatory_api_v1():

    return jsonify({
        "observatory_index": calculate_infinity_observatory_index_v1(),
        "signals": INFINITY_OBSERVATORY_SIGNALS_V1,
        "cognition": INFINITY_OBSERVATORY_STREAMS_V1
    })

# ============================================================
# END GOVERNANCE_INFINITY_OBSERVATORY_V1
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

print("Inserted Governance Infinity Observatory successfully.")
