from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "GOVERNANCE_SINGULARITY_CORE_V1_ACTIVE"

if MARKER in text:
    print("Governance Singularity Core already exists.")
    raise SystemExit()

if 'def governance_singularity_core_v1(' in text:
    print("Function already exists.")
    raise SystemExit()

INSERT = r"""

# ============================================================
# GOVERNANCE_SINGULARITY_CORE_V1_ACTIVE
# ============================================================

from flask import jsonify

SINGULARITY_SIGNALS_V1 = [
    {
        "domain": "Temporal Governance",
        "harmonic": 94,
        "convergence": "Synchronized",
        "status": "Operational"
    },
    {
        "domain": "Commercialization Continuity",
        "harmonic": 97,
        "convergence": "Unified",
        "status": "Stable"
    },
    {
        "domain": "Inspection Survivability",
        "harmonic": 91,
        "convergence": "Connected",
        "status": "Resilient"
    },
    {
        "domain": "Governance Stabilization",
        "harmonic": 86,
        "convergence": "Adaptive",
        "status": "Monitoring"
    },
    {
        "domain": "Operational Trust",
        "harmonic": 95,
        "convergence": "Conscious",
        "status": "Aligned"
    }
]

SINGULARITY_COGNITION_STREAM_V1 = [
    "Enterprise governance consciousness remains synchronized across operational survivability pathways.",
    "Commercialization continuity harmonics remain operationally aligned.",
    "Inspection survivability cognition is converging with stabilization orchestration.",
    "Temporal governance memory remains synchronized with operational trust fields.",
    "Governance consciousness harmonics remain commercially resilient."
]


def calculate_singularity_index_v1():

    total = 0

    for row in SINGULARITY_SIGNALS_V1:
        total += row["harmonic"]

    return round(total / len(SINGULARITY_SIGNALS_V1))


@app.route("/governance/singularity-core")
def governance_singularity_core_v1():

    singularity_index = calculate_singularity_index_v1()

    html = '''

    <!doctype html>

    <html>

    <head>

        <title>Governance Singularity Core</title>

        <style>

            body {
                margin:0;
                overflow:hidden;
                background:
                    radial-gradient(circle at center, rgba(255,159,28,0.14), transparent 20%),
                    radial-gradient(circle at top left, rgba(255,122,24,0.12), transparent 28%),
                    radial-gradient(circle at bottom right, rgba(255,159,28,0.10), transparent 24%),
                    linear-gradient(135deg,#030405 0%,#0b1018 45%,#050608 100%);
                color:white;
                font-family:Arial,sans-serif;
            }

            .grid-layer {
                position:fixed;
                width:100%;
                height:100%;
                opacity:0.07;
                background-image:
                    linear-gradient(rgba(255,159,28,0.15) 1px, transparent 1px),
                    linear-gradient(90deg, rgba(255,159,28,0.15) 1px, transparent 1px);
                background-size:48px 48px;
                animation:gridshift 22s linear infinite;
            }

            @keyframes gridshift {

                from {
                    transform:translateY(0px);
                }

                to {
                    transform:translateY(48px);
                }

            }

            .core-reactor {
                position:fixed;
                top:50%;
                left:50%;
                transform:translate(-50%, -50%);
                width:420px;
                height:420px;
                border-radius:50%;
                border:2px solid rgba(255,159,28,0.22);
                box-shadow:
                    0 0 45px rgba(255,159,28,0.20),
                    inset 0 0 60px rgba(255,159,28,0.15);
                animation:corepulse 8s ease-in-out infinite;
            }

            .core-reactor:before,
            .core-reactor:after {
                content:'';
                position:absolute;
                inset:28px;
                border-radius:50%;
                border:1px solid rgba(255,159,28,0.20);
                animation:rotor 16s linear infinite;
            }

            .core-reactor:after {
                inset:70px;
                animation-direction:reverse;
                animation-duration:22s;
            }

            @keyframes rotor {

                from {
                    transform:rotate(0deg);
                }

                to {
                    transform:rotate(360deg);
                }

            }

            @keyframes corepulse {

                0% {
                    transform:translate(-50%, -50%) scale(1);
                }

                50% {
                    transform:translate(-50%, -50%) scale(1.04);
                }

                100% {
                    transform:translate(-50%, -50%) scale(1);
                }

            }

            .orbit span {
                position:absolute;
                display:block;
                border-radius:50%;
                background:rgba(255,159,28,0.18);
                box-shadow:0 0 30px rgba(255,159,28,0.35);
                animation:orbital linear infinite;
            }

            .orbit span:nth-child(1){
                width:16px;
                height:16px;
                top:18%;
                left:20%;
                animation-duration:16s;
            }

            .orbit span:nth-child(2){
                width:26px;
                height:26px;
                top:32%;
                left:74%;
                animation-duration:22s;
            }

            .orbit span:nth-child(3){
                width:18px;
                height:18px;
                top:72%;
                left:18%;
                animation-duration:18s;
            }

            .orbit span:nth-child(4){
                width:30px;
                height:30px;
                top:78%;
                left:80%;
                animation-duration:24s;
            }

            .orbit span:nth-child(5){
                width:14px;
                height:14px;
                top:52%;
                left:50%;
                animation-duration:14s;
            }

            @keyframes orbital {

                0% {
                    transform:translateY(0px) scale(1);
                    opacity:0;
                }

                20% {
                    opacity:1;
                }

                50% {
                    transform:translateY(-220px) scale(1.5);
                }

                100% {
                    transform:translateY(-520px) scale(0.7);
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
                border-radius:32px;
                padding:32px;
                margin-bottom:24px;
                border:1px solid rgba(255,255,255,0.08);
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.015)),
                    rgba(20,24,33,0.80);
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
                animation:fieldrotate 30s linear infinite;
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
                font-size:90px;
                color:#ff9f1c;
                letter-spacing:-4px;
                text-shadow:0 0 32px rgba(255,159,28,0.28);
            }

            h2 {
                color:#ff9f1c;
            }

            p {
                color:#b4bcc9;
                line-height:1.8;
            }

            .overall {
                margin-top:30px;
                text-align:center;
                padding:34px;
                border-radius:28px;
                background:rgba(255,255,255,0.04);
            }

            .overall strong {
                display:block;
                font-size:160px;
                color:#ff9f1c;
                text-shadow:0 0 42px rgba(255,159,28,0.38);
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
                border-radius:26px;
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
                font-size:58px;
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

                .core-reactor {
                    width:240px;
                    height:240px;
                }

            }

        </style>

    </head>

    <body>

        <div class="grid-layer"></div>

        <div class="core-reactor"></div>

        <div class="orbit">
            <span></span>
            <span></span>
            <span></span>
            <span></span>
            <span></span>
        </div>

        <div class="wrap">

            <section class="hero">

                <h1>Governance Singularity Core</h1>

                <p>
                    Unified enterprise governance consciousness infrastructure
                    for survivability convergence,
                    commercialization continuity harmonization,
                    operational trust synchronization,
                    and systemic governance orchestration.
                </p>

                <div class="overall">

                    <strong>{{ singularity_index }}%</strong>

                    Unified Governance Consciousness Index

                </div>

            </section>

            <section class="panel">

                <h2>Enterprise Governance Harmonic Grid</h2>

                <div class="signal-grid">

                    {% for row in signals %}

                    <div class="signal-card">

                        <strong>{{ row.harmonic }}%</strong>

                        <h3>{{ row.domain }}</h3>

                        <p>
                            Convergence State:
                            {{ row.convergence }}
                        </p>

                        <span class="pill">
                            Status: {{ row.status }}
                        </span>

                    </div>

                    {% endfor %}

                </div>

            </section>

            <section class="panel">

                <h2>Governance Consciousness Streams</h2>

                <table>

                    <thead>

                        <tr>
                            <th>Consciousness Stream</th>
                            <th>Enterprise Interpretation</th>
                        </tr>

                    </thead>

                    <tbody>

                        {% for item in cognition %}

                        <tr>

                            <td>{{ item }}</td>

                            <td>Unified governance cognition intelligence</td>

                        </tr>

                        {% endfor %}

                    </tbody>

                </table>

            </section>

            <section class="panel">

                <h2>Governance Singularity Vision</h2>

                <p>
                    The Governance Singularity Core unifies enterprise governance
                    cognition across all COBIT-Chain AssuranceLayer operational domains.
                </p>

                <p>
                    This architecture supports:
                </p>

                <ul>

                    <li>Unified governance consciousness</li>

                    <li>Enterprise survivability harmonics</li>

                    <li>Commercialization continuity convergence</li>

                    <li>Operational trust synchronization</li>

                    <li>Systemic governance awareness</li>

                    <li>Governance cognition orchestration</li>

                    <li>Enterprise stabilization harmonization</li>

                    <li>Unified governance intelligence infrastructure</li>

                </ul>

            </section>

        </div>

    </body>

    </html>

    '''

    return render_template_string(
        html,
        signals=SINGULARITY_SIGNALS_V1,
        cognition=SINGULARITY_COGNITION_STREAM_V1,
        singularity_index=singularity_index
    )


@app.route("/governance/singularity-core/api")
def governance_singularity_core_api_v1():

    return jsonify({
        "singularity_index": calculate_singularity_index_v1(),
        "signals": SINGULARITY_SIGNALS_V1,
        "cognition": SINGULARITY_COGNITION_STREAM_V1
    })

# ============================================================
# END GOVERNANCE_SINGULARITY_CORE_V1
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

print("Inserted Governance Singularity Core successfully.")
