from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_GOVERNANCE_SINGULARITY_LAYER_V1_ACTIVE"

if MARKER in text:
    print("Singularity already exists.")
    raise SystemExit()

block = r"""

# ============================================================
# IRLT_GOVERNANCE_SINGULARITY_LAYER_V1_ACTIVE
# ============================================================

@app.route("/irlt-commercial-readiness/governance-singularity")
def irlt_governance_singularity():

    return '''
    <html>

    <head>

    <title>Governance Singularity Layer</title>

    <style>

    body{
        background:#0b0f16;
        color:white;
        font-family:Arial;
        padding:40px;
    }

    h1{
        color:orange;
        font-size:72px;
    }

    .card{
        background:#141b24;
        padding:24px;
        border-radius:20px;
        margin-top:24px;
    }

    </style>

    </head>

    <body>

        <h1>Governance Singularity Layer</h1>

        <div class="card">

            <h2>Unified Governance Cognition</h2>

            <p>
            Enterprise operational governance cognition layer
            for commercialization readiness, operational trust,
            inspection survivability, governance coherence,
            and executive defensibility intelligence.
            </p>

        </div>

        <div class="card">

            <h2>Unified Governance State</h2>

            <ul>
                <li>Operational Trust: Stable</li>
                <li>Inspection Survivability: Strong</li>
                <li>Governance Integrity: Aligned</li>
                <li>Evidence Coherence: Verified</li>
                <li>Commercialization Readiness: Controlled</li>
            </ul>

        </div>

    </body>

    </html>
    '''

# ============================================================
# END IRLT_GOVERNANCE_SINGULARITY_LAYER
# ============================================================

"""

index = text.rfind("app.run(")

if index == -1:
    print("Could not find app.run")
    raise SystemExit()

text = text[:index] + block + "\n\n" + text[index:]

APP.write_text(text, encoding="utf-8")

print("Governance Singularity appended successfully.")
