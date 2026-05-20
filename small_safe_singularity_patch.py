from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_GOVERNANCE_SINGULARITY_SMALL_SAFE_V1"

if MARKER in text:
    print("Small Singularity route already exists.")
    raise SystemExit()

block = r"""

# ============================================================
# IRLT_GOVERNANCE_SINGULARITY_SMALL_SAFE_V1
# ============================================================

@app.route("/irlt-commercial-readiness/governance-singularity")
def irlt_governance_singularity():

    return '''
    <html>

    <head>

        <title>Governance Singularity</title>

        <style>

            body{
                background:#0b0f16;
                color:white;
                font-family:Arial;
                padding:40px;
            }

            .panel{
                background:#141b24;
                padding:24px;
                border-radius:18px;
                margin-top:24px;
            }

            h1{
                color:orange;
                font-size:64px;
            }

        </style>

    </head>

    <body>

        <h1>Governance Singularity Layer</h1>

        <div class="panel">

            <h2>Unified Governance Cognition</h2>

            <p>
                Enterprise operational governance cognition layer
                for IRLT commercialization readiness.
            </p>

        </div>

        <div class="panel">

            <h2>Operational State</h2>

            <ul>
                <li>Operational Trust: Stable</li>
                <li>Inspection Survivability: Strong</li>
                <li>Evidence Coherence: Verified</li>
                <li>Commercialization Readiness: Controlled</li>
            </ul>

        </div>

    </body>

    </html>
    '''

# ============================================================
# END IRLT_GOVERNANCE_SINGULARITY_SMALL_SAFE_V1
# ============================================================

"""

anchor = '\nif __name__ == "__main__":'

if anchor not in text:
    print("Could not locate startup anchor.")
    raise SystemExit()

text = text.replace(anchor, "\n" + block + "\n" + anchor, 1)

APP.write_text(text, encoding="utf-8")

print("Small safe Singularity route inserted successfully.")
