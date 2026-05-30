from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_EVIDENCE_LINEAGE_INTELLIGENCE_V1_ACTIVE"

if MARKER in text:
    print("Evidence Lineage Intelligence already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# IRLT_EVIDENCE_LINEAGE_INTELLIGENCE_V1_ACTIVE
# ============================================================

@app.route("/irlt-commercial-readiness/evidence-lineage")
@app.route("/rlttrust/evidence-lineage")
def irlt_evidence_lineage_intelligence_v1():

    html = """
    <html>
    <head>
        <title>Evidence Lineage Intelligence</title>
        <style>
            body{
                margin:0;
                padding:40px;
                background:linear-gradient(135deg,#050608,#11151f,#050608);
                color:white;
                font-family:Arial,Segoe UI,sans-serif;
            }

            h1{
                font-size:76px;
                color:#ff9f1c;
                margin-bottom:20px;
            }

            .panel{
                background:#151c27;
                border-radius:28px;
                padding:30px;
                margin-bottom:24px;
                border:1px solid rgba(255,255,255,.08);
            }

            .flow{
                display:flex;
                flex-direction:column;
                align-items:center;
                gap:18px;
                margin-top:20px;
                margin-bottom:20px;
            }

            .box{
                width:420px;
                padding:24px;
                text-align:center;
                background:rgba(255,255,255,.04);
                border-radius:18px;
                border:1px solid rgba(255,255,255,.08);
            }

            .title{
                color:#ff9f1c;
                font-size:26px;
                font-weight:bold;
            }

            .arrow{
                font-size:42px;
                color:#ff9f1c;
                font-weight:bold;
            }

            p{
                color:#c6cfdb;
                line-height:1.8;
            }
        </style>
    </head>

    <body>

        <div class="panel">
            <h1>Evidence Lineage Intelligence</h1>

            <p>
                Governance assurance model showing how evidence is transformed
                into a defensible operational decision.
            </p>

            <div class="flow">

                <div class="box">
                    <div class="title">Evidence</div>
                    Deviation Records<br>
                    QC Results<br>
                    Audit Logs<br>
                    Chain of Custody
                </div>

                <div class="arrow">↓</div>

                <div class="box">
                    <div class="title">Control Validation</div>
                    SOP Verification<br>
                    CAPA Review<br>
                    Access Governance<br>
                    Dependency Validation
                </div>

                <div class="arrow">↓</div>

                <div class="box">
                    <div class="title">Approval Governance</div>
                    QA Approval<br>
                    Quality Review<br>
                    GMP Authorization<br>
                    Executive Sign-Off
                </div>

                <div class="arrow">↓</div>

                <div class="box">
                    <div class="title">Decision</div>
                    Release Decision<br>
                    Commercialization Decision<br>
                    Inspection Defense<br>
                    Operational Trust Certification
                </div>

            </div>

        </div>

        <div class="panel">

            <h2 style="color:#ff9f1c;">Governance Narrative</h2>

            <p>
                Traditional systems stop at storing records.
                COBIT-Chain™ extends governance by creating an explainable lineage
                from evidence collection through control validation and approval governance
                to final operational decisions.
            </p>

        </div>

    </body>
    </html>
    """

    return html

# ============================================================
# END IRLT_EVIDENCE_LINEAGE_INTELLIGENCE_V1
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("Evidence Lineage Intelligence installed.")
