from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

START = "# ============================================================\n# IRLT_EVIDENCE_LINEAGE_INTELLIGENCE_V1_ACTIVE"
END = "# END IRLT_EVIDENCE_LINEAGE_INTELLIGENCE_V1\n# ============================================================"

start = text.find(START)
end = text.find(END)

if start == -1 or end == -1:
    raise SystemExit("Could not find existing Evidence Lineage block.")

end = end + len(END)

new_block = r'''

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
                padding:24px;
                background:linear-gradient(135deg,#050608,#11151f,#050608);
                color:white;
                font-family:Arial,Segoe UI,sans-serif;
                overflow:hidden;
            }

            h1{
                font-size:58px;
                color:#ff9f1c;
                margin:0 0 10px;
                letter-spacing:-0.04em;
            }

            .panel{
                background:#151c27;
                border-radius:24px;
                padding:24px;
                margin-bottom:18px;
                border:1px solid rgba(255,255,255,.08);
            }

            .flow{
                display:flex;
                flex-direction:row;
                justify-content:center;
                align-items:stretch;
                gap:16px;
                margin-top:20px;
            }

            .box{
                width:23%;
                min-height:260px;
                padding:20px;
                text-align:center;
                background:rgba(255,255,255,.04);
                border-radius:20px;
                border:1px solid rgba(255,255,255,.08);
                display:flex;
                flex-direction:column;
                justify-content:center;
            }

            .title{
                color:#ff9f1c;
                font-size:25px;
                font-weight:bold;
                margin-bottom:14px;
            }

            .arrow{
                display:flex;
                align-items:center;
                justify-content:center;
                font-size:42px;
                color:#ff9f1c;
                font-weight:bold;
            }

            p{
                color:#c6cfdb;
                line-height:1.55;
                margin:8px 0;
            }

            .small{
                font-size:15px;
                color:#d7dee9;
                line-height:1.7;
            }
        </style>
    </head>

    <body>

        <div class="panel">
            <h1>Evidence Lineage Intelligence</h1>

            <p>
                One-screen governance assurance chain showing how operational evidence becomes a defensible decision.
            </p>

            <div class="flow">

                <div class="box">
                    <div class="title">Evidence</div>
                    <div class="small">
                        QC Results<br>
                        Deviation Records<br>
                        Audit Logs<br>
                        Chain of Custody<br>
                        Batch Records
                    </div>
                </div>

                <div class="arrow">→</div>

                <div class="box">
                    <div class="title">Control Validation</div>
                    <div class="small">
                        SOP Verification<br>
                        CAPA Review<br>
                        Access Governance<br>
                        Dependency Validation<br>
                        Data Integrity Check
                    </div>
                </div>

                <div class="arrow">→</div>

                <div class="box">
                    <div class="title">Approval Governance</div>
                    <div class="small">
                        QA Approval<br>
                        Quality Review<br>
                        GMP Authorization<br>
                        Executive Sign-Off<br>
                        Release Review
                    </div>
                </div>

                <div class="arrow">→</div>

                <div class="box">
                    <div class="title">Decision</div>
                    <div class="small">
                        Release Decision<br>
                        Inspection Defense<br>
                        Commercial Readiness<br>
                        Trust Certification<br>
                        Governance Passport
                    </div>
                </div>

            </div>

        </div>

        <div class="panel">

            <h2 style="color:#ff9f1c;margin-top:0;">Governance Narrative</h2>

            <p>
                COBIT-Chain™ converts fragmented evidence into control validation, approval governance,
                and defensible operational decisions. This supports audit survivability, inspection readiness,
                and executive commercialization confidence.
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

text = text[:start] + new_block + "\n\n" + text[end:]

APP.write_text(text, encoding="utf-8")

print("Evidence Lineage page replaced with wide one-screen layout.")
