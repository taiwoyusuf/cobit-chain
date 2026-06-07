from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_PRODUCT_HOME_V1_ACTIVE"

if MARKER in text:
    print("CITrust Product Home already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_PRODUCT_HOME_V1_ACTIVE
# ============================================================

@app.route("/citrust")
@app.route("/citrust-home")
@app.route("/citrust/product-home")
def citrust_product_home_v1():

    html = """
    <html>
    <head>
        <title>CITrust Product Home</title>
        <style>
            body{margin:0;padding:36px;background:linear-gradient(135deg,#050608,#11151f,#050608);color:white;font-family:Arial,Segoe UI,sans-serif}
            h1{font-size:76px;color:#ff9f1c;margin:0 0 12px;letter-spacing:-0.04em}
            h2{color:#ff9f1c;margin-top:0}
            p{color:#c6cfdb;line-height:1.7}
            .hero,.panel{background:#151c27;border-radius:26px;padding:30px;margin-bottom:24px;border:1px solid rgba(255,255,255,.08)}
            .grid{display:grid;grid-template-columns:repeat(3,1fr);gap:22px}
            .card{background:rgba(255,255,255,.04);border-radius:22px;padding:24px;border:1px solid rgba(255,255,255,.08)}
            .card strong{display:block;font-size:26px;color:#ff9f1c;margin-bottom:10px}
            .tag{display:inline-block;padding:8px 14px;border-radius:999px;background:rgba(255,122,24,.15);color:#ffd7ad;margin:4px}
            a{color:#ff9f1c;text-decoration:none;font-weight:bold}
            .chain{font-size:24px;color:#ff9f1c;font-weight:900;line-height:1.9}
            @media(max-width:1200px){.grid{grid-template-columns:1fr}h1{font-size:44px}}
        </style>
    </head>
    <body>

        <section class="hero">
            <h1>CITrust™</h1>
            <p>
                Configuration Item Governance Assurance Platform for ServiceNow CMDB, CI ownership,
                MyAccess readiness, operational evidence, and audit defensibility.
            </p>
            <p>
                ServiceNow stores the CI. CITrust™ determines whether the CI can be operationally trusted.
            </p>
            <span class="tag">CMDB Governance</span>
            <span class="tag">CI Ownership</span>
            <span class="tag">MyAccess Readiness</span>
            <span class="tag">Evidence Lineage</span>
            <span class="tag">Audit Readiness</span>
        </section>

        <section class="panel">
            <h2>CITrust Governance Chain</h2>
            <div class="chain">
                Ticket → CI → Owner → Support Group → MyAccess → SOP → Evidence → Shift Handoff → Data Integrity → Pre-Deviation Readiness → CITrust Score™
            </div>
        </section>

        <section class="panel">
            <h2>Existing CITrust Modules</h2>

            <div class="grid">

                <div class="card">
                    <strong>ServiceNow CI Readiness</strong>
                    Ticket-to-CI readiness assessment for owner, SOP, evidence, shift handoff, and data integrity.
                    <p><a href="/servicenow-ci-readiness">Open Module</a></p>
                </div>

                <div class="card">
                    <strong>CI Candidate Factory</strong>
                    Converts uploaded Planner, Excel, Blue Mountain, or asset records into governed CI candidates.
                    <p><a href="/ci-candidate-factory">Open Module</a></p>
                </div>

                <div class="card">
                    <strong>CI Candidate Review Board</strong>
                    Owner/reviewer decision layer before ServiceNow CMDB submission.
                    <p><a href="/ci-candidate-review">Open Module</a></p>
                </div>

                <div class="card">
                    <strong>CI + MyAccess Blueprint</strong>
                    Maps CI ownership, support groups, approvers, and access governance readiness.
                    <p><a href="/ci-myaccess-blueprint">Open Module</a></p>
                </div>

                <div class="card">
                    <strong>CI Submission Pack</strong>
                    Exportable readiness package for ServiceNow-style CI preparation.
                    <p><a href="/ci-submission-pack">Open Module</a></p>
                </div>

                <div class="card">
                    <strong>Governance Reconciliation Layer</strong>
                    Reconciles conflicting truths across ServiceNow, MyAccess, Blue Mountain, and operational records.
                    <p><a href="/governance-reconciliation-layer">Open Module</a></p>
                </div>

                <div class="card">
                    <strong>Dependency Validation</strong>
                    Validates upstream/downstream CI dependencies before operational reliance.
                    <p><a href="/cross-system-dependency-validation">Open Module</a></p>
                </div>

                <div class="card">
                    <strong>Executive Mission Control</strong>
                    Executive-level governance assurance cockpit.
                    <p><a href="/executive-mission-control">Open Module</a></p>
                </div>

                <div class="card">
                    <strong>Governance Passport</strong>
                    Portable assurance certificate for governed assets and operational records.
                    <p><a href="/governance-passport">Open Module</a></p>
                </div>

            </div>
        </section>

        <section class="panel">
            <h2>Infrastructure LCM Question</h2>
            <p>
                Can this CI be trusted enough to support regulated operations?
                CITrust™ answers this by validating ownership, support group, lifecycle responsibility,
                access routing, SOP linkage, evidence availability, audit readiness, and operational dependency context.
            </p>
        </section>

    </body>
    </html>
    """

    return html

# ============================================================
# END CITRUST_PRODUCT_HOME_V1
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Product Home installed.")
