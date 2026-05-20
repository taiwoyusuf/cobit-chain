from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "# CLINICAL_TRIAL_NODE_INTELLIGENCE_ACTIVE"

if MARKER in text:
    print("Clinical Trial Node Intelligence already installed.")
    raise SystemExit(0)

insert_block = r'''

# CLINICAL_TRIAL_NODE_INTELLIGENCE_ACTIVE
@app.route("/clinical-trial-node-intelligence")
def clinical_trial_node_intelligence():

    body = """
    <style>

    body{
        background:#06131f;
        font-family:Arial,sans-serif;
        color:#e2e8f0;
    }

    .hero{
        padding:40px;
        border-radius:24px;
        background:linear-gradient(135deg,#08111f,#0d2f46);
        border:1px solid #164e63;
        margin-bottom:30px;
    }

    .hero h1{
        font-size:44px;
        color:#7dd3fc;
    }

    .grid{
        display:grid;
        grid-template-columns:repeat(auto-fit,minmax(260px,1fr));
        gap:20px;
        margin-top:25px;
        margin-bottom:30px;
    }

    .card{
        background:#0f172a;
        border:1px solid #1e3a5f;
        border-radius:20px;
        padding:24px;
    }

    .label{
        font-size:12px;
        color:#94a3b8;
        text-transform:uppercase;
        margin-bottom:10px;
    }

    .value{
        font-size:30px;
        font-weight:800;
    }

    .green{color:#22c55e;}
    .yellow{color:#f59e0b;}
    .red{color:#ef4444;}
    .blue{color:#38bdf8;}

    .panel{
        margin-top:30px;
        padding:28px;
        border-radius:24px;
        background:#0f172a;
        border:1px solid #1e3a5f;
    }

    table{
        width:100%;
        border-collapse:collapse;
        margin-top:25px;
    }

    th{
        background:#0f172a;
        color:#7dd3fc;
        border:1px solid #1e293b;
        padding:16px;
        text-align:left;
    }

    td{
        border:1px solid #1e293b;
        padding:16px;
        background:#08111f;
    }

    .decision{
        margin-top:25px;
        padding:24px;
        border-radius:20px;
        font-weight:700;
        font-size:22px;
    }

    .danger{
        background:linear-gradient(135deg,#3a0911,#1b0c12);
        border:1px solid #ef4444;
        color:#ffb4bd;
    }

    .safe{
        background:linear-gradient(135deg,#0d3529,#09231a);
        border:1px solid #22c55e;
        color:#b7ffd2;
    }

    .timeline{
        margin-top:25px;
    }

    .event{
        border-left:4px solid #38bdf8;
        padding-left:18px;
        margin-bottom:22px;
    }

    </style>

    <div class="hero">

        <h1>Clinical Trial Node Intelligence</h1>

        <p>
        An explainable governance intelligence layer that evaluates
        operational blast radius, evidence dependency propagation,
        protocol exposure, inspection impact, Purview lineage,
        CAPA linkage, and submission defensibility for individual
        governance nodes across regulated clinical-trial ecosystems.
        </p>

    </div>

    <div class="grid">

        <div class="card">
            <div class="label">Selected Node</div>
            <div class="value blue">Deviation</div>
        </div>

        <div class="card">
            <div class="label">Governance Exposure</div>
            <div class="value red">HIGH</div>
        </div>

        <div class="card">
            <div class="label">Blast Radius</div>
            <div class="value yellow">4 Systems</div>
        </div>

        <div class="card">
            <div class="label">Inspection Survivability</div>
            <div class="value yellow">CONDITIONAL</div>
        </div>

    </div>

    <div class="panel">

        <h2>Dependency Propagation Map</h2>

        <table>

            <tr>
                <th>Upstream Dependency</th>
                <th>Operational State</th>
                <th>Downstream Exposure</th>
            </tr>

            <tr>
                <td>SAE Review Evidence</td>
                <td class="red">UNRESOLVED</td>
                <td>Safety governance instability</td>
            </tr>

            <tr>
                <td>CAPA Closure</td>
                <td class="red">FAILED</td>
                <td>Submission defensibility reduced</td>
            </tr>

            <tr>
                <td>Monitoring Lineage</td>
                <td class="yellow">INCOMPLETE</td>
                <td>Inspection continuity weakened</td>
            </tr>

            <tr>
                <td>Purview Retention Mapping</td>
                <td class="green">VERIFIED</td>
                <td>Evidence residency controlled</td>
            </tr>

        </table>

    </div>

    <div class="panel">

        <h2>Governance Blast Radius Analysis</h2>

        <table>

            <tr>
                <th>Affected Layer</th>
                <th>Exposure Level</th>
                <th>Operational Impact</th>
            </tr>

            <tr>
                <td>TMF Defensibility</td>
                <td class="red">CRITICAL</td>
                <td>Inspection narrative instability</td>
            </tr>

            <tr>
                <td>Submission Readiness</td>
                <td class="red">HIGH</td>
                <td>Release gate blocked</td>
            </tr>

            <tr>
                <td>Protocol Reconciliation</td>
                <td class="yellow">MEDIUM</td>
                <td>Cross-system drift detected</td>
            </tr>

            <tr>
                <td>Evidence Integrity</td>
                <td class="yellow">MEDIUM</td>
                <td>Trust confidence reduction</td>
            </tr>

        </table>

    </div>

    <div class="panel">

        <h2>Governance Reasoning Engine</h2>

        <div class="decision danger">
            NODE CURRENTLY CAUSING REGULATORY EXPOSURE PROPAGATION
        </div>

        <div class="timeline">

            <div class="event">
                <h3>Deviation dependency unresolved</h3>
                <p>
                CAPA closure chain remains incomplete across governance review layers.
                </p>
            </div>

            <div class="event">
                <h3>Inspection attack surface increased</h3>
                <p>
                Missing monitoring evidence weakens operational defensibility.
                </p>
            </div>

            <div class="event">
                <h3>Submission release risk elevated</h3>
                <p>
                Governance drift propagated into downstream release gates.
                </p>
            </div>

        </div>

        <div class="decision safe">
            RECOMMENDATION: GOVERNANCE RECONCILIATION REQUIRED BEFORE RELEASE APPROVAL
        </div>

    </div>

    """

    return rlt_page("Clinical Trial Node Intelligence", body)

'''

anchor = 'if __name__ == "__main__":'

if anchor not in text:
    raise RuntimeError("Could not locate Flask anchor.")

text = text.replace(anchor, insert_block + "\n\n" + anchor)

APP.write_text(text, encoding="utf-8")

print("Clinical Trial Node Intelligence installed successfully.")
