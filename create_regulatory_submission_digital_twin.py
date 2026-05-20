from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "# REGULATORY_SUBMISSION_DIGITAL_TWIN_ACTIVE"

if MARKER in text:
    print("Regulatory Submission Digital Twin already installed.")
    raise SystemExit(0)

insert_block = r'''

# REGULATORY_SUBMISSION_DIGITAL_TWIN_ACTIVE
@app.route("/regulatory-submission-digital-twin")
def regulatory_submission_digital_twin():

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
        margin-bottom:30px;
        border:1px solid #164e63;
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
        text-transform:uppercase;
        color:#94a3b8;
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

    table{
        width:100%;
        border-collapse:collapse;
        margin-top:25px;
    }

    th{
        background:#0f172a;
        color:#7dd3fc;
        padding:16px;
        text-align:left;
        border:1px solid #1e293b;
    }

    td{
        padding:16px;
        border:1px solid #1e293b;
        background:#08111f;
    }

    .panel{
        margin-top:30px;
        padding:28px;
        border-radius:24px;
        background:#0f172a;
        border:1px solid #1e3a5f;
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

        <h1>Regulatory Submission Digital Twin</h1>

        <p>
        A governance intelligence environment that evaluates
        submission defensibility, protocol survivability,
        evidence trust propagation, dependency validation,
        inspection attack surface exposure, and cross-system governance drift
        before regulatory release approval.
        </p>

    </div>

    <div class="grid">

        <div class="card">
            <div class="label">FDA Exposure Risk</div>
            <div class="value red">HIGH</div>
        </div>

        <div class="card">
            <div class="label">Submission Survivability</div>
            <div class="value yellow">82%</div>
        </div>

        <div class="card">
            <div class="label">Inspection Defensibility</div>
            <div class="value yellow">CONDITIONAL</div>
        </div>

        <div class="card">
            <div class="label">Cross-System Drift</div>
            <div class="value red">DETECTED</div>
        </div>

    </div>

    <div class="panel">

        <h2>Submission Attack Surface</h2>

        <table>

            <tr>
                <th>Governance Layer</th>
                <th>Operational State</th>
                <th>Submission Impact</th>
            </tr>

            <tr>
                <td>Protocol Integrity</td>
                <td class="green">PASS</td>
                <td>Stable lineage maintained</td>
            </tr>

            <tr>
                <td>TMF Completeness</td>
                <td class="yellow">WARNING</td>
                <td>Missing monitoring evidence</td>
            </tr>

            <tr>
                <td>Safety Governance</td>
                <td class="red">BLOCKED</td>
                <td>SAE review unresolved</td>
            </tr>

            <tr>
                <td>CAPA Closure</td>
                <td class="red">FAIL</td>
                <td>Deviation dependency incomplete</td>
            </tr>

            <tr>
                <td>Purview Retention</td>
                <td class="green">PASS</td>
                <td>DLP and retention aligned</td>
            </tr>

        </table>

    </div>

    <div class="panel">

        <h2>Governance Blast Radius</h2>

        <table>

            <tr>
                <th>Failure Node</th>
                <th>Downstream Exposure</th>
                <th>Risk Severity</th>
            </tr>

            <tr>
                <td>SAE Review Delay</td>
                <td>Safety governance chain unstable</td>
                <td class="red">CRITICAL</td>
            </tr>

            <tr>
                <td>CAPA Dependency Failure</td>
                <td>Submission defensibility reduced</td>
                <td class="red">HIGH</td>
            </tr>

            <tr>
                <td>Retention Drift</td>
                <td>Purview evidence trust weakened</td>
                <td class="yellow">MEDIUM</td>
            </tr>

            <tr>
                <td>Monitoring Evidence Missing</td>
                <td>Inspection narrative weakened</td>
                <td class="yellow">MEDIUM</td>
            </tr>

        </table>

    </div>

    <div class="panel">

        <h2>Governance Reasoning Engine</h2>

        <div class="decision danger">
            SUBMISSION CURRENTLY NON-DEFENSIBLE
        </div>

        <div class="timeline">

            <div class="event">
                <h3>Safety governance unresolved</h3>
                <p>
                SAE evidence remains incomplete across downstream review layers.
                </p>
            </div>

            <div class="event">
                <h3>Deviation reconciliation incomplete</h3>
                <p>
                CAPA closure dependency chain remains unresolved.
                </p>
            </div>

            <div class="event">
                <h3>Inspection attack surface elevated</h3>
                <p>
                Missing monitoring lineage weakens regulatory narrative continuity.
                </p>
            </div>

        </div>

        <div class="decision safe">
            RECOMMENDATION: RECONCILIATION REQUIRED BEFORE RELEASE AUTHORIZATION
        </div>

    </div>

    """

    return rlt_page("Regulatory Submission Digital Twin", body)

'''

anchor = 'if __name__ == "__main__":'

if anchor not in text:
    raise RuntimeError("Could not locate Flask anchor.")

text = text.replace(anchor, insert_block + "\n\n" + anchor)

APP.write_text(text, encoding="utf-8")

print("Regulatory Submission Digital Twin installed successfully.")
