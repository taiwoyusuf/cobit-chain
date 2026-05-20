from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "# GOVERNANCE_COMMAND_CENTER_ACTIVE"

if MARKER in text:
    print("Governance Command Center already installed.")
    raise SystemExit(0)

insert_block = r'''

# GOVERNANCE_COMMAND_CENTER_ACTIVE
@app.route("/governance-command-center")
def governance_command_center():

    body = """
    <style>

    body{
        background:#05111d;
        font-family:Arial,sans-serif;
        color:#e2e8f0;
    }

    .hero{
        padding:40px;
        border-radius:24px;
        background:linear-gradient(135deg,#07111f,#0d2f46);
        border:1px solid #164e63;
        margin-bottom:30px;
    }

    .hero h1{
        font-size:46px;
        color:#7dd3fc;
    }

    .hero p{
        max-width:1200px;
        line-height:1.8;
        color:#cbd5e1;
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
        transition:0.2s;
    }

    .card:hover{
        transform:translateY(-4px);
        border-color:#38bdf8;
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

    .topology{
        position:relative;
        height:520px;
        border-radius:24px;
        background:#020617;
        overflow:hidden;
        border:1px solid #1e293b;
        margin-top:20px;
    }

    .node{
        position:absolute;
        width:170px;
        padding:16px;
        border-radius:18px;
        background:#0f172a;
        text-align:center;
        border:2px solid #334155;
    }

    .line{
        position:absolute;
        height:4px;
        background:#334155;
    }

    .decision{
        margin-top:25px;
        padding:24px;
        border-radius:20px;
        font-size:22px;
        font-weight:700;
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

    table{
        width:100%;
        border-collapse:collapse;
        margin-top:20px;
    }

    th{
        background:#0f172a;
        color:#7dd3fc;
        border:1px solid #1e293b;
        padding:16px;
        text-align:left;
    }

    td{
        background:#08111f;
        border:1px solid #1e293b;
        padding:16px;
    }

    a{
        color:#7dd3fc;
        text-decoration:none;
    }

    </style>

    <div class="hero">

        <h1>Governance Command Center</h1>

        <p>
        A federated governance intelligence cockpit that orchestrates
        protocol defensibility, operational trust propagation,
        evidence lineage, Purview governance, dependency validation,
        submission survivability, inspection exposure,
        and explainable governance reasoning across regulated ecosystems.
        </p>

    </div>

    <div class="grid">

        <div class="card">
            <div class="label">Operational Trust</div>
            <div class="value green">94%</div>
        </div>

        <div class="card">
            <div class="label">Inspection Exposure</div>
            <div class="value red">HIGH</div>
        </div>

        <div class="card">
            <div class="label">Submission Readiness</div>
            <div class="value yellow">CONDITIONAL</div>
        </div>

        <div class="card">
            <div class="label">Protocol Drift</div>
            <div class="value red">DETECTED</div>
        </div>

    </div>

    <div class="panel">

        <h2>Federated Governance Topology</h2>

        <div class="topology">

            <div class="node blue" style="top:40px;left:80px;">
                <h3>Protocol</h3>
                <p>Governed baseline</p>
            </div>

            <div class="node green" style="top:180px;left:320px;">
                <h3>Purview</h3>
                <p>DLP and retention</p>
            </div>

            <div class="node yellow" style="top:100px;left:620px;">
                <h3>AI Anomaly</h3>
                <p>Review escalation</p>
            </div>

            <div class="node red" style="top:320px;left:640px;">
                <h3>Deviation</h3>
                <p>CAPA unresolved</p>
            </div>

            <div class="node green" style="top:360px;left:300px;">
                <h3>Evidence Ledger</h3>
                <p>Immutable verification</p>
            </div>

            <div class="node yellow" style="top:180px;left:920px;">
                <h3>Release Gate</h3>
                <p>Conditional hold</p>
            </div>

            <div class="line" style="top:120px;left:240px;width:140px;background:#38bdf8;"></div>
            <div class="line" style="top:210px;left:500px;width:160px;background:#22c55e;"></div>
            <div class="line" style="top:390px;left:470px;width:180px;background:#ef4444;"></div>
            <div class="line" style="top:220px;left:790px;width:150px;background:#f59e0b;"></div>

        </div>

    </div>

    <div class="panel">

        <h2>Governance Intelligence Modules</h2>

        <table>

            <tr>
                <th>Module</th>
                <th>Purpose</th>
                <th>Route</th>
            </tr>

            <tr>
                <td>Clinical Trial Trust Graph</td>
                <td>Protocol-to-evidence governance topology</td>
                <td><a href="/clinical-trial-trust-graph">Open</a></td>
            </tr>

            <tr>
                <td>Regulatory Submission Digital Twin</td>
                <td>Submission survivability intelligence</td>
                <td><a href="/regulatory-submission-digital-twin">Open</a></td>
            </tr>

            <tr>
                <td>Clinical Trial Node Intelligence</td>
                <td>Blast radius and dependency propagation</td>
                <td><a href="/clinical-trial-node-intelligence">Open</a></td>
            </tr>

            <tr>
                <td>Protocol-to-Evidence Integrity Graph</td>
                <td>Evidence lineage federation</td>
                <td><a href="/protocol-to-evidence-integrity-graph">Open</a></td>
            </tr>

        </table>

    </div>

    <div class="panel">

        <h2>Governance Alert Feed</h2>

        <table>

            <tr>
                <th>Alert</th>
                <th>Severity</th>
                <th>Impact</th>
            </tr>

            <tr>
                <td>SAE review unresolved</td>
                <td class="red">CRITICAL</td>
                <td>Safety governance exposure</td>
            </tr>

            <tr>
                <td>Retention mismatch detected</td>
                <td class="yellow">MEDIUM</td>
                <td>Purview trust reduction</td>
            </tr>

            <tr>
                <td>Protocol drift identified</td>
                <td class="red">HIGH</td>
                <td>Cross-system reconciliation required</td>
            </tr>

            <tr>
                <td>Release dependency failure</td>
                <td class="red">CRITICAL</td>
                <td>Submission hold activated</td>
            </tr>

        </table>

    </div>

    <div class="panel">

        <h2>Executive Governance Reasoning</h2>

        <div class="decision danger">
            CURRENT RELEASE POSTURE REMAINS CONDITIONALLY DEFENSIBLE
        </div>

        <p style="margin-top:25px;line-height:1.9;">
        Submission governance remains unstable because unresolved safety review evidence,
        incomplete CAPA dependency closure, monitoring lineage gaps,
        and protocol reconciliation drift continue propagating risk into downstream
        release authorization layers.
        </p>

        <div class="decision safe">
            RECOMMENDATION: COMPLETE GOVERNANCE RECONCILIATION BEFORE RELEASE AUTHORIZATION
        </div>

    </div>

    """

    return rlt_page("Governance Command Center", body)

'''

anchor = 'if __name__ == "__main__":'

if anchor not in text:
    raise RuntimeError("Could not locate Flask anchor.")

text = text.replace(anchor, insert_block + "\n\n" + anchor)

APP.write_text(text, encoding="utf-8")

print("Governance Command Center installed successfully.")
