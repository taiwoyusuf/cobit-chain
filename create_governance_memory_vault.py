from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "# GOVERNANCE_MEMORY_VAULT_ACTIVE"

if MARKER in text:
    print("Governance Memory Vault already installed.")
    raise SystemExit(0)

insert_block = r'''

# GOVERNANCE_MEMORY_VAULT_ACTIVE
@app.route("/governance-memory-vault")
def governance_memory_vault():

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
        line-height:1.9;
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

    .panel{
        margin-top:30px;
        padding:28px;
        border-radius:24px;
        background:#0f172a;
        border:1px solid #1e3a5f;
    }

    .timeline{
        margin-top:25px;
    }

    .event{
        border-left:4px solid #38bdf8;
        padding-left:18px;
        margin-bottom:22px;
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

    </style>

    <div class="hero">

        <h1>Governance Memory Vault</h1>

        <p>
        An institutional governance lineage repository that preserves
        intervention history, operational trust evolution,
        escalation continuity, reconciliation outcomes,
        governance learning loops, and explainable audit memory
        across regulated enterprise ecosystems.
        </p>

    </div>

    <div class="grid">

        <div class="card">
            <div class="label">Governance Memory State</div>
            <div class="value green">ACTIVE</div>
        </div>

        <div class="card">
            <div class="label">Operational Lineage Records</div>
            <div class="value blue">4,281</div>
        </div>

        <div class="card">
            <div class="label">Trust Continuity</div>
            <div class="value green">STABLE</div>
        </div>

        <div class="card">
            <div class="label">Institutional Learning State</div>
            <div class="value yellow">EVOLVING</div>
        </div>

    </div>

    <div class="panel">

        <h2>Governance Event Timeline</h2>

        <div class="timeline">

            <div class="event">
                <h3>May 01 : Protocol drift detected</h3>
                <p>
                Cross-system governance reconciliation mismatch identified.
                </p>
            </div>

            <div class="event">
                <h3>May 02 : CAPA escalation initiated</h3>
                <p>
                Dependency propagation triggered governance exposure review.
                </p>
            </div>

            <div class="event">
                <h3>May 03 : Purview reconciliation completed</h3>
                <p>
                Retention and DLP trust continuity restored.
                </p>
            </div>

            <div class="event">
                <h3>May 04 : QA authorization restored</h3>
                <p>
                Human governance reviewers completed reconciliation validation.
                </p>
            </div>

            <div class="event">
                <h3>May 05 : Release gate reopened</h3>
                <p>
                Operational trust posture stabilized after intervention closure.
                </p>
            </div>

        </div>

    </div>

    <div class="panel">

        <h2>Governance Learning Registry</h2>

        <table>

            <tr>
                <th>Prior Governance Failure</th>
                <th>Institutional Learning Control</th>
                <th>Future Mitigation</th>
            </tr>

            <tr>
                <td>Missing Monitoring Evidence</td>
                <td>Mandatory lineage validation</td>
                <td>Inspection continuity stabilization</td>
            </tr>

            <tr>
                <td>CAPA Drift</td>
                <td>Dependency lock enforcement</td>
                <td>Release survivability improvement</td>
            </tr>

            <tr>
                <td>Retention Mismatch</td>
                <td>Purview synchronization checks</td>
                <td>Evidence trust continuity maintained</td>
            </tr>

            <tr>
                <td>Protocol Drift</td>
                <td>Cross-system reconciliation triggers</td>
                <td>Governance propagation reduction</td>
            </tr>

        </table>

    </div>

    <div class="panel">

        <h2>Operational Lineage Vault</h2>

        <table>

            <tr>
                <th>Governance Artifact</th>
                <th>Recorded Lineage</th>
                <th>Trust State</th>
            </tr>

            <tr>
                <td>Original AI Anomaly</td>
                <td>Governance escalation chain preserved</td>
                <td class="yellow">MONITORED</td>
            </tr>

            <tr>
                <td>CAPA Reconciliation</td>
                <td>Reviewer intervention lineage recorded</td>
                <td class="green">VERIFIED</td>
            </tr>

            <tr>
                <td>Release Authorization</td>
                <td>Human governance decision preserved</td>
                <td class="green">TRUSTED</td>
            </tr>

            <tr>
                <td>Purview Retention Alignment</td>
                <td>Evidence continuity chain recorded</td>
                <td class="green">STABLE</td>
            </tr>

        </table>

        <div class="decision danger">
            GOVERNANCE MEMORY PRESERVES EXPLAINABLE OPERATIONAL LINEAGE
        </div>

        <div class="decision safe">
            RECOMMENDATION: MAINTAIN INSTITUTIONAL GOVERNANCE LEARNING CONTINUITY
        </div>

    </div>

    """

    return rlt_page("Governance Memory Vault", body)

'''

anchor = 'if __name__ == "__main__":'

if anchor not in text:
    raise RuntimeError("Could not locate Flask anchor.")

text = text.replace(anchor, insert_block + "\n\n" + anchor)

APP.write_text(text, encoding="utf-8")

print("Governance Memory Vault installed successfully.")
