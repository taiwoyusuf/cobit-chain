from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "# CLINICAL_TRIAL_TRUST_GRAPH_ACTIVE"

if MARKER in text:
    print("Clinical Trial Trust Graph already installed.")
    raise SystemExit(0)

insert_block = r'''

# CLINICAL_TRIAL_TRUST_GRAPH_ACTIVE
@app.route("/clinical-trial-trust-graph")
def clinical_trial_trust_graph():

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
        background:linear-gradient(135deg,#0f172a,#082f49);
        margin-bottom:30px;
        border:1px solid #164e63;
    }

    .hero h1{
        font-size:42px;
        color:#7dd3fc;
    }

    .grid{
        display:grid;
        grid-template-columns:repeat(auto-fit,minmax(280px,1fr));
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
        margin-bottom:10px;
        text-transform:uppercase;
    }

    .value{
        font-size:28px;
        font-weight:800;
    }

    .graph{
        position:relative;
        height:720px;
        background:#020617;
        border-radius:24px;
        border:1px solid #1e293b;
        overflow:hidden;
        margin-top:30px;
    }

    .node{
        position:absolute;
        width:180px;
        padding:18px;
        border-radius:18px;
        background:#0f172a;
        text-align:center;
        border:2px solid #334155;
    }

    .green{border-color:#22c55e;}
    .yellow{border-color:#f59e0b;}
    .red{border-color:#ef4444;}
    .blue{border-color:#38bdf8;}

    .line{
        position:absolute;
        background:#334155;
        height:3px;
        transform-origin:left center;
    }

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
        margin-bottom:20px;
    }

    </style>

    <div class="hero">
        <h1>Clinical Trial Trust Graph</h1>

        <p>
        A governed protocol-to-evidence intelligence fabric connecting
        protocol lineage, Purview governance, AI anomaly detection,
        cryptographic evidence integrity, deviation intelligence,
        dependency validation, and release defensibility.
        </p>
    </div>

    <div class="grid">

        <div class="card">
            <div class="label">Governance Confidence</div>
            <div class="value">94%</div>
        </div>

        <div class="card">
            <div class="label">Ledger Integrity</div>
            <div class="value">VERIFIED</div>
        </div>

        <div class="card">
            <div class="label">Purview Classification</div>
            <div class="value">PHI + GxP</div>
        </div>

        <div class="card">
            <div class="label">AI Risk Signal</div>
            <div class="value">REVIEW REQUIRED</div>
        </div>

    </div>

    <div class="graph">

        <div class="node blue" style="top:60px;left:70px;">
            <h3>Protocol</h3>
            <p>CT-PROT-4421</p>
        </div>

        <div class="node green" style="top:190px;left:320px;">
            <h3>eConsent</h3>
            <p>Immutable verified</p>
        </div>

        <div class="node green" style="top:360px;left:140px;">
            <h3>Patient Cohort</h3>
            <p>24 active participants</p>
        </div>

        <div class="node yellow" style="top:170px;left:620px;">
            <h3>AI Anomaly</h3>
            <p>Dosage variance</p>
        </div>

        <div class="node blue" style="top:360px;left:560px;">
            <h3>Purview</h3>
            <p>DLP retention enforced</p>
        </div>

        <div class="node green" style="top:560px;left:330px;">
            <h3>Evidence Ledger</h3>
            <p>Hash verified</p>
        </div>

        <div class="node red" style="top:540px;left:760px;">
            <h3>Deviation</h3>
            <p>CAPA unresolved</p>
        </div>

        <div class="node yellow" style="top:120px;left:960px;">
            <h3>Release Gate</h3>
            <p>Conditional hold</p>
        </div>

        <div class="line" style="top:130px;left:210px;width:190px;transform:rotate(28deg);"></div>
        <div class="line" style="top:280px;left:260px;width:160px;transform:rotate(65deg);"></div>
        <div class="line" style="top:250px;left:470px;width:180px;transform:rotate(-10deg);"></div>
        <div class="line" style="top:430px;left:420px;width:170px;transform:rotate(20deg);"></div>
        <div class="line" style="top:430px;left:710px;width:140px;transform:rotate(15deg);"></div>

    </div>

    <div class="panel">

        <h2>Governance Narrative</h2>

        <p>
        The Clinical Trial Trust Graph transforms isolated records
        into an explainable governance intelligence fabric capable of
        evaluating protocol defensibility, evidence integrity,
        Purview governance, anomaly propagation, and release readiness.
        </p>

        <div class="timeline">

            <div class="event">
                <h3>Protocol Registered</h3>
                <p>Clinical protocol hashed and baseline established.</p>
            </div>

            <div class="event">
                <h3>Purview Classification Applied</h3>
                <p>DLP retention and PHI controls attached.</p>
            </div>

            <div class="event">
                <h3>AI Anomaly Detected</h3>
                <p>Human governance review required before action.</p>
            </div>

            <div class="event">
                <h3>Release Gate Blocked</h3>
                <p>Dependency validation detected unresolved CAPA linkage.</p>
            </div>

        </div>

    </div>

    """

    return rlt_page("Clinical Trial Trust Graph", body)

'''

anchor = 'if __name__ == "__main__":'

if anchor not in text:
    raise RuntimeError("Could not locate Flask anchor.")

text = text.replace(anchor, insert_block + "\n\n" + anchor)

APP.write_text(text, encoding="utf-8")

print("Clinical Trial Trust Graph installed successfully.")
