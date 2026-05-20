from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "# GOVERNANCE_REASONING_ENGINE_ACTIVE"

if MARKER in text:
    print("Governance Reasoning Engine already installed.")
    raise SystemExit(0)

insert_block = r'''

# GOVERNANCE_REASONING_ENGINE_ACTIVE
@app.route("/governance-reasoning-engine")
def governance_reasoning_engine():

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

    .chain{
        margin-top:30px;
        padding:20px;
    }

    .step{
        margin-bottom:22px;
        padding:20px;
        border-radius:18px;
        background:#08111f;
        border-left:6px solid #38bdf8;
    }

    .arrow{
        text-align:center;
        font-size:36px;
        color:#38bdf8;
        margin-bottom:16px;
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

        <h1>Governance Reasoning Engine</h1>

        <p>
        An explainable governance intelligence layer that traces
        protocol exposure, dependency propagation, evidence drift,
        AI-assisted anomaly escalation, operational trust degradation,
        and release defensibility reasoning across regulated ecosystems.
        </p>

    </div>

    <div class="grid">

        <div class="card">
            <div class="label">Governance Confidence</div>
            <div class="value green">91%</div>
        </div>

        <div class="card">
            <div class="label">Reasoning Traceability</div>
            <div class="value blue">ACTIVE</div>
        </div>

        <div class="card">
            <div class="label">AI Advisory Status</div>
            <div class="value yellow">HUMAN REVIEW</div>
        </div>

        <div class="card">
            <div class="label">Release Posture</div>
            <div class="value red">BLOCKED</div>
        </div>

    </div>

    <div class="panel">

        <h2>Governance Reasoning Chain</h2>

        <div class="chain">

            <div class="step">
                <h3>AI anomaly detected</h3>
                <p>
                Dosage variance identified across monitored evidence streams.
                </p>
            </div>

            <div class="arrow">?</div>

            <div class="step">
                <h3>Cross-system drift verified</h3>
                <p>
                Protocol reconciliation mismatch detected between monitoring and TMF layers.
                </p>
            </div>

            <div class="arrow">?</div>

            <div class="step">
                <h3>CAPA dependency unresolved</h3>
                <p>
                Governance closure chain remains incomplete across downstream review layers.
                </p>
            </div>

            <div class="arrow">?</div>

            <div class="step">
                <h3>Submission exposure elevated</h3>
                <p>
                Inspection defensibility weakened because evidence continuity is incomplete.
                </p>
            </div>

            <div class="arrow">?</div>

            <div class="step">
                <h3>Release gate blocked</h3>
                <p>
                Human governance authorization required before operational release approval.
                </p>
            </div>

        </div>

    </div>

    <div class="panel">

        <h2>Explainability Matrix</h2>

        <table>

            <tr>
                <th>Governance Signal</th>
                <th>Confidence</th>
                <th>Operational Impact</th>
            </tr>

            <tr>
                <td>Protocol Drift</td>
                <td class="red">96%</td>
                <td>High submission exposure</td>
            </tr>

            <tr>
                <td>Retention Mismatch</td>
                <td class="yellow">81%</td>
                <td>Medium governance instability</td>
            </tr>

            <tr>
                <td>Missing Monitoring Evidence</td>
                <td class="red">92%</td>
                <td>Critical inspection impact</td>
            </tr>

            <tr>
                <td>Ledger Integrity</td>
                <td class="green">99%</td>
                <td>Evidence trust maintained</td>
            </tr>

        </table>

    </div>

    <div class="panel">

        <h2>Human Governance Authority</h2>

        <div class="decision danger">
            AI DID NOT MAKE THE REGULATED DECISION
        </div>

        <p style="margin-top:25px;line-height:1.9;">
        The AI layer remains advisory only.
        Governance recommendations are routed into human QA,
        compliance, validation, and operational review workflows.
        Human governance remains the authoritative control layer.
        </p>

        <div class="decision safe">
            RECOMMENDATION: DO NOT AUTHORIZE RELEASE UNTIL RECONCILIATION IS COMPLETE
        </div>

    </div>

    """

    return rlt_page("Governance Reasoning Engine", body)

'''

anchor = 'if __name__ == "__main__":'

if anchor not in text:
    raise RuntimeError("Could not locate Flask anchor.")

text = text.replace(anchor, insert_block + "\n\n" + anchor)

APP.write_text(text, encoding="utf-8")

print("Governance Reasoning Engine installed successfully.")
