from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "# GOVERNANCE_SIMULATION_LAB_ACTIVE"

if MARKER in text:
    print("Governance Simulation Lab already installed.")
    raise SystemExit(0)

insert_block = r'''

# GOVERNANCE_SIMULATION_LAB_ACTIVE
@app.route("/governance-simulation-lab")
def governance_simulation_lab():

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
        line-height:1.9;
        max-width:1200px;
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

        <h1>Governance Simulation Lab</h1>

        <p>
        A predictive governance intelligence environment used to simulate
        operational trust degradation, inspection exposure propagation,
        protocol survivability, evidence continuity instability,
        dependency escalation, and release authorization outcomes
        before real-world regulatory impact occurs.
        </p>

    </div>

    <div class="grid">

        <div class="card">
            <div class="label">Current Survivability</div>
            <div class="value yellow">82%</div>
        </div>

        <div class="card">
            <div class="label">Projected After Reconciliation</div>
            <div class="value green">96%</div>
        </div>

        <div class="card">
            <div class="label">Projected After Additional Drift</div>
            <div class="value red">61%</div>
        </div>

        <div class="card">
            <div class="label">Inspection Exposure Forecast</div>
            <div class="value red">ELEVATED</div>
        </div>

    </div>

    <div class="panel">

        <h2>Governance Stress Timeline</h2>

        <div class="timeline">

            <div class="event">
                <h3>T+0 : AI anomaly detected</h3>
                <p>
                Unexpected dosage variance identified across monitored evidence streams.
                </p>
            </div>

            <div class="event">
                <h3>T+1 : Protocol drift propagates</h3>
                <p>
                Cross-system reconciliation mismatch spreads into downstream governance layers.
                </p>
            </div>

            <div class="event">
                <h3>T+2 : CAPA dependency exposed</h3>
                <p>
                Governance closure chain instability begins affecting release defensibility.
                </p>
            </div>

            <div class="event">
                <h3>T+3 : Inspection exposure elevated</h3>
                <p>
                Missing monitoring evidence weakens inspection continuity narrative.
                </p>
            </div>

            <div class="event">
                <h3>T+4 : Release gate blocked</h3>
                <p>
                Human governance authorization required before operational release approval.
                </p>
            </div>

        </div>

    </div>

    <div class="panel">

        <h2>Predictive Governance Scenarios</h2>

        <table>

            <tr>
                <th>Scenario</th>
                <th>Predicted Outcome</th>
                <th>Governance Impact</th>
            </tr>

            <tr>
                <td>Missing Monitoring Evidence</td>
                <td class="yellow">Submission Risk Increase</td>
                <td>Inspection defensibility weakened</td>
            </tr>

            <tr>
                <td>CAPA Unresolved</td>
                <td class="red">Release Blocked</td>
                <td>Operational trust instability</td>
            </tr>

            <tr>
                <td>Purview Retention Drift</td>
                <td class="yellow">Evidence Trust Reduction</td>
                <td>Governance continuity weakened</td>
            </tr>

            <tr>
                <td>Ledger Verification Failure</td>
                <td class="red">Defensibility Collapse</td>
                <td>Evidence authenticity compromised</td>
            </tr>

            <tr>
                <td>Protocol Drift</td>
                <td class="red">Inspection Exposure Increase</td>
                <td>Cross-system reconciliation required</td>
            </tr>

        </table>

    </div>

    <div class="panel">

        <h2>Governance Attack Surface Projection</h2>

        <table>

            <tr>
                <th>Operational Layer</th>
                <th>Projected Risk</th>
                <th>Future Exposure</th>
            </tr>

            <tr>
                <td>Submission Defensibility</td>
                <td class="red">HIGH</td>
                <td>Release survivability instability</td>
            </tr>

            <tr>
                <td>Inspection Continuity</td>
                <td class="yellow">MEDIUM</td>
                <td>Monitoring lineage gaps</td>
            </tr>

            <tr>
                <td>Evidence Integrity</td>
                <td class="green">LOW</td>
                <td>Ledger trust remains stable</td>
            </tr>

            <tr>
                <td>Governance Reconciliation</td>
                <td class="red">HIGH</td>
                <td>Cross-system drift propagation</td>
            </tr>

        </table>

        <div class="decision danger">
            PROJECTED RELEASE POSTURE WILL BECOME NON-DEFENSIBLE IF CURRENT DRIFT CONTINUES
        </div>

        <div class="decision safe">
            RECOMMENDATION: EXECUTE RECONCILIATION AND CAPA CLOSURE BEFORE RELEASE WINDOW
        </div>

    </div>

    """

    return rlt_page("Governance Simulation Lab", body)

'''

anchor = 'if __name__ == "__main__":'

if anchor not in text:
    raise RuntimeError("Could not locate Flask anchor.")

text = text.replace(anchor, insert_block + "\n\n" + anchor)

APP.write_text(text, encoding="utf-8")

print("Governance Simulation Lab installed successfully.")
