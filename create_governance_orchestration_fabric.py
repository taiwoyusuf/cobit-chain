from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "# GOVERNANCE_ORCHESTRATION_FABRIC_ACTIVE"

if MARKER in text:
    print("Governance Orchestration Fabric already installed.")
    raise SystemExit(0)

insert_block = r'''

# GOVERNANCE_ORCHESTRATION_FABRIC_ACTIVE
@app.route("/governance-orchestration-fabric")
def governance_orchestration_fabric():

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

    .fabric{
        position:relative;
        height:760px;
        border-radius:24px;
        background:#020617;
        overflow:hidden;
        border:1px solid #1e293b;
        margin-top:30px;
    }

    .node{
        position:absolute;
        width:180px;
        padding:18px;
        border-radius:18px;
        background:#0f172a;
        border:2px solid #334155;
        text-align:center;
    }

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

        <h1>Governance Orchestration Fabric</h1>

        <p>
        A governed orchestration intelligence fabric that supervises
        escalation propagation, operational trust routing,
        explainable AI recommendations, human governance approvals,
        dependency reconciliation, and release authorization flows
        across regulated enterprise ecosystems.
        </p>

    </div>

    <div class="grid">

        <div class="card">
            <div class="label">Governance Fabric State</div>
            <div class="value green">ACTIVE</div>
        </div>

        <div class="card">
            <div class="label">AI Supervision Layer</div>
            <div class="value yellow">MONITORED</div>
        </div>

        <div class="card">
            <div class="label">Escalation Propagation</div>
            <div class="value red">IN PROGRESS</div>
        </div>

        <div class="card">
            <div class="label">Release Authorization</div>
            <div class="value yellow">PENDING REVIEW</div>
        </div>

    </div>

    <div class="panel">

        <h2>Governance Propagation Fabric</h2>

        <div class="fabric">

            <svg width="100%" height="100%" style="position:absolute;top:0;left:0;">

                <defs>

                    <marker id="blueArrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto">
                        <polygon points="0 0, 10 3, 0 6" fill="#38bdf8"/>
                    </marker>

                    <marker id="redArrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto">
                        <polygon points="0 0, 10 3, 0 6" fill="#ef4444"/>
                    </marker>

                    <marker id="greenArrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto">
                        <polygon points="0 0, 10 3, 0 6" fill="#22c55e"/>
                    </marker>

                </defs>

                <line x1="250" y1="140" x2="410" y2="140" stroke="#38bdf8" stroke-width="5" marker-end="url(#blueArrow)"/>
                <line x1="590" y1="140" x2="760" y2="140" stroke="#ef4444" stroke-width="5" marker-end="url(#redArrow)"/>
                <line x1="930" y1="140" x2="1080" y2="140" stroke="#ef4444" stroke-width="5" marker-end="url(#redArrow)"/>

                <line x1="1140" y1="230" x2="1140" y2="360" stroke="#22c55e" stroke-width="5" marker-end="url(#greenArrow)"/>

                <line x1="1000" y1="470" x2="820" y2="470" stroke="#38bdf8" stroke-width="5" marker-end="url(#blueArrow)"/>
                <line x1="650" y1="470" x2="470" y2="470" stroke="#22c55e" stroke-width="5" marker-end="url(#greenArrow)"/>
                <line x1="300" y1="470" x2="170" y2="470" stroke="#22c55e" stroke-width="5" marker-end="url(#greenArrow)"/>

            </svg>

            <div class="node blue" style="top:80px;left:60px;">
                <h3>AI Anomaly</h3>
                <p>Governance signal generated</p>
            </div>

            <div class="node blue" style="top:80px;left:410px;">
                <h3>Protocol Drift</h3>
                <p>Cross-system mismatch</p>
            </div>

            <div class="node red" style="top:80px;left:760px;">
                <h3>CAPA Exposure</h3>
                <p>Dependency unresolved</p>
            </div>

            <div class="node red" style="top:80px;left:1080px;">
                <h3>Release Gate</h3>
                <p>Authorization blocked</p>
            </div>

            <div class="node green" style="top:380px;left:1040px;">
                <h3>QA Review</h3>
                <p>Human governance review</p>
            </div>

            <div class="node green" style="top:380px;left:660px;">
                <h3>Executive Escalation</h3>
                <p>Operational supervision</p>
            </div>

            <div class="node green" style="top:380px;left:300px;">
                <h3>Audit Evidence</h3>
                <p>Trust continuity verified</p>
            </div>

            <div class="node green" style="top:380px;left:40px;">
                <h3>Purview Governance</h3>
                <p>DLP and retention enforced</p>
            </div>

        </div>

    </div>

    <div class="panel">

        <h2>Governance Intervention Engine</h2>

        <table>

            <tr>
                <th>Governance Event</th>
                <th>Automated Response</th>
                <th>Human Oversight</th>
            </tr>

            <tr>
                <td>Protocol Drift</td>
                <td>Reconciliation triggered</td>
                <td>QA review required</td>
            </tr>

            <tr>
                <td>Missing Evidence</td>
                <td>Inspection escalation initiated</td>
                <td>Compliance approval required</td>
            </tr>

            <tr>
                <td>CAPA Failure</td>
                <td>Release gate locked</td>
                <td>Executive authorization required</td>
            </tr>

            <tr>
                <td>Retention Mismatch</td>
                <td>Purview escalation triggered</td>
                <td>Governance reconciliation required</td>
            </tr>

        </table>

    </div>

    <div class="panel">

        <h2>Human Governance Authority</h2>

        <div class="decision danger">
            AI RECOMMENDATIONS REMAIN ADVISORY ONLY
        </div>

        <p style="margin-top:25px;line-height:1.9;">
        The orchestration fabric supervises governance escalation routing,
        operational trust propagation, dependency reconciliation,
        and release exposure analysis.
        Human governance reviewers remain the authoritative approval layer
        for regulated operational decisions.
        </p>

        <div class="decision safe">
            RECOMMENDATION: EXECUTE HUMAN REVIEW BEFORE OPERATIONAL RELEASE AUTHORIZATION
        </div>

    </div>

    """

    return rlt_page("Governance Orchestration Fabric", body)

'''

anchor = 'if __name__ == "__main__":'

if anchor not in text:
    raise RuntimeError("Could not locate Flask anchor.")

text = text.replace(anchor, insert_block + "\n\n" + anchor)

APP.write_text(text, encoding="utf-8")

print("Governance Orchestration Fabric installed successfully.")
