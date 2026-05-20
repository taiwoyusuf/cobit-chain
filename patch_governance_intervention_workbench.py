from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# GOVERNANCE_INTERVENTION_WORKBENCH_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

route_code = r'''

# GOVERNANCE_INTERVENTION_WORKBENCH_ACTIVE
@app.route("/governance-intervention-workbench")
def governance_intervention_workbench_view():
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Governance Intervention Workbench™ | COBIT-Chain™ / AssuranceLayer™</title>
    <style>
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: Arial, Helvetica, sans-serif;
            background: #f4f7fb;
            color: #172033;
        }
        .shell {
            max-width: 1400px;
            margin: 0 auto;
            padding: 28px 22px 42px;
        }
        .topbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 16px;
            margin-bottom: 22px;
            flex-wrap: wrap;
        }
        .brand {
            font-size: 14px;
            font-weight: 700;
            color: #335caa;
            letter-spacing: .04em;
            text-transform: uppercase;
        }
        .nav-links {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        .nav-links a {
            text-decoration: none;
            color: #163a72;
            background: #e8f0ff;
            padding: 9px 12px;
            border-radius: 999px;
            font-size: 13px;
            font-weight: 700;
        }
        .hero {
            background: linear-gradient(135deg, #24144d 0%, #352278 52%, #174c9d 100%);
            color: #fff;
            border-radius: 26px;
            padding: 28px;
            box-shadow: 0 16px 42px rgba(36, 20, 77, .22);
            margin-bottom: 20px;
        }
        .eyebrow {
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: .08em;
            opacity: .82;
            font-weight: 700;
            margin-bottom: 10px;
        }
        h1 {
            margin: 0 0 10px;
            font-size: 35px;
            line-height: 1.15;
        }
        .hero p {
            max-width: 1000px;
            margin: 0;
            line-height: 1.56;
            font-size: 16px;
            opacity: .95;
        }
        .hero-grid {
            display: grid;
            grid-template-columns: repeat(5, minmax(0, 1fr));
            gap: 12px;
            margin-top: 22px;
        }
        .hero-card {
            background: rgba(255,255,255,.12);
            border: 1px solid rgba(255,255,255,.18);
            border-radius: 18px;
            padding: 15px;
        }
        .hero-label {
            font-size: 12px;
            opacity: .80;
            text-transform: uppercase;
            letter-spacing: .06em;
            margin-bottom: 7px;
        }
        .hero-value {
            font-size: 20px;
            font-weight: 900;
        }
        .hero-note {
            font-size: 12px;
            opacity: .84;
            margin-top: 5px;
            line-height: 1.35;
        }
        .grid-2 {
            display: grid;
            grid-template-columns: 1.05fr .95fr;
            gap: 18px;
            margin-bottom: 18px;
        }
        .grid-3 {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 16px;
            margin-bottom: 18px;
        }
        .panel {
            background: #fff;
            border-radius: 22px;
            padding: 22px;
            box-shadow: 0 10px 28px rgba(22, 42, 74, .08);
        }
        .panel h2 {
            margin: 0 0 15px;
            font-size: 20px;
        }
        .panel p {
            line-height: 1.55;
            margin: 0 0 14px;
            color: #44536b;
        }
        .case-banner {
            display: grid;
            grid-template-columns: 1.1fr .9fr;
            gap: 14px;
            align-items: stretch;
        }
        .case-card {
            background: #fff1f2;
            border: 1px solid #fecdd3;
            border-radius: 20px;
            padding: 18px;
        }
        .case-card h3 {
            margin: 0 0 8px;
            font-size: 18px;
        }
        .case-meta {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 10px;
            margin-top: 14px;
        }
        .mini {
            background: rgba(255,255,255,.72);
            border-radius: 14px;
            padding: 12px;
        }
        .mini-label {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #6b7280;
            margin-bottom: 5px;
            font-weight: 800;
        }
        .mini-value {
            font-size: 15px;
            font-weight: 900;
        }
        .decision-card {
            background: #f8fbff;
            border: 1px solid #dfe8f7;
            border-radius: 20px;
            padding: 18px;
        }
        .decision-title {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .06em;
            color: #617089;
            font-weight: 800;
            margin-bottom: 8px;
        }
        .decision-value {
            font-size: 28px;
            font-weight: 900;
            color: #7f1d1d;
            margin-bottom: 8px;
        }
        .decision-note {
            color: #4d5b73;
            line-height: 1.5;
        }
        .lane-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 14px;
        }
        .lane {
            border-radius: 20px;
            padding: 18px;
            border: 1px solid #e2eaf7;
            background: #f8fbff;
        }
        .lane.red {
            background: #fff1f2;
            border-color: #fecdd3;
        }
        .lane.amber {
            background: #fffbeb;
            border-color: #fde68a;
        }
        .lane.blue {
            background: #eff6ff;
            border-color: #bfdbfe;
        }
        .lane.green {
            background: #ecfdf5;
            border-color: #a7f3d0;
        }
        .lane-title {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #5d6c84;
            font-weight: 800;
            margin-bottom: 9px;
        }
        .lane h3 {
            margin: 0 0 10px;
            font-size: 17px;
        }
        .lane ul {
            margin: 0;
            padding-left: 18px;
            color: #46556d;
            line-height: 1.55;
            font-size: 14px;
        }
        .workflow {
            display: grid;
            grid-template-columns: repeat(5, minmax(0, 1fr));
            gap: 12px;
        }
        .step {
            border-radius: 18px;
            padding: 16px;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
            position: relative;
        }
        .step-number {
            width: 32px;
            height: 32px;
            border-radius: 11px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: #173f86;
            color: #fff;
            font-weight: 900;
            margin-bottom: 12px;
        }
        .step h3 {
            margin: 0 0 8px;
            font-size: 16px;
        }
        .step p {
            margin: 0;
            font-size: 14px;
        }
        .controls {
            display: flex;
            gap: 10px;
            align-items: center;
            flex-wrap: wrap;
            margin-bottom: 16px;
        }
        .filter-btn {
            border: 0;
            cursor: pointer;
            border-radius: 999px;
            padding: 9px 13px;
            font-size: 13px;
            font-weight: 800;
            background: #e8f0ff;
            color: #173f86;
        }
        .filter-btn.active {
            background: #173f86;
            color: #fff;
        }
        .search {
            margin-left: auto;
            min-width: 300px;
            border: 1px solid #d7e1f0;
            border-radius: 999px;
            padding: 10px 14px;
            font-size: 14px;
            outline: none;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            overflow: hidden;
            border-radius: 18px;
        }
        th, td {
            text-align: left;
            padding: 13px 12px;
            border-bottom: 1px solid #e8edf5;
            font-size: 14px;
            vertical-align: top;
        }
        th {
            background: #eff4fb;
            color: #31415b;
            text-transform: uppercase;
            font-size: 12px;
            letter-spacing: .05em;
        }
        tr:last-child td { border-bottom: none; }
        .pill {
            display: inline-block;
            border-radius: 999px;
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 800;
            white-space: nowrap;
        }
        .pill.red {
            background: #fee2e2;
            color: #991b1b;
        }
        .pill.amber {
            background: #fef3c7;
            color: #92400e;
        }
        .pill.green {
            background: #dcfce7;
            color: #166534;
        }
        .pill.blue {
            background: #dbeafe;
            color: #1d4ed8;
        }
        .evidence-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .evidence-card {
            background: #f7faff;
            border: 1px solid #e2eaf7;
            border-radius: 18px;
            padding: 16px;
        }
        .evidence-card h3 {
            margin: 0 0 8px;
            font-size: 16px;
        }
        .evidence-card p {
            margin: 0 0 11px;
            font-size: 14px;
        }
        .gate {
            display: flex;
            align-items: center;
            gap: 9px;
            font-size: 13px;
            color: #4e5d75;
            font-weight: 700;
        }
        .dot {
            width: 11px;
            height: 11px;
            border-radius: 999px;
            flex: 0 0 11px;
        }
        .dot.red { background: #dc2626; }
        .dot.amber { background: #f59e0b; }
        .dot.green { background: #16a34a; }
        .reclose-grid {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 14px;
        }
        .reclose {
            border-radius: 18px;
            padding: 17px;
            border-left: 5px solid #173f86;
            background: #f8fbff;
        }
        .reclose.red { border-left-color: #b91c1c; }
        .reclose.amber { border-left-color: #d97706; }
        .reclose.green { border-left-color: #15803d; }
        .reclose h3 {
            margin: 0 0 8px;
            font-size: 16px;
        }
        .reclose p {
            margin: 0;
            font-size: 14px;
        }
        .footer-note {
            margin-top: 18px;
            color: #5c6a80;
            font-size: 13px;
            line-height: 1.5;
        }
        @media (max-width: 1180px) {
            .hero-grid {
                grid-template-columns: repeat(3, minmax(0, 1fr));
            }
            .grid-2,
            .grid-3,
            .case-banner {
                grid-template-columns: 1fr;
            }
            .lane-grid,
            .workflow,
            .evidence-grid,
            .reclose-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }
        @media (max-width: 760px) {
            .hero-grid,
            .lane-grid,
            .workflow,
            .evidence-grid,
            .reclose-grid,
            .case-meta {
                grid-template-columns: 1fr;
            }
            .search {
                margin-left: 0;
                width: 100%;
                min-width: 0;
            }
            h1 {
                font-size: 28px;
            }
        }
    </style>
</head>
<body>
    <div class="shell">
        <div class="topbar">
            <div class="brand">COBIT-Chain™ / AssuranceLayer™</div>
            <div class="nav-links">
                <a href="/governance-assurance-register">Assurance Register</a>
                <a href="/governance-passport">Governance Passport</a>
                <a href="/governance-decision-engine">Decision Engine</a>
                <a href="/governance-recovery-simulator">Recovery Simulator</a>
            </div>
        </div>

        <section class="hero">
            <div class="eyebrow">Enterprise Recovery Orchestration Layer</div>
            <h1>Governance Intervention Workbench™</h1>
            <p>
                The point where governance intelligence becomes controlled action. Once COBIT-Chain™ detects a false closure,
                broken dependency, or release blocker, the workbench converts that finding into a structured recovery plan:
                immediate controls, evidence requirements, accountable owners, closure gates, and the exact conditions that
                must be true before the enterprise may safely re-close the case.
            </p>

            <div class="hero-grid">
                <div class="hero-card">
                    <div class="hero-label">Selected Passport</div>
                    <div class="hero-value">GP-2026-001</div>
                    <div class="hero-note">False closure before release</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Intervention Status</div>
                    <div class="hero-value">Active</div>
                    <div class="hero-note">Cross-functional recovery underway</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Blocking Gates</div>
                    <div class="hero-value">3</div>
                    <div class="hero-note">Must clear before re-close</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Action Owners</div>
                    <div class="hero-value">4</div>
                    <div class="hero-note">QA, IT Security, QC, Engineering</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Current Decision</div>
                    <div class="hero-value">Hold</div>
                    <div class="hero-note">Release remains blocked</div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Selected Governance Case</h2>
                <div class="case-banner">
                    <div class="case-card">
                        <h3>GP-2026-001 — False Closure Before Batch Release</h3>
                        <p>
                            ServiceNow shows the work item as closed, but the wider enterprise chain is not yet true:
                            the Veeva CAPA remains open, myAccess evidence does not align with the approved entitlement,
                            and the Blue Mountain operational state has not been fully reconciled.
                        </p>
                        <div class="case-meta">
                            <div class="mini">
                                <div class="mini-label">Broken Chain</div>
                                <div class="mini-value">ServiceNow → Veeva → Blue Mountain</div>
                            </div>
                            <div class="mini">
                                <div class="mini-label">Risk Type</div>
                                <div class="mini-value">False Assurance</div>
                            </div>
                            <div class="mini">
                                <div class="mini-label">Primary Owner</div>
                                <div class="mini-value">QA Governance</div>
                            </div>
                            <div class="mini">
                                <div class="mini-label">Aging</div>
                                <div class="mini-value">11 Days</div>
                            </div>
                        </div>
                    </div>

                    <div class="decision-card">
                        <div class="decision-title">Current Control Decision</div>
                        <div class="decision-value">Do Not Re-Close</div>
                        <div class="decision-note">
                            The work item may only be re-closed when the open CAPA, entitlement mismatch,
                            and equipment-state reconciliation are all resolved and evidenced.
                        </div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Intervention Logic</h2>
                <p>
                    This is not a normal task board. It is a governed recovery board.
                    A task is not “done” merely because someone clicked complete; it is done only when the required
                    evidence exists, the related systems agree, and the re-closure gate passes.
                </p>
                <div class="reclose-grid">
                    <div class="reclose red">
                        <h3>1. Contain</h3>
                        <p>Freeze unsafe progression and stop the enterprise from acting on false closure.</p>
                    </div>
                    <div class="reclose amber">
                        <h3>2. Reconcile</h3>
                        <p>Repair the broken truth chain across systems, owners, and evidence.</p>
                    </div>
                    <div class="reclose green">
                        <h3>3. Re-Close</h3>
                        <p>Only permit closure after the passport becomes fully defensible again.</p>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Cross-Functional Intervention Lanes</h2>
            <p>
                Each lane shows the minimum work required from the responsible function before the case can move forward.
            </p>

            <div class="lane-grid">
                <div class="lane red">
                    <div class="lane-title">QA Governance</div>
                    <h3>Contain Release Risk</h3>
                    <ul>
                        <li>Confirm the active CAPA remains a release blocker.</li>
                        <li>Document why the prior closure was not defensible.</li>
                        <li>Maintain hold until dependency validation clears.</li>
                    </ul>
                </div>
                <div class="lane amber">
                    <div class="lane-title">IT Security</div>
                    <h3>Repair Access Truth</h3>
                    <ul>
                        <li>Reconcile ServiceNow request with myAccess approval.</li>
                        <li>Verify entitlement granted matches authorized role.</li>
                        <li>Attach approval evidence to the passport record.</li>
                    </ul>
                </div>
                <div class="lane blue">
                    <div class="lane-title">Engineering / Operations</div>
                    <h3>Resolve Equipment State</h3>
                    <ul>
                        <li>Validate Blue Mountain equipment status.</li>
                        <li>Confirm operational state matches governed record.</li>
                        <li>Escalate any unresolved discrepancy.</li>
                    </ul>
                </div>
                <div class="lane green">
                    <div class="lane-title">QC / Release</div>
                    <h3>Protect Downstream Decision</h3>
                    <ul>
                        <li>Confirm no downstream LIS or middleware blockers remain.</li>
                        <li>Record final release dependency confirmation.</li>
                        <li>Accept release only after re-closure gate passes.</li>
                    </ul>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Governed Recovery Sequence</h2>
            <div class="workflow">
                <div class="step">
                    <div class="step-number">1</div>
                    <h3>Freeze</h3>
                    <p>Prevent release or downstream progression while enterprise truth is broken.</p>
                </div>
                <div class="step">
                    <div class="step-number">2</div>
                    <h3>Assign</h3>
                    <p>Route each broken dependency to the accountable system owner.</p>
                </div>
                <div class="step">
                    <div class="step-number">3</div>
                    <h3>Evidence</h3>
                    <p>Require the exact proof needed to repair the governance passport.</p>
                </div>
                <div class="step">
                    <div class="step-number">4</div>
                    <h3>Validate</h3>
                    <p>Re-run reconciliation, dependency, and false-closure checks.</p>
                </div>
                <div class="step">
                    <div class="step-number">5</div>
                    <h3>Re-Close</h3>
                    <p>Permit closure only after all required gates return defensible.</p>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Intervention Action Board</h2>
            <p>
                Every action is tied to a closure gate. The board records not only who must act, but what evidence
                must exist before the system accepts the action as complete.
            </p>

            <div class="controls">
                <button class="filter-btn active" data-filter="all">All Actions</button>
                <button class="filter-btn" data-filter="blocking">Blocking</button>
                <button class="filter-btn" data-filter="in-progress">In Progress</button>
                <button class="filter-btn" data-filter="ready">Ready</button>
                <input id="searchInput" class="search" type="text" placeholder="Search owner, evidence, system, or action...">
            </div>

            <table id="interventionTable">
                <thead>
                    <tr>
                        <th>Sequence</th>
                        <th>Action</th>
                        <th>Owner</th>
                        <th>Evidence Required</th>
                        <th>System Gate</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    <tr data-status="blocking" data-search="qa governance capa veeva release hold blocker disposition">
                        <td>01</td>
                        <td>Confirm CAPA release dependency</td>
                        <td>QA Governance</td>
                        <td>Veeva CAPA status + release-impact rationale</td>
                        <td>No unresolved CAPA blocker</td>
                        <td><span class="pill red">Blocking</span></td>
                    </tr>
                    <tr data-status="blocking" data-search="it security myaccess entitlement approval servicenow privileged account mismatch">
                        <td>02</td>
                        <td>Reconcile entitlement approval</td>
                        <td>IT Security</td>
                        <td>myAccess approval + granted entitlement evidence</td>
                        <td>Approval = entitlement</td>
                        <td><span class="pill red">Blocking</span></td>
                    </tr>
                    <tr data-status="in-progress" data-search="engineering blue mountain equipment operational state reconciliation">
                        <td>03</td>
                        <td>Validate equipment-state reconciliation</td>
                        <td>Engineering</td>
                        <td>Blue Mountain state + supporting operational record</td>
                        <td>Record state = actual state</td>
                        <td><span class="pill amber">In Progress</span></td>
                    </tr>
                    <tr data-status="in-progress" data-search="qc middleware lis release dependency confirmation downstream assurance">
                        <td>04</td>
                        <td>Confirm downstream release chain</td>
                        <td>QC Operations</td>
                        <td>Middleware / LIS dependency confirmation</td>
                        <td>No downstream release blocker</td>
                        <td><span class="pill amber">In Progress</span></td>
                    </tr>
                    <tr data-status="ready" data-search="qa governance rerun passport false closure dependency reconciliation validation">
                        <td>05</td>
                        <td>Re-run passport validation</td>
                        <td>QA Governance</td>
                        <td>Updated evidence chain across all linked systems</td>
                        <td>All checks defensible</td>
                        <td><span class="pill blue">Ready Next</span></td>
                    </tr>
                    <tr data-status="ready" data-search="qa governance reclosing final approval closure decision audit defensibility">
                        <td>06</td>
                        <td>Authorize controlled re-closure</td>
                        <td>QA Governance</td>
                        <td>Final signed closure rationale</td>
                        <td>Passport = Green</td>
                        <td><span class="pill blue">Ready Next</span></td>
                    </tr>
                </tbody>
            </table>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Evidence Gates Before Re-Closure</h2>
                <div class="evidence-grid">
                    <div class="evidence-card">
                        <h3>CAPA Gate</h3>
                        <p>Open deviation/CAPA blockers must be resolved or formally dispositioned.</p>
                        <div class="gate"><span class="dot red"></span>Not yet cleared</div>
                    </div>
                    <div class="evidence-card">
                        <h3>Access Gate</h3>
                        <p>Requested role, approved role, and granted role must match exactly.</p>
                        <div class="gate"><span class="dot red"></span>Mismatch remains</div>
                    </div>
                    <div class="evidence-card">
                        <h3>Reconciliation Gate</h3>
                        <p>Veeva and Blue Mountain records must tell one consistent story.</p>
                        <div class="gate"><span class="dot amber"></span>Partial evidence</div>
                    </div>
                    <div class="evidence-card">
                        <h3>Release Gate</h3>
                        <p>Middleware, LIS, and release dependencies must be fully confirmed.</p>
                        <div class="gate"><span class="dot amber"></span>Pending confirmation</div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>What This Adds to COBIT-Chain™</h2>
                <p>
                    The Assurance Register tells executives <strong>where intervention is needed</strong>.
                </p>
                <p>
                    The Governance Intervention Workbench™ tells the enterprise <strong>how to recover safely</strong>:
                    who must act, what proof is required, what must be revalidated, and what must be true before closure is allowed.
                </p>
                <p>
                    That makes the platform materially more advanced than a dashboard or workflow tool.
                    It is now behaving like a governance control plane that can prevent false completion from becoming
                    deviation, CAPA, audit finding, or release failure.
                </p>
                <div class="footer-note">
                    Simulation chain: pain point detection → dependency validation → reconciliation → decision intelligence →
                    Governance Passport™ → Governance Assurance Register™ → Governance Intervention Workbench™.
                </div>
            </div>
        </section>
    </div>

    <script>
        const buttons = document.querySelectorAll(".filter-btn");
        const rows = document.querySelectorAll("#interventionTable tbody tr");
        const searchInput = document.getElementById("searchInput");
        let activeFilter = "all";

        function applyFilters() {
            const query = searchInput.value.toLowerCase().trim();

            rows.forEach(row => {
                const status = row.dataset.status;
                const searchable = row.dataset.search;
                const matchesFilter = activeFilter === "all" || status === activeFilter;
                const matchesSearch = searchable.includes(query);
                row.style.display = matchesFilter && matchesSearch ? "" : "none";
            });
        }

        buttons.forEach(button => {
            button.addEventListener("click", () => {
                buttons.forEach(btn => btn.classList.remove("active"));
                button.classList.add("active");
                activeFilter = button.dataset.filter;
                applyFilters();
            });
        });

        searchInput.addEventListener("input", applyFilters);
    </script>
</body>
</html>
    """)
'''

def main():
    if not APP_FILE.exists():
        raise SystemExit("ERROR: app.py was not found in the current folder.")

    text = APP_FILE.read_text(encoding="utf-8")

    if ACTIVE_MARKER in text:
        print("SKIP: GOVERNANCE_INTERVENTION_WORKBENCH_ACTIVE already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, route_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        '@app.route("/governance-intervention-workbench")',
        "Governance Intervention Workbench™",
        "Cross-Functional Intervention Lanes",
        "Governed Recovery Sequence",
        "Intervention Action Board",
        "Evidence Gates Before Re-Closure",
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: /governance-intervention-workbench route inserted safely.")
    print("VERIFIED: required markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
