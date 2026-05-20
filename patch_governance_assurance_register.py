from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# GOVERNANCE_ASSURANCE_REGISTER_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

route_code = r'''

# GOVERNANCE_ASSURANCE_REGISTER_ACTIVE
@app.route("/governance-assurance-register")
def governance_assurance_register_view():
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Governance Assurance Register™ | COBIT-Chain™ / AssuranceLayer™</title>
    <style>
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: Arial, Helvetica, sans-serif;
            background: #f4f7fb;
            color: #172033;
        }
        .shell {
            max-width: 1380px;
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
            background: linear-gradient(135deg, #102544 0%, #153b76 52%, #1f5bb7 100%);
            color: #fff;
            border-radius: 26px;
            padding: 28px;
            box-shadow: 0 16px 42px rgba(15, 37, 68, .22);
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
            max-width: 980px;
            margin: 0;
            line-height: 1.56;
            font-size: 16px;
            opacity: .95;
        }
        .kpis {
            display: grid;
            grid-template-columns: repeat(6, minmax(0, 1fr));
            gap: 12px;
            margin-top: 22px;
        }
        .kpi {
            background: rgba(255,255,255,.12);
            border: 1px solid rgba(255,255,255,.18);
            border-radius: 18px;
            padding: 15px;
        }
        .kpi-label {
            font-size: 12px;
            opacity: .80;
            text-transform: uppercase;
            letter-spacing: .06em;
            margin-bottom: 7px;
        }
        .kpi-value {
            font-size: 22px;
            font-weight: 900;
        }
        .kpi-note {
            font-size: 12px;
            opacity: .84;
            margin-top: 5px;
            line-height: 1.35;
        }
        .grid-2 {
            display: grid;
            grid-template-columns: 1.1fr .9fr;
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
        .portfolio-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .portfolio-card {
            border-radius: 18px;
            padding: 16px;
            border: 1px solid #e2eaf7;
            background: #f8fbff;
        }
        .portfolio-card.red {
            background: #fff1f2;
            border-color: #fecdd3;
        }
        .portfolio-card.amber {
            background: #fffbeb;
            border-color: #fde68a;
        }
        .portfolio-card.blue {
            background: #eff6ff;
            border-color: #bfdbfe;
        }
        .portfolio-card.green {
            background: #ecfdf5;
            border-color: #a7f3d0;
        }
        .portfolio-title {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #617089;
            font-weight: 800;
            margin-bottom: 8px;
        }
        .portfolio-value {
            font-size: 25px;
            font-weight: 900;
            margin-bottom: 7px;
        }
        .portfolio-note {
            font-size: 13px;
            line-height: 1.42;
            color: #516078;
        }
        .heatmap {
            display: grid;
            grid-template-columns: 1.3fr repeat(4, minmax(0, 1fr));
            gap: 8px;
            align-items: stretch;
        }
        .heat-cell,
        .heat-head,
        .heat-label {
            border-radius: 14px;
            padding: 12px;
            font-size: 13px;
        }
        .heat-head {
            background: #eef4fc;
            text-transform: uppercase;
            font-weight: 800;
            color: #4a5a73;
            text-align: center;
            letter-spacing: .04em;
        }
        .heat-label {
            background: #f8fbff;
            font-weight: 800;
        }
        .heat-cell {
            text-align: center;
            font-weight: 900;
            border: 1px solid transparent;
        }
        .heat-cell.red {
            background: #fee2e2;
            color: #991b1b;
            border-color: #fecaca;
        }
        .heat-cell.amber {
            background: #fef3c7;
            color: #92400e;
            border-color: #fde68a;
        }
        .heat-cell.green {
            background: #dcfce7;
            color: #166534;
            border-color: #bbf7d0;
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
            min-width: 280px;
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
        .priority {
            font-weight: 900;
            color: #102544;
        }
        .cluster {
            border-left: 5px solid #173f86;
            background: #f7faff;
            border-radius: 18px;
            padding: 16px;
        }
        .cluster.red { border-left-color: #b91c1c; }
        .cluster.amber { border-left-color: #d97706; }
        .cluster.blue { border-left-color: #2563eb; }
        .cluster h3 {
            margin: 0 0 8px;
            font-size: 16px;
        }
        .cluster p {
            font-size: 14px;
            margin: 0;
        }
        .queue {
            display: grid;
            gap: 12px;
        }
        .queue-item {
            display: grid;
            grid-template-columns: 58px 1fr auto;
            gap: 14px;
            align-items: start;
            background: #f8fbff;
            border: 1px solid #e1e9f6;
            border-radius: 18px;
            padding: 15px;
        }
        .queue-number {
            width: 42px;
            height: 42px;
            border-radius: 14px;
            background: #173f86;
            color: #fff;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 900;
        }
        .queue-title {
            font-weight: 900;
            margin-bottom: 5px;
        }
        .queue-note {
            color: #53637b;
            line-height: 1.45;
            font-size: 14px;
        }
        .queue-owner {
            text-align: right;
            font-size: 12px;
            color: #617089;
            text-transform: uppercase;
            font-weight: 800;
            letter-spacing: .05em;
        }
        .footer-note {
            margin-top: 18px;
            color: #5c6a80;
            font-size: 13px;
            line-height: 1.5;
        }
        @media (max-width: 1150px) {
            .kpis {
                grid-template-columns: repeat(3, minmax(0, 1fr));
            }
            .grid-2,
            .grid-3 {
                grid-template-columns: 1fr;
            }
            .portfolio-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }
        @media (max-width: 760px) {
            .kpis,
            .portfolio-grid {
                grid-template-columns: 1fr;
            }
            .heatmap {
                grid-template-columns: 1fr;
            }
            .heat-head {
                display: none;
            }
            .search {
                margin-left: 0;
                width: 100%;
                min-width: 0;
            }
            .queue-item {
                grid-template-columns: 1fr;
            }
            .queue-owner {
                text-align: left;
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
                <a href="/governance-passport">Governance Passport</a>
                <a href="/governance-decision-engine">Decision Engine</a>
                <a href="/governance-reconciliation-layer">Reconciliation Layer</a>
                <a href="/executive-mission-control">Mission Control</a>
            </div>
        </div>

        <section class="hero">
            <div class="eyebrow">Enterprise Portfolio Truth Layer</div>
            <h1>Governance Assurance Register™</h1>
            <p>
                A governed portfolio view of every active Governance Passport™ across the enterprise.
                The register does not simply list open work; it shows which records are truly defensible,
                which closures are false, which dependency chains are broken, and where leadership intervention
                is required before risk becomes deviation, audit finding, or release failure.
            </p>

            <div class="kpis">
                <div class="kpi">
                    <div class="kpi-label">Active Passports</div>
                    <div class="kpi-value">18</div>
                    <div class="kpi-note">Across QA, IT, QC, and operations</div>
                </div>
                <div class="kpi">
                    <div class="kpi-label">Red Assurance Cases</div>
                    <div class="kpi-value">6</div>
                    <div class="kpi-note">Immediate governance action</div>
                </div>
                <div class="kpi">
                    <div class="kpi-label">False Closures</div>
                    <div class="kpi-value">4</div>
                    <div class="kpi-note">Closed locally, not true enterprise-wide</div>
                </div>
                <div class="kpi">
                    <div class="kpi-label">Release Blockers</div>
                    <div class="kpi-value">3</div>
                    <div class="kpi-note">Batch or QC release affected</div>
                </div>
                <div class="kpi">
                    <div class="kpi-label">Aging > 7 Days</div>
                    <div class="kpi-value">5</div>
                    <div class="kpi-note">Evidence chain still incomplete</div>
                </div>
                <div class="kpi">
                    <div class="kpi-label">Audit Defensible</div>
                    <div class="kpi-value">61%</div>
                    <div class="kpi-note">Portfolio readiness today</div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>False Closure Portfolio</h2>
                <p>
                    These are the cases that look complete in a local workflow but still fail enterprise truth validation.
                    COBIT-Chain™ treats these as the most dangerous class because the organization may believe the risk is already resolved.
                </p>
                <div class="portfolio-grid">
                    <div class="portfolio-card red">
                        <div class="portfolio-title">ServiceNow Closed</div>
                        <div class="portfolio-value">4</div>
                        <div class="portfolio-note">Still carrying unresolved downstream evidence gaps.</div>
                    </div>
                    <div class="portfolio-card amber">
                        <div class="portfolio-title">Veeva ↔ Blue Mountain</div>
                        <div class="portfolio-value">3</div>
                        <div class="portfolio-note">Document and operational truth not fully reconciled.</div>
                    </div>
                    <div class="portfolio-card blue">
                        <div class="portfolio-title">ServiceNow ↔ myAccess</div>
                        <div class="portfolio-value">2</div>
                        <div class="portfolio-note">Approval chain and entitlement chain disagree.</div>
                    </div>
                    <div class="portfolio-card green">
                        <div class="portfolio-title">Recovered</div>
                        <div class="portfolio-value">5</div>
                        <div class="portfolio-note">Previously broken chains restored and defensible.</div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Assurance Heatmap</h2>
                <p>
                    A portfolio-level reading of where enterprise governance truth is strongest and where it is currently weakest.
                </p>
                <div class="heatmap">
                    <div></div>
                    <div class="heat-head">Closure</div>
                    <div class="heat-head">Evidence</div>
                    <div class="heat-head">Dependency</div>
                    <div class="heat-head">Audit</div>

                    <div class="heat-label">Batch Disposition</div>
                    <div class="heat-cell red">RED</div>
                    <div class="heat-cell amber">AMBER</div>
                    <div class="heat-cell red">RED</div>
                    <div class="heat-cell red">RED</div>

                    <div class="heat-label">QC Release</div>
                    <div class="heat-cell amber">AMBER</div>
                    <div class="heat-cell amber">AMBER</div>
                    <div class="heat-cell red">RED</div>
                    <div class="heat-cell amber">AMBER</div>

                    <div class="heat-label">Access Governance</div>
                    <div class="heat-cell red">RED</div>
                    <div class="heat-cell red">RED</div>
                    <div class="heat-cell amber">AMBER</div>
                    <div class="heat-cell red">RED</div>

                    <div class="heat-label">Equipment Review</div>
                    <div class="heat-cell green">GREEN</div>
                    <div class="heat-cell amber">AMBER</div>
                    <div class="heat-cell amber">AMBER</div>
                    <div class="heat-cell amber">AMBER</div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Prioritized Assurance Queue</h2>
            <p>
                This register is not a passive list. It ranks cases by governance consequence:
                release impact, false-closure exposure, dependency breakage, audit defensibility, and aging.
            </p>

            <div class="controls">
                <button class="filter-btn active" data-filter="all">All Cases</button>
                <button class="filter-btn" data-filter="red">Red</button>
                <button class="filter-btn" data-filter="amber">Amber</button>
                <button class="filter-btn" data-filter="green">Green</button>
                <button class="filter-btn" data-filter="false-closure">False Closure</button>
                <input id="searchInput" class="search" type="text" placeholder="Search passport, system, owner, or issue...">
            </div>

            <table id="assuranceTable">
                <thead>
                    <tr>
                        <th>Priority</th>
                        <th>Passport</th>
                        <th>Scenario</th>
                        <th>Broken Truth Chain</th>
                        <th>Owner</th>
                        <th>Status</th>
                        <th>Aging</th>
                        <th>Decision</th>
                    </tr>
                </thead>
                <tbody>
                    <tr data-severity="red" data-class="false-closure" data-search="gp-2026-001 batch disposition servicenow veeva blue mountain qa false closure release hold">
                        <td class="priority">P1</td>
                        <td>GP-2026-001</td>
                        <td>False closure before batch release</td>
                        <td>ServiceNow → Veeva → Blue Mountain</td>
                        <td>QA Governance</td>
                        <td><span class="pill red">RED</span></td>
                        <td>11 days</td>
                        <td>Hold release</td>
                    </tr>
                    <tr data-severity="red" data-class="false-closure" data-search="gp-2026-004 access role upgrade servicenow myaccess privileged account it security false closure">
                        <td class="priority">P1</td>
                        <td>GP-2026-004</td>
                        <td>Role upgrade closed without entitlement proof</td>
                        <td>ServiceNow → myAccess</td>
                        <td>IT Security</td>
                        <td><span class="pill red">RED</span></td>
                        <td>8 days</td>
                        <td>Re-open review</td>
                    </tr>
                    <tr data-severity="red" data-class="release-blocker" data-search="gp-2026-007 qc release middleware lis downstream batch blocker qc operations">
                        <td class="priority">P1</td>
                        <td>GP-2026-007</td>
                        <td>QC release dependency incomplete</td>
                        <td>Middleware → LIS → Release</td>
                        <td>QC Operations</td>
                        <td><span class="pill red">RED</span></td>
                        <td>6 days</td>
                        <td>Block release</td>
                    </tr>
                    <tr data-severity="amber" data-class="reconciliation" data-search="gp-2026-009 equipment periodic review veeva blue mountain reconciliation engineering">
                        <td class="priority">P2</td>
                        <td>GP-2026-009</td>
                        <td>Periodic review evidence partial</td>
                        <td>Veeva → Blue Mountain</td>
                        <td>Engineering</td>
                        <td><span class="pill amber">AMBER</span></td>
                        <td>5 days</td>
                        <td>Complete evidence</td>
                    </tr>
                    <tr data-severity="amber" data-class="dependency" data-search="gp-2026-011 deviation capa workflow veeva erp mes lims qa dependency">
                        <td class="priority">P2</td>
                        <td>GP-2026-011</td>
                        <td>Deviation / CAPA dependency drift</td>
                        <td>Veeva → ERP → MES → LIMS</td>
                        <td>QA Systems</td>
                        <td><span class="pill amber">AMBER</span></td>
                        <td>4 days</td>
                        <td>Review chain</td>
                    </tr>
                    <tr data-severity="green" data-class="recovered" data-search="gp-2026-013 sterile compounding batch passport supervisor review recovered operations">
                        <td class="priority">P3</td>
                        <td>GP-2026-013</td>
                        <td>Sterile compounding review recovered</td>
                        <td>Batch Record → Supervisor Review → Audit Lineage</td>
                        <td>Operations</td>
                        <td><span class="pill green">GREEN</span></td>
                        <td>Resolved</td>
                        <td>Defensible</td>
                    </tr>
                    <tr data-severity="amber" data-class="false-closure" data-search="gp-2026-015 work order closure planner blue mountain veeva false closure maintenance">
                        <td class="priority">P2</td>
                        <td>GP-2026-015</td>
                        <td>Work order marked complete too early</td>
                        <td>Planner → Blue Mountain → Veeva</td>
                        <td>Maintenance</td>
                        <td><span class="pill amber">AMBER</span></td>
                        <td>3 days</td>
                        <td>Validate closure</td>
                    </tr>
                </tbody>
            </table>
        </section>

        <section class="grid-3">
            <div class="cluster red">
                <h3>Root Cause Cluster 1</h3>
                <p>
                    Local workflow closure is being mistaken for enterprise truth.
                    This is the dominant source of false assurance in the current portfolio.
                </p>
            </div>
            <div class="cluster amber">
                <h3>Root Cause Cluster 2</h3>
                <p>
                    Cross-system records exist, but they are not reconciled before decisions are made.
                    That creates audit and investigation exposure.
                </p>
            </div>
            <div class="cluster blue">
                <h3>Root Cause Cluster 3</h3>
                <p>
                    Downstream dependencies are visible too late.
                    The organization discovers blockers after work appears finished.
                </p>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Enterprise Intervention Queue</h2>
                <div class="queue">
                    <div class="queue-item">
                        <div class="queue-number">1</div>
                        <div>
                            <div class="queue-title">Stop relying on ticket closure as proof of completion</div>
                            <div class="queue-note">
                                Require cross-system dependency validation before release-sensitive work can be considered complete.
                            </div>
                        </div>
                        <div class="queue-owner">Executive / QA</div>
                    </div>
                    <div class="queue-item">
                        <div class="queue-number">2</div>
                        <div>
                            <div class="queue-title">Prioritize ServiceNow ↔ myAccess reconciliation</div>
                            <div class="queue-note">
                                Privileged access changes should not be treated as defensible until approval, entitlement, and evidence agree.
                            </div>
                        </div>
                        <div class="queue-owner">IT Security</div>
                    </div>
                    <div class="queue-item">
                        <div class="queue-number">3</div>
                        <div>
                            <div class="queue-title">Elevate QC release dependency chains</div>
                            <div class="queue-note">
                                Middleware, LIS, and downstream release assurance should be visible before batch disposition decisions.
                            </div>
                        </div>
                        <div class="queue-owner">QC Operations</div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>What This Adds to the Platform</h2>
                <p>
                    Governance Passport™ answers: <strong>“What is the truth of this one case?”</strong>
                </p>
                <p>
                    Governance Assurance Register™ answers: <strong>“Across the enterprise, where are we currently carrying hidden governance risk?”</strong>
                </p>
                <p>
                    That distinction moves COBIT-Chain™ beyond a workflow tool and into an enterprise assurance intelligence layer:
                    individual record truth, portfolio truth, leadership prioritization, and audit-ready intervention.
                </p>
                <div class="footer-note">
                    Simulation chain: pain point detection → dependency validation → reconciliation → decision intelligence →
                    Governance Passport™ → Governance Assurance Register™.
                </div>
            </div>
        </section>
    </div>

    <script>
        const buttons = document.querySelectorAll(".filter-btn");
        const rows = document.querySelectorAll("#assuranceTable tbody tr");
        const searchInput = document.getElementById("searchInput");
        let activeFilter = "all";

        function applyFilters() {
            const query = searchInput.value.toLowerCase().trim();

            rows.forEach(row => {
                const severity = row.dataset.severity;
                const classification = row.dataset.class;
                const searchable = row.dataset.search;
                const matchesFilter =
                    activeFilter === "all" ||
                    severity === activeFilter ||
                    classification === activeFilter;
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
        print("SKIP: GOVERNANCE_ASSURANCE_REGISTER_ACTIVE already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, route_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        '@app.route("/governance-assurance-register")',
        "Governance Assurance Register™",
        "False Closure Portfolio",
        "Prioritized Assurance Queue",
        "Enterprise Intervention Queue",
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: /governance-assurance-register route inserted safely.")
    print("VERIFIED: required markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
