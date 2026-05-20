from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# GOVERNANCE_PASSPORT_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

route_code = r'''

# GOVERNANCE_PASSPORT_ACTIVE
@app.route("/governance-passport")
def governance_passport_view():
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Governance Passport™ | COBIT-Chain™ / AssuranceLayer™</title>
    <style>
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: Arial, Helvetica, sans-serif;
            background: #f4f7fb;
            color: #172033;
        }
        .shell {
            max-width: 1320px;
            margin: 0 auto;
            padding: 28px 22px 40px;
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
            background: linear-gradient(135deg, #0f2d5c 0%, #173f86 55%, #2453a6 100%);
            color: #fff;
            border-radius: 24px;
            padding: 28px;
            box-shadow: 0 16px 40px rgba(15, 45, 92, .20);
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
            font-size: 34px;
            line-height: 1.15;
        }
        .hero p {
            max-width: 920px;
            margin: 0;
            line-height: 1.55;
            font-size: 16px;
            opacity: .95;
        }
        .status-strip {
            display: grid;
            grid-template-columns: repeat(5, minmax(0, 1fr));
            gap: 12px;
            margin-top: 22px;
        }
        .status-card {
            background: rgba(255,255,255,.12);
            border: 1px solid rgba(255,255,255,.18);
            border-radius: 18px;
            padding: 15px;
        }
        .status-label {
            font-size: 12px;
            opacity: .80;
            text-transform: uppercase;
            letter-spacing: .06em;
            margin-bottom: 7px;
        }
        .status-value {
            font-size: 18px;
            font-weight: 800;
        }
        .grid-2 {
            display: grid;
            grid-template-columns: 1.15fr .85fr;
            gap: 18px;
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
        .passport-meta {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 12px;
        }
        .meta-card {
            background: #f6f9fe;
            border: 1px solid #dfe8f7;
            border-radius: 16px;
            padding: 14px;
        }
        .meta-label {
            font-size: 12px;
            color: #60708c;
            text-transform: uppercase;
            letter-spacing: .05em;
            margin-bottom: 6px;
        }
        .meta-value {
            font-weight: 800;
            font-size: 16px;
        }
        .decision-box {
            border-left: 6px solid #b91c1c;
            background: #fff1f2;
            border-radius: 18px;
            padding: 18px;
        }
        .decision-box .title {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .06em;
            color: #991b1b;
            font-weight: 800;
            margin-bottom: 8px;
        }
        .decision-box .decision {
            font-size: 24px;
            font-weight: 900;
            color: #7f1d1d;
            margin-bottom: 8px;
        }
        .decision-box .reason {
            color: #6b1d1d;
            line-height: 1.5;
        }
        .chain {
            display: grid;
            grid-template-columns: repeat(6, minmax(0, 1fr));
            gap: 10px;
            margin-top: 16px;
        }
        .node {
            border-radius: 18px;
            padding: 14px 12px;
            min-height: 108px;
            border: 1px solid #dfe7f5;
            background: #f8fbff;
        }
        .node.red {
            background: #fff1f2;
            border-color: #fecdd3;
        }
        .node.amber {
            background: #fffbeb;
            border-color: #fde68a;
        }
        .node.green {
            background: #ecfdf5;
            border-color: #a7f3d0;
        }
        .node-title {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #5d6c84;
            font-weight: 800;
            margin-bottom: 8px;
        }
        .node-value {
            font-weight: 800;
            font-size: 15px;
            margin-bottom: 7px;
        }
        .node-note {
            font-size: 12px;
            line-height: 1.4;
            color: #516078;
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
        .why-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .why-card {
            background: #f7faff;
            border: 1px solid #e2eaf7;
            border-radius: 18px;
            padding: 16px;
        }
        .why-card h3 {
            margin: 0 0 8px;
            font-size: 16px;
        }
        .why-card p {
            margin: 0;
            font-size: 14px;
        }
        .footer-note {
            margin-top: 18px;
            color: #5c6a80;
            font-size: 13px;
            line-height: 1.5;
        }
        @media (max-width: 1100px) {
            .status-strip,
            .chain,
            .why-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
            .grid-2 {
                grid-template-columns: 1fr;
            }
        }
        @media (max-width: 680px) {
            .status-strip,
            .chain,
            .why-grid,
            .passport-meta {
                grid-template-columns: 1fr;
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
                <a href="/operational-pain-point-framework">Pain Point Framework</a>
                <a href="/cross-system-dependency-validation">Dependency Validation</a>
                <a href="/governance-reconciliation-layer">Reconciliation Layer</a>
                <a href="/governance-decision-engine">Decision Engine</a>
            </div>
        </div>

        <section class="hero">
            <div class="eyebrow">Enterprise Governance Intelligence Record</div>
            <h1>Governance Passport™</h1>
            <p>
                A single audit-defensible record that converts detected pain points, dependency failures,
                reconciliation gaps, false-closure signals, and governance decisions into one governed case file.
                This is where COBIT-Chain™ moves from “finding issues” to proving the enterprise truth of an issue.
            </p>

            <div class="status-strip">
                <div class="status-card">
                    <div class="status-label">Passport ID</div>
                    <div class="status-value">GP-2026-001</div>
                </div>
                <div class="status-card">
                    <div class="status-label">Governance Status</div>
                    <div class="status-value">RED</div>
                </div>
                <div class="status-card">
                    <div class="status-label">False Closure Risk</div>
                    <div class="status-value">Detected</div>
                </div>
                <div class="status-card">
                    <div class="status-label">Audit Readiness</div>
                    <div class="status-value">Partial</div>
                </div>
                <div class="status-card">
                    <div class="status-label">Release Posture</div>
                    <div class="status-value">Hold</div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Passport Summary</h2>
                <p>
                    A batch disposition workflow appears complete in one system, but the enterprise truth is not complete.
                    The ServiceNow item is closed, while downstream dependency validation still shows unresolved CAPA linkage,
                    myAccess approval mismatch, and incomplete Veeva ↔ Blue Mountain reconciliation.
                </p>

                <div class="passport-meta">
                    <div class="meta-card">
                        <div class="meta-label">Primary Scenario</div>
                        <div class="meta-value">False Closure Before Release</div>
                    </div>
                    <div class="meta-card">
                        <div class="meta-label">Affected Chain</div>
                        <div class="meta-value">ERP → MES → LIMS</div>
                    </div>
                    <div class="meta-card">
                        <div class="meta-label">Decision Owner</div>
                        <div class="meta-value">QA / Governance Review</div>
                    </div>
                    <div class="meta-card">
                        <div class="meta-label">Evidence Posture</div>
                        <div class="meta-value">Not Yet Defensible</div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Governance Decision</h2>
                <div class="decision-box">
                    <div class="title">System Recommendation</div>
                    <div class="decision">Do Not Release</div>
                    <div class="reason">
                        Workflow completion alone is insufficient. The passport shows that release should remain on hold
                        until deviation/CAPA dependency, access approval, and cross-system reconciliation are resolved.
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Cross-System Truth Chain</h2>
            <p>
                The passport does not trust one application in isolation. It reads the full chain and exposes where the
                enterprise story breaks.
            </p>

            <div class="chain">
                <div class="node green">
                    <div class="node-title">ServiceNow</div>
                    <div class="node-value">Closed</div>
                    <div class="node-note">Ticket shows workflow complete.</div>
                </div>
                <div class="node red">
                    <div class="node-title">myAccess</div>
                    <div class="node-value">Mismatch</div>
                    <div class="node-note">Approver evidence not aligned.</div>
                </div>
                <div class="node red">
                    <div class="node-title">Veeva</div>
                    <div class="node-value">Open CAPA</div>
                    <div class="node-note">Dependency remains unresolved.</div>
                </div>
                <div class="node amber">
                    <div class="node-title">Blue Mountain</div>
                    <div class="node-value">Partial Match</div>
                    <div class="node-note">Equipment state not fully reconciled.</div>
                </div>
                <div class="node amber">
                    <div class="node-title">Middleware / LIS</div>
                    <div class="node-value">Pending</div>
                    <div class="node-note">Downstream release assurance incomplete.</div>
                </div>
                <div class="node red">
                    <div class="node-title">Batch Disposition</div>
                    <div class="node-value">Blocked</div>
                    <div class="node-note">Enterprise truth does not support release.</div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Control-to-Evidence Passport</h2>
            <table>
                <thead>
                    <tr>
                        <th>Governance Check</th>
                        <th>Expected Truth</th>
                        <th>Observed State</th>
                        <th>Passport Result</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>Workflow closure</td>
                        <td>Closure only after all dependencies resolve</td>
                        <td>Closed in ServiceNow before cross-system validation</td>
                        <td><span class="pill red">False Closure</span></td>
                    </tr>
                    <tr>
                        <td>Access approval</td>
                        <td>Entitlement must match approved evidence</td>
                        <td>myAccess record and approval chain disagree</td>
                        <td><span class="pill red">Mismatch</span></td>
                    </tr>
                    <tr>
                        <td>Deviation / CAPA dependency</td>
                        <td>No unresolved blocker before release</td>
                        <td>Veeva CAPA remains open</td>
                        <td><span class="pill red">Blocker</span></td>
                    </tr>
                    <tr>
                        <td>Equipment reconciliation</td>
                        <td>Operational state and governed record should agree</td>
                        <td>Blue Mountain status only partially reconciled</td>
                        <td><span class="pill amber">Review</span></td>
                    </tr>
                    <tr>
                        <td>Downstream assurance</td>
                        <td>LIS / middleware / release dependencies complete</td>
                        <td>Pending release dependency confirmation</td>
                        <td><span class="pill amber">Pending</span></td>
                    </tr>
                    <tr>
                        <td>Audit defensibility</td>
                        <td>Evidence chain complete, explainable, and consistent</td>
                        <td>Story cannot yet be defended end-to-end</td>
                        <td><span class="pill red">Not Ready</span></td>
                    </tr>
                </tbody>
            </table>
        </section>

        <section class="panel">
            <h2>Why the Governance Passport™ Matters</h2>
            <div class="why-grid">
                <div class="why-card">
                    <h3>For Leadership</h3>
                    <p>Shows the real enterprise risk, not just whether a local task was marked complete.</p>
                </div>
                <div class="why-card">
                    <h3>For QA</h3>
                    <p>Turns scattered system signals into one defendable decision record before release.</p>
                </div>
                <div class="why-card">
                    <h3>For Auditors</h3>
                    <p>Provides the full chain: control, evidence, contradiction, decision, and owner.</p>
                </div>
                <div class="why-card">
                    <h3>For Operations</h3>
                    <p>Prevents teams from discovering hidden blockers only after a deviation or investigation.</p>
                </div>
            </div>

            <div class="footer-note">
                Governance Passport™ is the synthesis layer above the earlier engines:
                pain point detection → dependency validation → reconciliation → decision intelligence → auditable passport.
            </div>
        </section>
    </div>
</body>
</html>
    """)
'''

def main():
    if not APP_FILE.exists():
        raise SystemExit("ERROR: app.py was not found in the current folder.")

    text = APP_FILE.read_text(encoding="utf-8")

    if ACTIVE_MARKER in text:
        print("SKIP: GOVERNANCE_PASSPORT_ACTIVE already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, route_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        '@app.route("/governance-passport")',
        "Governance Passport™",
        "False Closure Risk",
        "Cross-System Truth Chain",
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: /governance-passport route inserted safely.")
    print("VERIFIED: required markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
