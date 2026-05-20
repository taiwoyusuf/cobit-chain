from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# GOVERNANCE_CLOSURE_CERTIFICATE_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

route_code = r'''

# GOVERNANCE_CLOSURE_CERTIFICATE_ACTIVE
@app.route("/governance-closure-certificate")
def governance_closure_certificate_view():
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Governance Closure Certificate™ | COBIT-Chain™ / AssuranceLayer™</title>
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
            background: linear-gradient(135deg, #064e3b 0%, #0f766e 48%, #173f86 100%);
            color: #fff;
            border-radius: 26px;
            padding: 28px;
            box-shadow: 0 16px 42px rgba(6, 78, 59, .22);
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
            max-width: 1020px;
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
            grid-template-columns: 1.08fr .92fr;
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
        .certificate {
            background: linear-gradient(180deg, #ffffff 0%, #f8fffd 100%);
            border: 2px solid #a7f3d0;
            border-radius: 26px;
            padding: 28px;
            position: relative;
            overflow: hidden;
        }
        .certificate:before {
            content: "";
            position: absolute;
            width: 300px;
            height: 300px;
            right: -120px;
            top: -130px;
            border-radius: 50%;
            background: rgba(16, 185, 129, .08);
        }
        .cert-header {
            display: flex;
            justify-content: space-between;
            gap: 18px;
            align-items: flex-start;
            flex-wrap: wrap;
            position: relative;
            z-index: 1;
        }
        .cert-kicker {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .08em;
            color: #0f766e;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .cert-title {
            font-size: 29px;
            font-weight: 900;
            color: #064e3b;
            margin-bottom: 8px;
        }
        .cert-subtitle {
            color: #486375;
            line-height: 1.5;
            max-width: 720px;
        }
        .seal {
            width: 112px;
            height: 112px;
            border-radius: 50%;
            border: 3px solid #10b981;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            background: #ecfdf5;
            color: #065f46;
            text-align: center;
            font-weight: 900;
            flex: 0 0 112px;
        }
        .seal-main {
            font-size: 18px;
            line-height: 1.05;
        }
        .seal-sub {
            font-size: 11px;
            margin-top: 4px;
            text-transform: uppercase;
            letter-spacing: .05em;
        }
        .cert-meta {
            position: relative;
            z-index: 1;
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
            margin-top: 24px;
        }
        .meta-card {
            background: rgba(255,255,255,.78);
            border: 1px solid #d1fae5;
            border-radius: 16px;
            padding: 14px;
        }
        .meta-label {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 6px;
        }
        .meta-value {
            font-size: 15px;
            font-weight: 900;
        }
        .truth-statement {
            position: relative;
            z-index: 1;
            margin-top: 22px;
            background: #064e3b;
            color: #fff;
            border-radius: 20px;
            padding: 20px;
        }
        .truth-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .08em;
            opacity: .78;
            font-weight: 800;
            margin-bottom: 8px;
        }
        .truth-text {
            font-size: 19px;
            line-height: 1.45;
            font-weight: 800;
        }
        .timeline {
            display: grid;
            gap: 12px;
        }
        .timeline-item {
            display: grid;
            grid-template-columns: 54px 1fr;
            gap: 14px;
            align-items: start;
            background: #f8fbff;
            border: 1px solid #e2eaf7;
            border-radius: 18px;
            padding: 15px;
        }
        .timeline-no {
            width: 40px;
            height: 40px;
            border-radius: 14px;
            background: #173f86;
            color: #fff;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 900;
        }
        .timeline-title {
            font-weight: 900;
            margin-bottom: 5px;
        }
        .timeline-note {
            color: #53637b;
            line-height: 1.45;
            font-size: 14px;
        }
        .gate-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .gate-card {
            border-radius: 18px;
            padding: 17px;
            background: #ecfdf5;
            border: 1px solid #a7f3d0;
        }
        .gate-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #5d6c84;
            font-weight: 800;
            margin-bottom: 8px;
        }
        .gate-title {
            font-size: 16px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .gate-status {
            display: inline-block;
            border-radius: 999px;
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 900;
            background: #dcfce7;
            color: #166534;
            margin-bottom: 10px;
        }
        .gate-note {
            color: #516078;
            line-height: 1.45;
            font-size: 14px;
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
        .pill.green {
            background: #dcfce7;
            color: #166534;
        }
        .pill.blue {
            background: #dbeafe;
            color: #1d4ed8;
        }
        .pill.teal {
            background: #ccfbf1;
            color: #115e59;
        }
        .approval-grid {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 14px;
        }
        .approval-card {
            background: #f7faff;
            border: 1px solid #e2eaf7;
            border-radius: 18px;
            padding: 17px;
        }
        .approval-role {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 7px;
        }
        .approval-name {
            font-size: 17px;
            font-weight: 900;
            margin-bottom: 7px;
        }
        .approval-note {
            color: #516078;
            line-height: 1.45;
            font-size: 14px;
        }
        .hash-box {
            background: #0f172a;
            color: #e2e8f0;
            border-radius: 22px;
            padding: 22px;
        }
        .hash-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .06em;
            color: #93c5fd;
            font-weight: 800;
            margin-bottom: 8px;
        }
        .hash-value {
            font-family: Consolas, "Courier New", monospace;
            word-break: break-all;
            font-size: 14px;
            line-height: 1.55;
            margin-bottom: 14px;
        }
        .verify-row {
            display: flex;
            gap: 10px;
            align-items: center;
            flex-wrap: wrap;
        }
        .verify-btn {
            border: 0;
            cursor: pointer;
            border-radius: 999px;
            padding: 10px 14px;
            background: #10b981;
            color: #062f25;
            font-weight: 900;
            font-size: 13px;
        }
        .verify-state {
            display: inline-block;
            border-radius: 999px;
            padding: 8px 12px;
            background: rgba(255,255,255,.12);
            font-size: 13px;
            font-weight: 800;
        }
        .why-card {
            border-left: 5px solid #0f766e;
            background: #f0fdfa;
            border-radius: 18px;
            padding: 17px;
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
        @media (max-width: 1180px) {
            .hero-grid {
                grid-template-columns: repeat(3, minmax(0, 1fr));
            }
            .grid-2,
            .grid-3 {
                grid-template-columns: 1fr;
            }
            .gate-grid,
            .cert-meta,
            .approval-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }
        @media (max-width: 760px) {
            .hero-grid,
            .gate-grid,
            .cert-meta,
            .approval-grid {
                grid-template-columns: 1fr;
            }
            .timeline-item {
                grid-template-columns: 1fr;
            }
            h1 {
                font-size: 28px;
            }
            .cert-title {
                font-size: 24px;
            }
        }
    </style>
</head>
<body>
    <div class="shell">
        <div class="topbar">
            <div class="brand">COBIT-Chain™ / AssuranceLayer™</div>
            <div class="nav-links">
                <a href="/governance-reclosure-gate">Re-Closure Gate</a>
                <a href="/governance-intervention-workbench">Intervention Workbench</a>
                <a href="/governance-passport">Governance Passport</a>
                <a href="/executive-mission-control">Mission Control</a>
            </div>
        </div>

        <section class="hero">
            <div class="eyebrow">Final Audit-Defensible Artifact</div>
            <h1>Governance Closure Certificate™</h1>
            <p>
                The official end-state artifact issued only after a challenged case has passed every re-closure gate.
                It records what was originally wrong, what was repaired, which evidence gates passed, who approved the closure,
                and the final enterprise truth that is now safe to rely on.
            </p>

            <div class="hero-grid">
                <div class="hero-card">
                    <div class="hero-label">Certificate ID</div>
                    <div class="hero-value">GCC-2026-001</div>
                    <div class="hero-note">Issued from GP-2026-001</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Certificate Status</div>
                    <div class="hero-value">Issued</div>
                    <div class="hero-note">All gates satisfied</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Final Disposition</div>
                    <div class="hero-value">Re-Closed</div>
                    <div class="hero-note">Defensible closure authorized</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Audit Posture</div>
                    <div class="hero-value">Defensible</div>
                    <div class="hero-note">Evidence chain complete</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Ledger Seal</div>
                    <div class="hero-value">Anchored</div>
                    <div class="hero-note">Integrity proof recorded</div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Certificate of Governed Closure</h2>
                <div class="certificate">
                    <div class="cert-header">
                        <div>
                            <div class="cert-kicker">COBIT-Chain™ / AssuranceLayer™</div>
                            <div class="cert-title">Governance Closure Certificate™</div>
                            <div class="cert-subtitle">
                                This certifies that Governance Passport GP-2026-001 has completed controlled remediation,
                                passed the formal Governance Re-Closure Gate™, and is now approved for defensible closure.
                            </div>
                        </div>
                        <div class="seal">
                            <div class="seal-main">CLOSED</div>
                            <div class="seal-sub">Verified</div>
                        </div>
                    </div>

                    <div class="cert-meta">
                        <div class="meta-card">
                            <div class="meta-label">Source Passport</div>
                            <div class="meta-value">GP-2026-001</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Original Finding</div>
                            <div class="meta-value">False Closure</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Gate Result</div>
                            <div class="meta-value">4 / 4 Passed</div>
                        </div>
                        <div class="meta-card">
                            <div class="meta-label">Closure Date</div>
                            <div class="meta-value">2026-05-09</div>
                        </div>
                    </div>

                    <div class="truth-statement">
                        <div class="truth-label">Certified Enterprise Truth</div>
                        <div class="truth-text">
                            The previously broken closure chain has been repaired. CAPA dependency, access approval,
                            equipment-state reconciliation, and downstream release assurance now agree across the governed record.
                        </div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>From False Closure to Trusted Closure</h2>
                <div class="timeline">
                    <div class="timeline-item">
                        <div class="timeline-no">1</div>
                        <div>
                            <div class="timeline-title">False Closure Detected</div>
                            <div class="timeline-note">
                                ServiceNow showed complete, but the wider enterprise chain still carried unresolved dependencies.
                            </div>
                        </div>
                    </div>
                    <div class="timeline-item">
                        <div class="timeline-no">2</div>
                        <div>
                            <div class="timeline-title">Governance Intervention Executed</div>
                            <div class="timeline-note">
                                QA, IT Security, Engineering, and QC repaired the broken evidence and dependency chain.
                            </div>
                        </div>
                    </div>
                    <div class="timeline-item">
                        <div class="timeline-no">3</div>
                        <div>
                            <div class="timeline-title">Re-Closure Gate Passed</div>
                            <div class="timeline-note">
                                Every required gate returned defensible: CAPA, access truth, reconciliation, and release assurance.
                            </div>
                        </div>
                    </div>
                    <div class="timeline-item">
                        <div class="timeline-no">4</div>
                        <div>
                            <div class="timeline-title">Certificate Issued</div>
                            <div class="timeline-note">
                                The final closure record was sealed, linked back to the passport, and made audit-ready.
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Evidence Gates Certified as Passed</h2>
            <p>
                A closure certificate is not issued because someone says the work is done.
                It is issued because every required condition is now demonstrably true.
            </p>

            <div class="gate-grid">
                <div class="gate-card">
                    <div class="gate-label">Gate 01</div>
                    <div class="gate-title">CAPA / Deviation</div>
                    <div class="gate-status">PASS</div>
                    <div class="gate-note">CAPA dependency resolved or formally dispositioned.</div>
                </div>
                <div class="gate-card">
                    <div class="gate-label">Gate 02</div>
                    <div class="gate-title">Access Truth</div>
                    <div class="gate-status">PASS</div>
                    <div class="gate-note">Requested role, approved role, and granted role now agree.</div>
                </div>
                <div class="gate-card">
                    <div class="gate-label">Gate 03</div>
                    <div class="gate-title">Reconciliation</div>
                    <div class="gate-status">PASS</div>
                    <div class="gate-note">Veeva and Blue Mountain record one consistent state.</div>
                </div>
                <div class="gate-card">
                    <div class="gate-label">Gate 04</div>
                    <div class="gate-title">Release Assurance</div>
                    <div class="gate-status">PASS</div>
                    <div class="gate-note">Middleware / LIS downstream release chain confirmed.</div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Repair Record</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Original Break</th>
                            <th>Repair Performed</th>
                            <th>Evidence Attached</th>
                            <th>Result</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>Open CAPA linked to release</td>
                            <td>CAPA disposition completed and approved</td>
                            <td>Veeva closure evidence</td>
                            <td><span class="pill green">Resolved</span></td>
                        </tr>
                        <tr>
                            <td>myAccess entitlement mismatch</td>
                            <td>Role approval and entitlement aligned</td>
                            <td>Approval record + entitlement proof</td>
                            <td><span class="pill green">Resolved</span></td>
                        </tr>
                        <tr>
                            <td>Blue Mountain state partially reconciled</td>
                            <td>Operational record and governed record matched</td>
                            <td>Equipment review evidence</td>
                            <td><span class="pill green">Resolved</span></td>
                        </tr>
                        <tr>
                            <td>Downstream release dependency uncertain</td>
                            <td>Middleware / LIS confirmation received</td>
                            <td>Release-chain confirmation</td>
                            <td><span class="pill green">Resolved</span></td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <div class="panel">
                <h2>Approval Chain</h2>
                <div class="approval-grid">
                    <div class="approval-card">
                        <div class="approval-role">QA Governance</div>
                        <div class="approval-name">Closure Owner</div>
                        <div class="approval-note">
                            Confirmed all release-sensitive governance gates were satisfied.
                        </div>
                    </div>
                    <div class="approval-card">
                        <div class="approval-role">IT Security</div>
                        <div class="approval-name">Access Owner</div>
                        <div class="approval-note">
                            Certified entitlement evidence now matches approved access.
                        </div>
                    </div>
                    <div class="approval-card">
                        <div class="approval-role">QC / Operations</div>
                        <div class="approval-name">Release Owner</div>
                        <div class="approval-note">
                            Confirmed no downstream release dependency remains open.
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Integrity Seal and Ledger Proof</h2>
                <div class="hash-box">
                    <div class="hash-label">Certificate Hash</div>
                    <div class="hash-value">
                        4f2b7e9c6d8310f8a5d72c1e493bb0a71c4df9268e1053bd7ac9f64e2a78c115
                    </div>
                    <div class="hash-label">Ledger Anchor</div>
                    <div class="hash-value">
                        ACL-TX-20260509-GCC2026001-7C91E8D4
                    </div>
                    <div class="verify-row">
                        <button id="verifyBtn" class="verify-btn">Verify Certificate Integrity</button>
                        <span id="verifyState" class="verify-state">Awaiting verification</span>
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Why This Certificate Matters</h2>
                <div class="grid-3">
                    <div class="why-card">
                        <h3>For Auditors</h3>
                        <p>Shows not just closure, but the evidence logic behind why closure was valid.</p>
                    </div>
                    <div class="why-card">
                        <h3>For Leadership</h3>
                        <p>Separates trustworthy closure from administrative closure.</p>
                    </div>
                    <div class="why-card">
                        <h3>For Investigations</h3>
                        <p>Preserves the repair path, approvals, and final truth in one artifact.</p>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel">
            <h2>Platform Maturity Added by This Certificate</h2>
            <p>
                The Governance Re-Closure Gate™ answers: <strong>“Is closure now allowed?”</strong>
            </p>
            <p>
                The Governance Closure Certificate™ answers: <strong>“What is the final trusted record proving why closure was allowed?”</strong>
            </p>
            <p>
                That closes the loop. COBIT-Chain™ no longer stops at detecting, prioritizing, or even controlling remediation.
                It now produces the final audit-defensible artifact that explains the issue, the repair, the evidence,
                the approval chain, and the integrity seal behind the end state.
            </p>
            <div class="footer-note">
                Simulation chain: pain point detection → dependency validation → reconciliation → decision intelligence →
                Governance Passport™ → Governance Assurance Register™ → Governance Intervention Workbench™ →
                Governance Re-Closure Gate™ → Governance Closure Certificate™.
            </div>
        </section>
    </div>

    <script>
        const verifyBtn = document.getElementById("verifyBtn");
        const verifyState = document.getElementById("verifyState");

        verifyBtn.addEventListener("click", () => {
            verifyState.textContent = "Verified — hash matches ledger anchor";
            verifyState.style.background = "rgba(16,185,129,.18)";
            verifyState.style.color = "#d1fae5";
        });
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
        print("SKIP: GOVERNANCE_CLOSURE_CERTIFICATE_ACTIVE already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, route_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        '@app.route("/governance-closure-certificate")',
        "Governance Closure Certificate™",
        "Certificate of Governed Closure",
        "Evidence Gates Certified as Passed",
        "Integrity Seal and Ledger Proof",
        "Verified — hash matches ledger anchor",
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: /governance-closure-certificate route inserted safely.")
    print("VERIFIED: required markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
