from pathlib import Path

APP_FILE = Path("app.py")
ACTIVE_MARKER = "# GOVERNANCE_RECLOSURE_GATE_ACTIVE"
ANCHOR = '\nif __name__ == "__main__":'

route_code = r'''

# GOVERNANCE_RECLOSURE_GATE_ACTIVE
@app.route("/governance-reclosure-gate")
def governance_reclosure_gate_view():
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Governance Re-Closure Gate™ | COBIT-Chain™ / AssuranceLayer™</title>
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
            background: linear-gradient(135deg, #3b0d16 0%, #7f1d1d 48%, #173f86 100%);
            color: #fff;
            border-radius: 26px;
            padding: 28px;
            box-shadow: 0 16px 42px rgba(59, 13, 22, .22);
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
        .decision-card {
            border-radius: 22px;
            padding: 22px;
            border: 1px solid #fecaca;
            background: #fff1f2;
        }
        .decision-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .06em;
            color: #991b1b;
            font-weight: 800;
            margin-bottom: 8px;
        }
        .decision-value {
            font-size: 32px;
            font-weight: 900;
            color: #7f1d1d;
            margin-bottom: 8px;
        }
        .decision-note {
            color: #6b1d1d;
            line-height: 1.55;
        }
        .passport-meta {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 12px;
        }
        .meta-card {
            background: #f7faff;
            border: 1px solid #e2eaf7;
            border-radius: 18px;
            padding: 15px;
        }
        .meta-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .05em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 6px;
        }
        .meta-value {
            font-size: 16px;
            font-weight: 900;
        }
        .gate-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .gate-card {
            border-radius: 20px;
            padding: 18px;
            border: 1px solid #e2eaf7;
            background: #f8fbff;
        }
        .gate-card.red {
            background: #fff1f2;
            border-color: #fecdd3;
        }
        .gate-card.amber {
            background: #fffbeb;
            border-color: #fde68a;
        }
        .gate-card.green {
            background: #ecfdf5;
            border-color: #a7f3d0;
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
            font-size: 17px;
            font-weight: 900;
            margin-bottom: 8px;
        }
        .gate-status {
            display: inline-block;
            border-radius: 999px;
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 900;
            margin-bottom: 10px;
        }
        .gate-status.red {
            background: #fee2e2;
            color: #991b1b;
        }
        .gate-status.amber {
            background: #fef3c7;
            color: #92400e;
        }
        .gate-status.green {
            background: #dcfce7;
            color: #166534;
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
        .simulator {
            display: grid;
            grid-template-columns: 1fr .78fr;
            gap: 18px;
        }
        .toggle-grid {
            display: grid;
            gap: 12px;
        }
        .toggle-card {
            background: #f8fbff;
            border: 1px solid #e2eaf7;
            border-radius: 18px;
            padding: 16px;
            display: flex;
            justify-content: space-between;
            gap: 14px;
            align-items: center;
        }
        .toggle-card h3 {
            margin: 0 0 5px;
            font-size: 16px;
        }
        .toggle-card p {
            margin: 0;
            font-size: 14px;
        }
        .switch {
            position: relative;
            display: inline-block;
            width: 58px;
            height: 32px;
            flex: 0 0 58px;
        }
        .switch input {
            opacity: 0;
            width: 0;
            height: 0;
        }
        .slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: #ef4444;
            transition: .25s;
            border-radius: 999px;
        }
        .slider:before {
            position: absolute;
            content: "";
            height: 24px;
            width: 24px;
            left: 4px;
            bottom: 4px;
            background: white;
            transition: .25s;
            border-radius: 50%;
        }
        input:checked + .slider {
            background: #16a34a;
        }
        input:checked + .slider:before {
            transform: translateX(26px);
        }
        .sim-result {
            border-radius: 22px;
            padding: 22px;
            background: #fff1f2;
            border: 1px solid #fecaca;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }
        .sim-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: .06em;
            color: #64748b;
            font-weight: 800;
            margin-bottom: 8px;
        }
        .sim-decision {
            font-size: 30px;
            font-weight: 900;
            color: #7f1d1d;
            margin-bottom: 10px;
        }
        .sim-note {
            color: #4d5b73;
            line-height: 1.55;
        }
        .path-grid {
            display: grid;
            grid-template-columns: repeat(5, minmax(0, 1fr));
            gap: 12px;
        }
        .path-step {
            background: #f8fbff;
            border: 1px solid #e2eaf7;
            border-radius: 18px;
            padding: 16px;
        }
        .path-number {
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
        .path-step h3 {
            margin: 0 0 8px;
            font-size: 16px;
        }
        .path-step p {
            margin: 0;
            font-size: 14px;
        }
        .cert-card {
            border-radius: 20px;
            padding: 18px;
            border-left: 6px solid #b91c1c;
            background: #fff7f7;
        }
        .cert-card h3 {
            margin: 0 0 8px;
            font-size: 17px;
        }
        .cert-card p {
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
            .simulator {
                grid-template-columns: 1fr;
            }
            .gate-grid,
            .path-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }
        @media (max-width: 760px) {
            .hero-grid,
            .gate-grid,
            .path-grid,
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
                <a href="/governance-intervention-workbench">Intervention Workbench</a>
                <a href="/governance-assurance-register">Assurance Register</a>
                <a href="/governance-passport">Governance Passport</a>
                <a href="/governance-decision-engine">Decision Engine</a>
            </div>
        </div>

        <section class="hero">
            <div class="eyebrow">Formal Enterprise Closure Control</div>
            <h1>Governance Re-Closure Gate™</h1>
            <p>
                The final verification layer before a previously challenged case may be closed again.
                The gate does not accept “task completed” as proof. It requires restored cross-system truth,
                cleared dependency blockers, aligned evidence, and a defensible audit trail before COBIT-Chain™
                allows the enterprise to move from hold to controlled re-closure.
            </p>

            <div class="hero-grid">
                <div class="hero-card">
                    <div class="hero-label">Selected Passport</div>
                    <div class="hero-value">GP-2026-001</div>
                    <div class="hero-note">False closure before release</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Current Gate</div>
                    <div class="hero-value">Denied</div>
                    <div class="hero-note">Re-closure not permitted</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Gates Passed</div>
                    <div class="hero-value">1 / 4</div>
                    <div class="hero-note">Three gates still unresolved</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Audit Posture</div>
                    <div class="hero-value">Not Defensible</div>
                    <div class="hero-note">Evidence chain incomplete</div>
                </div>
                <div class="hero-card">
                    <div class="hero-label">Release Posture</div>
                    <div class="hero-value">Hold</div>
                    <div class="hero-note">No release permitted</div>
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="panel">
                <h2>Current Re-Closure Decision</h2>
                <div class="decision-card">
                    <div class="decision-label">Gate Result</div>
                    <div class="decision-value">Re-Closure Denied</div>
                    <div class="decision-note">
                        The case cannot be safely closed again because the CAPA gate is unresolved,
                        the access evidence still conflicts with the approved entitlement, and the Veeva ↔ Blue Mountain
                        reconciliation is not yet complete.
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>Passport Under Review</h2>
                <div class="passport-meta">
                    <div class="meta-card">
                        <div class="meta-label">Passport ID</div>
                        <div class="meta-value">GP-2026-001</div>
                    </div>
                    <div class="meta-card">
                        <div class="meta-label">Case Type</div>
                        <div class="meta-value">False Closure</div>
                    </div>
                    <div class="meta-card">
                        <div class="meta-label">Primary Chain</div>
                        <div class="meta-value">ServiceNow → Veeva → Blue Mountain</div>
                    </div>
                    <div class="meta-card">
                        <div class="meta-label">Control Owner</div>
                        <div class="meta-value">QA Governance</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Re-Closure Gate Matrix</h2>
            <p>
                Every gate must pass. One unresolved gate is enough to keep the case open because one broken dependency
                can still make the overall enterprise story untrue.
            </p>

            <div class="gate-grid">
                <div class="gate-card red">
                    <div class="gate-label">Gate 01</div>
                    <div class="gate-title">CAPA / Deviation Gate</div>
                    <div class="gate-status red">FAIL</div>
                    <div class="gate-note">Veeva CAPA remains unresolved and still affects release confidence.</div>
                </div>
                <div class="gate-card red">
                    <div class="gate-label">Gate 02</div>
                    <div class="gate-title">Access Truth Gate</div>
                    <div class="gate-status red">FAIL</div>
                    <div class="gate-note">Requested, approved, and granted role evidence do not yet align.</div>
                </div>
                <div class="gate-card amber">
                    <div class="gate-label">Gate 03</div>
                    <div class="gate-title">Reconciliation Gate</div>
                    <div class="gate-status amber">PARTIAL</div>
                    <div class="gate-note">Veeva and Blue Mountain records are not fully reconciled.</div>
                </div>
                <div class="gate-card green">
                    <div class="gate-label">Gate 04</div>
                    <div class="gate-title">Downstream Release Gate</div>
                    <div class="gate-status green">PASS</div>
                    <div class="gate-note">Middleware / LIS release dependency confirmation is complete.</div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Gate-by-Gate Evidence Review</h2>
            <table>
                <thead>
                    <tr>
                        <th>Gate</th>
                        <th>Required Proof</th>
                        <th>Observed Evidence</th>
                        <th>Decision Impact</th>
                        <th>Result</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>CAPA / Deviation</td>
                        <td>Resolved CAPA or approved disposition</td>
                        <td>Open CAPA remains linked to release chain</td>
                        <td>Case cannot be re-closed</td>
                        <td><span class="pill red">FAIL</span></td>
                    </tr>
                    <tr>
                        <td>Access Truth</td>
                        <td>Approved role = granted role = evidence chain</td>
                        <td>myAccess approval and granted entitlement disagree</td>
                        <td>Privilege state not defensible</td>
                        <td><span class="pill red">FAIL</span></td>
                    </tr>
                    <tr>
                        <td>Reconciliation</td>
                        <td>Veeva record and Blue Mountain state agree</td>
                        <td>Partial match only; one state field unresolved</td>
                        <td>Operational truth remains uncertain</td>
                        <td><span class="pill amber">PARTIAL</span></td>
                    </tr>
                    <tr>
                        <td>Downstream Release</td>
                        <td>LIS / middleware dependency confirmation</td>
                        <td>Release chain confirmation received</td>
                        <td>No current downstream blocker</td>
                        <td><span class="pill green">PASS</span></td>
                    </tr>
                </tbody>
            </table>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Re-Closure Decision Simulator</h2>
            <p>
                In a live implementation, these signals would be supplied by system integrations.
                In this simulation, switch each unresolved gate to show how COBIT-Chain™ changes the closure decision
                only when the full governance story becomes true again.
            </p>

            <div class="simulator">
                <div class="toggle-grid">
                    <div class="toggle-card">
                        <div>
                            <h3>CAPA resolved or dispositioned</h3>
                            <p>Release blocker removed in Veeva.</p>
                        </div>
                        <label class="switch">
                            <input type="checkbox" class="gate-toggle">
                            <span class="slider"></span>
                        </label>
                    </div>
                    <div class="toggle-card">
                        <div>
                            <h3>Access evidence reconciled</h3>
                            <p>ServiceNow request, myAccess approval, and granted entitlement agree.</p>
                        </div>
                        <label class="switch">
                            <input type="checkbox" class="gate-toggle">
                            <span class="slider"></span>
                        </label>
                    </div>
                    <div class="toggle-card">
                        <div>
                            <h3>Veeva ↔ Blue Mountain aligned</h3>
                            <p>Documented state and operational state now match.</p>
                        </div>
                        <label class="switch">
                            <input type="checkbox" class="gate-toggle">
                            <span class="slider"></span>
                        </label>
                    </div>
                    <div class="toggle-card">
                        <div>
                            <h3>Release chain still confirmed</h3>
                            <p>Middleware / LIS dependency remains valid.</p>
                        </div>
                        <label class="switch">
                            <input type="checkbox" class="gate-toggle" checked>
                            <span class="slider"></span>
                        </label>
                    </div>
                </div>

                <div id="simResult" class="sim-result">
                    <div class="sim-label">Simulated Gate Result</div>
                    <div id="simDecision" class="sim-decision">Re-Closure Denied</div>
                    <div id="simNote" class="sim-note">
                        Only 1 of 4 gates is currently satisfied. The enterprise must remain on hold.
                    </div>
                </div>
            </div>
        </section>

        <section class="panel" style="margin-bottom: 18px;">
            <h2>Controlled Re-Closure Path</h2>
            <div class="path-grid">
                <div class="path-step">
                    <div class="path-number">1</div>
                    <h3>Intervene</h3>
                    <p>Complete the recovery work assigned in the Intervention Workbench.</p>
                </div>
                <div class="path-step">
                    <div class="path-number">2</div>
                    <h3>Resubmit</h3>
                    <p>Return the repaired case to the re-closure gate for formal review.</p>
                </div>
                <div class="path-step">
                    <div class="path-number">3</div>
                    <h3>Revalidate</h3>
                    <p>Run dependency, reconciliation, and evidence checks again.</p>
                </div>
                <div class="path-step">
                    <div class="path-number">4</div>
                    <h3>Certify</h3>
                    <p>Issue defensible closure only when every gate has passed.</p>
                </div>
                <div class="path-step">
                    <div class="path-number">5</div>
                    <h3>Release</h3>
                    <p>Allow downstream progression only after control truth is restored.</p>
                </div>
            </div>
        </section>

        <section class="grid-3">
            <div class="cert-card">
                <h3>What Is Withheld</h3>
                <p>
                    No closure certificate, no release authorization, and no audit-ready outcome while any gate remains unresolved.
                </p>
            </div>
            <div class="cert-card">
                <h3>What Is Protected</h3>
                <p>
                    The enterprise is protected from false assurance, premature release, and post-closure discovery of hidden blockers.
                </p>
            </div>
            <div class="cert-card">
                <h3>What This Adds</h3>
                <p>
                    COBIT-Chain™ now does not just identify and manage governance issues; it formally controls when closure is allowed.
                </p>
            </div>
        </section>

        <section class="panel">
            <h2>Platform Maturity Added by This Gate</h2>
            <p>
                The Intervention Workbench answers: <strong>“What must be fixed?”</strong>
            </p>
            <p>
                The Governance Re-Closure Gate™ answers: <strong>“Has enough been proven to safely close it again?”</strong>
            </p>
            <p>
                That distinction is central to regulated operations. It prevents a team from assuming that because corrective work
                was performed, the enterprise is automatically safe. COBIT-Chain™ requires the evidence chain itself to become true again.
            </p>
            <div class="footer-note">
                Simulation chain: pain point detection → dependency validation → reconciliation → decision intelligence →
                Governance Passport™ → Governance Assurance Register™ → Governance Intervention Workbench™ →
                Governance Re-Closure Gate™.
            </div>
        </section>
    </div>

    <script>
        const toggles = document.querySelectorAll(".gate-toggle");
        const simResult = document.getElementById("simResult");
        const simDecision = document.getElementById("simDecision");
        const simNote = document.getElementById("simNote");

        function updateDecision() {
            const passed = Array.from(toggles).filter(toggle => toggle.checked).length;

            if (passed === 4) {
                simResult.style.background = "#ecfdf5";
                simResult.style.borderColor = "#a7f3d0";
                simDecision.textContent = "Defensible Re-Closure";
                simDecision.style.color = "#166534";
                simNote.textContent = "All 4 gates are satisfied. The case is now eligible for controlled re-closure.";
            } else if (passed === 3) {
                simResult.style.background = "#fffbeb";
                simResult.style.borderColor = "#fde68a";
                simDecision.textContent = "Nearly Ready — Still Blocked";
                simDecision.style.color = "#92400e";
                simNote.textContent = "3 of 4 gates are satisfied. One remaining governance gap is enough to keep closure blocked.";
            } else {
                simResult.style.background = "#fff1f2";
                simResult.style.borderColor = "#fecaca";
                simDecision.textContent = "Re-Closure Denied";
                simDecision.style.color = "#7f1d1d";
                simNote.textContent = passed + " of 4 gates are currently satisfied. The enterprise must remain on hold.";
            }
        }

        toggles.forEach(toggle => toggle.addEventListener("change", updateDecision));
        updateDecision();
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
        print("SKIP: GOVERNANCE_RECLOSURE_GATE_ACTIVE already exists. No duplicate code inserted.")
        return

    if ANCHOR not in text:
        raise SystemExit('ERROR: Could not find anchor: if __name__ == "__main__":')

    updated = text.replace(ANCHOR, route_code + ANCHOR, 1)

    required_markers = [
        ACTIVE_MARKER,
        '@app.route("/governance-reclosure-gate")',
        "Governance Re-Closure Gate™",
        "Re-Closure Gate Matrix",
        "Re-Closure Decision Simulator",
        "Controlled Re-Closure Path",
        "Defensible Re-Closure",
    ]

    missing = [marker for marker in required_markers if marker not in updated]
    if missing:
        raise SystemExit(f"ERROR: Required markers missing after patch: {missing}")

    APP_FILE.write_text(updated, encoding="utf-8")
    print("SUCCESS: /governance-reclosure-gate route inserted safely.")
    print("VERIFIED: required markers found.")
    print("NEXT: run python -m py_compile app.py")

if __name__ == "__main__":
    main()
