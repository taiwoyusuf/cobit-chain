from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_GOVERNANCE_OPERATING_SYSTEM_V1_ACTIVE"
ROUTE_PRIMARY = '@app.route("/citrust/governance-operating-system")'
ROUTE_ALIAS = '@app.route("/citrust/govos")'

if MARKER in text or ROUTE_PRIMARY in text or ROUTE_ALIAS in text:
    print("CITrust Governance Operating System already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_GOVERNANCE_OPERATING_SYSTEM_V1_ACTIVE
# ============================================================

@app.route("/citrust/governance-operating-system")
@app.route("/citrust/govos")
def citrust_governance_operating_system():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Governance Operating System</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">

        <style>
            :root {
                --bg:#040b14; --panel:rgba(14,27,44,.92); --line:rgba(255,255,255,.12);
                --text:#eef5ff; --muted:#a8bbd4; --green:#31d07d; --yellow:#f7c948;
                --red:#ff5c70; --blue:#5cc8ff; --purple:#b49cff; --orange:#ffb86b; --cyan:#7efcff;
            }
            *{box-sizing:border-box}
            body{margin:0;font-family:Arial,Helvetica,sans-serif;background:
                radial-gradient(circle at top left,rgba(92,200,255,.22),transparent 30%),
                radial-gradient(circle at top right,rgba(49,208,125,.18),transparent 28%),
                radial-gradient(circle at bottom right,rgba(180,156,255,.14),transparent 30%),var(--bg);color:var(--text)}
            .page{max-width:1460px;margin:0 auto;padding:28px}
            .hero{border:1px solid var(--line);background:linear-gradient(135deg,rgba(16,29,47,.98),rgba(20,40,66,.92));border-radius:26px;padding:30px;box-shadow:0 24px 80px rgba(0,0,0,.42)}
            .eyebrow{color:var(--cyan);font-size:13px;text-transform:uppercase;letter-spacing:1.9px;font-weight:900;margin-bottom:10px}
            h1{margin:0;font-size:42px;line-height:1.08}
            .subtitle{color:var(--muted);font-size:16px;line-height:1.65;max-width:1180px;margin-top:14px}
            .positioning{margin-top:18px;padding:17px 19px;border:1px solid rgba(92,200,255,.38);background:rgba(92,200,255,.10);border-radius:18px;color:#d9f3ff;line-height:1.6}
            .nav{display:flex;flex-wrap:wrap;gap:10px;margin-top:22px}
            .nav a{color:var(--text);text-decoration:none;border:1px solid var(--line);background:rgba(255,255,255,.06);padding:10px 13px;border-radius:999px;font-size:13px}
            .nav a:hover{border-color:rgba(92,200,255,.7);background:rgba(92,200,255,.12)}
            .kpis{display:grid;grid-template-columns:repeat(6,1fr);gap:14px;margin-top:20px}
            .metric{border:1px solid var(--line);background:var(--panel);border-radius:18px;padding:18px}
            .metric .label{color:var(--muted);font-size:13px;margin-bottom:8px}
            .metric .value{font-size:29px;font-weight:900}
            .metric .note{margin-top:8px;color:var(--muted);font-size:12px;line-height:1.4}
            .section{margin-top:24px;border:1px solid var(--line);background:var(--panel);border-radius:24px;padding:23px}
            .section h2{margin:0 0 8px 0;font-size:23px}
            .section p{color:var(--muted);line-height:1.56;margin-top:0}
            .answer{border:1px solid rgba(92,200,255,.38);background:rgba(92,200,255,.10);color:#d9f3ff;border-radius:18px;padding:20px;margin-top:16px;line-height:1.65;font-size:15px}
            .badge{display:inline-block;padding:6px 9px;border-radius:999px;font-size:12px;font-weight:900;white-space:nowrap}
            .green{color:#04140b;background:var(--green)} .yellow{color:#1d1600;background:var(--yellow)}
            .red{color:#fff;background:var(--red)} .blue{color:#06101d;background:var(--blue)}
            .purple{color:#120b24;background:var(--purple)} .orange{color:#211100;background:var(--orange)}
            .os-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:16px}
            .os-card{border:1px solid rgba(92,200,255,.32);background:linear-gradient(135deg,rgba(255,255,255,.06),rgba(92,200,255,.07)),rgba(255,255,255,.035);border-radius:22px;padding:22px;min-height:300px;position:relative;overflow:hidden}
            .os-card:after{content:"GovOS";position:absolute;right:-18px;top:42px;transform:rotate(28deg);color:rgba(92,200,255,.16);font-size:42px;font-weight:900;letter-spacing:4px}
            .os-card h3{margin:0 0 12px 0;font-size:22px}
            .os-row{display:grid;grid-template-columns:210px 1fr 120px;gap:12px;align-items:center;padding:11px 0;border-bottom:1px solid rgba(255,255,255,.08);font-size:14px}
            .os-row .key{color:var(--muted)}
            .os-row .val{color:var(--text);font-weight:800}
            .os-row .state{text-align:right}
            .cards{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-top:16px}
            .card{border:1px solid var(--line);background:rgba(255,255,255,.045);border-radius:18px;padding:18px;min-height:150px}
            .card h3{margin:0 0 8px 0;font-size:17px}.card p{margin:0;color:var(--muted);font-size:14px;line-height:1.55}
            table{width:100%;border-collapse:collapse;overflow:hidden;border-radius:16px;margin-top:16px}
            th{text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.8px;color:#c9dbef;background:rgba(255,255,255,.07);padding:13px 12px;border-bottom:1px solid var(--line)}
            td{padding:13px 12px;border-bottom:1px solid rgba(255,255,255,.08);color:#e9f2ff;vertical-align:top;font-size:14px}
            tr:hover td{background:rgba(92,200,255,.05)}
            .footer{color:var(--muted);font-size:12px;margin-top:22px;line-height:1.6}
            @media(max-width:1180px){.kpis,.cards,.os-grid{grid-template-columns:1fr}.os-row{grid-template-columns:1fr}.os-row .state{text-align:left}h1{font-size:30px}table{display:block;overflow-x:auto;white-space:nowrap}}
        </style>
    </head>

    <body>
        <div class="page">
            <section class="hero">
                <div class="eyebrow">CITrust™ / ServiceNow AI / Governance Operating System</div>
                <h1>CITrust™ Governance Operating System</h1>
                <div class="subtitle">
                    The executive command layer that unifies ServiceNow AI governance, CMDB trust, evidence sufficiency, authority boundaries, Trust DNA, governance entropy, claim firewall, regulatory replay, trust market, and immune defense into one governed operating system for autonomous operations.
                </div>
                <div class="positioning">
                    <strong>ServiceNow-focused positioning:</strong>
                    ServiceNow enables AI-powered enterprise workflow execution. CITrust™ GovOS™ determines whether those workflows are trusted, bounded, evidence-backed, human-governed, reversible, inspection-ready, and safe for leadership reliance in regulated environments.
                </div>
                <div class="nav">
                    <a href="/citrust">CITrust™ Home</a>
                    <a href="/citrust/trust-immune-system">Trust Immune System</a>
                    <a href="/citrust/regulatory-replay">Regulatory Replay</a>
                    <a href="/citrust/ai-authority-envelope">AI Authority Envelope</a>
                    <a href="/citrust/executive-confidence-index">Executive Confidence</a>
                    <a href="/citrust/governance-entropy">Governance Entropy</a>
                    <a href="/citrust/trust-market">Trust Market</a>
                    <a href="/citrust/trust-dna">Trust DNA</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric"><div class="label">GovOS Status</div><div class="value" style="color:var(--green);">Online</div><div class="note">CITrust™ governance operating layer is active.</div></div>
                <div class="metric"><div class="label">ServiceNow AI Readiness</div><div class="value" style="color:var(--blue);">Bounded</div><div class="note">AI actions allowed only inside authority envelope.</div></div>
                <div class="metric"><div class="label">Evidence Sufficiency</div><div class="value" style="color:var(--green);">91%</div><div class="note">Evidence is strong for low-risk actions; conditional for high-impact changes.</div></div>
                <div class="metric"><div class="label">Trust DNA State</div><div class="value" style="color:var(--purple);">Stable</div><div class="note">Governance genome stable with monitored support/access mutations.</div></div>
                <div class="metric"><div class="label">Governance Entropy</div><div class="value" style="color:var(--orange);">46%</div><div class="note">Disorder remains elevated in support and access domains.</div></div>
                <div class="metric"><div class="label">Executive Decision</div><div class="value" style="color:var(--yellow);">Rely With Limits</div><div class="note">Leadership can rely within defined governance boundaries.</div></div>
            </section>

            <section class="section">
                <h2>Governance Operating System Answer</h2>
                <div class="answer">
                    <strong>Current GovOS interpretation:</strong>
                    CITrust™ allows ServiceNow AI to operate as a governed assistant for CI evidence preparation, recommendation, replay, and anomaly detection. High-impact decisions involving lifecycle, access, certificate state, validation, CAPA, readiness, support ownership, or executive trust remain human-gated, replayable, and evidence-dependent.
                </div>
            </section>

            <section class="section">
                <h2>GovOS Command Kernel</h2>
                <div class="os-grid">
                    <div class="os-card">
                        <h3>Governance Kernel Status</h3>
                        <div class="os-row"><div class="key">Agent Passport</div><div class="val">ServiceNow AI certified inside envelope</div><div class="state"><span class="badge green">Active</span></div></div>
                        <div class="os-row"><div class="key">Authority Envelope</div><div class="val">Autonomous, human-gated, and forbidden zones defined</div><div class="state"><span class="badge green">Active</span></div></div>
                        <div class="os-row"><div class="key">Black Box</div><div class="val">Prompt-to-outcome replay required</div><div class="state"><span class="badge green">Active</span></div></div>
                        <div class="os-row"><div class="key">Claim Firewall</div><div class="val">Unsupported claims blocked or downgraded</div><div class="state"><span class="badge blue">Active</span></div></div>
                        <div class="os-row"><div class="key">Trust DNA</div><div class="val">Living genome stable with monitored mutations</div><div class="state"><span class="badge yellow">Watch</span></div></div>
                        <div class="os-row"><div class="key">Immune System</div><div class="val">Abnormal governance patterns quarantined</div><div class="state"><span class="badge green">Active</span></div></div>
                    </div>

                    <div class="os-card">
                        <h3>Executive Governance Decision</h3>
                        <div class="os-row"><div class="key">Can AI act?</div><div class="val">Yes, for low-risk evidence and recommendation actions</div><div class="state"><span class="badge green">Allow</span></div></div>
                        <div class="os-row"><div class="key">Can AI approve?</div><div class="val">No, for regulated lifecycle, certificate, access, validation, or readiness decisions</div><div class="state"><span class="badge red">Block</span></div></div>
                        <div class="os-row"><div class="key">Can leadership rely?</div><div class="val">Yes, within limitation language and current evidence boundaries</div><div class="state"><span class="badge yellow">Conditional</span></div></div>
                        <div class="os-row"><div class="key">Can QA defend?</div><div class="val">Yes, as human-governed AI assistance with replay</div><div class="state"><span class="badge green">Defensible</span></div></div>
                        <div class="os-row"><div class="key">Can audit replay?</div><div class="val">Yes, trigger, evidence, authority, approval, rollback, and trust impact are preserved</div><div class="state"><span class="badge green">Ready</span></div></div>
                        <div class="os-row"><div class="key">Can trust improve?</div><div class="val">Yes, after support gate, hidden intake, access bundle, and exception owner controls close</div><div class="state"><span class="badge blue">Actionable</span></div></div>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>GovOS Core Engines</h2>
                <div class="cards">
                    <div class="card"><h3>ServiceNow AI Trust Kernel</h3><p>Determines whether ServiceNow AI action is allowed, human-gated, blocked, quarantined, or replay-required.</p></div>
                    <div class="card"><h3>Evidence Sufficiency Kernel</h3><p>Measures whether the evidence is enough to support the requested action or executive claim.</p></div>
                    <div class="card"><h3>Human Governance Kernel</h3><p>Preserves human accountability for regulated decisions, risk acceptance, validation, lifecycle, and certificate state.</p></div>
                    <div class="card"><h3>Inspection Readiness Kernel</h3><p>Converts every AI-assisted decision into replayable inspection evidence with limitation language.</p></div>
                </div>
            </section>

            <section class="section">
                <h2>Governance Operating Matrix</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Governance Question</th>
                            <th>GovOS Engine</th>
                            <th>Current Answer</th>
                            <th>ServiceNow AI Decision</th>
                            <th>Human Gate</th>
                            <th>Evidence Required</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><strong>Can this AI action execute?</strong></td>
                            <td>AI Authority Envelope</td>
                            <td>Allowed only if low-risk, reversible, replayable, and inside approved scope.</td>
                            <td><span class="badge green">Allow low-risk</span></td>
                            <td>Required for regulated impact.</td>
                            <td>Action scope, evidence basis, rollback, replay trace.</td>
                        </tr>
                        <tr>
                            <td><strong>Can leadership trust the result?</strong></td>
                            <td>Assurance Claim Firewall</td>
                            <td>Trust is conditional where support/access evidence is incomplete.</td>
                            <td><span class="badge yellow">Downgrade claim</span></td>
                            <td>Executive owner acceptance.</td>
                            <td>Owner, support, access, certificate, exception, lifecycle evidence.</td>
                        </tr>
                        <tr>
                            <td><strong>Can QA defend the action?</strong></td>
                            <td>Regulatory Replay</td>
                            <td>Yes, where AI is positioned as governed assistance and not final QA authority.</td>
                            <td><span class="badge green">Replay ready</span></td>
                            <td>QA remains accountable.</td>
                            <td>Trigger, evidence, policy, approval, limitation, outcome.</td>
                        </tr>
                        <tr>
                            <td><strong>Is the CI genome stable?</strong></td>
                            <td>Trust DNA</td>
                            <td>Stable, but support and access mutations require monitoring.</td>
                            <td><span class="badge yellow">Monitor</span></td>
                            <td>Needed if mutation affects trust state.</td>
                            <td>Trust genes, mutation history, owner/access/support changes.</td>
                        </tr>
                        <tr>
                            <td><strong>Is governance becoming chaotic?</strong></td>
                            <td>Governance Entropy</td>
                            <td>Entropy elevated in support and access domains.</td>
                            <td><span class="badge orange">Restrict autonomy</span></td>
                            <td>Required for high-entropy domains.</td>
                            <td>Owner churn, evidence decay, exception aging, dependency bypass.</td>
                        </tr>
                        <tr>
                            <td><strong>Where should effort be invested?</strong></td>
                            <td>Trust Market</td>
                            <td>Invest first in hidden dependency intake, support gate, and access evidence bundle.</td>
                            <td><span class="badge blue">Optimize effort</span></td>
                            <td>Leadership prioritization.</td>
                            <td>Trust gain, effort, ROI, downstream assurance lift.</td>
                        </tr>
                        <tr>
                            <td><strong>Should trust be quarantined?</strong></td>
                            <td>Trust Immune System</td>
                            <td>Quarantine if AI overreaches, evidence decays, or support/access mutation affects reliability.</td>
                            <td><span class="badge red">Quarantine if triggered</span></td>
                            <td>Reviewer required to restore trust.</td>
                            <td>Anomaly signal, Black Box replay, recovery evidence.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>GovOS Executive Action Queue</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Action</th>
                            <th>Why It Matters</th>
                            <th>GovOS Impact</th>
                            <th>Expected Result</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><span class="badge red">1</span></td>
                            <td>Make Support and LCM Evidence Gate mandatory.</td>
                            <td>Prevents ServiceNow AI from relying on unclear support accountability.</td>
                            <td>Reduces entropy, stabilizes Trust DNA, improves operations confidence.</td>
                            <td>Support trust becomes evidence-backed.</td>
                        </tr>
                        <tr>
                            <td><span class="badge red">2</span></td>
                            <td>Force Hidden Dependency Candidate Creation.</td>
                            <td>Prevents invisible dependencies from supporting trusted CIs without governance.</td>
                            <td>Improves Trust Market ROI and reduces audit blind spots.</td>
                            <td>Dependencies become visible, owned, and reviewable.</td>
                        </tr>
                        <tr>
                            <td><span class="badge orange">3</span></td>
                            <td>Enforce Access Evidence Bundle before reliance.</td>
                            <td>Prevents unsupported access confidence and unsafe AI recommendations.</td>
                            <td>Improves cyber confidence and Claim Firewall pass rate.</td>
                            <td>Access trust becomes defensible.</td>
                        </tr>
                        <tr>
                            <td><span class="badge yellow">4</span></td>
                            <td>Require Exception Escalation Owner.</td>
                            <td>Prevents unresolved exceptions from becoming governance debt.</td>
                            <td>Improves audit confidence and executive reliance language.</td>
                            <td>Exception closure becomes accountable.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>GovOS Operating Rules</h2>
                <div class="cards">
                    <div class="card"><h3>AI Is Advisory by Default</h3><p>ServiceNow AI may recommend, prepare, detect, and explain, but regulated final decisions remain human-governed.</p></div>
                    <div class="card"><h3>Evidence Is Source of Truth</h3><p>Claims, readiness, certificates, and trust decisions must pass evidence sufficiency before reliance.</p></div>
                    <div class="card"><h3>Autonomy Is Bounded</h3><p>Agents operate only inside approved authority envelopes with rollback and replay requirements.</p></div>
                    <div class="card"><h3>Trust Is Continuously Earned</h3><p>Trust decays, mutates, and recovers based on evidence freshness, entropy, reviewer acceptance, and control maturity.</p></div>
                </div>
            </section>

            <div class="footer">
                CITrust™ does not replace ServiceNow, ServiceNow AI agents, AI Control Tower, CMDB, CSDM, ITSM, ITOM, MyAccess, validation systems, quality systems, audit systems, or accountable human governance. Governance Operating System™ is a governance assurance overlay for ServiceNow AI and autonomous operations, unifying Agent Passport, Governance Black Box, AI Authority Envelope, Regulatory Replay, Trust DNA, Governance Entropy, Trust Market, Claim Firewall, Trust Immune System, Executive Confidence, and evidence-backed human-governed trust decisions.
            </div>
        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_GOVERNANCE_OPERATING_SYSTEM_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Governance Operating System installed.")
