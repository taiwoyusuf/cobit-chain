from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_AUTONOMOUS_GOVERNANCE_KERNEL_INDEX_V1_ACTIVE"

if MARKER in text:
    print("CITrust Autonomous Governance Kernel Index already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_AUTONOMOUS_GOVERNANCE_KERNEL_INDEX_V1_ACTIVE
# ============================================================

@app.route("/citrust/autonomous-governance-kernel")
@app.route("/citrust/ai-governance-kernel")
@app.route("/citrust/servicenow-ai-governance-kernel")
def citrust_autonomous_governance_kernel_index():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CITrust™ Autonomous Governance Kernel</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            :root{--bg:#040b14;--panel:rgba(14,27,44,.92);--line:rgba(255,255,255,.12);--text:#eef5ff;--muted:#a8bbd4;--green:#31d07d;--yellow:#f7c948;--red:#ff5c70;--blue:#5cc8ff;--purple:#b49cff;--orange:#ffb86b;--cyan:#7efcff}
            *{box-sizing:border-box}
            body{margin:0;font-family:Arial,Helvetica,sans-serif;background:radial-gradient(circle at top left,rgba(92,200,255,.22),transparent 30%),radial-gradient(circle at top right,rgba(49,208,125,.18),transparent 28%),radial-gradient(circle at bottom right,rgba(180,156,255,.16),transparent 30%),var(--bg);color:var(--text)}
            .page{max-width:1500px;margin:0 auto;padding:28px}
            .hero{border:1px solid var(--line);background:linear-gradient(135deg,rgba(16,29,47,.98),rgba(20,40,66,.92));border-radius:28px;padding:34px;box-shadow:0 24px 80px rgba(0,0,0,.42)}
            .eyebrow{color:var(--cyan);font-size:13px;text-transform:uppercase;letter-spacing:1.9px;font-weight:900;margin-bottom:10px}
            h1{margin:0;font-size:44px;line-height:1.08}.subtitle{color:var(--muted);font-size:16px;line-height:1.65;max-width:1200px;margin-top:14px}
            .positioning{margin-top:18px;padding:18px 20px;border:1px solid rgba(92,200,255,.38);background:rgba(92,200,255,.10);border-radius:18px;color:#d9f3ff;line-height:1.6}
            .kpis{display:grid;grid-template-columns:repeat(6,1fr);gap:14px;margin-top:20px}.metric{border:1px solid var(--line);background:var(--panel);border-radius:18px;padding:18px}.metric .label{color:var(--muted);font-size:13px;margin-bottom:8px}.metric .value{font-size:28px;font-weight:900}.metric .note{margin-top:8px;color:var(--muted);font-size:12px;line-height:1.4}
            .section{margin-top:24px;border:1px solid var(--line);background:var(--panel);border-radius:24px;padding:23px}.section h2{margin:0 0 8px 0;font-size:23px}.section p{color:var(--muted);line-height:1.56;margin-top:0}
            .answer{border:1px solid rgba(49,208,125,.38);background:rgba(49,208,125,.10);color:#dfffea;border-radius:18px;padding:20px;margin-top:16px;line-height:1.65;font-size:15px}
            .badge{display:inline-block;padding:6px 9px;border-radius:999px;font-size:12px;font-weight:900;white-space:nowrap}.green{color:#04140b;background:var(--green)}.yellow{color:#1d1600;background:var(--yellow)}.red{color:#fff;background:var(--red)}.blue{color:#06101d;background:var(--blue)}.purple{color:#120b24;background:var(--purple)}.orange{color:#211100;background:var(--orange)}
            .grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-top:16px}
            .card{border:1px solid var(--line);background:linear-gradient(135deg,rgba(255,255,255,.055),rgba(92,200,255,.055));border-radius:20px;padding:18px;min-height:165px}
            .card h3{margin:0 0 8px 0;font-size:17px}.card p{margin:0;color:var(--muted);font-size:14px;line-height:1.55}.card a{display:inline-block;margin-top:12px;color:#7efcff;text-decoration:none;font-weight:900;font-size:13px}
            table{width:100%;border-collapse:collapse;overflow:hidden;border-radius:16px;margin-top:16px}th{text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.8px;color:#c9dbef;background:rgba(255,255,255,.07);padding:13px 12px;border-bottom:1px solid var(--line)}td{padding:13px 12px;border-bottom:1px solid rgba(255,255,255,.08);color:#e9f2ff;vertical-align:top;font-size:14px}tr:hover td{background:rgba(92,200,255,.05)}
            .footer{color:var(--muted);font-size:12px;margin-top:22px;line-height:1.6}
            @media(max-width:1180px){.kpis,.grid{grid-template-columns:1fr}h1{font-size:30px}table{display:block;overflow-x:auto;white-space:nowrap}}
        </style>
    </head>
    <body>
        <div class="page">
            <section class="hero">
                <div class="eyebrow">CITrust™ / ServiceNow AI / Final Kernel Index</div>
                <h1>CITrust™ Autonomous Governance Kernel</h1>
                <div class="subtitle">
                    Unified command index for the CITrust™ ServiceNow AI governance suite: the governance assurance layer that certifies whether ServiceNow AI actions are evidence-backed, bounded, human-governed, reversible, replayable, inspection-ready, and safe for regulated reliance.
                </div>
                <div class="positioning">
                    <strong>Final positioning:</strong> ServiceNow + NVIDIA-style autonomous agents help enterprises act. CITrust™ proves whether those actions should be trusted in regulated operations.
                </div>
            </section>

            <section class="kpis">
                <div class="metric"><div class="label">Kernel Status</div><div class="value" style="color:var(--green);">Complete</div><div class="note">Core autonomous governance suite assembled.</div></div>
                <div class="metric"><div class="label">ServiceNow Focus</div><div class="value" style="color:var(--blue);">100%</div><div class="note">Built around ServiceNow AI, CMDB, change, access, and governance.</div></div>
                <div class="metric"><div class="label">Human Governance</div><div class="value" style="color:var(--green);">Enforced</div><div class="note">Regulated decisions remain accountable.</div></div>
                <div class="metric"><div class="label">AI Autonomy</div><div class="value" style="color:var(--yellow);">Bounded</div><div class="note">Allowed only inside authority envelope.</div></div>
                <div class="metric"><div class="label">Inspection Defense</div><div class="value" style="color:var(--green);">Ready</div><div class="note">Replay, lineage, rollback, and decision rights integrated.</div></div>
                <div class="metric"><div class="label">Market Position</div><div class="value" style="color:var(--purple);">Unique</div><div class="note">Governance-native layer for ServiceNow AI.</div></div>
            </section>

            <section class="section">
                <h2>Kernel Answer</h2>
                <div class="answer">
                    <strong>CITrust™ Autonomous Governance Kernel is the final wrapper:</strong>
                    It connects Agent Passport, Governance Black Box, Trust DNA, Trust Market, Governance Entropy, Executive Confidence, Authority Envelope, Regulatory Replay, Trust Immune System, GovOS, AI Readiness, Change Gate, Validation Impact, Evidence Sufficiency, Human-Governed Execution, Risk Tiering, Rollback, Decision Rights, Evidence Lineage, Policy Routing, Residual Risk, Exception Sentinel, and Governance DNA Genome into one ServiceNow AI governance assurance suite.
                </div>
            </section>

            <section class="section">
                <h2>Core Kernel Modules</h2>
                <div class="grid">
                    <div class="card"><h3>Agent Governance Passport™</h3><p>Certifies whether ServiceNow AI agents are authorized, governed, and inspection-ready.</p><a href="/citrust/autonomous-agent-governance-passport">Open module</a></div>
                    <div class="card"><h3>Governance Black Box™</h3><p>Preserves prompt, evidence, decision, approval, execution, rollback, and outcome.</p><a href="/citrust/governance-black-box">Open module</a></div>
                    <div class="card"><h3>Governance DNA™</h3><p>Creates the governance identity profile for every CI, AI agent, workflow, and decision.</p><a href="/citrust/governance-dna">Open module</a></div>
                    <div class="card"><h3>Enterprise Genome™</h3><p>Sequences enterprise governance health across CMDB, access, QA, validation, cyber, AI, and trust.</p><a href="/citrust/governance-genome">Open module</a></div>

                    <div class="card"><h3>AI Evidence Sufficiency™</h3><p>Determines whether evidence is enough to support AI action or executive reliance.</p><a href="/citrust/ai-evidence-sufficiency-index">Open module</a></div>
                    <div class="card"><h3>AI Authority Envelope™</h3><p>Separates allowed, human-gated, and forbidden AI actions.</p><a href="/citrust/ai-authority-envelope">Open module</a></div>
                    <div class="card"><h3>Decision Rights Matrix™</h3><p>Defines what AI may decide, recommend, draft, escalate, or never do.</p><a href="/citrust/ai-decision-rights-matrix">Open module</a></div>
                    <div class="card"><h3>Human-Governed AI Board™</h3><p>Preserves accountable human decision-making for regulated operations.</p><a href="/citrust/human-governed-ai-execution-board">Open module</a></div>

                    <div class="card"><h3>Regulatory Replay™</h3><p>Reconstructs AI actions for FDA/MHRA/EMA-style inspection questions.</p><a href="/citrust/regulatory-replay">Open module</a></div>
                    <div class="card"><h3>Rollback Verifier™</h3><p>Blocks AI action if prior state, recovery owner, and verification are missing.</p><a href="/citrust/ai-action-rollback-verifier">Open module</a></div>
                    <div class="card"><h3>Evidence Lineage Mapper™</h3><p>Maps evidence from source to AI recommendation, human decision, and executive claim.</p><a href="/citrust/ai-evidence-lineage-mapper">Open module</a></div>
                    <div class="card"><h3>Policy Compliance Router™</h3><p>Routes AI actions through CMDB, change, access, validation, QA, cyber, and executive policy lanes.</p><a href="/citrust/ai-policy-compliance-router">Open module</a></div>

                    <div class="card"><h3>Residual Risk Ledger™</h3><p>Records who accepted AI-related residual risk, why, for how long, and with what limits.</p><a href="/citrust/ai-residual-risk-acceptance-ledger">Open module</a></div>
                    <div class="card"><h3>Exception Expiry Sentinel™</h3><p>Prevents AI from relying on expired, ownerless, stale, or unresolved exceptions.</p><a href="/citrust/ai-exception-expiry-sentinel">Open module</a></div>
                    <div class="card"><h3>Trust Immune System™</h3><p>Detects governance anomalies, quarantines trust, and blocks unsafe autonomy.</p><a href="/citrust/trust-immune-system">Open module</a></div>
                    <div class="card"><h3>GovOS™</h3><p>Unifies the entire CITrust™ ServiceNow AI governance operating layer.</p><a href="/citrust/governance-operating-system">Open module</a></div>
                </div>
            </section>

            <section class="section">
                <h2>Final Executive Positioning Matrix</h2>
                <table>
                    <thead>
                        <tr>
                            <th>ServiceNow / NVIDIA Direction</th>
                            <th>What It Enables</th>
                            <th>CITrust™ Gap Coverage</th>
                            <th>Regulated Enterprise Value</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><strong>Autonomous AI agents</strong></td>
                            <td>Agents perform multistep enterprise work.</td>
                            <td>Agent Passport, Authority Envelope, Decision Rights, Human-Governed AI.</td>
                            <td>Ensures AI action is bounded, authorized, and accountable.</td>
                        </tr>
                        <tr>
                            <td><strong>Workflow automation</strong></td>
                            <td>Tasks move faster through ServiceNow workflows.</td>
                            <td>Policy Router, Change Gate, Validation Impact, Risk Tiering.</td>
                            <td>Prevents IT automation from bypassing regulated controls.</td>
                        </tr>
                        <tr>
                            <td><strong>AI observability</strong></td>
                            <td>Organizations see AI activity and status.</td>
                            <td>Governance Black Box, Regulatory Replay, Evidence Lineage.</td>
                            <td>Turns logs into inspection-ready governance explanation.</td>
                        </tr>
                        <tr>
                            <td><strong>AI confidence</strong></td>
                            <td>AI may provide confident recommendations.</td>
                            <td>Evidence Sufficiency, Trust DNA, Governance Entropy, Executive Confidence.</td>
                            <td>Recalculates confidence using evidence, policy, validation, access, and rollback.</td>
                        </tr>
                        <tr>
                            <td><strong>Enterprise AI scaling</strong></td>
                            <td>AI expands across functions and workflows.</td>
                            <td>Governance Genome, Trust Immune System, Residual Risk Ledger, Exception Sentinel.</td>
                            <td>Prevents governance debt from scaling with AI adoption.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Final Brand Statement</h2>
                <div class="answer">
                    <strong>CITrust™ — Governance Assurance for ServiceNow AI & Autonomous Operations.</strong>
                    Making ServiceNow AI explainable, evidence-backed, human-governed, reversible, inspection-ready, and safe for regulated reliance.
                </div>
            </section>

            <div class="footer">
                CITrust™ Autonomous Governance Kernel™ does not replace ServiceNow, ServiceNow AI agents, AI Control Tower, CMDB, CSDM, ITSM, ITOM, Change, IRM/GRC, MyAccess, validation systems, QA systems, cyber governance, or accountable human decision-making. It is a governance assurance layer for regulated ServiceNow AI operations.
            </div>
        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_AUTONOMOUS_GOVERNANCE_KERNEL_INDEX_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Autonomous Governance Kernel Index installed.")
