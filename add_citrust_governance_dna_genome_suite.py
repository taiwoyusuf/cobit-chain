from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_GOVERNANCE_DNA_GENOME_SUITE_V1_ACTIVE"

if MARKER in text:
    print("CITrust Governance DNA Genome Suite already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_GOVERNANCE_DNA_GENOME_SUITE_V1_ACTIVE
# ============================================================

@app.route("/citrust/governance-dna")
@app.route("/citrust/governance-dna-profile")
def citrust_governance_dna_profile():
    return citrust_governance_dna_genome_suite("dna")


@app.route("/citrust/governance-dna-drift")
@app.route("/citrust/dna-drift")
def citrust_governance_dna_drift():
    return citrust_governance_dna_genome_suite("drift")


@app.route("/citrust/governance-mutation-detector")
@app.route("/citrust/mutation-detector")
def citrust_governance_mutation_detector():
    return citrust_governance_dna_genome_suite("mutation")


@app.route("/citrust/governance-genome")
@app.route("/citrust/enterprise-governance-genome")
def citrust_enterprise_governance_genome():
    return citrust_governance_dna_genome_suite("genome")


def citrust_governance_dna_genome_suite(active):
    pages = {
        "dna": {
            "title": "CITrust™ Governance DNA Profile",
            "eyebrow": "CITrust™ / ServiceNow AI / Governance Identity Layer",
            "subtitle": "Creates a living Governance DNA profile for every ServiceNow CI, AI agent, workflow, evidence object, and operational decision.",
            "answer": "CITrust™ Governance DNA converts ServiceNow CI data, AI authority, evidence lineage, access proof, validation state, lifecycle control, support ownership, rollback, replay, residual risk, and executive reliance into one governed identity profile.",
            "score": "91%",
            "decision": "Trust With Limits"
        },
        "drift": {
            "title": "CITrust™ Governance DNA Drift",
            "eyebrow": "CITrust™ / ServiceNow AI / Governance Drift Detection",
            "subtitle": "Detects when the governance identity of a CI, AI agent, workflow, or decision has shifted away from its approved trusted state.",
            "answer": "CITrust™ Governance DNA Drift shows that support ownership, access evidence, and exception age have shifted from the prior trusted state. Executive reliance remains conditional until drift is reviewed and accepted.",
            "score": "+12%",
            "decision": "Review Drift"
        },
        "mutation": {
            "title": "CITrust™ Governance Mutation Detector",
            "eyebrow": "CITrust™ / ServiceNow AI / Governance Mutation Intelligence",
            "subtitle": "Detects abnormal governance mutations before they become audit exposure, operational trust collapse, or unsafe autonomous AI execution.",
            "answer": "CITrust™ detected a governance mutation caused by support ownership change, stale access evidence, and certificate readiness language. AI execution should be human-gated and trust should be quarantined until reviewer acceptance.",
            "score": "High",
            "decision": "Quarantine"
        },
        "genome": {
            "title": "CITrust™ Enterprise Governance Genome",
            "eyebrow": "CITrust™ / ServiceNow AI / Enterprise Governance Genome",
            "subtitle": "Sequences the enterprise governance genome across CMDB, access, validation, change, QA, cyber, infrastructure, AI agents, evidence, risk, and executive reliance.",
            "answer": "CITrust™ Enterprise Governance Genome shows the organization is ready for bounded ServiceNow AI assistance but not high-impact autonomous governance decisions until support, access, exception, and validation-impact gates are fully enforced.",
            "score": "84%",
            "decision": "Bounded AI"
        }
    }

    p = pages.get(active, pages["dna"])

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>{p["title"]}</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            :root {{
                --bg:#040b14; --panel:rgba(14,27,44,.92); --line:rgba(255,255,255,.12);
                --text:#eef5ff; --muted:#a8bbd4; --green:#31d07d; --yellow:#f7c948;
                --red:#ff5c70; --blue:#5cc8ff; --purple:#b49cff; --orange:#ffb86b; --cyan:#7efcff;
            }}
            *{{box-sizing:border-box}}
            body{{
                margin:0;font-family:Arial,Helvetica,sans-serif;
                background:
                radial-gradient(circle at top left,rgba(180,156,255,.23),transparent 30%),
                radial-gradient(circle at top right,rgba(92,200,255,.20),transparent 28%),
                radial-gradient(circle at bottom right,rgba(49,208,125,.14),transparent 30%),var(--bg);
                color:var(--text)
            }}
            .page{{max-width:1460px;margin:0 auto;padding:28px}}
            .hero{{border:1px solid var(--line);background:linear-gradient(135deg,rgba(16,29,47,.98),rgba(20,40,66,.92));border-radius:26px;padding:30px;box-shadow:0 24px 80px rgba(0,0,0,.42)}}
            .eyebrow{{color:var(--cyan);font-size:13px;text-transform:uppercase;letter-spacing:1.9px;font-weight:900;margin-bottom:10px}}
            h1{{margin:0;font-size:42px;line-height:1.08}}
            .subtitle{{color:var(--muted);font-size:16px;line-height:1.65;max-width:1180px;margin-top:14px}}
            .positioning{{margin-top:18px;padding:17px 19px;border:1px solid rgba(180,156,255,.38);background:rgba(180,156,255,.10);border-radius:18px;color:#eee7ff;line-height:1.6}}
            .nav{{display:flex;flex-wrap:wrap;gap:10px;margin-top:22px}}
            .nav a{{color:var(--text);text-decoration:none;border:1px solid var(--line);background:rgba(255,255,255,.06);padding:10px 13px;border-radius:999px;font-size:13px}}
            .nav a:hover{{border-color:rgba(92,200,255,.7);background:rgba(92,200,255,.12)}}
            .kpis{{display:grid;grid-template-columns:repeat(6,1fr);gap:14px;margin-top:20px}}
            .metric{{border:1px solid var(--line);background:var(--panel);border-radius:18px;padding:18px}}
            .metric .label{{color:var(--muted);font-size:13px;margin-bottom:8px}}
            .metric .value{{font-size:29px;font-weight:900}}
            .metric .note{{margin-top:8px;color:var(--muted);font-size:12px;line-height:1.4}}
            .section{{margin-top:24px;border:1px solid var(--line);background:var(--panel);border-radius:24px;padding:23px}}
            .section h2{{margin:0 0 8px 0;font-size:23px}}
            .section p{{color:var(--muted);line-height:1.56;margin-top:0}}
            .answer{{border:1px solid rgba(92,200,255,.38);background:rgba(92,200,255,.10);color:#d9f3ff;border-radius:18px;padding:20px;margin-top:16px;line-height:1.65;font-size:15px}}
            .badge{{display:inline-block;padding:6px 9px;border-radius:999px;font-size:12px;font-weight:900;white-space:nowrap}}
            .green{{color:#04140b;background:var(--green)}} .yellow{{color:#1d1600;background:var(--yellow)}}
            .red{{color:#fff;background:var(--red)}} .blue{{color:#06101d;background:var(--blue)}}
            .purple{{color:#120b24;background:var(--purple)}} .orange{{color:#211100;background:var(--orange)}}
            .grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:18px;margin-top:16px}}
            .box{{border:1px solid rgba(180,156,255,.32);background:linear-gradient(135deg,rgba(255,255,255,.06),rgba(180,156,255,.07)),rgba(255,255,255,.035);border-radius:22px;padding:22px;min-height:250px}}
            .box h3{{margin:0 0 12px 0;font-size:21px}}
            .box ul{{margin:0;padding-left:20px;color:var(--muted);font-size:14px;line-height:1.85}}
            .cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-top:16px}}
            .card{{border:1px solid var(--line);background:rgba(255,255,255,.045);border-radius:18px;padding:18px;min-height:150px}}
            .card h3{{margin:0 0 8px 0;font-size:17px}}
            .card p{{margin:0;color:var(--muted);font-size:14px;line-height:1.55}}
            table{{width:100%;border-collapse:collapse;overflow:hidden;border-radius:16px;margin-top:16px}}
            th{{text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.8px;color:#c9dbef;background:rgba(255,255,255,.07);padding:13px 12px;border-bottom:1px solid var(--line)}}
            td{{padding:13px 12px;border-bottom:1px solid rgba(255,255,255,.08);color:#e9f2ff;vertical-align:top;font-size:14px}}
            tr:hover td{{background:rgba(92,200,255,.05)}}
            .footer{{color:var(--muted);font-size:12px;margin-top:22px;line-height:1.6}}
            @media(max-width:1180px){{.kpis,.cards,.grid{{grid-template-columns:1fr}}h1{{font-size:30px}}table{{display:block;overflow-x:auto;white-space:nowrap}}}}
        </style>
    </head>

    <body>
        <div class="page">

            <section class="hero">
                <div class="eyebrow">{p["eyebrow"]}</div>
                <h1>{p["title"]}</h1>
                <div class="subtitle">{p["subtitle"]}</div>
                <div class="positioning">
                    <strong>ServiceNow-focused positioning:</strong>
                    CITrust™ creates the missing governance identity layer above ServiceNow AI, CMDB, ITSM, change, access, validation, evidence, and executive readiness. It does not compete with ServiceNow AI; it proves whether ServiceNow AI actions and ServiceNow-controlled states can be trusted in regulated operations.
                </div>
                <div class="nav">
                    <a href="/citrust/governance-dna">Governance DNA</a>
                    <a href="/citrust/governance-dna-drift">DNA Drift</a>
                    <a href="/citrust/governance-mutation-detector">Mutation Detector</a>
                    <a href="/citrust/governance-genome">Enterprise Genome</a>
                    <a href="/citrust/governance-operating-system">GovOS</a>
                    <a href="/citrust/ai-evidence-sufficiency-index">Evidence Sufficiency</a>
                    <a href="/citrust/ai-decision-rights-matrix">Decision Rights</a>
                    <a href="/citrust/ai-exception-expiry-sentinel">Exception Sentinel</a>
                </div>
            </section>

            <section class="kpis">
                <div class="metric"><div class="label">Governance DNA Score</div><div class="value" style="color:var(--green);">{p["score"]}</div><div class="note">Composite governance identity strength.</div></div>
                <div class="metric"><div class="label">Current Decision</div><div class="value" style="color:var(--yellow);">{p["decision"]}</div><div class="note">Operational trust decision for ServiceNow AI reliance.</div></div>
                <div class="metric"><div class="label">DNA Drift</div><div class="value" style="color:var(--orange);">+12%</div><div class="note">Governance identity changed from approved baseline.</div></div>
                <div class="metric"><div class="label">Mutation Signals</div><div class="value" style="color:var(--red);">4</div><div class="note">Abnormal shifts requiring review.</div></div>
                <div class="metric"><div class="label">Genome Coverage</div><div class="value" style="color:var(--blue);">87%</div><div class="note">Enterprise governance domains sequenced.</div></div>
                <div class="metric"><div class="label">AI Reliance</div><div class="value" style="color:var(--purple);">Bounded</div><div class="note">ServiceNow AI allowed only inside governed boundaries.</div></div>
            </section>

            <section class="section">
                <h2>Governance DNA Answer</h2>
                <div class="answer"><strong>Current interpretation:</strong> {p["answer"]}</div>
            </section>

            <section class="section">
                <h2>Governance DNA Structure</h2>
                <div class="grid">
                    <div class="box">
                        <h3><span class="badge green">Asset DNA</span></h3>
                        <ul>
                            <li>Identity DNA</li>
                            <li>Ownership DNA</li>
                            <li>Support DNA</li>
                            <li>Lifecycle DNA</li>
                            <li>CMDB Relationship DNA</li>
                            <li>Operational Continuity DNA</li>
                        </ul>
                    </div>
                    <div class="box">
                        <h3><span class="badge blue">Evidence DNA</span></h3>
                        <ul>
                            <li>Evidence Sufficiency DNA</li>
                            <li>Evidence Lineage DNA</li>
                            <li>Rollback DNA</li>
                            <li>Replay DNA</li>
                            <li>Certificate DNA</li>
                            <li>Inspection Readiness DNA</li>
                        </ul>
                    </div>
                    <div class="box">
                        <h3><span class="badge purple">AI Governance DNA</span></h3>
                        <ul>
                            <li>Authority Envelope DNA</li>
                            <li>Decision Rights DNA</li>
                            <li>Human Approval DNA</li>
                            <li>Residual Risk DNA</li>
                            <li>Exception Control DNA</li>
                            <li>Executive Reliance DNA</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Governance DNA Matrix</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Governance Gene</th>
                            <th>ServiceNow / AI Signal</th>
                            <th>Current State</th>
                            <th>Mutation Risk</th>
                            <th>AI Reliance Decision</th>
                            <th>Required Control</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><strong>Identity DNA</strong></td>
                            <td>CI name, class, environment, criticality, relationships.</td>
                            <td><span class="badge green">Stable</span></td>
                            <td>Low.</td>
                            <td>AI may draft and recommend.</td>
                            <td>Maintain CMDB identity verification.</td>
                        </tr>
                        <tr>
                            <td><strong>Ownership DNA</strong></td>
                            <td>Owner, LCM, support group, resolver path, escalation owner.</td>
                            <td><span class="badge yellow">Drifting</span></td>
                            <td>Medium-high.</td>
                            <td>Human gate required.</td>
                            <td>Mandatory support and LCM evidence gate.</td>
                        </tr>
                        <tr>
                            <td><strong>Access DNA</strong></td>
                            <td>MyAccess route, approver group, admin/vendor proof, access review.</td>
                            <td><span class="badge orange">Conditional</span></td>
                            <td>High if review proof remains stale.</td>
                            <td>AI cannot approve access.</td>
                            <td>Full access evidence bundle.</td>
                        </tr>
                        <tr>
                            <td><strong>Validation DNA</strong></td>
                            <td>Validation impact, QA/CSV/CSA review, test evidence, baseline state.</td>
                            <td><span class="badge yellow">Human-Gated</span></td>
                            <td>High if AI attempts no-impact conclusion.</td>
                            <td>AI may draft only.</td>
                            <td>QA / validation approval required.</td>
                        </tr>
                        <tr>
                            <td><strong>Rollback DNA</strong></td>
                            <td>Prior state, rollback owner, recovery method, verification criteria.</td>
                            <td><span class="badge green">Replayable</span></td>
                            <td>Low if preserved.</td>
                            <td>Supports bounded AI execution.</td>
                            <td>Post-rollback verification acceptance.</td>
                        </tr>
                        <tr>
                            <td><strong>Exception DNA</strong></td>
                            <td>Exception owner, expiry, residual risk, closure action, escalation.</td>
                            <td><span class="badge red">Mutation Watch</span></td>
                            <td>High if expired or unowned.</td>
                            <td>Claims downgraded.</td>
                            <td>Exception Expiry Sentinel closure.</td>
                        </tr>
                        <tr>
                            <td><strong>Executive Reliance DNA</strong></td>
                            <td>Claim Firewall result, evidence sufficiency, residual risk, approval.</td>
                            <td><span class="badge yellow">Conditional</span></td>
                            <td>Medium.</td>
                            <td>Rely with limitation language.</td>
                            <td>Evidence sufficiency and owner acceptance.</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Governance Genome Engines</h2>
                <div class="cards">
                    <div class="card"><h3>Governance DNA Sequencer</h3><p>Creates a governed identity profile for every ServiceNow CI, workflow, AI agent, and operational decision.</p></div>
                    <div class="card"><h3>DNA Drift Monitor</h3><p>Detects when governance identity changes from the approved trusted baseline.</p></div>
                    <div class="card"><h3>Mutation Detector</h3><p>Detects abnormal shifts that could damage access trust, support reliability, validation state, or executive reliance.</p></div>
                    <div class="card"><h3>Enterprise Genome Mapper</h3><p>Sequences governance health across CMDB, access, validation, QA, cyber, infrastructure, AI, risk, and trust domains.</p></div>
                </div>
            </section>

            <section class="section">
                <h2>Enterprise Governance Genome</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Genome Domain</th>
                            <th>Current Health</th>
                            <th>Mutation Signal</th>
                            <th>ServiceNow AI Impact</th>
                            <th>Leadership Meaning</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr><td><strong>CMDB Genome</strong></td><td><span class="badge green">Strong</span></td><td>Relationship gaps monitored.</td><td>AI can assist with candidate intake.</td><td>CMDB foundation is usable for bounded AI.</td></tr>
                        <tr><td><strong>Access Genome</strong></td><td><span class="badge orange">Conditional</span></td><td>Review freshness and approver proof gaps.</td><td>AI cannot approve access.</td><td>Access claims require limitation language.</td></tr>
                        <tr><td><strong>Validation Genome</strong></td><td><span class="badge yellow">Human-Gated</span></td><td>AI no-impact conclusions forbidden.</td><td>AI may draft assessment only.</td><td>QA/CSV/CSA accountability preserved.</td></tr>
                        <tr><td><strong>Change Genome</strong></td><td><span class="badge yellow">Governed</span></td><td>Impact route must be classified.</td><td>AI may prepare change evidence.</td><td>Formal change remains human-owned.</td></tr>
                        <tr><td><strong>AI Genome</strong></td><td><span class="badge blue">Bounded</span></td><td>Authority drift monitored.</td><td>AI acts only inside envelope.</td><td>Autonomy is controlled, not open-ended.</td></tr>
                        <tr><td><strong>Trust Genome</strong></td><td><span class="badge yellow">Conditional</span></td><td>Support/access/exception mutations.</td><td>AI reliance remains limited.</td><td>Leadership may rely only with evidence boundaries.</td></tr>
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Final CITrust™ Positioning</h2>
                <div class="answer">
                    <strong>CITrust™ is the Governance Assurance Layer for ServiceNow AI and Autonomous Operations.</strong>
                    ServiceNow and NVIDIA-style autonomous agents help enterprises act. CITrust™ proves whether those actions are governed, evidence-backed, human-approved, reversible, replayable, inspection-ready, and safe for regulated reliance.
                </div>
            </section>

            <div class="footer">
                CITrust™ Governance DNA™, Governance DNA Drift™, Governance Mutation Detector™, and Enterprise Governance Genome™ do not replace ServiceNow, ServiceNow AI agents, AI Control Tower, CMDB, CSDM, ITSM, ITOM, Change, IRM/GRC, MyAccess, validation systems, QA systems, cyber governance, or accountable human decision-making. They provide a governance assurance layer that sequences trust identity, detects mutation, measures drift, maps enterprise governance health, and protects regulated organizations from unsupported autonomous reliance.
            </div>
        </div>
    </body>
    </html>
    """
    return html

# ============================================================
# END CITRUST_GOVERNANCE_DNA_GENOME_SUITE_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Governance DNA Genome Suite installed.")
