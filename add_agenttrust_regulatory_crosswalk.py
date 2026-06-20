from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_REGULATORY_CROSSWALK_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust Regulatory Crosswalk already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base module not found. Install AgentTrust module first.")

nav_old = '<a href="/agenttrust/passport-factory" class="secondary">Passport Factory</a>'
nav_new = '''<a href="/agenttrust/passport-factory" class="secondary">Passport Factory</a>
                    <a href="/agenttrust/regulatory-crosswalk" class="secondary">Regulatory Crosswalk</a>
                    <a href="/agenttrust/cobit-crosswalk" class="dark">COBIT Map</a>
                    <a href="/agenttrust/gxp-impact-router" class="dark">GxP Router</a>
                    <a href="/agenttrust/ai-policy-router" class="dark">Policy Router</a>'''

if nav_old in text and "/agenttrust/regulatory-crosswalk" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# AGENTTRUST_REGULATORY_CROSSWALK_V1_ACTIVE
# AgentTrust™ Regulatory Crosswalk, COBIT Map, GxP Impact Router,
# AI Policy Router, and Enterprise Control Tower
# ============================================================

@app.route("/agenttrust/regulatory-crosswalk")
@app.route("/agenttrust/standards-crosswalk")
@app.route("/agenttrust/ai-governance-crosswalk")
def agenttrust_regulatory_crosswalk():
    body = """
    <section class="kpis">
        <div class="metric"><div class="label">Crosswalk Status</div><div class="value" style="color:var(--green);">Active</div><div class="note">Regulatory and governance lenses connected.</div></div>
        <div class="metric"><div class="label">COBIT Lens</div><div class="value" style="color:var(--blue);">Mapped</div><div class="note">Governance objectives translated into AI agent controls.</div></div>
        <div class="metric"><div class="label">AI Risk Lens</div><div class="value" style="color:var(--yellow);">Tiered</div><div class="note">Agent risk increases with autonomy and operational impact.</div></div>
        <div class="metric"><div class="label">GxP Lens</div><div class="value" style="color:var(--red);">Routed</div><div class="note">Regulated impact triggers QA and validation review.</div></div>
        <div class="metric"><div class="label">Cyber Lens</div><div class="value" style="color:var(--orange);">Controlled</div><div class="note">Privileged execution requires access governance.</div></div>
        <div class="metric"><div class="label">Audit Lens</div><div class="value" style="color:var(--purple);">Replayable</div><div class="note">Evidence must survive audit and inspection.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Regulatory Crosswalk</h2>
        <div class="answer">
            <strong>Purpose:</strong> translate AI governance expectations into operational controls for AI agents.
            AgentTrust™ does not only ask whether the AI system is compliant in theory. It asks whether every agent action is
            identified, authorized, evidenced, human-accountable, risk-classified, and defensible at the time of execution.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Governance / Regulatory Lens</th>
                    <th>AgentTrust™ Translation</th>
                    <th>Required Evidence</th>
                    <th>Operational Outcome</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td><strong>COBIT 2019 Governance Lens</strong></td>
                    <td>AI agent must have ownership, objectives, risk controls, monitoring, and evidence.</td>
                    <td>Agent owner, control mapping, risk score, evidence ledger.</td>
                    <td><span class="badge green">Governed AI action</span></td>
                </tr>
                <tr>
                    <td><strong>AI Risk Management Lens</strong></td>
                    <td>Agent risk must be identified, measured, controlled, monitored, and escalated.</td>
                    <td>Risk tier, permitted actions, prohibited actions, escalation route.</td>
                    <td><span class="badge yellow">Risk-tiered execution</span></td>
                </tr>
                <tr>
                    <td><strong>AI Management System Lens</strong></td>
                    <td>Agent lifecycle, change, accountability, monitoring, and continual improvement must be managed.</td>
                    <td>Lifecycle status, owner, change history, review cadence.</td>
                    <td><span class="badge blue">Managed AI lifecycle</span></td>
                </tr>
                <tr>
                    <td><strong>AI Act Readiness Lens</strong></td>
                    <td>Agent must be checked for prohibited use, high-risk impact, transparency, logging, and oversight.</td>
                    <td>AI Act classification, transparency rule, human oversight record.</td>
                    <td><span class="badge purple">Regulatory readiness</span></td>
                </tr>
                <tr>
                    <td><strong>GxP / QA / Validation Lens</strong></td>
                    <td>Agent must be routed if it influences GMP, QC, validation, batch, release, deviation, or inspection evidence.</td>
                    <td>GxP impact assessment, QA owner, validation impact, approval record.</td>
                    <td><span class="badge red">Human-governed only</span></td>
                </tr>
                <tr>
                    <td><strong>CyberArk / MyAccess / ServiceNow Lens</strong></td>
                    <td>Agent access, entitlement, privileged execution, and workflow triggers must be controlled.</td>
                    <td>Access route, entitlement owner, CyberArk impact, tool-call log.</td>
                    <td><span class="badge orange">Access-controlled action</span></td>
                </tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Regulatory Crosswalk",
        "Crosswalk between AI agent governance, COBIT-Chain™, regulated operations, access governance, and audit evidence.",
        body
    )


@app.route("/agenttrust/cobit-crosswalk")
@app.route("/agenttrust/cobit-control-map")
def agenttrust_cobit_crosswalk():
    body = """
    <section class="section">
        <h2>AgentTrust™ COBIT Control Map</h2>
        <p>
            This page translates COBIT-style governance expectations into practical AI agent controls.
            The objective is to move from abstract governance to operational proof.
        </p>

        <table>
            <thead>
                <tr>
                    <th>COBIT-Chain™ Governance Theme</th>
                    <th>AgentTrust™ Control</th>
                    <th>Evidence Artifact</th>
                    <th>Executive Question</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Evaluate</td><td>Agent Risk Classification</td><td>Risk tier, AI Act lens, GxP/cyber impact.</td><td>Should this agent be allowed into operation?</td></tr>
                <tr><td>Direct</td><td>Authority Before Execution</td><td>Decision rights, approval route, permitted/prohibited action matrix.</td><td>Who authorized the agent to act?</td></tr>
                <tr><td>Monitor</td><td>Tool-Call Evidence Ledger</td><td>API calls, workflow triggers, data access logs, timestamps.</td><td>Can we prove what the agent did?</td></tr>
                <tr><td>Accountability</td><td>Human Accountability Map</td><td>Business owner, technical owner, QA/cyber/risk owner.</td><td>Which human remains accountable?</td></tr>
                <tr><td>Risk Optimization</td><td>Agent Risk Passport™</td><td>Purpose, model, data, connected systems, escalation, restrictions.</td><td>Is the risk known and controlled?</td></tr>
                <tr><td>Resource Optimization</td><td>System Boundary Control</td><td>Approved systems, tools, data sources, workflow boundaries.</td><td>Is the agent operating only where it should?</td></tr>
                <tr><td>Assurance</td><td>Evidence at the Time of Action™</td><td>Real-time captured evidence, replay package, outcome record.</td><td>Can the action survive audit or inspection?</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>COBIT-Chain™ Positioning</h2>
        <div class="answer">
            COBIT-Chain™ operationalizes governance by converting control intent into evidence, ownership,
            authority, execution boundaries, risk routing, and audit-ready proof. AgentTrust™ applies that same model to AI agents.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ COBIT Control Map",
        "COBIT-style governance control map for AI agent identity, authority, evidence, risk, accountability, and assurance.",
        body
    )


@app.route("/agenttrust/gxp-impact-router")
@app.route("/agenttrust/regulated-impact-router")
@app.route("/agenttrust/qa-validation-router")
def agenttrust_gxp_impact_router():
    body = """
    <section class="section">
        <h2>AgentTrust™ GxP / QA / Validation Impact Router</h2>
        <p>
            This router determines whether an AI agent must be escalated to QA, validation, cyber, risk, or system ownership
            before it can recommend, draft, trigger, update, or influence regulated operations.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Agent Touchpoint</th>
                    <th>Impact Question</th>
                    <th>Required Owner</th>
                    <th>Execution Rule</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>GMP System Data</td>
                    <td>Does the agent read, summarize, or interpret GMP system data?</td>
                    <td>System Owner / QA where applicable.</td>
                    <td><span class="badge yellow">Human review required</span></td>
                </tr>
                <tr>
                    <td>QC Evidence</td>
                    <td>Does the agent influence QC readiness, QC evidence, or QC interpretation?</td>
                    <td>QC Owner / QA Owner.</td>
                    <td><span class="badge red">Human-governed only</span></td>
                </tr>
                <tr>
                    <td>Validation Evidence</td>
                    <td>Does the agent create, classify, summarize, or influence validation evidence?</td>
                    <td>Validation Owner / QA Owner.</td>
                    <td><span class="badge red">Validation impact review</span></td>
                </tr>
                <tr>
                    <td>Deviation / CAPA</td>
                    <td>Does the agent recommend deviation classification, root cause, CAPA, or closure language?</td>
                    <td>Quality Owner / Process Owner.</td>
                    <td><span class="badge red">Human accountable approval</span></td>
                </tr>
                <tr>
                    <td>Batch / Release</td>
                    <td>Does the agent influence batch disposition, release readiness, or regulated claims?</td>
                    <td>QA Release Owner.</td>
                    <td><span class="badge red">No autonomous approval</span></td>
                </tr>
                <tr>
                    <td>Inspection Evidence</td>
                    <td>Does the agent prepare evidence for FDA, MHRA, EMA, internal audit, or leadership review?</td>
                    <td>QA / Inspection Readiness Owner.</td>
                    <td><span class="badge orange">Evidence package required</span></td>
                </tr>
                <tr>
                    <td>CMDB / ServiceNow Governance</td>
                    <td>Does the agent recommend CI ownership, support group, lifecycle state, or service mapping?</td>
                    <td>LCM / CMDB Owner.</td>
                    <td><span class="badge yellow">Human-gated update</span></td>
                </tr>
                <tr>
                    <td>Access / Privileged Execution</td>
                    <td>Does the agent influence access routing, entitlement, CyberArk, or privileged workflow?</td>
                    <td>Cybersecurity / Access Owner.</td>
                    <td><span class="badge red">Cyber review required</span></td>
                </tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>GxP Routing Rule</h2>
        <div class="answer">
            If an AI agent can influence regulated evidence, quality decisions, validation status, access control,
            batch/release readiness, or inspection claims, AgentTrust™ routes it into <strong>human-governed execution</strong>.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ GxP Impact Router",
        "Routing layer for AI agents that may affect GxP, QA, validation, QC, inspection evidence, or regulated operations.",
        body
    )


@app.route("/agenttrust/ai-policy-router")
@app.route("/agenttrust/policy-router")
@app.route("/agenttrust/agent-policy-router")
def agenttrust_ai_policy_router():
    body = """
    <section class="section">
        <h2>AgentTrust™ AI Policy Router</h2>
        <p>
            The AI Policy Router sends each AI agent action to the correct governance lane before execution.
            It prevents AI from bypassing CMDB, change control, access governance, validation, QA, cybersecurity, or risk acceptance.
        </p>

        <table>
            <thead>
                <tr>
                    <th>AI Agent Action</th>
                    <th>Policy Lane</th>
                    <th>Required Evidence</th>
                    <th>Routing Outcome</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Reads system inventory or CI data.</td><td>CMDB / CITrust™</td><td>Data access scope, CI linkage, owner.</td><td><a href="/citrust/agenttrust-integration">CITrust™ hook</a></td></tr>
                <tr><td>Recommends CI owner, LCM, support group, or service mapping.</td><td>ServiceNow / CMDB</td><td>Recommendation evidence and human reviewer.</td><td><a href="/servicenow-ci-readiness/agenttrust-integration">ServiceNow hook</a></td></tr>
                <tr><td>Creates or updates readiness status.</td><td>CutoverTrust™</td><td>Approval, rollback, transition evidence.</td><td><a href="/cutovertrust/agenttrust-integration">CutoverTrust™ hook</a></td></tr>
                <tr><td>Influences access or privileged workflow.</td><td>MyAccess / CyberArk</td><td>Entitlement owner, approval route, privileged action log.</td><td><a href="/citrust/myaccess-readiness/agenttrust-integration">Access hook</a></td></tr>
                <tr><td>Touches GMP, QC, validation, release, or inspection evidence.</td><td>IRLTTrust™ / RLTTrust™</td><td>QA owner, validation review, regulated evidence package.</td><td><a href="/irlt-commercial-readiness/agenttrust-integration">IRLT hook</a></td></tr>
                <tr><td>Uses AI-generated output in a governance decision.</td><td>AI Governance</td><td>AI Act lens, transparency, risk classification, oversight.</td><td><a href="/ai-governance/agenttrust-integration">AI Governance hook</a></td></tr>
                <tr><td>Executes or triggers workflow automation.</td><td>Governance Black Box</td><td>Tool-call log, authority proof, timestamp, replay package.</td><td><a href="/agenttrust/governance-black-box-integration">Black Box hook</a></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Policy Router Principle</h2>
        <div class="answer">
            AgentTrust™ does not allow agentic execution to float outside governance.
            Every AI agent action must be routed through the correct policy lane before operational reliance.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ AI Policy Router",
        "Policy routing layer for AI agent action across CITrust™, CutoverTrust™, IRLTTrust™, ServiceNow, MyAccess, CyberArk, and AI Governance.",
        body
    )


@app.route("/agenttrust/enterprise-control-tower")
@app.route("/agenttrust/control-tower")
def agenttrust_enterprise_control_tower():
    body = """
    <section class="section">
        <h2>AgentTrust™ Enterprise Control Tower</h2>
        <div class="answer">
            The Enterprise Control Tower gives leadership one view of where AI agents exist, what they can touch,
            what authority they have, what evidence exists, what risk tier they carry, and which human remains accountable.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Leadership View</th>
                    <th>Signal</th>
                    <th>Governance Meaning</th>
                    <th>Required Action</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Unowned Agents</td><td>No business or technical owner.</td><td>AI activity has no accountable human.</td><td><span class="badge red">Assign owner before use</span></td></tr>
                <tr><td>Boundary Gaps</td><td>Agent can access undefined systems or data.</td><td>Operating scope is uncontrolled.</td><td><span class="badge red">Define system boundary</span></td></tr>
                <tr><td>Authority Gaps</td><td>Agent can act without approved decision rights.</td><td>Execution may be unauthorized.</td><td><span class="badge red">Block action</span></td></tr>
                <tr><td>Evidence Gaps</td><td>No tool-call or time-of-action evidence.</td><td>Audit replay may fail.</td><td><span class="badge orange">Restrict to recommendation</span></td></tr>
                <tr><td>GxP Impact</td><td>Agent touches regulated quality or validation process.</td><td>QA and validation review required.</td><td><span class="badge red">Human-governed only</span></td></tr>
                <tr><td>Privileged Execution</td><td>Agent influences access, CyberArk, admin tasks, or workflow triggers.</td><td>Cybersecurity review required.</td><td><span class="badge red">Escalate to cyber owner</span></td></tr>
                <tr><td>Expired Exception</td><td>Agent relies on stale approval or expired risk acceptance.</td><td>Governance debt is being automated.</td><td><span class="badge red">Revalidate or revoke</span></td></tr>
                <tr><td>Trusted Agent</td><td>Identity, authority, evidence, owner, passport, and risk controls complete.</td><td>Agent may operate inside approved boundary.</td><td><span class="badge green">Monitor continuously</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Executive Statement</h2>
        <div class="answer">
            AgentTrust™ turns AI agent adoption into a governed operating model:
            <strong>known agents, known owners, known authority, known evidence, known risk, known accountability.</strong>
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Enterprise Control Tower",
        "Leadership control tower for AI agent risk, ownership, authority, evidence, GxP impact, cyber impact, and operational trust.",
        body
    )

# ============================================================
# END AGENTTRUST_REGULATORY_CROSSWALK_V1_ACTIVE
# ============================================================

'''

targets = [
    'if __name__ == "__main__":',
    "if __name__ == '__main__':"
]

idx = -1
target_found = None

for target in targets:
    current_idx = text.rfind(target)
    if current_idx > idx:
        idx = current_idx
        target_found = target

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("AgentTrust Regulatory Crosswalk installed.")
print(f"Inserted before: {target_found}")
