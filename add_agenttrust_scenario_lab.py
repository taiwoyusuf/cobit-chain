from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_SCENARIO_LAB_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust Scenario Lab already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base module not found. Install AgentTrust module first.")

nav_old = '<a href="/agenttrust/route-health-check" class="secondary">Health Check</a>'
nav_new = '''<a href="/agenttrust/route-health-check" class="secondary">Health Check</a>
                    <a href="/agenttrust/scenario-lab" class="secondary">Scenario Lab</a>
                    <a href="/agenttrust/scenario-casebook" class="dark">Casebook</a>
                    <a href="/agenttrust/scenario-decision-matrix" class="dark">Decision Matrix</a>'''

if nav_old in text and "/agenttrust/scenario-lab" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# AGENTTRUST_SCENARIO_LAB_V1_ACTIVE
# AgentTrust™ Scenario Lab, Demonstration Casebook,
# ServiceNow Agent Scenario, Cutover Agent Scenario,
# MyAccess / CyberArk Agent Scenario, GxP Agent Scenario,
# Audit Replay Scenario, and Executive Decision Matrix
# ============================================================

AGENTTRUST_SCENARIOS = [
    {
        "id": "SCN-001",
        "name": "ServiceNow CMDB Ownership Recommendation Agent",
        "domain": "ServiceNow / CITrust™",
        "risk": "Medium",
        "route": "/agenttrust/servicenow-agent-scenario",
        "question": "Can the agent recommend CI ownership without becoming the hidden CMDB decision-maker?",
        "decision": "Human-gated recommendation only."
    },
    {
        "id": "SCN-002",
        "name": "Cutover Readiness Summary Agent",
        "domain": "CutoverTrust™",
        "risk": "Medium / High",
        "route": "/agenttrust/cutover-agent-scenario",
        "question": "Can the agent summarize cutover readiness without approving go-live?",
        "decision": "Allowed to summarize; blocked from approval."
    },
    {
        "id": "SCN-003",
        "name": "MyAccess / CyberArk Routing Agent",
        "domain": "Access / Cybersecurity",
        "risk": "High",
        "route": "/agenttrust/cyberark-agent-scenario",
        "question": "Can the agent recommend privileged-access routing without granting access?",
        "decision": "Recommendation only; privileged execution requires cyber owner."
    },
    {
        "id": "SCN-004",
        "name": "GxP Inspection Evidence Agent",
        "domain": "QA / Validation / Regulated Operations",
        "risk": "Critical",
        "route": "/agenttrust/gxp-agent-scenario",
        "question": "Can the agent prepare inspection evidence without making regulated conclusions?",
        "decision": "Human-governed only with QA review."
    },
    {
        "id": "SCN-005",
        "name": "Audit Replay and Incident Reconstruction Agent",
        "domain": "Audit / Governance Black Box",
        "risk": "High Control",
        "route": "/agenttrust/audit-replay-scenario",
        "question": "Can leadership reconstruct exactly what the AI agent did?",
        "decision": "Allowed if evidence lineage is complete."
    }
]


def agenttrust_scenario_rows():
    rows = ""

    for item in AGENTTRUST_SCENARIOS:
        badge = "green"
        if item["risk"] == "High":
            badge = "red"
        elif item["risk"] == "Medium / High":
            badge = "orange"
        elif item["risk"] == "Critical":
            badge = "red"
        elif item["risk"] == "High Control":
            badge = "purple"

        rows += f"""
        <tr>
            <td><strong>{item["id"]}</strong><br>{item["name"]}</td>
            <td><span class="badge blue">{item["domain"]}</span></td>
            <td><span class="badge {badge}">{item["risk"]}</span></td>
            <td>{item["question"]}</td>
            <td>{item["decision"]}</td>
            <td><a href="{item["route"]}">Open</a></td>
        </tr>
        """

    return rows


@app.route("/agenttrust/scenario-lab")
@app.route("/agenttrust/demo-scenario-lab")
@app.route("/agenttrust/agent-scenario-lab")
def agenttrust_scenario_lab():
    rows = agenttrust_scenario_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Scenario Lab</div><div class="value" style="color:var(--green);">Active</div><div class="note">Demonstrates AgentTrust™ using enterprise scenarios.</div></div>
        <div class="metric"><div class="label">ServiceNow</div><div class="value" style="color:var(--blue);">Mapped</div><div class="note">CMDB, CSDM, CI ownership, support group, LCM.</div></div>
        <div class="metric"><div class="label">Access</div><div class="value" style="color:var(--red);">Controlled</div><div class="note">MyAccess and CyberArk require human governance.</div></div>
        <div class="metric"><div class="label">GxP</div><div class="value" style="color:var(--orange);">Escalated</div><div class="note">QA and validation review required for regulated impact.</div></div>
        <div class="metric"><div class="label">Audit Replay</div><div class="value" style="color:var(--purple);">Defensible</div><div class="note">Evidence lineage reconstructs agent actions.</div></div>
        <div class="metric"><div class="label">Executive Decision</div><div class="value" style="color:var(--yellow);">Gated</div><div class="note">Leadership can see trust status before reliance.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Scenario Lab</h2>
        <div class="answer">
            <strong>Purpose:</strong> demonstrate how AgentTrust™ controls AI agents inside real enterprise workflows.
            Each scenario shows the agent action, authority gate, evidence rule, human owner, risk route, and final trust decision.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Scenario</th>
                    <th>Domain</th>
                    <th>Risk</th>
                    <th>Trust Question</th>
                    <th>AgentTrust™ Decision</th>
                    <th>Open</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Scenario Lab Rule</h2>
        <div class="answer">
            AgentTrust™ does not ask whether an AI agent can technically perform a task.
            It asks whether the agent can perform or influence the task with identity, authority, evidence,
            human accountability, runtime control, risk routing, and audit defensibility.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Scenario Lab",
        "Demonstration lab for ServiceNow, cutover, MyAccess, CyberArk, GxP, audit replay, and executive AI agent governance scenarios.",
        body
    )


@app.route("/agenttrust/scenario-casebook")
@app.route("/agenttrust/demo-casebook")
@app.route("/agenttrust/agenttrust-casebook")
def agenttrust_scenario_casebook():
    rows = agenttrust_scenario_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Demonstration Casebook</h2>
        <p>
            This casebook gives a boardroom-ready set of AI agent governance demonstrations.
            It can be used to explain why autonomous AI agents need operational assurance before enterprise deployment.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Case</th>
                    <th>Domain</th>
                    <th>Risk</th>
                    <th>Core Question</th>
                    <th>Decision</th>
                    <th>Open</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Casebook Narrative</h2>
        <div class="answer">
            AgentTrust™ shows that the future risk of AI agents is not only model hallucination.
            The deeper operational risk is ungoverned action: unknown agents, unclear owners, unapproved authority,
            missing evidence, weak runtime controls, hidden human accountability gaps, and poor audit replay.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Demonstration Casebook",
        "Casebook of AI agent governance scenarios for ServiceNow, cutover, access, GxP, audit replay, and executive assurance.",
        body
    )


@app.route("/agenttrust/servicenow-agent-scenario")
@app.route("/agenttrust/cmdb-agent-scenario")
@app.route("/agenttrust/ci-agent-scenario")
def agenttrust_servicenow_agent_scenario():
    body = """
    <section class="section">
        <h2>Scenario: ServiceNow CMDB Ownership Recommendation Agent</h2>
        <div class="answer">
            <strong>Scenario:</strong> An AI agent reviews orphan CIs, CI candidates, application records, support group fields,
            and LCM ownership gaps. It recommends CI ownership and service mapping updates.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Governance Check</th>
                    <th>Scenario Evidence</th>
                    <th>Risk If Missing</th>
                    <th>AgentTrust™ Decision</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent Identity</td><td>ServiceNow CI Triage Agent™ registered with owner and purpose.</td><td>Unknown AI actor in CMDB workflow.</td><td><span class="badge green">Pass</span></td></tr>
                <tr><td>System Boundary</td><td>Limited to ServiceNow CMDB, CI candidate factory, and CITrust™ review records.</td><td>Agent may touch unrelated systems.</td><td><span class="badge green">Pass</span></td></tr>
                <tr><td>Authority</td><td>Allowed to recommend. Not allowed to approve or update production CI fields.</td><td>AI becomes hidden CMDB approver.</td><td><span class="badge yellow">Human-gated</span></td></tr>
                <tr><td>Evidence</td><td>Source CI, recommendation, rationale, reviewer, and timestamp captured.</td><td>No proof of why ownership was suggested.</td><td><span class="badge green">Required</span></td></tr>
                <tr><td>Human Owner</td><td>LCM / CMDB owner reviews and approves any final CI update.</td><td>No accountable human.</td><td><span class="badge yellow">Review required</span></td></tr>
                <tr><td>Execution Firewall</td><td>Update, approve, or lifecycle-state change blocked without human approval.</td><td>Unauthorized CMDB changes.</td><td><span class="badge red">Block update</span></td></tr>
                <tr><td>Audit Replay</td><td>Decision replay package links CI source, recommendation, approver, and outcome.</td><td>Weak audit trail.</td><td><span class="badge green">Replayable</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Scenario Decision</h2>
        <div class="answer">
            <strong>AgentTrust™ decision:</strong> The ServiceNow agent may summarize and recommend CI ownership,
            but it must not directly approve, update, or change CI records without LCM / CMDB human approval and evidence.
        </div>
    </section>
    """

    return agenttrust_shell(
        "ServiceNow CMDB Agent Scenario",
        "Scenario showing how AgentTrust™ controls AI recommendations for CI ownership, ServiceNow CMDB, CSDM, support group, and LCM decisions.",
        body
    )


@app.route("/agenttrust/cutover-agent-scenario")
@app.route("/agenttrust/cutover-readiness-agent-scenario")
@app.route("/agenttrust/transition-agent-scenario")
def agenttrust_cutover_agent_scenario():
    body = """
    <section class="section">
        <h2>Scenario: Cutover Readiness Summary Agent</h2>
        <div class="answer">
            <strong>Scenario:</strong> An AI agent reviews cutover trackers, readiness evidence, validation gaps,
            rollback status, change control records, CMDB readiness, MyAccess readiness, and post-cutover checks.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Governance Check</th>
                    <th>Scenario Evidence</th>
                    <th>Risk If Missing</th>
                    <th>AgentTrust™ Decision</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent Identity</td><td>Cutover Readiness Summary Agent™ registered.</td><td>Unknown source of cutover decision support.</td><td><span class="badge green">Pass</span></td></tr>
                <tr><td>Authority</td><td>Allowed to summarize readiness and gaps. Not allowed to approve go-live.</td><td>AI becomes hidden cutover approver.</td><td><span class="badge yellow">Human-gated</span></td></tr>
                <tr><td>Evidence</td><td>Readiness sources, owners, open risks, blockers, and timestamps captured.</td><td>Leadership cannot defend readiness statement.</td><td><span class="badge green">Required</span></td></tr>
                <tr><td>Change Control</td><td>Agent output linked to change records and transition evidence where applicable.</td><td>Cutover bypasses change governance.</td><td><span class="badge orange">Change-linked</span></td></tr>
                <tr><td>Rollback</td><td>Agent checks whether rollback owner, rollback path, and verification evidence exist.</td><td>Unsafe transition decision.</td><td><span class="badge red">Block approval</span></td></tr>
                <tr><td>Human Owner</td><td>Cutover owner, system owner, QA/validation owner review readiness status.</td><td>No accountable readiness decision-maker.</td><td><span class="badge yellow">Review required</span></td></tr>
                <tr><td>Audit Replay</td><td>Replay package shows source evidence, readiness logic, reviewer, and final decision.</td><td>Readiness conclusion not defensible.</td><td><span class="badge purple">Replayable</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Scenario Decision</h2>
        <div class="answer">
            <strong>AgentTrust™ decision:</strong> The cutover agent may summarize and highlight gaps,
            but it cannot approve cutover, override validation gaps, accept risk, or bypass rollback evidence.
        </div>
    </section>
    """

    return agenttrust_shell(
        "Cutover Readiness Agent Scenario",
        "Scenario showing how AgentTrust™ controls AI support for cutover readiness, rollback, validation gaps, change control, and post-cutover verification.",
        body
    )


@app.route("/agenttrust/cyberark-agent-scenario")
@app.route("/agenttrust/myaccess-agent-scenario")
@app.route("/agenttrust/access-agent-scenario")
def agenttrust_cyberark_agent_scenario():
    body = """
    <section class="section">
        <h2>Scenario: MyAccess / CyberArk Routing Agent</h2>
        <div class="answer">
            <strong>Scenario:</strong> An AI agent helps identify whether a user, vendor, support group, system, or privileged action
            should route through MyAccess, CyberArk, PSM, RDP Gateway, or human cybersecurity review.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Governance Check</th>
                    <th>Scenario Evidence</th>
                    <th>Risk If Missing</th>
                    <th>AgentTrust™ Decision</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent Identity</td><td>MyAccess / CyberArk Routing Agent™ registered.</td><td>Unknown actor influencing access decisions.</td><td><span class="badge green">Pass</span></td></tr>
                <tr><td>Authority</td><td>May recommend route. Cannot approve access or privileged execution.</td><td>AI becomes hidden access approver.</td><td><span class="badge red">Approval blocked</span></td></tr>
                <tr><td>Access Scope</td><td>Must identify entitlement group, approver, privileged route, and cybersecurity owner.</td><td>Incorrect access route or privilege exposure.</td><td><span class="badge orange">Review required</span></td></tr>
                <tr><td>CyberArk Impact</td><td>Privileged execution, PSM, admin route, and vendor access flagged.</td><td>Privileged access risk.</td><td><span class="badge red">Cyber review required</span></td></tr>
                <tr><td>Evidence</td><td>Recommendation, source, access request, approver, and outcome captured.</td><td>No access decision trail.</td><td><span class="badge green">Required</span></td></tr>
                <tr><td>Human Owner</td><td>Access owner or cybersecurity owner approves final route.</td><td>AI-controlled access governance.</td><td><span class="badge red">Human approval required</span></td></tr>
                <tr><td>Runtime Firewall</td><td>Agent cannot submit, approve, or activate privileged workflow unless explicitly authorized.</td><td>Unauthorized privileged action.</td><td><span class="badge red">Block</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Scenario Decision</h2>
        <div class="answer">
            <strong>AgentTrust™ decision:</strong> The access agent may assist with routing logic,
            but access approval and privileged execution must remain human-governed, evidenced, and cybersecurity-reviewed.
        </div>
    </section>
    """

    return agenttrust_shell(
        "MyAccess / CyberArk Agent Scenario",
        "Scenario showing how AgentTrust™ controls AI agents that influence access routing, CyberArk, PSM, privileged execution, and cybersecurity review.",
        body
    )


@app.route("/agenttrust/gxp-agent-scenario")
@app.route("/agenttrust/qa-agent-scenario")
@app.route("/agenttrust/regulated-agent-scenario")
def agenttrust_gxp_agent_scenario():
    body = """
    <section class="section">
        <h2>Scenario: GxP Inspection Evidence Agent</h2>
        <div class="answer">
            <strong>Scenario:</strong> An AI agent prepares summaries of validation evidence, QC readiness,
            system ownership, change records, deviation context, or inspection evidence for regulated operations.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Governance Check</th>
                    <th>Scenario Evidence</th>
                    <th>Risk If Missing</th>
                    <th>AgentTrust™ Decision</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent Identity</td><td>GxP Inspection Evidence Agent™ registered with QA-relevant owner.</td><td>Unknown source of regulated evidence summary.</td><td><span class="badge green">Pass</span></td></tr>
                <tr><td>GxP Impact</td><td>Agent touches GMP, QA, validation, QC, release, deviation, or inspection evidence.</td><td>Regulated reliance without impact review.</td><td><span class="badge red">Critical</span></td></tr>
                <tr><td>Authority</td><td>May prepare evidence package. Cannot make final quality conclusion.</td><td>AI becomes hidden quality decision-maker.</td><td><span class="badge red">Human-governed only</span></td></tr>
                <tr><td>QA Review</td><td>QA / validation owner reviews output before operational reliance.</td><td>Inspection or validation defensibility weakness.</td><td><span class="badge red">Required</span></td></tr>
                <tr><td>Evidence Lineage</td><td>Source records, system, timestamp, owner, review, and outcome captured.</td><td>Evidence cannot be defended.</td><td><span class="badge purple">Replay required</span></td></tr>
                <tr><td>Prohibited Action</td><td>Agent cannot approve validation evidence, deviation closure, batch release, or inspection response.</td><td>Regulated decision bypass.</td><td><span class="badge red">Blocked</span></td></tr>
                <tr><td>Lifecycle Change</td><td>Model, prompt, or evidence-source change triggers QA impact review.</td><td>Uncontrolled regulated behavior drift.</td><td><span class="badge orange">Change gate</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Scenario Decision</h2>
        <div class="answer">
            <strong>AgentTrust™ decision:</strong> The GxP agent may assist with evidence preparation,
            but regulated conclusions, validation approval, quality decisions, release decisions, and inspection responses
            must remain human-governed and QA-reviewed.
        </div>
    </section>
    """

    return agenttrust_shell(
        "GxP / QA Impact Agent Scenario",
        "Scenario showing how AgentTrust™ controls AI agents that touch GMP, QA, validation, QC, release, deviation, and inspection evidence.",
        body
    )


@app.route("/agenttrust/audit-replay-scenario")
@app.route("/agenttrust/decision-replay-scenario")
@app.route("/agenttrust/incident-replay-scenario")
def agenttrust_audit_replay_scenario():
    body = """
    <section class="section">
        <h2>Scenario: Audit Replay and Incident Reconstruction Agent</h2>
        <div class="answer">
            <strong>Scenario:</strong> Leadership, QA, cybersecurity, or audit asks:
            “What exactly did the AI agent do, why did it do it, who allowed it, what did it touch, and what was the outcome?”
        </div>

        <table>
            <thead>
                <tr>
                    <th>Replay Layer</th>
                    <th>Evidence Required</th>
                    <th>Question Answered</th>
                    <th>Defensibility Status</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent Identity</td><td>Agent ID, version, owner, lifecycle status.</td><td>Which AI agent acted?</td><td><span class="badge green">Required</span></td></tr>
                <tr><td>Authority Proof</td><td>Decision rights, approval route, permitted action.</td><td>Why was it allowed?</td><td><span class="badge yellow">Required before action</span></td></tr>
                <tr><td>Input Evidence</td><td>Prompt, source data, retrieved record, timestamp.</td><td>What did the agent rely on?</td><td><span class="badge blue">Traceable</span></td></tr>
                <tr><td>Tool Evidence</td><td>API call, workflow trigger, data access, system touched.</td><td>What did the agent do?</td><td><span class="badge purple">Logged</span></td></tr>
                <tr><td>Human Accountability</td><td>Reviewer, approver, accountable owner, escalation owner.</td><td>Which human remained accountable?</td><td><span class="badge orange">Mapped</span></td></tr>
                <tr><td>Outcome Evidence</td><td>Executed, blocked, escalated, failed, rolled back, verified.</td><td>What happened after the action?</td><td><span class="badge green">Closed loop</span></td></tr>
                <tr><td>Replay Package</td><td>Timeline, authority lineage, evidence lineage, owner, outcome.</td><td>Can the action be defended?</td><td><span class="badge green">Audit-ready</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Scenario Decision</h2>
        <div class="answer">
            <strong>AgentTrust™ decision:</strong> The agent action is defensible only when identity, authority,
            input, tool-call evidence, human accountability, outcome, and replay package are complete.
        </div>
    </section>
    """

    return agenttrust_shell(
        "Audit Replay Scenario",
        "Scenario showing how AgentTrust™ reconstructs AI agent action for audit, QA, cybersecurity, incident review, and executive assurance.",
        body
    )


@app.route("/agenttrust/scenario-decision-matrix")
@app.route("/agenttrust/demo-decision-matrix")
@app.route("/agenttrust/agent-decision-matrix")
def agenttrust_scenario_decision_matrix():
    body = """
    <section class="section">
        <h2>AgentTrust™ Scenario Decision Matrix</h2>
        <p>
            This matrix shows how AgentTrust™ decides whether an AI agent may execute, must be human-gated,
            must be restricted, must be escalated, or must be blocked.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Scenario Condition</th>
                    <th>AgentTrust™ Signal</th>
                    <th>Decision</th>
                    <th>Required Owner</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent is registered, owned, bounded, authorized, evidenced, and low-risk.</td><td>Strong trust package.</td><td><span class="badge green">Execute within boundary</span></td><td>Business / technical owner.</td></tr>
                <tr><td>Agent can recommend but not approve.</td><td>Authority allows advisory action only.</td><td><span class="badge yellow">Human-gated</span></td><td>Process owner.</td></tr>
                <tr><td>Evidence capture is incomplete.</td><td>Audit replay weakness.</td><td><span class="badge orange">Restrict to draft / summary</span></td><td>Audit / platform owner.</td></tr>
                <tr><td>Agent touches access or privileged workflow.</td><td>Cybersecurity impact.</td><td><span class="badge red">Escalate to cyber owner</span></td><td>Cybersecurity / CyberArk owner.</td></tr>
                <tr><td>Agent touches GMP, QA, validation, release, or inspection evidence.</td><td>Regulated impact.</td><td><span class="badge red">Human-governed only</span></td><td>QA / validation owner.</td></tr>
                <tr><td>Agent lacks owner or authority.</td><td>Accountability or authority failure.</td><td><span class="badge red">Block</span></td><td>Governance owner.</td></tr>
                <tr><td>Agent acts outside approved boundary.</td><td>Boundary violation.</td><td><span class="badge red">Quarantine</span></td><td>Technical owner / risk owner.</td></tr>
                <tr><td>Agent model, prompt, tool, data source, or authority changes.</td><td>Lifecycle drift.</td><td><span class="badge orange">Change gate</span></td><td>Lifecycle owner.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Decision Matrix Rule</h2>
        <div class="answer">
            AgentTrust™ does not have only yes/no decisions. It supports graded governance outcomes:
            execute, human-gate, restrict, escalate, block, quarantine, revalidate, or retire.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Scenario Decision Matrix",
        "Decision matrix for AI agent execution, human gating, restriction, escalation, block, quarantine, revalidation, and retirement.",
        body
    )


@app.route("/agenttrust/sample-decision-log")
@app.route("/agenttrust/scenario-decision-log")
@app.route("/agenttrust/demo-decision-log")
def agenttrust_sample_decision_log():
    body = """
    <section class="section">
        <h2>AgentTrust™ Sample Decision Log</h2>
        <p>
            This sample log shows how AgentTrust™ decisions can be recorded for each AI agent scenario.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Decision ID</th>
                    <th>Agent Scenario</th>
                    <th>Decision</th>
                    <th>Evidence Package</th>
                    <th>Human Owner</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>AT-DL-001</td><td>ServiceNow CMDB ownership recommendation.</td><td>Recommendation allowed; update blocked.</td><td>CI source, recommendation rationale, reviewer.</td><td>LCM / CMDB Owner.</td><td><span class="badge yellow">Human-gated</span></td></tr>
                <tr><td>AT-DL-002</td><td>Cutover readiness summary.</td><td>Summary allowed; go-live approval blocked.</td><td>Readiness tracker, blockers, rollback evidence.</td><td>Cutover Owner.</td><td><span class="badge yellow">Human-gated</span></td></tr>
                <tr><td>AT-DL-003</td><td>MyAccess / CyberArk routing.</td><td>Route recommendation allowed; access approval blocked.</td><td>Request context, entitlement route, cyber owner.</td><td>Access / Cybersecurity Owner.</td><td><span class="badge red">Restricted</span></td></tr>
                <tr><td>AT-DL-004</td><td>GxP inspection evidence preparation.</td><td>Evidence prep allowed; regulated conclusion blocked.</td><td>Source evidence, QA review, validation impact.</td><td>QA / Validation Owner.</td><td><span class="badge red">Human-governed only</span></td></tr>
                <tr><td>AT-DL-005</td><td>Audit replay reconstruction.</td><td>Replay allowed if evidence lineage complete.</td><td>Agent ID, authority, tool-call evidence, outcome.</td><td>Audit / Governance Owner.</td><td><span class="badge green">Replayable</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Decision Log Rule</h2>
        <div class="answer">
            Every important AI agent governance decision should leave behind a decision record:
            what the agent requested, what AgentTrust™ decided, what evidence supported the decision,
            who remained accountable, and what final status was assigned.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Sample Decision Log",
        "Sample decision log for AI agent governance decisions, evidence packages, human owners, and trust status.",
        body
    )

# ============================================================
# END AGENTTRUST_SCENARIO_LAB_V1_ACTIVE
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

print("AgentTrust Scenario Lab installed.")
print(f"Inserted before: {target_found}")
