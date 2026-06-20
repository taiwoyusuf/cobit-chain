from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_DECISION_REPLAY_STUDIO_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust Decision Replay Studio already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base module not found. Install AgentTrust module first.")

nav_old = '<a href="/agenttrust/execution-firewall" class="secondary">Execution Firewall</a>'
nav_new = '''<a href="/agenttrust/execution-firewall" class="secondary">Execution Firewall</a>
                    <a href="/agenttrust/decision-replay-studio" class="secondary">Decision Replay</a>
                    <a href="/agenttrust/evidence-lineage-engine" class="dark">Evidence Lineage</a>
                    <a href="/agenttrust/action-timeline" class="dark">Action Timeline</a>
                    <a href="/agenttrust/audit-defense-room" class="dark">Audit Defense</a>'''

if nav_old in text and "/agenttrust/decision-replay-studio" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# AGENTTRUST_DECISION_REPLAY_STUDIO_V1_ACTIVE
# AgentTrust™ Decision Replay Studio, Evidence Lineage Engine,
# Action Timeline, Chain of Authority, Audit Defense Room,
# Immutable Evidence Ledger, and Incident Reconstruction
# ============================================================

AGENTTRUST_REPLAY_EVENTS = [
    {
        "event": "Agent requested CI ownership recommendation",
        "agent": "ServiceNow CI Triage Agent™",
        "authority": "Human-gated recommendation only",
        "tool": "ServiceNow CMDB read access",
        "owner": "CMDB / LCM Owner",
        "outcome": "Recommendation created, no record update executed",
        "status": "Replayable"
    },
    {
        "event": "Agent prepared cutover readiness summary",
        "agent": "Cutover Readiness Summary Agent™",
        "authority": "Draft allowed, human approval required",
        "tool": "Cutover readiness evidence register",
        "owner": "Cutover Governance Owner",
        "outcome": "Draft summary generated for human review",
        "status": "Replayable"
    },
    {
        "event": "Agent attempted privileged access routing",
        "agent": "MyAccess Routing Agent™",
        "authority": "Privileged execution restricted",
        "tool": "MyAccess / CyberArk readiness route",
        "owner": "Access Governance Owner",
        "outcome": "Action escalated to cybersecurity owner",
        "status": "Escalated"
    },
    {
        "event": "Agent summarized regulated inspection evidence",
        "agent": "IRLT Inspection Evidence Agent™",
        "authority": "Human-governed only",
        "tool": "Inspection evidence package",
        "owner": "QA / Regulated Operations Owner",
        "outcome": "Evidence package marked for QA review",
        "status": "Human Review"
    }
]


def agenttrust_replay_event_rows():
    rows = ""

    for item in AGENTTRUST_REPLAY_EVENTS:
        status_class = "green"
        if item["status"] == "Escalated":
            status_class = "orange"
        if item["status"] == "Human Review":
            status_class = "red"

        rows += f"""
        <tr>
            <td><strong>{item["event"]}</strong></td>
            <td>{item["agent"]}</td>
            <td>{item["authority"]}</td>
            <td>{item["tool"]}</td>
            <td>{item["owner"]}</td>
            <td>{item["outcome"]}</td>
            <td><span class="badge {status_class}">{item["status"]}</span></td>
        </tr>
        """

    return rows


@app.route("/agenttrust/decision-replay-studio")
@app.route("/agenttrust/decision-replay")
@app.route("/agenttrust/replay-studio")
def agenttrust_decision_replay_studio():
    rows = agenttrust_replay_event_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Replay Status</div><div class="value" style="color:var(--green);">Ready</div><div class="note">Agent action can be reconstructed.</div></div>
        <div class="metric"><div class="label">Authority Proof</div><div class="value" style="color:var(--yellow);">Required</div><div class="note">Pre-action authority must be visible.</div></div>
        <div class="metric"><div class="label">Tool Evidence</div><div class="value" style="color:var(--blue);">Logged</div><div class="note">API, workflow, and data access evidence.</div></div>
        <div class="metric"><div class="label">Human Owner</div><div class="value" style="color:var(--orange);">Mapped</div><div class="note">Every action links to accountability.</div></div>
        <div class="metric"><div class="label">Outcome</div><div class="value" style="color:var(--purple);">Tracked</div><div class="note">Success, block, escalation, or rollback.</div></div>
        <div class="metric"><div class="label">Audit Defense</div><div class="value" style="color:var(--green);">Built</div><div class="note">Replay package supports inspection defense.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Decision Replay Studio</h2>
        <div class="answer">
            <strong>Purpose:</strong> reconstruct exactly what an AI agent did, what authority existed before the action,
            what tools or data it used, which human owner remained accountable, and what outcome occurred.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Replay Event</th>
                    <th>Agent</th>
                    <th>Authority</th>
                    <th>Tool / Data Evidence</th>
                    <th>Human Owner</th>
                    <th>Outcome</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Replay Questions</h2>
        <div class="grid3">
            <div class="card"><span class="badge blue">1</span><h3>Who acted?</h3><p>Identify the AI agent, version, owner, lifecycle status, and approved purpose.</p></div>
            <div class="card"><span class="badge yellow">2</span><h3>Who allowed it?</h3><p>Show the authority rule, approval route, decision rights, and human-gated controls.</p></div>
            <div class="card"><span class="badge purple">3</span><h3>What did it touch?</h3><p>Show systems, APIs, data sources, workflows, records, and operational boundaries.</p></div>
            <div class="card"><span class="badge orange">4</span><h3>What evidence exists?</h3><p>Show timestamp, tool-call record, input, output, review status, and outcome.</p></div>
            <div class="card"><span class="badge red">5</span><h3>Was it safe?</h3><p>Show prohibited action check, risk tier, rollback path, and escalation outcome.</p></div>
            <div class="card"><span class="badge green">6</span><h3>Can it be defended?</h3><p>Show audit-ready explanation, accountable owner, evidence lineage, and replay package.</p></div>
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Decision Replay Studio",
        "Replay layer for AI agent actions, authority, tool-call evidence, human accountability, and audit defense.",
        body
    )


@app.route("/agenttrust/evidence-lineage-engine")
@app.route("/agenttrust/evidence-lineage")
@app.route("/agenttrust/agent-evidence-lineage")
def agenttrust_evidence_lineage_engine():
    body = """
    <section class="section">
        <h2>AgentTrust™ Evidence Lineage Engine</h2>
        <p>
            Evidence Lineage Engine maps the full chain from source data to AI agent output, human review,
            workflow action, outcome, and audit evidence.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Lineage Step</th>
                    <th>Evidence Captured</th>
                    <th>Governance Purpose</th>
                    <th>Failure Risk</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Source Data</td><td>System, record, data class, retrieval timestamp.</td><td>Proves what the agent relied on.</td><td>Untraceable recommendation.</td></tr>
                <tr><td>Agent Input</td><td>Prompt, context, instruction, user request, system boundary.</td><td>Shows what triggered the AI behavior.</td><td>Unknown decision origin.</td></tr>
                <tr><td>Model / Agent Logic</td><td>Agent ID, model, version, role, tool permission.</td><td>Identifies the acting AI component.</td><td>Unowned or unapproved AI action.</td></tr>
                <tr><td>Tool Call</td><td>API, workflow, data access, action type, result.</td><td>Shows what the agent touched.</td><td>Missing operational proof.</td></tr>
                <tr><td>Human Review</td><td>Reviewer, approver, accountable owner, decision status.</td><td>Preserves human accountability.</td><td>Accountability gap.</td></tr>
                <tr><td>Execution Outcome</td><td>Executed, blocked, escalated, failed, rolled back.</td><td>Shows operational result.</td><td>No post-action proof.</td></tr>
                <tr><td>Replay Package</td><td>Timeline, authority, evidence, owner, outcome, exception.</td><td>Supports audit and inspection defense.</td><td>Weak defensibility.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Lineage Principle</h2>
        <div class="answer">
            AgentTrust™ does not accept isolated AI output as evidence.
            It requires a lineage chain from source evidence to agent action to human accountability to operational outcome.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Evidence Lineage Engine",
        "Evidence lineage from data source to AI output, tool call, human review, outcome, and audit replay.",
        body
    )


@app.route("/agenttrust/action-timeline")
@app.route("/agenttrust/agent-action-timeline")
@app.route("/agenttrust/replay-timeline")
def agenttrust_action_timeline():
    body = """
    <section class="section">
        <h2>AgentTrust™ Action Timeline</h2>
        <p>
            The Action Timeline shows the order of events before, during, and after an AI agent action.
            This is the foundation for audit replay and deviation investigation.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Timeline Stage</th>
                    <th>What Happens</th>
                    <th>Evidence Required</th>
                    <th>Control Outcome</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>T-5: Agent Request</td><td>Agent receives task or user prompt.</td><td>Prompt, requester, timestamp, agent ID.</td><td><span class="badge blue">Request captured</span></td></tr>
                <tr><td>T-4: Boundary Check</td><td>Agent checks whether target system is allowed.</td><td>Passport boundary and system match.</td><td><span class="badge yellow">Boundary verified</span></td></tr>
                <tr><td>T-3: Authority Check</td><td>Agent checks whether action type is permitted.</td><td>Decision rights and approval rule.</td><td><span class="badge yellow">Authority verified</span></td></tr>
                <tr><td>T-2: Risk Check</td><td>Agent checks risk tier and regulated impact.</td><td>Risk tier, GxP/cyber/access impact.</td><td><span class="badge orange">Risk routed</span></td></tr>
                <tr><td>T-1: Evidence Check</td><td>Agent confirms evidence capture is active.</td><td>Tool log, timestamp, linked record.</td><td><span class="badge green">Evidence ready</span></td></tr>
                <tr><td>T0: Action</td><td>Agent reads, recommends, drafts, triggers, or escalates.</td><td>Tool-call record and action result.</td><td><span class="badge purple">Action recorded</span></td></tr>
                <tr><td>T+1: Human Review</td><td>Human owner reviews or approves where required.</td><td>Reviewer, approver, decision record.</td><td><span class="badge orange">Accountability preserved</span></td></tr>
                <tr><td>T+2: Outcome</td><td>Result is executed, blocked, escalated, or rolled back.</td><td>Outcome and verification evidence.</td><td><span class="badge green">Replay complete</span></td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Action Timeline",
        "Timeline of AI agent request, boundary check, authority check, risk routing, evidence capture, action, review, and outcome.",
        body
    )


@app.route("/agenttrust/chain-of-authority")
@app.route("/agenttrust/authority-lineage")
@app.route("/agenttrust/execution-authority-chain")
def agenttrust_chain_of_authority():
    body = """
    <section class="section">
        <h2>AgentTrust™ Chain of Authority</h2>
        <p>
            Chain of Authority proves who or what permitted the AI agent to move from recommendation to action.
            It prevents agents from becoming invisible approvers.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Authority Layer</th>
                    <th>Required Proof</th>
                    <th>Who Owns It</th>
                    <th>Failure Outcome</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Business Authority</td><td>Approved business purpose and use case.</td><td>Business owner.</td><td><span class="badge red">No business use</span></td></tr>
                <tr><td>Technical Authority</td><td>Approved integration, support model, and lifecycle ownership.</td><td>Technical owner.</td><td><span class="badge red">No deployment</span></td></tr>
                <tr><td>Data Authority</td><td>Approved data access scope and sensitivity class.</td><td>Data owner.</td><td><span class="badge orange">Read restricted</span></td></tr>
                <tr><td>Tool Authority</td><td>Approved tools, APIs, workflow triggers, and permission boundaries.</td><td>Platform owner.</td><td><span class="badge red">Tool call blocked</span></td></tr>
                <tr><td>Execution Authority</td><td>Approved action level and human approval rule.</td><td>Process owner / risk owner.</td><td><span class="badge red">Execution blocked</span></td></tr>
                <tr><td>Regulated Authority</td><td>QA, validation, cyber, or access approval where applicable.</td><td>QA / validation / cyber owner.</td><td><span class="badge red">Human-governed only</span></td></tr>
                <tr><td>Exception Authority</td><td>Active exception, expiry date, owner, and accepted residual risk.</td><td>Risk owner.</td><td><span class="badge red">Exception rejected</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Authority Principle</h2>
        <div class="answer">
            The AI agent may execute only when the chain of authority is complete.
            Missing authority converts the action to human review, restriction, escalation, or block.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Chain of Authority",
        "Authority lineage proving who allowed an AI agent to access data, call tools, trigger workflows, or influence operations.",
        body
    )


@app.route("/agenttrust/audit-defense-room")
@app.route("/agenttrust/inspection-defense-room")
@app.route("/agenttrust/replay-defense-room")
def agenttrust_audit_defense_room():
    body = """
    <section class="section">
        <h2>AgentTrust™ Audit Defense Room</h2>
        <p>
            The Audit Defense Room organizes AI agent evidence into inspection-ready questions and answers.
            It is designed for internal audit, QA review, cybersecurity review, regulator inspection, and executive assurance.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Audit Question</th>
                    <th>AgentTrust™ Evidence</th>
                    <th>Defensible Answer</th>
                    <th>Weakness If Missing</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Which AI agent acted?</td><td>Agent ID, name, version, owner, passport.</td><td>Agent identity is traceable.</td><td>Unknown actor.</td></tr>
                <tr><td>Why was the agent allowed to act?</td><td>Authority gate, decision rights, approval rule.</td><td>Authority existed before execution.</td><td>Unauthorized action risk.</td></tr>
                <tr><td>What data did the agent use?</td><td>Source data, record IDs, retrieval evidence.</td><td>Input evidence is traceable.</td><td>Unverifiable output.</td></tr>
                <tr><td>What tool or workflow did it trigger?</td><td>API log, workflow trigger, tool-call evidence.</td><td>System interaction is documented.</td><td>Missing operational trail.</td></tr>
                <tr><td>Who reviewed or approved it?</td><td>Human accountability map, reviewer, approver.</td><td>Human accountability is preserved.</td><td>AI becomes hidden decision-maker.</td></tr>
                <tr><td>What was the result?</td><td>Outcome, exception, rollback, verification.</td><td>Operational outcome is known.</td><td>No result traceability.</td></tr>
                <tr><td>Can the action be replayed?</td><td>Timeline, authority, evidence, owner, outcome package.</td><td>Action is inspection-defensible.</td><td>Replay failure.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Audit Defense Statement</h2>
        <div class="answer">
            AgentTrust™ turns AI agent activity into a defensible evidence package:
            <strong>known agent, known authority, known evidence, known human owner, known outcome.</strong>
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Audit Defense Room",
        "Inspection-ready defense room for AI agent evidence, authority, accountability, decision replay, and operational outcome.",
        body
    )


@app.route("/agenttrust/immutable-evidence-ledger")
@app.route("/agenttrust/evidence-ledger-vault")
@app.route("/agenttrust/agent-evidence-vault")
def agenttrust_immutable_evidence_ledger():
    body = """
    <section class="section">
        <h2>AgentTrust™ Immutable Evidence Ledger</h2>
        <p>
            The Immutable Evidence Ledger defines the evidence records that should be preserved for AI agent action.
            This is the control layer that prevents later reconstruction from replacing time-of-action evidence.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Ledger Record</th>
                    <th>Captured Detail</th>
                    <th>Integrity Requirement</th>
                    <th>Reason</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent Record</td><td>Agent ID, version, owner, lifecycle status.</td><td>Cannot be ownerless.</td><td>Proves actor identity.</td></tr>
                <tr><td>Authority Record</td><td>Action permission, human approval, decision rights.</td><td>Must exist before action.</td><td>Proves allowed execution.</td></tr>
                <tr><td>Input Record</td><td>Prompt, source data, linked record, request context.</td><td>Must be timestamped.</td><td>Proves input basis.</td></tr>
                <tr><td>Tool Record</td><td>Tool/API/workflow called, target system, result.</td><td>Must be linked to agent action.</td><td>Proves system interaction.</td></tr>
                <tr><td>Output Record</td><td>Recommendation, draft, trigger result, status change.</td><td>Must be reviewable.</td><td>Proves generated output.</td></tr>
                <tr><td>Human Record</td><td>Reviewer, approver, accountable owner, escalation owner.</td><td>Must link to named role.</td><td>Preserves accountability.</td></tr>
                <tr><td>Outcome Record</td><td>Executed, blocked, escalated, failed, rolled back.</td><td>Must close the action loop.</td><td>Proves final result.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Ledger Rule</h2>
        <div class="answer">
            If AgentTrust™ cannot preserve the evidence record at the time of action,
            the AI agent should be restricted from execution and limited to recommendation or draft mode.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Immutable Evidence Ledger",
        "Evidence vault for preserving AI agent authority, input, tool-call, output, human accountability, and outcome records.",
        body
    )


@app.route("/agenttrust/incident-reconstruction")
@app.route("/agenttrust/agent-incident-reconstruction")
@app.route("/agenttrust/ai-incident-replay")
def agenttrust_incident_reconstruction():
    body = """
    <section class="section">
        <h2>AgentTrust™ Incident Reconstruction</h2>
        <p>
            Incident Reconstruction is used when an AI agent action creates risk, confusion, operational error,
            access concern, data issue, quality concern, or audit question.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Investigation Step</th>
                    <th>Question</th>
                    <th>Evidence Needed</th>
                    <th>Governance Decision</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>1. Identify Agent</td><td>Which AI agent was involved?</td><td>Agent ID, version, passport, owner.</td><td>Confirm actor.</td></tr>
                <tr><td>2. Confirm Authority</td><td>Was the agent allowed to perform the action?</td><td>Authority gate, approval, decision rights.</td><td>Valid or unauthorized.</td></tr>
                <tr><td>3. Confirm Boundary</td><td>Was the target system inside approved boundary?</td><td>Passport boundary and system evidence.</td><td>Inside or outside boundary.</td></tr>
                <tr><td>4. Review Inputs</td><td>What data or prompt drove the action?</td><td>Prompt, source data, record IDs.</td><td>Valid input or flawed input.</td></tr>
                <tr><td>5. Review Tool Calls</td><td>What API, workflow, or system did the agent touch?</td><td>Tool-call log and timestamp.</td><td>Approved or unauthorized tool use.</td></tr>
                <tr><td>6. Review Human Accountability</td><td>Who reviewed, approved, or should have reviewed?</td><td>Reviewer, approver, accountable owner.</td><td>Accountability preserved or broken.</td></tr>
                <tr><td>7. Determine Outcome</td><td>What happened after the action?</td><td>Outcome, exception, rollback, verification.</td><td>Close, escalate, quarantine, or correct.</td></tr>
                <tr><td>8. Update Governance</td><td>What needs to change?</td><td>Updated passport, risk tier, controls, training.</td><td>Prevent recurrence.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Incident Rule</h2>
        <div class="answer">
            When an AI agent incident occurs, AgentTrust™ reconstructs the action from evidence rather than opinion.
            The goal is to identify whether the failure was identity, authority, boundary, evidence, tool, owner, or outcome related.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Incident Reconstruction",
        "Investigation and replay layer for AI agent incidents, evidence gaps, unauthorized actions, and governance failures.",
        body
    )

# ============================================================
# END AGENTTRUST_DECISION_REPLAY_STUDIO_V1_ACTIVE
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

print("AgentTrust Decision Replay Studio installed.")
print(f"Inserted before: {target_found}")
