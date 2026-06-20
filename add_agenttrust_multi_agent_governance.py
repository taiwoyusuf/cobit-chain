from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_MULTI_AGENT_ORCHESTRATION_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust Multi-Agent Orchestration Governance already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base module not found. Install AgentTrust module first.")

nav_old = '<a href="/agenttrust/policy-decision-engine" class="secondary">Decision Engine</a>'
nav_new = '''<a href="/agenttrust/policy-decision-engine" class="secondary">Decision Engine</a>
                    <a href="/agenttrust/multi-agent-governance" class="secondary">Multi-Agent</a>
                    <a href="/agenttrust/agent-delegation-map" class="dark">Delegation Map</a>
                    <a href="/agenttrust/agent-handoff-control" class="dark">Handoff Control</a>
                    <a href="/agenttrust/cascading-risk-map" class="dark">Cascading Risk</a>'''

if nav_old in text and "/agenttrust/multi-agent-governance" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# AGENTTRUST_MULTI_AGENT_ORCHESTRATION_V1_ACTIVE
# AgentTrust™ Multi-Agent Orchestration Governance,
# Delegation Map, Handoff Control, Cascading Risk Map,
# Composite Evidence Bundle, Orchestration Firewall,
# and Multi-Agent JSON Map
# ============================================================

AGENTTRUST_MULTI_AGENT_CHAIN = [
    {
        "step": "1",
        "agent": "ServiceNow CI Triage Agent™",
        "role": "Reviews CI candidate and recommends owner / support group.",
        "handoff_to": "Policy Decision Agent™",
        "risk": "Medium",
        "control": "Recommendation only; no CI update."
    },
    {
        "step": "2",
        "agent": "Policy Decision Agent™",
        "role": "Checks owner, boundary, authority, evidence, GxP, cyber, and rollback.",
        "handoff_to": "Evidence Packaging Agent™",
        "risk": "High Control",
        "control": "Decision engine must produce execute / human-gate / restrict / block."
    },
    {
        "step": "3",
        "agent": "Evidence Packaging Agent™",
        "role": "Builds source evidence, tool-call evidence, human owner, and outcome package.",
        "handoff_to": "Human Reviewer",
        "risk": "Medium",
        "control": "Evidence must be captured at time of action."
    },
    {
        "step": "4",
        "agent": "Human Reviewer",
        "role": "Approves, rejects, escalates, or requests correction.",
        "handoff_to": "ServiceNow Workflow",
        "risk": "Accountability Critical",
        "control": "Human decision must be captured before operational reliance."
    },
    {
        "step": "5",
        "agent": "ServiceNow Workflow",
        "role": "Creates task, change, review item, CI candidate, or update request.",
        "handoff_to": "Audit Replay Package",
        "risk": "Operational",
        "control": "Workflow trigger must be linked to authority and evidence."
    }
]


def agenttrust_multi_agent_chain_rows():
    rows = ""

    for item in AGENTTRUST_MULTI_AGENT_CHAIN:
        risk_badge = "blue"
        if item["risk"] in ["High Control", "Accountability Critical"]:
            risk_badge = "red"
        elif item["risk"] == "Operational":
            risk_badge = "orange"

        rows += f"""
        <tr>
            <td><strong>{item["step"]}</strong></td>
            <td>{item["agent"]}</td>
            <td>{item["role"]}</td>
            <td>{item["handoff_to"]}</td>
            <td><span class="badge {risk_badge}">{item["risk"]}</span></td>
            <td>{item["control"]}</td>
        </tr>
        """

    return rows


@app.route("/agenttrust/multi-agent-governance")
@app.route("/agenttrust/multi-agent-orchestration")
@app.route("/agenttrust/agent-orchestration-governance")
def agenttrust_multi_agent_governance():
    rows = agenttrust_multi_agent_chain_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Multi-Agent Status</div><div class="value" style="color:var(--green);">Governed</div><div class="note">Agent-to-agent handoffs must be controlled.</div></div>
        <div class="metric"><div class="label">Delegation</div><div class="value" style="color:var(--yellow);">Restricted</div><div class="note">Agents cannot delegate authority they do not possess.</div></div>
        <div class="metric"><div class="label">Handoff Evidence</div><div class="value" style="color:var(--blue);">Required</div><div class="note">Every handoff must leave evidence.</div></div>
        <div class="metric"><div class="label">Cascade Risk</div><div class="value" style="color:var(--red);">Mapped</div><div class="note">Risk can increase as agents chain actions.</div></div>
        <div class="metric"><div class="label">Human Review</div><div class="value" style="color:var(--orange);">Preserved</div><div class="note">Multi-agent automation must not erase human accountability.</div></div>
        <div class="metric"><div class="label">Replay</div><div class="value" style="color:var(--purple);">Composite</div><div class="note">Replay package must include every agent in the chain.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Multi-Agent Orchestration Governance</h2>
        <div class="answer">
            <strong>Purpose:</strong> govern AI agents that hand work to other AI agents, tools, workflows, ServiceNow records,
            access routes, evidence packages, or human reviewers. Multi-agent systems create a new risk:
            responsibility can disappear between handoffs unless authority, evidence, and accountability are preserved.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Step</th>
                    <th>Actor</th>
                    <th>Role</th>
                    <th>Handoff To</th>
                    <th>Risk</th>
                    <th>Control</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Multi-Agent Governance Rule</h2>
        <div class="answer">
            An AI agent cannot delegate more authority than it has been granted.
            If Agent A is only allowed to recommend, Agent B must not convert that recommendation into an unauthorized update,
            approval, access grant, workflow trigger, or regulated conclusion.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Multi-Agent Governance",
        "Governance layer for AI agent orchestration, delegation, handoffs, cascading risk, composite evidence, and multi-agent audit replay.",
        body
    )


@app.route("/agenttrust/agent-delegation-map")
@app.route("/agenttrust/delegation-map")
@app.route("/agenttrust/agent-authority-delegation")
def agenttrust_agent_delegation_map():
    body = """
    <section class="section">
        <h2>AgentTrust™ Agent Delegation Map</h2>
        <p>
            The Delegation Map defines what one AI agent may pass to another AI agent.
            Delegation must preserve boundary, authority, evidence, owner, and risk tier.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Delegation Type</th>
                    <th>Allowed?</th>
                    <th>Required Control</th>
                    <th>Risk If Missing</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Pass source evidence to another agent.</td><td><span class="badge green">Allowed</span></td><td>Source record and timestamp must be preserved.</td><td>Evidence lineage breaks.</td></tr>
                <tr><td>Pass recommendation to another agent.</td><td><span class="badge yellow">Human-gated</span></td><td>Recommendation must remain advisory unless approved.</td><td>Recommendation becomes hidden decision.</td></tr>
                <tr><td>Delegate tool-call authority.</td><td><span class="badge red">Restricted</span></td><td>Receiving agent must have its own approved tool authority.</td><td>Authority laundering between agents.</td></tr>
                <tr><td>Delegate approval authority.</td><td><span class="badge red">Prohibited</span></td><td>Human approval required.</td><td>AI becomes invisible approver.</td></tr>
                <tr><td>Delegate access or privileged action.</td><td><span class="badge red">Cyber review</span></td><td>CyberArk / access owner review required.</td><td>Privileged workflow risk.</td></tr>
                <tr><td>Delegate GxP / QA conclusion.</td><td><span class="badge red">Prohibited by default</span></td><td>QA / validation owner must review.</td><td>Regulated decision bypass.</td></tr>
                <tr><td>Delegate workflow trigger.</td><td><span class="badge orange">Restricted</span></td><td>Execution firewall, evidence, and rollback required.</td><td>Uncontrolled operational action.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Delegation Principle</h2>
        <div class="answer">
            Multi-agent delegation must not become authority laundering.
            Each receiving agent must independently satisfy identity, owner, boundary, authority, evidence, and risk controls.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Agent Delegation Map",
        "Delegation map controlling what AI agents may pass to other agents, tools, workflows, and human reviewers.",
        body
    )


@app.route("/agenttrust/agent-handoff-control")
@app.route("/agenttrust/handoff-control")
@app.route("/agenttrust/agent-handoff-governance")
def agenttrust_agent_handoff_control():
    body = """
    <section class="section">
        <h2>AgentTrust™ Agent Handoff Control</h2>
        <p>
            Handoff Control ensures that every movement from one AI agent to another preserves authority, evidence,
            context, human accountability, and final outcome traceability.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Handoff Field</th>
                    <th>Required Evidence</th>
                    <th>Why It Matters</th>
                    <th>Failure Outcome</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Sending Agent</td><td>Agent ID, owner, purpose, risk tier.</td><td>Identifies where the handoff began.</td><td><span class="badge red">Unknown origin</span></td></tr>
                <tr><td>Receiving Agent</td><td>Agent ID, approved boundary, authority level.</td><td>Confirms receiving agent is allowed to continue.</td><td><span class="badge red">Unauthorized continuation</span></td></tr>
                <tr><td>Handoff Reason</td><td>Why the work moved to another agent.</td><td>Explains orchestration logic.</td><td><span class="badge orange">Weak replay</span></td></tr>
                <tr><td>Transferred Context</td><td>Source records, prompt, recommendation, evidence package.</td><td>Preserves decision lineage.</td><td><span class="badge red">Context loss</span></td></tr>
                <tr><td>Authority Limit</td><td>What the receiving agent may and may not do.</td><td>Prevents authority expansion.</td><td><span class="badge red">Authority drift</span></td></tr>
                <tr><td>Human Owner</td><td>Reviewer, approver, escalation owner.</td><td>Preserves accountability.</td><td><span class="badge red">Owner gap</span></td></tr>
                <tr><td>Outcome</td><td>Executed, blocked, escalated, restricted, or quarantined.</td><td>Closes the handoff loop.</td><td><span class="badge orange">Incomplete chain</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Handoff Rule</h2>
        <div class="answer">
            A multi-agent handoff is not complete until the receiving agent, transferred context, authority limit,
            human owner, and outcome are all evidenced.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Agent Handoff Control",
        "Control model for AI agent handoffs, transferred context, authority limits, human accountability, and outcome evidence.",
        body
    )


@app.route("/agenttrust/cascading-risk-map")
@app.route("/agenttrust/agent-cascade-risk")
@app.route("/agenttrust/multi-agent-risk-map")
def agenttrust_cascading_risk_map():
    body = """
    <section class="section">
        <h2>AgentTrust™ Cascading Risk Map</h2>
        <p>
            Cascading risk occurs when a low-risk AI action becomes high-risk after another agent uses it,
            expands it, or converts it into a workflow action.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Initial Agent Action</th>
                    <th>Next Agent Action</th>
                    <th>Cascading Risk</th>
                    <th>Required Control</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Summarizes CI gap.</td><td>Another agent creates update task.</td><td>Summary becomes operational workflow.</td><td><span class="badge yellow">Human review</span></td></tr>
                <tr><td>Recommends access group.</td><td>Another agent drafts MyAccess request.</td><td>Access recommendation enters workflow.</td><td><span class="badge orange">Access owner review</span></td></tr>
                <tr><td>Flags privileged route.</td><td>Another agent triggers CyberArk-related task.</td><td>Privileged access pathway risk.</td><td><span class="badge red">Cyber review</span></td></tr>
                <tr><td>Summarizes validation evidence.</td><td>Another agent drafts QA conclusion.</td><td>Regulated interpretation risk.</td><td><span class="badge red">QA / validation review</span></td></tr>
                <tr><td>Prepares cutover summary.</td><td>Another agent recommends go-live readiness.</td><td>AI influences transition decision.</td><td><span class="badge red">Human cutover approval</span></td></tr>
                <tr><td>Detects missing rollback.</td><td>Another agent still triggers workflow.</td><td>Unsafe execution despite known gap.</td><td><span class="badge red">Execution firewall block</span></td></tr>
                <tr><td>Evidence package incomplete.</td><td>Another agent relies on it for decision.</td><td>Weak evidence is amplified.</td><td><span class="badge orange">Restrict reliance</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Cascading Risk Rule</h2>
        <div class="answer">
            In multi-agent systems, the risk is not only what the first agent does.
            The risk is what the next agent does with the first agent’s output.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Cascading Risk Map",
        "Risk map for multi-agent chains where AI outputs become operational workflows, access requests, regulated evidence, or executive decisions.",
        body
    )


@app.route("/agenttrust/composite-evidence-bundle")
@app.route("/agenttrust/multi-agent-evidence-bundle")
@app.route("/agenttrust/orchestration-evidence-bundle")
def agenttrust_composite_evidence_bundle():
    body = """
    <section class="section">
        <h2>AgentTrust™ Composite Evidence Bundle</h2>
        <p>
            A multi-agent workflow requires a composite evidence bundle, not isolated evidence for only one agent.
            The bundle must show the full chain from first input to final outcome.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Evidence Layer</th>
                    <th>Captured Detail</th>
                    <th>AgentTrust™ Purpose</th>
                    <th>Audit Question Answered</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Chain ID</td><td>Unique multi-agent workflow ID.</td><td>Groups all agents and actions together.</td><td>Which chain is being reviewed?</td></tr>
                <tr><td>Agent Sequence</td><td>Every agent involved and sequence order.</td><td>Shows who acted and when.</td><td>Which agents participated?</td></tr>
                <tr><td>Input Lineage</td><td>Original request, source data, context.</td><td>Preserves origin of the chain.</td><td>What started the chain?</td></tr>
                <tr><td>Handoff Records</td><td>Sending agent, receiving agent, handoff reason, context.</td><td>Preserves chain of custody.</td><td>How did work move?</td></tr>
                <tr><td>Authority Records</td><td>Authority decision for each agent.</td><td>Prevents silent authority expansion.</td><td>Who allowed each step?</td></tr>
                <tr><td>Tool Records</td><td>Tools, APIs, workflows, systems touched.</td><td>Shows operational footprint.</td><td>What systems were touched?</td></tr>
                <tr><td>Human Records</td><td>Reviewer, approver, escalation owner.</td><td>Preserves accountability.</td><td>Which human remained accountable?</td></tr>
                <tr><td>Final Outcome</td><td>Executed, blocked, escalated, restricted, quarantined, or retired.</td><td>Closes the evidence chain.</td><td>What was the result?</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Composite Evidence Rule</h2>
        <div class="answer">
            When multiple agents participate, audit defense must explain the full chain, not only the final agent output.
            AgentTrust™ requires chain-level evidence.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Composite Evidence Bundle",
        "Evidence bundle for multi-agent workflows, including sequence, handoffs, authority, tool calls, human owners, and final outcome.",
        body
    )


@app.route("/agenttrust/orchestration-firewall")
@app.route("/agenttrust/multi-agent-firewall")
@app.route("/agenttrust/agent-orchestration-firewall")
def agenttrust_orchestration_firewall():
    body = """
    <section class="section">
        <h2>AgentTrust™ Orchestration Firewall</h2>
        <p>
            The Orchestration Firewall checks the entire multi-agent chain before allowing workflow continuation.
            It stops unsafe delegation, authority expansion, weak evidence, cyber risk, and GxP bypass.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Firewall Check</th>
                    <th>Question</th>
                    <th>Pass Condition</th>
                    <th>Fail Outcome</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Chain Identity</td><td>Is the multi-agent chain identified?</td><td>Chain ID and agent sequence exist.</td><td><span class="badge red">Block chain</span></td></tr>
                <tr><td>Agent Registration</td><td>Are all agents registered?</td><td>Every agent has ID, owner, purpose, risk tier.</td><td><span class="badge red">Block unregistered agent</span></td></tr>
                <tr><td>Delegation Authority</td><td>Can Agent A hand off to Agent B?</td><td>Delegation allowed in both passports.</td><td><span class="badge red">Block handoff</span></td></tr>
                <tr><td>Authority Preservation</td><td>Did authority expand during handoff?</td><td>Receiving agent does not exceed permitted authority.</td><td><span class="badge red">Block escalation</span></td></tr>
                <tr><td>Evidence Continuity</td><td>Is source and handoff evidence preserved?</td><td>Composite evidence bundle complete.</td><td><span class="badge orange">Restrict reliance</span></td></tr>
                <tr><td>Cyber Escalation</td><td>Does any step involve access, CyberArk, PSM, or privilege?</td><td>Cyber owner review captured.</td><td><span class="badge red">Escalate to cyber</span></td></tr>
                <tr><td>GxP Escalation</td><td>Does any step touch regulated evidence or QA workflow?</td><td>QA / validation owner review captured.</td><td><span class="badge red">Human-governed only</span></td></tr>
                <tr><td>Final Outcome</td><td>Is the final decision recorded?</td><td>Outcome and owner recorded.</td><td><span class="badge orange">Incomplete replay</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Orchestration Firewall Rule</h2>
        <div class="answer">
            Multi-agent speed is not enough. The chain must preserve trust from start to finish:
            known agents, valid delegation, preserved authority, continuous evidence, human accountability, and final outcome.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Orchestration Firewall",
        "Firewall for multi-agent orchestration, delegation authority, handoff evidence, authority preservation, cyber escalation, GxP routing, and final outcome.",
        body
    )


@app.route("/agenttrust/multi-agent-map-json")
@app.route("/agenttrust/orchestration-map-json")
@app.route("/agenttrust/agent-chain-json")
def agenttrust_multi_agent_map_json():
    from flask import jsonify

    return jsonify({
        "module": "AgentTrust™",
        "capability": "Multi-Agent Orchestration Governance",
        "primary_question": "Can this chain of AI agents be operationally trusted to act?",
        "chain": AGENTTRUST_MULTI_AGENT_CHAIN,
        "required_controls": [
            "Every agent must be registered",
            "Every agent must have an accountable owner",
            "Delegation must be allowed by passport",
            "Authority cannot expand during handoff",
            "Composite evidence bundle must be complete",
            "CyberArk / privileged impact must escalate to cybersecurity owner",
            "GxP / QA impact must escalate to QA or validation owner",
            "Final outcome must be replayable"
        ],
        "default_decision": "Human-gate or restrict unless all chain controls are complete"
    })

# ============================================================
# END AGENTTRUST_MULTI_AGENT_ORCHESTRATION_V1_ACTIVE
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

print("AgentTrust Multi-Agent Orchestration Governance installed.")
print(f"Inserted before: {target_found}")
