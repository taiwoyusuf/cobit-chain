from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_COMMAND_CENTER_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust Command Center already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base module not found. Install AgentTrust module first.")

nav_old = '<a href="/agenttrust/integration-map" class="secondary">Integration Map</a>'
nav_new = '''<a href="/agenttrust/integration-map" class="secondary">Integration Map</a>
                    <a href="/agenttrust/command-center" class="secondary">Command Center</a>
                    <a href="/agenttrust/readiness-gate" class="dark">Readiness Gate</a>
                    <a href="/agenttrust/risk-tiering" class="dark">Risk Tiering</a>
                    <a href="/agenttrust/control-library" class="dark">Control Library</a>'''

if nav_old in text and "/agenttrust/command-center" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# AGENTTRUST_COMMAND_CENTER_V1_ACTIVE
# AgentTrust™ Operational Command Center, Readiness Gate,
# Risk Tiering, Control Library, and Operational Matrix
# ============================================================

@app.route("/agenttrust/command-center")
@app.route("/agenttrust/operational-command-center")
def agenttrust_command_center():
    body = """
    <section class="kpis">
        <div class="metric"><div class="label">Agent Register</div><div class="value" style="color:var(--green);">Defined</div><div class="note">Agent identity and ownership model established.</div></div>
        <div class="metric"><div class="label">Authority Gate</div><div class="value" style="color:var(--yellow);">Required</div><div class="note">AI agents must prove authority before action.</div></div>
        <div class="metric"><div class="label">Evidence Capture</div><div class="value" style="color:var(--green);">At Action</div><div class="note">Evidence captured when the agent acts.</div></div>
        <div class="metric"><div class="label">Human Owner</div><div class="value" style="color:var(--orange);">Mandatory</div><div class="note">Every action maps to an accountable human.</div></div>
        <div class="metric"><div class="label">Risk Passport</div><div class="value" style="color:var(--purple);">Core</div><div class="note">Main assurance artifact for each AI agent.</div></div>
        <div class="metric"><div class="label">Operational Trust</div><div class="value" style="color:var(--blue);">Scored</div><div class="note">Trust based on identity, authority, evidence, and risk.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Operational Command Center</h2>
        <div class="answer">
            <strong>Command Center purpose:</strong> determine whether an AI agent is operationally trusted, conditionally trusted,
            restricted, blocked, or requires human-governed escalation before it can act inside COBIT-Chain™ governed operations.
        </div>

        <div class="grid">
            <div class="card"><span class="badge green">Trusted</span><h3>Operationally Trusted Agent</h3><p>Identity, owner, authority, evidence, risk passport, human accountability, and boundary are complete.</p><a href="/agenttrust/readiness-gate">Open Readiness Gate</a></div>
            <div class="card"><span class="badge yellow">Conditional</span><h3>Conditionally Trusted Agent</h3><p>Agent may recommend or draft, but cannot execute without human approval or missing evidence closure.</p><a href="/agenttrust/risk-tiering">Open Risk Tiering</a></div>
            <div class="card"><span class="badge orange">Restricted</span><h3>Restricted Agent</h3><p>Agent has limited authority because it touches critical systems, regulated data, cyber controls, or GxP workflows.</p><a href="/agenttrust/operational-matrix">Open Operational Matrix</a></div>
            <div class="card"><span class="badge red">Blocked</span><h3>Blocked Agent</h3><p>Agent cannot act because authority, owner, boundary, evidence, or prohibited-action controls are missing.</p><a href="/agenttrust/control-library">Open Control Library</a></div>
        </div>
    </section>

    <section class="section">
        <h2>Executive Governance View</h2>
        <table>
            <thead>
                <tr>
                    <th>Governance Domain</th>
                    <th>AgentTrust™ Control</th>
                    <th>Executive Question Answered</th>
                    <th>Trust Outcome</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Identity</td><td>Agent Identity Register</td><td>Do we know what this AI agent is and who owns it?</td><td><span class="badge green">Traceable</span></td></tr>
                <tr><td>Authority</td><td>Authority Before Execution</td><td>Was the agent allowed to act before it acted?</td><td><span class="badge yellow">Pre-Gated</span></td></tr>
                <tr><td>Evidence</td><td>Tool-Call Evidence Ledger</td><td>Can we prove what the agent did?</td><td><span class="badge green">Defensible</span></td></tr>
                <tr><td>Accountability</td><td>Human Accountability Map</td><td>Which human remains accountable for the agent action?</td><td><span class="badge orange">Owned</span></td></tr>
                <tr><td>Risk</td><td>Agent Risk Passport™</td><td>What is the agent allowed to do, prohibited from doing, and required to escalate?</td><td><span class="badge purple">Governed</span></td></tr>
                <tr><td>Audit</td><td>Evidence at the Time of Action™</td><td>Was evidence captured at the time of the decision or reconstructed later?</td><td><span class="badge green">Inspection-Ready</span></td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Command Center",
        "Operational trust command center for AI agent identity, authority, evidence, accountability, risk, and execution readiness.",
        body
    )


@app.route("/agenttrust/readiness-gate")
@app.route("/agenttrust/agent-readiness-gate")
def agenttrust_readiness_gate():
    body = """
    <section class="section">
        <h2>AgentTrust™ Readiness Gate</h2>
        <p>
            This gate determines whether an AI agent can move from concept, pilot, or sandbox into governed operational use.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Gate</th>
                    <th>Required Evidence</th>
                    <th>Pass / Fail Rule</th>
                    <th>Result If Missing</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Gate 1 — Identity</td><td>Agent ID, owner, role, purpose, lifecycle status.</td><td>Must be complete.</td><td><span class="badge red">Block go-live</span></td></tr>
                <tr><td>Gate 2 — Boundary</td><td>Connected systems, data scope, allowed environment, prohibited zones.</td><td>Must define where the agent can and cannot act.</td><td><span class="badge red">Block execution</span></td></tr>
                <tr><td>Gate 3 — Authority</td><td>Decision rights, action level, approval rule, escalation rule.</td><td>Must prove authority before execution.</td><td><span class="badge red">Block action</span></td></tr>
                <tr><td>Gate 4 — Evidence</td><td>Tool logs, workflow trigger record, data access record, timestamp, outcome.</td><td>Must capture evidence at time of action.</td><td><span class="badge yellow">Restrict to recommendation only</span></td></tr>
                <tr><td>Gate 5 — Human Accountability</td><td>Business owner, technical owner, risk owner, QA/cyber owner where applicable.</td><td>Must link every action to a human owner.</td><td><span class="badge red">Block autonomous action</span></td></tr>
                <tr><td>Gate 6 — Risk Passport</td><td>Purpose, model, data, systems, tools, prohibited actions, escalation, audit evidence.</td><td>Must be approved before operational use.</td><td><span class="badge orange">Conditional trust only</span></td></tr>
                <tr><td>Gate 7 — Rollback / Stop Control</td><td>Rollback owner, stop rule, recovery path, exception handling.</td><td>Required for workflow-triggering or record-changing agents.</td><td><span class="badge red">Block execution</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Readiness Outcome Logic</h2>
        <div class="grid3">
            <div class="card"><span class="badge green">Pass</span><h3>Operationally Trusted</h3><p>All gates complete. Agent may operate inside approved boundary.</p></div>
            <div class="card"><span class="badge yellow">Conditional</span><h3>Human-Gated</h3><p>Agent may recommend, draft, or prepare action, but human approval is required.</p></div>
            <div class="card"><span class="badge red">Fail</span><h3>Blocked</h3><p>Agent cannot act until missing authority, evidence, owner, or risk controls are closed.</p></div>
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Readiness Gate",
        "Go-live readiness gate for AI agents and autonomous workflows.",
        body
    )


@app.route("/agenttrust/risk-tiering")
@app.route("/agenttrust/agent-risk-tiering")
def agenttrust_risk_tiering():
    body = """
    <section class="section">
        <h2>AgentTrust™ Risk Tiering</h2>
        <p>
            Risk tiering classifies each AI agent based on what it can touch, what it can change,
            how much autonomy it has, and whether it affects regulated, cyber, access, quality, or operational decisions.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Tier</th>
                    <th>Agent Capability</th>
                    <th>Governance Requirement</th>
                    <th>Permitted Trust Level</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Tier 0</td><td>Information-only chatbot with no system action.</td><td>Identity, owner, content boundary, basic logging.</td><td><span class="badge green">Low Risk</span></td></tr>
                <tr><td>Tier 1</td><td>Reads approved data and summarizes.</td><td>Data scope, access evidence, source traceability.</td><td><span class="badge green">Trusted Read</span></td></tr>
                <tr><td>Tier 2</td><td>Recommends action or drafts workflow content.</td><td>Human review, decision rights, evidence sufficiency.</td><td><span class="badge yellow">Human-Gated</span></td></tr>
                <tr><td>Tier 3</td><td>Creates tickets or initiates non-regulated workflows.</td><td>Workflow authority, owner, tool-call log, exception route.</td><td><span class="badge orange">Restricted Execution</span></td></tr>
                <tr><td>Tier 4</td><td>Updates records, triggers access, changes status, or affects operational systems.</td><td>Approval trail, rollback, cyber review, audit evidence.</td><td><span class="badge red">High Control</span></td></tr>
                <tr><td>Tier 5</td><td>Influences GxP, QA, validation, batch, release, safety, inspection, or regulated decisions.</td><td>QA approval, validation impact, human authorization, complete risk passport.</td><td><span class="badge red">Regulated Critical</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Simple Rule</h2>
        <div class="answer">
            The more an AI agent can change, trigger, approve, access, or influence regulated operations, the more AgentTrust™ moves it from
            <strong>trusted automation</strong> to <strong>human-governed execution</strong>.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Risk Tiering",
        "Risk classification model for AI agents, autonomous workflows, and AI-enabled operational actions.",
        body
    )


@app.route("/agenttrust/control-library")
@app.route("/agenttrust/controls")
def agenttrust_control_library():
    body = """
    <section class="section">
        <h2>AgentTrust™ Control Library</h2>
        <p>
            This library defines the core controls required to govern AI agents before, during, and after execution.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Control ID</th>
                    <th>Control Name</th>
                    <th>Control Objective</th>
                    <th>Evidence Required</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>AT-001</td><td>Agent Identity Control</td><td>Every AI agent must have a unique ID, owner, purpose, and lifecycle status.</td><td>Agent register record.</td></tr>
                <tr><td>AT-002</td><td>Human Accountability Control</td><td>Every autonomous action must map to a responsible human owner.</td><td>Accountability map.</td></tr>
                <tr><td>AT-003</td><td>Authority Before Execution Control</td><td>Agent must confirm authority before acting.</td><td>Authority gate record.</td></tr>
                <tr><td>AT-004</td><td>Tool-Call Evidence Control</td><td>Every API call, workflow trigger, or data access must be logged.</td><td>Tool-call evidence ledger.</td></tr>
                <tr><td>AT-005</td><td>Prohibited Action Control</td><td>Agent must be prevented from actions outside approved boundary.</td><td>Prohibited action list and block evidence.</td></tr>
                <tr><td>AT-006</td><td>Risk Passport Control</td><td>Agent risk, purpose, data, tools, systems, and escalation rules must be documented.</td><td>Agent Risk Passport™.</td></tr>
                <tr><td>AT-007</td><td>Time-of-Action Evidence Control</td><td>Evidence must be captured when action happens, not reconstructed later.</td><td>Timestamped action evidence.</td></tr>
                <tr><td>AT-008</td><td>Escalation and Override Control</td><td>Humans must be able to intervene, override, stop, or escalate.</td><td>Escalation route and stop-control evidence.</td></tr>
                <tr><td>AT-009</td><td>Rollback Control</td><td>Agents that trigger change must have recovery and rollback path.</td><td>Rollback owner, prior state, verification evidence.</td></tr>
                <tr><td>AT-010</td><td>Audit Replay Control</td><td>Agent action must be explainable after execution.</td><td>Replay package: input, action, owner, tool, evidence, outcome.</td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Control Library",
        "Control library for AI agent identity, authority, evidence, accountability, rollback, and audit replay.",
        body
    )


@app.route("/agenttrust/operational-matrix")
@app.route("/agenttrust/action-matrix")
def agenttrust_operational_matrix():
    body = """
    <section class="section">
        <h2>AgentTrust™ Operational Action Matrix</h2>
        <p>
            This matrix separates what an AI agent may read, recommend, draft, create, update, trigger, approve, or never do.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Action Type</th>
                    <th>Example</th>
                    <th>AI Agent Permission</th>
                    <th>Required Governance</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Read</td><td>Retrieve approved CMDB or policy data.</td><td><span class="badge green">Allowed if scoped</span></td><td>Data boundary and access log.</td></tr>
                <tr><td>Summarize</td><td>Summarize ServiceNow tickets, risks, or evidence gaps.</td><td><span class="badge green">Allowed if sourced</span></td><td>Source traceability and evidence reference.</td></tr>
                <tr><td>Recommend</td><td>Recommend CI owner, risk tier, or readiness status.</td><td><span class="badge yellow">Human review required</span></td><td>Evidence sufficiency and reviewer.</td></tr>
                <tr><td>Draft</td><td>Draft change text, exception notes, or readiness summary.</td><td><span class="badge yellow">Human approval required</span></td><td>Approver and submission evidence.</td></tr>
                <tr><td>Create</td><td>Create ticket, task, CI candidate, or review item.</td><td><span class="badge orange">Restricted</span></td><td>Workflow authority and owner.</td></tr>
                <tr><td>Update</td><td>Update CI status, ownership, risk, access, or validation field.</td><td><span class="badge red">High control</span></td><td>Approval, audit log, rollback path.</td></tr>
                <tr><td>Trigger</td><td>Trigger workflow, access request, change route, or escalation.</td><td><span class="badge red">High control</span></td><td>Authority gate, tool-call log, stop-control.</td></tr>
                <tr><td>Approve</td><td>Approve change, access, validation, QA, release, or regulated decision.</td><td><span class="badge red">Normally prohibited</span></td><td>Human accountable approval required.</td></tr>
                <tr><td>Regulated Execution</td><td>Influence batch, QC, release, deviation, inspection claim, or GMP decision.</td><td><span class="badge red">Human-governed only</span></td><td>QA, validation, risk, human authorization, full evidence package.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Operating Principle</h2>
        <div class="answer">
            AgentTrust™ does not ask only whether an AI agent is intelligent. It asks whether the agent is
            <strong>identified, bounded, authorized, evidenced, accountable, reversible, and defensible</strong>.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Operational Matrix",
        "Action permission matrix for AI agent reading, recommending, drafting, creating, updating, triggering, approving, and regulated execution.",
        body
    )

# ============================================================
# END AGENTTRUST_COMMAND_CENTER_V1_ACTIVE
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

print("AgentTrust Command Center installed.")
print(f"Inserted before: {target_found}")
