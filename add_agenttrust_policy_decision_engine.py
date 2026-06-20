from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_POLICY_DECISION_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust Policy Decision Engine already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base module not found. Install AgentTrust module first.")

nav_old = '<a href="/agenttrust/data-model" class="secondary">Data Model</a>'
nav_new = '''<a href="/agenttrust/data-model" class="secondary">Data Model</a>
                    <a href="/agenttrust/policy-decision-engine" class="secondary">Decision Engine</a>
                    <a href="/agenttrust/action-decision-simulator" class="dark">Simulator</a>
                    <a href="/agenttrust/decision-rules-library" class="dark">Rules</a>
                    <a href="/agenttrust/control-decision-tree" class="dark">Decision Tree</a>'''

if nav_old in text and "/agenttrust/policy-decision-engine" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# AGENTTRUST_POLICY_DECISION_ENGINE_V1_ACTIVE
# AgentTrust™ Policy-as-Code Decision Engine, Action Simulator,
# Decision Rules Library, Control Decision Tree, Escalation Tree,
# Policy Test Cases, and JSON Decision API
# ============================================================

AGENTTRUST_POLICY_RULES = [
    {
        "rule_id": "AT-RULE-001",
        "rule": "No owner, no operation.",
        "condition": "Agent has no accountable business or technical owner.",
        "decision": "Block",
        "reason": "AI agent cannot be trusted if no human remains accountable."
    },
    {
        "rule_id": "AT-RULE-002",
        "rule": "No boundary, no execution.",
        "condition": "Approved systems, tools, APIs, data, or workflow boundary is undefined.",
        "decision": "Restrict / Block",
        "reason": "Agent may act outside approved operational scope."
    },
    {
        "rule_id": "AT-RULE-003",
        "rule": "No authority, no action.",
        "condition": "Requested action is not explicitly permitted or human-gated.",
        "decision": "Block",
        "reason": "Agent cannot execute without pre-action authority."
    },
    {
        "rule_id": "AT-RULE-004",
        "rule": "Missing evidence reduces trust.",
        "condition": "Tool-call, input, output, owner, timestamp, or outcome evidence is missing.",
        "decision": "Restrict",
        "reason": "Action cannot be reliably replayed or defended."
    },
    {
        "rule_id": "AT-RULE-005",
        "rule": "Approval actions are prohibited by default.",
        "condition": "Agent attempts to approve access, change, validation, release, deviation, or quality decision.",
        "decision": "Block",
        "reason": "AI must not become a hidden approver."
    },
    {
        "rule_id": "AT-RULE-006",
        "rule": "Privileged access requires cyber review.",
        "condition": "Agent influences CyberArk, PSM, admin access, privileged action, or entitlement workflow.",
        "decision": "Escalate",
        "reason": "Privileged or access-impacting AI action requires cybersecurity ownership."
    },
    {
        "rule_id": "AT-RULE-007",
        "rule": "GxP impact requires QA / validation review.",
        "condition": "Agent touches GMP, QC, validation, batch, release, deviation, CAPA, or inspection evidence.",
        "decision": "Human-Governed Only",
        "reason": "Regulated operations require human accountability and QA review."
    },
    {
        "rule_id": "AT-RULE-008",
        "rule": "No rollback, no high-impact execution.",
        "condition": "Agent can update, trigger, create, or execute high-impact workflow without rollback route.",
        "decision": "Block / Human-Gate",
        "reason": "Unsafe execution must be reversible or recoverable where required."
    }
]


def agenttrust_policy_eval(action, owner, boundary, authority, evidence, gxp, privileged, rollback):
    action = (action or "").lower()
    owner = (owner or "").lower()
    boundary = (boundary or "").lower()
    authority = (authority or "").lower()
    evidence = (evidence or "").lower()
    gxp = (gxp or "").lower()
    privileged = (privileged or "").lower()
    rollback = (rollback or "").lower()

    reasons = []
    required_owner = "Business / technical owner"
    decision = "Execute Within Approved Boundary"
    badge = "green"
    trust_status = "Operationally Trusted"

    if owner != "yes":
        return {
            "decision": "Block",
            "badge": "red",
            "trust_status": "Not Trusted",
            "required_owner": "Business owner and technical owner",
            "reason": "No accountable human owner is assigned. AgentTrust™ blocks operational reliance."
        }

    if boundary != "yes":
        return {
            "decision": "Block",
            "badge": "red",
            "trust_status": "Not Trusted",
            "required_owner": "System owner / CMDB owner",
            "reason": "The agent boundary is not defined. Approved systems, data, tools, and workflows must be documented first."
        }

    if authority != "yes":
        return {
            "decision": "Block",
            "badge": "red",
            "trust_status": "Not Trusted",
            "required_owner": "Process owner / risk owner",
            "reason": "No pre-action authority exists for this requested action."
        }

    if action in ["approve", "release", "deviation", "validation_approval", "access_approval"]:
        return {
            "decision": "Block",
            "badge": "red",
            "trust_status": "Prohibited",
            "required_owner": "Human approver / QA / access owner",
            "reason": "Approval-type actions are prohibited by default. AI must not approve access, change, release, validation, deviation, or quality decisions."
        }

    if gxp == "yes":
        return {
            "decision": "Human-Governed Only",
            "badge": "red",
            "trust_status": "Regulated Critical",
            "required_owner": "QA / validation owner",
            "reason": "The agent touches GxP, QA, validation, QC, release, deviation, batch, or inspection evidence. QA / validation review is required."
        }

    if privileged == "yes":
        return {
            "decision": "Escalate to Cybersecurity",
            "badge": "red",
            "trust_status": "High Cyber Control",
            "required_owner": "Cybersecurity / CyberArk owner",
            "reason": "The action affects access, CyberArk, PSM, privileged workflow, admin activity, or entitlement routing."
        }

    if evidence != "yes":
        reasons.append("Evidence capture is incomplete. Agent should be restricted to recommendation or draft mode.")
        decision = "Restrict to Recommendation / Draft"
        badge = "orange"
        trust_status = "Restricted"
        required_owner = "Audit / platform owner"

    if action in ["create", "update", "trigger"]:
        if rollback != "yes":
            return {
                "decision": "Human-Gate / Block Execution",
                "badge": "red",
                "trust_status": "Execution Not Ready",
                "required_owner": "Process owner / technical owner",
                "reason": "The action can create, update, or trigger workflow, but rollback or recovery path is missing."
            }

        if evidence == "yes":
            return {
                "decision": "Human-Gated Execution",
                "badge": "yellow",
                "trust_status": "Human-Gated Trusted",
                "required_owner": "Process owner / technical owner",
                "reason": "The action has owner, boundary, authority, evidence, and rollback, but create/update/trigger actions require human approval."
            }

    if action in ["read", "summarize"] and evidence == "yes":
        return {
            "decision": "Execute Within Approved Boundary",
            "badge": "green",
            "trust_status": "Operationally Trusted",
            "required_owner": "Business / technical owner",
            "reason": "Read or summarize action is within approved boundary, owner exists, authority is present, and evidence is captured."
        }

    if action in ["recommend", "draft"]:
        return {
            "decision": "Human-Gated Trusted",
            "badge": "yellow",
            "trust_status": "Human-Gated Trusted",
            "required_owner": "Process owner / reviewer",
            "reason": "Agent may recommend or draft, but final operational reliance requires human review."
        }

    if not reasons:
        reasons.append("Controls are present, but action should remain inside approved boundary and continuous monitoring.")

    return {
        "decision": decision,
        "badge": badge,
        "trust_status": trust_status,
        "required_owner": required_owner,
        "reason": " ".join(reasons)
    }


def agenttrust_policy_rule_rows():
    rows = ""

    for item in AGENTTRUST_POLICY_RULES:
        rows += f"""
        <tr>
            <td><strong>{item["rule_id"]}</strong></td>
            <td>{item["rule"]}</td>
            <td>{item["condition"]}</td>
            <td><span class="badge blue">{item["decision"]}</span></td>
            <td>{item["reason"]}</td>
        </tr>
        """

    return rows


@app.route("/agenttrust/policy-decision-engine")
@app.route("/agenttrust/policy-as-code")
@app.route("/agenttrust/decision-engine")
def agenttrust_policy_decision_engine():
    body = """
    <section class="kpis">
        <div class="metric"><div class="label">Decision Engine</div><div class="value" style="color:var(--green);">Active</div><div class="note">Policy logic converts checks into trust decisions.</div></div>
        <div class="metric"><div class="label">Authority</div><div class="value" style="color:var(--yellow);">Pre-Action</div><div class="note">No authority means block.</div></div>
        <div class="metric"><div class="label">Evidence</div><div class="value" style="color:var(--blue);">Required</div><div class="note">Weak evidence means restrict.</div></div>
        <div class="metric"><div class="label">GxP</div><div class="value" style="color:var(--red);">QA Routed</div><div class="note">Regulated impact requires human governance.</div></div>
        <div class="metric"><div class="label">CyberArk</div><div class="value" style="color:var(--orange);">Cyber Routed</div><div class="note">Privileged impact escalates to cyber owner.</div></div>
        <div class="metric"><div class="label">Output</div><div class="value" style="color:var(--purple);">Decision</div><div class="note">Execute, human-gate, restrict, escalate, block, or quarantine.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Policy-as-Code Decision Engine</h2>
        <div class="answer">
            <strong>Purpose:</strong> convert AgentTrust™ governance controls into executable decision logic.
            The engine determines whether an AI agent action can execute, must be human-gated, should be restricted,
            must be escalated, should be blocked, or must be quarantined.
        </div>

        <div class="grid">
            <div class="card"><span class="badge green">Simulator</span><h3>Action Decision Simulator</h3><p>Test AI agent action scenarios and receive an AgentTrust™ decision.</p><a href="/agenttrust/action-decision-simulator">Open Simulator</a></div>
            <div class="card"><span class="badge blue">Rules</span><h3>Decision Rules Library</h3><p>Policy rules used to classify action requests.</p><a href="/agenttrust/decision-rules-library">Open Rules</a></div>
            <div class="card"><span class="badge yellow">Tree</span><h3>Control Decision Tree</h3><p>Decision flow from identity to authority, evidence, GxP, cyber, and rollback.</p><a href="/agenttrust/control-decision-tree">Open Tree</a></div>
            <div class="card"><span class="badge red">Escalation</span><h3>Escalation Decision Tree</h3><p>Routes unsafe or high-impact actions to the correct owner.</p><a href="/agenttrust/escalation-decision-tree">Open Escalation</a></div>
            <div class="card"><span class="badge purple">JSON</span><h3>Decision JSON API</h3><p>Returns a machine-readable policy decision.</p><a href="/agenttrust/decision-engine-json">Open JSON</a></div>
            <div class="card"><span class="badge orange">Tests</span><h3>Policy Test Cases</h3><p>Shows sample decisions for common agent scenarios.</p><a href="/agenttrust/policy-test-cases">Open Tests</a></div>
        </div>
    </section>

    <section class="section">
        <h2>Decision Engine Rule</h2>
        <div class="answer">
            AgentTrust™ policy-as-code does not replace human governance. It makes human governance visible, consistent,
            measurable, and enforceable before AI agents are trusted to act.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Policy Decision Engine",
        "Policy-as-code engine for AI agent action decisions, authority checks, evidence checks, GxP routing, cyber escalation, and runtime trust outcomes.",
        body
    )


@app.route("/agenttrust/action-decision-simulator", methods=["GET", "POST"])
@app.route("/agenttrust/agent-action-simulator", methods=["GET", "POST"])
@app.route("/agenttrust/policy-simulator", methods=["GET", "POST"])
def agenttrust_action_decision_simulator():
    from flask import request

    action = request.form.get("action", "recommend")
    owner = request.form.get("owner", "yes")
    boundary = request.form.get("boundary", "yes")
    authority = request.form.get("authority", "yes")
    evidence = request.form.get("evidence", "yes")
    gxp = request.form.get("gxp", "no")
    privileged = request.form.get("privileged", "no")
    rollback = request.form.get("rollback", "yes")

    result = agenttrust_policy_eval(action, owner, boundary, authority, evidence, gxp, privileged, rollback)

    def selected(value, expected):
        return "selected" if value == expected else ""

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Decision</div><div class="value" style="color:var(--yellow);">{result["decision"]}</div><div class="note">{result["trust_status"]}</div></div>
        <div class="metric"><div class="label">Required Owner</div><div class="value" style="color:var(--blue);">Mapped</div><div class="note">{result["required_owner"]}</div></div>
        <div class="metric"><div class="label">Decision Class</div><div class="value" style="color:var(--purple);">{result["trust_status"]}</div><div class="note">Generated by AgentTrust™ policy logic.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Action Decision Simulator</h2>
        <p>
            Select the proposed AI agent action and control conditions. The simulator returns the governance decision.
        </p>

        <form method="POST" action="/agenttrust/action-decision-simulator">
            <table>
                <tbody>
                    <tr>
                        <td><strong>Requested Action</strong></td>
                        <td>
                            <select name="action" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;">
                                <option value="read" {selected(action, "read")}>Read</option>
                                <option value="summarize" {selected(action, "summarize")}>Summarize</option>
                                <option value="recommend" {selected(action, "recommend")}>Recommend</option>
                                <option value="draft" {selected(action, "draft")}>Draft</option>
                                <option value="create" {selected(action, "create")}>Create</option>
                                <option value="update" {selected(action, "update")}>Update</option>
                                <option value="trigger" {selected(action, "trigger")}>Trigger Workflow</option>
                                <option value="approve" {selected(action, "approve")}>Approve</option>
                                <option value="access_approval" {selected(action, "access_approval")}>Access Approval</option>
                                <option value="validation_approval" {selected(action, "validation_approval")}>Validation Approval</option>
                                <option value="release" {selected(action, "release")}>Batch / Release Decision</option>
                                <option value="deviation" {selected(action, "deviation")}>Deviation / CAPA Decision</option>
                            </select>
                        </td>
                    </tr>

                    <tr><td><strong>Owner Assigned?</strong></td><td><select name="owner" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(owner, "yes")}>Yes</option><option value="no" {selected(owner, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Boundary Defined?</strong></td><td><select name="boundary" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(boundary, "yes")}>Yes</option><option value="no" {selected(boundary, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Authority Confirmed?</strong></td><td><select name="authority" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(authority, "yes")}>Yes</option><option value="no" {selected(authority, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Evidence Capture Ready?</strong></td><td><select name="evidence" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(evidence, "yes")}>Yes</option><option value="no" {selected(evidence, "no")}>No</option></select></td></tr>
                    <tr><td><strong>GxP / QA / Validation Impact?</strong></td><td><select name="gxp" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="no" {selected(gxp, "no")}>No</option><option value="yes" {selected(gxp, "yes")}>Yes</option></select></td></tr>
                    <tr><td><strong>CyberArk / Privileged Access Impact?</strong></td><td><select name="privileged" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="no" {selected(privileged, "no")}>No</option><option value="yes" {selected(privileged, "yes")}>Yes</option></select></td></tr>
                    <tr><td><strong>Rollback / Recovery Path Defined?</strong></td><td><select name="rollback" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(rollback, "yes")}>Yes</option><option value="no" {selected(rollback, "no")}>No</option></select></td></tr>
                </tbody>
            </table>

            <button type="submit" style="margin-top:16px;padding:12px 18px;border-radius:12px;border:0;background:#2563eb;color:white;font-weight:800;">Run Decision Engine</button>
        </form>
    </section>

    <section class="section">
        <h2>Decision Result</h2>
        <div class="answer">
            <strong>Decision:</strong> <span class="badge {result["badge"]}">{result["decision"]}</span><br>
            <strong>Trust Status:</strong> {result["trust_status"]}<br>
            <strong>Required Owner:</strong> {result["required_owner"]}<br>
            <strong>Reason:</strong> {result["reason"]}
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Action Decision Simulator",
        "Interactive simulator for AI agent action governance decisions based on ownership, boundary, authority, evidence, GxP impact, privileged access, and rollback.",
        body
    )


@app.route("/agenttrust/decision-rules-library")
@app.route("/agenttrust/policy-rules-library")
@app.route("/agenttrust/rules-library")
def agenttrust_decision_rules_library():
    rows = agenttrust_policy_rule_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Decision Rules Library</h2>
        <p>
            These are the core rules used by the Policy-as-Code Decision Engine.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Rule ID</th>
                    <th>Rule</th>
                    <th>Condition</th>
                    <th>Decision</th>
                    <th>Reason</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Rules Principle</h2>
        <div class="answer">
            AgentTrust™ rules make AI agent governance consistent. The same action should not be trusted in one workflow
            and ignored in another when the authority, evidence, owner, cyber, or GxP risk is the same.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Decision Rules Library",
        "Policy rule library for AI agent action decisions, ownership gaps, authority gaps, evidence gaps, cyber escalation, GxP routing, and rollback controls.",
        body
    )


@app.route("/agenttrust/control-decision-tree")
@app.route("/agenttrust/decision-tree")
@app.route("/agenttrust/action-control-tree")
def agenttrust_control_decision_tree():
    body = """
    <section class="section">
        <h2>AgentTrust™ Control Decision Tree</h2>
        <p>
            The decision tree shows the order in which AgentTrust™ evaluates AI agent action readiness.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Decision Step</th>
                    <th>Question</th>
                    <th>If Yes</th>
                    <th>If No</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>1. Agent Identity</td><td>Is the AI agent registered?</td><td>Continue to owner check.</td><td><span class="badge red">Block</span></td></tr>
                <tr><td>2. Ownership</td><td>Is there an accountable human owner?</td><td>Continue to boundary check.</td><td><span class="badge red">Block</span></td></tr>
                <tr><td>3. Boundary</td><td>Are approved systems, tools, data, and workflows defined?</td><td>Continue to authority check.</td><td><span class="badge red">Block</span></td></tr>
                <tr><td>4. Authority</td><td>Is the requested action authorized?</td><td>Continue to prohibited action check.</td><td><span class="badge red">Block</span></td></tr>
                <tr><td>5. Prohibited Action</td><td>Is the action prohibited by default?</td><td><span class="badge red">Block</span></td><td>Continue to evidence check.</td></tr>
                <tr><td>6. Evidence</td><td>Can action evidence be captured at the time of action?</td><td>Continue to impact check.</td><td><span class="badge orange">Restrict</span></td></tr>
                <tr><td>7. GxP Impact</td><td>Does the action touch GMP, QA, validation, release, or inspection evidence?</td><td><span class="badge red">Human-governed only</span></td><td>Continue to cyber check.</td></tr>
                <tr><td>8. Cyber / Privileged Impact</td><td>Does the action touch CyberArk, PSM, admin access, or entitlement routing?</td><td><span class="badge red">Escalate to cyber owner</span></td><td>Continue to rollback check.</td></tr>
                <tr><td>9. Rollback</td><td>Can high-impact execution be stopped or recovered?</td><td><span class="badge yellow">Human-gate or execute within boundary</span></td><td><span class="badge red">Block high-impact execution</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Decision Tree Rule</h2>
        <div class="answer">
            AgentTrust™ checks the simplest trust blockers first: identity, owner, boundary, and authority.
            If those fail, advanced AI capability does not matter because operational trust is already broken.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Control Decision Tree",
        "Decision tree for AI agent identity, ownership, boundary, authority, prohibited action, evidence, GxP, cyber, and rollback controls.",
        body
    )


@app.route("/agenttrust/escalation-decision-tree")
@app.route("/agenttrust/escalation-tree")
@app.route("/agenttrust/policy-escalation-tree")
def agenttrust_escalation_decision_tree():
    body = """
    <section class="section">
        <h2>AgentTrust™ Escalation Decision Tree</h2>
        <p>
            This tree routes AI agent issues to the correct accountable owner.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Issue Detected</th>
                    <th>Escalate To</th>
                    <th>Reason</th>
                    <th>Temporary Agent Status</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Owner missing.</td><td>Business process owner / governance owner.</td><td>No human accountability.</td><td><span class="badge red">Blocked</span></td></tr>
                <tr><td>Technical support missing.</td><td>Technical owner / platform owner.</td><td>No support or lifecycle owner.</td><td><span class="badge red">Blocked</span></td></tr>
                <tr><td>Boundary unclear.</td><td>System owner / CMDB owner.</td><td>Operating scope is unknown.</td><td><span class="badge orange">Restricted</span></td></tr>
                <tr><td>Authority unclear.</td><td>Process owner / risk owner.</td><td>Action rights are not approved.</td><td><span class="badge red">Blocked</span></td></tr>
                <tr><td>Evidence missing.</td><td>Audit owner / platform owner.</td><td>Action cannot be replayed.</td><td><span class="badge orange">Recommendation only</span></td></tr>
                <tr><td>Access or privileged impact.</td><td>Cybersecurity / CyberArk owner.</td><td>Privilege or entitlement risk.</td><td><span class="badge red">Escalated</span></td></tr>
                <tr><td>GxP / QA / validation impact.</td><td>QA / validation owner.</td><td>Regulated evidence or quality risk.</td><td><span class="badge red">Human-governed only</span></td></tr>
                <tr><td>Rollback missing.</td><td>Technical owner / process owner.</td><td>Unsafe action may not be recoverable.</td><td><span class="badge red">Block execution</span></td></tr>
                <tr><td>Repeated unsafe behavior.</td><td>Governance board / risk owner.</td><td>Trust degradation or drift.</td><td><span class="badge red">Quarantine</span></td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Escalation Decision Tree",
        "Escalation decision tree for AI agent ownership gaps, boundary gaps, authority gaps, evidence gaps, cyber impact, GxP impact, rollback gaps, and quarantine.",
        body
    )


@app.route("/agenttrust/policy-test-cases")
@app.route("/agenttrust/decision-test-cases")
@app.route("/agenttrust/action-test-cases")
def agenttrust_policy_test_cases():
    test_cases = [
        ("Read approved CMDB record", "read", "yes", "yes", "yes", "yes", "no", "no", "yes"),
        ("Recommend CI owner", "recommend", "yes", "yes", "yes", "yes", "no", "no", "yes"),
        ("Update CI owner field", "update", "yes", "yes", "yes", "yes", "no", "no", "yes"),
        ("Update CI owner field without rollback", "update", "yes", "yes", "yes", "yes", "no", "no", "no"),
        ("Approve access request", "access_approval", "yes", "yes", "yes", "yes", "no", "yes", "yes"),
        ("Summarize validation evidence", "summarize", "yes", "yes", "yes", "yes", "yes", "no", "yes"),
        ("Agent without owner", "recommend", "no", "yes", "yes", "yes", "no", "no", "yes"),
        ("Agent with missing evidence", "recommend", "yes", "yes", "yes", "no", "no", "no", "yes")
    ]

    rows = ""

    for name, action, owner, boundary, authority, evidence, gxp, privileged, rollback in test_cases:
        result = agenttrust_policy_eval(action, owner, boundary, authority, evidence, gxp, privileged, rollback)
        rows += f"""
        <tr>
            <td><strong>{name}</strong></td>
            <td>{action}</td>
            <td>{owner}</td>
            <td>{boundary}</td>
            <td>{authority}</td>
            <td>{evidence}</td>
            <td>{gxp}</td>
            <td>{privileged}</td>
            <td>{rollback}</td>
            <td><span class="badge {result["badge"]}">{result["decision"]}</span></td>
        </tr>
        """

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Policy Test Cases</h2>
        <p>
            These test cases show how the policy decision engine handles common AI agent scenarios.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Scenario</th>
                    <th>Action</th>
                    <th>Owner</th>
                    <th>Boundary</th>
                    <th>Authority</th>
                    <th>Evidence</th>
                    <th>GxP</th>
                    <th>Privileged</th>
                    <th>Rollback</th>
                    <th>Decision</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Policy Test Cases",
        "Sample policy test cases showing AgentTrust™ decisions for read, recommend, update, access approval, validation evidence, owner gaps, and evidence gaps.",
        body
    )


@app.route("/agenttrust/decision-engine-json")
@app.route("/agenttrust/policy-decision-json")
@app.route("/agenttrust/action-decision-json")
def agenttrust_decision_engine_json():
    from flask import jsonify, request

    action = request.args.get("action", "recommend")
    owner = request.args.get("owner", "yes")
    boundary = request.args.get("boundary", "yes")
    authority = request.args.get("authority", "yes")
    evidence = request.args.get("evidence", "yes")
    gxp = request.args.get("gxp", "no")
    privileged = request.args.get("privileged", "no")
    rollback = request.args.get("rollback", "yes")

    result = agenttrust_policy_eval(action, owner, boundary, authority, evidence, gxp, privileged, rollback)

    return jsonify({
        "module": "AgentTrust™",
        "engine": "Policy-as-Code Decision Engine",
        "input": {
            "action": action,
            "owner": owner,
            "boundary": boundary,
            "authority": authority,
            "evidence": evidence,
            "gxp": gxp,
            "privileged": privileged,
            "rollback": rollback
        },
        "decision": result
    })

# ============================================================
# END AGENTTRUST_POLICY_DECISION_ENGINE_V1_ACTIVE
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

print("AgentTrust Policy Decision Engine installed.")
print(f"Inserted before: {target_found}")
