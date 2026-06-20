from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_RUNTIME_CONTROL_PLANE_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust Runtime Control Plane already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base module not found. Install AgentTrust module first.")

nav_old = '<a href="/agenttrust/integration-adapter-center" class="secondary">Adapters</a>'
nav_new = '''<a href="/agenttrust/integration-adapter-center" class="secondary">Adapters</a>
                    <a href="/agenttrust/runtime-control-plane" class="secondary">Control Plane</a>
                    <a href="/agenttrust/enforcement-gateway" class="dark">Gateway</a>
                    <a href="/agenttrust/action-preflight-gate" class="dark">Preflight Gate</a>
                    <a href="/agenttrust/trust-token-registry" class="dark">Trust Tokens</a>'''

if nav_old in text and "/agenttrust/runtime-control-plane" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# AGENTTRUST_RUNTIME_CONTROL_PLANE_V1_ACTIVE
# AgentTrust™ Runtime Control Plane, Enforcement Gateway,
# Action Preflight Gate, Trust Token Registry, Action Permit Registry,
# Session Boundary Control, Policy Packet Builder,
# Preflight Simulator, and Control Plane JSON Export
# ============================================================

AGENTTRUST_CONTROL_PLANE_FLOW = [
    {
        "step": "1",
        "stage": "Agent Action Request",
        "purpose": "AI agent requests permission to read, summarize, recommend, draft, create, update, trigger, approve, access, or influence workflow.",
        "required_input": "Agent ID, action type, target system, tool, data source, requester, intended outcome.",
        "output": "Preflight review request."
    },
    {
        "step": "2",
        "stage": "Identity Check",
        "purpose": "Confirm the agent is registered, owned, lifecycle-classified, and operating under a trust contract.",
        "required_input": "Agent Register, Agent Risk Passport™, Trust Contract, Operating License.",
        "output": "Identity pass / fail."
    },
    {
        "step": "3",
        "stage": "Boundary Check",
        "purpose": "Confirm the target system, tool, API, data source, and workflow are inside the approved AgentBOM.",
        "required_input": "AgentBOM, dependency graph, approved systems, tools, APIs, data sources.",
        "output": "Boundary pass / fail."
    },
    {
        "step": "4",
        "stage": "Authority Check",
        "purpose": "Decide whether the requested action is allowed, human-gated, restricted, escalated, blocked, or quarantined.",
        "required_input": "Authority Gate, Policy Decision Engine, Operating License, Contract Obligations.",
        "output": "Authority decision."
    },
    {
        "step": "5",
        "stage": "Cyber / GxP Routing",
        "purpose": "Route privileged, access, CyberArk, PSM, GMP, QA, validation, release, deviation, or inspection impact to required owners.",
        "required_input": "Access context, regulated context, cyber review rule, QA review rule.",
        "output": "Cyber / QA route or no-impact confirmation."
    },
    {
        "step": "6",
        "stage": "Trust Token Issue",
        "purpose": "Issue a time-bound trust token that describes the permitted action, evidence obligations, owner, and expiry.",
        "required_input": "Identity pass, boundary pass, authority decision, owner route, evidence obligations.",
        "output": "Trust Token / Action Permit."
    },
    {
        "step": "7",
        "stage": "Enforcement Gateway",
        "purpose": "Allow, human-gate, restrict, escalate, block, or quarantine the action before system execution.",
        "required_input": "Trust Token, tool request, policy packet, runtime context.",
        "output": "Runtime enforcement decision."
    },
    {
        "step": "8",
        "stage": "Evidence Capture",
        "purpose": "Capture input, source, authority, tool-call, human decision, output, timestamp, and outcome evidence.",
        "required_input": "Action permit, tool-call result, human decision, system outcome.",
        "output": "Evidence package and audit replay record."
    }
]


AGENTTRUST_TRUST_TOKENS = [
    {
        "token_id": "AT-TKN-001",
        "agent": "ServiceNow CMDB Ownership Recommendation Agent™",
        "action": "Recommend CI owner and support group review",
        "license": "Human-Gated License",
        "scope": "Read-only CMDB review and recommendation output",
        "owner": "LCM / CMDB Owner",
        "expiry": "Single action / 24 hours",
        "decision": "Human-Gated Trusted",
        "evidence_obligation": "Source CI, recommendation rationale, reviewer decision, outcome."
    },
    {
        "token_id": "AT-TKN-002",
        "agent": "MyAccess / CyberArk Routing Agent™",
        "action": "Recommend privileged access route",
        "license": "Cyber-Gated License",
        "scope": "Routing recommendation only; no access approval or privileged execution",
        "owner": "Cybersecurity / CyberArk Owner",
        "expiry": "Single action / until cyber review",
        "decision": "Escalate to Cybersecurity",
        "evidence_obligation": "Access context, privileged route, cyber reviewer, decision, outcome."
    },
    {
        "token_id": "AT-TKN-003",
        "agent": "GxP Inspection Evidence Agent™",
        "action": "Prepare inspection evidence summary",
        "license": "QA-Governed License",
        "scope": "Evidence preparation only; no QA conclusion or regulated approval",
        "owner": "QA / Validation Owner",
        "expiry": "Until QA review",
        "decision": "Human-Governed Only",
        "evidence_obligation": "Regulated source, summary, QA reviewer, decision, evidence lineage."
    },
    {
        "token_id": "AT-TKN-004",
        "agent": "Cutover Readiness Summary Agent™",
        "action": "Summarize readiness blockers and rollback gaps",
        "license": "Restricted Advisory License",
        "scope": "Readiness summary only; no go-live approval",
        "owner": "Cutover Owner / QA where applicable",
        "expiry": "Single report cycle",
        "decision": "Restricted Advisory",
        "evidence_obligation": "Source evidence, blocker list, rollback status, human review, final outcome."
    }
]


AGENTTRUST_POLICY_PACKETS = [
    {
        "packet_id": "AT-PKT-001",
        "packet": "ServiceNow CMDB Recommendation Packet",
        "required_controls": "Agent identity, CMDB boundary, read-only tool mode, human reviewer, evidence capture.",
        "blocked_actions": "Production CI update, LCM assignment, lifecycle-state change, access approval.",
        "enforcement": "Human-gate recommendation; block production update without approval."
    },
    {
        "packet_id": "AT-PKT-002",
        "packet": "Privileged Access Routing Packet",
        "required_controls": "Agent identity, access context, cyber owner route, no autonomous approval, privileged-action block.",
        "blocked_actions": "Access approval, entitlement activation, CyberArk session trigger, credential action.",
        "enforcement": "Escalate to cybersecurity and block privileged execution by default."
    },
    {
        "packet_id": "AT-PKT-003",
        "packet": "GxP Evidence Support Packet",
        "required_controls": "QA owner, regulated source lineage, validation owner route, evidence sufficiency check.",
        "blocked_actions": "QA conclusion, validation approval, deviation closure, release decision.",
        "enforcement": "Human-governed only until QA / validation review is complete."
    },
    {
        "packet_id": "AT-PKT-004",
        "packet": "Multi-Agent Handoff Packet",
        "required_controls": "Sending agent ID, receiving agent ID, handoff reason, authority preservation, composite evidence.",
        "blocked_actions": "Delegated approval, hidden workflow trigger, missing handoff evidence.",
        "enforcement": "Block handoff if authority expands or evidence breaks."
    }
]


def agenttrust_control_plane_flow_rows():
    rows = ""

    for item in AGENTTRUST_CONTROL_PLANE_FLOW:
        rows += f"""
        <tr>
            <td><strong>{item["step"]}</strong></td>
            <td><span class="badge blue">{item["stage"]}</span></td>
            <td>{item["purpose"]}</td>
            <td>{item["required_input"]}</td>
            <td>{item["output"]}</td>
        </tr>
        """

    return rows


def agenttrust_trust_token_rows():
    rows = ""

    for item in AGENTTRUST_TRUST_TOKENS:
        badge = "yellow"
        if "Cyber" in item["license"] or "QA" in item["license"]:
            badge = "red"
        elif "Restricted" in item["license"]:
            badge = "orange"

        rows += f"""
        <tr>
            <td><strong>{item["token_id"]}</strong></td>
            <td>{item["agent"]}</td>
            <td>{item["action"]}</td>
            <td><span class="badge {badge}">{item["license"]}</span></td>
            <td>{item["scope"]}</td>
            <td>{item["owner"]}</td>
            <td>{item["expiry"]}</td>
            <td>{item["decision"]}</td>
            <td>{item["evidence_obligation"]}</td>
        </tr>
        """

    return rows


def agenttrust_policy_packet_rows():
    rows = ""

    for item in AGENTTRUST_POLICY_PACKETS:
        rows += f"""
        <tr>
            <td><strong>{item["packet_id"]}</strong></td>
            <td>{item["packet"]}</td>
            <td>{item["required_controls"]}</td>
            <td><span class="badge red">{item["blocked_actions"]}</span></td>
            <td>{item["enforcement"]}</td>
        </tr>
        """

    return rows


def agenttrust_preflight_decision(action, identity, boundary, authority, evidence, cyber, gxp, rollback):
    action = (action or "").lower()
    identity = (identity or "").lower()
    boundary = (boundary or "").lower()
    authority = (authority or "").lower()
    evidence = (evidence or "").lower()
    cyber = (cyber or "").lower()
    gxp = (gxp or "").lower()
    rollback = (rollback or "").lower()

    if identity != "yes":
        return ("Block", "red", "No registered agent identity, trust contract, or accountable owner is confirmed.")
    if boundary != "yes":
        return ("Block", "red", "The requested system, tool, API, data source, or workflow is outside approved boundary.")
    if authority != "yes":
        return ("Block", "red", "No pre-action authority exists for the requested action.")
    if action in ["approve", "access_approval", "validation_approval", "release_decision", "deviation_closure"]:
        return ("Prohibited / Block", "red", "Approval-type action is prohibited by default. A human owner must decide.")
    if cyber == "yes":
        return ("Escalate to Cybersecurity", "red", "Access, CyberArk, PSM, admin, or privileged context requires cyber owner review.")
    if gxp == "yes":
        return ("Human-Governed Only", "red", "GMP, QA, validation, release, deviation, CAPA, or inspection context requires QA / validation review.")
    if action in ["create", "update", "trigger"] and rollback != "yes":
        return ("Block Execution", "red", "High-impact execution requires rollback or recovery route.")
    if evidence != "yes":
        return ("Restrict to Advisory Mode", "orange", "Evidence capture is incomplete. Action must be restricted to recommendation or draft mode.")
    if action in ["create", "update", "trigger"]:
        return ("Human-Gated Execution", "yellow", "Action may proceed only after human approval, evidence capture, and runtime monitoring.")
    if action in ["recommend", "draft"]:
        return ("Human-Gated Trusted", "yellow", "Agent may recommend or draft, but final reliance requires human review.")
    return ("Permit Within Boundary", "green", "Action may proceed within approved boundary with evidence capture and monitoring.")


try:
    AGENTTRUST_EXPECTED_ROUTES.extend([
        "/agenttrust/runtime-control-plane",
        "/agenttrust/enforcement-gateway",
        "/agenttrust/action-preflight-gate",
        "/agenttrust/preflight-gate-simulator",
        "/agenttrust/action-permit-registry",
        "/agenttrust/trust-token-registry",
        "/agenttrust/session-boundary-control",
        "/agenttrust/policy-packet-builder",
        "/agenttrust/runtime-control-plane-json"
    ])
except Exception:
    pass


@app.route("/agenttrust/runtime-control-plane")
@app.route("/agenttrust/control-plane")
@app.route("/agenttrust/agent-control-plane")
def agenttrust_runtime_control_plane():
    rows = agenttrust_control_plane_flow_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Control Plane</div><div class="value" style="color:var(--green);">Active</div><div class="note">Runtime governance flow is defined.</div></div>
        <div class="metric"><div class="label">Preflight Gate</div><div class="value" style="color:var(--blue);">Required</div><div class="note">Actions checked before execution.</div></div>
        <div class="metric"><div class="label">Trust Token</div><div class="value" style="color:var(--yellow);">Issued</div><div class="note">Time-bound action permit.</div></div>
        <div class="metric"><div class="label">Gateway</div><div class="value" style="color:var(--orange);">Enforcing</div><div class="note">Permit, gate, restrict, escalate, block, quarantine.</div></div>
        <div class="metric"><div class="label">Cyber / GxP</div><div class="value" style="color:var(--red);">Routed</div><div class="note">Privileged and regulated impact routed to owners.</div></div>
        <div class="metric"><div class="label">Evidence</div><div class="value" style="color:var(--purple);">Captured</div><div class="note">Every action must be replayable.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Runtime Control Plane</h2>
        <div class="answer">
            <strong>Purpose:</strong> place an enforceable governance control plane between AI agents and enterprise systems.
            Before an AI agent acts, the control plane checks identity, boundary, authority, cyber impact, GxP impact,
            rollback, evidence obligations, and human accountability.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Step</th>
                    <th>Control Stage</th>
                    <th>Purpose</th>
                    <th>Required Input</th>
                    <th>Output</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Control Plane Rule</h2>
        <div class="answer">
            AgentTrust™ should not wait until after the AI agent acts to ask governance questions.
            The control plane asks them before execution and issues a time-bound action permit only when trust conditions are satisfied.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Runtime Control Plane",
        "Runtime control plane for AI agent preflight checks, trust tokens, enforcement gateway, evidence capture, cyber routing, GxP routing, and audit replay.",
        body
    )


@app.route("/agenttrust/enforcement-gateway")
@app.route("/agenttrust/runtime-enforcement-gateway")
@app.route("/agenttrust/agent-enforcement-gateway")
def agenttrust_enforcement_gateway():
    body = """
    <section class="section">
        <h2>AgentTrust™ Enforcement Gateway</h2>
        <p>
            The Enforcement Gateway decides whether an AI agent action is permitted, human-gated, restricted,
            escalated, blocked, quarantined, or retired before the enterprise system is touched.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Gateway Decision</th>
                    <th>When Used</th>
                    <th>Required Evidence</th>
                    <th>Runtime Outcome</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Permit Within Boundary</td><td>Low-risk read or summarize action with identity, boundary, authority, and evidence.</td><td>Agent ID, source, timestamp, outcome.</td><td><span class="badge green">Allow</span></td></tr>
                <tr><td>Human-Gated Trusted</td><td>Recommendation or draft action that needs human review before reliance.</td><td>Reviewer, rationale, source evidence, decision.</td><td><span class="badge yellow">Hold for human review</span></td></tr>
                <tr><td>Restricted Advisory</td><td>Evidence, ownership, or boundary is incomplete but advisory output is still useful.</td><td>Gap record and restriction reason.</td><td><span class="badge orange">No execution</span></td></tr>
                <tr><td>Escalate to Cybersecurity</td><td>Access, CyberArk, PSM, admin, or privileged context detected.</td><td>Cyber owner route and decision.</td><td><span class="badge red">Escalate / block privilege</span></td></tr>
                <tr><td>Human-Governed Only</td><td>GMP, QA, validation, release, deviation, CAPA, or inspection context detected.</td><td>QA / validation owner decision.</td><td><span class="badge red">QA / validation review</span></td></tr>
                <tr><td>Block</td><td>No identity, no owner, no boundary, no authority, prohibited action, or missing rollback.</td><td>Block reason and required remediation.</td><td><span class="badge red">Stop action</span></td></tr>
                <tr><td>Quarantine</td><td>Repeated breach, red-team failure, drift, evidence tampering, or unsafe runtime behavior.</td><td>Quarantine reason, release condition, owner decision.</td><td><span class="badge red">Isolate agent</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Gateway Rule</h2>
        <div class="answer">
            The Enforcement Gateway turns governance from documentation into runtime control.
            It decides what the agent may do before the agent touches the system.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Enforcement Gateway",
        "Runtime enforcement gateway for AI agent permit, human-gate, restrict, escalate, block, quarantine, and retire decisions.",
        body
    )


@app.route("/agenttrust/action-preflight-gate")
@app.route("/agenttrust/preflight-gate")
@app.route("/agenttrust/agent-preflight-gate")
def agenttrust_action_preflight_gate():
    body = """
    <section class="section">
        <h2>AgentTrust™ Action Preflight Gate</h2>
        <p>
            The Action Preflight Gate is the mandatory check before any AI agent action becomes operational.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Preflight Check</th>
                    <th>Question</th>
                    <th>Pass Condition</th>
                    <th>Fail Decision</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent Identity</td><td>Is the agent registered and owned?</td><td>Agent ID, owner, passport, contract.</td><td><span class="badge red">Block</span></td></tr>
                <tr><td>Operating License</td><td>Is the agent licensed for this action type?</td><td>License permits action or human-gated mode.</td><td><span class="badge red">Restrict / block</span></td></tr>
                <tr><td>Boundary</td><td>Is the target system, tool, data, API, and workflow approved?</td><td>AgentBOM contains dependency.</td><td><span class="badge red">Block</span></td></tr>
                <tr><td>Authority</td><td>Is this action permitted before execution?</td><td>Authority decision exists.</td><td><span class="badge red">Block</span></td></tr>
                <tr><td>Cyber Impact</td><td>Does it touch access, CyberArk, PSM, admin, or privilege?</td><td>Cyber owner route exists.</td><td><span class="badge red">Escalate</span></td></tr>
                <tr><td>GxP Impact</td><td>Does it touch GMP, QA, validation, release, deviation, or inspection?</td><td>QA / validation route exists.</td><td><span class="badge red">Human-governed only</span></td></tr>
                <tr><td>Rollback</td><td>Can high-impact execution be recovered?</td><td>Rollback or recovery route exists.</td><td><span class="badge red">Block execution</span></td></tr>
                <tr><td>Evidence</td><td>Can evidence be captured at the time of action?</td><td>Input, source, tool, human, outcome evidence available.</td><td><span class="badge orange">Restrict reliance</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Preflight Rule</h2>
        <div class="answer">
            No AI agent action should move into enterprise workflow unless the preflight gate confirms identity,
            license, boundary, authority, routing, rollback, and evidence readiness.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Action Preflight Gate",
        "Preflight gate for checking AI agent identity, operating license, boundary, authority, cyber impact, GxP impact, rollback, and evidence before execution.",
        body
    )


@app.route("/agenttrust/preflight-gate-simulator", methods=["GET", "POST"])
@app.route("/agenttrust/runtime-decision-simulator", methods=["GET", "POST"])
@app.route("/agenttrust/enforcement-simulator", methods=["GET", "POST"])
def agenttrust_preflight_gate_simulator():
    from flask import request

    action = request.form.get("action", "recommend")
    identity = request.form.get("identity", "yes")
    boundary = request.form.get("boundary", "yes")
    authority = request.form.get("authority", "yes")
    evidence = request.form.get("evidence", "yes")
    cyber = request.form.get("cyber", "no")
    gxp = request.form.get("gxp", "no")
    rollback = request.form.get("rollback", "yes")

    decision, badge, reason = agenttrust_preflight_decision(action, identity, boundary, authority, evidence, cyber, gxp, rollback)

    def selected(value, expected):
        return "selected" if value == expected else ""

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Preflight Gate Simulator</h2>
        <p>
            Simulate a runtime AI agent action before execution. The simulator returns the enforcement decision.
        </p>

        <form method="POST" action="/agenttrust/preflight-gate-simulator">
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
                                <option value="release_decision" {selected(action, "release_decision")}>Release Decision</option>
                                <option value="deviation_closure" {selected(action, "deviation_closure")}>Deviation Closure</option>
                            </select>
                        </td>
                    </tr>

                    <tr><td><strong>Agent Identity / Contract Confirmed?</strong></td><td><select name="identity" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(identity, "yes")}>Yes</option><option value="no" {selected(identity, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Boundary Approved?</strong></td><td><select name="boundary" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(boundary, "yes")}>Yes</option><option value="no" {selected(boundary, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Authority Confirmed?</strong></td><td><select name="authority" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(authority, "yes")}>Yes</option><option value="no" {selected(authority, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Evidence Capture Ready?</strong></td><td><select name="evidence" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(evidence, "yes")}>Yes</option><option value="no" {selected(evidence, "no")}>No</option></select></td></tr>
                    <tr><td><strong>CyberArk / Access / Privileged Impact?</strong></td><td><select name="cyber" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="no" {selected(cyber, "no")}>No</option><option value="yes" {selected(cyber, "yes")}>Yes</option></select></td></tr>
                    <tr><td><strong>GxP / QA / Validation Impact?</strong></td><td><select name="gxp" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="no" {selected(gxp, "no")}>No</option><option value="yes" {selected(gxp, "yes")}>Yes</option></select></td></tr>
                    <tr><td><strong>Rollback / Recovery Ready?</strong></td><td><select name="rollback" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(rollback, "yes")}>Yes</option><option value="no" {selected(rollback, "no")}>No</option></select></td></tr>
                </tbody>
            </table>

            <button type="submit" style="margin-top:16px;padding:12px 18px;border-radius:12px;border:0;background:#2563eb;color:white;font-weight:800;">Run Preflight Gate</button>
        </form>
    </section>

    <section class="section">
        <h2>Runtime Enforcement Decision</h2>
        <div class="answer">
            <strong>Decision:</strong> <span class="badge {badge}">{decision}</span><br>
            <strong>Reason:</strong> {reason}
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Preflight Gate Simulator",
        "Simulator for AI agent runtime preflight decisions across identity, boundary, authority, evidence, cyber impact, GxP impact, and rollback.",
        body
    )


@app.route("/agenttrust/action-permit-registry")
@app.route("/agenttrust/action-permits")
@app.route("/agenttrust/agent-action-permits")
def agenttrust_action_permit_registry():
    rows = agenttrust_trust_token_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Action Permit Registry</h2>
        <p>
            Action permits are time-bound permissions issued by the control plane after preflight checks.
            A permit defines what the agent may do, under what license, with which owner, and what evidence is required.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Permit / Token ID</th>
                    <th>Agent</th>
                    <th>Action</th>
                    <th>License</th>
                    <th>Scope</th>
                    <th>Owner</th>
                    <th>Expiry</th>
                    <th>Decision</th>
                    <th>Evidence Obligation</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Action Permit Rule</h2>
        <div class="answer">
            AgentTrust™ action permits are not permanent permissions.
            They are scoped, time-bound, owner-linked, evidence-backed, and revocable.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Action Permit Registry",
        "Registry of AI agent action permits and trust tokens with license, scope, owner, expiry, decision, and evidence obligations.",
        body
    )


@app.route("/agenttrust/trust-token-registry")
@app.route("/agenttrust/trust-tokens")
@app.route("/agenttrust/agent-trust-tokens")
def agenttrust_trust_token_registry():
    rows = agenttrust_trust_token_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Trust Token Registry</h2>
        <p>
            A Trust Token is the runtime expression of governed permission.
            It carries the action decision, owner, scope, expiry, evidence obligations, and enforcement state.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Token ID</th>
                    <th>Agent</th>
                    <th>Action</th>
                    <th>License</th>
                    <th>Scope</th>
                    <th>Owner</th>
                    <th>Expiry</th>
                    <th>Decision</th>
                    <th>Evidence Obligation</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Trust Token Rule</h2>
        <div class="answer">
            A trust token proves that an AI agent action was checked before execution.
            Without a valid trust token, the action should be blocked, restricted, or human-gated.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Trust Token Registry",
        "Trust token registry for runtime AI agent action permissions, scope, owner, expiry, evidence obligations, and enforcement decisions.",
        body
    )


@app.route("/agenttrust/session-boundary-control")
@app.route("/agenttrust/runtime-session-boundary")
@app.route("/agenttrust/agent-session-boundary")
def agenttrust_session_boundary_control():
    body = """
    <section class="section">
        <h2>AgentTrust™ Session Boundary Control</h2>
        <p>
            Session Boundary Control prevents an AI agent from expanding its scope during a session.
            It checks whether the current prompt, tool, data source, target system, user, and workflow remain inside the approved boundary.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Boundary Element</th>
                    <th>Allowed Condition</th>
                    <th>Drift Signal</th>
                    <th>Control Plane Response</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Prompt Boundary</td><td>Prompt matches approved instruction set.</td><td>Prompt attempts to override guardrail or prohibited action.</td><td><span class="badge red">Block or restrict</span></td></tr>
                <tr><td>Tool Boundary</td><td>Tool is listed in AgentBOM and approved for action type.</td><td>New tool or mode appears.</td><td><span class="badge red">Run tool authority gate</span></td></tr>
                <tr><td>Data Boundary</td><td>Source is approved and traceable.</td><td>Unknown or regulated source appears.</td><td><span class="badge orange">Route to owner</span></td></tr>
                <tr><td>System Boundary</td><td>Target system is approved in Trust Contract and AgentBOM.</td><td>Agent attempts different system or workflow.</td><td><span class="badge red">Block action</span></td></tr>
                <tr><td>Access Boundary</td><td>No access, entitlement, CyberArk, PSM, admin, or privileged impact unless cyber-routed.</td><td>Privileged context detected.</td><td><span class="badge red">Escalate to cyber</span></td></tr>
                <tr><td>GxP Boundary</td><td>No regulated conclusion or QA decision without QA route.</td><td>Validation, QC, release, deviation, CAPA, inspection context appears.</td><td><span class="badge red">Human-governed only</span></td></tr>
                <tr><td>Outcome Boundary</td><td>Outcome remains inside permitted action type.</td><td>Recommendation becomes update, approval, or workflow trigger.</td><td><span class="badge red">Execution firewall block</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Session Boundary Rule</h2>
        <div class="answer">
            AI agent scope can drift during a session.
            AgentTrust™ continuously checks that the action remains inside the approved boundary from request to outcome.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Session Boundary Control",
        "Session boundary control for AI agent prompts, tools, data sources, systems, access routes, GxP context, and outcomes.",
        body
    )


@app.route("/agenttrust/policy-packet-builder")
@app.route("/agenttrust/runtime-policy-packet")
@app.route("/agenttrust/policy-packets")
def agenttrust_policy_packet_builder():
    rows = agenttrust_policy_packet_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Policy Packet Builder</h2>
        <p>
            Policy packets package the controls required for a specific AI agent action class.
            The Enforcement Gateway uses the packet to decide what the agent may do and what must be blocked.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Packet ID</th>
                    <th>Policy Packet</th>
                    <th>Required Controls</th>
                    <th>Blocked Actions</th>
                    <th>Enforcement</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Policy Packet Rule</h2>
        <div class="answer">
            A policy packet makes runtime enforcement repeatable.
            Similar AI agent actions should be governed by the same control pattern across the enterprise.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Policy Packet Builder",
        "Policy packet builder for runtime AI agent enforcement across ServiceNow CMDB, privileged access, GxP evidence, and multi-agent handoff scenarios.",
        body
    )


@app.route("/agenttrust/runtime-control-plane-json")
@app.route("/agenttrust/control-plane-json")
@app.route("/agenttrust/enforcement-gateway-json")
def agenttrust_runtime_control_plane_json():
    from flask import jsonify

    return jsonify({
        "module": "AgentTrust™",
        "capability": "Runtime Control Plane + Enforcement Gateway",
        "primary_question": "Should this AI agent action be permitted before execution?",
        "control_plane_flow": AGENTTRUST_CONTROL_PLANE_FLOW,
        "trust_tokens": AGENTTRUST_TRUST_TOKENS,
        "policy_packets": AGENTTRUST_POLICY_PACKETS,
        "runtime_decisions": [
            "Permit Within Boundary",
            "Human-Gated Trusted",
            "Restricted Advisory",
            "Escalate to Cybersecurity",
            "Human-Governed Only",
            "Block",
            "Quarantine"
        ],
        "default_rule": "No valid identity, boundary, authority, evidence, owner, and routing decision means no operational execution"
    })

# ============================================================
# END AGENTTRUST_RUNTIME_CONTROL_PLANE_V1_ACTIVE
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

print("AgentTrust Runtime Control Plane installed.")
print(f"Inserted before: {target_found}")
