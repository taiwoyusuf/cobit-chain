from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_AGENT_RELEASE_GATE_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust Agent Release Gate already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base module not found. Install AgentTrust module first.")

nav_old = '<a href="/agenttrust/runtime-control-plane" class="secondary">Control Plane</a>'
nav_new = '''<a href="/agenttrust/runtime-control-plane" class="secondary">Control Plane</a>
                    <a href="/agenttrust/agent-release-gate" class="secondary">Release Gate</a>
                    <a href="/agenttrust/production-promotion-control" class="dark">Production Control</a>
                    <a href="/agenttrust/release-readiness-board" class="dark">Readiness Board</a>
                    <a href="/agenttrust/release-gate-simulator" class="dark">Release Simulator</a>'''

if nav_old in text and "/agenttrust/agent-release-gate" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# AGENTTRUST_AGENT_RELEASE_GATE_V1_ACTIVE
# AgentTrust™ Agent Release Gate, Production Promotion Control,
# Release Readiness Board, Deployment Certification Matrix,
# Post-Release Verification, Rollback and Retirement Plan,
# Release Gate Simulator, and Release Gate JSON Export
# ============================================================

AGENTTRUST_RELEASE_GATES = [
    {
        "gate_id": "AT-REL-001",
        "gate": "Intake Complete",
        "question": "Has the AI agent been formally captured through intake?",
        "required_evidence": "Agent intake form, purpose, owner, intended actions, systems, data sources.",
        "owner": "Governance Owner",
        "release_decision": "Block release if incomplete."
    },
    {
        "gate_id": "AT-REL-002",
        "gate": "Agent Registered",
        "question": "Is the AI agent known, owned, and lifecycle-classified?",
        "required_evidence": "Agent Register, Agent Risk Passport™, lifecycle status, risk tier.",
        "owner": "Agent Lifecycle Owner",
        "release_decision": "Block release if owner or lifecycle state is missing."
    },
    {
        "gate_id": "AT-REL-003",
        "gate": "Trust Contract Active",
        "question": "Does the agent have a valid operating license and trust contract?",
        "required_evidence": "Trust Contract, permitted scope, prohibited scope, revocation triggers.",
        "owner": "Risk Owner",
        "release_decision": "Restrict release if operating license is conditional or missing."
    },
    {
        "gate_id": "AT-REL-004",
        "gate": "AgentBOM Approved",
        "question": "Are model, prompt, tools, APIs, data, workflows, owners, and evidence dependencies known?",
        "required_evidence": "AgentBOM, Dependency Graph, dependency drift watch.",
        "owner": "Agent Lifecycle Owner",
        "release_decision": "Human-gate release if critical dependency is unknown."
    },
    {
        "gate_id": "AT-REL-005",
        "gate": "Authority Model Approved",
        "question": "Are permitted, human-gated, restricted, and prohibited actions defined?",
        "required_evidence": "Authority Gate, Policy Decision Engine, Operating License, Action Decision Matrix.",
        "owner": "Process Owner / Risk Owner",
        "release_decision": "Block release if create, update, trigger, approve, access, or regulated actions lack authority."
    },
    {
        "gate_id": "AT-REL-006",
        "gate": "Human Oversight Ready",
        "question": "Are human reviewers, approvers, escalation owners, and risk owners mapped?",
        "required_evidence": "Human Oversight Workbench, Signoff Matrix, Approval Queue, Risk Acceptance Register.",
        "owner": "Required Human Owner",
        "release_decision": "Human-gate release if review route is incomplete."
    },
    {
        "gate_id": "AT-REL-007",
        "gate": "Cyber / Access Impact Reviewed",
        "question": "Does the agent touch MyAccess, CyberArk, PSM, admin, entitlement, or privileged workflow?",
        "required_evidence": "MyAccess / CyberArk adapter, cyber routing evidence, privileged impact decision.",
        "owner": "Cybersecurity / CyberArk Owner",
        "release_decision": "Block privileged release unless cyber owner approves."
    },
    {
        "gate_id": "AT-REL-008",
        "gate": "GxP / QA Impact Reviewed",
        "question": "Does the agent touch GMP, QA, validation, QC, release, deviation, CAPA, or inspection evidence?",
        "required_evidence": "GxP screening, QA review, validation owner decision, regulated impact route.",
        "owner": "QA / Validation Owner",
        "release_decision": "Block regulated reliance unless QA / validation review is complete."
    },
    {
        "gate_id": "AT-REL-009",
        "gate": "Red-Team Passed",
        "question": "Has the agent been tested against prompt injection, authority bypass, tool abuse, and evidence tampering?",
        "required_evidence": "Red-Team Lab, Failure Mode Library, Red-Team Scorecard, remediation evidence.",
        "owner": "Risk / Security Owner",
        "release_decision": "Restrict or quarantine if unresolved critical failure mode exists."
    },
    {
        "gate_id": "AT-REL-010",
        "gate": "Runtime Control Plane Ready",
        "question": "Will runtime actions pass through preflight gate, trust token, enforcement gateway, and evidence capture?",
        "required_evidence": "Runtime Control Plane, Trust Token Registry, Policy Packet, Enforcement Gateway.",
        "owner": "Platform / Runtime Owner",
        "release_decision": "Block operational execution if runtime enforcement is not ready."
    },
    {
        "gate_id": "AT-REL-011",
        "gate": "Monitoring Ready",
        "question": "Can drift, trust degradation, alerts, exceptions, and breaches be monitored after release?",
        "required_evidence": "Continuous Monitoring Center, Drift Alert Console, Exception Breach Console.",
        "owner": "Control Owner",
        "release_decision": "Do not release without post-release monitoring."
    },
    {
        "gate_id": "AT-REL-012",
        "gate": "Audit Dossier Ready",
        "question": "Can leadership defend why the agent was released?",
        "required_evidence": "Assurance Case, Audit Dossier, Decision Replay, Evidence Lineage, Release Decision.",
        "owner": "Governance / Audit Owner",
        "release_decision": "Do not promote without release dossier."
    }
]


AGENTTRUST_PROMOTION_STATES = [
    {
        "state": "Concept",
        "description": "Idea or use case is being explored.",
        "allowed_activity": "Discussion, intake, concept note.",
        "blocked_activity": "No enterprise data, no operational action, no production workflow."
    },
    {
        "state": "Sandbox",
        "description": "Agent is tested with synthetic or controlled data.",
        "allowed_activity": "Prototype, prompt test, model behavior test.",
        "blocked_activity": "No production record interaction."
    },
    {
        "state": "Pilot",
        "description": "Agent is tested with controlled human oversight.",
        "allowed_activity": "Read-only or recommendation-only use with evidence capture.",
        "blocked_activity": "No autonomous create, update, trigger, approval, access, or regulated conclusion."
    },
    {
        "state": "Human-Gated Production",
        "description": "Agent supports operational workflow but requires human approval before reliance.",
        "allowed_activity": "Summarize, recommend, draft, prepare evidence.",
        "blocked_activity": "No hidden approval or unauthorized execution."
    },
    {
        "state": "Restricted Execution",
        "description": "Agent may execute limited actions only inside approved boundary and runtime control plane.",
        "allowed_activity": "Scoped create or trigger with trust token, rollback, evidence, and monitoring.",
        "blocked_activity": "No approval, privileged action, or regulated conclusion."
    },
    {
        "state": "Quarantine",
        "description": "Agent is isolated because trust conditions failed.",
        "allowed_activity": "Investigation, remediation, evidence review.",
        "blocked_activity": "No operational reliance."
    },
    {
        "state": "Retired",
        "description": "Agent is removed from operational use.",
        "allowed_activity": "Archive evidence and close lifecycle record.",
        "blocked_activity": "No new action or workflow use."
    }
]


AGENTTRUST_RELEASE_PACKETS = [
    {
        "packet_id": "AT-RPK-001",
        "packet": "ServiceNow CMDB Recommendation Agent Release Packet",
        "release_type": "Human-Gated Production",
        "required_signoffs": "CMDB Owner, LCM Owner, ServiceNow Platform Owner, Governance Owner.",
        "required_evidence": "Agent Passport, AgentBOM, Trust Contract, authority matrix, test evidence, human review route.",
        "go_live_condition": "Recommendation-only; no production CI update without human approval."
    },
    {
        "packet_id": "AT-RPK-002",
        "packet": "MyAccess / CyberArk Routing Agent Release Packet",
        "release_type": "Cyber-Gated Pilot",
        "required_signoffs": "Cybersecurity Owner, Access Owner, CyberArk Owner, Governance Owner.",
        "required_evidence": "Access impact screening, cyber review, prohibited action control, trust token, evidence route.",
        "go_live_condition": "No autonomous access approval, entitlement activation, CyberArk trigger, or privileged execution."
    },
    {
        "packet_id": "AT-RPK-003",
        "packet": "GxP Evidence Support Agent Release Packet",
        "release_type": "QA-Governed Pilot",
        "required_signoffs": "QA Owner, Validation Owner, System Owner, Governance Owner.",
        "required_evidence": "GxP screening, validation review route, source lineage, regulated conclusion block, audit dossier.",
        "go_live_condition": "Evidence preparation only; no QA conclusion, validation approval, or release decision."
    },
    {
        "packet_id": "AT-RPK-004",
        "packet": "Cutover Readiness Summary Agent Release Packet",
        "release_type": "Restricted Advisory",
        "required_signoffs": "Cutover Owner, Technical Owner, QA where applicable, Governance Owner.",
        "required_evidence": "Readiness source map, blocker evidence, rollback evidence, human review route, release memo.",
        "go_live_condition": "Summary may support discussion but cannot approve cutover or go-live."
    }
]


def agenttrust_release_gate_rows():
    rows = ""

    for item in AGENTTRUST_RELEASE_GATES:
        rows += f"""
        <tr>
            <td><strong>{item["gate_id"]}</strong></td>
            <td><span class="badge blue">{item["gate"]}</span></td>
            <td>{item["question"]}</td>
            <td>{item["required_evidence"]}</td>
            <td>{item["owner"]}</td>
            <td>{item["release_decision"]}</td>
        </tr>
        """

    return rows


def agenttrust_promotion_state_rows():
    rows = ""

    for item in AGENTTRUST_PROMOTION_STATES:
        badge = "blue"
        if item["state"] in ["Quarantine", "Retired"]:
            badge = "red"
        elif item["state"] in ["Restricted Execution", "Human-Gated Production"]:
            badge = "yellow"
        elif item["state"] == "Pilot":
            badge = "orange"

        rows += f"""
        <tr>
            <td><span class="badge {badge}">{item["state"]}</span></td>
            <td>{item["description"]}</td>
            <td>{item["allowed_activity"]}</td>
            <td>{item["blocked_activity"]}</td>
        </tr>
        """

    return rows


def agenttrust_release_packet_rows():
    rows = ""

    for item in AGENTTRUST_RELEASE_PACKETS:
        rows += f"""
        <tr>
            <td><strong>{item["packet_id"]}</strong></td>
            <td>{item["packet"]}</td>
            <td><span class="badge yellow">{item["release_type"]}</span></td>
            <td>{item["required_signoffs"]}</td>
            <td>{item["required_evidence"]}</td>
            <td>{item["go_live_condition"]}</td>
        </tr>
        """

    return rows


def agenttrust_release_gate_decision(intake, passport, contract, bom, authority, oversight, cyber, gxp, redteam, runtime, monitoring, dossier):
    controls = {
        "intake": intake,
        "passport": passport,
        "contract": contract,
        "bom": bom,
        "authority": authority,
        "oversight": oversight,
        "cyber": cyber,
        "gxp": gxp,
        "redteam": redteam,
        "runtime": runtime,
        "monitoring": monitoring,
        "dossier": dossier
    }

    complete = sum(1 for value in controls.values() if value == "yes")
    score = int((complete / len(controls)) * 100)

    blockers = []
    if intake != "yes":
        blockers.append("intake incomplete")
    if passport != "yes":
        blockers.append("agent passport missing")
    if contract != "yes":
        blockers.append("trust contract missing")
    if bom != "yes":
        blockers.append("AgentBOM incomplete")
    if authority != "yes":
        blockers.append("authority model missing")
    if oversight != "yes":
        blockers.append("human oversight not ready")
    if runtime != "yes":
        blockers.append("runtime control plane not ready")
    if monitoring != "yes":
        blockers.append("continuous monitoring not ready")
    if dossier != "yes":
        blockers.append("release audit dossier missing")

    if cyber == "no":
        blockers.append("cyber/access review not confirmed")
    if gxp == "no":
        blockers.append("GxP/QA impact review not confirmed")
    if redteam == "no":
        blockers.append("red-team testing not passed")

    if score >= 95 and not blockers:
        return score, "Promote to Human-Gated Production", "green", "Release gate passed with governance, evidence, runtime, monitoring, and dossier controls complete."
    if runtime != "yes" or authority != "yes" or passport != "yes":
        return score, "Block Production Release", "red", "Core release blocker exists: agent passport, authority model, or runtime control plane is missing."
    if cyber == "no" or gxp == "no" or redteam == "no":
        return score, "Restricted Pilot Only", "orange", "Cyber, GxP, or red-team release controls are not fully confirmed. Restrict to pilot or advisory use."
    if score >= 75:
        return score, "Human-Gated Pilot", "yellow", "Agent may proceed only in controlled human-gated pilot with evidence capture and open gap tracking."
    return score, "Do Not Release", "red", "Release readiness is too weak. Close release gate gaps before operational use."


try:
    AGENTTRUST_EXPECTED_ROUTES.extend([
        "/agenttrust/agent-release-gate",
        "/agenttrust/production-promotion-control",
        "/agenttrust/release-readiness-board",
        "/agenttrust/deployment-certification-matrix",
        "/agenttrust/post-release-verification",
        "/agenttrust/rollback-and-retirement-plan",
        "/agenttrust/release-gate-simulator",
        "/agenttrust/release-gate-json"
    ])
except Exception:
    pass


@app.route("/agenttrust/agent-release-gate")
@app.route("/agenttrust/ai-agent-release-gate")
@app.route("/agenttrust/release-gate")
def agenttrust_agent_release_gate():
    rows = agenttrust_release_gate_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Release Gate</div><div class="value" style="color:var(--green);">Defined</div><div class="note">Promotion controls are mapped.</div></div>
        <div class="metric"><div class="label">Gates</div><div class="value" style="color:var(--blue);">12</div><div class="note">Identity, contract, BOM, authority, cyber, GxP, runtime, monitoring, dossier.</div></div>
        <div class="metric"><div class="label">Promotion</div><div class="value" style="color:var(--yellow);">Controlled</div><div class="note">Agents move through governed lifecycle states.</div></div>
        <div class="metric"><div class="label">Production</div><div class="value" style="color:var(--orange);">Human-Gated</div><div class="note">Production release requires signoff and evidence.</div></div>
        <div class="metric"><div class="label">Rollback</div><div class="value" style="color:var(--red);">Required</div><div class="note">Unsafe agent behavior must be reversible or quarantined.</div></div>
        <div class="metric"><div class="label">Dossier</div><div class="value" style="color:var(--purple);">Required</div><div class="note">Release decision must be audit-defensible.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Agent Release Gate</h2>
        <div class="answer">
            <strong>Purpose:</strong> prevent AI agents from moving into operational use before identity, ownership,
            operating license, dependencies, authority, human oversight, cyber routing, GxP routing, red-team testing,
            runtime enforcement, monitoring, and audit dossier controls are ready.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Gate ID</th>
                    <th>Release Gate</th>
                    <th>Release Question</th>
                    <th>Required Evidence</th>
                    <th>Owner</th>
                    <th>Release Decision</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Release Gate Rule</h2>
        <div class="answer">
            An AI agent should not move to production because the demo works.
            It should move only when the release gate proves that the agent is known, owned, bounded, authorized,
            evidenced, human-governed, monitored, controlled, and defensible.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Agent Release Gate",
        "Release gate for AI agent promotion across intake, passport, trust contract, AgentBOM, authority, human oversight, cyber, GxP, red-team, runtime, monitoring, and audit dossier controls.",
        body
    )


@app.route("/agenttrust/production-promotion-control")
@app.route("/agenttrust/agent-promotion-control")
@app.route("/agenttrust/production-release-control")
def agenttrust_production_promotion_control():
    rows = agenttrust_promotion_state_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Production Promotion Control</h2>
        <p>
            Promotion Control defines how an AI agent moves from concept to sandbox, pilot, human-gated production,
            restricted execution, quarantine, or retirement.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Promotion State</th>
                    <th>Description</th>
                    <th>Allowed Activity</th>
                    <th>Blocked Activity</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Promotion Rule</h2>
        <div class="answer">
            AgentTrust™ promotion is lifecycle-based. An AI agent must earn operational trust through evidence,
            testing, ownership, runtime control, and post-release monitoring before it can support production workflows.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Production Promotion Control",
        "Production promotion control for AI agent concept, sandbox, pilot, human-gated production, restricted execution, quarantine, and retirement states.",
        body
    )


@app.route("/agenttrust/release-readiness-board")
@app.route("/agenttrust/agent-release-board")
@app.route("/agenttrust/release-board")
def agenttrust_release_readiness_board():
    packet_rows = agenttrust_release_packet_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Release Readiness Board</h2>
        <p>
            The Release Readiness Board shows release packets for common AI agent types and the signoffs required before operational use.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Packet ID</th>
                    <th>Release Packet</th>
                    <th>Release Type</th>
                    <th>Required Signoffs</th>
                    <th>Required Evidence</th>
                    <th>Go-Live Condition</th>
                </tr>
            </thead>
            <tbody>
                {packet_rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Readiness Board Rule</h2>
        <div class="answer">
            Release readiness must show who signed off, what evidence was reviewed, what the agent may do,
            what the agent must not do, and what condition limits go-live.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Release Readiness Board",
        "Release readiness board for AI agent release packets, required signoffs, evidence, release type, and go-live conditions.",
        body
    )


@app.route("/agenttrust/deployment-certification-matrix")
@app.route("/agenttrust/agent-certification-matrix")
@app.route("/agenttrust/release-certification-matrix")
def agenttrust_deployment_certification_matrix():
    body = """
    <section class="section">
        <h2>AgentTrust™ Deployment Certification Matrix</h2>
        <p>
            This matrix defines what must be certified before different AI agent capabilities can be deployed.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Agent Capability</th>
                    <th>Required Certification</th>
                    <th>Required Owner</th>
                    <th>Release Decision</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Read-only agent.</td><td>Identity, owner, boundary, source traceability.</td><td>Business / Technical Owner.</td><td><span class="badge green">Can release in controlled mode</span></td></tr>
                <tr><td>Summarization agent.</td><td>Source lineage, evidence, reviewer route for material use.</td><td>Process Owner.</td><td><span class="badge green">Can release with evidence</span></td></tr>
                <tr><td>Recommendation agent.</td><td>Authority model, human signoff, prohibited-action control.</td><td>Process / LCM / System Owner.</td><td><span class="badge yellow">Human-gated release</span></td></tr>
                <tr><td>Drafting agent.</td><td>No auto-submit rule, approval queue, evidence vault.</td><td>Workflow Owner.</td><td><span class="badge yellow">Human approval required</span></td></tr>
                <tr><td>Create / update agent.</td><td>Runtime control plane, trust token, rollback, monitoring, change link.</td><td>Platform / Process Owner.</td><td><span class="badge red">Restricted execution only</span></td></tr>
                <tr><td>Workflow trigger agent.</td><td>Enforcement gateway, rollback, evidence, owner decision, monitoring.</td><td>Workflow / Risk Owner.</td><td><span class="badge red">Human-gated execution</span></td></tr>
                <tr><td>Access-influencing agent.</td><td>MyAccess / CyberArk review, cyber owner approval, no AI access approval.</td><td>Cybersecurity / Access Owner.</td><td><span class="badge red">Cyber-gated release</span></td></tr>
                <tr><td>GxP-influencing agent.</td><td>QA / validation review, regulated conclusion block, evidence lineage.</td><td>QA / Validation Owner.</td><td><span class="badge red">QA-governed release</span></td></tr>
                <tr><td>Multi-agent chain.</td><td>Delegation map, orchestration firewall, composite evidence, chain replay.</td><td>Governance Owner.</td><td><span class="badge orange">Chain-controlled release</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Certification Rule</h2>
        <div class="answer">
            Certification level must match agent capability. The more an AI agent can influence execution, access,
            regulated evidence, or workflow outcomes, the stronger the deployment certification must be.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Deployment Certification Matrix",
        "Deployment certification matrix for AI agent read-only, summarization, recommendation, drafting, update, workflow trigger, access, GxP, and multi-agent capabilities.",
        body
    )


@app.route("/agenttrust/post-release-verification")
@app.route("/agenttrust/agent-post-release-check")
@app.route("/agenttrust/post-go-live-verification")
def agenttrust_post_release_verification():
    body = """
    <section class="section">
        <h2>AgentTrust™ Post-Release Verification</h2>
        <p>
            Post-release verification confirms that the AI agent still behaves as released after deployment.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Verification Area</th>
                    <th>Question</th>
                    <th>Evidence Required</th>
                    <th>Failure Response</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Identity</td><td>Is the released agent the approved agent?</td><td>Agent ID, version, owner, release packet.</td><td><span class="badge red">Suspend release</span></td></tr>
                <tr><td>Prompt / Model</td><td>Did prompt, model, endpoint, or configuration change after release?</td><td>Model and prompt version evidence.</td><td><span class="badge orange">Run change gate</span></td></tr>
                <tr><td>Tool Boundary</td><td>Are only approved tools and APIs active?</td><td>Tool inventory and tool-call evidence.</td><td><span class="badge red">Restrict tools</span></td></tr>
                <tr><td>Human Oversight</td><td>Are human reviews being captured?</td><td>Approval queue, reviewer decision, outcome.</td><td><span class="badge red">Human-gate all actions</span></td></tr>
                <tr><td>Evidence Capture</td><td>Are input, source, tool-call, output, and outcome evidence captured?</td><td>Evidence package and replay test.</td><td><span class="badge orange">Restrict reliance</span></td></tr>
                <tr><td>Cyber Routing</td><td>Are access or privileged signals routed correctly?</td><td>Cyber review record and alert route.</td><td><span class="badge red">Escalate and suspend cyber scope</span></td></tr>
                <tr><td>GxP Routing</td><td>Are regulated signals routed to QA / validation?</td><td>QA review and regulated evidence record.</td><td><span class="badge red">Suspend regulated use</span></td></tr>
                <tr><td>Monitoring</td><td>Are drift, exception, and degradation alerts active?</td><td>Monitoring event register and alert logs.</td><td><span class="badge orange">Open remediation</span></td></tr>
                <tr><td>Replay</td><td>Can one released action be reconstructed end-to-end?</td><td>Decision replay package.</td><td><span class="badge red">Release not defensible</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Post-Release Rule</h2>
        <div class="answer">
            Release approval is not the end of governance. AgentTrust™ verifies that the released AI agent continues
            to operate within its approved trust contract, runtime controls, evidence obligations, and monitoring rules.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Post-Release Verification",
        "Post-release verification for AI agent identity, model, prompt, tools, human oversight, evidence, cyber routing, GxP routing, monitoring, and replay.",
        body
    )


@app.route("/agenttrust/rollback-and-retirement-plan")
@app.route("/agenttrust/agent-rollback-plan")
@app.route("/agenttrust/agent-retirement-plan")
def agenttrust_rollback_and_retirement_plan():
    body = """
    <section class="section">
        <h2>AgentTrust™ Rollback and Retirement Plan</h2>
        <p>
            Every released AI agent needs a rollback and retirement plan because trust can fail after deployment.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Trigger</th>
                    <th>Immediate Action</th>
                    <th>Owner</th>
                    <th>Closure Evidence</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent exceeds authority.</td><td><span class="badge red">Block and revoke action permit</span></td><td>Risk / Process Owner.</td><td>Authority breach record and remediation.</td></tr>
                <tr><td>Prompt injection succeeds.</td><td><span class="badge red">Quarantine agent</span></td><td>Security / AI Platform Owner.</td><td>Red-team failure closure and retest.</td></tr>
                <tr><td>Tool abuse detected.</td><td><span class="badge red">Disable tool or restrict mode</span></td><td>Platform Owner.</td><td>Tool authority review and evidence.</td></tr>
                <tr><td>Evidence capture fails.</td><td><span class="badge orange">Restrict to advisory mode</span></td><td>Audit / Platform Owner.</td><td>Evidence restoration and replay test.</td></tr>
                <tr><td>Cyber impact without review.</td><td><span class="badge red">Suspend cyber scope</span></td><td>Cybersecurity Owner.</td><td>Cyber review and access decision.</td></tr>
                <tr><td>GxP impact without QA review.</td><td><span class="badge red">Suspend regulated use</span></td><td>QA / Validation Owner.</td><td>QA review and regulated evidence decision.</td></tr>
                <tr><td>Owner missing.</td><td><span class="badge red">Suspend operational reliance</span></td><td>Governance Owner.</td><td>New owner assignment and register update.</td></tr>
                <tr><td>Agent retired.</td><td><span class="badge blue">Archive evidence and close license</span></td><td>Lifecycle Owner.</td><td>Retirement record and evidence archive.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Rollback Rule</h2>
        <div class="answer">
            AgentTrust™ release is reversible. When trust conditions fail, the agent must be restricted,
            quarantined, rolled back, or retired with evidence.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Rollback and Retirement Plan",
        "Rollback and retirement plan for AI agent authority breach, prompt injection, tool abuse, evidence failure, cyber impact, GxP impact, owner gap, and retirement.",
        body
    )


@app.route("/agenttrust/release-gate-simulator", methods=["GET", "POST"])
@app.route("/agenttrust/agent-release-simulator", methods=["GET", "POST"])
@app.route("/agenttrust/production-release-simulator", methods=["GET", "POST"])
def agenttrust_release_gate_simulator():
    from flask import request

    intake = request.form.get("intake", "yes")
    passport = request.form.get("passport", "yes")
    contract = request.form.get("contract", "yes")
    bom = request.form.get("bom", "yes")
    authority = request.form.get("authority", "yes")
    oversight = request.form.get("oversight", "yes")
    cyber = request.form.get("cyber", "yes")
    gxp = request.form.get("gxp", "yes")
    redteam = request.form.get("redteam", "yes")
    runtime = request.form.get("runtime", "yes")
    monitoring = request.form.get("monitoring", "yes")
    dossier = request.form.get("dossier", "yes")

    score, decision, badge, reason = agenttrust_release_gate_decision(
        intake, passport, contract, bom, authority, oversight, cyber, gxp, redteam, runtime, monitoring, dossier
    )

    def selected(value, expected):
        return "selected" if value == expected else ""

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Release Score</div><div class="value" style="color:var(--green);">{score}%</div><div class="note">Calculated from release gate controls.</div></div>
        <div class="metric"><div class="label">Release Decision</div><div class="value" style="color:var(--yellow);">{decision}</div><div class="note">{reason}</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Release Gate Simulator</h2>
        <p>
            Select whether each release control is complete. The simulator returns the production promotion decision.
        </p>

        <form method="POST" action="/agenttrust/release-gate-simulator">
            <table>
                <tbody>
                    <tr><td><strong>Intake Complete?</strong></td><td><select name="intake" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(intake, "yes")}>Yes</option><option value="no" {selected(intake, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Agent Passport / Register Ready?</strong></td><td><select name="passport" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(passport, "yes")}>Yes</option><option value="no" {selected(passport, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Trust Contract Active?</strong></td><td><select name="contract" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(contract, "yes")}>Yes</option><option value="no" {selected(contract, "no")}>No</option></select></td></tr>
                    <tr><td><strong>AgentBOM Approved?</strong></td><td><select name="bom" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(bom, "yes")}>Yes</option><option value="no" {selected(bom, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Authority Model Approved?</strong></td><td><select name="authority" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(authority, "yes")}>Yes</option><option value="no" {selected(authority, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Human Oversight Ready?</strong></td><td><select name="oversight" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(oversight, "yes")}>Yes</option><option value="no" {selected(oversight, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Cyber / Access Review Confirmed?</strong></td><td><select name="cyber" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(cyber, "yes")}>Yes</option><option value="no" {selected(cyber, "no")}>No</option></select></td></tr>
                    <tr><td><strong>GxP / QA Review Confirmed?</strong></td><td><select name="gxp" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(gxp, "yes")}>Yes</option><option value="no" {selected(gxp, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Red-Team Passed?</strong></td><td><select name="redteam" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(redteam, "yes")}>Yes</option><option value="no" {selected(redteam, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Runtime Control Plane Ready?</strong></td><td><select name="runtime" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(runtime, "yes")}>Yes</option><option value="no" {selected(runtime, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Continuous Monitoring Ready?</strong></td><td><select name="monitoring" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(monitoring, "yes")}>Yes</option><option value="no" {selected(monitoring, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Audit Dossier Ready?</strong></td><td><select name="dossier" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(dossier, "yes")}>Yes</option><option value="no" {selected(dossier, "no")}>No</option></select></td></tr>
                </tbody>
            </table>

            <button type="submit" style="margin-top:16px;padding:12px 18px;border-radius:12px;border:0;background:#2563eb;color:white;font-weight:800;">Run Release Gate</button>
        </form>
    </section>

    <section class="section">
        <h2>Release Decision</h2>
        <div class="answer">
            <strong>Score:</strong> {score}%<br>
            <strong>Decision:</strong> <span class="badge {badge}">{decision}</span><br>
            <strong>Reason:</strong> {reason}
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Release Gate Simulator",
        "Simulator for AI agent release readiness across intake, passport, trust contract, AgentBOM, authority, human oversight, cyber, GxP, red-team, runtime, monitoring, and audit dossier.",
        body
    )


@app.route("/agenttrust/release-gate-json")
@app.route("/agenttrust/agent-release-json")
@app.route("/agenttrust/production-promotion-json")
def agenttrust_release_gate_json():
    from flask import jsonify

    return jsonify({
        "module": "AgentTrust™",
        "capability": "Agent Release Gate + Production Promotion Control",
        "primary_question": "Can this AI agent be promoted to operational use?",
        "release_gates": AGENTTRUST_RELEASE_GATES,
        "promotion_states": AGENTTRUST_PROMOTION_STATES,
        "release_packets": AGENTTRUST_RELEASE_PACKETS,
        "minimum_release_conditions": [
            "Agent intake complete",
            "Agent passport and owner assigned",
            "Trust contract and operating license active",
            "AgentBOM and dependency graph approved",
            "Authority model approved",
            "Human oversight route ready",
            "Cyber/access impact reviewed where applicable",
            "GxP/QA impact reviewed where applicable",
            "Red-team testing passed",
            "Runtime control plane ready",
            "Continuous monitoring ready",
            "Audit dossier ready"
        ],
        "default_decision": "Do not promote AI agent to operational use unless release gates, evidence, owners, runtime controls, monitoring, and rollback plan are complete"
    })

# ============================================================
# END AGENTTRUST_AGENT_RELEASE_GATE_V1_ACTIVE
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

print("AgentTrust Agent Release Gate installed.")
print(f"Inserted before: {target_found}")
