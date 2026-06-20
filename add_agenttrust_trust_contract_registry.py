from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_TRUST_CONTRACT_REGISTRY_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust Trust Contract Registry already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base module not found. Install AgentTrust module first.")

nav_old = '<a href="/agenttrust/assurance-case-builder" class="secondary">Assurance Case</a>'
nav_new = '''<a href="/agenttrust/assurance-case-builder" class="secondary">Assurance Case</a>
                    <a href="/agenttrust/trust-contract-registry" class="secondary">Trust Contract</a>
                    <a href="/agenttrust/agent-operating-license" class="dark">Operating License</a>
                    <a href="/agenttrust/guardrail-obligations" class="dark">Obligations</a>
                    <a href="/agenttrust/contract-breach-register" class="dark">Breach Register</a>'''

if nav_old in text and "/agenttrust/trust-contract-registry" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# AGENTTRUST_TRUST_CONTRACT_REGISTRY_V1_ACTIVE
# AgentTrust™ Trust Contract Registry, Agent Trust Contract,
# Agent Operating License, Guardrail Obligations,
# Control Obligation Matrix, Contract Breach Register,
# License Revocation Rules, and Trust Contract JSON Export
# ============================================================

AGENTTRUST_CONTRACTS = [
    {
        "contract_id": "AT-CON-001",
        "agent": "ServiceNow CMDB Ownership Recommendation Agent™",
        "license_status": "Human-Gated License",
        "permitted_scope": "Read CMDB records, summarize CI gaps, recommend owner/support group review.",
        "prohibited_scope": "No production CI update, no LCM assignment, no lifecycle-state change, no access approval.",
        "required_owner": "LCM / CMDB Owner",
        "trust_condition": "Recommendation-only mode with source evidence and human reviewer decision.",
        "revocation_trigger": "Attempts update, hidden approval, missing evidence, or owner gap."
    },
    {
        "contract_id": "AT-CON-002",
        "agent": "Cutover Readiness Summary Agent™",
        "license_status": "Restricted Advisory License",
        "permitted_scope": "Summarize readiness, blockers, rollback gaps, validation gaps, and evidence status.",
        "prohibited_scope": "No cutover approval, no risk acceptance, no go-live decision, no validation override.",
        "required_owner": "Cutover Owner / QA where applicable",
        "trust_condition": "Must display evidence gaps and route unresolved risks to accountable owner.",
        "revocation_trigger": "Presents readiness as approved or hides blocker evidence."
    },
    {
        "contract_id": "AT-CON-003",
        "agent": "MyAccess / CyberArk Routing Agent™",
        "license_status": "Cyber-Gated License",
        "permitted_scope": "Recommend routing logic for access, entitlement, CyberArk, PSM, or admin context.",
        "prohibited_scope": "No access approval, no privileged execution, no entitlement activation, no credential action.",
        "required_owner": "Cybersecurity / CyberArk Owner",
        "trust_condition": "Privileged or access-impacting output must route to cyber/access owner.",
        "revocation_trigger": "Triggers access workflow or implies approval without cyber owner."
    },
    {
        "contract_id": "AT-CON-004",
        "agent": "GxP Inspection Evidence Agent™",
        "license_status": "QA-Governed License",
        "permitted_scope": "Prepare evidence summaries and inspection support packets.",
        "prohibited_scope": "No QA conclusion, no validation approval, no deviation closure, no release decision.",
        "required_owner": "QA / Validation Owner",
        "trust_condition": "All regulated reliance requires QA / validation review and evidence lineage.",
        "revocation_trigger": "Creates or implies regulated conclusion without QA review."
    },
    {
        "contract_id": "AT-CON-005",
        "agent": "Multi-Agent Orchestration Chain",
        "license_status": "Chain-Controlled License",
        "permitted_scope": "Coordinate approved handoffs between registered agents with preserved evidence.",
        "prohibited_scope": "No authority expansion, no delegation of approval, no hidden execution, no evidence loss.",
        "required_owner": "Governance Owner",
        "trust_condition": "Composite evidence bundle and chain-level authority check must be complete.",
        "revocation_trigger": "Delegation laundering, missing handoff evidence, or receiving-agent authority failure."
    }
]


AGENTTRUST_GUARDRAIL_OBLIGATIONS = [
    {
        "obligation_id": "AT-OBL-001",
        "obligation": "Maintain agent identity.",
        "requirement": "Every AI agent must have a unique ID, owner, purpose, lifecycle status, and risk tier.",
        "control": "Agent Register / Agent Risk Passport™",
        "breach_response": "Block operational reliance until registered."
    },
    {
        "obligation_id": "AT-OBL-002",
        "obligation": "Preserve human accountability.",
        "requirement": "Every material AI agent decision must map to a named human owner, reviewer, approver, or escalation owner.",
        "control": "Human Oversight Workbench / Signoff Matrix",
        "breach_response": "Human-gate, restrict, or block action."
    },
    {
        "obligation_id": "AT-OBL-003",
        "obligation": "Stay inside approved boundary.",
        "requirement": "Agent may only operate on approved systems, tools, APIs, workflows, and data sources.",
        "control": "AgentBOM / Dependency Graph / Boundary Control",
        "breach_response": "Quarantine agent and run boundary review."
    },
    {
        "obligation_id": "AT-OBL-004",
        "obligation": "Confirm authority before action.",
        "requirement": "Create, update, trigger, access, privileged, or regulated actions require explicit pre-action authority.",
        "control": "Authority Gate / Policy Decision Engine",
        "breach_response": "Block action and create authority breach record."
    },
    {
        "obligation_id": "AT-OBL-005",
        "obligation": "Capture evidence at time of action.",
        "requirement": "Input, source, tool-call, output, human review, timestamp, and outcome evidence must be captured.",
        "control": "Evidence Ledger / Evidence Lineage Engine",
        "breach_response": "Restrict reliance and mark replay weakness."
    },
    {
        "obligation_id": "AT-OBL-006",
        "obligation": "Escalate cyber-impacting actions.",
        "requirement": "Access, MyAccess, CyberArk, PSM, admin, or privileged impacts must route to cybersecurity owner.",
        "control": "MyAccess / CyberArk Routing / Cyber Escalation",
        "breach_response": "Escalate to cyber owner and block privileged execution."
    },
    {
        "obligation_id": "AT-OBL-007",
        "obligation": "Escalate regulated-impacting actions.",
        "requirement": "GMP, QA, validation, QC, release, deviation, CAPA, or inspection impact must route to QA / validation owner.",
        "control": "GxP Impact Router / QA Review",
        "breach_response": "Human-governed only; block regulated conclusion."
    },
    {
        "obligation_id": "AT-OBL-008",
        "obligation": "Prevent silent trust drift.",
        "requirement": "Model, prompt, tool, API, data, workflow, owner, and evidence changes must trigger review.",
        "control": "Dependency Drift Watch / Lifecycle Change Gate",
        "breach_response": "Re-score, re-gate, restrict, or quarantine."
    }
]


AGENTTRUST_BREACHES = [
    {
        "breach_id": "AT-BR-001",
        "breach": "Recommendation treated as approval.",
        "agent": "ServiceNow CMDB Ownership Recommendation Agent™",
        "severity": "High",
        "contract_violation": "Human signoff condition breached.",
        "required_response": "Block production update and require LCM / CMDB owner decision."
    },
    {
        "breach_id": "AT-BR-002",
        "breach": "Privileged route suggested without cyber escalation.",
        "agent": "MyAccess / CyberArk Routing Agent™",
        "severity": "Critical",
        "contract_violation": "Cyber-gated license condition breached.",
        "required_response": "Escalate to cybersecurity owner and suspend privileged workflow reliance."
    },
    {
        "breach_id": "AT-BR-003",
        "breach": "Validation evidence summary used as QA conclusion.",
        "agent": "GxP Inspection Evidence Agent™",
        "severity": "Critical",
        "contract_violation": "QA-governed license condition breached.",
        "required_response": "Route to QA / validation owner and mark output non-authoritative."
    },
    {
        "breach_id": "AT-BR-004",
        "breach": "Agent-to-agent handoff lost source evidence.",
        "agent": "Multi-Agent Orchestration Chain",
        "severity": "High",
        "contract_violation": "Composite evidence condition breached.",
        "required_response": "Restrict chain and rebuild handoff evidence package."
    },
    {
        "breach_id": "AT-BR-005",
        "breach": "Prompt changed after approved passport review.",
        "agent": "ServiceNow CMDB Ownership Recommendation Agent™",
        "severity": "High",
        "contract_violation": "Lifecycle change gate breached.",
        "required_response": "Run prompt change gate and recalculate trust score."
    }
]


def agenttrust_contract_rows():
    rows = ""

    for item in AGENTTRUST_CONTRACTS:
        badge = "yellow"
        if "Cyber" in item["license_status"] or "QA" in item["license_status"] or "Chain" in item["license_status"]:
            badge = "red"
        elif "Restricted" in item["license_status"]:
            badge = "orange"

        rows += f"""
        <tr>
            <td><strong>{item["contract_id"]}</strong></td>
            <td>{item["agent"]}</td>
            <td><span class="badge {badge}">{item["license_status"]}</span></td>
            <td>{item["permitted_scope"]}</td>
            <td>{item["prohibited_scope"]}</td>
            <td>{item["required_owner"]}</td>
            <td>{item["trust_condition"]}</td>
            <td>{item["revocation_trigger"]}</td>
        </tr>
        """

    return rows


def agenttrust_obligation_rows():
    rows = ""

    for item in AGENTTRUST_GUARDRAIL_OBLIGATIONS:
        rows += f"""
        <tr>
            <td><strong>{item["obligation_id"]}</strong></td>
            <td>{item["obligation"]}</td>
            <td>{item["requirement"]}</td>
            <td><span class="badge blue">{item["control"]}</span></td>
            <td>{item["breach_response"]}</td>
        </tr>
        """

    return rows


def agenttrust_breach_rows():
    rows = ""

    for item in AGENTTRUST_BREACHES:
        badge = "orange"
        if item["severity"] == "Critical":
            badge = "red"
        elif item["severity"] == "High":
            badge = "yellow"

        rows += f"""
        <tr>
            <td><strong>{item["breach_id"]}</strong></td>
            <td>{item["breach"]}</td>
            <td>{item["agent"]}</td>
            <td><span class="badge {badge}">{item["severity"]}</span></td>
            <td>{item["contract_violation"]}</td>
            <td>{item["required_response"]}</td>
        </tr>
        """

    return rows


try:
    AGENTTRUST_EXPECTED_ROUTES.extend([
        "/agenttrust/trust-contract-registry",
        "/agenttrust/agent-trust-contract",
        "/agenttrust/agent-operating-license",
        "/agenttrust/guardrail-obligations",
        "/agenttrust/control-obligation-matrix",
        "/agenttrust/contract-breach-register",
        "/agenttrust/license-revocation-rules",
        "/agenttrust/trust-contract-json"
    ])
except Exception:
    pass


@app.route("/agenttrust/trust-contract-registry")
@app.route("/agenttrust/agent-trust-contracts")
@app.route("/agenttrust/trust-contracts")
def agenttrust_trust_contract_registry():
    rows = agenttrust_contract_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Trust Contracts</div><div class="value" style="color:var(--green);">Active</div><div class="note">AI agents operate under governed contract terms.</div></div>
        <div class="metric"><div class="label">Operating License</div><div class="value" style="color:var(--yellow);">Conditional</div><div class="note">License depends on owner, evidence, authority, and scope.</div></div>
        <div class="metric"><div class="label">Guardrails</div><div class="value" style="color:var(--blue);">Obligations</div><div class="note">Controls become enforceable obligations.</div></div>
        <div class="metric"><div class="label">Breach Logic</div><div class="value" style="color:var(--red);">Revocable</div><div class="note">Violation can restrict, block, or quarantine agent.</div></div>
        <div class="metric"><div class="label">Cyber / QA</div><div class="value" style="color:var(--orange);">Routed</div><div class="note">Privileged and regulated use require owner review.</div></div>
        <div class="metric"><div class="label">Evidence</div><div class="value" style="color:var(--purple);">Required</div><div class="note">Contract compliance must be replayable.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Trust Contract Registry</h2>
        <div class="answer">
            <strong>Purpose:</strong> define the operating terms under which each AI agent may be trusted.
            A Trust Contract turns governance rules into enforceable conditions: what the agent may do, what it must not do,
            who owns the decision, what evidence is required, and what causes restriction, revocation, or quarantine.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Contract ID</th>
                    <th>Agent</th>
                    <th>License Status</th>
                    <th>Permitted Scope</th>
                    <th>Prohibited Scope</th>
                    <th>Required Owner</th>
                    <th>Trust Condition</th>
                    <th>Revocation Trigger</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Trust Contract Rule</h2>
        <div class="answer">
            An AI agent should not be allowed to operate only because it exists.
            It should operate only under a clear trust contract with scope, owner, authority, evidence, obligations, and revocation rules.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Trust Contract Registry",
        "Registry of AI agent trust contracts, operating licenses, permitted scope, prohibited scope, required owners, trust conditions, and revocation triggers.",
        body
    )


@app.route("/agenttrust/agent-trust-contract")
@app.route("/agenttrust/sample-trust-contract")
@app.route("/agenttrust/trust-contract-template")
def agenttrust_agent_trust_contract():
    body = """
    <section class="section">
        <h2>AgentTrust™ Sample Agent Trust Contract</h2>
        <div class="answer">
            <strong>Contract:</strong> AT-CON-001<br>
            <strong>Agent:</strong> ServiceNow CMDB Ownership Recommendation Agent™<br>
            <strong>License Type:</strong> Human-Gated License<br>
            <strong>Primary Question:</strong> Can this AI agent recommend CI governance actions without becoming the hidden CMDB decision-maker?
        </div>

        <table>
            <thead>
                <tr>
                    <th>Contract Clause</th>
                    <th>Contract Requirement</th>
                    <th>Evidence Required</th>
                    <th>Breach Outcome</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Identity</td><td>Agent must be registered with owner, purpose, lifecycle state, and risk tier.</td><td>Agent Register and Passport.</td><td><span class="badge red">No register, no trust</span></td></tr>
                <tr><td>Permitted Actions</td><td>Read, summarize, recommend, and draft CI review notes.</td><td>Source CI, recommendation, timestamp.</td><td><span class="badge yellow">Recommendation only</span></td></tr>
                <tr><td>Prohibited Actions</td><td>No CI approval, no production update, no LCM assignment, no lifecycle-state change.</td><td>Execution firewall record.</td><td><span class="badge red">Block and record breach</span></td></tr>
                <tr><td>Human Accountability</td><td>LCM / CMDB owner must review before operational reliance.</td><td>Reviewer decision and outcome.</td><td><span class="badge red">Hidden approval breach</span></td></tr>
                <tr><td>Evidence</td><td>Tool-call, source, output, human review, and outcome must be captured.</td><td>Evidence package and replay record.</td><td><span class="badge orange">Restrict reliance</span></td></tr>
                <tr><td>Cyber Impact</td><td>If access or privileged context appears, route to cybersecurity.</td><td>Cyber review record.</td><td><span class="badge red">Escalate</span></td></tr>
                <tr><td>Regulated Impact</td><td>If CI supports regulated operation, route to QA / validation where required.</td><td>QA / validation review record.</td><td><span class="badge red">Human-governed only</span></td></tr>
                <tr><td>Revocation</td><td>License may be suspended if agent exceeds scope, loses evidence, or drifts.</td><td>Breach record and remediation plan.</td><td><span class="badge red">Quarantine or revoke</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Contract Statement</h2>
        <div class="answer">
            This agent is licensed only for human-gated CMDB recommendation support.
            It is not licensed to approve, update, trigger, assign, delete, grant access, or make regulated conclusions.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Sample Trust Contract",
        "Sample AI agent trust contract defining identity, permitted actions, prohibited actions, human accountability, evidence, cyber impact, regulated impact, and revocation.",
        body
    )


@app.route("/agenttrust/agent-operating-license")
@app.route("/agenttrust/operating-license")
@app.route("/agenttrust/ai-agent-license")
def agenttrust_agent_operating_license():
    body = """
    <section class="section">
        <h2>AgentTrust™ Agent Operating License</h2>
        <p>
            The Operating License is the runtime permission state assigned to an AI agent.
            It determines whether the agent may execute, recommend, draft, remain restricted, escalate, or be quarantined.
        </p>

        <table>
            <thead>
                <tr>
                    <th>License Type</th>
                    <th>Allowed Behavior</th>
                    <th>Required Controls</th>
                    <th>Revocation Trigger</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Observation License</td><td>Read approved records only.</td><td>Agent identity, owner, access log, source traceability.</td><td>Reads outside approved boundary.</td></tr>
                <tr><td>Advisory License</td><td>Summarize and recommend only.</td><td>Evidence capture, human reviewer, prohibited action list.</td><td>Recommendation treated as approval.</td></tr>
                <tr><td>Human-Gated License</td><td>Draft, recommend, or prepare action for human approval.</td><td>Approval queue, signoff matrix, evidence vault.</td><td>Agent bypasses human review.</td></tr>
                <tr><td>Restricted Execution License</td><td>Create or trigger only inside approved workflow and rollback path.</td><td>Authority gate, execution firewall, rollback, monitoring.</td><td>Tool call exceeds authority.</td></tr>
                <tr><td>Cyber-Gated License</td><td>May support access routing but not approve or execute access.</td><td>Cybersecurity owner, CyberArk / MyAccess review, access evidence.</td><td>Privileged workflow triggered without cyber owner.</td></tr>
                <tr><td>QA-Governed License</td><td>May prepare regulated evidence but not conclude or approve.</td><td>QA / validation owner, evidence lineage, regulated impact review.</td><td>AI output becomes regulated conclusion.</td></tr>
                <tr><td>Quarantine State</td><td>No operational reliance except investigation or remediation.</td><td>Quarantine reason, release condition, owner decision.</td><td>Release attempted before closure.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Operating License Rule</h2>
        <div class="answer">
            AgentTrust™ can downgrade an agent license when trust weakens.
            An agent can move from trusted to human-gated, restricted, blocked, or quarantined based on evidence, authority, drift, cyber, GxP, or breach signals.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Agent Operating License",
        "Operating license model for AI agent observation, advisory, human-gated, restricted execution, cyber-gated, QA-governed, and quarantine states.",
        body
    )


@app.route("/agenttrust/guardrail-obligations")
@app.route("/agenttrust/agent-obligations")
@app.route("/agenttrust/control-obligations")
def agenttrust_guardrail_obligations():
    rows = agenttrust_obligation_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Guardrail Obligations</h2>
        <p>
            Guardrails are not just design preferences. In AgentTrust™, guardrails become obligations that must be evidenced,
            monitored, and enforced.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Obligation ID</th>
                    <th>Obligation</th>
                    <th>Requirement</th>
                    <th>Control</th>
                    <th>Breach Response</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Obligation Rule</h2>
        <div class="answer">
            A guardrail without evidence is only an intention.
            AgentTrust™ turns guardrails into obligations with owners, controls, breach logic, and audit replay.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Guardrail Obligations",
        "Guardrail obligation library for AI agent identity, accountability, boundary, authority, evidence, cyber escalation, regulated escalation, and drift control.",
        body
    )


@app.route("/agenttrust/control-obligation-matrix")
@app.route("/agenttrust/obligation-matrix")
@app.route("/agenttrust/control-contract-matrix")
def agenttrust_control_obligation_matrix():
    body = """
    <section class="section">
        <h2>AgentTrust™ Control Obligation Matrix</h2>
        <p>
            This matrix connects each major AgentTrust™ control to the obligation it enforces and the operational decision it supports.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Control</th>
                    <th>Obligation Enforced</th>
                    <th>Evidence Required</th>
                    <th>Decision Supported</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent Register</td><td>Agent must be known.</td><td>Agent ID, owner, purpose, lifecycle status.</td><td><span class="badge red">No register, no trust</span></td></tr>
                <tr><td>Agent Risk Passport™</td><td>Agent must have scope and risk defined.</td><td>Boundary, actions, tools, data, owners, review cadence.</td><td><span class="badge yellow">Human-gate if incomplete</span></td></tr>
                <tr><td>Authority Gate</td><td>Agent must have authority before action.</td><td>Permitted action and decision rule.</td><td><span class="badge red">Block unauthorized action</span></td></tr>
                <tr><td>Execution Firewall</td><td>Unsafe execution must be stopped.</td><td>Pre-action decision, allowed mode, outcome.</td><td><span class="badge red">Block / quarantine</span></td></tr>
                <tr><td>Evidence Ledger</td><td>Action must be evidenced.</td><td>Input, tool-call, output, human, outcome.</td><td><span class="badge orange">Restrict if weak evidence</span></td></tr>
                <tr><td>Human Oversight Workbench</td><td>Human accountability must remain visible.</td><td>Reviewer, approval, rejection, escalation, risk acceptance.</td><td><span class="badge yellow">Human-gated decision</span></td></tr>
                <tr><td>GxP Impact Router</td><td>Regulated impact must route to QA / validation.</td><td>GxP screening and QA review record.</td><td><span class="badge red">Human-governed only</span></td></tr>
                <tr><td>Cyber Routing</td><td>Access and privileged impact must route to cyber owner.</td><td>Cyber review and access routing evidence.</td><td><span class="badge red">Escalate to cyber</span></td></tr>
                <tr><td>Continuous Monitoring</td><td>Trust must remain current.</td><td>Drift, alerts, exceptions, degradation signals.</td><td><span class="badge orange">Re-score / re-gate</span></td></tr>
                <tr><td>Decision Replay</td><td>Action must be defensible later.</td><td>Timeline, lineage, authority, evidence, outcome.</td><td><span class="badge green">Audit-ready if complete</span></td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Control Obligation Matrix",
        "Matrix connecting AgentTrust™ controls to obligations, evidence requirements, and operational trust decisions.",
        body
    )


@app.route("/agenttrust/contract-breach-register")
@app.route("/agenttrust/trust-contract-breach")
@app.route("/agenttrust/agent-breach-register")
def agenttrust_contract_breach_register():
    rows = agenttrust_breach_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Contract Breach Register</h2>
        <p>
            This register records breaches of AI agent trust contracts and defines the required response.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Breach ID</th>
                    <th>Breach</th>
                    <th>Agent</th>
                    <th>Severity</th>
                    <th>Contract Violation</th>
                    <th>Required Response</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Breach Register Rule</h2>
        <div class="answer">
            A contract breach should not remain informal.
            AgentTrust™ records the breach, affected agent, severity, violated condition, owner route, and required response.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Contract Breach Register",
        "Breach register for AI agent trust contract violations, hidden approvals, cyber escalation gaps, regulated conclusion creep, evidence loss, and drift.",
        body
    )


@app.route("/agenttrust/license-revocation-rules")
@app.route("/agenttrust/revocation-rules")
@app.route("/agenttrust/agent-license-revocation")
def agenttrust_license_revocation_rules():
    body = """
    <section class="section">
        <h2>AgentTrust™ License Revocation Rules</h2>
        <p>
            These rules define when an AI agent operating license should be downgraded, suspended, revoked, or quarantined.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Revocation Trigger</th>
                    <th>Trust Impact</th>
                    <th>Immediate Action</th>
                    <th>Release Condition</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Owner missing or removed.</td><td>Accountability failure.</td><td><span class="badge red">Suspend license</span></td><td>Assign accountable owner and update register.</td></tr>
                <tr><td>Agent exceeds authority.</td><td>Unauthorized action risk.</td><td><span class="badge red">Block and breach record</span></td><td>Authority review and decision record.</td></tr>
                <tr><td>Prohibited action attempted.</td><td>Critical control failure.</td><td><span class="badge red">Quarantine</span></td><td>Root cause, remediation, approval to release.</td></tr>
                <tr><td>Evidence capture fails.</td><td>Audit replay weakness.</td><td><span class="badge orange">Restrict license</span></td><td>Restore evidence capture and replay test.</td></tr>
                <tr><td>Cyber impact without review.</td><td>Privileged or access governance failure.</td><td><span class="badge red">Escalate and suspend cyber scope</span></td><td>Cybersecurity owner approval.</td></tr>
                <tr><td>GxP impact without QA review.</td><td>Regulated defensibility failure.</td><td><span class="badge red">Suspend regulated use</span></td><td>QA / validation owner approval.</td></tr>
                <tr><td>Dependency drift detected.</td><td>Trust score stale.</td><td><span class="badge orange">Re-score and re-gate</span></td><td>Updated AgentBOM and change review.</td></tr>
                <tr><td>Red-team failure unresolved.</td><td>Unsafe under adversarial conditions.</td><td><span class="badge red">Quarantine</span></td><td>Failure mode remediated and retested.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Revocation Rule</h2>
        <div class="answer">
            AgentTrust™ licenses are conditional. When conditions fail, trust is downgraded immediately until evidence,
            authority, ownership, and control integrity are restored.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ License Revocation Rules",
        "License revocation rules for AI agent owner gaps, authority breaches, prohibited actions, evidence failures, cyber gaps, GxP gaps, dependency drift, and red-team failures.",
        body
    )


@app.route("/agenttrust/trust-contract-json")
@app.route("/agenttrust/contract-registry-json")
@app.route("/agenttrust/operating-license-json")
def agenttrust_trust_contract_json():
    from flask import jsonify

    return jsonify({
        "module": "AgentTrust™",
        "capability": "Trust Contract Registry + Agent Operating License",
        "primary_question": "Under what conditions is this AI agent licensed to operate?",
        "contracts": AGENTTRUST_CONTRACTS,
        "guardrail_obligations": AGENTTRUST_GUARDRAIL_OBLIGATIONS,
        "breach_register": AGENTTRUST_BREACHES,
        "license_states": [
            "Observation License",
            "Advisory License",
            "Human-Gated License",
            "Restricted Execution License",
            "Cyber-Gated License",
            "QA-Governed License",
            "Quarantine State"
        ],
        "default_rule": "If contract conditions fail, downgrade, restrict, block, revoke, or quarantine the AI agent until remediation evidence is complete"
    })

# ============================================================
# END AGENTTRUST_TRUST_CONTRACT_REGISTRY_V1_ACTIVE
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

print("AgentTrust Trust Contract Registry installed.")
print(f"Inserted before: {target_found}")
