from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_AGENT_IDENTITY_ENTITLEMENT_GOVERNANCE_V1_ACTIVE"

if MARKER in text:
    print("CITrust Agent Identity & Entitlement Governance already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base shell not found. Install AgentTrust base module first.")

nav_old = '<a href="/citrust/agent-observability-evidence-fabric" class="secondary">Observability Fabric</a>'
nav_new = '''<a href="/citrust/agent-observability-evidence-fabric" class="secondary">Observability Fabric</a>
                    <a href="/citrust/agent-identity-entitlement-governance" class="secondary">Agent Identity</a>
                    <a href="/citrust/agent-least-privilege-gate" class="dark">Least Privilege</a>
                    <a href="/citrust/agent-myaccess-entitlement-map" class="dark">MyAccess Map</a>
                    <a href="/citrust/agent-identity-simulator" class="dark">Identity Sim</a>'''

if nav_old in text and "/citrust/agent-identity-entitlement-governance" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# CITRUST_AGENT_IDENTITY_ENTITLEMENT_GOVERNANCE_V1_ACTIVE
# CITrust™ Agent Identity & Entitlement Governance Center
# Agent Identity Register, Agent Service Account Map,
# Least Privilege Gate, MyAccess Entitlement Map,
# CyberArk / PSM Agent Gate, Segregation of Duties Control,
# Agent Entitlement Review, Agent Access Recertification,
# Identity Governance Simulator, and JSON Export
# ============================================================

CITRUST_AGENT_IDENTITY_DOMAINS = [
    {
        "domain_id": "AIG-001",
        "domain": "Agent Identity",
        "governance_question": "Does the AI agent have a unique identity that can be traced to action?",
        "required_evidence": "Agent ID, agent name, owner, purpose, approved use case, operating license.",
        "risk_if_missing": "Unknown digital actor may influence CI, access, or change workflows.",
        "default_decision": "Block unknown agent."
    },
    {
        "domain_id": "AIG-002",
        "domain": "Agent Owner",
        "governance_question": "Who is accountable for the agent's behavior, access, evidence, and exceptions?",
        "required_evidence": "Business owner, technical owner, governance owner, support owner.",
        "risk_if_missing": "No accountable human for agent action or failure.",
        "default_decision": "No owner, no operation."
    },
    {
        "domain_id": "AIG-003",
        "domain": "Service Account / Non-Human Identity",
        "governance_question": "What service account, app registration, managed identity, or integration identity does the agent use?",
        "required_evidence": "Account ID, account type, owner, access scope, review date, credential boundary.",
        "risk_if_missing": "Agent may operate through uncontrolled or shared identity.",
        "default_decision": "Restrict until mapped."
    },
    {
        "domain_id": "AIG-004",
        "domain": "Entitlement Scope",
        "governance_question": "What systems, CIs, APIs, records, fields, workflows, or tools can the agent access?",
        "required_evidence": "Entitlement list, allowed actions, denied actions, data boundary, tool boundary.",
        "risk_if_missing": "Agent may access more than required.",
        "default_decision": "Least-privilege reduction required."
    },
    {
        "domain_id": "AIG-005",
        "domain": "MyAccess Route",
        "governance_question": "Is the agent's entitlement route governed through approved access workflow?",
        "required_evidence": "MyAccess group, approver group, access owner, entitlement approval, access review.",
        "risk_if_missing": "Agent may bypass standard access governance.",
        "default_decision": "Route to access owner."
    },
    {
        "domain_id": "AIG-006",
        "domain": "CyberArk / PSM Route",
        "governance_question": "Does the agent touch privileged, admin, CyberArk, PSM, or controlled session context?",
        "required_evidence": "CyberArk route, PSM session requirement, privileged account, cyber owner approval.",
        "risk_if_missing": "Privileged AI action may occur without cyber evidence.",
        "default_decision": "Cyber-gated."
    },
    {
        "domain_id": "AIG-007",
        "domain": "Segregation of Duties",
        "governance_question": "Can the same agent recommend, approve, execute, and close the same action?",
        "required_evidence": "Role separation, approval gate, execution boundary, closure owner.",
        "risk_if_missing": "AI becomes hidden requester, approver, executor, and closer.",
        "default_decision": "Separate duties."
    },
    {
        "domain_id": "AIG-008",
        "domain": "Access Recertification",
        "governance_question": "Is the agent's access periodically reviewed, reduced, revoked, or reapproved?",
        "required_evidence": "Review cadence, reviewer, access decision, removal evidence, exception owner.",
        "risk_if_missing": "Agent retains stale or excessive access.",
        "default_decision": "Recertification required."
    }
]


CITRUST_AGENT_SERVICE_ACCOUNT_MAP = [
    {
        "identity_type": "Azure Managed Identity",
        "used_for": "Cloud-hosted agent runtime, Azure function, app service, workflow, or integration execution.",
        "required_controls": "Owner, resource scope, RBAC assignment, managed identity review, telemetry link.",
        "risk": "Overbroad cloud resource access."
    },
    {
        "identity_type": "App Registration / Enterprise App",
        "used_for": "Graph/API access, system integration, automation, or ServiceNow connector.",
        "required_controls": "App owner, API permissions, consent evidence, secret/certificate control, review cadence.",
        "risk": "Unreviewed API permissions or stale secret."
    },
    {
        "identity_type": "ServiceNow Integration User",
        "used_for": "ServiceNow API, CMDB read/write, task creation, change linkage, workflow routing.",
        "required_controls": "Role list, table access, field access, CI update permission, ServiceNow audit log.",
        "risk": "Agent may update CMDB fields beyond approved scope."
    },
    {
        "identity_type": "CyberArk-Governed Account",
        "used_for": "Privileged access, admin workflow, controlled session, vendor/admin route.",
        "required_controls": "Safe, account owner, PSM route, session evidence, privileged approval.",
        "risk": "Privileged action without session governance."
    },
    {
        "identity_type": "MyAccess Entitlement",
        "used_for": "Access group, support group, approver group, agent access to workflow or data.",
        "required_controls": "Approver group, access owner, role justification, periodic access review.",
        "risk": "Agent may receive access without formal entitlement route."
    },
    {
        "identity_type": "Vendor / External AI Identity",
        "used_for": "Third-party AI, vendor connector, external support automation, hosted AI service.",
        "required_controls": "Contract boundary, data boundary, deletion right, audit right, vendor owner.",
        "risk": "External AI access without enterprise control."
    }
]


CITRUST_LEAST_PRIVILEGE_GATES = [
    {
        "gate_id": "LPG-001",
        "gate": "Purpose Fit",
        "question": "Is each entitlement tied to a named approved agent use case?",
        "required_evidence": "Use case, entitlement, owner, purpose justification.",
        "block_condition": "Access has no approved purpose."
    },
    {
        "gate_id": "LPG-002",
        "gate": "Read vs Write Boundary",
        "question": "Does the agent need read, recommend, draft, route, update, trigger, or approve capability?",
        "required_evidence": "Allowed action list and prohibited action list.",
        "block_condition": "Write or trigger permissions granted where recommendation-only is enough."
    },
    {
        "gate_id": "LPG-003",
        "gate": "CI Field Boundary",
        "question": "Which ServiceNow CI fields or tables may the agent read or influence?",
        "required_evidence": "Table, field, role, action type, field-risk classification.",
        "block_condition": "Agent can update GxP, access, lifecycle, support, or relationship fields without approval."
    },
    {
        "gate_id": "LPG-004",
        "gate": "GxP Boundary",
        "question": "Can the agent access or influence GMP, validated, QA, release, deviation, CAPA, or inspection-sensitive records?",
        "required_evidence": "GxP screen, QA owner approval, validation boundary.",
        "block_condition": "Regulated access without QA route."
    },
    {
        "gate_id": "LPG-005",
        "gate": "Cyber Boundary",
        "question": "Can the agent access MyAccess, CyberArk, PSM, privileged route, admin, or access-approval workflows?",
        "required_evidence": "Cyber review, access owner approval, privileged route decision.",
        "block_condition": "Access-impacting capability without cyber approval."
    },
    {
        "gate_id": "LPG-006",
        "gate": "Time-Bound Access",
        "question": "Is agent access permanent, temporary, emergency, or project-specific?",
        "required_evidence": "Access expiry, review date, removal condition, exception owner.",
        "block_condition": "Permanent broad access without periodic review."
    },
    {
        "gate_id": "LPG-007",
        "gate": "Telemetry Boundary",
        "question": "Is every entitlement observable and attributable in logs?",
        "required_evidence": "ServiceNow log, Azure telemetry, CyberArk/PSM log if privileged, correlation ID.",
        "block_condition": "Access cannot be monitored or attributed."
    }
]


CITRUST_MYACCESS_AGENT_ENTITLEMENT_MAP = [
    {
        "entitlement_area": "CMDB Read Access",
        "agent_mode": "Read and summarize CI records.",
        "approval_route": "CMDB / LCM Owner.",
        "evidence": "MyAccess entitlement, ServiceNow role, allowed tables, review cadence.",
        "default_position": "Allowed with logging."
    },
    {
        "entitlement_area": "CMDB Write Access",
        "agent_mode": "Update CI field, relationship, owner, support group, lifecycle, or evidence link.",
        "approval_route": "CMDB Owner + Change Owner + QA/Cyber where applicable.",
        "evidence": "Change-control approval, field-risk review, rollback, post-check.",
        "default_position": "Blocked by default."
    },
    {
        "entitlement_area": "Support Group Routing",
        "agent_mode": "Recommend or route support group / assignment group.",
        "approval_route": "Support Owner / Service Owner.",
        "evidence": "Support route evidence, owner approval, before/after group.",
        "default_position": "Human-gated."
    },
    {
        "entitlement_area": "Access Approval Workflow",
        "agent_mode": "Read or route access request context.",
        "approval_route": "Access Owner / Cybersecurity.",
        "evidence": "MyAccess request, approver group, cyber decision.",
        "default_position": "No autonomous approval."
    },
    {
        "entitlement_area": "CyberArk / PSM Context",
        "agent_mode": "Identify privileged route or session requirement.",
        "approval_route": "CyberArk / Cybersecurity Owner.",
        "evidence": "CyberArk policy, PSM requirement, privileged session evidence.",
        "default_position": "Cyber-gated."
    },
    {
        "entitlement_area": "GxP / QA Workflow",
        "agent_mode": "Identify regulated context and route to QA.",
        "approval_route": "QA / Validation Owner.",
        "evidence": "GxP screen, validation status, QA decision.",
        "default_position": "QA-governed."
    }
]


CITRUST_AGENT_SOD_CONTROLS = [
    {
        "sod_area": "Recommend vs Approve",
        "rule": "AI agent may recommend but must not approve its own recommendation.",
        "evidence": "Recommendation record, human approver, approval timestamp."
    },
    {
        "sod_area": "Approve vs Execute",
        "rule": "Approver and executor must be separated for material CI, access, GxP, or change actions.",
        "evidence": "Approval record, execution actor, change/task evidence."
    },
    {
        "sod_area": "Execute vs Close",
        "rule": "The actor executing the action should not close without post-check and owner signoff.",
        "evidence": "Execution log, post-check, closure owner."
    },
    {
        "sod_area": "Access Request vs Access Approval",
        "rule": "AI may assist request preparation but must not approve access or entitlement.",
        "evidence": "Requester, access owner, cyber decision, approval record."
    },
    {
        "sod_area": "GxP Assessment vs QA Decision",
        "rule": "AI may flag GxP impact but must not make QA or validation conclusion.",
        "evidence": "GxP flag, QA reviewer, validation decision."
    },
    {
        "sod_area": "Exception Creation vs Exception Approval",
        "rule": "AI may draft exception but owner must approve, time-bound, and sign the exception.",
        "evidence": "Exception ID, owner, expiry, risk acceptance."
    }
]


CITRUST_AGENT_ENTITLEMENT_REVIEW = [
    {
        "review_item": "Agent exists and is still needed",
        "review_question": "Is the AI agent still approved for its original use case?",
        "review_owner": "Agent Owner / Governance Owner",
        "evidence": "Use-case review and active/inactive decision."
    },
    {
        "review_item": "Owner still valid",
        "review_question": "Are business, technical, support, cyber, and governance owners current?",
        "review_owner": "Governance / CMDB Owner",
        "evidence": "Owner confirmation and update record."
    },
    {
        "review_item": "Entitlements still required",
        "review_question": "Does the agent still require each access role, group, API permission, or tool access?",
        "review_owner": "Access Owner / Cybersecurity",
        "evidence": "Access review decision and removal evidence."
    },
    {
        "review_item": "Privileged access still justified",
        "review_question": "Does the agent still need privileged, CyberArk, PSM, admin, or elevated context?",
        "review_owner": "Cybersecurity / CyberArk Owner",
        "evidence": "Privileged access review and session evidence."
    },
    {
        "review_item": "GxP access still controlled",
        "review_question": "Does the agent have access to GMP, validation, QA, or inspection-sensitive data?",
        "review_owner": "QA / Validation Owner",
        "evidence": "QA decision and regulated access boundary."
    },
    {
        "review_item": "Access exceptions still valid",
        "review_question": "Are all exceptions time-bound, owner-approved, and remediated?",
        "review_owner": "Risk / Governance Owner",
        "evidence": "Exception register and closure plan."
    }
]


def citrust_agent_identity_domain_rows():
    rows = ""
    for item in CITRUST_AGENT_IDENTITY_DOMAINS:
        rows += f"""
        <tr>
            <td><strong>{item["domain_id"]}</strong></td>
            <td><span class="badge blue">{item["domain"]}</span></td>
            <td>{item["governance_question"]}</td>
            <td>{item["required_evidence"]}</td>
            <td><span class="badge red">{item["risk_if_missing"]}</span></td>
            <td><span class="badge orange">{item["default_decision"]}</span></td>
        </tr>
        """
    return rows


def citrust_service_account_rows():
    rows = ""
    for item in CITRUST_AGENT_SERVICE_ACCOUNT_MAP:
        rows += f"""
        <tr>
            <td><strong>{item["identity_type"]}</strong></td>
            <td>{item["used_for"]}</td>
            <td>{item["required_controls"]}</td>
            <td><span class="badge red">{item["risk"]}</span></td>
        </tr>
        """
    return rows


def citrust_least_privilege_rows():
    rows = ""
    for item in CITRUST_LEAST_PRIVILEGE_GATES:
        rows += f"""
        <tr>
            <td><strong>{item["gate_id"]}</strong></td>
            <td><span class="badge blue">{item["gate"]}</span></td>
            <td>{item["question"]}</td>
            <td>{item["required_evidence"]}</td>
            <td><span class="badge red">{item["block_condition"]}</span></td>
        </tr>
        """
    return rows


def citrust_myaccess_entitlement_rows():
    rows = ""
    for item in CITRUST_MYACCESS_AGENT_ENTITLEMENT_MAP:
        badge = "green"
        if "Blocked" in item["default_position"]:
            badge = "red"
        elif "gated" in item["default_position"].lower() or "governed" in item["default_position"].lower():
            badge = "orange"
        elif "Human" in item["default_position"] or "No autonomous" in item["default_position"]:
            badge = "yellow"

        rows += f"""
        <tr>
            <td><strong>{item["entitlement_area"]}</strong></td>
            <td>{item["agent_mode"]}</td>
            <td>{item["approval_route"]}</td>
            <td>{item["evidence"]}</td>
            <td><span class="badge {badge}">{item["default_position"]}</span></td>
        </tr>
        """
    return rows


def citrust_sod_rows():
    rows = ""
    for item in CITRUST_AGENT_SOD_CONTROLS:
        rows += f"""
        <tr>
            <td><strong>{item["sod_area"]}</strong></td>
            <td>{item["rule"]}</td>
            <td>{item["evidence"]}</td>
        </tr>
        """
    return rows


def citrust_entitlement_review_rows():
    rows = ""
    for item in CITRUST_AGENT_ENTITLEMENT_REVIEW:
        rows += f"""
        <tr>
            <td><strong>{item["review_item"]}</strong></td>
            <td>{item["review_question"]}</td>
            <td>{item["review_owner"]}</td>
            <td>{item["evidence"]}</td>
        </tr>
        """
    return rows


def citrust_agent_identity_decision(identity, owner, account, entitlement, privilege, myaccess, sod, recert, telemetry):
    checks = [identity, owner, account, entitlement, myaccess, sod, recert, telemetry]
    score = int((sum(1 for item in checks if item == "yes") / len(checks)) * 100)

    if identity != "yes":
        return score, "Block Agent Operation", "red", "Agent identity is unknown or not registered."
    if owner != "yes":
        return score, "No Owner, No Operation", "red", "Agent does not have accountable human ownership."
    if account != "yes":
        return score, "Identity Mapping Required", "red", "Service account, managed identity, app registration, or integration identity is not mapped."
    if entitlement != "yes":
        return score, "Least Privilege Review Required", "orange", "Entitlement scope is incomplete or overbroad."
    if privilege == "yes":
        return score, "CyberArk / PSM Gate Required", "red", "Privileged or admin context requires cybersecurity and CyberArk / PSM evidence."
    if myaccess != "yes":
        return score, "MyAccess Route Required", "orange", "Access route or approver group is not governed."
    if sod != "yes":
        return score, "Segregation of Duties Failure", "red", "Agent may recommend, approve, execute, or close without separation."
    if recert != "yes":
        return score, "Access Recertification Required", "orange", "Agent access review cadence is missing."
    if telemetry != "yes":
        return score, "Access Not Observable", "red", "Agent entitlement cannot be monitored or attributed."
    if score == 100:
        return score, "Agent Identity Trusted", "green", "Agent identity, owner, account, entitlement, MyAccess route, SoD, recertification, and telemetry controls are ready."
    return score, "Conditional Identity Trust", "yellow", "Agent may operate only with restrictions and remediation tracking."


try:
    AGENTTRUST_EXPECTED_ROUTES.extend([
        "/citrust/agent-identity-entitlement-governance",
        "/citrust/agent-identity-register",
        "/citrust/agent-service-account-map",
        "/citrust/agent-least-privilege-gate",
        "/citrust/agent-myaccess-entitlement-map",
        "/citrust/agent-cyberark-psm-gate",
        "/citrust/agent-segregation-of-duties",
        "/citrust/agent-entitlement-review",
        "/citrust/agent-identity-simulator",
        "/citrust/agent-identity-json"
    ])
except Exception:
    pass


@app.route("/citrust/agent-identity-entitlement-governance")
@app.route("/citrust/ai-agent-identity-governance")
@app.route("/citrust/agent-entitlement-governance")
def citrust_agent_identity_entitlement_governance():
    rows = citrust_agent_identity_domain_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Agent Identity</div><div class="value" style="color:var(--green);">Governed</div><div class="note">AI agents treated as controlled digital actors.</div></div>
        <div class="metric"><div class="label">Identity Domains</div><div class="value" style="color:var(--blue);">8</div><div class="note">Identity, owner, service account, entitlement, MyAccess, CyberArk, SoD, review.</div></div>
        <div class="metric"><div class="label">Least Privilege</div><div class="value" style="color:var(--yellow);">Required</div><div class="note">Only approved use-case access is allowed.</div></div>
        <div class="metric"><div class="label">CyberArk / PSM</div><div class="value" style="color:var(--red);">Gated</div><div class="note">Privileged context requires cyber evidence.</div></div>
        <div class="metric"><div class="label">MyAccess</div><div class="value" style="color:var(--orange);">Mapped</div><div class="note">Entitlement route and approver group required.</div></div>
        <div class="metric"><div class="label">Review Cadence</div><div class="value" style="color:var(--purple);">Certified</div><div class="note">Agent access must be periodically recertified.</div></div>
    </section>

    <section class="section">
        <h2>CITrust™ Agent Identity & Entitlement Governance Center</h2>
        <div class="answer">
            <strong>Purpose:</strong> ensure every AI agent that touches ServiceNow, CMDB, MyAccess, CyberArk, PSM,
            support groups, change workflows, or GMP-impacting records has a governed identity, accountable owner,
            controlled entitlement, least-privilege boundary, review cadence, and audit trail.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Domain ID</th>
                    <th>Identity Domain</th>
                    <th>Governance Question</th>
                    <th>Required Evidence</th>
                    <th>Risk If Missing</th>
                    <th>Default Decision</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Identity Governance Rule</h2>
        <div class="answer">
            An AI agent must not be treated as an invisible system process. CITrust™ treats agents like governed
            non-human identities with owner, entitlement, least privilege, access review, privileged route, and telemetry.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agent Identity Entitlement Governance",
        "Agent identity and entitlement governance for ServiceNow, CMDB, MyAccess, CyberArk, PSM, access routes, support groups, GxP workflows, and change control.",
        body
    )


@app.route("/citrust/agent-identity-register")
@app.route("/citrust/ai-agent-identity-register")
@app.route("/citrust/citrust-agent-identity-register")
def citrust_agent_identity_register():
    rows = citrust_agent_identity_domain_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agent Identity Register</h2>
        <p>
            This register defines the minimum identity fields required before an AI agent can interact with CITrust™ or ServiceNow workflows.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Domain ID</th>
                    <th>Domain</th>
                    <th>Governance Question</th>
                    <th>Required Evidence</th>
                    <th>Risk</th>
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
        "CITrust™ Agent Identity Register",
        "Identity register for AI agents touching CITrust™, ServiceNow CMDB, CI records, access routes, CyberArk, GxP metadata, and change-control workflows.",
        body
    )


@app.route("/citrust/agent-service-account-map")
@app.route("/citrust/ai-agent-service-account-map")
@app.route("/citrust/agent-non-human-identity-map")
def citrust_agent_service_account_map():
    rows = citrust_service_account_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agent Service Account Map</h2>
        <p>
            This map connects AI agents to the actual non-human identities, service accounts, app registrations, and integration users they operate through.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Identity Type</th>
                    <th>Used For</th>
                    <th>Required Controls</th>
                    <th>Risk</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Service Account Rule</h2>
        <div class="answer">
            Every AI agent action must be attributable to a governed identity. Shared, unknown, or ownerless service
            accounts are not acceptable for regulated or access-impacting workflows.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agent Service Account Map",
        "Service account and non-human identity map for Azure managed identities, app registrations, ServiceNow integration users, CyberArk accounts, MyAccess entitlements, and vendor AI identities.",
        body
    )


@app.route("/citrust/agent-least-privilege-gate")
@app.route("/citrust/ai-agent-least-privilege")
@app.route("/citrust/agent-access-scope-gate")
def citrust_agent_least_privilege_gate():
    rows = citrust_least_privilege_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agent Least Privilege Gate</h2>
        <p>
            The least-privilege gate determines whether agent access is limited to what the approved use case requires.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Gate ID</th>
                    <th>Least-Privilege Gate</th>
                    <th>Question</th>
                    <th>Required Evidence</th>
                    <th>Block Condition</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Least-Privilege Rule</h2>
        <div class="answer">
            AI agents should not receive broad access because they are useful. Access must be scoped by purpose,
            action type, CI field boundary, GxP boundary, cyber boundary, expiry, and telemetry.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agent Least Privilege Gate",
        "Least-privilege gate for AI agent purpose fit, read/write boundary, CI field boundary, GxP boundary, cyber boundary, time-bound access, and telemetry.",
        body
    )


@app.route("/citrust/agent-myaccess-entitlement-map")
@app.route("/citrust/ai-agent-myaccess-map")
@app.route("/citrust/myaccess-agent-entitlement-map")
def citrust_agent_myaccess_entitlement_map():
    rows = citrust_myaccess_entitlement_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agent MyAccess Entitlement Map</h2>
        <p>
            This map defines how AI agent access should route through MyAccess, approver groups, access owners, and cyber / QA routes.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Entitlement Area</th>
                    <th>Agent Mode</th>
                    <th>Approval Route</th>
                    <th>Evidence</th>
                    <th>Default Position</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>MyAccess Rule</h2>
        <div class="answer">
            CITrust™ should know which MyAccess route, approver group, access owner, and entitlement scope applies
            before an AI agent can access or influence ServiceNow / CMDB workflows.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agent MyAccess Entitlement Map",
        "MyAccess entitlement map for AI agent CMDB read access, CMDB write access, support group routing, access workflows, CyberArk / PSM context, and GxP / QA workflow.",
        body
    )


@app.route("/citrust/agent-cyberark-psm-gate")
@app.route("/citrust/ai-agent-cyberark-gate")
@app.route("/citrust/agent-privileged-access-gate")
def citrust_agent_cyberark_psm_gate():
    body = """
    <section class="section">
        <h2>CITrust™ Agent CyberArk / PSM Gate</h2>
        <p>
            This gate controls AI agent interactions with privileged access, CyberArk, PSM, admin routes, and controlled sessions.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Privileged Context</th>
                    <th>Required Control</th>
                    <th>Evidence</th>
                    <th>Default Decision</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent identifies privileged route.</td><td>Cybersecurity review and CyberArk owner route.</td><td>CyberArk policy, safe, account, route evidence.</td><td><span class="badge orange">Cyber-gated recommendation</span></td></tr>
                <tr><td>Agent triggers admin workflow.</td><td>Formal action permit, change record, owner approval.</td><td>Action permit, change ID, runtime evidence.</td><td><span class="badge red">Blocked by default</span></td></tr>
                <tr><td>Agent influences PSM session.</td><td>PSM evidence and human-controlled session.</td><td>PSM session ID, user, target, approval.</td><td><span class="badge red">No autonomous privileged session</span></td></tr>
                <tr><td>Agent recommends entitlement.</td><td>Access owner and cybersecurity approval.</td><td>MyAccess request, access decision, approver.</td><td><span class="badge red">No AI approval</span></td></tr>
                <tr><td>Agent reads privileged logs.</td><td>Approved evidence use and cyber boundary.</td><td>Log source, data boundary, reviewer route.</td><td><span class="badge orange">Restricted evidence use</span></td></tr>
                <tr><td>Agent stores privileged context in memory.</td><td>Memory boundary and suppression control.</td><td>Context provenance and memory governance evidence.</td><td><span class="badge red">Suppress sensitive memory</span></td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agent CyberArk PSM Gate",
        "CyberArk and PSM gate for AI agent privileged route, admin workflow, PSM session, entitlement recommendation, privileged logs, and sensitive memory context.",
        body
    )


@app.route("/citrust/agent-segregation-of-duties")
@app.route("/citrust/ai-agent-sod")
@app.route("/citrust/agent-sod-control")
def citrust_agent_segregation_of_duties():
    rows = citrust_sod_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agent Segregation of Duties Control</h2>
        <p>
            AI agents must not collapse requester, recommender, approver, executor, reviewer, and closer into one invisible workflow.
        </p>

        <table>
            <thead>
                <tr>
                    <th>SoD Area</th>
                    <th>Rule</th>
                    <th>Evidence</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>SoD Rule</h2>
        <div class="answer">
            AI may assist, but accountability must remain separated. CITrust™ blocks hidden AI approval,
            self-execution, self-closure, access approval, QA conclusion, and exception approval.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agent Segregation of Duties",
        "Segregation of duties controls for AI agents across recommendation, approval, execution, closure, access approval, GxP assessment, and exception handling.",
        body
    )


@app.route("/citrust/agent-entitlement-review")
@app.route("/citrust/agent-access-recertification")
@app.route("/citrust/ai-agent-entitlement-review")
def citrust_agent_entitlement_review():
    rows = citrust_entitlement_review_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agent Entitlement Review</h2>
        <p>
            AI agent access must be periodically reviewed like any other controlled non-human identity.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Review Item</th>
                    <th>Review Question</th>
                    <th>Review Owner</th>
                    <th>Evidence</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Recertification Rule</h2>
        <div class="answer">
            Agent access that was valid during onboarding may become excessive later. CITrust™ requires recurring
            access recertification, removal evidence, exception review, and cyber / QA review where applicable.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agent Entitlement Review",
        "Agent entitlement review and access recertification for AI agent use case, owners, entitlements, privileged access, GxP access, and exceptions.",
        body
    )


@app.route("/citrust/agent-identity-simulator", methods=["GET", "POST"])
@app.route("/citrust/agent-entitlement-simulator", methods=["GET", "POST"])
@app.route("/citrust/ai-agent-identity-simulator", methods=["GET", "POST"])
def citrust_agent_identity_simulator():
    from flask import request

    identity = request.form.get("identity", "yes")
    owner = request.form.get("owner", "yes")
    account = request.form.get("account", "yes")
    entitlement = request.form.get("entitlement", "yes")
    privilege = request.form.get("privilege", "no")
    myaccess = request.form.get("myaccess", "yes")
    sod = request.form.get("sod", "yes")
    recert = request.form.get("recert", "yes")
    telemetry = request.form.get("telemetry", "yes")

    score, decision, badge, reason = citrust_agent_identity_decision(
        identity, owner, account, entitlement, privilege, myaccess, sod, recert, telemetry
    )

    def selected(value, expected):
        return "selected" if value == expected else ""

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Identity Trust Score</div><div class="value" style="color:var(--green);">{score}%</div><div class="note">Calculated from agent identity and entitlement controls.</div></div>
        <div class="metric"><div class="label">Identity Decision</div><div class="value" style="color:var(--yellow);">{decision}</div><div class="note">{reason}</div></div>
    </section>

    <section class="section">
        <h2>CITrust™ Agent Identity Simulator</h2>
        <p>
            Simulate whether an AI agent has enough identity, ownership, entitlement, MyAccess, CyberArk, SoD,
            recertification, and telemetry control to interact with ServiceNow / CMDB workflows.
        </p>

        <form method="POST" action="/citrust/agent-identity-simulator">
            <table>
                <tbody>
                    <tr><td><strong>Agent Identity Registered?</strong></td><td><select name="identity" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(identity, "yes")}>Yes</option><option value="no" {selected(identity, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Accountable Human Owner Assigned?</strong></td><td><select name="owner" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(owner, "yes")}>Yes</option><option value="no" {selected(owner, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Service Account / Managed Identity Mapped?</strong></td><td><select name="account" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(account, "yes")}>Yes</option><option value="no" {selected(account, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Entitlement Scope Least-Privilege?</strong></td><td><select name="entitlement" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(entitlement, "yes")}>Yes</option><option value="no" {selected(entitlement, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Privileged / Admin / CyberArk / PSM Impact Present?</strong></td><td><select name="privilege" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="no" {selected(privilege, "no")}>No</option><option value="yes" {selected(privilege, "yes")}>Yes</option></select></td></tr>
                    <tr><td><strong>MyAccess / Approver Route Governed?</strong></td><td><select name="myaccess" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(myaccess, "yes")}>Yes</option><option value="no" {selected(myaccess, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Segregation of Duties Preserved?</strong></td><td><select name="sod" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(sod, "yes")}>Yes</option><option value="no" {selected(sod, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Access Recertification Ready?</strong></td><td><select name="recert" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(recert, "yes")}>Yes</option><option value="no" {selected(recert, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Access Telemetry / Audit Trail Ready?</strong></td><td><select name="telemetry" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(telemetry, "yes")}>Yes</option><option value="no" {selected(telemetry, "no")}>No</option></select></td></tr>
                </tbody>
            </table>

            <button type="submit" style="margin-top:16px;padding:12px 18px;border-radius:12px;border:0;background:#2563eb;color:white;font-weight:800;">Run Agent Identity Trust Check</button>
        </form>
    </section>

    <section class="section">
        <h2>Agent Identity Decision</h2>
        <div class="answer">
            <strong>Score:</strong> {score}%<br>
            <strong>Decision:</strong> <span class="badge {badge}">{decision}</span><br>
            <strong>Reason:</strong> {reason}
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agent Identity Simulator",
        "Simulator for AI agent identity and entitlement trust across identity, owner, service account, entitlement, privilege, MyAccess, SoD, recertification, and telemetry.",
        body
    )


@app.route("/citrust/agent-identity-json")
@app.route("/citrust/agent-entitlement-json")
@app.route("/citrust/agent-identity-governance-json")
def citrust_agent_identity_json():
    from flask import jsonify

    return jsonify({
        "module": "CITrust™",
        "capability": "Agent Identity & Entitlement Governance Center",
        "primary_question": "Is this AI agent identity controlled enough to interact with ServiceNow, CMDB, MyAccess, CyberArk, PSM, support groups, GxP workflows, or change control?",
        "agent_identity_domains": CITRUST_AGENT_IDENTITY_DOMAINS,
        "agent_service_account_map": CITRUST_AGENT_SERVICE_ACCOUNT_MAP,
        "least_privilege_gates": CITRUST_LEAST_PRIVILEGE_GATES,
        "myaccess_agent_entitlement_map": CITRUST_MYACCESS_AGENT_ENTITLEMENT_MAP,
        "segregation_of_duties_controls": CITRUST_AGENT_SOD_CONTROLS,
        "agent_entitlement_review": CITRUST_AGENT_ENTITLEMENT_REVIEW,
        "minimum_conditions": [
            "Agent has a unique identity",
            "Agent has accountable human owner",
            "Service account, app registration, managed identity, or integration identity is mapped",
            "Entitlement scope is least-privilege",
            "MyAccess route and approver group are governed",
            "CyberArk / PSM route is enforced where privileged context exists",
            "Segregation of duties prevents hidden AI approval",
            "Access recertification cadence is defined",
            "Telemetry and audit trail attribute agent activity"
        ],
        "default_decision": "Do not allow AI agent access to ServiceNow, CMDB, access workflows, privileged context, GxP records, or change-control workflows unless identity, owner, entitlement, least privilege, MyAccess, CyberArk, SoD, recertification, and telemetry controls are complete"
    })

# ============================================================
# END CITRUST_AGENT_IDENTITY_ENTITLEMENT_GOVERNANCE_V1_ACTIVE
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

print("CITrust Agent Identity & Entitlement Governance installed.")
print(f"Inserted before: {target_found}")
