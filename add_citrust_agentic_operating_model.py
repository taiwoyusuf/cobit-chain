from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_AGENTIC_GOVERNANCE_OPERATING_MODEL_V1_ACTIVE"

if MARKER in text:
    print("CITrust Agentic Governance Operating Model already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base shell not found. Install AgentTrust base module first.")

nav_old = '<a href="/citrust/agentic-ai-assurance-control-tower" class="secondary">Agentic Tower</a>'
nav_new = '''<a href="/citrust/agentic-ai-assurance-control-tower" class="secondary">Agentic Tower</a>
                    <a href="/citrust/agentic-governance-operating-model" class="secondary">Operating Model</a>
                    <a href="/citrust/agentic-raci-authority-matrix" class="dark">RACI</a>
                    <a href="/citrust/agentic-approval-authority-map" class="dark">Authority Map</a>
                    <a href="/citrust/agentic-operating-model-simulator" class="dark">RACI Sim</a>'''

if nav_old in text and "/citrust/agentic-governance-operating-model" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# CITRUST_AGENTIC_GOVERNANCE_OPERATING_MODEL_V1_ACTIVE
# CITrust™ Agentic Governance Operating Model
# RACI Authority Matrix, Approval Authority Map,
# LCM / CMDB / QA / Cyber / Change / System Owner Roles,
# Escalation Model, Role Conflict Checker,
# Operating Model Simulator, and JSON Export
# ============================================================

CITRUST_AGENTIC_OPERATING_MODEL_ROLES = [
    {
        "role": "AI Agent Owner",
        "accountability": "Owns agent purpose, operating license, approved use case, behavior, evidence obligations, and retirement.",
        "must_approve": "Agent onboarding, use-case scope, operating boundary, exception response.",
        "cannot_approve": "GxP conclusion, access entitlement, privileged route, or ServiceNow change closure alone.",
        "evidence": "Agent registry, operating license, owner signoff, review cadence."
    },
    {
        "role": "CMDB / CI Owner",
        "accountability": "Owns CI accuracy, CI identity, ownership fields, CI passport, CI trust score, and remediation of CMDB gaps.",
        "must_approve": "CI owner changes, CI field updates, CI trust remediation, CI passport closure.",
        "cannot_approve": "Cyber access decision, QA validation conclusion, or privileged session decision.",
        "evidence": "CI passport, owner approval, field before/after, CMDB evidence."
    },
    {
        "role": "LCM Owner",
        "accountability": "Owns lifecycle management alignment, CI lifecycle state, LCM responsibility, and operational readiness ownership route.",
        "must_approve": "Lifecycle state updates, LCM assignment, ownership readiness, decommission/cutover state where applicable.",
        "cannot_approve": "QA validation status or CyberArk privileged route.",
        "evidence": "LCM assignment, lifecycle evidence, readiness review, owner signoff."
    },
    {
        "role": "System Owner / Business Owner",
        "accountability": "Owns business/operational accountability for system use, operational impact, readiness, and owner acceptance.",
        "must_approve": "Operational reliance, system readiness decision, business owner acceptance, support model alignment.",
        "cannot_approve": "Technical privileged access or QA regulated validation decision alone.",
        "evidence": "Owner decision, operational impact review, readiness acceptance."
    },
    {
        "role": "Support / Service Owner",
        "accountability": "Owns support group, assignment group, resolver routing, escalation path, and service-impact alignment.",
        "must_approve": "Support group changes, assignment group changes, resolver route changes, service map support impact.",
        "cannot_approve": "GxP validation decision or access entitlement approval alone.",
        "evidence": "Support route evidence, before/after group, support owner approval."
    },
    {
        "role": "QA / Validation Owner",
        "accountability": "Owns GxP, validation status, QA decision, inspection sensitivity, deviation/CAPA implication, and regulated evidence reliance.",
        "must_approve": "GMP class, validation metadata, QA route, regulated reliance, deviation/CAPA assessment, inspection-sensitive AI output.",
        "cannot_approve": "Cyber entitlement or privileged access route alone.",
        "evidence": "QA decision, validation evidence, GxP screen, regulated impact review."
    },
    {
        "role": "Cybersecurity / Access Owner",
        "accountability": "Owns MyAccess route, CyberArk / PSM impact, privileged context, entitlement approval, access risk, and least privilege.",
        "must_approve": "Access route, privileged route, CyberArk/PSM context, admin impact, entitlement scope, access exception.",
        "cannot_approve": "QA validation conclusion or CI business owner acceptance alone.",
        "evidence": "Cyber decision, MyAccess evidence, CyberArk/PSM evidence, access review."
    },
    {
        "role": "Change Owner",
        "accountability": "Owns ServiceNow change classification, implementation plan, impact analysis, rollback, post-check, and closure evidence.",
        "must_approve": "Material CI update, relationship update, lifecycle change, support route change, operational-state change.",
        "cannot_approve": "QA or cyber decisions without those owner inputs.",
        "evidence": "Change record, approvals, rollback, post-implementation verification."
    },
    {
        "role": "Governance / Assurance Owner",
        "accountability": "Owns CITrust control model, assurance scorecard, evidence completeness, exceptions, and executive reporting.",
        "must_approve": "Control exceptions, risk acceptance, evidence closure, assurance dossier readiness.",
        "cannot_approve": "Operational, QA, cyber, or change decision on behalf of accountable owner.",
        "evidence": "Assurance dossier, exception register, risk acceptance, executive signoff."
    }
]


CITRUST_AGENTIC_RACI_MATRIX = [
    {
        "activity": "Register AI Agent",
        "responsible": "AI Agent Owner",
        "accountable": "Governance / Assurance Owner",
        "consulted": "Cybersecurity, CMDB Owner, System Owner",
        "informed": "QA / Validation Owner where GxP impact exists",
        "evidence": "Agent registry and operating license."
    },
    {
        "activity": "Map Agent to CI",
        "responsible": "CMDB / CI Owner",
        "accountable": "LCM Owner",
        "consulted": "System Owner, Support Owner, AI Agent Owner",
        "informed": "QA / Cyber where regulated or access context exists",
        "evidence": "Agent-to-CI impact map and CI passport."
    },
    {
        "activity": "Approve AI Recommendation",
        "responsible": "Relevant Domain Owner",
        "accountable": "System Owner or Process Owner",
        "consulted": "CMDB, QA, Cyber, Change depending on impact",
        "informed": "Governance / Assurance Owner",
        "evidence": "Recommendation package and owner decision."
    },
    {
        "activity": "Approve CI Field Update",
        "responsible": "CMDB / CI Owner",
        "accountable": "LCM Owner or System Owner",
        "consulted": "Change Owner, QA, Cyber, Support Owner as needed",
        "informed": "Governance / Assurance Owner",
        "evidence": "Field risk, before/after, approval, change/task link."
    },
    {
        "activity": "Approve Support Group Change",
        "responsible": "Support / Service Owner",
        "accountable": "System Owner",
        "consulted": "CMDB Owner, Change Owner, Access Owner if access route changes",
        "informed": "LCM and Governance Owner",
        "evidence": "Old/new group, impact review, approval, rollback."
    },
    {
        "activity": "Approve GxP / Validation Impact",
        "responsible": "QA / Validation Owner",
        "accountable": "QA / Validation Owner",
        "consulted": "System Owner, CMDB Owner, Change Owner",
        "informed": "Governance / Assurance Owner",
        "evidence": "GxP screen, QA decision, validation evidence."
    },
    {
        "activity": "Approve Access / Cyber / Privileged Route",
        "responsible": "Cybersecurity / Access Owner",
        "accountable": "Cybersecurity / Access Owner",
        "consulted": "System Owner, Support Owner, CyberArk Owner, Change Owner",
        "informed": "Governance / Assurance Owner",
        "evidence": "MyAccess, CyberArk, PSM, entitlement, access review."
    },
    {
        "activity": "Approve Change Execution",
        "responsible": "Change Owner",
        "accountable": "System Owner / Change Authority",
        "consulted": "CMDB, QA, Cyber, Support, LCM as impact requires",
        "informed": "Governance / Assurance Owner",
        "evidence": "Change record, implementation, rollback, post-check."
    },
    {
        "activity": "Approve Exception / Risk Acceptance",
        "responsible": "Governance / Assurance Owner",
        "accountable": "Risk Owner / System Owner",
        "consulted": "QA, Cyber, Change, CMDB depending on risk",
        "informed": "Executive Owner where material",
        "evidence": "Exception ID, expiry, compensating control, owner signoff."
    }
]


CITRUST_AGENTIC_APPROVAL_AUTHORITY_MAP = [
    {
        "decision_type": "AI may read or summarize CI data",
        "minimum_authority": "AI Agent Owner + CMDB Owner approval of use case.",
        "additional_route": "QA/Cyber if regulated or access-sensitive data is included.",
        "default_position": "Allowed with logging."
    },
    {
        "decision_type": "AI may recommend CI owner or support group",
        "minimum_authority": "CMDB Owner + LCM Owner + Support/System Owner.",
        "additional_route": "Change Owner if recommendation becomes operationally binding.",
        "default_position": "Human-gated."
    },
    {
        "decision_type": "AI may recommend CI relationship",
        "minimum_authority": "CMDB Owner + Technical / Service Owner.",
        "additional_route": "Change Owner if relationship affects impact analysis or service map.",
        "default_position": "Relationship owner review."
    },
    {
        "decision_type": "AI may influence GxP or validation metadata",
        "minimum_authority": "QA / Validation Owner.",
        "additional_route": "Change Owner if metadata becomes controlled record update.",
        "default_position": "QA-governed only."
    },
    {
        "decision_type": "AI may influence MyAccess, CyberArk, PSM, or entitlement",
        "minimum_authority": "Cybersecurity / Access Owner.",
        "additional_route": "CyberArk Owner, System Owner, Change Owner as needed.",
        "default_position": "Cyber-gated only."
    },
    {
        "decision_type": "AI may update CI field or trigger workflow",
        "minimum_authority": "CMDB Owner + System Owner + Change Owner.",
        "additional_route": "QA/Cyber if regulated or access impact exists.",
        "default_position": "Blocked unless formally approved."
    },
    {
        "decision_type": "AI may approve, reject, or close accountable decision",
        "minimum_authority": "Human accountable owner only.",
        "additional_route": "Governance signoff for evidence closure.",
        "default_position": "Prohibited for autonomous AI."
    }
]


CITRUST_AGENTIC_ESCALATION_MODEL = [
    {
        "trigger": "Unknown agent or ownerless agent",
        "escalate_to": "AI Agent Owner / Governance Owner",
        "action": "Block operation until agent identity and owner are registered.",
        "evidence": "Agent registry update and owner signoff."
    },
    {
        "trigger": "Ownerless CI or incomplete CI passport",
        "escalate_to": "CMDB Owner / LCM Owner",
        "action": "Create remediation task and block AI reliance.",
        "evidence": "CI passport remediation and owner assignment."
    },
    {
        "trigger": "GxP / validation uncertainty",
        "escalate_to": "QA / Validation Owner",
        "action": "Restrict AI output from regulated reliance until QA decision.",
        "evidence": "QA review, validation evidence, GxP decision."
    },
    {
        "trigger": "Access, MyAccess, CyberArk, PSM, privileged context",
        "escalate_to": "Cybersecurity / Access Owner",
        "action": "Block autonomous access action and require cyber approval.",
        "evidence": "Cyber decision, entitlement record, privileged session evidence."
    },
    {
        "trigger": "Material CI update or workflow trigger",
        "escalate_to": "Change Owner",
        "action": "Route to change/task with rollback and post-check.",
        "evidence": "Change record, approval, rollback, post-check."
    },
    {
        "trigger": "Conflicting agent outputs",
        "escalate_to": "Governance Owner + Relevant Domain Owner",
        "action": "Stop automation and require reconciliation.",
        "evidence": "Conflict record, accepted output, rejected output, rationale."
    },
    {
        "trigger": "Wrong AI output with possible regulated impact",
        "escalate_to": "QA / Risk Owner",
        "action": "Assess deviation/CAPA need and suppress unsafe memory.",
        "evidence": "Impact assessment, correction workflow, QA closure."
    }
]


CITRUST_AGENTIC_ROLE_CONFLICTS = [
    {
        "conflict": "AI recommends and approves same action",
        "risk": "Hidden AI approval.",
        "required_control": "Human accountable owner approval.",
        "default_decision": "Block."
    },
    {
        "conflict": "AI executes and closes without post-check",
        "risk": "No independent verification.",
        "required_control": "Post-action verification and closure owner signoff.",
        "default_decision": "Do not close."
    },
    {
        "conflict": "Agent owner approves own high-risk exception",
        "risk": "Self-approved risk acceptance.",
        "required_control": "Governance owner and risk owner approval.",
        "default_decision": "Escalate."
    },
    {
        "conflict": "CMDB owner changes GxP metadata without QA",
        "risk": "Regulated metadata bypass.",
        "required_control": "QA / validation owner decision.",
        "default_decision": "QA-governed block."
    },
    {
        "conflict": "Support owner changes access route without cyber",
        "risk": "Access governance bypass.",
        "required_control": "Cybersecurity / access owner approval.",
        "default_decision": "Cyber-gated block."
    },
    {
        "conflict": "Change owner closes action without domain owner acceptance",
        "risk": "Operational owner not accountable for final state.",
        "required_control": "System owner / domain owner signoff.",
        "default_decision": "Closure incomplete."
    }
]


def citrust_operating_model_role_rows():
    rows = ""
    for item in CITRUST_AGENTIC_OPERATING_MODEL_ROLES:
        rows += f"""
        <tr>
            <td><strong>{item["role"]}</strong></td>
            <td>{item["accountability"]}</td>
            <td>{item["must_approve"]}</td>
            <td><span class="badge red">{item["cannot_approve"]}</span></td>
            <td>{item["evidence"]}</td>
        </tr>
        """
    return rows


def citrust_raci_rows():
    rows = ""
    for item in CITRUST_AGENTIC_RACI_MATRIX:
        rows += f"""
        <tr>
            <td><strong>{item["activity"]}</strong></td>
            <td>{item["responsible"]}</td>
            <td><span class="badge blue">{item["accountable"]}</span></td>
            <td>{item["consulted"]}</td>
            <td>{item["informed"]}</td>
            <td>{item["evidence"]}</td>
        </tr>
        """
    return rows


def citrust_approval_authority_rows():
    rows = ""
    for item in CITRUST_AGENTIC_APPROVAL_AUTHORITY_MAP:
        badge = "green"
        if "Prohibited" in item["default_position"] or "Blocked" in item["default_position"]:
            badge = "red"
        elif "gated" in item["default_position"].lower() or "governed" in item["default_position"].lower():
            badge = "orange"
        elif "review" in item["default_position"].lower():
            badge = "yellow"

        rows += f"""
        <tr>
            <td><strong>{item["decision_type"]}</strong></td>
            <td>{item["minimum_authority"]}</td>
            <td>{item["additional_route"]}</td>
            <td><span class="badge {badge}">{item["default_position"]}</span></td>
        </tr>
        """
    return rows


def citrust_escalation_rows():
    rows = ""
    for item in CITRUST_AGENTIC_ESCALATION_MODEL:
        rows += f"""
        <tr>
            <td><strong>{item["trigger"]}</strong></td>
            <td><span class="badge orange">{item["escalate_to"]}</span></td>
            <td>{item["action"]}</td>
            <td>{item["evidence"]}</td>
        </tr>
        """
    return rows


def citrust_role_conflict_rows():
    rows = ""
    for item in CITRUST_AGENTIC_ROLE_CONFLICTS:
        rows += f"""
        <tr>
            <td><strong>{item["conflict"]}</strong></td>
            <td><span class="badge red">{item["risk"]}</span></td>
            <td>{item["required_control"]}</td>
            <td><span class="badge orange">{item["default_decision"]}</span></td>
        </tr>
        """
    return rows


def citrust_operating_model_decision(agent_owner, ci_owner, lcm, qa, cyber, change, sod, escalation, evidence):
    checks = [agent_owner, ci_owner, lcm, qa, cyber, change, sod, escalation, evidence]
    score = int((sum(1 for item in checks if item == "yes") / len(checks)) * 100)

    if agent_owner != "yes":
        return score, "Block Agentic Governance", "red", "AI agent owner is missing."
    if ci_owner != "yes":
        return score, "CI Ownership Gap", "red", "CI owner or CMDB accountability is missing."
    if lcm != "yes":
        return score, "LCM Route Required", "orange", "LCM owner or lifecycle responsibility is not assigned."
    if qa != "yes":
        return score, "QA Route Gap", "orange", "QA / validation approval route is not defined for regulated impact."
    if cyber != "yes":
        return score, "Cyber Route Gap", "orange", "Cybersecurity / access approval route is not defined for access or privileged impact."
    if change != "yes":
        return score, "Change Authority Gap", "red", "Change owner route, rollback, and post-check authority are incomplete."
    if sod != "yes":
        return score, "Segregation of Duties Failure", "red", "AI or one owner may recommend, approve, execute, and close without separation."
    if escalation != "yes":
        return score, "Escalation Model Required", "orange", "Escalation route is not defined for exceptions, conflicts, or missing evidence."
    if evidence != "yes":
        return score, "Evidence Signoff Gap", "red", "Owner decisions and signoff evidence are incomplete."
    if score == 100:
        return score, "Operating Model Ready", "green", "Roles, RACI, authority, escalation, SoD, and evidence signoff are ready."
    return score, "Conditional Operating Model", "yellow", "Operating model may proceed only with restrictions and remediation tracking."


try:
    AGENTTRUST_EXPECTED_ROUTES.extend([
        "/citrust/agentic-governance-operating-model",
        "/citrust/agentic-raci-authority-matrix",
        "/citrust/agentic-approval-authority-map",
        "/citrust/agentic-escalation-model",
        "/citrust/agentic-role-conflict-checker",
        "/citrust/lcm-agentic-approval-model",
        "/citrust/qa-cyber-change-approval-map",
        "/citrust/agentic-operating-model-simulator",
        "/citrust/agentic-operating-model-json"
    ])
except Exception:
    pass


@app.route("/citrust/agentic-governance-operating-model")
@app.route("/citrust/agentic-operating-model")
@app.route("/citrust/ci-agentic-operating-model")
def citrust_agentic_governance_operating_model():
    rows = citrust_operating_model_role_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Operating Model</div><div class="value" style="color:var(--green);">Active</div><div class="note">Agentic governance roles and authorities defined.</div></div>
        <div class="metric"><div class="label">Core Roles</div><div class="value" style="color:var(--blue);">9</div><div class="note">Agent, CMDB, LCM, system, support, QA, cyber, change, governance.</div></div>
        <div class="metric"><div class="label">RACI</div><div class="value" style="color:var(--yellow);">Mapped</div><div class="note">Responsible, accountable, consulted, informed defined.</div></div>
        <div class="metric"><div class="label">SoD</div><div class="value" style="color:var(--red);">Protected</div><div class="note">AI cannot approve or close its own action.</div></div>
        <div class="metric"><div class="label">Escalation</div><div class="value" style="color:var(--orange);">Routed</div><div class="note">Unknown agent, GxP, cyber, change, conflict, exception routed.</div></div>
        <div class="metric"><div class="label">Signoff</div><div class="value" style="color:var(--purple);">Evidence-Based</div><div class="note">Owner decisions must leave evidence.</div></div>
    </section>

    <section class="section">
        <h2>CITrust™ Agentic Governance Operating Model</h2>
        <div class="answer">
            <strong>Purpose:</strong> define who owns, approves, reviews, escalates, blocks, and signs off when AI agents
            interact with ServiceNow CMDB, CIs, support groups, MyAccess, CyberArk, PSM, GxP metadata, change records,
            cutover-sensitive workflows, or operational readiness decisions.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Role</th>
                    <th>Accountability</th>
                    <th>Must Approve</th>
                    <th>Cannot Approve Alone</th>
                    <th>Evidence</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Operating Model Rule</h2>
        <div class="answer">
            AI agents can assist, recommend, route, and summarize, but accountability remains with named human owners.
            CITrust™ separates agent ownership, CI ownership, QA, cyber, change, support, LCM, and governance authority.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Governance Operating Model",
        "Operating model for AI agent governance across ServiceNow CMDB, CI ownership, LCM, support, QA, cyber, change, MyAccess, CyberArk, GxP, and evidence signoff.",
        body
    )


@app.route("/citrust/agentic-raci-authority-matrix")
@app.route("/citrust/agentic-raci-matrix")
@app.route("/citrust/ci-agentic-raci")
def citrust_agentic_raci_authority_matrix():
    rows = citrust_raci_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agentic RACI Authority Matrix</h2>
        <p>
            This matrix defines who is responsible, accountable, consulted, and informed for AI-assisted CITrust™ workflows.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Activity</th>
                    <th>Responsible</th>
                    <th>Accountable</th>
                    <th>Consulted</th>
                    <th>Informed</th>
                    <th>Evidence</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic RACI Authority Matrix",
        "RACI authority matrix for AI agent registration, agent-to-CI mapping, recommendations, CI field updates, support group changes, GxP impact, access impact, change execution, and exceptions.",
        body
    )


@app.route("/citrust/agentic-approval-authority-map")
@app.route("/citrust/agentic-authority-map")
@app.route("/citrust/ci-agentic-approval-map")
def citrust_agentic_approval_authority_map():
    rows = citrust_approval_authority_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agentic Approval Authority Map</h2>
        <p>
            This map defines the minimum authority needed before AI output can become operationally binding.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Decision Type</th>
                    <th>Minimum Authority</th>
                    <th>Additional Route</th>
                    <th>Default Position</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Approval Authority Map",
        "Approval authority map for AI-assisted CI read, summary, recommendation, relationship, GxP, access, CI update, workflow trigger, approval, rejection, and closure decisions.",
        body
    )


@app.route("/citrust/agentic-escalation-model")
@app.route("/citrust/agentic-escalation-router")
@app.route("/citrust/ci-agentic-escalation-model")
def citrust_agentic_escalation_model():
    rows = citrust_escalation_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agentic Escalation Model</h2>
        <p>
            This model routes missing evidence, conflicts, exceptions, regulated impact, cyber impact, and change impact to the correct owner.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Escalation Trigger</th>
                    <th>Escalate To</th>
                    <th>Action</th>
                    <th>Evidence</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Escalation Model",
        "Escalation model for unknown agents, ownerless CIs, GxP uncertainty, cyber impact, change impact, conflicting outputs, and wrong AI output with regulated impact.",
        body
    )


@app.route("/citrust/agentic-role-conflict-checker")
@app.route("/citrust/agentic-sod-conflict-checker")
@app.route("/citrust/ci-agentic-role-conflicts")
def citrust_agentic_role_conflict_checker():
    rows = citrust_role_conflict_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agentic Role Conflict Checker</h2>
        <p>
            This checker identifies role conflicts where AI or a single actor collapses recommendation, approval, execution, and closure.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Conflict</th>
                    <th>Risk</th>
                    <th>Required Control</th>
                    <th>Default Decision</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Conflict Rule</h2>
        <div class="answer">
            CITrust™ blocks hidden AI approval, self-execution, self-closure, QA bypass, cyber bypass, and change closure
            without domain owner acceptance.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Role Conflict Checker",
        "Role conflict checker for AI-assisted recommendation, approval, execution, closure, QA metadata, cyber access, and change-control workflows.",
        body
    )


@app.route("/citrust/lcm-agentic-approval-model")
@app.route("/citrust/lcm-ai-approval-model")
@app.route("/citrust/agentic-lcm-approval")
def citrust_lcm_agentic_approval_model():
    body = """
    <section class="section">
        <h2>CITrust™ LCM Agentic Approval Model</h2>
        <p>
            This page defines when LCM must approve AI-assisted CI lifecycle, ownership, readiness, or operational state decisions.
        </p>

        <table>
            <thead>
                <tr>
                    <th>LCM Decision Area</th>
                    <th>LCM Approval Needed When</th>
                    <th>Consulted Owner</th>
                    <th>Evidence</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>LCM assignment</td><td>AI recommends or changes LCM ownership.</td><td>CMDB Owner / System Owner.</td><td>LCM assignment evidence and approval.</td></tr>
                <tr><td>Lifecycle state</td><td>AI influences install, operational, retire, decommission, or cutover state.</td><td>System Owner / Change Owner.</td><td>Lifecycle evidence, change record, rollback.</td></tr>
                <tr><td>Operational readiness</td><td>AI output affects readiness conclusion for CI or system.</td><td>System Owner / QA / Support Owner.</td><td>Readiness scorecard and owner acceptance.</td></tr>
                <tr><td>Owner remediation</td><td>AI identifies orphaned or ownerless CI.</td><td>CMDB Owner / Business Owner.</td><td>Remediation task and owner update.</td></tr>
                <tr><td>Cutover-sensitive CI</td><td>AI recommendation affects go-live, migration, support, or rollback readiness.</td><td>Cutover Owner / QA / Change Owner.</td><td>Cutover risk, rollback, post-check, owner signoff.</td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ LCM Agentic Approval Model",
        "LCM approval model for AI-assisted CI lifecycle, LCM assignment, operational readiness, owner remediation, and cutover-sensitive CI decisions.",
        body
    )


@app.route("/citrust/qa-cyber-change-approval-map")
@app.route("/citrust/qa-cyber-change-map")
@app.route("/citrust/agentic-qa-cyber-change-map")
def citrust_qa_cyber_change_approval_map():
    body = """
    <section class="section">
        <h2>CITrust™ QA / Cyber / Change Approval Map</h2>
        <p>
            This map separates regulated, cyber, and change-control authority for AI-assisted CI actions.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Impact Type</th>
                    <th>Approval Owner</th>
                    <th>Required Evidence</th>
                    <th>Default Decision</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>GMP / validation / QA metadata.</td><td>QA / Validation Owner.</td><td>GxP screen, validation evidence, QA decision.</td><td><span class="badge red">QA-governed</span></td></tr>
                <tr><td>Access / entitlement / MyAccess route.</td><td>Cybersecurity / Access Owner.</td><td>MyAccess record, approver group, entitlement decision.</td><td><span class="badge red">Cyber-gated</span></td></tr>
                <tr><td>CyberArk / PSM / privileged route.</td><td>Cybersecurity / CyberArk Owner.</td><td>CyberArk policy, PSM route, session evidence.</td><td><span class="badge red">Privileged block unless approved</span></td></tr>
                <tr><td>Material CI update.</td><td>Change Owner + CI/System Owner.</td><td>Change record, before/after, rollback, post-check.</td><td><span class="badge orange">Change-controlled</span></td></tr>
                <tr><td>Support group / assignment route.</td><td>Support / Service Owner.</td><td>Support impact, old/new group, owner approval.</td><td><span class="badge yellow">Owner-gated</span></td></tr>
                <tr><td>Exception / temporary workaround.</td><td>Risk Owner / Governance Owner.</td><td>Exception ID, expiry, compensating control, closure plan.</td><td><span class="badge orange">Time-bound exception</span></td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ QA Cyber Change Approval Map",
        "Approval map separating QA, cybersecurity, CyberArk, PSM, change, support, risk, and governance authority for AI-assisted CITrust workflows.",
        body
    )


@app.route("/citrust/agentic-operating-model-simulator", methods=["GET", "POST"])
@app.route("/citrust/agentic-raci-simulator", methods=["GET", "POST"])
@app.route("/citrust/ci-agentic-operating-model-simulator", methods=["GET", "POST"])
def citrust_agentic_operating_model_simulator():
    from flask import request

    agent_owner = request.form.get("agent_owner", "yes")
    ci_owner = request.form.get("ci_owner", "yes")
    lcm = request.form.get("lcm", "yes")
    qa = request.form.get("qa", "yes")
    cyber = request.form.get("cyber", "yes")
    change = request.form.get("change", "yes")
    sod = request.form.get("sod", "yes")
    escalation = request.form.get("escalation", "yes")
    evidence = request.form.get("evidence", "yes")

    score, decision, badge, reason = citrust_operating_model_decision(
        agent_owner, ci_owner, lcm, qa, cyber, change, sod, escalation, evidence
    )

    def selected(value, expected):
        return "selected" if value == expected else ""

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Operating Model Score</div><div class="value" style="color:var(--green);">{score}%</div><div class="note">Calculated from RACI and authority readiness.</div></div>
        <div class="metric"><div class="label">Governance Decision</div><div class="value" style="color:var(--yellow);">{decision}</div><div class="note">{reason}</div></div>
    </section>

    <section class="section">
        <h2>CITrust™ Agentic Operating Model Simulator</h2>
        <p>
            Simulate whether the roles, authority, escalation, segregation of duties, and signoff model are ready
            for AI-assisted ServiceNow / CMDB / GxP / cyber / change workflows.
        </p>

        <form method="POST" action="/citrust/agentic-operating-model-simulator">
            <table>
                <tbody>
                    <tr><td><strong>AI Agent Owner Assigned?</strong></td><td><select name="agent_owner" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(agent_owner, "yes")}>Yes</option><option value="no" {selected(agent_owner, "no")}>No</option></select></td></tr>
                    <tr><td><strong>CI / CMDB Owner Assigned?</strong></td><td><select name="ci_owner" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(ci_owner, "yes")}>Yes</option><option value="no" {selected(ci_owner, "no")}>No</option></select></td></tr>
                    <tr><td><strong>LCM Route Ready?</strong></td><td><select name="lcm" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(lcm, "yes")}>Yes</option><option value="no" {selected(lcm, "no")}>No</option></select></td></tr>
                    <tr><td><strong>QA / Validation Route Ready?</strong></td><td><select name="qa" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(qa, "yes")}>Yes</option><option value="no" {selected(qa, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Cyber / Access Route Ready?</strong></td><td><select name="cyber" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(cyber, "yes")}>Yes</option><option value="no" {selected(cyber, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Change Owner Route Ready?</strong></td><td><select name="change" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(change, "yes")}>Yes</option><option value="no" {selected(change, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Segregation of Duties Preserved?</strong></td><td><select name="sod" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(sod, "yes")}>Yes</option><option value="no" {selected(sod, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Escalation Model Ready?</strong></td><td><select name="escalation" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(escalation, "yes")}>Yes</option><option value="no" {selected(escalation, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Owner Signoff Evidence Ready?</strong></td><td><select name="evidence" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(evidence, "yes")}>Yes</option><option value="no" {selected(evidence, "no")}>No</option></select></td></tr>
                </tbody>
            </table>

            <button type="submit" style="margin-top:16px;padding:12px 18px;border-radius:12px;border:0;background:#2563eb;color:white;font-weight:800;">Run Operating Model Check</button>
        </form>
    </section>

    <section class="section">
        <h2>Operating Model Decision</h2>
        <div class="answer">
            <strong>Score:</strong> {score}%<br>
            <strong>Decision:</strong> <span class="badge {badge}">{decision}</span><br>
            <strong>Reason:</strong> {reason}
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Operating Model Simulator",
        "Simulator for CITrust agentic governance operating model readiness across agent owner, CI owner, LCM, QA, cyber, change, SoD, escalation, and evidence signoff.",
        body
    )


@app.route("/citrust/agentic-operating-model-json")
@app.route("/citrust/agentic-raci-json")
@app.route("/citrust/ci-agentic-operating-model-json")
def citrust_agentic_operating_model_json():
    from flask import jsonify

    return jsonify({
        "module": "CITrust™",
        "capability": "Agentic Governance Operating Model + RACI Authority Matrix",
        "primary_question": "Who owns, approves, reviews, escalates, blocks, and signs off AI-assisted ServiceNow / CMDB / GxP / cyber / change workflows?",
        "roles": CITRUST_AGENTIC_OPERATING_MODEL_ROLES,
        "raci_matrix": CITRUST_AGENTIC_RACI_MATRIX,
        "approval_authority_map": CITRUST_AGENTIC_APPROVAL_AUTHORITY_MAP,
        "escalation_model": CITRUST_AGENTIC_ESCALATION_MODEL,
        "role_conflicts": CITRUST_AGENTIC_ROLE_CONFLICTS,
        "minimum_conditions": [
            "AI agent owner is assigned",
            "CI / CMDB owner is assigned",
            "LCM owner route is defined",
            "System / business owner route is defined",
            "Support / service owner route is defined",
            "QA / validation route is defined for regulated impact",
            "Cybersecurity / access route is defined for access and privileged impact",
            "Change owner route is defined for material CI impact",
            "Governance / assurance owner route is defined for exceptions and evidence closure",
            "Segregation of duties prevents hidden AI approval",
            "Escalation model exists for gaps, conflicts, and unsafe outputs",
            "Owner decision and signoff evidence are captured"
        ],
        "default_decision": "Do not allow AI-assisted CITrust workflows to become operationally binding unless RACI, authority, escalation, SoD, and owner signoff evidence are complete"
    })

# ============================================================
# END CITRUST_AGENTIC_GOVERNANCE_OPERATING_MODEL_V1_ACTIVE
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

print("CITrust Agentic Governance Operating Model installed.")
print(f"Inserted before: {target_found}")
