from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_AGENTIC_CHANGE_CONTROL_GATE_V1_ACTIVE"

if MARKER in text:
    print("CITrust Agentic Change-Control Gate already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base shell not found. Install AgentTrust base module first.")

nav_old = '<a href="/citrust/cmdb-graph-trust-score" class="secondary">Graph Trust Score</a>'
nav_new = '''<a href="/citrust/cmdb-graph-trust-score" class="secondary">Graph Trust Score</a>
                    <a href="/citrust/agentic-change-control-gate" class="secondary">AI Change Gate</a>
                    <a href="/citrust/ci-agent-action-permit" class="dark">Action Permit</a>
                    <a href="/citrust/agentic-rollback-assurance" class="dark">Rollback</a>
                    <a href="/citrust/agentic-change-simulator" class="dark">Change Sim</a>'''

if nav_old in text and "/citrust/agentic-change-control-gate" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# CITRUST_AGENTIC_CHANGE_CONTROL_GATE_V1_ACTIVE
# CITrust™ Agentic Change-Control Gate,
# AI CI Update Permit Engine, CI Field Change Risk Matrix,
# Agentic CI Action Permit Register, Rollback Assurance Matrix,
# Human Approval Gate, AI CMDB Update Preflight,
# Agentic Change Simulator, and JSON Export
# ============================================================

CITRUST_AGENTIC_CI_FIELD_RISK = [
    {
        "field_group": "CI Ownership Fields",
        "examples": "Business owner, technical owner, CI owner, LCM, CMDB contact.",
        "risk": "High",
        "ai_allowed_mode": "Recommend only",
        "required_approval": "LCM / CMDB owner / business owner review.",
        "change_control": "Required when ownership affects support, accountability, or regulated operation."
    },
    {
        "field_group": "Support / Assignment Fields",
        "examples": "Support group, assignment group, resolver group, MyAccess approver group.",
        "risk": "Critical",
        "ai_allowed_mode": "Recommend and route only",
        "required_approval": "Support owner, access owner, cybersecurity where access route is affected.",
        "change_control": "Required when support or access routing changes."
    },
    {
        "field_group": "GxP / Validation Fields",
        "examples": "GMP class, validation status, QA owner, validation owner, regulated impact flag.",
        "risk": "Critical",
        "ai_allowed_mode": "No autonomous update",
        "required_approval": "QA / validation owner.",
        "change_control": "Required before any regulated metadata change."
    },
    {
        "field_group": "Lifecycle / Operational State",
        "examples": "Lifecycle state, operational status, install status, decommission state.",
        "risk": "Critical",
        "ai_allowed_mode": "No autonomous update",
        "required_approval": "System owner, LCM, change owner, QA if regulated.",
        "change_control": "Required before operational-state change."
    },
    {
        "field_group": "CI Relationships",
        "examples": "Depends on, runs on, hosted on, supports, application service, business service.",
        "risk": "High",
        "ai_allowed_mode": "Recommend relationship only",
        "required_approval": "Technical owner, service owner, application owner.",
        "change_control": "Required when relationship affects impact analysis or support routing."
    },
    {
        "field_group": "Access / Cyber Route Fields",
        "examples": "MyAccess route, CyberArk/PSM requirement, privileged access flag, admin route.",
        "risk": "Critical",
        "ai_allowed_mode": "Cyber-gated recommendation only",
        "required_approval": "Cybersecurity / access owner / CyberArk owner.",
        "change_control": "Required for access-routing or privileged-impact changes."
    },
    {
        "field_group": "Evidence / Documentation Fields",
        "examples": "Knowledge article link, validation evidence link, SOP/GSOP link, change evidence, owner notes.",
        "risk": "Medium",
        "ai_allowed_mode": "Draft or suggest",
        "required_approval": "Document owner, QA owner if regulated evidence.",
        "change_control": "Required if evidence changes regulated interpretation."
    },
    {
        "field_group": "Non-critical Descriptive Fields",
        "examples": "Description, comments, non-regulated notes, tags.",
        "risk": "Medium",
        "ai_allowed_mode": "Draft with human review",
        "required_approval": "CI owner or CMDB reviewer.",
        "change_control": "May be lightweight unless regulated or operationally material."
    }
]


CITRUST_AGENTIC_ACTION_PERMITS = [
    {
        "permit_id": "CIP-001",
        "action": "Read CI",
        "agent_mode": "Allowed with logging",
        "preconditions": "Agent registered, purpose approved, CI source known.",
        "evidence_required": "Agent ID, CI ID, timestamp, purpose.",
        "default_decision": "Permit"
    },
    {
        "permit_id": "CIP-002",
        "action": "Summarize CI",
        "agent_mode": "Allowed with source trace",
        "preconditions": "CI record source and field list known.",
        "evidence_required": "Source CI, fields used, generated summary, reviewer where relied upon.",
        "default_decision": "Permit with evidence"
    },
    {
        "permit_id": "CIP-003",
        "action": "Recommend CI Owner / Support Group",
        "agent_mode": "Recommendation-only",
        "preconditions": "Existing owner/support evidence, orphan status, LCM route, support route.",
        "evidence_required": "Recommendation rationale, source fields, reviewer, final decision.",
        "default_decision": "Human-gated"
    },
    {
        "permit_id": "CIP-004",
        "action": "Recommend CI Relationship",
        "agent_mode": "Recommendation-only",
        "preconditions": "Source and target CIs known, relationship confidence evidence available.",
        "evidence_required": "Source CI, target CI, relationship type, confidence basis, owner approval.",
        "default_decision": "Human-gated"
    },
    {
        "permit_id": "CIP-005",
        "action": "Update CI Field",
        "agent_mode": "Blocked by default",
        "preconditions": "Change-control record, owner approval, rollback, impact route.",
        "evidence_required": "Change record, approval, field before/after, rollback, post-check.",
        "default_decision": "Block unless formally approved"
    },
    {
        "permit_id": "CIP-006",
        "action": "Update GxP / Validation Metadata",
        "agent_mode": "Prohibited for autonomous AI",
        "preconditions": "QA / validation decision and change-control approval.",
        "evidence_required": "QA decision, validation evidence, change record, owner signoff.",
        "default_decision": "QA-governed block"
    },
    {
        "permit_id": "CIP-007",
        "action": "Update Access / Cyber Route",
        "agent_mode": "Prohibited for autonomous AI",
        "preconditions": "Cybersecurity approval, access owner approval, change record.",
        "evidence_required": "Cyber decision, MyAccess/CyberArk route evidence, approval, rollback.",
        "default_decision": "Cyber-gated block"
    },
    {
        "permit_id": "CIP-008",
        "action": "Trigger Workflow or Change",
        "agent_mode": "Blocked by default",
        "preconditions": "Explicit action permit, process owner approval, rollback, post-action check.",
        "evidence_required": "Action permit, workflow ID, approver, runtime evidence, outcome.",
        "default_decision": "Block unless permit exists"
    }
]


CITRUST_ROLLBACK_ASSURANCE = [
    {
        "rollback_area": "Field Before / After",
        "requirement": "Capture original CI field value and proposed new value.",
        "owner": "CMDB / LCM Owner",
        "block_if_missing": "Cannot prove what changed or restore previous state."
    },
    {
        "rollback_area": "Relationship Reversal",
        "requirement": "Capture original relationship map and proposed relationship change.",
        "owner": "Technical / Service Owner",
        "block_if_missing": "Cannot reverse incorrect dependency mapping."
    },
    {
        "rollback_area": "Support Route Recovery",
        "requirement": "Capture original support group, assignment group, and access route.",
        "owner": "Support / Access Owner",
        "block_if_missing": "Incorrect support or access route may persist."
    },
    {
        "rollback_area": "GxP Metadata Reversal",
        "requirement": "Capture QA-approved prior state and approved correction path.",
        "owner": "QA / Validation Owner",
        "block_if_missing": "Regulated metadata cannot be safely corrected."
    },
    {
        "rollback_area": "Change Record Link",
        "requirement": "Link AI-influenced action to change record and post-change check.",
        "owner": "Change Owner",
        "block_if_missing": "No controlled change trace."
    },
    {
        "rollback_area": "Post-Action Verification",
        "requirement": "Confirm CI value, relationship, owner, support route, and evidence after action.",
        "owner": "CMDB / System Owner",
        "block_if_missing": "No proof that the AI-influenced action landed correctly."
    }
]


CITRUST_AGENTIC_CHANGE_GATE_RULES = [
    {
        "gate_id": "CCG-001",
        "gate": "Agent Identity Gate",
        "question": "Is the AI agent registered and approved for this CI workflow?",
        "required_evidence": "Agent registry, operating license, approved use case.",
        "block_condition": "Unknown or unlicensed AI agent."
    },
    {
        "gate_id": "CCG-002",
        "gate": "CI Trust Gate",
        "question": "Is the CI trusted enough for AI recommendation or action?",
        "required_evidence": "CI owner, support group, LCM, lifecycle state, validation status.",
        "block_condition": "Ownerless, supportless, orphaned, stale, or validation-unknown CI."
    },
    {
        "gate_id": "CCG-003",
        "gate": "Field Risk Gate",
        "question": "What field or relationship is being touched?",
        "required_evidence": "Field group, before/after, field risk tier.",
        "block_condition": "Critical field without human, cyber, QA, or change route."
    },
    {
        "gate_id": "CCG-004",
        "gate": "GxP / QA Gate",
        "question": "Does the action touch GMP, validation, QA, release, deviation, CAPA, or inspection-sensitive context?",
        "required_evidence": "GxP screen, QA owner decision, validation review.",
        "block_condition": "Regulated CI without QA / validation route."
    },
    {
        "gate_id": "CCG-005",
        "gate": "Cyber / Access Gate",
        "question": "Does the action touch support group, MyAccess route, CyberArk, PSM, admin, or privileged context?",
        "required_evidence": "Cyber route, access owner decision, privileged impact screen.",
        "block_condition": "Access-impacting change without cyber review."
    },
    {
        "gate_id": "CCG-006",
        "gate": "Change-Control Gate",
        "question": "Does the action require controlled change, impact review, or cutover alignment?",
        "required_evidence": "Change record, impact analysis, approval, implementation plan.",
        "block_condition": "Material CI change without change record."
    },
    {
        "gate_id": "CCG-007",
        "gate": "Rollback Gate",
        "question": "Can the AI-influenced change be reversed or corrected?",
        "required_evidence": "Rollback plan, prior value, post-check, recovery owner.",
        "block_condition": "No rollback or recovery path."
    },
    {
        "gate_id": "CCG-008",
        "gate": "Runtime Evidence Gate",
        "question": "Can the action be replayed from AI recommendation to final outcome?",
        "required_evidence": "Prompt, source CI, recommendation, approval, tool-call, outcome.",
        "block_condition": "Missing runtime evidence."
    }
]


def citrust_field_risk_rows():
    rows = ""
    for item in CITRUST_AGENTIC_CI_FIELD_RISK:
        badge = "yellow"
        if item["risk"] == "Critical":
            badge = "red"
        elif item["risk"] == "High":
            badge = "orange"

        rows += f"""
        <tr>
            <td><strong>{item["field_group"]}</strong></td>
            <td>{item["examples"]}</td>
            <td><span class="badge {badge}">{item["risk"]}</span></td>
            <td>{item["ai_allowed_mode"]}</td>
            <td>{item["required_approval"]}</td>
            <td>{item["change_control"]}</td>
        </tr>
        """
    return rows


def citrust_action_permit_rows():
    rows = ""
    for item in CITRUST_AGENTIC_ACTION_PERMITS:
        badge = "green"
        if "Block" in item["default_decision"] or "block" in item["default_decision"]:
            badge = "red"
        elif "gated" in item["default_decision"].lower() or "governed" in item["default_decision"].lower():
            badge = "orange"
        elif "evidence" in item["default_decision"].lower():
            badge = "yellow"

        rows += f"""
        <tr>
            <td><strong>{item["permit_id"]}</strong></td>
            <td>{item["action"]}</td>
            <td>{item["agent_mode"]}</td>
            <td>{item["preconditions"]}</td>
            <td>{item["evidence_required"]}</td>
            <td><span class="badge {badge}">{item["default_decision"]}</span></td>
        </tr>
        """
    return rows


def citrust_rollback_rows():
    rows = ""
    for item in CITRUST_ROLLBACK_ASSURANCE:
        rows += f"""
        <tr>
            <td><strong>{item["rollback_area"]}</strong></td>
            <td>{item["requirement"]}</td>
            <td>{item["owner"]}</td>
            <td><span class="badge red">{item["block_if_missing"]}</span></td>
        </tr>
        """
    return rows


def citrust_change_gate_rule_rows():
    rows = ""
    for item in CITRUST_AGENTIC_CHANGE_GATE_RULES:
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


def citrust_agentic_change_decision(agent, ci, field, owner, gxp, cyber, change, rollback, evidence):
    checks = [agent, ci, field, owner, change, rollback, evidence]
    score = int((sum(1 for item in checks if item == "yes") / len(checks)) * 100)

    if agent != "yes":
        return score, "Block Action", "red", "AI agent is not registered or licensed for this CI workflow."
    if ci != "yes":
        return score, "Block Action", "red", "CI is not trusted enough for AI reliance or action."
    if field != "yes":
        return score, "Field Risk Review Required", "red", "Field or relationship risk has not been classified."
    if owner != "yes":
        return score, "Human Approval Required", "red", "Accountable CI owner, LCM, support owner, or reviewer is missing."
    if gxp == "yes":
        return score, "QA-Governed Only", "red", "GxP or validation-impacting CI action requires QA / validation owner approval."
    if cyber == "yes":
        return score, "Cyber-Gated Only", "red", "Access, support group, CyberArk, PSM, or privileged route requires cybersecurity approval."
    if change != "yes":
        return score, "Change-Control Required", "orange", "Material CI action requires change-control evidence."
    if rollback != "yes":
        return score, "No Execution", "red", "Rollback or recovery evidence is missing."
    if evidence != "yes":
        return score, "Restrict to Advisory", "orange", "Runtime evidence and replay package are incomplete."
    if score == 100:
        return score, "Permit Human-Gated CI Action", "green", "AI action may proceed only within approved owner, change, rollback, and evidence controls."
    return score, "Conditional Recommendation Only", "yellow", "AI may recommend but cannot update, trigger, or approve."


try:
    AGENTTRUST_EXPECTED_ROUTES.extend([
        "/citrust/agentic-change-control-gate",
        "/citrust/ci-field-change-risk-matrix",
        "/citrust/ci-agent-action-permit",
        "/citrust/agentic-rollback-assurance",
        "/citrust/human-approval-gate",
        "/citrust/ai-cmdb-update-preflight",
        "/citrust/agentic-change-gate-rules",
        "/citrust/agentic-change-simulator",
        "/citrust/agentic-change-control-json"
    ])
except Exception:
    pass


@app.route("/citrust/agentic-change-control-gate")
@app.route("/citrust/ai-change-control-gate")
@app.route("/citrust/ci-agent-change-control")
def citrust_agentic_change_control_gate():
    rows = citrust_change_gate_rule_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">AI Change Gate</div><div class="value" style="color:var(--green);">Active</div><div class="note">Agentic CI change-control installed.</div></div>
        <div class="metric"><div class="label">Field Risk</div><div class="value" style="color:var(--yellow);">Classified</div><div class="note">Owner, support, GxP, lifecycle, relationship, access fields gated.</div></div>
        <div class="metric"><div class="label">Critical Fields</div><div class="value" style="color:var(--red);">Blocked</div><div class="note">No autonomous AI update for GxP, access, lifecycle, or support route.</div></div>
        <div class="metric"><div class="label">Human Approval</div><div class="value" style="color:var(--blue);">Required</div><div class="note">LCM, QA, cyber, support, or system owner routes preserved.</div></div>
        <div class="metric"><div class="label">Rollback</div><div class="value" style="color:var(--orange);">Mandatory</div><div class="note">No execution without recovery path.</div></div>
        <div class="metric"><div class="label">Replay</div><div class="value" style="color:var(--purple);">Required</div><div class="note">AI-influenced CI action must be audit replayable.</div></div>
    </section>

    <section class="section">
        <h2>CITrust™ Agentic Change-Control Gate</h2>
        <div class="answer">
            <strong>Purpose:</strong> control whether an AI agent may read, summarize, recommend, route, map, update,
            or trigger a ServiceNow CI-related action. The gate prevents AI from silently changing ownership,
            support group, GxP metadata, lifecycle state, access route, or CI relationships without the right approval.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Gate ID</th>
                    <th>Gate</th>
                    <th>Assurance Question</th>
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
        <h2>Change-Control Rule</h2>
        <div class="answer">
            AI can recommend, but it must not silently update or trigger material CI changes.
            CITrust™ requires field-risk classification, owner approval, change-control evidence, rollback, and runtime replay.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Change-Control Gate",
        "Agentic change-control gate for AI agents reading, recommending, mapping, updating, or triggering CI-related ServiceNow actions.",
        body
    )


@app.route("/citrust/ci-field-change-risk-matrix")
@app.route("/citrust/ai-ci-field-risk")
@app.route("/citrust/cmdb-field-risk-matrix")
def citrust_ci_field_change_risk_matrix():
    rows = citrust_field_risk_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ CI Field Change Risk Matrix</h2>
        <p>
            This matrix classifies CMDB fields by the risk created if an AI agent recommends or changes them.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Field Group</th>
                    <th>Examples</th>
                    <th>Risk</th>
                    <th>AI Allowed Mode</th>
                    <th>Required Approval</th>
                    <th>Change-Control Position</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Field Risk Rule</h2>
        <div class="answer">
            Not all CI fields are equal. AI changes to ownership, support group, lifecycle, validation,
            GxP, access route, or relationships can create operational, cyber, or regulated risk.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ CI Field Change Risk Matrix",
        "CI field risk matrix for AI-assisted updates to ownership, support, GxP, validation, lifecycle, relationships, access route, evidence, and descriptive fields.",
        body
    )


@app.route("/citrust/ci-agent-action-permit")
@app.route("/citrust/ai-ci-action-permit")
@app.route("/citrust/agentic-ci-action-permit")
def citrust_ci_agent_action_permit():
    rows = citrust_action_permit_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ AI CI Action Permit Engine</h2>
        <p>
            The permit engine defines what an AI agent may do to a CI and what evidence is required.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Permit ID</th>
                    <th>AI CI Action</th>
                    <th>Agent Mode</th>
                    <th>Preconditions</th>
                    <th>Evidence Required</th>
                    <th>Default Decision</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Permit Rule</h2>
        <div class="answer">
            CITrust™ separates AI reading, summarizing, recommending, mapping, updating, and triggering.
            Higher-impact actions require stronger evidence, approval, change control, and rollback.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ AI CI Action Permit",
        "AI CI action permit engine for read, summarize, recommend, relationship mapping, CI update, GxP metadata update, cyber route update, and workflow trigger actions.",
        body
    )


@app.route("/citrust/agentic-rollback-assurance")
@app.route("/citrust/ci-rollback-assurance")
@app.route("/citrust/ai-ci-rollback-assurance")
def citrust_agentic_rollback_assurance():
    rows = citrust_rollback_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agentic Rollback Assurance</h2>
        <p>
            Rollback assurance defines what must be captured before any AI-influenced CI update, mapping, routing, or workflow action.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Rollback Area</th>
                    <th>Requirement</th>
                    <th>Owner</th>
                    <th>Block If Missing</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Rollback Rule</h2>
        <div class="answer">
            No AI-influenced CI execution should proceed without a way to prove the prior state,
            reverse the change, verify the post-state, and assign the recovery owner.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Rollback Assurance",
        "Rollback assurance for AI-influenced CI field updates, relationship changes, support route changes, GxP metadata changes, change records, and post-action verification.",
        body
    )


@app.route("/citrust/human-approval-gate")
@app.route("/citrust/ci-human-approval-gate")
@app.route("/citrust/ai-ci-human-approval")
def citrust_human_approval_gate():
    body = """
    <section class="section">
        <h2>CITrust™ Human Approval Gate</h2>
        <p>
            This gate determines which human owner must approve an AI-assisted CI action.
        </p>

        <table>
            <thead>
                <tr>
                    <th>AI Action Context</th>
                    <th>Required Human Owner</th>
                    <th>Evidence Needed</th>
                    <th>Default Decision</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>CI owner or LCM recommendation.</td><td>LCM / CMDB owner / business owner.</td><td>Recommendation rationale and source fields.</td><td><span class="badge yellow">Human-gated</span></td></tr>
                <tr><td>Support group or assignment group recommendation.</td><td>Support owner / service owner.</td><td>Support route and operational impact.</td><td><span class="badge orange">Owner approval</span></td></tr>
                <tr><td>MyAccess, access route, CyberArk, PSM, or privileged context.</td><td>Cybersecurity / access owner.</td><td>Access impact and cyber route.</td><td><span class="badge red">Cyber-gated</span></td></tr>
                <tr><td>GMP, validation, QA, deviation, CAPA, or inspection-sensitive field.</td><td>QA / validation owner.</td><td>GxP screen and validation evidence.</td><td><span class="badge red">QA-governed</span></td></tr>
                <tr><td>CI relationship affecting service impact.</td><td>Technical owner / service owner.</td><td>Relationship confidence and impact map.</td><td><span class="badge orange">Technical review</span></td></tr>
                <tr><td>Lifecycle or operational status change.</td><td>System owner / LCM / change owner.</td><td>Change record, rollback, post-check.</td><td><span class="badge red">Change-controlled</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Approval Rule</h2>
        <div class="answer">
            AI output should never become invisible approval. The right accountable owner must review the evidence
            and approve or reject the AI-assisted CI decision.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Human Approval Gate",
        "Human approval gate for AI-assisted CI ownership, support group, access route, GxP metadata, relationship, and lifecycle decisions.",
        body
    )


@app.route("/citrust/ai-cmdb-update-preflight")
@app.route("/citrust/cmdb-update-preflight")
@app.route("/citrust/ci-update-preflight")
def citrust_ai_cmdb_update_preflight():
    body = """
    <section class="section">
        <h2>CITrust™ AI CMDB Update Preflight</h2>
        <p>
            This preflight must pass before any AI-influenced CI update, relationship change, or workflow trigger.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Preflight Check</th>
                    <th>Pass Condition</th>
                    <th>Failure Response</th>
                    <th>Evidence</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent is registered.</td><td>Agent ID and operating license exist.</td><td><span class="badge red">Block</span></td><td>AI Agent Registry.</td></tr>
                <tr><td>CI is trusted.</td><td>Owner, support group, LCM, lifecycle, validation state known.</td><td><span class="badge red">Block</span></td><td>CI Passport / Graph Trust Score.</td></tr>
                <tr><td>Field risk is known.</td><td>Target field group and risk tier classified.</td><td><span class="badge red">Block</span></td><td>Field risk matrix.</td></tr>
                <tr><td>Approval route exists.</td><td>LCM, cyber, QA, support, service, or change owner identified.</td><td><span class="badge red">Block</span></td><td>Approval route record.</td></tr>
                <tr><td>Change-control route exists.</td><td>Change record or documented no-change rationale.</td><td><span class="badge orange">Restrict</span></td><td>Change record / rationale.</td></tr>
                <tr><td>Rollback exists.</td><td>Prior state, recovery path, and post-check documented.</td><td><span class="badge red">No execution</span></td><td>Rollback plan.</td></tr>
                <tr><td>Runtime evidence ready.</td><td>Prompt, source, recommendation, approval, tool-call, outcome captured.</td><td><span class="badge orange">Advisory only</span></td><td>Evidence ledger.</td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ AI CMDB Update Preflight",
        "Preflight gate for AI-influenced CMDB updates, relationship changes, workflow triggers, owner approvals, change control, rollback, and runtime evidence.",
        body
    )


@app.route("/citrust/agentic-change-gate-rules")
@app.route("/citrust/ai-change-gate-rules")
@app.route("/citrust/ci-change-gate-rules")
def citrust_agentic_change_gate_rules():
    rows = citrust_change_gate_rule_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agentic Change Gate Rules</h2>
        <p>
            These rules define the full gate sequence before AI can influence a material CI action.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Gate ID</th>
                    <th>Gate</th>
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
    """

    return agenttrust_shell(
        "CITrust™ Agentic Change Gate Rules",
        "Gate rules for AI agent identity, CI trust, field risk, GxP route, cyber route, change control, rollback, and runtime evidence.",
        body
    )


@app.route("/citrust/agentic-change-simulator", methods=["GET", "POST"])
@app.route("/citrust/ci-agent-change-simulator", methods=["GET", "POST"])
@app.route("/citrust/ai-cmdb-change-simulator", methods=["GET", "POST"])
def citrust_agentic_change_simulator():
    from flask import request

    agent = request.form.get("agent", "yes")
    ci = request.form.get("ci", "yes")
    field = request.form.get("field", "yes")
    owner = request.form.get("owner", "yes")
    gxp = request.form.get("gxp", "no")
    cyber = request.form.get("cyber", "no")
    change = request.form.get("change", "yes")
    rollback = request.form.get("rollback", "yes")
    evidence = request.form.get("evidence", "yes")

    score, decision, badge, reason = citrust_agentic_change_decision(
        agent, ci, field, owner, gxp, cyber, change, rollback, evidence
    )

    def selected(value, expected):
        return "selected" if value == expected else ""

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Change Permit Score</div><div class="value" style="color:var(--green);">{score}%</div><div class="note">Calculated from CI agentic change controls.</div></div>
        <div class="metric"><div class="label">Permit Decision</div><div class="value" style="color:var(--yellow);">{decision}</div><div class="note">{reason}</div></div>
    </section>

    <section class="section">
        <h2>CITrust™ Agentic Change Simulator</h2>
        <p>
            Simulate whether an AI agent should be allowed to influence a CI update, relationship change, support route,
            GxP metadata decision, or workflow action.
        </p>

        <form method="POST" action="/citrust/agentic-change-simulator">
            <table>
                <tbody>
                    <tr><td><strong>AI Agent Registered / Licensed?</strong></td><td><select name="agent" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(agent, "yes")}>Yes</option><option value="no" {selected(agent, "no")}>No</option></select></td></tr>
                    <tr><td><strong>CI Trusted / Complete?</strong></td><td><select name="ci" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(ci, "yes")}>Yes</option><option value="no" {selected(ci, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Field / Relationship Risk Classified?</strong></td><td><select name="field" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(field, "yes")}>Yes</option><option value="no" {selected(field, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Human Owner Approval Route Ready?</strong></td><td><select name="owner" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(owner, "yes")}>Yes</option><option value="no" {selected(owner, "no")}>No</option></select></td></tr>
                    <tr><td><strong>GxP / Validation Impact Present?</strong></td><td><select name="gxp" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="no" {selected(gxp, "no")}>No</option><option value="yes" {selected(gxp, "yes")}>Yes</option></select></td></tr>
                    <tr><td><strong>Cyber / Access / Privileged Impact Present?</strong></td><td><select name="cyber" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="no" {selected(cyber, "no")}>No</option><option value="yes" {selected(cyber, "yes")}>Yes</option></select></td></tr>
                    <tr><td><strong>Change-Control Evidence Ready?</strong></td><td><select name="change" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(change, "yes")}>Yes</option><option value="no" {selected(change, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Rollback / Recovery Ready?</strong></td><td><select name="rollback" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(rollback, "yes")}>Yes</option><option value="no" {selected(rollback, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Runtime Evidence / Replay Ready?</strong></td><td><select name="evidence" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(evidence, "yes")}>Yes</option><option value="no" {selected(evidence, "no")}>No</option></select></td></tr>
                </tbody>
            </table>

            <button type="submit" style="margin-top:16px;padding:12px 18px;border-radius:12px;border:0;background:#2563eb;color:white;font-weight:800;">Run Agentic CI Change Check</button>
        </form>
    </section>

    <section class="section">
        <h2>Agentic CI Change Decision</h2>
        <div class="answer">
            <strong>Score:</strong> {score}%<br>
            <strong>Decision:</strong> <span class="badge {badge}">{decision}</span><br>
            <strong>Reason:</strong> {reason}
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Change Simulator",
        "Simulator for AI agent CI update permits across agent identity, CI trust, field risk, owner approval, GxP impact, cyber impact, change control, rollback, and runtime evidence.",
        body
    )


@app.route("/citrust/agentic-change-control-json")
@app.route("/citrust/ci-agent-change-json")
@app.route("/citrust/ai-cmdb-update-json")
def citrust_agentic_change_control_json():
    from flask import jsonify

    return jsonify({
        "module": "CITrust™",
        "capability": "Agentic Change-Control Gate + AI CI Update Permit Engine",
        "primary_question": "Can this AI agent safely influence this CI action, field update, relationship map, or workflow trigger?",
        "ci_field_risk": CITRUST_AGENTIC_CI_FIELD_RISK,
        "action_permits": CITRUST_AGENTIC_ACTION_PERMITS,
        "rollback_assurance": CITRUST_ROLLBACK_ASSURANCE,
        "change_gate_rules": CITRUST_AGENTIC_CHANGE_GATE_RULES,
        "minimum_conditions": [
            "AI agent is registered and licensed for the CI workflow",
            "CI identity, owner, support group, LCM, lifecycle, and validation status are trusted",
            "Target field or relationship risk is classified",
            "Human approval route is defined",
            "GxP and validation impact routes to QA where applicable",
            "Access, CyberArk, PSM, support group, and privileged impact routes to cybersecurity where applicable",
            "Material CI action is linked to change control",
            "Rollback and recovery path exist",
            "Runtime evidence captures source, recommendation, approval, tool-call, outcome, and post-check"
        ],
        "default_decision": "Do not allow AI-influenced CI update, relationship change, workflow trigger, GxP metadata change, or access-route change unless owner approval, change control, rollback, and runtime evidence are complete"
    })

# ============================================================
# END CITRUST_AGENTIC_CHANGE_CONTROL_GATE_V1_ACTIVE
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

print("CITrust Agentic Change-Control Gate installed.")
print(f"Inserted before: {target_found}")
