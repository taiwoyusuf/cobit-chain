from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_AGENTIC_CHANGE_INTEGRATION_CENTER_V1_ACTIVE"

if MARKER in text:
    print("CITrust Agentic Change Integration Center already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base shell not found. Install AgentTrust base module first.")

nav_old = '<a href="/citrust/agent-identity-entitlement-governance" class="secondary">Agent Identity</a>'
nav_new = '''<a href="/citrust/agent-identity-entitlement-governance" class="secondary">Agent Identity</a>
                    <a href="/citrust/agentic-change-integration-center" class="secondary">Change Integration</a>
                    <a href="/citrust/ai-to-change-record-router" class="dark">Change Router</a>
                    <a href="/citrust/agentic-task-deviation-router" class="dark">Deviation Router</a>
                    <a href="/citrust/change-integration-simulator" class="dark">Change Sim</a>'''

if nav_old in text and "/citrust/agentic-change-integration-center" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# CITRUST_AGENTIC_CHANGE_INTEGRATION_CENTER_V1_ACTIVE
# CITrust™ Agentic Change Integration Center
# AI-to-Change Record Router, AI Change Impact Matrix,
# Agentic Task / Deviation / Exception Router,
# Change Record Classifier, Rollback / Post-Check Center,
# Agentic Exception Risk Acceptance,
# Change Closure Dossier, Simulator, and JSON Export
# ============================================================

CITRUST_AI_CHANGE_ACTION_CLASSES = [
    {
        "action_class": "Read / Summarize",
        "examples": "Read CI, summarize owner, summarize support group, summarize validation status.",
        "change_need": "Usually no formal change.",
        "required_route": "Runtime evidence and source citation.",
        "default_decision": "Permit with logging."
    },
    {
        "action_class": "Recommend",
        "examples": "Recommend CI owner, support group, relationship, MyAccess route, readiness status.",
        "change_need": "Change or review task if recommendation affects operational accountability.",
        "required_route": "Human owner review, evidence package, no autonomous update.",
        "default_decision": "Human-gated."
    },
    {
        "action_class": "Draft",
        "examples": "Draft change description, task note, CI update justification, rollback text.",
        "change_need": "No formal change until submitted by human owner.",
        "required_route": "Reviewer approval before use.",
        "default_decision": "Draft-only."
    },
    {
        "action_class": "Route",
        "examples": "Route to LCM, QA, cybersecurity, support owner, change owner, validation owner.",
        "change_need": "Task or approval record required when routing affects workflow decision.",
        "required_route": "Route reason, recipient owner, workflow record.",
        "default_decision": "Permit with workflow evidence."
    },
    {
        "action_class": "Update CI Field",
        "examples": "Owner, support group, lifecycle state, validation field, relationship, access route.",
        "change_need": "Formal change or approved task required if material.",
        "required_route": "Change owner, rollback, field before/after, post-check.",
        "default_decision": "Blocked by default."
    },
    {
        "action_class": "Trigger Workflow",
        "examples": "Trigger change, access request, support workflow, remediation task, cutover task.",
        "change_need": "Formal action permit and owner approval required.",
        "required_route": "Action permit, workflow ID, owner approval, runtime evidence.",
        "default_decision": "Controlled execution only."
    },
    {
        "action_class": "Approve / Close",
        "examples": "Approve change, approve access, approve QA decision, close task, close exception.",
        "change_need": "AI must not approve or close accountable decisions.",
        "required_route": "Human owner signoff.",
        "default_decision": "Prohibited for autonomous AI."
    }
]


CITRUST_CHANGE_RECORD_DECISION_MATRIX = [
    {
        "impact_area": "CI Ownership / LCM",
        "change_question": "Does the AI output change who is accountable for the CI?",
        "record_required": "Review task or change record if ownership becomes operationally binding.",
        "approval_owner": "LCM / CMDB Owner / Business Owner",
        "evidence": "Owner before/after, recommendation rationale, approval."
    },
    {
        "impact_area": "Support Group / Assignment Group",
        "change_question": "Does the AI output change resolver route, escalation route, or support model?",
        "record_required": "Change or support-routing task.",
        "approval_owner": "Support Owner / Service Owner",
        "evidence": "Old group, new group, impact, approval, rollback."
    },
    {
        "impact_area": "MyAccess / CyberArk / PSM",
        "change_question": "Does the AI output affect access, entitlement, privileged route, or admin workflow?",
        "record_required": "Access request, cyber review, privileged access evidence.",
        "approval_owner": "Cybersecurity / Access / CyberArk Owner",
        "evidence": "Access route, entitlement, cyber decision, session evidence if privileged."
    },
    {
        "impact_area": "GxP / Validation Metadata",
        "change_question": "Does the AI output affect GMP class, validation status, QA route, release, deviation, CAPA, or inspection evidence?",
        "record_required": "QA / validation review, change/deviation if applicable.",
        "approval_owner": "QA / Validation Owner",
        "evidence": "GxP screen, validation evidence, QA decision, change/deviation link."
    },
    {
        "impact_area": "CI Relationship / Service Map",
        "change_question": "Does the AI output affect dependency, application service, business service, infrastructure, or database mapping?",
        "record_required": "Relationship review task or change record.",
        "approval_owner": "Technical Owner / Service Owner",
        "evidence": "Source CI, target CI, relationship confidence, before/after map."
    },
    {
        "impact_area": "Lifecycle / Operational State",
        "change_question": "Does the AI output affect install status, operational state, decommission, cutover, or migration state?",
        "record_required": "Formal change record.",
        "approval_owner": "System Owner / Change Owner / LCM",
        "evidence": "Change ID, implementation window, rollback, post-check."
    },
    {
        "impact_area": "Cutover-Sensitive Process",
        "change_question": "Could the AI output affect go-live, cutover readiness, migration, rollback, or hypercare?",
        "record_required": "Cutover task, risk record, or change record.",
        "approval_owner": "Cutover Owner / QA / System Owner",
        "evidence": "Cutover impact, readiness decision, rollback, owner signoff."
    }
]


CITRUST_TASK_DEVIATION_EXCEPTION_ROUTES = [
    {
        "route_type": "ServiceNow Task",
        "used_when": "AI identifies missing owner, missing support group, relationship gap, stale CI, missing evidence, or remediation need.",
        "owner": "CMDB / LCM / System Owner",
        "closure_evidence": "Task closure note, evidence attached, reviewer confirmation."
    },
    {
        "route_type": "Change Record",
        "used_when": "AI recommendation becomes material CI update, support route change, lifecycle change, relationship update, or operational state change.",
        "owner": "Change Owner / System Owner",
        "closure_evidence": "Approval, implementation, rollback, post-check, closure."
    },
    {
        "route_type": "Access Request",
        "used_when": "AI output touches MyAccess, approver group, entitlement, privileged route, CyberArk, PSM, or admin context.",
        "owner": "Access Owner / Cybersecurity",
        "closure_evidence": "Access decision, cyber review, entitlement record, privileged session evidence if applicable."
    },
    {
        "route_type": "QA / Validation Review",
        "used_when": "AI output touches GMP, validation, QA, release, deviation, CAPA, QC, inspection-sensitive record, or regulated conclusion.",
        "owner": "QA / Validation Owner",
        "closure_evidence": "QA decision, validation evidence, regulated reliance decision."
    },
    {
        "route_type": "Deviation / CAPA Assessment",
        "used_when": "AI action, wrong recommendation, missed guardrail, stale memory, or uncontrolled update may have regulated impact.",
        "owner": "QA / Quality Risk Owner",
        "closure_evidence": "Impact assessment, root cause, remediation, retest, QA closure."
    },
    {
        "route_type": "Risk Acceptance / Exception",
        "used_when": "AI-assisted workflow proceeds with known gap, temporary workaround, missing evidence, or restricted control.",
        "owner": "Risk Owner / Governance Owner",
        "closure_evidence": "Exception ID, condition, expiry, compensating control, owner signoff."
    }
]


CITRUST_ROLLBACK_POSTCHECK_REQUIREMENTS = [
    {
        "requirement": "Before-state capture",
        "purpose": "Know what CI value, relationship, owner, support group, access route, or lifecycle state existed before action.",
        "evidence": "Before value, source record, timestamp, owner."
    },
    {
        "requirement": "Approved change path",
        "purpose": "Confirm action followed the correct change, task, access, QA, or exception route.",
        "evidence": "Change/task/access/QA/exception record."
    },
    {
        "requirement": "Rollback owner",
        "purpose": "Identify who is accountable if AI-influenced action must be reversed.",
        "evidence": "Rollback owner and recovery route."
    },
    {
        "requirement": "Rollback method",
        "purpose": "Define how to reverse field, relationship, access, support, lifecycle, or evidence change.",
        "evidence": "Rollback steps and expected restored state."
    },
    {
        "requirement": "Post-action verification",
        "purpose": "Confirm action landed correctly and did not create downstream CI, support, GxP, cyber, or change risk.",
        "evidence": "Post-check result, reviewer, timestamp."
    },
    {
        "requirement": "Closure signoff",
        "purpose": "Ensure accountable owner accepts final state and evidence package.",
        "evidence": "Owner signoff and closure record."
    }
]


CITRUST_CHANGE_CLOSURE_DOSSIER = [
    {
        "dossier_section": "Trigger and AI Action",
        "contents": "Trigger source, event ID, AI agent, action class, CI impacted, workflow context."
    },
    {
        "dossier_section": "CI Impact",
        "contents": "CI passport, owner, support group, LCM, lifecycle, validation status, relationship impact."
    },
    {
        "dossier_section": "Risk Routing",
        "contents": "GxP screen, cyber/access screen, change impact, cutover sensitivity, exception route."
    },
    {
        "dossier_section": "Approval Evidence",
        "contents": "LCM, system owner, QA, cyber, change owner, support owner, or risk owner decision."
    },
    {
        "dossier_section": "Execution / Block Evidence",
        "contents": "Action permit, tool-call log, ServiceNow log, Azure telemetry, blocked reason, or executed result."
    },
    {
        "dossier_section": "Rollback and Post-Check",
        "contents": "Before-state, rollback plan, recovery owner, post-action verification, restored state if rollback occurred."
    },
    {
        "dossier_section": "Closure and Attestation",
        "contents": "Closure owner, final decision, exception status, signoff, audit replay package."
    }
]


def citrust_ai_change_action_rows():
    rows = ""
    for item in CITRUST_AI_CHANGE_ACTION_CLASSES:
        badge = "green"
        if "Blocked" in item["default_decision"] or "Prohibited" in item["default_decision"]:
            badge = "red"
        elif "Human" in item["default_decision"] or "Controlled" in item["default_decision"]:
            badge = "orange"
        elif "Draft" in item["default_decision"]:
            badge = "yellow"

        rows += f"""
        <tr>
            <td><strong>{item["action_class"]}</strong></td>
            <td>{item["examples"]}</td>
            <td>{item["change_need"]}</td>
            <td>{item["required_route"]}</td>
            <td><span class="badge {badge}">{item["default_decision"]}</span></td>
        </tr>
        """
    return rows


def citrust_change_decision_rows():
    rows = ""
    for item in CITRUST_CHANGE_RECORD_DECISION_MATRIX:
        rows += f"""
        <tr>
            <td><strong>{item["impact_area"]}</strong></td>
            <td>{item["change_question"]}</td>
            <td><span class="badge orange">{item["record_required"]}</span></td>
            <td>{item["approval_owner"]}</td>
            <td>{item["evidence"]}</td>
        </tr>
        """
    return rows


def citrust_task_deviation_rows():
    rows = ""
    for item in CITRUST_TASK_DEVIATION_EXCEPTION_ROUTES:
        rows += f"""
        <tr>
            <td><strong>{item["route_type"]}</strong></td>
            <td>{item["used_when"]}</td>
            <td>{item["owner"]}</td>
            <td>{item["closure_evidence"]}</td>
        </tr>
        """
    return rows


def citrust_rollback_postcheck_rows():
    rows = ""
    for item in CITRUST_ROLLBACK_POSTCHECK_REQUIREMENTS:
        rows += f"""
        <tr>
            <td><strong>{item["requirement"]}</strong></td>
            <td>{item["purpose"]}</td>
            <td>{item["evidence"]}</td>
        </tr>
        """
    return rows


def citrust_change_dossier_rows():
    rows = ""
    for item in CITRUST_CHANGE_CLOSURE_DOSSIER:
        rows += f"""
        <tr>
            <td><strong>{item["dossier_section"]}</strong></td>
            <td>{item["contents"]}</td>
        </tr>
        """
    return rows


def citrust_change_integration_decision(action_class, ci_impact, record_route, owner, gxp, cyber, rollback, postcheck, closure):
    checks = [action_class, ci_impact, record_route, owner, rollback, postcheck, closure]
    score = int((sum(1 for item in checks if item == "yes") / len(checks)) * 100)

    if action_class != "yes":
        return score, "Classify AI Action First", "red", "AI action class is not defined."
    if ci_impact != "yes":
        return score, "CI Impact Review Required", "red", "CI impact is not understood."
    if gxp == "yes":
        return score, "QA / Validation Route Required", "red", "GxP or validation impact requires QA route before reliance."
    if cyber == "yes":
        return score, "Cyber / Access Route Required", "red", "Access, MyAccess, CyberArk, PSM, or privileged impact requires cybersecurity route."
    if record_route != "yes":
        return score, "Record Route Required", "orange", "ServiceNow task, change, access request, QA review, deviation, CAPA, or exception route is not defined."
    if owner != "yes":
        return score, "Owner Approval Required", "red", "Accountable human owner approval is missing."
    if rollback != "yes":
        return score, "No Execution", "red", "Rollback or recovery plan is missing."
    if postcheck != "yes":
        return score, "Do Not Close", "orange", "Post-action verification is missing."
    if closure != "yes":
        return score, "Closure Dossier Required", "orange", "Closure evidence package is incomplete."
    if score == 100:
        return score, "Change Integrated and Defensible", "green", "AI action is classified, routed, approved, rollback-ready, post-checked, and closure-ready."
    return score, "Conditional Change Integration", "yellow", "AI action may proceed only with restrictions and remediation tracking."


try:
    AGENTTRUST_EXPECTED_ROUTES.extend([
        "/citrust/agentic-change-integration-center",
        "/citrust/ai-to-change-record-router",
        "/citrust/agentic-task-deviation-router",
        "/citrust/ai-change-impact-matrix",
        "/citrust/agent-change-record-classifier",
        "/citrust/agentic-exception-risk-acceptance",
        "/citrust/change-rollback-postcheck-center",
        "/citrust/agentic-change-closure-dossier",
        "/citrust/change-integration-simulator",
        "/citrust/agentic-change-integration-json"
    ])
except Exception:
    pass


@app.route("/citrust/agentic-change-integration-center")
@app.route("/citrust/agentic-change-command-center")
@app.route("/citrust/citrust-agentic-change-integration")
def citrust_agentic_change_integration_center():
    action_rows = citrust_ai_change_action_rows()
    decision_rows = citrust_change_decision_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Change Integration</div><div class="value" style="color:var(--green);">Active</div><div class="note">AI outputs mapped to task, change, access, QA, deviation, and exception routes.</div></div>
        <div class="metric"><div class="label">Action Classes</div><div class="value" style="color:var(--blue);">7</div><div class="note">Read, recommend, draft, route, update, trigger, approve/close.</div></div>
        <div class="metric"><div class="label">GxP Route</div><div class="value" style="color:var(--red);">QA-Governed</div><div class="note">Regulated impact requires QA / validation owner.</div></div>
        <div class="metric"><div class="label">Cyber Route</div><div class="value" style="color:var(--orange);">Cyber-Gated</div><div class="note">Access and privileged context route to cybersecurity.</div></div>
        <div class="metric"><div class="label">Rollback</div><div class="value" style="color:var(--yellow);">Mandatory</div><div class="note">No material execution without recovery evidence.</div></div>
        <div class="metric"><div class="label">Closure Dossier</div><div class="value" style="color:var(--purple);">Required</div><div class="note">Action must close with evidence package.</div></div>
    </section>

    <section class="section">
        <h2>CITrust™ Agentic Change Integration Center</h2>
        <div class="answer">
            <strong>Purpose:</strong> decide whether an AI-assisted ServiceNow / CMDB action requires a task,
            change record, access request, QA review, deviation/CAPA assessment, exception, rollback, post-check,
            or closure dossier.
        </div>

        <h3>AI Action Classifier</h3>
        <table>
            <thead>
                <tr>
                    <th>Action Class</th>
                    <th>Examples</th>
                    <th>Change Need</th>
                    <th>Required Route</th>
                    <th>Default Decision</th>
                </tr>
            </thead>
            <tbody>
                {action_rows}
            </tbody>
        </table>

        <h3>Change Record Decision Matrix</h3>
        <table>
            <thead>
                <tr>
                    <th>Impact Area</th>
                    <th>Change Question</th>
                    <th>Record Required</th>
                    <th>Approval Owner</th>
                    <th>Evidence</th>
                </tr>
            </thead>
            <tbody>
                {decision_rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Integration Rule</h2>
        <div class="answer">
            AI output is not operationally safe until it is classified, routed to the correct ServiceNow record,
            reviewed by the accountable owner, linked to rollback, verified after action, and closed with evidence.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Change Integration Center",
        "AI-to-change-control integration center for AI-assisted ServiceNow, CMDB, GxP, access, cyber, deviation, exception, rollback, and closure workflows.",
        body
    )


@app.route("/citrust/ai-to-change-record-router")
@app.route("/citrust/agent-change-record-router")
@app.route("/citrust/change-record-router")
def citrust_ai_to_change_record_router():
    rows = citrust_change_decision_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ AI-to-Change Record Router</h2>
        <p>
            This router determines when an AI-assisted action must become a ServiceNow task, change, access record,
            QA review, deviation/CAPA, or exception.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Impact Area</th>
                    <th>Routing Question</th>
                    <th>Record Required</th>
                    <th>Approval Owner</th>
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
        "CITrust™ AI to Change Record Router",
        "Router that determines required ServiceNow record type for AI-assisted CI ownership, support, access, GxP, relationship, lifecycle, and cutover impacts.",
        body
    )


@app.route("/citrust/agentic-task-deviation-router")
@app.route("/citrust/ai-task-deviation-router")
@app.route("/citrust/agentic-exception-router")
def citrust_agentic_task_deviation_router():
    rows = citrust_task_deviation_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agentic Task / Deviation / Exception Router</h2>
        <p>
            AI-assisted actions must route to the correct operational record type based on risk and regulated impact.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Route Type</th>
                    <th>Used When</th>
                    <th>Owner</th>
                    <th>Closure Evidence</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Task Deviation Router",
        "Task, change, access, QA, deviation, CAPA, and exception router for AI-assisted CI and ServiceNow workflows.",
        body
    )


@app.route("/citrust/ai-change-impact-matrix")
@app.route("/citrust/agentic-change-impact-matrix")
@app.route("/citrust/ci-ai-change-impact")
def citrust_ai_change_impact_matrix():
    rows = citrust_change_decision_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ AI Change Impact Matrix</h2>
        <p>
            This matrix identifies where AI recommendations or actions create operational, cyber, GxP, cutover,
            or change-control impact.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Impact Area</th>
                    <th>Question</th>
                    <th>Record Required</th>
                    <th>Approval Owner</th>
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
        "CITrust™ AI Change Impact Matrix",
        "AI change impact matrix for ownership, support group, access, GxP metadata, relationships, lifecycle, and cutover-sensitive ServiceNow actions.",
        body
    )


@app.route("/citrust/agent-change-record-classifier")
@app.route("/citrust/ai-action-classifier")
@app.route("/citrust/agentic-action-classifier")
def citrust_agent_change_record_classifier():
    rows = citrust_ai_change_action_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agent Change Record Classifier</h2>
        <p>
            This classifier separates AI read, summarize, recommend, draft, route, update, trigger, approve, and close actions.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Action Class</th>
                    <th>Examples</th>
                    <th>Change Need</th>
                    <th>Required Route</th>
                    <th>Default Decision</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agent Change Record Classifier",
        "Classifier for AI-assisted action types and required change, task, QA, cyber, access, rollback, and evidence routes.",
        body
    )


@app.route("/citrust/agentic-exception-risk-acceptance")
@app.route("/citrust/ai-exception-risk-acceptance")
@app.route("/citrust/agentic-risk-acceptance")
def citrust_agentic_exception_risk_acceptance():
    body = """
    <section class="section">
        <h2>CITrust™ Agentic Exception / Risk Acceptance</h2>
        <p>
            When an AI-assisted workflow proceeds with a known gap, the gap must be visible, owned, time-bound, restricted, and closed.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Exception Scenario</th>
                    <th>Risk</th>
                    <th>Required Restriction</th>
                    <th>Closure Evidence</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Missing owner but advisory output needed.</td><td>No accountability.</td><td>Advisory only; no update or routing.</td><td>Owner assignment task.</td></tr>
                <tr><td>Missing validation evidence.</td><td>GxP defensibility gap.</td><td>No regulated reliance.</td><td>QA review and validation evidence.</td></tr>
                <tr><td>Missing cyber review.</td><td>Access / privileged risk.</td><td>No access recommendation or privileged route action.</td><td>Cybersecurity decision.</td></tr>
                <tr><td>Missing rollback.</td><td>Unsafe execution.</td><td>No execution; recommend only.</td><td>Rollback plan and owner signoff.</td></tr>
                <tr><td>Missing telemetry.</td><td>Cannot prove what happened.</td><td>No audit-defensible closure.</td><td>Correlation ID and evidence trail.</td></tr>
                <tr><td>Temporary manual workaround.</td><td>Control weakness.</td><td>Expiry date and compensating control.</td><td>Retest and owner closure.</td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Exception Risk Acceptance",
        "Exception and risk acceptance control for AI-assisted ServiceNow and CMDB workflows with known owner, validation, cyber, rollback, telemetry, or manual workaround gaps.",
        body
    )


@app.route("/citrust/change-rollback-postcheck-center")
@app.route("/citrust/agentic-rollback-postcheck")
@app.route("/citrust/ai-change-postcheck-center")
def citrust_change_rollback_postcheck_center():
    rows = citrust_rollback_postcheck_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Change Rollback / Post-Check Center</h2>
        <p>
            AI-influenced material actions require before-state capture, rollback owner, rollback method, post-check, and closure signoff.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Requirement</th>
                    <th>Purpose</th>
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
        "CITrust™ Change Rollback Post-Check Center",
        "Rollback and post-check center for AI-influenced CI updates, support group changes, access route changes, lifecycle changes, and relationship changes.",
        body
    )


@app.route("/citrust/agentic-change-closure-dossier")
@app.route("/citrust/ai-change-closure-dossier")
@app.route("/citrust/change-closure-dossier")
def citrust_agentic_change_closure_dossier():
    rows = citrust_change_dossier_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agentic Change Closure Dossier</h2>
        <p>
            The closure dossier assembles the evidence needed to defend an AI-assisted CI or ServiceNow workflow decision.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Dossier Section</th>
                    <th>Contents</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Closure Rule</h2>
        <div class="answer">
            AI-assisted workflows should not close with only a comment. Closure requires trigger, CI impact,
            risk routing, approval, execution/block evidence, rollback/post-check, and final signoff.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Change Closure Dossier",
        "Closure dossier for AI-assisted ServiceNow, CMDB, change, QA, cyber, rollback, exception, and owner signoff evidence.",
        body
    )


@app.route("/citrust/change-integration-simulator", methods=["GET", "POST"])
@app.route("/citrust/agentic-change-integration-simulator", methods=["GET", "POST"])
@app.route("/citrust/ai-change-router-simulator", methods=["GET", "POST"])
def citrust_change_integration_simulator():
    from flask import request

    action_class = request.form.get("action_class", "yes")
    ci_impact = request.form.get("ci_impact", "yes")
    record_route = request.form.get("record_route", "yes")
    owner = request.form.get("owner", "yes")
    gxp = request.form.get("gxp", "no")
    cyber = request.form.get("cyber", "no")
    rollback = request.form.get("rollback", "yes")
    postcheck = request.form.get("postcheck", "yes")
    closure = request.form.get("closure", "yes")

    score, decision, badge, reason = citrust_change_integration_decision(
        action_class, ci_impact, record_route, owner, gxp, cyber, rollback, postcheck, closure
    )

    def selected(value, expected):
        return "selected" if value == expected else ""

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Change Integration Score</div><div class="value" style="color:var(--green);">{score}%</div><div class="note">Calculated from AI-to-change-control controls.</div></div>
        <div class="metric"><div class="label">Integration Decision</div><div class="value" style="color:var(--yellow);">{decision}</div><div class="note">{reason}</div></div>
    </section>

    <section class="section">
        <h2>CITrust™ Change Integration Simulator</h2>
        <p>
            Simulate whether an AI-assisted ServiceNow / CMDB action is properly routed to task, change, access,
            QA, deviation, exception, rollback, post-check, and closure evidence.
        </p>

        <form method="POST" action="/citrust/change-integration-simulator">
            <table>
                <tbody>
                    <tr><td><strong>AI Action Class Defined?</strong></td><td><select name="action_class" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(action_class, "yes")}>Yes</option><option value="no" {selected(action_class, "no")}>No</option></select></td></tr>
                    <tr><td><strong>CI Impact Known?</strong></td><td><select name="ci_impact" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(ci_impact, "yes")}>Yes</option><option value="no" {selected(ci_impact, "no")}>No</option></select></td></tr>
                    <tr><td><strong>ServiceNow Record Route Defined?</strong></td><td><select name="record_route" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(record_route, "yes")}>Yes</option><option value="no" {selected(record_route, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Accountable Owner Approval Ready?</strong></td><td><select name="owner" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(owner, "yes")}>Yes</option><option value="no" {selected(owner, "no")}>No</option></select></td></tr>
                    <tr><td><strong>GxP / Validation Impact Present?</strong></td><td><select name="gxp" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="no" {selected(gxp, "no")}>No</option><option value="yes" {selected(gxp, "yes")}>Yes</option></select></td></tr>
                    <tr><td><strong>Cyber / Access / Privileged Impact Present?</strong></td><td><select name="cyber" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="no" {selected(cyber, "no")}>No</option><option value="yes" {selected(cyber, "yes")}>Yes</option></select></td></tr>
                    <tr><td><strong>Rollback / Recovery Ready?</strong></td><td><select name="rollback" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(rollback, "yes")}>Yes</option><option value="no" {selected(rollback, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Post-Action Verification Ready?</strong></td><td><select name="postcheck" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(postcheck, "yes")}>Yes</option><option value="no" {selected(postcheck, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Closure Dossier Ready?</strong></td><td><select name="closure" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(closure, "yes")}>Yes</option><option value="no" {selected(closure, "no")}>No</option></select></td></tr>
                </tbody>
            </table>

            <button type="submit" style="margin-top:16px;padding:12px 18px;border-radius:12px;border:0;background:#2563eb;color:white;font-weight:800;">Run Change Integration Check</button>
        </form>
    </section>

    <section class="section">
        <h2>Change Integration Decision</h2>
        <div class="answer">
            <strong>Score:</strong> {score}%<br>
            <strong>Decision:</strong> <span class="badge {badge}">{decision}</span><br>
            <strong>Reason:</strong> {reason}
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Change Integration Simulator",
        "Simulator for AI-to-change-control readiness across action classification, CI impact, record route, owner approval, GxP, cyber, rollback, post-check, and closure dossier.",
        body
    )


@app.route("/citrust/agentic-change-integration-json")
@app.route("/citrust/change-integration-json")
@app.route("/citrust/ai-change-router-json")
def citrust_agentic_change_integration_json():
    from flask import jsonify

    return jsonify({
        "module": "CITrust™",
        "capability": "Agentic Change Integration Center + Deviation / Exception Router",
        "primary_question": "Does this AI-assisted ServiceNow / CMDB action require a task, change record, access request, QA review, deviation/CAPA, exception, rollback, post-check, or closure dossier?",
        "ai_change_action_classes": CITRUST_AI_CHANGE_ACTION_CLASSES,
        "change_record_decision_matrix": CITRUST_CHANGE_RECORD_DECISION_MATRIX,
        "task_deviation_exception_routes": CITRUST_TASK_DEVIATION_EXCEPTION_ROUTES,
        "rollback_postcheck_requirements": CITRUST_ROLLBACK_POSTCHECK_REQUIREMENTS,
        "change_closure_dossier": CITRUST_CHANGE_CLOSURE_DOSSIER,
        "minimum_conditions": [
            "AI action class is defined",
            "CI impact is known",
            "Required ServiceNow record route is selected",
            "Accountable owner approval is captured",
            "GxP / validation impact routes to QA where applicable",
            "Cyber / access / privileged impact routes to cybersecurity where applicable",
            "Rollback or recovery path is defined",
            "Post-action verification is completed",
            "Closure dossier is assembled and signed"
        ],
        "default_decision": "Do not let AI-assisted ServiceNow / CMDB action become operationally binding unless it is routed to the correct task, change, QA, cyber, deviation, exception, rollback, post-check, and closure evidence path"
    })

# ============================================================
# END CITRUST_AGENTIC_CHANGE_INTEGRATION_CENTER_V1_ACTIVE
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

print("CITrust Agentic Change Integration Center installed.")
print(f"Inserted before: {target_found}")
