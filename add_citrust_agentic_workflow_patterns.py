from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_AGENTIC_WORKFLOW_GOVERNANCE_PATTERNS_V1_ACTIVE"

if MARKER in text:
    print("CITrust Agentic Workflow Governance Patterns already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base shell not found. Install AgentTrust base module first.")

nav_old = '<a href="/citrust/agentic-change-control-gate" class="secondary">AI Change Gate</a>'
nav_new = '''<a href="/citrust/agentic-change-control-gate" class="secondary">AI Change Gate</a>
                    <a href="/citrust/agentic-workflow-governance-patterns" class="secondary">Workflow Patterns</a>
                    <a href="/citrust/azure-agentic-pattern-mapping" class="dark">Azure Mapping</a>
                    <a href="/citrust/agent-trigger-governance" class="dark">Triggers</a>
                    <a href="/citrust/prompt-chain-evidence" class="dark">Prompt Chain</a>'''

if nav_old in text and "/citrust/agentic-workflow-governance-patterns" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# CITRUST_AGENTIC_WORKFLOW_GOVERNANCE_PATTERNS_V1_ACTIVE
# CITrust™ Agentic Workflow Governance Patterns
# Azure Agentic Pattern Mapping, Agent Trigger Governance,
# Prompt Chain Evidence, Agent Routing Policy,
# Supervisor Agent Oversight, Saga / Rollback Assurance,
# Parallel Agent Control, Evaluator Loop Scorecard,
# Identity / Entitlement Control, Observability Evidence,
# AI-to-Change-Control Integration, Workflow Simulator, JSON Export
# ============================================================

CITRUST_AGENTIC_WORKFLOW_PATTERN_MAP = [
    {
        "pattern": "Event-Driven Agent",
        "azure_meaning": "Agent reacts to events, requests, telemetry, triggers, tickets, or workflow messages.",
        "citrust_question": "What triggered the AI agent, and was the trigger trusted?",
        "service_now_impact": "Incident, request, change task, CI update, monitoring alert, access request, exception, or workflow event.",
        "required_evidence": "Trigger source, event ID, CI ID, workflow context, timestamp, owner route, action decision.",
        "default_guardrail": "Block if trigger source is unknown, untrusted, duplicated, or outside approved workflow."
    },
    {
        "pattern": "Cognition-Augmented Workflow",
        "azure_meaning": "Agent combines automation with reasoning, policies, context, memory, and knowledge sources.",
        "citrust_question": "Was the agent using approved CMDB, policy, SOP, validation, ownership, and support context?",
        "service_now_impact": "CI recommendation, ownership inference, support routing, GxP classification, relationship mapping.",
        "required_evidence": "Approved knowledge source, CMDB data trust score, policy reference, data freshness, context lineage.",
        "default_guardrail": "Restrict if context is stale, unsupported, unapproved, or not traceable."
    },
    {
        "pattern": "Prompt Chaining",
        "azure_meaning": "Complex objective is broken into multiple reasoning or prompt steps.",
        "citrust_question": "Can each prompt step, input, output, decision, and handoff be reconstructed?",
        "service_now_impact": "Multi-step CI classification, impact analysis, owner recommendation, change readiness decision.",
        "required_evidence": "Prompt chain, intermediate outputs, source records, decision checkpoints, reviewer signoff.",
        "default_guardrail": "Do not rely on final output if chain evidence is missing."
    },
    {
        "pattern": "Agent Router",
        "azure_meaning": "Requests are routed to the most suitable specialist agent.",
        "citrust_question": "Why was this agent selected, and was it authorized for this CI, process, or regulated context?",
        "service_now_impact": "Routes to CI agent, access agent, observability agent, FinOps agent, DevOps agent, QA route.",
        "required_evidence": "Routing rule, selected agent, rejected agents, CI impact, risk tier, escalation decision.",
        "default_guardrail": "Block if router sends GMP, access, or change-sensitive work to an unauthorized agent."
    },
    {
        "pattern": "Supervisor Pattern",
        "azure_meaning": "Supervisor coordinates multiple agents, tracks execution, validates outcomes, and handles failures.",
        "citrust_question": "Who or what validated the AI output before CI, access, GxP, or change action?",
        "service_now_impact": "Multi-agent CI review, support group recommendation, access route check, readiness decision.",
        "required_evidence": "Supervisor decision, validation result, failed-agent handling, escalation, human approval.",
        "default_guardrail": "Supervisor agent cannot replace QA, cyber, LCM, system owner, or change owner approval."
    },
    {
        "pattern": "Saga Orchestration",
        "azure_meaning": "Long-running workflow uses retry, compensation, rollback, and recovery.",
        "citrust_question": "Is rollback, compensation, recovery, and deviation handling available before agentic CI action?",
        "service_now_impact": "CI update, relationship change, support group change, access route change, cutover workflow.",
        "required_evidence": "Saga steps, compensation plan, rollback path, prior state, post-check, deviation/CAPA route if needed.",
        "default_guardrail": "No execution if rollback or compensation is missing."
    },
    {
        "pattern": "Parallel Agents",
        "azure_meaning": "Multiple agents execute simultaneously to increase speed and coverage.",
        "citrust_question": "Are simultaneous agents prevented from conflicting CI updates, duplicate actions, or inconsistent access changes?",
        "service_now_impact": "Parallel CMDB review, access review, validation evidence review, relationship mapping.",
        "required_evidence": "Concurrency control, lock rule, conflict detection, deduplication, merge owner, final decision.",
        "default_guardrail": "Block conflicting updates until a human owner reconciles them."
    },
    {
        "pattern": "Evaluator and Feedback Loop",
        "azure_meaning": "Outputs are validated for execution, accuracy, cost, risk, and human approval.",
        "citrust_question": "Was the AI output evaluated for accuracy, completeness, GxP impact, access risk, and evidence quality?",
        "service_now_impact": "CI readiness score, AI recommendation score, field update permit, operational trust score.",
        "required_evidence": "Evaluation score, policy check, source match, reviewer decision, exception route, monitoring feedback.",
        "default_guardrail": "Do not close AI-assisted CI action without evaluator evidence."
    },
    {
        "pattern": "Identity and Security Governance",
        "azure_meaning": "Agent identities, keys, access, roles, and security controls are governed.",
        "citrust_question": "Does the agent have approved identity, entitlement, owner, least privilege, and audit trail?",
        "service_now_impact": "Service account, MyAccess route, CyberArk / PSM impact, support group access, admin action.",
        "required_evidence": "Agent identity, owner, access scope, entitlement approval, privileged route, cyber review.",
        "default_guardrail": "No access, entitlement, or privileged action without cybersecurity approval."
    },
    {
        "pattern": "Observability and Telemetry",
        "azure_meaning": "Azure Monitor, App Insights, logs, metrics, traces, and alerts provide runtime visibility.",
        "citrust_question": "Can ServiceNow, Azure logs, CyberArk, QA, and CMDB evidence show what happened?",
        "service_now_impact": "CI action trace, workflow event, tool call, access event, change record, monitoring alert.",
        "required_evidence": "ServiceNow log, Azure telemetry, tool-call evidence, CyberArk log, change evidence, outcome.",
        "default_guardrail": "Restrict reliance if runtime evidence cannot reconstruct the action."
    }
]


CITRUST_AGENT_TRIGGER_TYPES = [
    {
        "trigger": "ServiceNow Ticket / Request",
        "risk": "AI may act on incomplete user request or wrong CI.",
        "required_control": "Verify CI, requester, owner, workflow state, and approval route.",
        "default_decision": "Human-gated if CI impact exists."
    },
    {
        "trigger": "CMDB Field Update",
        "risk": "AI may react to stale, wrong, duplicated, or unauthorized CI update.",
        "required_control": "Validate update source, field risk, owner, and change link.",
        "default_decision": "Block if field risk is critical and approval is missing."
    },
    {
        "trigger": "Monitoring Alert",
        "risk": "AI may infer incident or support route from weak telemetry.",
        "required_control": "Confirm telemetry source, CI mapping, support group, and incident route.",
        "default_decision": "Recommend only unless owner confirms."
    },
    {
        "trigger": "Access Request",
        "risk": "AI may influence entitlement, MyAccess, CyberArk, or privileged route.",
        "required_control": "Cybersecurity / access owner route and no autonomous approval.",
        "default_decision": "Cyber-gated."
    },
    {
        "trigger": "Change Task",
        "risk": "AI may trigger workflow during unstable change or cutover state.",
        "required_control": "Change owner approval, rollback, post-check, cutover state.",
        "default_decision": "Change-controlled."
    },
    {
        "trigger": "GxP / Validation Event",
        "risk": "AI may create regulated conclusion without QA review.",
        "required_control": "QA / validation owner route, evidence lineage, regulated conclusion block.",
        "default_decision": "QA-governed only."
    }
]


CITRUST_PROMPT_CHAIN_EVIDENCE = [
    {
        "chain_step": "Intent Capture",
        "evidence_needed": "Original request, user role, workflow context, CI reference, trigger source.",
        "risk_if_missing": "Agent may solve the wrong problem."
    },
    {
        "chain_step": "Context Retrieval",
        "evidence_needed": "CMDB records, CI passport, owner/support data, validation status, change state.",
        "risk_if_missing": "Agent may use stale or untrusted CMDB context."
    },
    {
        "chain_step": "Risk Classification",
        "evidence_needed": "GxP, access, cyber, change, lifecycle, cutover, and relationship risk classification.",
        "risk_if_missing": "Agent may under-control regulated or privileged context."
    },
    {
        "chain_step": "Agent Selection / Routing",
        "evidence_needed": "Router rule, selected agent, authorized scope, rejected alternatives.",
        "risk_if_missing": "Wrong agent may act on sensitive CI."
    },
    {
        "chain_step": "Recommendation Generation",
        "evidence_needed": "Source fields, reasoning summary, confidence, limitations, assumptions.",
        "risk_if_missing": "Output may look authoritative without evidence."
    },
    {
        "chain_step": "Evaluator Review",
        "evidence_needed": "Accuracy score, policy score, GxP score, access risk, evidence score.",
        "risk_if_missing": "Low-quality output may be accepted."
    },
    {
        "chain_step": "Human Approval",
        "evidence_needed": "Reviewer, decision, timestamp, approval/rejection, conditions.",
        "risk_if_missing": "Hidden AI approval risk."
    },
    {
        "chain_step": "Outcome and Replay",
        "evidence_needed": "Executed, blocked, escalated, rejected, changed, rolled back, or closed outcome.",
        "risk_if_missing": "Audit replay is incomplete."
    }
]


CITRUST_PARALLEL_AGENT_CONTROLS = [
    {
        "control": "Concurrency Lock",
        "purpose": "Prevent two agents from updating or recommending conflicting CI changes at the same time.",
        "evidence": "Lock ID, CI ID, active agent, queued agents, resolution owner."
    },
    {
        "control": "Conflict Detection",
        "purpose": "Detect conflicting owner, support group, relationship, GxP, access, or lifecycle recommendations.",
        "evidence": "Conflict record, agents involved, fields affected, reconciliation decision."
    },
    {
        "control": "Duplicate Action Suppression",
        "purpose": "Prevent duplicated change tasks, access requests, CI updates, or relationship updates.",
        "evidence": "Duplicate check, existing action reference, suppression result."
    },
    {
        "control": "Final Decision Owner",
        "purpose": "Ensure one accountable human owner resolves parallel agent outputs.",
        "evidence": "Owner decision, accepted output, rejected output, rationale."
    },
    {
        "control": "Merged Evidence Package",
        "purpose": "Combine outputs from multiple agents into one replayable evidence package.",
        "evidence": "Agent outputs, evaluator scores, reviewer decision, final outcome."
    }
]


CITRUST_EVALUATOR_SCORECARD = [
    {
        "score_area": "Accuracy",
        "question": "Does the output match ServiceNow source records and CI passport evidence?",
        "failure_response": "Reject or require source correction."
    },
    {
        "score_area": "Completeness",
        "question": "Does the output include owner, support group, LCM, validation, change, rollback, and evidence fields where required?",
        "failure_response": "Return for evidence completion."
    },
    {
        "score_area": "GxP Impact",
        "question": "Does the output identify GMP, validated, QA, release, deviation, CAPA, or inspection sensitivity?",
        "failure_response": "Route to QA / validation owner."
    },
    {
        "score_area": "Cyber / Access Risk",
        "question": "Does the output touch MyAccess, CyberArk, PSM, privileged route, admin action, or support group access?",
        "failure_response": "Route to cybersecurity / access owner."
    },
    {
        "score_area": "Change-Control Impact",
        "question": "Does the output require ServiceNow change, task, approval, rollback, or post-check evidence?",
        "failure_response": "Route to change owner."
    },
    {
        "score_area": "Audit Replay Quality",
        "question": "Can the output be reconstructed from trigger to final outcome?",
        "failure_response": "Restrict reliance."
    }
]


def citrust_agentic_pattern_rows():
    rows = ""
    for item in CITRUST_AGENTIC_WORKFLOW_PATTERN_MAP:
        rows += f"""
        <tr>
            <td><strong>{item["pattern"]}</strong></td>
            <td>{item["azure_meaning"]}</td>
            <td>{item["citrust_question"]}</td>
            <td>{item["service_now_impact"]}</td>
            <td>{item["required_evidence"]}</td>
            <td><span class="badge red">{item["default_guardrail"]}</span></td>
        </tr>
        """
    return rows


def citrust_agent_trigger_rows():
    rows = ""
    for item in CITRUST_AGENT_TRIGGER_TYPES:
        rows += f"""
        <tr>
            <td><strong>{item["trigger"]}</strong></td>
            <td><span class="badge red">{item["risk"]}</span></td>
            <td>{item["required_control"]}</td>
            <td><span class="badge orange">{item["default_decision"]}</span></td>
        </tr>
        """
    return rows


def citrust_prompt_chain_rows():
    rows = ""
    for item in CITRUST_PROMPT_CHAIN_EVIDENCE:
        rows += f"""
        <tr>
            <td><strong>{item["chain_step"]}</strong></td>
            <td>{item["evidence_needed"]}</td>
            <td><span class="badge red">{item["risk_if_missing"]}</span></td>
        </tr>
        """
    return rows


def citrust_parallel_agent_rows():
    rows = ""
    for item in CITRUST_PARALLEL_AGENT_CONTROLS:
        rows += f"""
        <tr>
            <td><strong>{item["control"]}</strong></td>
            <td>{item["purpose"]}</td>
            <td>{item["evidence"]}</td>
        </tr>
        """
    return rows


def citrust_evaluator_scorecard_rows():
    rows = ""
    for item in CITRUST_EVALUATOR_SCORECARD:
        rows += f"""
        <tr>
            <td><strong>{item["score_area"]}</strong></td>
            <td>{item["question"]}</td>
            <td><span class="badge orange">{item["failure_response"]}</span></td>
        </tr>
        """
    return rows


def citrust_agentic_workflow_decision(trigger, context, chain, router, supervisor, rollback, parallel, evaluator, identity, telemetry, change):
    checks = [trigger, context, chain, router, supervisor, rollback, parallel, evaluator, identity, telemetry, change]
    score = int((sum(1 for item in checks if item == "yes") / len(checks)) * 100)

    if trigger != "yes":
        return score, "Block Agentic Workflow", "red", "Agent trigger is not trusted or not traceable."
    if identity != "yes":
        return score, "Block Agentic Workflow", "red", "Agent identity, entitlement, owner, or least-privilege control is missing."
    if context != "yes":
        return score, "Restrict to Advisory", "orange", "Agent context is not approved, current, or traceable."
    if chain != "yes":
        return score, "Prompt Chain Evidence Required", "orange", "Prompt chain cannot be reconstructed."
    if router != "yes":
        return score, "Routing Policy Required", "red", "Agent router decision is not governed."
    if supervisor != "yes":
        return score, "Supervisor / Human Oversight Required", "red", "Agent output has not been validated before reliance."
    if rollback != "yes":
        return score, "No Execution", "red", "Saga rollback, compensation, or recovery evidence is missing."
    if parallel != "yes":
        return score, "Parallel Agent Restriction", "orange", "Conflict, duplicate action, or concurrency control is missing."
    if evaluator != "yes":
        return score, "Evaluator Loop Required", "orange", "Accuracy, completeness, GxP, access, change, and evidence checks are incomplete."
    if telemetry != "yes":
        return score, "Observability Gap", "orange", "Runtime telemetry and audit trail cannot prove what happened."
    if change != "yes":
        return score, "Change-Control Integration Required", "red", "AI-to-change-control routing is incomplete."
    if score == 100:
        return score, "Agentic Workflow Trusted With Controls", "green", "Workflow is trigger-trusted, identity-controlled, routed, supervised, rollback-ready, evaluated, observable, and change-integrated."
    return score, "Conditional Agentic Workflow", "yellow", "Workflow may operate only with restrictions and remediation tracking."


try:
    AGENTTRUST_EXPECTED_ROUTES.extend([
        "/citrust/agentic-workflow-governance-patterns",
        "/citrust/agentic-workflow-assurance-patterns",
        "/citrust/azure-agentic-pattern-mapping",
        "/citrust/agent-trigger-governance",
        "/citrust/prompt-chain-evidence",
        "/citrust/agent-routing-policy",
        "/citrust/supervisor-agent-oversight",
        "/citrust/saga-rollback-assurance",
        "/citrust/parallel-agent-control",
        "/citrust/agent-evaluation-scorecard",
        "/citrust/agent-identity-entitlement-control",
        "/citrust/agent-observability-telemetry",
        "/citrust/ai-change-control-integration",
        "/citrust/agentic-workflow-simulator",
        "/citrust/agentic-workflow-json"
    ])
except Exception:
    pass


@app.route("/citrust/agentic-workflow-governance-patterns")
@app.route("/citrust/agentic-workflow-assurance-patterns")
@app.route("/citrust/azure-agentic-workflow-patterns")
def citrust_agentic_workflow_governance_patterns():
    rows = citrust_agentic_pattern_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Azure Patterns</div><div class="value" style="color:var(--green);">Mapped</div><div class="note">Agentic workflow patterns converted to CITrust™ controls.</div></div>
        <div class="metric"><div class="label">Trigger Governance</div><div class="value" style="color:var(--blue);">Required</div><div class="note">Every agent action must have trusted trigger evidence.</div></div>
        <div class="metric"><div class="label">Prompt Chain</div><div class="value" style="color:var(--yellow);">Replayable</div><div class="note">Multi-step reasoning needs chain evidence.</div></div>
        <div class="metric"><div class="label">Supervisor</div><div class="value" style="color:var(--orange);">Human-Governed</div><div class="note">Supervisor agent cannot replace accountable owner approval.</div></div>
        <div class="metric"><div class="label">Rollback</div><div class="value" style="color:var(--red);">Mandatory</div><div class="note">Saga recovery and rollback required before execution.</div></div>
        <div class="metric"><div class="label">Observability</div><div class="value" style="color:var(--purple);">Evidence-Led</div><div class="note">Azure, ServiceNow, CyberArk, and QA evidence unified.</div></div>
    </section>

    <section class="section">
        <h2>CITrust™ Agentic Workflow Governance Patterns</h2>
        <div class="answer">
            <strong>Purpose:</strong> translate Azure agentic workflow patterns into regulated ServiceNow / CMDB assurance controls.
            Azure explains how to build agentic workflows. CITrust™ proves whether those workflows are trusted enough
            to interact with CIs, support groups, access routes, change records, validation status, and GMP-impacting systems.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Azure Pattern</th>
                    <th>Azure Meaning</th>
                    <th>CITrust™ Governance Question</th>
                    <th>ServiceNow / CMDB Impact</th>
                    <th>Required Evidence</th>
                    <th>Default Guardrail</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Positioning</h2>
        <div class="answer">
            <strong>Azure answers:</strong> How do we build agentic AI workflows?<br>
            <strong>AgentTrust™ answers:</strong> Can this AI agent be governed, authorized, monitored, evidenced, and trusted?<br>
            <strong>CITrust™ answers:</strong> Can this AI agent safely interact with ServiceNow CMDB, CIs, ownership, support groups,
            access routes, change control, validation state, and GMP-impacting systems?
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Workflow Governance Patterns",
        "Azure agentic workflow patterns converted into regulated ServiceNow, CMDB, GxP, access, change-control, evidence, and operational trust controls.",
        body
    )


@app.route("/citrust/azure-agentic-pattern-mapping")
@app.route("/citrust/azure-agentic-mapping")
@app.route("/citrust/agentic-pattern-mapping")
def citrust_azure_agentic_pattern_mapping():
    rows = citrust_agentic_pattern_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Azure Agentic Pattern Mapping</h2>
        <p>
            This mapping shows how CITrust™ governs each Azure agentic workflow pattern when agents interact with ServiceNow, CMDB, access, GxP, or change-control workflows.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Pattern</th>
                    <th>Azure Meaning</th>
                    <th>CITrust™ Question</th>
                    <th>ServiceNow Impact</th>
                    <th>Evidence</th>
                    <th>Guardrail</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Azure Agentic Pattern Mapping",
        "Mapping of Azure agentic workflow patterns to CITrust™ ServiceNow, CMDB, GxP, access, change-control, evidence, and rollback guardrails.",
        body
    )


@app.route("/citrust/agent-trigger-governance")
@app.route("/citrust/ai-agent-trigger-governance")
@app.route("/citrust/event-driven-agent-governance")
def citrust_agent_trigger_governance():
    rows = citrust_agent_trigger_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agent Trigger Governance</h2>
        <p>
            Event-driven AI agents must prove what triggered the action before they can touch CI, access, change, or regulated workflows.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Trigger</th>
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
        <h2>Trigger Rule</h2>
        <div class="answer">
            CITrust™ should not trust an agentic action unless the trigger is known, authorized, current, mapped to the correct CI,
            and routed to the correct owner.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agent Trigger Governance",
        "Trigger governance for event-driven AI agents reacting to ServiceNow tickets, CMDB updates, alerts, access requests, change tasks, and GxP events.",
        body
    )


@app.route("/citrust/prompt-chain-evidence")
@app.route("/citrust/ai-prompt-chain-evidence")
@app.route("/citrust/prompt-chaining-evidence")
def citrust_prompt_chain_evidence():
    rows = citrust_prompt_chain_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Prompt Chain Evidence</h2>
        <p>
            Prompt chaining must preserve each reasoning step, input, output, routing decision, evaluator result, and human approval.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Prompt Chain Step</th>
                    <th>Evidence Needed</th>
                    <th>Risk If Missing</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Prompt Chain Rule</h2>
        <div class="answer">
            Final AI output is not enough. For regulated CMDB workflows, CITrust™ must preserve the chain of reasoning,
            retrieved CMDB context, risk classification, routing, evaluation, human decision, and outcome.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Prompt Chain Evidence",
        "Prompt chain evidence for multi-step AI reasoning across ServiceNow CI context, risk classification, routing, evaluation, approval, and outcome replay.",
        body
    )


@app.route("/citrust/agent-routing-policy")
@app.route("/citrust/ai-agent-router-policy")
@app.route("/citrust/agent-router-governance")
def citrust_agent_routing_policy():
    body = """
    <section class="section">
        <h2>CITrust™ Agent Routing Policy</h2>
        <p>
            Agent routing policy governs why a request is sent to a specific specialist agent.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Routing Scenario</th>
                    <th>Required Route</th>
                    <th>Evidence Needed</th>
                    <th>Block Condition</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>CI ownership or support gap.</td><td>CI Ownership Agent + LCM / CMDB Owner.</td><td>CI ID, owner fields, support group, orphan status.</td><td><span class="badge red">No owner route</span></td></tr>
                <tr><td>Access, MyAccess, CyberArk, PSM, privileged context.</td><td>Access / Cyber Agent + Cybersecurity Owner.</td><td>Access route, entitlement context, cyber decision.</td><td><span class="badge red">No cyber review</span></td></tr>
                <tr><td>GMP, validated, QA, release, deviation, CAPA, inspection context.</td><td>GxP Agent + QA / Validation Owner.</td><td>GxP screen, validation status, QA decision.</td><td><span class="badge red">No QA route</span></td></tr>
                <tr><td>Service impact or relationship mapping.</td><td>Relationship Mapping Agent + Service / Technical Owner.</td><td>Source CI, target CI, confidence score, owner approval.</td><td><span class="badge orange">Weak relationship confidence</span></td></tr>
                <tr><td>Change or cutover-sensitive workflow.</td><td>Change / Cutover Agent + Change Owner.</td><td>Change record, rollback, post-check, cutover status.</td><td><span class="badge red">No change evidence</span></td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agent Routing Policy",
        "Agent routing policy for ServiceNow, CMDB, access, CyberArk, GxP, relationship mapping, change-control, and cutover-sensitive workflows.",
        body
    )


@app.route("/citrust/supervisor-agent-oversight")
@app.route("/citrust/supervisor-pattern-oversight")
@app.route("/citrust/ai-supervisor-oversight")
def citrust_supervisor_agent_oversight():
    body = """
    <section class="section">
        <h2>CITrust™ Supervisor Agent Oversight</h2>
        <p>
            Supervisor agents may coordinate AI work, but they must not replace accountable human owners.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Supervisor Function</th>
                    <th>Allowed Role</th>
                    <th>Not Allowed</th>
                    <th>Evidence Required</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Coordinate specialist agents.</td><td>Assign tasks to approved agents.</td><td>Assign regulated work to unauthorized agent.</td><td>Routing rule and selected agent evidence.</td></tr>
                <tr><td>Validate output.</td><td>Check completeness, policy, evidence, and risk flags.</td><td>Declare QA, cyber, or owner approval.</td><td>Evaluator score and validation result.</td></tr>
                <tr><td>Handle failures.</td><td>Escalate failed actions, missing evidence, or risky outputs.</td><td>Suppress failure or auto-close issue.</td><td>Failure log and escalation route.</td></tr>
                <tr><td>Coordinate rollback.</td><td>Confirm rollback evidence exists.</td><td>Execute recovery without owner approval.</td><td>Rollback plan and recovery owner.</td></tr>
                <tr><td>Prepare final package.</td><td>Assemble evidence for owner review.</td><td>Sign off on behalf of accountable owner.</td><td>Evidence package and human signoff.</td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Supervisor Agent Oversight",
        "Supervisor agent oversight for multi-agent coordination, output validation, failure handling, rollback coordination, evidence packaging, and human signoff.",
        body
    )


@app.route("/citrust/saga-rollback-assurance")
@app.route("/citrust/agentic-saga-rollback")
@app.route("/citrust/agent-saga-orchestration")
def citrust_saga_rollback_assurance():
    body = """
    <section class="section">
        <h2>CITrust™ Saga / Rollback Assurance</h2>
        <p>
            Long-running agentic workflows require compensation, rollback, recovery, and deviation handling before AI action.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Saga Step</th>
                    <th>Required Assurance</th>
                    <th>Evidence</th>
                    <th>Failure Response</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Pre-action state capture.</td><td>Capture original CI values, relationships, owner, support group, and change state.</td><td>Before-state evidence.</td><td><span class="badge red">No execution</span></td></tr>
                <tr><td>Compensation plan.</td><td>Define how to reverse, compensate, or correct each step.</td><td>Compensation route and owner.</td><td><span class="badge red">Block workflow</span></td></tr>
                <tr><td>Retry control.</td><td>Prevent repeated failed AI actions from creating duplicate changes.</td><td>Retry policy and duplicate suppression.</td><td><span class="badge orange">Escalate</span></td></tr>
                <tr><td>Rollback owner.</td><td>Named owner must approve recovery.</td><td>Owner signoff.</td><td><span class="badge red">No recovery action</span></td></tr>
                <tr><td>Deviation / CAPA route.</td><td>GxP-impacting failures route to QA if regulated impact exists.</td><td>QA decision and incident evidence.</td><td><span class="badge red">QA-governed</span></td></tr>
                <tr><td>Post-action check.</td><td>Verify CI state, relationship, support route, and evidence after action.</td><td>Post-check evidence.</td><td><span class="badge orange">Do not close</span></td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Saga Rollback Assurance",
        "Saga orchestration and rollback assurance for long-running AI workflows touching CMDB, ServiceNow, GxP, access, support, and change processes.",
        body
    )


@app.route("/citrust/parallel-agent-control")
@app.route("/citrust/parallel-ai-agent-control")
@app.route("/citrust/parallel-agent-governance")
def citrust_parallel_agent_control():
    rows = citrust_parallel_agent_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Parallel Agent Control</h2>
        <p>
            Parallel agents must not create conflicting CI updates, duplicate changes, inconsistent access routes, or unsupported merged outputs.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Parallel Control</th>
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
        "CITrust™ Parallel Agent Control",
        "Parallel agent control for concurrency locks, conflict detection, duplicate action suppression, final owner decision, and merged evidence packages.",
        body
    )


@app.route("/citrust/agent-evaluation-scorecard")
@app.route("/citrust/ai-agent-evaluator-scorecard")
@app.route("/citrust/evaluator-feedback-loop")
def citrust_agent_evaluation_scorecard():
    rows = citrust_evaluator_scorecard_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agent Evaluation Scorecard</h2>
        <p>
            Every AI-assisted CI output should be evaluated before closure or operational reliance.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Score Area</th>
                    <th>Evaluation Question</th>
                    <th>Failure Response</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agent Evaluation Scorecard",
        "Evaluator feedback loop scorecard for AI-assisted CI accuracy, completeness, GxP impact, cyber risk, change-control impact, and audit replay quality.",
        body
    )


@app.route("/citrust/agent-identity-entitlement-control")
@app.route("/citrust/ai-agent-identity-control")
@app.route("/citrust/agent-security-entitlement-control")
def citrust_agent_identity_entitlement_control():
    body = """
    <section class="section">
        <h2>CITrust™ Agent Identity and Entitlement Control</h2>
        <p>
            AI agents should be governed like controlled digital actors with identity, owner, access scope, least privilege, and audit trail.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Identity Control</th>
                    <th>Requirement</th>
                    <th>Evidence</th>
                    <th>Default Decision</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent identity</td><td>Unique agent ID and owner.</td><td>Agent registry and owner record.</td><td><span class="badge red">Block if unknown</span></td></tr>
                <tr><td>Entitlement scope</td><td>Least-privilege access only.</td><td>Entitlement list and approval route.</td><td><span class="badge orange">Restrict excess access</span></td></tr>
                <tr><td>Service account mapping</td><td>Agent account mapped to accountable owner.</td><td>Service account owner and review evidence.</td><td><span class="badge red">No owner, no access</span></td></tr>
                <tr><td>Privileged context</td><td>CyberArk / PSM route if admin or privileged action exists.</td><td>Cybersecurity approval.</td><td><span class="badge red">Cyber-gated</span></td></tr>
                <tr><td>Audit trail</td><td>Agent activity logged with CI, workflow, tool, and outcome.</td><td>Runtime evidence and telemetry.</td><td><span class="badge red">No trust without logs</span></td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agent Identity Entitlement Control",
        "Identity and entitlement control for AI agents touching ServiceNow CMDB, CIs, access routes, CyberArk, PSM, support groups, and workflow actions.",
        body
    )


@app.route("/citrust/agent-observability-telemetry")
@app.route("/citrust/ai-agent-observability")
@app.route("/citrust/agent-telemetry-evidence")
def citrust_agent_observability_telemetry():
    body = """
    <section class="section">
        <h2>CITrust™ Agent Observability and Telemetry Evidence</h2>
        <p>
            Observability connects Azure Monitor, App Insights, ServiceNow logs, CyberArk logs, CMDB activity, QA evidence, and runtime evidence.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Evidence Source</th>
                    <th>What It Proves</th>
                    <th>Required Link</th>
                    <th>If Missing</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>ServiceNow activity log</td><td>CI, ticket, task, workflow, field, or relationship touched.</td><td>CI ID / workflow ID.</td><td><span class="badge red">No CMDB audit trail</span></td></tr>
                <tr><td>Azure Monitor / App Insights</td><td>Agent runtime, call trace, errors, latency, failure events.</td><td>Agent session ID.</td><td><span class="badge orange">Weak runtime trace</span></td></tr>
                <tr><td>CyberArk / PSM logs</td><td>Privileged route, admin context, access activity.</td><td>Cyber session / access request.</td><td><span class="badge red">Cyber evidence gap</span></td></tr>
                <tr><td>CMDB evidence ledger</td><td>Source CI, before/after state, owner, relationship, validation status.</td><td>CI passport / evidence record.</td><td><span class="badge red">Cannot replay CI action</span></td></tr>
                <tr><td>QA / validation evidence</td><td>Regulated impact, validation status, QA decision.</td><td>QA review / validation evidence.</td><td><span class="badge red">GxP defensibility gap</span></td></tr>
                <tr><td>Change record</td><td>Impact analysis, approval, rollback, post-check.</td><td>Change ID.</td><td><span class="badge red">Change-control gap</span></td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agent Observability Telemetry",
        "Observability and telemetry evidence for AI agent actions using ServiceNow logs, Azure Monitor, App Insights, CyberArk, CMDB evidence, QA evidence, and change records.",
        body
    )


@app.route("/citrust/ai-change-control-integration")
@app.route("/citrust/agent-change-control-integration")
@app.route("/citrust/ai-to-change-control-integration")
def citrust_ai_change_control_integration():
    body = """
    <section class="section">
        <h2>CITrust™ AI-to-Change-Control Integration</h2>
        <p>
            AI recommendations and agentic actions must determine whether ServiceNow change, task, deviation, exception, or approval record is required.
        </p>

        <table>
            <thead>
                <tr>
                    <th>AI Output / Action</th>
                    <th>Change-Control Question</th>
                    <th>Required Record</th>
                    <th>Default Decision</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>CI owner or support group recommendation.</td><td>Does this affect operational accountability?</td><td>Review task or change if material.</td><td><span class="badge yellow">Human-gated</span></td></tr>
                <tr><td>CI relationship recommendation.</td><td>Does this affect impact analysis, service map, or support route?</td><td>Change/task with relationship owner approval.</td><td><span class="badge orange">Change review</span></td></tr>
                <tr><td>Lifecycle or operational state change.</td><td>Does this change system operational status?</td><td>Formal change record.</td><td><span class="badge red">Change-controlled</span></td></tr>
                <tr><td>GxP / validation metadata update.</td><td>Does this affect regulated state or validation evidence?</td><td>QA review, validation record, change/deviation if applicable.</td><td><span class="badge red">QA-governed</span></td></tr>
                <tr><td>Access or privileged route update.</td><td>Does this affect MyAccess, CyberArk, PSM, or entitlement route?</td><td>Cyber/access approval record.</td><td><span class="badge red">Cyber-gated</span></td></tr>
                <tr><td>Cutover-sensitive recommendation.</td><td>Does this affect cutover readiness, rollback, or go-live risk?</td><td>Cutover task, risk record, change record.</td><td><span class="badge red">No autonomous action</span></td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ AI to Change Control Integration",
        "AI-to-change-control integration for CI ownership, support group, relationships, lifecycle state, GxP metadata, access route, and cutover-sensitive actions.",
        body
    )


@app.route("/citrust/agentic-workflow-simulator", methods=["GET", "POST"])
@app.route("/citrust/azure-agentic-workflow-simulator", methods=["GET", "POST"])
@app.route("/citrust/agentic-pattern-simulator", methods=["GET", "POST"])
def citrust_agentic_workflow_simulator():
    from flask import request

    trigger = request.form.get("trigger", "yes")
    context = request.form.get("context", "yes")
    chain = request.form.get("chain", "yes")
    router = request.form.get("router", "yes")
    supervisor = request.form.get("supervisor", "yes")
    rollback = request.form.get("rollback", "yes")
    parallel = request.form.get("parallel", "yes")
    evaluator = request.form.get("evaluator", "yes")
    identity = request.form.get("identity", "yes")
    telemetry = request.form.get("telemetry", "yes")
    change = request.form.get("change", "yes")

    score, decision, badge, reason = citrust_agentic_workflow_decision(
        trigger, context, chain, router, supervisor, rollback, parallel, evaluator, identity, telemetry, change
    )

    def selected(value, expected):
        return "selected" if value == expected else ""

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Workflow Trust Score</div><div class="value" style="color:var(--green);">{score}%</div><div class="note">Calculated from agentic workflow controls.</div></div>
        <div class="metric"><div class="label">Workflow Decision</div><div class="value" style="color:var(--yellow);">{decision}</div><div class="note">{reason}</div></div>
    </section>

    <section class="section">
        <h2>CITrust™ Agentic Workflow Simulator</h2>
        <p>
            Simulate whether an Azure-style agentic workflow is trusted enough to interact with ServiceNow CMDB, CIs,
            GxP metadata, access routes, support groups, or change-control workflows.
        </p>

        <form method="POST" action="/citrust/agentic-workflow-simulator">
            <table>
                <tbody>
                    <tr><td><strong>Trusted Trigger Evidence Ready?</strong></td><td><select name="trigger" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(trigger, "yes")}>Yes</option><option value="no" {selected(trigger, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Approved Context / Knowledge Ready?</strong></td><td><select name="context" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(context, "yes")}>Yes</option><option value="no" {selected(context, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Prompt Chain Evidence Ready?</strong></td><td><select name="chain" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(chain, "yes")}>Yes</option><option value="no" {selected(chain, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Agent Router Policy Ready?</strong></td><td><select name="router" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(router, "yes")}>Yes</option><option value="no" {selected(router, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Supervisor / Human Oversight Ready?</strong></td><td><select name="supervisor" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(supervisor, "yes")}>Yes</option><option value="no" {selected(supervisor, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Saga Rollback / Recovery Ready?</strong></td><td><select name="rollback" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(rollback, "yes")}>Yes</option><option value="no" {selected(rollback, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Parallel Agent Conflict Control Ready?</strong></td><td><select name="parallel" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(parallel, "yes")}>Yes</option><option value="no" {selected(parallel, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Evaluator / Feedback Loop Ready?</strong></td><td><select name="evaluator" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(evaluator, "yes")}>Yes</option><option value="no" {selected(evaluator, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Agent Identity / Entitlement Controlled?</strong></td><td><select name="identity" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(identity, "yes")}>Yes</option><option value="no" {selected(identity, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Observability / Telemetry Evidence Ready?</strong></td><td><select name="telemetry" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(telemetry, "yes")}>Yes</option><option value="no" {selected(telemetry, "no")}>No</option></select></td></tr>
                    <tr><td><strong>AI-to-Change-Control Integration Ready?</strong></td><td><select name="change" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(change, "yes")}>Yes</option><option value="no" {selected(change, "no")}>No</option></select></td></tr>
                </tbody>
            </table>

            <button type="submit" style="margin-top:16px;padding:12px 18px;border-radius:12px;border:0;background:#2563eb;color:white;font-weight:800;">Run Agentic Workflow Trust Check</button>
        </form>
    </section>

    <section class="section">
        <h2>Agentic Workflow Trust Decision</h2>
        <div class="answer">
            <strong>Score:</strong> {score}%<br>
            <strong>Decision:</strong> <span class="badge {badge}">{decision}</span><br>
            <strong>Reason:</strong> {reason}
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Workflow Simulator",
        "Simulator for Azure-style agentic workflow trust across trigger, context, prompt chain, router, supervisor, rollback, parallel control, evaluator loop, identity, observability, and change-control integration.",
        body
    )


@app.route("/citrust/agentic-workflow-json")
@app.route("/citrust/azure-agentic-workflow-json")
@app.route("/citrust/agentic-pattern-json")
def citrust_agentic_workflow_json():
    from flask import jsonify

    return jsonify({
        "module": "CITrust™",
        "capability": "Agentic Workflow Governance Patterns",
        "primary_question": "Can this Azure-style agentic workflow be trusted to interact with ServiceNow CMDB, CIs, GxP metadata, access routes, support groups, and change-control workflows?",
        "agentic_pattern_map": CITRUST_AGENTIC_WORKFLOW_PATTERN_MAP,
        "agent_trigger_types": CITRUST_AGENT_TRIGGER_TYPES,
        "prompt_chain_evidence": CITRUST_PROMPT_CHAIN_EVIDENCE,
        "parallel_agent_controls": CITRUST_PARALLEL_AGENT_CONTROLS,
        "evaluator_scorecard": CITRUST_EVALUATOR_SCORECARD,
        "minimum_conditions": [
            "Agent trigger is trusted and traceable",
            "Agent context uses approved CMDB, policy, SOP, validation, and ownership sources",
            "Prompt chain evidence is replayable",
            "Agent router selection is governed",
            "Supervisor agent does not replace accountable human owner",
            "Saga rollback, compensation, and recovery are defined",
            "Parallel agents cannot create conflicting CI or access changes",
            "Evaluator loop checks accuracy, completeness, GxP, cyber, change, and audit replay quality",
            "Agent identity, entitlement, owner, and least privilege are controlled",
            "Observability and telemetry evidence are linked across ServiceNow, Azure, CyberArk, QA, and CMDB",
            "AI-to-change-control integration is ready"
        ],
        "default_decision": "Do not allow agentic workflow reliance against ServiceNow CMDB, CIs, access, GxP, or change-control workflows unless trigger, context, routing, supervision, rollback, evaluator, identity, observability, and change-control evidence are complete"
    })

# ============================================================
# END CITRUST_AGENTIC_WORKFLOW_GOVERNANCE_PATTERNS_V1_ACTIVE
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

print("CITrust Agentic Workflow Governance Patterns installed.")
print(f"Inserted before: {target_found}")
