from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_AGENT_OBSERVABILITY_EVIDENCE_FABRIC_V1_ACTIVE"

if MARKER in text:
    print("CITrust Agent Observability Evidence Fabric already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base shell not found. Install AgentTrust base module first.")

nav_old = '<a href="/citrust/agent-memory-governance" class="secondary">Agent Memory</a>'
nav_new = '''<a href="/citrust/agent-memory-governance" class="secondary">Agent Memory</a>
                    <a href="/citrust/agent-observability-evidence-fabric" class="secondary">Observability Fabric</a>
                    <a href="/citrust/telemetry-correlation-center" class="dark">Telemetry Correlation</a>
                    <a href="/citrust/agent-runtime-event-ledger" class="dark">Runtime Events</a>
                    <a href="/citrust/observability-evidence-simulator" class="dark">Telemetry Sim</a>'''

if nav_old in text and "/citrust/agent-observability-evidence-fabric" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# CITRUST_AGENT_OBSERVABILITY_EVIDENCE_FABRIC_V1_ACTIVE
# CITrust™ Agent Observability Evidence Fabric
# Telemetry Correlation Center, ServiceNow Agent Log Map,
# Azure Monitor / App Insights Evidence, CyberArk / PSM Evidence,
# CMDB Activity Evidence, QA / Change Evidence Linkage,
# Runtime Event Ledger, Evidence Fusion Rules,
# Observability Evidence Simulator, and JSON Export
# ============================================================

CITRUST_OBSERVABILITY_EVIDENCE_SOURCES = [
    {
        "source_id": "OBS-001",
        "source": "ServiceNow Activity / Audit Log",
        "proves": "Which ticket, task, CI, field, relationship, workflow, or change record was touched.",
        "required_link": "CI ID, task ID, change ID, field name, before/after value, timestamp.",
        "risk_if_missing": "No CMDB audit trail for AI-assisted action."
    },
    {
        "source_id": "OBS-002",
        "source": "Azure Monitor / App Insights",
        "proves": "Agent runtime, request trace, error, latency, dependency call, exception, and session behavior.",
        "required_link": "Agent session ID, correlation ID, trace ID, runtime event ID.",
        "risk_if_missing": "Cannot reconstruct agent runtime behavior."
    },
    {
        "source_id": "OBS-003",
        "source": "Agent Runtime / Tool-Call Log",
        "proves": "What tool or API the agent used, target system, request mode, result, and action outcome.",
        "required_link": "Tool-call ID, target system, action type, permit decision, outcome.",
        "risk_if_missing": "No evidence of what the agent actually did."
    },
    {
        "source_id": "OBS-004",
        "source": "CyberArk / PSM / Access Log",
        "proves": "Privileged route, admin context, session activity, access decision, or credential boundary.",
        "required_link": "CyberArk session, PSM route, access request, privileged account reference.",
        "risk_if_missing": "Cybersecurity cannot defend privileged or access-related AI action."
    },
    {
        "source_id": "OBS-005",
        "source": "CMDB Evidence Ledger",
        "proves": "CI identity, ownership, support group, LCM, lifecycle, relationship, validation, and graph trust state.",
        "required_link": "CI passport, graph trust score, owner record, relationship confidence.",
        "risk_if_missing": "AI action cannot be tied to trusted CI state."
    },
    {
        "source_id": "OBS-006",
        "source": "QA / Validation Evidence",
        "proves": "GMP status, validation status, QA owner decision, regulated impact, inspection sensitivity.",
        "required_link": "QA review, validation evidence, GxP screen, regulated decision.",
        "risk_if_missing": "GxP defensibility gap."
    },
    {
        "source_id": "OBS-007",
        "source": "Change-Control Evidence",
        "proves": "Impact assessment, approval, implementation state, rollback, post-check, and closure.",
        "required_link": "Change ID, task ID, approval, rollback record, post-implementation verification.",
        "risk_if_missing": "AI-influenced operational change is not change-controlled."
    },
    {
        "source_id": "OBS-008",
        "source": "Human Review / Attestation Record",
        "proves": "Who reviewed the AI output, approved or rejected it, and under what conditions.",
        "required_link": "Reviewer, owner role, decision, timestamp, exception, signoff record.",
        "risk_if_missing": "Hidden AI approval risk."
    }
]


CITRUST_TELEMETRY_CORRELATION_CONTROLS = [
    {
        "control_id": "TC-001",
        "control": "Correlation ID Control",
        "question": "Can all logs be tied to the same agent session and CI action?",
        "required_evidence": "Shared correlation ID across agent runtime, ServiceNow, Azure, and tool-call evidence.",
        "failure_response": "Do not treat the evidence trail as complete."
    },
    {
        "control_id": "TC-002",
        "control": "Time Synchronization Control",
        "question": "Do timestamps align across ServiceNow, Azure, CyberArk, CMDB, and change evidence?",
        "required_evidence": "Timestamp sequence from trigger to final outcome.",
        "failure_response": "Run evidence reconciliation before closure."
    },
    {
        "control_id": "TC-003",
        "control": "Actor Identity Control",
        "question": "Can we identify the AI agent, service account, user, reviewer, and approver?",
        "required_evidence": "Agent ID, service account, user ID, reviewer, approver, owner.",
        "failure_response": "Block reliance if actor is unknown."
    },
    {
        "control_id": "TC-004",
        "control": "CI Object Linkage",
        "question": "Can the telemetry prove which CI, CI field, relationship, workflow, or change was affected?",
        "required_evidence": "CI ID, field name, relationship ID, workflow ID, change ID.",
        "failure_response": "No CI impact claim."
    },
    {
        "control_id": "TC-005",
        "control": "GxP / Cyber Route Preservation",
        "question": "Did the evidence preserve regulated and privileged context?",
        "required_evidence": "GxP flag, QA route, access flag, CyberArk / PSM route, cyber decision.",
        "failure_response": "Escalate to QA or cybersecurity."
    },
    {
        "control_id": "TC-006",
        "control": "Outcome Closure Control",
        "question": "Can the evidence show whether the action was executed, blocked, rejected, escalated, rolled back, or closed?",
        "required_evidence": "Outcome event, owner decision, post-check, closure evidence.",
        "failure_response": "Do not close workflow."
    }
]


CITRUST_RUNTIME_EVENT_TYPES = [
    {
        "event_type": "Agent Triggered",
        "description": "Agent starts because of ServiceNow request, CMDB update, monitoring alert, access request, change task, or GxP event.",
        "required_fields": "Trigger source, event ID, CI ID, initiator, timestamp."
    },
    {
        "event_type": "Context Retrieved",
        "description": "Agent retrieves CMDB, owner, support group, validation, access, relationship, or change context.",
        "required_fields": "Source system, source record, context version, freshness timestamp."
    },
    {
        "event_type": "Risk Classified",
        "description": "Agent classifies CI, access, GxP, change, lifecycle, relationship, or cutover risk.",
        "required_fields": "Risk tier, rule ID, classification basis, owner route."
    },
    {
        "event_type": "Tool Call Attempted",
        "description": "Agent attempts to call tool, API, workflow, ServiceNow route, or evidence function.",
        "required_fields": "Tool ID, target system, action type, permit decision, timestamp."
    },
    {
        "event_type": "Human Review Requested",
        "description": "Agent pauses for LCM, QA, cyber, system owner, support owner, or change owner review.",
        "required_fields": "Reviewer role, reviewer name, review reason, due condition."
    },
    {
        "event_type": "Action Blocked",
        "description": "Agent action is blocked by GxP, cyber, change, rollback, authority, or evidence gate.",
        "required_fields": "Block rule, reason, owner route, remediation needed."
    },
    {
        "event_type": "Action Executed",
        "description": "Approved action is executed inside allowed boundary.",
        "required_fields": "Approval ID, change ID if applicable, tool-call result, outcome."
    },
    {
        "event_type": "Rollback / Recovery",
        "description": "AI-influenced action is reversed, compensated, corrected, or recovered.",
        "required_fields": "Rollback owner, prior state, restored state, post-check."
    },
    {
        "event_type": "Workflow Closed",
        "description": "Evidence package is complete and owner closes the workflow.",
        "required_fields": "Closure owner, evidence package, final decision, signoff."
    }
]


CITRUST_EVIDENCE_FUSION_RULES = [
    {
        "fusion_rule": "One action, one correlation trail",
        "meaning": "Every AI-assisted CI action must have one traceable evidence chain across systems.",
        "minimum_evidence": "Agent session, ServiceNow record, CI ID, telemetry, tool call, reviewer, outcome."
    },
    {
        "fusion_rule": "Runtime evidence must match CMDB evidence",
        "meaning": "Telemetry must tie back to the actual CI and current CMDB state.",
        "minimum_evidence": "CI passport, field touched, owner, support group, lifecycle, validation state."
    },
    {
        "fusion_rule": "Cyber evidence must be attached for access or privileged context",
        "meaning": "Access, MyAccess, CyberArk, PSM, admin, or privileged impact requires cyber evidence.",
        "minimum_evidence": "Cyber route, access decision, privileged session evidence, approval or block."
    },
    {
        "fusion_rule": "QA evidence must be attached for regulated context",
        "meaning": "GMP, validated, QA, release, deviation, CAPA, QC, or inspection context requires QA evidence.",
        "minimum_evidence": "GxP screen, QA decision, validation evidence, regulated reliance status."
    },
    {
        "fusion_rule": "Change evidence must be attached for material CI impact",
        "meaning": "Material updates, relationship changes, lifecycle changes, and support route changes require change evidence.",
        "minimum_evidence": "Change record, approval, rollback, post-check, closure."
    },
    {
        "fusion_rule": "No closure without outcome evidence",
        "meaning": "Workflow is not complete until result is executed, blocked, rejected, escalated, rolled back, or closed.",
        "minimum_evidence": "Outcome event, owner signoff, closure timestamp."
    }
]


def citrust_observability_source_rows():
    rows = ""
    for item in CITRUST_OBSERVABILITY_EVIDENCE_SOURCES:
        rows += f"""
        <tr>
            <td><strong>{item["source_id"]}</strong></td>
            <td><span class="badge blue">{item["source"]}</span></td>
            <td>{item["proves"]}</td>
            <td>{item["required_link"]}</td>
            <td><span class="badge red">{item["risk_if_missing"]}</span></td>
        </tr>
        """
    return rows


def citrust_telemetry_control_rows():
    rows = ""
    for item in CITRUST_TELEMETRY_CORRELATION_CONTROLS:
        rows += f"""
        <tr>
            <td><strong>{item["control_id"]}</strong></td>
            <td><span class="badge blue">{item["control"]}</span></td>
            <td>{item["question"]}</td>
            <td>{item["required_evidence"]}</td>
            <td><span class="badge orange">{item["failure_response"]}</span></td>
        </tr>
        """
    return rows


def citrust_runtime_event_rows():
    rows = ""
    for item in CITRUST_RUNTIME_EVENT_TYPES:
        rows += f"""
        <tr>
            <td><strong>{item["event_type"]}</strong></td>
            <td>{item["description"]}</td>
            <td>{item["required_fields"]}</td>
        </tr>
        """
    return rows


def citrust_fusion_rule_rows():
    rows = ""
    for item in CITRUST_EVIDENCE_FUSION_RULES:
        rows += f"""
        <tr>
            <td><strong>{item["fusion_rule"]}</strong></td>
            <td>{item["meaning"]}</td>
            <td>{item["minimum_evidence"]}</td>
        </tr>
        """
    return rows


def citrust_observability_decision(servicenow, azure, runtime, cmdb, cyber, qa, change, human, correlation):
    checks = [servicenow, azure, runtime, cmdb, correlation]
    score = int((sum(1 for item in checks if item == "yes") / len(checks)) * 100)

    if correlation != "yes":
        return score, "Evidence Trail Not Correlated", "red", "No shared correlation ID or unified trace across evidence sources."
    if servicenow != "yes":
        return score, "No ServiceNow Audit Defense", "red", "ServiceNow record or CMDB activity evidence is missing."
    if azure != "yes":
        return score, "Runtime Telemetry Gap", "orange", "Azure Monitor / App Insights runtime trace is missing."
    if runtime != "yes":
        return score, "Tool-Call Evidence Missing", "red", "Agent tool-call or action evidence is missing."
    if cmdb != "yes":
        return score, "CI Evidence Gap", "red", "CMDB evidence ledger or CI passport evidence is missing."
    if cyber == "no":
        return score, "Cyber Evidence Required If Access Impact Exists", "orange", "CyberArk, PSM, access, or privileged evidence is not attached."
    if qa == "no":
        return score, "QA Evidence Required If GxP Impact Exists", "orange", "QA / validation evidence is not attached."
    if change == "no":
        return score, "Change Evidence Required If Material CI Impact Exists", "orange", "Change-control evidence is not attached."
    if human == "no":
        return score, "Human Review Evidence Required", "red", "Reviewer, approver, or owner signoff is missing."
    if score == 100:
        return score, "Evidence Fabric Trusted", "green", "Observability evidence is correlated, runtime-visible, CI-linked, and reviewable."
    return score, "Conditional Evidence Fabric", "yellow", "Evidence trail may support limited reliance with declared gaps and remediation."


try:
    AGENTTRUST_EXPECTED_ROUTES.extend([
        "/citrust/agent-observability-evidence-fabric",
        "/citrust/telemetry-correlation-center",
        "/citrust/servicenow-agent-log-map",
        "/citrust/azure-monitor-appinsights-evidence",
        "/citrust/cyberark-psm-agent-evidence",
        "/citrust/qa-change-evidence-linkage",
        "/citrust/agent-runtime-event-ledger",
        "/citrust/evidence-fusion-rules",
        "/citrust/observability-evidence-simulator",
        "/citrust/agent-observability-json"
    ])
except Exception:
    pass


@app.route("/citrust/agent-observability-evidence-fabric")
@app.route("/citrust/agent-observability-fabric")
@app.route("/citrust/ai-observability-evidence-fabric")
def citrust_agent_observability_evidence_fabric():
    rows = citrust_observability_source_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Evidence Fabric</div><div class="value" style="color:var(--green);">Active</div><div class="note">Agent telemetry and CI evidence unified.</div></div>
        <div class="metric"><div class="label">Sources</div><div class="value" style="color:var(--blue);">8</div><div class="note">ServiceNow, Azure, runtime, CyberArk, CMDB, QA, change, human review.</div></div>
        <div class="metric"><div class="label">Correlation</div><div class="value" style="color:var(--yellow);">Required</div><div class="note">One action must have one evidence trail.</div></div>
        <div class="metric"><div class="label">Cyber Evidence</div><div class="value" style="color:var(--red);">Attached</div><div class="note">Access and privileged context require cyber logs.</div></div>
        <div class="metric"><div class="label">QA Evidence</div><div class="value" style="color:var(--orange);">Attached</div><div class="note">GxP context requires QA / validation evidence.</div></div>
        <div class="metric"><div class="label">Audit Replay</div><div class="value" style="color:var(--purple);">End-to-End</div><div class="note">Trigger to final outcome must be replayable.</div></div>
    </section>

    <section class="section">
        <h2>CITrust™ Agent Observability Evidence Fabric</h2>
        <div class="answer">
            <strong>Purpose:</strong> unify observability evidence for AI-assisted CI actions across ServiceNow,
            Azure Monitor, App Insights, runtime tool calls, CyberArk / PSM, CMDB evidence, QA evidence,
            change records, and human signoff.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Source ID</th>
                    <th>Evidence Source</th>
                    <th>What It Proves</th>
                    <th>Required Link</th>
                    <th>Risk If Missing</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Evidence Fabric Rule</h2>
        <div class="answer">
            CITrust™ does not accept isolated logs as assurance. The evidence must correlate across agent runtime,
            ServiceNow, CMDB, cyber, QA, change, and human decision records.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agent Observability Evidence Fabric",
        "Observability evidence fabric for AI agent actions using ServiceNow, Azure Monitor, App Insights, runtime tool-call logs, CyberArk, CMDB, QA, change, and human review evidence.",
        body
    )


@app.route("/citrust/telemetry-correlation-center")
@app.route("/citrust/agent-telemetry-correlation")
@app.route("/citrust/ai-telemetry-correlation")
def citrust_telemetry_correlation_center():
    rows = citrust_telemetry_control_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Telemetry Correlation Center</h2>
        <p>
            The correlation center determines whether evidence from different systems belongs to the same AI-assisted CI action.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Control ID</th>
                    <th>Correlation Control</th>
                    <th>Question</th>
                    <th>Required Evidence</th>
                    <th>Failure Response</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Correlation Rule</h2>
        <div class="answer">
            If ServiceNow, Azure, CyberArk, CMDB, QA, and change evidence cannot be correlated,
            the AI action is not audit-defensible.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Telemetry Correlation Center",
        "Telemetry correlation center for matching AI agent runtime, ServiceNow, Azure, CyberArk, CMDB, QA, change, and human review evidence.",
        body
    )


@app.route("/citrust/servicenow-agent-log-map")
@app.route("/citrust/servicenow-ai-agent-log-map")
@app.route("/citrust/cmdb-agent-log-map")
def citrust_servicenow_agent_log_map():
    body = """
    <section class="section">
        <h2>CITrust™ ServiceNow Agent Log Map</h2>
        <p>
            This map defines which ServiceNow evidence must be captured for AI-assisted CI actions.
        </p>

        <table>
            <thead>
                <tr>
                    <th>ServiceNow Evidence</th>
                    <th>Proves</th>
                    <th>Required Fields</th>
                    <th>If Missing</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>CI activity log</td><td>Which CI was viewed, summarized, changed, or recommended.</td><td>CI ID, class, field, timestamp.</td><td><span class="badge red">No CI audit trail</span></td></tr>
                <tr><td>Task / ticket record</td><td>What workflow triggered the AI action.</td><td>Task ID, requester, CI, workflow state.</td><td><span class="badge orange">Trigger unclear</span></td></tr>
                <tr><td>Change record</td><td>Whether material CI action was approved and controlled.</td><td>Change ID, approval, implementation, rollback, post-check.</td><td><span class="badge red">Change-control gap</span></td></tr>
                <tr><td>Approval record</td><td>Which human owner accepted or rejected the recommendation.</td><td>Approver, role, decision, timestamp, comments.</td><td><span class="badge red">Hidden approval risk</span></td></tr>
                <tr><td>Relationship history</td><td>Whether AI changed or recommended dependency mapping.</td><td>Source CI, target CI, relationship type, before/after.</td><td><span class="badge orange">Relationship not defensible</span></td></tr>
                <tr><td>Assignment/support history</td><td>Whether AI influenced support group or assignment group.</td><td>Old group, new group, owner decision, change/task link.</td><td><span class="badge red">Support route risk</span></td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ ServiceNow Agent Log Map",
        "ServiceNow log map for AI-assisted CI actions, tickets, changes, approvals, relationships, support groups, and assignment routes.",
        body
    )


@app.route("/citrust/azure-monitor-appinsights-evidence")
@app.route("/citrust/azure-agent-evidence")
@app.route("/citrust/appinsights-agent-evidence")
def citrust_azure_monitor_appinsights_evidence():
    body = """
    <section class="section">
        <h2>CITrust™ Azure Monitor / App Insights Evidence</h2>
        <p>
            Azure telemetry provides runtime evidence for the AI agent execution path.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Azure Evidence</th>
                    <th>Proves</th>
                    <th>Required Link</th>
                    <th>If Missing</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Trace ID</td><td>Runtime execution path.</td><td>Agent session and ServiceNow correlation ID.</td><td><span class="badge orange">Runtime weak</span></td></tr>
                <tr><td>Dependency call</td><td>External system or API touched by agent.</td><td>Tool-call ID and target system.</td><td><span class="badge red">Tool path unclear</span></td></tr>
                <tr><td>Exception / failure event</td><td>Agent failure, timeout, policy block, or runtime error.</td><td>Error ID, timestamp, affected CI/action.</td><td><span class="badge orange">Incident may be missed</span></td></tr>
                <tr><td>Performance metric</td><td>Latency, retry, repeated call, or degraded behavior.</td><td>Session ID and operation name.</td><td><span class="badge yellow">Monitoring gap</span></td></tr>
                <tr><td>Custom event</td><td>Governance events like preflight, block, approval, rollback, closure.</td><td>Event name, rule ID, CI ID, outcome.</td><td><span class="badge red">Governance event not visible</span></td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Azure Monitor App Insights Evidence",
        "Azure Monitor and App Insights evidence for AI agent runtime trace, dependency calls, exceptions, performance, custom governance events, and ServiceNow correlation.",
        body
    )


@app.route("/citrust/cyberark-psm-agent-evidence")
@app.route("/citrust/cyberark-agent-evidence")
@app.route("/citrust/psm-agent-evidence")
def citrust_cyberark_psm_agent_evidence():
    body = """
    <section class="section">
        <h2>CITrust™ CyberArk / PSM Agent Evidence</h2>
        <p>
            CyberArk and PSM evidence is required when AI workflows touch access, privileged routes, admin context, or CyberArk-governed systems.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Cyber Evidence</th>
                    <th>Proves</th>
                    <th>Required Link</th>
                    <th>Default Guardrail</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Access request</td><td>Who requested access and why.</td><td>Request ID, user, CI/system, approver.</td><td><span class="badge red">No AI approval</span></td></tr>
                <tr><td>CyberArk route</td><td>Whether privileged route is required.</td><td>Safe, account, policy, PSM route.</td><td><span class="badge red">Cyber-gated</span></td></tr>
                <tr><td>PSM session</td><td>Privileged session evidence.</td><td>Session ID, user, target system, timestamp.</td><td><span class="badge red">Privileged audit required</span></td></tr>
                <tr><td>Entitlement decision</td><td>Approved or rejected access scope.</td><td>Approver, entitlement, role, decision.</td><td><span class="badge red">Human approval only</span></td></tr>
                <tr><td>Admin activity</td><td>Any admin action taken after AI recommendation.</td><td>Admin log, change record, runtime evidence.</td><td><span class="badge red">Evidence required</span></td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ CyberArk PSM Agent Evidence",
        "CyberArk and PSM evidence for AI-assisted access, privileged route, admin context, entitlement decisions, and privileged session auditability.",
        body
    )


@app.route("/citrust/qa-change-evidence-linkage")
@app.route("/citrust/gxp-change-evidence-linkage")
@app.route("/citrust/qa-agent-evidence-linkage")
def citrust_qa_change_evidence_linkage():
    body = """
    <section class="section">
        <h2>CITrust™ QA / Change Evidence Linkage</h2>
        <p>
            This linkage ensures AI-assisted CI actions that affect regulated or operational state are tied to QA and change-control evidence.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Evidence Linkage</th>
                    <th>Required When</th>
                    <th>Required Evidence</th>
                    <th>If Missing</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>QA review</td><td>CI is GMP, validated, QA-relevant, or inspection-sensitive.</td><td>QA owner decision, GxP screen, validation evidence.</td><td><span class="badge red">No regulated reliance</span></td></tr>
                <tr><td>Validation evidence</td><td>AI action touches validation status or evidence interpretation.</td><td>Validation owner review and source evidence.</td><td><span class="badge red">Validation gap</span></td></tr>
                <tr><td>Change record</td><td>AI action affects CI state, owner, support group, relationship, lifecycle, or access route.</td><td>Change ID, approval, implementation, rollback, post-check.</td><td><span class="badge red">No update</span></td></tr>
                <tr><td>Deviation / CAPA route</td><td>AI incident or wrong output impacts regulated process.</td><td>Incident, deviation/CAPA assessment, root cause, closure evidence.</td><td><span class="badge red">Do not close</span></td></tr>
                <tr><td>Post-action verification</td><td>Any AI-influenced action is completed.</td><td>Verified state, owner signoff, evidence package.</td><td><span class="badge orange">Closure incomplete</span></td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ QA Change Evidence Linkage",
        "QA and change evidence linkage for AI-assisted CI actions affecting GMP status, validation evidence, change records, deviation/CAPA, and post-action verification.",
        body
    )


@app.route("/citrust/agent-runtime-event-ledger")
@app.route("/citrust/runtime-event-ledger")
@app.route("/citrust/ai-agent-event-ledger")
def citrust_agent_runtime_event_ledger():
    rows = citrust_runtime_event_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agent Runtime Event Ledger</h2>
        <p>
            The runtime event ledger defines the minimum event types required to replay an AI-assisted CI workflow.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Runtime Event</th>
                    <th>Description</th>
                    <th>Required Fields</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Runtime Ledger Rule</h2>
        <div class="answer">
            Every AI-assisted CI workflow should leave a ledger from trigger, context, risk, tool call, review,
            block or execution, rollback, and closure.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agent Runtime Event Ledger",
        "Runtime event ledger for AI-assisted CI workflows from trigger through context retrieval, risk classification, tool call, human review, block, execution, rollback, and closure.",
        body
    )


@app.route("/citrust/evidence-fusion-rules")
@app.route("/citrust/observability-fusion-rules")
@app.route("/citrust/agent-evidence-fusion")
def citrust_evidence_fusion_rules():
    rows = citrust_fusion_rule_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Evidence Fusion Rules</h2>
        <p>
            Evidence fusion rules define how isolated logs become one defensible audit trail.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Fusion Rule</th>
                    <th>Meaning</th>
                    <th>Minimum Evidence</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Evidence Fusion Rules",
        "Evidence fusion rules for correlating AI agent runtime, ServiceNow, CMDB, CyberArk, QA, change, and human review evidence.",
        body
    )


@app.route("/citrust/observability-evidence-simulator", methods=["GET", "POST"])
@app.route("/citrust/agent-observability-simulator", methods=["GET", "POST"])
@app.route("/citrust/telemetry-evidence-simulator", methods=["GET", "POST"])
def citrust_observability_evidence_simulator():
    from flask import request

    servicenow = request.form.get("servicenow", "yes")
    azure = request.form.get("azure", "yes")
    runtime = request.form.get("runtime", "yes")
    cmdb = request.form.get("cmdb", "yes")
    cyber = request.form.get("cyber", "yes")
    qa = request.form.get("qa", "yes")
    change = request.form.get("change", "yes")
    human = request.form.get("human", "yes")
    correlation = request.form.get("correlation", "yes")

    score, decision, badge, reason = citrust_observability_decision(
        servicenow, azure, runtime, cmdb, cyber, qa, change, human, correlation
    )

    def selected(value, expected):
        return "selected" if value == expected else ""

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Evidence Fabric Score</div><div class="value" style="color:var(--green);">{score}%</div><div class="note">Calculated from correlated observability evidence.</div></div>
        <div class="metric"><div class="label">Evidence Decision</div><div class="value" style="color:var(--yellow);">{decision}</div><div class="note">{reason}</div></div>
    </section>

    <section class="section">
        <h2>CITrust™ Observability Evidence Simulator</h2>
        <p>
            Simulate whether an AI-assisted CI action has enough correlated telemetry and evidence to be audit-defensible.
        </p>

        <form method="POST" action="/citrust/observability-evidence-simulator">
            <table>
                <tbody>
                    <tr><td><strong>ServiceNow / CMDB Activity Evidence Ready?</strong></td><td><select name="servicenow" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(servicenow, "yes")}>Yes</option><option value="no" {selected(servicenow, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Azure Monitor / App Insights Runtime Evidence Ready?</strong></td><td><select name="azure" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(azure, "yes")}>Yes</option><option value="no" {selected(azure, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Agent Tool-Call Evidence Ready?</strong></td><td><select name="runtime" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(runtime, "yes")}>Yes</option><option value="no" {selected(runtime, "no")}>No</option></select></td></tr>
                    <tr><td><strong>CMDB Evidence Ledger / CI Passport Ready?</strong></td><td><select name="cmdb" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(cmdb, "yes")}>Yes</option><option value="no" {selected(cmdb, "no")}>No</option></select></td></tr>
                    <tr><td><strong>CyberArk / PSM / Access Evidence Attached?</strong></td><td><select name="cyber" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(cyber, "yes")}>Yes</option><option value="no" {selected(cyber, "no")}>No</option></select></td></tr>
                    <tr><td><strong>QA / Validation Evidence Attached?</strong></td><td><select name="qa" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(qa, "yes")}>Yes</option><option value="no" {selected(qa, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Change-Control Evidence Attached?</strong></td><td><select name="change" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(change, "yes")}>Yes</option><option value="no" {selected(change, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Human Review / Signoff Evidence Ready?</strong></td><td><select name="human" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(human, "yes")}>Yes</option><option value="no" {selected(human, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Correlation ID / Unified Trace Ready?</strong></td><td><select name="correlation" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(correlation, "yes")}>Yes</option><option value="no" {selected(correlation, "no")}>No</option></select></td></tr>
                </tbody>
            </table>

            <button type="submit" style="margin-top:16px;padding:12px 18px;border-radius:12px;border:0;background:#2563eb;color:white;font-weight:800;">Run Observability Evidence Check</button>
        </form>
    </section>

    <section class="section">
        <h2>Observability Evidence Decision</h2>
        <div class="answer">
            <strong>Score:</strong> {score}%<br>
            <strong>Decision:</strong> <span class="badge {badge}">{decision}</span><br>
            <strong>Reason:</strong> {reason}
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Observability Evidence Simulator",
        "Simulator for correlated AI observability evidence across ServiceNow, Azure Monitor, App Insights, runtime tool calls, CMDB, CyberArk, QA, change, human review, and correlation IDs.",
        body
    )


@app.route("/citrust/agent-observability-json")
@app.route("/citrust/observability-evidence-json")
@app.route("/citrust/telemetry-correlation-json")
def citrust_agent_observability_json():
    from flask import jsonify

    return jsonify({
        "module": "CITrust™",
        "capability": "Agent Observability Evidence Fabric + Telemetry Correlation Center",
        "primary_question": "Can we prove what this AI agent did across ServiceNow, CMDB, Azure, CyberArk, QA, change control, and human review evidence?",
        "observability_evidence_sources": CITRUST_OBSERVABILITY_EVIDENCE_SOURCES,
        "telemetry_correlation_controls": CITRUST_TELEMETRY_CORRELATION_CONTROLS,
        "runtime_event_types": CITRUST_RUNTIME_EVENT_TYPES,
        "evidence_fusion_rules": CITRUST_EVIDENCE_FUSION_RULES,
        "minimum_conditions": [
            "ServiceNow / CMDB activity evidence is available",
            "Azure Monitor / App Insights runtime evidence is available",
            "Agent tool-call evidence is available",
            "CMDB evidence ledger or CI passport is linked",
            "CyberArk / PSM / access evidence is attached where access or privileged impact exists",
            "QA / validation evidence is attached where GxP impact exists",
            "Change-control evidence is attached where material CI impact exists",
            "Human reviewer or owner signoff is captured",
            "Correlation ID or unified trace ties all evidence together",
            "Outcome evidence shows executed, blocked, rejected, escalated, rolled back, or closed"
        ],
        "default_decision": "Do not treat AI-assisted CI action as audit-defensible unless observability evidence is correlated across runtime, ServiceNow, CMDB, cyber, QA, change, and human review sources"
    })

# ============================================================
# END CITRUST_AGENT_OBSERVABILITY_EVIDENCE_FABRIC_V1_ACTIVE
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

print("CITrust Agent Observability Evidence Fabric installed.")
print(f"Inserted before: {target_found}")
