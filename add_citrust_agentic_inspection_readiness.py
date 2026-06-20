from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_AGENTIC_INSPECTION_READINESS_CENTER_V1_ACTIVE"

if MARKER in text:
    print("CITrust Agentic Inspection Readiness Center already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base shell not found. Install AgentTrust base module first.")

nav_old = '<a href="/citrust/agentic-regulatory-traceability-crosswalk" class="secondary">Reg Crosswalk</a>'
nav_new = '''<a href="/citrust/agentic-regulatory-traceability-crosswalk" class="secondary">Reg Crosswalk</a>
                    <a href="/citrust/agentic-inspection-readiness-center" class="secondary">Inspection Ready</a>
                    <a href="/citrust/agentic-auditor-evidence-router" class="dark">Evidence Router</a>
                    <a href="/citrust/agentic-inspection-question-bank" class="dark">Question Bank</a>
                    <a href="/citrust/agentic-inspection-simulator" class="dark">Inspection Sim</a>'''

if nav_old in text and "/citrust/agentic-inspection-readiness-center" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# CITRUST_AGENTIC_INSPECTION_READINESS_CENTER_V1_ACTIVE
# CITrust™ Agentic Inspection Readiness Center
# Auditor Evidence Request Router, Inspection Question Bank,
# Evidence Response Pack, Gap Triage Board,
# Inspection Response Approval Gate, Mock Inspection Simulator,
# and JSON Export
# ============================================================

CITRUST_AGENTIC_INSPECTION_DOMAINS = [
    {
        "domain": "AI Agent Identity",
        "inspection_question": "Which AI agents are in scope, who owns them, what are they allowed to do, and how are they controlled?",
        "evidence_required": "Agent registry, owner, operating license, approved use case, identity map, entitlement scope.",
        "owner": "AI Agent Owner / Governance Owner",
        "inspection_risk": "Unknown or uncontrolled AI actor."
    },
    {
        "domain": "CI Impact Traceability",
        "inspection_question": "Which CIs, CI fields, relationships, support groups, workflows, or change records were affected by AI?",
        "evidence_required": "Agent-to-CI impact map, CI passport, field risk matrix, before/after state, relationship confidence.",
        "owner": "CMDB / CI Owner",
        "inspection_risk": "Cannot prove what AI affected."
    },
    {
        "domain": "GxP / Validation Boundary",
        "inspection_question": "Did AI influence GMP, validation, QA, release, deviation, CAPA, or inspection-sensitive context?",
        "evidence_required": "GxP screen, validation evidence, QA review, regulated reliance decision.",
        "owner": "QA / Validation Owner",
        "inspection_risk": "Regulated reliance without QA evidence."
    },
    {
        "domain": "Cyber / Access Boundary",
        "inspection_question": "Did AI influence MyAccess, CyberArk, PSM, privileged access, admin route, or entitlement decisions?",
        "evidence_required": "MyAccess route, approver group, CyberArk evidence, PSM session evidence, cyber decision.",
        "owner": "Cybersecurity / Access Owner",
        "inspection_risk": "Access or privileged workflow bypass."
    },
    {
        "domain": "Prompt Chain and Context",
        "inspection_question": "Can the AI recommendation be replayed from trigger through prompt chain, retrieved context, memory, and reviewer decision?",
        "evidence_required": "Prompt chain, context provenance, RAG evidence, memory freshness, reviewer decision.",
        "owner": "AI Agent Owner / Data Owner",
        "inspection_risk": "AI reasoning cannot be reconstructed."
    },
    {
        "domain": "Runtime Observability",
        "inspection_question": "Can runtime logs prove what happened across ServiceNow, Azure, tools, CyberArk, QA, change, and human review?",
        "evidence_required": "Correlation ID, ServiceNow log, Azure Monitor / App Insights trace, tool-call log, CyberArk log.",
        "owner": "Observability / Governance Owner",
        "inspection_risk": "No audit replay."
    },
    {
        "domain": "Change Control",
        "inspection_question": "Did material AI-assisted actions route through task, change, rollback, post-check, and closure evidence?",
        "evidence_required": "Action classifier, task/change record, approval, rollback, post-check, closure dossier.",
        "owner": "Change Owner / System Owner",
        "inspection_risk": "Operational change without controlled evidence."
    },
    {
        "domain": "Monitoring and Drift",
        "inspection_question": "How do you know the AI workflow remained controlled after release?",
        "evidence_required": "Runtime KPIs, drift signals, threshold alerts, exception aging, monitoring escalation records.",
        "owner": "Monitoring / Governance Owner",
        "inspection_risk": "One-time release control with no ongoing assurance."
    },
    {
        "domain": "Control Testing and Findings",
        "inspection_question": "Were controls tested, were findings tracked, were remediations retested, and were gaps closed?",
        "evidence_required": "Control test plan, evidence samples, findings register, remediation tracker, retest evidence.",
        "owner": "Governance / Assurance Owner",
        "inspection_risk": "Control exists but effectiveness is unproven."
    },
    {
        "domain": "Attestation and Residual Risk",
        "inspection_question": "Who signed off, what residual risk remains, and what reliance boundary was accepted?",
        "evidence_required": "Control owner certification, QA/cyber/change attestation, residual risk register, executive signoff.",
        "owner": "Executive / Governance Owner",
        "inspection_risk": "Leadership cannot defend final trust decision."
    }
]


CITRUST_AUDITOR_EVIDENCE_REQUEST_ROUTER = [
    {
        "request_type": "Show me the AI agent inventory.",
        "route_to": "AI Agent Owner / Governance Owner",
        "evidence_pack": "Agent registry, operating license, use case, owner, identity, entitlement scope.",
        "response_rule": "Do not answer with only a list; include owner and approved boundary."
    },
    {
        "request_type": "Show me what CI this AI action affected.",
        "route_to": "CMDB / CI Owner",
        "evidence_pack": "CI passport, agent-to-CI map, field touched, before/after value, relationship map.",
        "response_rule": "Tie every answer to CI ID and evidence source."
    },
    {
        "request_type": "Show me how GxP impact was assessed.",
        "route_to": "QA / Validation Owner",
        "evidence_pack": "GxP screen, validation status, QA decision, regulated reliance decision.",
        "response_rule": "No regulated conclusion without QA evidence."
    },
    {
        "request_type": "Show me how access and privileged risk were controlled.",
        "route_to": "Cybersecurity / Access Owner",
        "evidence_pack": "MyAccess route, approver group, CyberArk evidence, PSM evidence, entitlement review.",
        "response_rule": "No AI access approval claim unless cyber evidence exists."
    },
    {
        "request_type": "Show me the prompt chain and context used.",
        "route_to": "AI Agent Owner / Data Owner",
        "evidence_pack": "Prompt chain, context provenance, memory freshness, source authority, reviewer decision.",
        "response_rule": "If prompt chain is missing, classify as replay gap."
    },
    {
        "request_type": "Show me runtime logs proving what happened.",
        "route_to": "Observability Owner",
        "evidence_pack": "Correlation ID, ServiceNow log, Azure trace, tool-call log, runtime event ledger.",
        "response_rule": "Evidence must connect trigger to outcome."
    },
    {
        "request_type": "Show me change-control evidence.",
        "route_to": "Change Owner / System Owner",
        "evidence_pack": "Task/change record, approval, rollback, post-check, closure dossier.",
        "response_rule": "No material action closure without rollback and post-check."
    },
    {
        "request_type": "Show me monitoring after go-live.",
        "route_to": "Monitoring / Governance Owner",
        "evidence_pack": "Runtime KPIs, drift signal register, threshold alerts, exception aging monitor.",
        "response_rule": "Show continuous monitoring, not only go-live readiness."
    },
    {
        "request_type": "Show me open findings and remediation.",
        "route_to": "Governance / Assurance Owner",
        "evidence_pack": "Findings register, remediation tracker, retest gate, closure signoff.",
        "response_rule": "Separate open, overdue, remediated, and retested findings."
    },
    {
        "request_type": "Show me final leadership signoff.",
        "route_to": "Executive / Governance Owner",
        "evidence_pack": "Attestation package, residual risk register, executive risk brief, signoff ledger.",
        "response_rule": "Show reliance boundary and residual risk."
    }
]


CITRUST_INSPECTION_QUESTION_BANK = [
    {
        "question": "How do you know this AI agent was allowed to interact with ServiceNow CMDB?",
        "best_answer_component": "Agent registry, approved use case, owner, operating license, identity and entitlement map.",
        "weak_answer": "The tool is approved or the platform is trusted.",
        "risk": "Platform approval does not prove workflow governance."
    },
    {
        "question": "How do you know the CMDB data used by the AI was reliable?",
        "best_answer_component": "CMDB graph trust score, CI passport, owner/support/LCM completeness, relationship confidence.",
        "weak_answer": "The data came from ServiceNow.",
        "risk": "Source system alone does not prove data quality."
    },
    {
        "question": "How do you know AI did not make a regulated QA decision?",
        "best_answer_component": "GxP guardrail, QA route, human QA decision, no autonomous GxP conclusion policy.",
        "weak_answer": "The AI only helped.",
        "risk": "Assistance still needs boundary evidence."
    },
    {
        "question": "How do you know AI did not approve access or privileged activity?",
        "best_answer_component": "Cyber guardrail, MyAccess route, CyberArk / PSM evidence, human cyber decision.",
        "weak_answer": "The AI does not have access.",
        "risk": "Access influence must also be controlled."
    },
    {
        "question": "Can you replay how the AI reached its recommendation?",
        "best_answer_component": "Trigger, prompt chain, context, memory provenance, evaluator result, reviewer decision.",
        "weak_answer": "The final output was saved.",
        "risk": "Final output is not enough for replay."
    },
    {
        "question": "How do you know the AI action was not an uncontrolled change?",
        "best_answer_component": "Action classifier, change router, task/change record, rollback, post-check, closure dossier.",
        "weak_answer": "The change was small.",
        "risk": "Materiality must be assessed and evidenced."
    },
    {
        "question": "How do you know AI governance remained effective after launch?",
        "best_answer_component": "Continuous monitoring, runtime KPIs, drift alerts, exception aging, control testing.",
        "weak_answer": "It passed go-live review.",
        "risk": "Controls can drift after release."
    },
    {
        "question": "Who accepted the residual risk?",
        "best_answer_component": "Residual risk register, risk owner, restriction, expiry, executive visibility, signoff.",
        "weak_answer": "The team was aware.",
        "risk": "Awareness is not formal risk acceptance."
    }
]


CITRUST_INSPECTION_RESPONSE_PACK = [
    {
        "pack_section": "Scope Statement",
        "contents": "AI agents, affected ServiceNow workflows, affected CIs, regulated/cyber/change boundaries, date range."
    },
    {
        "pack_section": "Agent Governance Evidence",
        "contents": "Agent registry, owner, operating license, identity, entitlement, approved use case."
    },
    {
        "pack_section": "CI Trust Evidence",
        "contents": "CI passport, graph trust score, owner/support/LCM fields, relationship confidence, orphan status."
    },
    {
        "pack_section": "GxP / QA Evidence",
        "contents": "GxP screen, validation evidence, QA review, regulated reliance decision."
    },
    {
        "pack_section": "Cyber / Access Evidence",
        "contents": "MyAccess route, approver group, CyberArk/PSM evidence, entitlement review, cyber decision."
    },
    {
        "pack_section": "AI Replay Evidence",
        "contents": "Trigger, prompt chain, context provenance, memory freshness, tool-call log, runtime ledger."
    },
    {
        "pack_section": "Change-Control Evidence",
        "contents": "Action classification, task/change route, approval, rollback, post-check, closure dossier."
    },
    {
        "pack_section": "Monitoring and Testing Evidence",
        "contents": "Control test results, findings, remediation, retest, runtime KPIs, drift signals, threshold alerts."
    },
    {
        "pack_section": "Attestation and Residual Risk",
        "contents": "Control owner certifications, residual risk register, executive risk brief, final signoff."
    }
]


CITRUST_INSPECTION_GAP_TRIAGE = [
    {
        "gap_type": "Missing agent registry",
        "severity": "Critical",
        "triage_decision": "Block reliance and register agent.",
        "owner": "AI Agent Owner / Governance Owner",
        "closure_evidence": "Agent registry and operating license."
    },
    {
        "gap_type": "Missing CI owner or support group",
        "severity": "Critical",
        "triage_decision": "Restrict AI reliance and open CI remediation.",
        "owner": "CMDB / LCM Owner",
        "closure_evidence": "CI passport complete."
    },
    {
        "gap_type": "Missing QA evidence for GxP context",
        "severity": "Critical",
        "triage_decision": "No regulated reliance.",
        "owner": "QA / Validation Owner",
        "closure_evidence": "QA decision and validation evidence."
    },
    {
        "gap_type": "Missing cyber evidence for access context",
        "severity": "Critical",
        "triage_decision": "No access or privileged reliance.",
        "owner": "Cybersecurity / Access Owner",
        "closure_evidence": "Cyber / MyAccess / CyberArk / PSM decision."
    },
    {
        "gap_type": "Missing prompt chain",
        "severity": "High",
        "triage_decision": "Classify as replay gap and restrict assurance claim.",
        "owner": "AI Agent Owner",
        "closure_evidence": "Prompt chain restored or limitation declared."
    },
    {
        "gap_type": "Missing telemetry correlation",
        "severity": "High",
        "triage_decision": "Do not call action audit-replayable.",
        "owner": "Observability Owner",
        "closure_evidence": "Correlation ID and runtime evidence."
    },
    {
        "gap_type": "Missing change rollback/post-check",
        "severity": "Critical",
        "triage_decision": "No closure until change evidence complete.",
        "owner": "Change Owner",
        "closure_evidence": "Rollback, post-check, closure signoff."
    },
    {
        "gap_type": "Residual risk not accepted",
        "severity": "High",
        "triage_decision": "Escalate to risk owner and executive owner where material.",
        "owner": "Risk / Governance Owner",
        "closure_evidence": "Residual risk accepted, restricted, expired, or closed."
    }
]


CITRUST_INSPECTION_RESPONSE_APPROVALS = [
    {
        "response_area": "AI Agent Scope",
        "approver": "AI Agent Owner / Governance Owner",
        "approval_basis": "Agent registry, operating license, approved use case, entitlement scope."
    },
    {
        "response_area": "CI / CMDB Evidence",
        "approver": "CMDB / LCM Owner",
        "approval_basis": "CI passport, graph trust score, owner/support/LCM, relationship confidence."
    },
    {
        "response_area": "GxP / QA Response",
        "approver": "QA / Validation Owner",
        "approval_basis": "GxP screen, QA decision, validation evidence."
    },
    {
        "response_area": "Cyber / Access Response",
        "approver": "Cybersecurity / Access Owner",
        "approval_basis": "MyAccess, CyberArk, PSM, entitlement, cyber review."
    },
    {
        "response_area": "Change-Control Response",
        "approver": "Change Owner / System Owner",
        "approval_basis": "Change/task, approval, rollback, post-check, closure."
    },
    {
        "response_area": "Final Inspection Package",
        "approver": "Governance / Executive Owner",
        "approval_basis": "Evidence package, gap triage, residual risk, attestation, response boundary."
    }
]


def citrust_inspection_domain_rows():
    rows = ""
    for item in CITRUST_AGENTIC_INSPECTION_DOMAINS:
        rows += f"""
        <tr>
            <td><strong>{item["domain"]}</strong></td>
            <td>{item["inspection_question"]}</td>
            <td>{item["evidence_required"]}</td>
            <td>{item["owner"]}</td>
            <td><span class="badge red">{item["inspection_risk"]}</span></td>
        </tr>
        """
    return rows


def citrust_evidence_router_rows():
    rows = ""
    for item in CITRUST_AUDITOR_EVIDENCE_REQUEST_ROUTER:
        rows += f"""
        <tr>
            <td><strong>{item["request_type"]}</strong></td>
            <td><span class="badge blue">{item["route_to"]}</span></td>
            <td>{item["evidence_pack"]}</td>
            <td>{item["response_rule"]}</td>
        </tr>
        """
    return rows


def citrust_question_bank_rows():
    rows = ""
    for item in CITRUST_INSPECTION_QUESTION_BANK:
        rows += f"""
        <tr>
            <td><strong>{item["question"]}</strong></td>
            <td>{item["best_answer_component"]}</td>
            <td><span class="badge orange">{item["weak_answer"]}</span></td>
            <td><span class="badge red">{item["risk"]}</span></td>
        </tr>
        """
    return rows


def citrust_response_pack_rows():
    rows = ""
    for item in CITRUST_INSPECTION_RESPONSE_PACK:
        rows += f"""
        <tr>
            <td><strong>{item["pack_section"]}</strong></td>
            <td>{item["contents"]}</td>
        </tr>
        """
    return rows


def citrust_gap_triage_rows():
    rows = ""
    for item in CITRUST_INSPECTION_GAP_TRIAGE:
        badge = "red" if item["severity"] == "Critical" else "orange"
        rows += f"""
        <tr>
            <td><strong>{item["gap_type"]}</strong></td>
            <td><span class="badge {badge}">{item["severity"]}</span></td>
            <td>{item["triage_decision"]}</td>
            <td>{item["owner"]}</td>
            <td>{item["closure_evidence"]}</td>
        </tr>
        """
    return rows


def citrust_response_approval_rows():
    rows = ""
    for item in CITRUST_INSPECTION_RESPONSE_APPROVALS:
        rows += f"""
        <tr>
            <td><strong>{item["response_area"]}</strong></td>
            <td><span class="badge blue">{item["approver"]}</span></td>
            <td>{item["approval_basis"]}</td>
        </tr>
        """
    return rows


def citrust_inspection_readiness_decision(scope, agent, ci, gxp, cyber, replay, change, monitoring, attestation):
    checks = [scope, agent, ci, gxp, cyber, replay, change, monitoring, attestation]
    score = int((sum(1 for item in checks if item == "yes") / len(checks)) * 100)

    if scope != "yes":
        return score, "Inspection Scope Missing", "red", "Scope, date range, agents, workflows, or CIs are not defined."
    if agent != "yes":
        return score, "Agent Evidence Missing", "red", "Agent identity, owner, operating license, or entitlement evidence is incomplete."
    if ci != "yes":
        return score, "CI Evidence Missing", "red", "CI passport, owner, support, LCM, or graph trust evidence is incomplete."
    if gxp != "yes":
        return score, "QA Evidence Missing", "red", "GxP, validation, or QA evidence is incomplete."
    if cyber != "yes":
        return score, "Cyber Evidence Missing", "red", "Access, CyberArk, PSM, or entitlement evidence is incomplete."
    if replay != "yes":
        return score, "Replay Evidence Missing", "red", "Prompt chain, context, telemetry, or runtime replay evidence is incomplete."
    if change != "yes":
        return score, "Change Evidence Missing", "orange", "Task/change, rollback, post-check, or closure evidence is incomplete."
    if monitoring != "yes":
        return score, "Monitoring Evidence Missing", "orange", "Runtime KPIs, drift, threshold, or exception aging evidence is incomplete."
    if attestation != "yes":
        return score, "Attestation Missing", "red", "Control owner, residual risk, or executive signoff evidence is incomplete."
    if score == 100:
        return score, "Inspection Ready", "green", "Evidence package is scoped, routed, approved, replayable, and signoff-ready."
    return score, "Conditional Inspection Readiness", "yellow", "Inspection response may proceed only with declared limitations and remediation tracking."


try:
    AGENTTRUST_EXPECTED_ROUTES.extend([
        "/citrust/agentic-inspection-readiness-center",
        "/citrust/agentic-auditor-evidence-router",
        "/citrust/agentic-inspection-question-bank",
        "/citrust/agentic-inspection-response-pack",
        "/citrust/agentic-inspection-gap-triage",
        "/citrust/agentic-inspection-response-approval",
        "/citrust/agentic-inspection-simulator",
        "/citrust/agentic-inspection-json"
    ])
except Exception:
    pass


@app.route("/citrust/agentic-inspection-readiness-center")
@app.route("/citrust/agentic-inspection-center")
@app.route("/citrust/ci-agentic-inspection-readiness")
def citrust_agentic_inspection_readiness_center():
    rows = citrust_inspection_domain_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Inspection Center</div><div class="value" style="color:var(--green);">Active</div><div class="note">Audit and inspection response layer installed.</div></div>
        <div class="metric"><div class="label">Inspection Domains</div><div class="value" style="color:var(--blue);">10</div><div class="note">Agent, CI, GxP, cyber, prompt, telemetry, change, monitoring, testing, attestation.</div></div>
        <div class="metric"><div class="label">Evidence Router</div><div class="value" style="color:var(--yellow);">Ready</div><div class="note">Auditor requests route to accountable owners.</div></div>
        <div class="metric"><div class="label">Gap Triage</div><div class="value" style="color:var(--red);">Controlled</div><div class="note">Missing evidence is classified and escalated.</div></div>
        <div class="metric"><div class="label">Response Approval</div><div class="value" style="color:var(--orange);">Owner-Based</div><div class="note">QA, cyber, change, CMDB, governance approvals separated.</div></div>
        <div class="metric"><div class="label">Inspection Answer</div><div class="value" style="color:var(--purple);">Defensible</div><div class="note">Answers are evidence-backed, not opinion-based.</div></div>
    </section>

    <section class="section">
        <h2>CITrust™ Agentic Inspection Readiness Center</h2>
        <div class="answer">
            <strong>Purpose:</strong> prepare CITrust™ to answer auditor, inspector, QA, cyber, change, and executive
            questions about AI-assisted ServiceNow / CMDB workflows using evidence, owner routing, gap triage,
            response approval, and inspection-ready packages.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Inspection Domain</th>
                    <th>Inspection Question</th>
                    <th>Evidence Required</th>
                    <th>Owner</th>
                    <th>Inspection Risk</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Inspection Rule</h2>
        <div class="answer">
            An inspection response should not depend on memory, opinion, or platform reputation. CITrust™ routes
            each question to the accountable owner and requires evidence that can be replayed, approved, and signed off.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Inspection Readiness Center",
        "Inspection readiness center for AI-assisted ServiceNow CMDB workflows covering agent identity, CI impact, GxP, cyber, prompt chain, runtime observability, change control, monitoring, control testing, attestation, and residual risk.",
        body
    )


@app.route("/citrust/agentic-auditor-evidence-router")
@app.route("/citrust/agentic-evidence-request-router")
@app.route("/citrust/ci-agentic-auditor-evidence-router")
def citrust_agentic_auditor_evidence_router():
    rows = citrust_evidence_router_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Auditor Evidence Request Router</h2>
        <p>
            This router converts inspection or audit questions into evidence packs and accountable owner routes.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Auditor Request</th>
                    <th>Route To</th>
                    <th>Evidence Pack</th>
                    <th>Response Rule</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Auditor Evidence Request Router",
        "Auditor evidence request router for AI agent inventory, CI impact, GxP assessment, cyber/access controls, prompt chain, runtime logs, change control, monitoring, findings, and executive signoff.",
        body
    )


@app.route("/citrust/agentic-inspection-question-bank")
@app.route("/citrust/agentic-audit-question-bank")
@app.route("/citrust/ci-agentic-inspection-questions")
def citrust_agentic_inspection_question_bank():
    rows = citrust_question_bank_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agentic Inspection Question Bank</h2>
        <p>
            This question bank prepares the team to answer likely inspection questions with evidence-backed responses.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Inspection Question</th>
                    <th>Best Answer Component</th>
                    <th>Weak Answer</th>
                    <th>Risk</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Inspection Question Bank",
        "Inspection question bank for AI agent identity, CMDB data quality, GxP boundaries, access control, prompt chain replay, change control, monitoring, and residual risk.",
        body
    )


@app.route("/citrust/agentic-inspection-response-pack")
@app.route("/citrust/agentic-audit-response-pack")
@app.route("/citrust/ci-agentic-inspection-response-pack")
def citrust_agentic_inspection_response_pack():
    rows = citrust_response_pack_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agentic Inspection Response Pack</h2>
        <p>
            This response pack defines the evidence bundle needed to answer auditor or inspection requests.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Pack Section</th>
                    <th>Contents</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Inspection Response Pack",
        "Inspection response pack for scope, agent governance, CI trust, GxP, cyber, AI replay, change control, monitoring, testing, attestation, and residual risk evidence.",
        body
    )


@app.route("/citrust/agentic-inspection-gap-triage")
@app.route("/citrust/agentic-audit-gap-triage")
@app.route("/citrust/ci-agentic-inspection-gap-triage")
def citrust_agentic_inspection_gap_triage():
    rows = citrust_gap_triage_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agentic Inspection Gap Triage</h2>
        <p>
            This board classifies missing evidence and defines the immediate inspection response.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Gap Type</th>
                    <th>Severity</th>
                    <th>Triage Decision</th>
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
        "CITrust™ Agentic Inspection Gap Triage",
        "Inspection gap triage board for missing agent registry, CI ownership, QA evidence, cyber evidence, prompt chain, telemetry, change rollback/post-check, and residual risk acceptance.",
        body
    )


@app.route("/citrust/agentic-inspection-response-approval")
@app.route("/citrust/agentic-audit-response-approval")
@app.route("/citrust/ci-agentic-response-approval")
def citrust_agentic_inspection_response_approval():
    rows = citrust_response_approval_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agentic Inspection Response Approval Gate</h2>
        <p>
            Inspection answers should be approved by the accountable domain owner before they are represented as official evidence.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Response Area</th>
                    <th>Approver</th>
                    <th>Approval Basis</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Approval Rule</h2>
        <div class="answer">
            QA approves QA responses. Cyber approves access responses. Change approves change responses.
            CMDB / LCM approves CI evidence. Governance approves final package completeness.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Inspection Response Approval",
        "Inspection response approval gate for agent scope, CI evidence, QA/GxP response, cyber/access response, change-control response, and final inspection package.",
        body
    )


@app.route("/citrust/agentic-inspection-simulator", methods=["GET", "POST"])
@app.route("/citrust/agentic-audit-simulator", methods=["GET", "POST"])
@app.route("/citrust/ci-agentic-inspection-simulator", methods=["GET", "POST"])
def citrust_agentic_inspection_simulator():
    from flask import request

    scope = request.form.get("scope", "yes")
    agent = request.form.get("agent", "yes")
    ci = request.form.get("ci", "yes")
    gxp = request.form.get("gxp", "yes")
    cyber = request.form.get("cyber", "yes")
    replay = request.form.get("replay", "yes")
    change = request.form.get("change", "yes")
    monitoring = request.form.get("monitoring", "yes")
    attestation = request.form.get("attestation", "yes")

    score, decision, badge, reason = citrust_inspection_readiness_decision(
        scope, agent, ci, gxp, cyber, replay, change, monitoring, attestation
    )

    def selected(value, expected):
        return "selected" if value == expected else ""

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Inspection Readiness Score</div><div class="value" style="color:var(--green);">{score}%</div><div class="note">Calculated from inspection evidence domains.</div></div>
        <div class="metric"><div class="label">Inspection Decision</div><div class="value" style="color:var(--yellow);">{decision}</div><div class="note">{reason}</div></div>
    </section>

    <section class="section">
        <h2>CITrust™ Agentic Inspection Simulator</h2>
        <p>
            Simulate whether an AI-assisted ServiceNow / CMDB / GxP / cyber / change workflow is ready for audit or inspection response.
        </p>

        <form method="POST" action="/citrust/agentic-inspection-simulator">
            <table>
                <tbody>
                    <tr><td><strong>Inspection Scope Defined?</strong></td><td><select name="scope" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(scope, "yes")}>Yes</option><option value="no" {selected(scope, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Agent Governance Evidence Ready?</strong></td><td><select name="agent" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(agent, "yes")}>Yes</option><option value="no" {selected(agent, "no")}>No</option></select></td></tr>
                    <tr><td><strong>CI / CMDB Evidence Ready?</strong></td><td><select name="ci" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(ci, "yes")}>Yes</option><option value="no" {selected(ci, "no")}>No</option></select></td></tr>
                    <tr><td><strong>GxP / QA Evidence Ready?</strong></td><td><select name="gxp" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(gxp, "yes")}>Yes</option><option value="no" {selected(gxp, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Cyber / Access Evidence Ready?</strong></td><td><select name="cyber" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(cyber, "yes")}>Yes</option><option value="no" {selected(cyber, "no")}>No</option></select></td></tr>
                    <tr><td><strong>AI Replay Evidence Ready?</strong></td><td><select name="replay" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(replay, "yes")}>Yes</option><option value="no" {selected(replay, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Change-Control Evidence Ready?</strong></td><td><select name="change" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(change, "yes")}>Yes</option><option value="no" {selected(change, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Monitoring / Testing Evidence Ready?</strong></td><td><select name="monitoring" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(monitoring, "yes")}>Yes</option><option value="no" {selected(monitoring, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Attestation / Residual Risk Evidence Ready?</strong></td><td><select name="attestation" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(attestation, "yes")}>Yes</option><option value="no" {selected(attestation, "no")}>No</option></select></td></tr>
                </tbody>
            </table>

            <button type="submit" style="margin-top:16px;padding:12px 18px;border-radius:12px;border:0;background:#2563eb;color:white;font-weight:800;">Run Inspection Readiness Check</button>
        </form>
    </section>

    <section class="section">
        <h2>Inspection Readiness Decision</h2>
        <div class="answer">
            <strong>Score:</strong> {score}%<br>
            <strong>Decision:</strong> <span class="badge {badge}">{decision}</span><br>
            <strong>Reason:</strong> {reason}
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Inspection Simulator",
        "Simulator for inspection readiness across scope, agent governance, CI evidence, GxP, cyber, AI replay, change control, monitoring, testing, attestation, and residual risk.",
        body
    )


@app.route("/citrust/agentic-inspection-json")
@app.route("/citrust/agentic-audit-json")
@app.route("/citrust/ci-agentic-inspection-json")
def citrust_agentic_inspection_json():
    from flask import jsonify

    return jsonify({
        "module": "CITrust™",
        "capability": "Agentic Inspection Readiness Center + Auditor Evidence Request Router",
        "primary_question": "Can CITrust™ answer auditor, inspector, QA, cyber, change, and executive questions with routed, approved, replayable evidence?",
        "inspection_domains": CITRUST_AGENTIC_INSPECTION_DOMAINS,
        "auditor_evidence_request_router": CITRUST_AUDITOR_EVIDENCE_REQUEST_ROUTER,
        "inspection_question_bank": CITRUST_INSPECTION_QUESTION_BANK,
        "inspection_response_pack": CITRUST_INSPECTION_RESPONSE_PACK,
        "inspection_gap_triage": CITRUST_INSPECTION_GAP_TRIAGE,
        "inspection_response_approvals": CITRUST_INSPECTION_RESPONSE_APPROVALS,
        "minimum_conditions": [
            "Inspection scope is defined",
            "Agent governance evidence is ready",
            "CI / CMDB evidence is ready",
            "GxP / QA evidence is ready where applicable",
            "Cyber / access evidence is ready where applicable",
            "AI replay evidence is ready",
            "Change-control evidence is ready where applicable",
            "Monitoring and control testing evidence are ready",
            "Attestation and residual risk evidence are ready",
            "Domain owners approve their response areas"
        ],
        "default_decision": "Do not present an AI-assisted CITrust workflow as inspection-ready unless scope, evidence, owner routing, replay, gap triage, response approval, and attestation are complete"
    })

# ============================================================
# END CITRUST_AGENTIC_INSPECTION_READINESS_CENTER_V1_ACTIVE
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

print("CITrust Agentic Inspection Readiness Center installed.")
print(f"Inserted before: {target_found}")
