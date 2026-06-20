from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_AI_INCIDENT_RESPONSE_CAPA_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust AI Incident Response Center already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base module not found. Install AgentTrust module first.")

nav_old = '<a href="/agenttrust/model-risk-control-center" class="secondary">Model Risk</a>'
nav_new = '''<a href="/agenttrust/model-risk-control-center" class="secondary">Model Risk</a>
                    <a href="/agenttrust/ai-incident-response-center" class="secondary">Incident Response</a>
                    <a href="/agenttrust/agent-incident-classifier" class="dark">Classifier</a>
                    <a href="/agenttrust/capa-deviation-router" class="dark">CAPA / Deviation</a>
                    <a href="/agenttrust/incident-response-simulator" class="dark">Incident Simulator</a>'''

if nav_old in text and "/agenttrust/ai-incident-response-center" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# AGENTTRUST_AI_INCIDENT_RESPONSE_CAPA_V1_ACTIVE
# AgentTrust™ AI Incident Response Center, Agent Incident Classifier,
# CAPA / Deviation Router, Containment Playbook, Root Cause Mapper,
# Regulatory / QA / Cyber Notification Router, Incident Evidence Vault,
# Incident Response Simulator, and Incident Response JSON Export
# ============================================================

AGENTTRUST_INCIDENT_TYPES = [
    {
        "incident_id": "AT-INC-001",
        "incident_type": "Unauthorized Action Attempt",
        "trigger": "Agent attempts create, update, trigger, approve, access, or regulated conclusion outside approved authority.",
        "severity": "Critical",
        "owner_route": "Risk Owner / Process Owner / Platform Owner",
        "containment": "Block action, revoke trust token, preserve evidence, open incident record.",
        "closure_evidence": "Authority breach record, root cause, remediation, retest, owner signoff."
    },
    {
        "incident_id": "AT-INC-002",
        "incident_type": "Cyber / Privileged Access Breach",
        "trigger": "Agent touches access, entitlement, CyberArk, PSM, admin, privileged route, or credential context without cyber review.",
        "severity": "Critical",
        "owner_route": "Cybersecurity / CyberArk / Access Owner",
        "containment": "Suspend access-related scope, block privileged execution, escalate to cybersecurity.",
        "closure_evidence": "Cyber review, access decision, session evidence, remediation, control update."
    },
    {
        "incident_id": "AT-INC-003",
        "incident_type": "GxP / QA Governance Breach",
        "trigger": "Agent output becomes QA, validation, release, deviation, CAPA, QC, inspection, or regulated conclusion without QA review.",
        "severity": "Critical",
        "owner_route": "QA / Validation / Quality Owner",
        "containment": "Mark output non-authoritative, suspend regulated reliance, route to QA.",
        "closure_evidence": "QA review, regulated impact decision, evidence lineage, deviation/CAPA decision if needed."
    },
    {
        "incident_id": "AT-INC-004",
        "incident_type": "Evidence Integrity Failure",
        "trigger": "Missing source, missing tool-call evidence, missing reviewer, post-created evidence, or incomplete outcome trace.",
        "severity": "High",
        "owner_route": "Audit / Governance / Platform Owner",
        "containment": "Restrict reliance, mark replay weak, rebuild evidence package.",
        "closure_evidence": "Evidence gap closure, replay test, evidence vault update, audit owner signoff."
    },
    {
        "incident_id": "AT-INC-005",
        "incident_type": "Prompt Injection / Instruction Override",
        "trigger": "External content, user prompt, or retrieved text attempts to override system rules, authority, or prohibited actions.",
        "severity": "High",
        "owner_route": "Security / AI Platform / Governance Owner",
        "containment": "Block unsafe instruction, quarantine affected session, preserve prompt and source evidence.",
        "closure_evidence": "Red-team review, prompt defense update, retest evidence, model/prompt change gate if needed."
    },
    {
        "incident_id": "AT-INC-006",
        "incident_type": "Model / Prompt / Tool Drift Incident",
        "trigger": "Model, prompt, endpoint, tool, API, data source, output parser, or owner changes without review.",
        "severity": "High",
        "owner_route": "AI Platform / Lifecycle / Governance Owner",
        "containment": "Suspend trust score, run change validation gate, restrict release state.",
        "closure_evidence": "Change record, validation evidence, updated AgentBOM, recalculated trust score."
    },
    {
        "incident_id": "AT-INC-007",
        "incident_type": "Vendor AI Boundary Breach",
        "trigger": "Vendor AI processes data outside approved boundary, retention rule, contract control, or exit plan.",
        "severity": "High",
        "owner_route": "Vendor Owner / Security / Privacy / Legal",
        "containment": "Suspend vendor AI use, preserve evidence, initiate vendor assurance review.",
        "closure_evidence": "Vendor response, contract review, deletion/export evidence, risk acceptance or termination."
    },
    {
        "incident_id": "AT-INC-008",
        "incident_type": "Privacy / Data Protection Breach",
        "trigger": "Agent processes personal, sensitive, regulated, access, cyber, or confidential data outside approved privacy boundary.",
        "severity": "Critical",
        "owner_route": "Privacy / Legal / Data Owner / Security",
        "containment": "Stop processing, preserve evidence, route to privacy/legal owner, review transfer and retention.",
        "closure_evidence": "Privacy review, data boundary correction, deletion/retention evidence, owner decision."
    }
]


AGENTTRUST_RESPONSE_PLAYBOOKS = [
    {
        "playbook_id": "AT-PB-001",
        "playbook": "Immediate Containment",
        "actions": "Block action, revoke trust token, freeze session, preserve prompt/input/output/tool-call evidence.",
        "owner": "Runtime / Platform Owner",
        "timeframe": "Immediate"
    },
    {
        "playbook_id": "AT-PB-002",
        "playbook": "Owner Routing",
        "actions": "Route cyber events to cybersecurity, GxP events to QA, privacy events to privacy/legal, vendor events to vendor owner.",
        "owner": "Governance Owner",
        "timeframe": "Same business day for high/critical events"
    },
    {
        "playbook_id": "AT-PB-003",
        "playbook": "Evidence Preservation",
        "actions": "Preserve agent ID, model ID, prompt, source, tool call, reviewer, output, decision, timestamp, and outcome.",
        "owner": "Audit / Evidence Owner",
        "timeframe": "Before remediation changes"
    },
    {
        "playbook_id": "AT-PB-004",
        "playbook": "Root Cause Analysis",
        "actions": "Classify root cause as model, prompt, tool, data, boundary, owner, authority, evidence, user, vendor, or control failure.",
        "owner": "Risk / Platform / Process Owner",
        "timeframe": "Before closure"
    },
    {
        "playbook_id": "AT-PB-005",
        "playbook": "CAPA / Deviation Decision",
        "actions": "Determine whether the event requires CAPA, deviation, change control, cyber incident, privacy review, vendor escalation, or audit note.",
        "owner": "QA / Risk / Governance Owner",
        "timeframe": "Based on severity and regulated impact"
    },
    {
        "playbook_id": "AT-PB-006",
        "playbook": "Retest and Release",
        "actions": "Run simulator, red-team test, replay test, release gate, and trust score recalculation before restoring use.",
        "owner": "Lifecycle / Release Owner",
        "timeframe": "Before reactivation"
    }
]


AGENTTRUST_CAPA_DEVIATION_ROUTES = [
    {
        "route_id": "AT-CDR-001",
        "event": "AI output influenced regulated decision without QA review.",
        "route": "Deviation / QA Investigation",
        "owner": "QA / Validation Owner",
        "required_evidence": "Source evidence, AI output, human reliance, regulated impact, QA decision."
    },
    {
        "route_id": "AT-CDR-002",
        "event": "AI agent failed to route GxP impact.",
        "route": "CAPA or Quality Event Assessment",
        "owner": "QA / Validation Owner",
        "required_evidence": "Routing failure, impact assessment, control update, retest evidence."
    },
    {
        "route_id": "AT-CDR-003",
        "event": "AI attempted unauthorized access or privileged action.",
        "route": "Cyber Incident / Access Governance Review",
        "owner": "Cybersecurity / Access Owner",
        "required_evidence": "Access context, privileged route, block record, cyber decision."
    },
    {
        "route_id": "AT-CDR-004",
        "event": "AI output used with incomplete evidence.",
        "route": "Evidence Gap Closure / Audit Note",
        "owner": "Audit / Governance Owner",
        "required_evidence": "Evidence gap, reliance decision, reconstructed timeline, closure proof."
    },
    {
        "route_id": "AT-CDR-005",
        "event": "Prompt injection bypassed guardrail.",
        "route": "Security Review / Red-Team Remediation",
        "owner": "Security / AI Platform Owner",
        "required_evidence": "Injected / Red-Team Remediation",
        "owner": "Security / AI Platform Owner",
        "required_evidence": "Injected prompt, source, failed control, remediation, retest."
    },
    {
        "route_id": "AT-CDR-006",
        "event": "Vendor AI breached data or contract boundary.",
        "route": "Vendor Risk Escalation / Contract Review",
        "owner": "Vendor Owner / Legal / Security",
        "required_evidence": "Vendor AI action, data boundary breach, vendor response, exit/deletion evidence."
    },
    {
        "route_id": "AT-CDR-007",
        "event": "Personal, sensitive, or confidential data processed outside approved boundary.",
        "route": "Privacy / Legal Review",
        "owner": "Privacy / Legal / Data Owner",
        "required_evidence": "Data category, prompt/output, transfer path, retention/deletion status."
    }
]


AGENTTRUST_ROOT_CAUSE_MAP = [
    {
        "cause": "Model Failure",
        "example": "Unsupported claim, incorrect summary, false confidence, unsuitable model behavior.",
        "required_fix": "Model validation review, limitation update, monitoring threshold, human review rule."
    },
    {
        "cause": "Prompt Failure",
        "example": "Prompt allows hidden approval, weak prohibited-action language, injection susceptibility.",
        "required_fix": "Prompt change gate, prompt defense update, red-team retest."
    },
    {
        "cause": "Tool Failure",
        "example": "Tool allows update, trigger, or access path not covered by authority.",
        "required_fix": "Tool authority review, execution firewall update, tool mode restriction."
    },
    {
        "cause": "Data Boundary Failure",
        "example": "Agent uses personal, cyber, regulated, vendor, or confidential data without routing.",
        "required_fix": "Privacy boundary update, data classification route, minimization gate."
    },
    {
        "cause": "Authority Failure",
        "example": "Agent action does not have valid authority, operating license, or trust token.",
        "required_fix": "Authority gate update, trust contract correction, preflight rule."
    },
    {
        "cause": "Human Oversight Failure",
        "example": "Reviewer missing, approval assumed, escalation owner not captured.",
        "required_fix": "Human oversight route, signoff matrix update, approval evidence vault."
    },
    {
        "cause": "Evidence Failure",
        "example": "Missing source, timestamp, tool-call, reviewer, outcome, or replay package.",
        "required_fix": "Evidence ledger update, replay test, evidence sufficiency review."
    },
    {
        "cause": "Vendor Failure",
        "example": "Vendor AI changed behavior, retained data, exported data, or lacked audit support.",
        "required_fix": "Vendor assurance review, contract enforcement, exit plan."
    }
]


def agenttrust_incident_type_rows():
    rows = ""

    for item in AGENTTRUST_INCIDENT_TYPES:
        badge = "orange"
        if item["severity"] == "Critical":
            badge = "red"
        elif item["severity"] == "High":
            badge = "yellow"

        rows += f"""
        <tr>
            <td><strong>{item["incident_id"]}</strong></td>
            <td>{item["incident_type"]}</td>
            <td>{item["trigger"]}</td>
            <td><span class="badge {badge}">{item["severity"]}</span></td>
            <td>{item["owner_route"]}</td>
            <td>{item["containment"]}</td>
            <td>{item["closure_evidence"]}</td>
        </tr>
        """

    return rows


def agenttrust_playbook_rows():
    rows = ""

    for item in AGENTTRUST_RESPONSE_PLAYBOOKS:
        rows += f"""
        <tr>
            <td><strong>{item["playbook_id"]}</strong></td>
            <td><span class="badge blue">{item["playbook"]}</span></td>
            <td>{item["actions"]}</td>
            <td>{item["owner"]}</td>
            <td>{item["timeframe"]}</td>
        </tr>
        """

    return rows


def agenttrust_capa_deviation_rows():
    rows = ""

    for item in AGENTTRUST_CAPA_DEVIATION_ROUTES:
        rows += f"""
        <tr>
            <td><strong>{item["route_id"]}</strong></td>
            <td>{item["event"]}</td>
            <td><span class="badge orange">{item["route"]}</span></td>
            <td>{item["owner"]}</td>
            <td>{item["required_evidence"]}</td>
        </tr>
        """

    return rows


def agenttrust_root_cause_rows():
    rows = ""

    for item in AGENTTRUST_ROOT_CAUSE_MAP:
        rows += f"""
        <tr>
            <td><strong>{item["cause"]}</strong></td>
            <td>{item["example"]}</td>
            <td><span class="badge yellow">{item["required_fix"]}</span></td>
        </tr>
        """

    return rows


def agenttrust_incident_response_decision(severity, cyber, gxp, privacy, evidence, authority, vendor, recurrence):
    severity = severity or "high"

    if severity == "critical":
        base_score = 100
    elif severity == "high":
        base_score = 80
    elif severity == "medium":
        base_score = 55
    else:
        base_score = 30

    routes = []
    if cyber == "yes":
        routes.append("Cybersecurity / CyberArk / Access Owner")
    if gxp == "yes":
        routes.append("QA / Validation Owner")
    if privacy == "yes":
        routes.append("Privacy / Legal / Data Owner")
    if vendor == "yes":
        routes.append("Vendor Owner / Legal / Security")
    if evidence == "no":
        routes.append("Audit / Evidence Owner")
    if authority == "no":
        routes.append("Risk / Process Owner")
    if recurrence == "yes":
        routes.append("Governance Board / CAPA Owner")

    if not routes:
        routes.append("Governance Owner")

    if severity == "critical" or cyber == "yes" or gxp == "yes" or privacy == "yes":
        return base_score, "Critical Incident — Contain and Escalate", "red", ", ".join(routes), "Block or suspend affected agent scope, preserve evidence, route to accountable owner, and require closure evidence before reactivation."
    if authority == "no":
        return base_score, "Authority Incident — Block Action", "red", ", ".join(routes), "Revoke trust token, block action, update authority gate, and retest."
    if evidence == "no":
        return base_score, "Evidence Incident — Restrict Reliance", "orange", ", ".join(routes), "Mark replay weak, rebuild evidence package, and restrict operational reliance."
    if recurrence == "yes":
        return base_score, "Recurring Incident — CAPA Review", "orange", ", ".join(routes), "Open recurring issue review and determine CAPA or control redesign."
    return base_score, "Managed Incident — Track to Closure", "yellow", ", ".join(routes), "Document incident, preserve evidence, assign owner, and close with remediation proof."


try:
    AGENTTRUST_EXPECTED_ROUTES.extend([
        "/agenttrust/ai-incident-response-center",
        "/agenttrust/agent-incident-classifier",
        "/agenttrust/incident-containment-playbook",
        "/agenttrust/capa-deviation-router",
        "/agenttrust/root-cause-mapper",
        "/agenttrust/regulatory-notification-router",
        "/agenttrust/incident-evidence-vault",
        "/agenttrust/incident-response-simulator",
        "/agenttrust/incident-response-json"
    ])
except Exception:
    pass


@app.route("/agenttrust/ai-incident-response-center")
@app.route("/agenttrust/agent-incident-response")
@app.route("/agenttrust/incident-response-center")
def agenttrust_ai_incident_response_center():
    rows = agenttrust_incident_type_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Incident Center</div><div class="value" style="color:var(--green);">Active</div><div class="note">AI event response and escalation defined.</div></div>
        <div class="metric"><div class="label">Incident Types</div><div class="value" style="color:var(--blue);">8</div><div class="note">Authority, cyber, GxP, evidence, prompt, drift, vendor, privacy.</div></div>
        <div class="metric"><div class="label">Containment</div><div class="value" style="color:var(--red);">Immediate</div><div class="note">Block, suspend, revoke token, quarantine, preserve evidence.</div></div>
        <div class="metric"><div class="label">CAPA / Deviation</div><div class="value" style="color:var(--orange);">Routed</div><div class="note">QA and governance routes mapped.</div></div>
        <div class="metric"><div class="label">Root Cause</div><div class="value" style="color:var(--yellow);">Mapped</div><div class="note">Model, prompt, tool, data, authority, human, evidence, vendor.</div></div>
        <div class="metric"><div class="label">Closure</div><div class="value" style="color:var(--purple);">Evidence-Based</div><div class="note">No closure without remediation and replay proof.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ AI Incident Response Center</h2>
        <div class="answer">
            <strong>Purpose:</strong> control AI agent failures after they occur.
            AgentTrust™ classifies the incident, preserves evidence, contains risk, routes to the correct owner,
            determines whether CAPA, deviation, cyber review, privacy review, vendor escalation, or change control is required,
            and closes only with evidence.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Incident ID</th>
                    <th>Incident Type</th>
                    <th>Trigger</th>
                    <th>Severity</th>
                    <th>Owner Route</th>
                    <th>Containment</th>
                    <th>Closure Evidence</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Incident Response Rule</h2>
        <div class="answer">
            AI incidents must not be treated as informal defects.
            They require severity, owner route, containment, root cause, remediation, evidence preservation, and closure proof.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ AI Incident Response Center",
        "AI incident response center for authority breach, cyber breach, GxP breach, evidence failure, prompt injection, drift, vendor boundary breach, and privacy breach.",
        body
    )


@app.route("/agenttrust/agent-incident-classifier")
@app.route("/agenttrust/ai-incident-classifier")
@app.route("/agenttrust/incident-classifier")
def agenttrust_agent_incident_classifier():
    rows = agenttrust_incident_type_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Agent Incident Classifier</h2>
        <p>
            The classifier determines what kind of AI governance failure occurred and which owner must respond.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Incident ID</th>
                    <th>Incident Type</th>
                    <th>Trigger</th>
                    <th>Severity</th>
                    <th>Owner Route</th>
                    <th>Containment</th>
                    <th>Closure Evidence</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Classification Rule</h2>
        <div class="answer">
            Correct classification drives correct response.
            Cyber incidents route to cyber owners, GxP incidents route to QA, privacy incidents route to privacy/legal,
            and authority failures route to process and risk owners.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Agent Incident Classifier",
        "Classifier for AI agent incidents across authority, cyber, GxP, evidence, prompt injection, drift, vendor, and privacy failures.",
        body
    )


@app.route("/agenttrust/incident-containment-playbook")
@app.route("/agenttrust/containment-playbook")
@app.route("/agenttrust/ai-containment-playbook")
def agenttrust_incident_containment_playbook():
    rows = agenttrust_playbook_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Incident Containment Playbook</h2>
        <p>
            The containment playbook defines immediate response actions when an AI agent incident occurs.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Playbook ID</th>
                    <th>Playbook</th>
                    <th>Actions</th>
                    <th>Owner</th>
                    <th>Timeframe</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Containment Rule</h2>
        <div class="answer">
            Containment comes before debate. Block unsafe action, preserve evidence, route to owner, and prevent further reliance
            until the incident is classified and controlled.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Incident Containment Playbook",
        "Containment playbook for AI agent block, trust token revocation, evidence preservation, owner routing, root cause analysis, CAPA decision, retest, and release.",
        body
    )


@app.route("/agenttrust/capa-deviation-router")
@app.route("/agenttrust/ai-capa-router")
@app.route("/agenttrust/ai-deviation-router")
def agenttrust_capa_deviation_router():
    rows = agenttrust_capa_deviation_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ CAPA / Deviation Router</h2>
        <p>
            This router determines whether an AI event should become a CAPA, deviation, cyber incident,
            privacy review, vendor escalation, evidence gap closure, or governance remediation.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Route ID</th>
                    <th>Event</th>
                    <th>Route</th>
                    <th>Owner</th>
                    <th>Required Evidence</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>CAPA / Deviation Rule</h2>
        <div class="answer">
            If an AI agent event impacts regulated evidence, QA decisions, validation, release, deviation, CAPA,
            cyber access, or privacy boundaries, the event must be routed, evidenced, and formally closed.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ CAPA Deviation Router",
        "Router for AI events requiring deviation, CAPA, cyber incident, privacy review, vendor escalation, evidence gap closure, or governance remediation.",
        body
    )


@app.route("/agenttrust/root-cause-mapper")
@app.route("/agenttrust/ai-root-cause-mapper")
@app.route("/agenttrust/incident-root-cause")
def agenttrust_root_cause_mapper():
    rows = agenttrust_root_cause_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Root Cause Mapper</h2>
        <p>
            The Root Cause Mapper identifies the control weakness behind an AI incident.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Root Cause</th>
                    <th>Example</th>
                    <th>Required Fix</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Root Cause Rule</h2>
        <div class="answer">
            AI incident closure must fix the control weakness, not just the output.
            Root cause may be model, prompt, tool, data boundary, authority, human oversight, evidence, or vendor failure.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Root Cause Mapper",
        "Root cause mapper for AI incident model failure, prompt failure, tool failure, data boundary failure, authority failure, human oversight failure, evidence failure, and vendor failure.",
        body
    )


@app.route("/agenttrust/regulatory-notification-router")
@app.route("/agenttrust/qa-cyber-privacy-notification-router")
@app.route("/agenttrust/incident-notification-router")
def agenttrust_regulatory_notification_router():
    body = """
    <section class="section">
        <h2>AgentTrust™ Regulatory / QA / Cyber Notification Router</h2>
        <p>
            This router determines who must be notified based on incident impact.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Impact Signal</th>
                    <th>Notify</th>
                    <th>Evidence Needed</th>
                    <th>Default Response</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Access, CyberArk, PSM, entitlement, admin, or privileged impact.</td><td>Cybersecurity / Access / CyberArk Owner.</td><td>Access context, tool call, decision, containment.</td><td><span class="badge red">Cyber escalation</span></td></tr>
                <tr><td>GMP, QA, validation, QC, release, deviation, CAPA, or inspection impact.</td><td>QA / Validation / Quality Owner.</td><td>Regulated source, output, reliance, reviewer, impact decision.</td><td><span class="badge red">QA-governed review</span></td></tr>
                <tr><td>Personal, sensitive, or confidential data exposure.</td><td>Privacy / Legal / Data Owner.</td><td>Data category, transfer, retention, deletion, output evidence.</td><td><span class="badge red">Privacy review</span></td></tr>
                <tr><td>Vendor AI boundary breach.</td><td>Vendor Owner / Legal / Security.</td><td>Vendor system, data boundary, contract obligation, vendor response.</td><td><span class="badge orange">Vendor escalation</span></td></tr>
                <tr><td>Audit replay failure.</td><td>Audit / Governance Owner.</td><td>Missing evidence, timeline gap, final outcome, remediation.</td><td><span class="badge orange">Evidence gap closure</span></td></tr>
                <tr><td>Repeated incident or systemic failure.</td><td>Governance Board / CAPA Owner.</td><td>Trend evidence, root cause, corrective action, effectiveness check.</td><td><span class="badge red">CAPA assessment</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Notification Rule</h2>
        <div class="answer">
            Notification is impact-based. AgentTrust™ routes incidents to the owner who can defend and correct the risk:
            cyber, QA, privacy, vendor, audit, governance, or CAPA owner.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Notification Router",
        "Notification router for AI incident cyber, QA, GxP, privacy, vendor, audit, governance, and CAPA impact routes.",
        body
    )


@app.route("/agenttrust/incident-evidence-vault")
@app.route("/agenttrust/ai-incident-evidence")
@app.route("/agenttrust/incident-evidence")
def agenttrust_incident_evidence_vault():
    body = """
    <section class="section">
        <h2>AgentTrust™ Incident Evidence Vault</h2>
        <p>
            The Incident Evidence Vault defines the minimum evidence required to close an AI incident.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Evidence Category</th>
                    <th>Required Content</th>
                    <th>Why Required</th>
                    <th>If Missing</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent Identity</td><td>Agent ID, owner, passport, operating license.</td><td>Shows which AI agent failed.</td><td><span class="badge red">Unknown actor</span></td></tr>
                <tr><td>Model / Prompt</td><td>Model ID, endpoint, prompt version, configuration.</td><td>Shows model layer context.</td><td><span class="badge orange">Weak root cause</span></td></tr>
                <tr><td>Input / Source</td><td>Prompt, retrieved source, record ID, document reference.</td><td>Shows what the agent relied on.</td><td><span class="badge red">Cannot reconstruct</span></td></tr>
                <tr><td>Tool Call</td><td>Tool, API, target system, mode, timestamp, result.</td><td>Shows operational touchpoint.</td><td><span class="badge red">No execution trace</span></td></tr>
                <tr><td>Authority Decision</td><td>Preflight gate, trust token, action permit, decision rule.</td><td>Shows whether action was allowed.</td><td><span class="badge red">Authority gap</span></td></tr>
                <tr><td>Human Review</td><td>Reviewer, approver, escalation owner, decision.</td><td>Preserves human accountability.</td><td><span class="badge red">Hidden approval risk</span></td></tr>
                <tr><td>Impact Assessment</td><td>Cyber, GxP, privacy, vendor, audit, operational impact.</td><td>Shows severity and route.</td><td><span class="badge orange">Weak response</span></td></tr>
                <tr><td>Closure Evidence</td><td>Root cause, remediation, retest, owner signoff, effectiveness check.</td><td>Proves incident was closed.</td><td><span class="badge red">Do not close</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Evidence Vault Rule</h2>
        <div class="answer">
            AI incident closure must be evidence-based.
            If the incident cannot be reconstructed from identity to closure, it is not defensibly closed.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Incident Evidence Vault",
        "Incident evidence vault for AI agent identity, model, prompt, source, tool call, authority, human review, impact assessment, and closure evidence.",
        body
    )


@app.route("/agenttrust/incident-response-simulator", methods=["GET", "POST"])
@app.route("/agenttrust/ai-incident-simulator", methods=["GET", "POST"])
@app.route("/agenttrust/incident-triage-simulator", methods=["GET", "POST"])
def agenttrust_incident_response_simulator():
    from flask import request

    severity = request.form.get("severity", "high")
    cyber = request.form.get("cyber", "no")
    gxp = request.form.get("gxp", "no")
    privacy = request.form.get("privacy", "no")
    evidence = request.form.get("evidence", "yes")
    authority = request.form.get("authority", "yes")
    vendor = request.form.get("vendor", "no")
    recurrence = request.form.get("recurrence", "no")

    score, decision, badge, owner_route, response = agenttrust_incident_response_decision(
        severity, cyber, gxp, privacy, evidence, authority, vendor, recurrence
    )

    def selected(value, expected):
        return "selected" if value == expected else ""

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Incident Severity Score</div><div class="value" style="color:var(--red);">{score}</div><div class="note">Calculated from incident impact.</div></div>
        <div class="metric"><div class="label">Incident Decision</div><div class="value" style="color:var(--yellow);">{decision}</div><div class="note">Owner route: {owner_route}</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Incident Response Simulator</h2>
        <p>
            Simulate an AI incident and generate containment, routing, and closure direction.
        </p>

        <form method="POST" action="/agenttrust/incident-response-simulator">
            <table>
                <tbody>
                    <tr>
                        <td><strong>Severity</strong></td>
                        <td>
                            <select name="severity" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;">
                                <option value="low" {selected(severity, "low")}>Low</option>
                                <option value="medium" {selected(severity, "medium")}>Medium</option>
                                <option value="high" {selected(severity, "high")}>High</option>
                                <option value="critical" {selected(severity, "critical")}>Critical</option>
                            </select>
                        </td>
                    </tr>
                    <tr><td><strong>Cyber / Access / Privileged Impact?</strong></td><td><select name="cyber" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="no" {selected(cyber, "no")}>No</option><option value="yes" {selected(cyber, "yes")}>Yes</option></select></td></tr>
                    <tr><td><strong>GxP / QA / Validation Impact?</strong></td><td><select name="gxp" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="no" {selected(gxp, "no")}>No</option><option value="yes" {selected(gxp, "yes")}>Yes</option></select></td></tr>
                    <tr><td><strong>Privacy / Sensitive Data Impact?</strong></td><td><select name="privacy" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="no" {selected(privacy, "no")}>No</option><option value="yes" {selected(privacy, "yes")}>Yes</option></select></td></tr>
                    <tr><td><strong>Evidence Complete?</strong></td><td><select name="evidence" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(evidence, "yes")}>Yes</option><option value="no" {selected(evidence, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Authority Confirmed?</strong></td><td><select name="authority" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(authority, "yes")}>Yes</option><option value="no" {selected(authority, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Vendor AI Involved?</strong></td><td><select name="vendor" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="no" {selected(vendor, "no")}>No</option><option value="yes" {selected(vendor, "yes")}>Yes</option></select></td></tr>
                    <tr><td><strong>Recurring / Systemic?</strong></td><td><select name="recurrence" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="no" {selected(recurrence, "no")}>No</option><option value="yes" {selected(recurrence, "yes")}>Yes</option></select></td></tr>
                </tbody>
            </table>

            <button type="submit" style="margin-top:16px;padding:12px 18px;border-radius:12px;border:0;background:#2563eb;color:white;font-weight:800;">Run Incident Triage</button>
        </form>
    </section>

    <section class="section">
        <h2>Incident Response Decision</h2>
        <div class="answer">
            <strong>Decision:</strong> <span class="badge {badge}">{decision}</span><br>
            <strong>Owner Route:</strong> {owner_route}<br>
            <strong>Response:</strong> {response}
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Incident Response Simulator",
        "Simulator for AI incident triage across severity, cyber impact, GxP impact, privacy impact, evidence, authority, vendor involvement, and recurrence.",
        body
    )


@app.route("/agenttrust/incident-response-json")
@app.route("/agenttrust/ai-incident-json")
@app.route("/agenttrust/capa-deviation-json")
def agenttrust_incident_response_json():
    from flask import jsonify

    return jsonify({
        "module": "AgentTrust™",
        "capability": "AI Incident Response Center + CAPA / Deviation Router",
        "primary_question": "How should this AI agent incident be classified, contained, routed, remediated, and closed?",
        "incident_types": AGENTTRUST_INCIDENT_TYPES,
        "response_playbooks": AGENTTRUST_RESPONSE_PLAYBOOKS,
        "capa_deviation_routes": AGENTTRUST_CAPA_DEVIATION_ROUTES,
        "root_cause_map": AGENTTRUST_ROOT_CAUSE_MAP,
        "minimum_closure_conditions": [
            "Incident type classified",
            "Severity assigned",
            "Correct owner route identified",
            "Immediate containment completed",
            "Evidence preserved",
            "Root cause mapped",
            "CAPA / deviation / cyber / privacy / vendor route assessed",
            "Remediation completed",
            "Retest performed",
            "Closure evidence and owner signoff captured"
        ],
        "default_decision": "Do not close AI incidents until containment, owner routing, evidence preservation, root cause, remediation, retest, and closure evidence are complete"
    })

# ============================================================
# END AGENTTRUST_AI_INCIDENT_RESPONSE_CAPA_V1_ACTIVE
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

print("AgentTrust AI Incident Response Center installed.")
print(f"Inserted before: {target_found}")
