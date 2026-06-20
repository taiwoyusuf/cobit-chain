from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_EXECUTIVE_ATTESTATION_CENTER_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust Executive Attestation Center already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base module not found. Install AgentTrust module first.")

nav_old = '<a href="/agenttrust/control-effectiveness-testing" class="secondary">Control Testing</a>'
nav_new = '''<a href="/agenttrust/control-effectiveness-testing" class="secondary">Control Testing</a>
                    <a href="/agenttrust/executive-attestation-center" class="secondary">Attestation</a>
                    <a href="/agenttrust/accountability-signoff-ledger" class="dark">Signoff Ledger</a>
                    <a href="/agenttrust/ai-reliance-attestation" class="dark">Reliance</a>
                    <a href="/agenttrust/attestation-simulator" class="dark">Attestation Sim</a>'''

if nav_old in text and "/agenttrust/executive-attestation-center" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# AGENTTRUST_EXECUTIVE_ATTESTATION_CENTER_V1_ACTIVE
# AgentTrust™ Executive Attestation Center,
# Accountability Signoff Ledger, AI Reliance Attestation,
# Board Risk Attestation, Control Owner Certification,
# Signoff Exception Register, Attestation Package Builder,
# Attestation Simulator, and Attestation JSON Export
# ============================================================

AGENTTRUST_ATTESTATION_ROLES = [
    {
        "role_id": "AT-ATT-001",
        "role": "Business / Process Owner",
        "attests_to": "The AI agent use case, workflow purpose, operational boundary, and human reliance model are acceptable.",
        "evidence_reviewed": "Agent passport, operating license, use case, authority matrix, human oversight route.",
        "cannot_attest_if": "Owner is missing, workflow impact is unclear, or AI output can become hidden approval."
    },
    {
        "role_id": "AT-ATT-002",
        "role": "Technical / Platform Owner",
        "attests_to": "The AI agent architecture, tool calls, integrations, runtime controls, and evidence capture are technically controlled.",
        "evidence_reviewed": "AgentBOM, integration adapter map, runtime control plane, evidence ledger, monitoring events.",
        "cannot_attest_if": "Tool boundary, API route, logging, rollback, or runtime enforcement is incomplete."
    },
    {
        "role_id": "AT-ATT-003",
        "role": "Cybersecurity / Access Owner",
        "attests_to": "Access, entitlement, CyberArk, PSM, admin, and privileged-impacting risks are reviewed and controlled.",
        "evidence_reviewed": "MyAccess / CyberArk route, privileged impact assessment, cyber escalation evidence, SIEM alert route.",
        "cannot_attest_if": "AI can approve access, influence privileged workflow, or bypass cyber review."
    },
    {
        "role_id": "AT-ATT-004",
        "role": "QA / Validation Owner",
        "attests_to": "GxP, QA, validation, QC, release, deviation, CAPA, and inspection impacts are reviewed and human-governed.",
        "evidence_reviewed": "GxP screen, QA review, validation decision, regulated conclusion block, audit dossier.",
        "cannot_attest_if": "AI output can become regulated conclusion or validation approval without QA signoff."
    },
    {
        "role_id": "AT-ATT-005",
        "role": "Privacy / Data Owner",
        "attests_to": "Data classification, minimization, retention, transfer, privacy, and sensitive data controls are acceptable.",
        "evidence_reviewed": "Privacy boundary, DPIA, data classification router, retention rule, transfer screen.",
        "cannot_attest_if": "Sensitive, personal, regulated, cyber, or vendor-processed data boundary is unresolved."
    },
    {
        "role_id": "AT-ATT-006",
        "role": "Vendor / Third-Party Owner",
        "attests_to": "Vendor AI identity, data boundary, contract obligations, audit support, and exit rights are acceptable.",
        "evidence_reviewed": "Vendor AI register, contract controls, evidence dossier, data sharing boundary, exit plan.",
        "cannot_attest_if": "Vendor cannot support audit evidence, deletion, change notice, or exit."
    },
    {
        "role_id": "AT-ATT-007",
        "role": "Governance / Audit Owner",
        "attests_to": "The trust decision is defensible using controls, evidence, owner signoffs, monitoring, and replay package.",
        "evidence_reviewed": "Assurance case, audit dossier, control effectiveness test, incident register, signoff ledger.",
        "cannot_attest_if": "Evidence package, control test, open exception, or audit replay is incomplete."
    },
    {
        "role_id": "AT-ATT-008",
        "role": "Executive Sponsor",
        "attests_to": "Leadership understands the AI agent trust posture, residual risk, exceptions, and operating restrictions.",
        "evidence_reviewed": "Executive dashboard, board risk attestation, open exceptions, trust score, release decision.",
        "cannot_attest_if": "Critical exceptions are unowned, evidence is weak, or operational restrictions are unclear."
    }
]


AGENTTRUST_SIGNOFF_LEDGER = [
    {
        "signoff_id": "AT-SGN-001",
        "agent": "ServiceNow CMDB Ownership Recommendation Agent™",
        "signoff_owner": "LCM / CMDB Owner",
        "attestation": "Recommendation-only use is acceptable when source CI evidence and human review are captured.",
        "status": "Conditional Signoff",
        "restriction": "No production CI update, LCM assignment, lifecycle-state change, or hidden approval."
    },
    {
        "signoff_id": "AT-SGN-002",
        "agent": "MyAccess / CyberArk Routing Agent™",
        "signoff_owner": "Cybersecurity / CyberArk Owner",
        "attestation": "Access-routing assistance is acceptable only when cyber review is triggered for privileged context.",
        "status": "Cyber-Gated",
        "restriction": "No access approval, entitlement activation, CyberArk trigger, credential action, or privileged execution."
    },
    {
        "signoff_id": "AT-SGN-003",
        "agent": "GxP Inspection Evidence Agent™",
        "signoff_owner": "QA / Validation Owner",
        "attestation": "Regulated evidence preparation is acceptable only with QA / validation review before reliance.",
        "status": "QA-Governed",
        "restriction": "No QA conclusion, validation approval, deviation closure, batch release, or inspection certification."
    },
    {
        "signoff_id": "AT-SGN-004",
        "agent": "Cutover Readiness Summary Agent™",
        "signoff_owner": "Cutover / Transition Owner",
        "attestation": "Readiness summaries may support discussion when blockers, rollback gaps, and evidence gaps are visible.",
        "status": "Restricted Advisory",
        "restriction": "No go-live approval, no risk acceptance, no validation override, no cutover authorization."
    },
    {
        "signoff_id": "AT-SGN-005",
        "agent": "Vendor Document Intelligence AI",
        "signoff_owner": "Document / Vendor / Quality Owner",
        "attestation": "Document extraction may be used only inside approved data boundary with evidence trace and human review.",
        "status": "Vendor Conditional",
        "restriction": "No vendor training use, no uncontrolled retention, no unsupported evidence conclusion."
    }
]


AGENTTRUST_ATTESTATION_REQUIREMENTS = [
    {
        "requirement_id": "AT-REQ-001",
        "requirement": "Trust decision is clearly stated.",
        "evidence": "Approved, conditional, restricted, human-gated, cyber-gated, QA-governed, blocked, or quarantined decision.",
        "owner": "Governance Owner"
    },
    {
        "requirement_id": "AT-REQ-002",
        "requirement": "Accountable owner is named.",
        "evidence": "Business, technical, QA, cyber, privacy, vendor, audit, or executive owner record.",
        "owner": "Governance Owner"
    },
    {
        "requirement_id": "AT-REQ-003",
        "requirement": "Evidence reviewed is listed.",
        "evidence": "Agent passport, AgentBOM, trust contract, release packet, audit dossier, control test, incident register.",
        "owner": "Audit / Evidence Owner"
    },
    {
        "requirement_id": "AT-REQ-004",
        "requirement": "Restrictions are explicit.",
        "evidence": "Prohibited actions, operating license limits, cyber/GxP restrictions, human-gated requirements.",
        "owner": "Risk Owner"
    },
    {
        "requirement_id": "AT-REQ-005",
        "requirement": "Exceptions are declared.",
        "evidence": "Open risk acceptances, expired exceptions, evidence gaps, control deficiencies, unresolved incidents.",
        "owner": "Risk / Control Owner"
    },
    {
        "requirement_id": "AT-REQ-006",
        "requirement": "Residual risk is accepted or rejected.",
        "evidence": "Risk acceptance record, conditions, expiry, owner, mitigation, and monitoring requirement.",
        "owner": "Risk Owner / Executive Sponsor"
    },
    {
        "requirement_id": "AT-REQ-007",
        "requirement": "Retest and monitoring are defined.",
        "evidence": "Continuous monitoring cadence, control testing plan, drift watch, incident response route.",
        "owner": "Control Owner"
    },
    {
        "requirement_id": "AT-REQ-008",
        "requirement": "Signoff is timestamped and reviewable.",
        "evidence": "Signoff ID, owner, date, scope, evidence references, restrictions, next review date.",
        "owner": "Governance / Audit Owner"
    }
]


AGENTTRUST_SIGNOFF_EXCEPTIONS = [
    {
        "exception_id": "AT-EXC-001",
        "exception": "Evidence package incomplete but advisory use requested.",
        "risk": "Output may be used beyond evidence strength.",
        "required_condition": "Label as advisory only and assign evidence closure owner.",
        "expiry": "30 days"
    },
    {
        "exception_id": "AT-EXC-002",
        "exception": "Cyber review pending for access-impacting recommendation.",
        "risk": "Access governance exposure.",
        "required_condition": "Block access approval and route to cybersecurity owner.",
        "expiry": "Before operational reliance"
    },
    {
        "exception_id": "AT-EXC-003",
        "exception": "QA review pending for regulated evidence summary.",
        "risk": "GxP or inspection defensibility risk.",
        "required_condition": "Mark output non-authoritative until QA / validation signoff.",
        "expiry": "Before regulated reliance"
    },
    {
        "exception_id": "AT-EXC-004",
        "exception": "Control deficiency open after effectiveness testing.",
        "risk": "Leadership may rely on ineffective control.",
        "required_condition": "Track remediation, retest, and owner signoff before full approval.",
        "expiry": "Before production promotion"
    },
    {
        "exception_id": "AT-EXC-005",
        "exception": "Vendor AI contract addendum not complete.",
        "risk": "Data, audit, retention, deletion, or exit rights may be weak.",
        "required_condition": "Restrict to synthetic or non-sensitive data until contract control is complete.",
        "expiry": "Before enterprise data use"
    }
]


def agenttrust_attestation_role_rows():
    rows = ""

    for item in AGENTTRUST_ATTESTATION_ROLES:
        rows += f"""
        <tr>
            <td><strong>{item["role_id"]}</strong></td>
            <td><span class="badge blue">{item["role"]}</span></td>
            <td>{item["attests_to"]}</td>
            <td>{item["evidence_reviewed"]}</td>
            <td><span class="badge red">{item["cannot_attest_if"]}</span></td>
        </tr>
        """

    return rows


def agenttrust_signoff_ledger_rows():
    rows = ""

    for item in AGENTTRUST_SIGNOFF_LEDGER:
        badge = "yellow"
        if "Cyber" in item["status"] or "QA" in item["status"]:
            badge = "red"
        elif "Restricted" in item["status"] or "Vendor" in item["status"]:
            badge = "orange"

        rows += f"""
        <tr>
            <td><strong>{item["signoff_id"]}</strong></td>
            <td>{item["agent"]}</td>
            <td>{item["signoff_owner"]}</td>
            <td>{item["attestation"]}</td>
            <td><span class="badge {badge}">{item["status"]}</span></td>
            <td>{item["restriction"]}</td>
        </tr>
        """

    return rows


def agenttrust_attestation_requirement_rows():
    rows = ""

    for item in AGENTTRUST_ATTESTATION_REQUIREMENTS:
        rows += f"""
        <tr>
            <td><strong>{item["requirement_id"]}</strong></td>
            <td>{item["requirement"]}</td>
            <td>{item["evidence"]}</td>
            <td>{item["owner"]}</td>
        </tr>
        """

    return rows


def agenttrust_signoff_exception_rows():
    rows = ""

    for item in AGENTTRUST_SIGNOFF_EXCEPTIONS:
        rows += f"""
        <tr>
            <td><strong>{item["exception_id"]}</strong></td>
            <td>{item["exception"]}</td>
            <td><span class="badge red">{item["risk"]}</span></td>
            <td>{item["required_condition"]}</td>
            <td><span class="badge orange">{item["expiry"]}</span></td>
        </tr>
        """

    return rows


def agenttrust_attestation_decision(owner, evidence, controls, exceptions, cyber, gxp, privacy, vendor, incident, executive):
    controls_list = [owner, evidence, controls, exceptions, cyber, gxp, privacy, vendor, incident, executive]
    score = int((sum(1 for item in controls_list if item == "yes") / len(controls_list)) * 100)

    if owner != "yes":
        return score, "Cannot Attest", "red", "No accountable owner is assigned."
    if evidence != "yes":
        return score, "Cannot Attest — Evidence Gap", "red", "Evidence reviewed is incomplete or not traceable."
    if controls != "yes":
        return score, "Cannot Attest — Control Gap", "red", "Required controls are not tested or not operating effectively."
    if cyber != "yes":
        return score, "Cyber Attestation Required", "red", "Cyber, access, CyberArk, PSM, admin, or privileged impact requires cybersecurity signoff."
    if gxp != "yes":
        return score, "QA Attestation Required", "red", "GxP, QA, validation, release, deviation, CAPA, or inspection impact requires QA / validation signoff."
    if privacy != "yes":
        return score, "Privacy Attestation Required", "orange", "Privacy, personal data, sensitive data, or transfer boundary requires privacy/data owner signoff."
    if vendor != "yes":
        return score, "Vendor Attestation Required", "orange", "Vendor AI boundary, contract, data use, deletion, or exit control is incomplete."
    if incident != "yes":
        return score, "Incident Closure Required", "red", "Open AI incidents must be contained, remediated, retested, and closed before full attestation."
    if exceptions != "yes":
        return score, "Conditional Attestation", "yellow", "Open exceptions must be declared, owned, time-bound, and monitored."
    if executive != "yes":
        return score, "Pending Executive Signoff", "yellow", "Executive sponsor has not acknowledged trust posture and residual risk."
    if score == 100:
        return score, "Attested and Defensible", "green", "Trust decision is owner-signed, evidence-backed, exception-declared, and executive-reviewable."
    return score, "Conditional Attestation", "yellow", "Attestation may proceed only with restrictions and tracked remediation."


try:
    AGENTTRUST_EXPECTED_ROUTES.extend([
        "/agenttrust/executive-attestation-center",
        "/agenttrust/accountability-signoff-ledger",
        "/agenttrust/ai-reliance-attestation",
        "/agenttrust/board-risk-attestation",
        "/agenttrust/control-owner-certification",
        "/agenttrust/signoff-exception-register",
        "/agenttrust/attestation-package-builder",
        "/agenttrust/attestation-simulator",
        "/agenttrust/attestation-json"
    ])
except Exception:
    pass


@app.route("/agenttrust/executive-attestation-center")
@app.route("/agenttrust/attestation-center")
@app.route("/agenttrust/ai-attestation-center")
def agenttrust_executive_attestation_center():
    rows = agenttrust_attestation_role_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Attestation Center</div><div class="value" style="color:var(--green);">Active</div><div class="note">Owner signoff model installed.</div></div>
        <div class="metric"><div class="label">Attestation Roles</div><div class="value" style="color:var(--blue);">8</div><div class="note">Business, technical, cyber, QA, privacy, vendor, audit, executive.</div></div>
        <div class="metric"><div class="label">Evidence</div><div class="value" style="color:var(--yellow);">Required</div><div class="note">No signoff without reviewed evidence.</div></div>
        <div class="metric"><div class="label">Exceptions</div><div class="value" style="color:var(--orange);">Declared</div><div class="note">Open risks must be visible and owned.</div></div>
        <div class="metric"><div class="label">Critical Routes</div><div class="value" style="color:var(--red);">Cyber / QA</div><div class="note">Privileged and regulated reliance require owner signoff.</div></div>
        <div class="metric"><div class="label">Executive Defense</div><div class="value" style="color:var(--purple);">Supported</div><div class="note">Leadership can see evidence and residual risk.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Executive Attestation Center</h2>
        <div class="answer">
            <strong>Purpose:</strong> convert AI agent trust into accountable signoff.
            AgentTrust™ requires named owners to attest what they reviewed, what they accept, what is restricted,
            what exceptions remain, and what evidence supports the trust decision.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Role ID</th>
                    <th>Attestation Role</th>
                    <th>Attests To</th>
                    <th>Evidence Reviewed</th>
                    <th>Cannot Attest If</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Attestation Rule</h2>
        <div class="answer">
            Trust is not complete until the accountable owner signs what was reviewed, what is allowed,
            what remains restricted, and what risk is accepted or rejected.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Executive Attestation Center",
        "Executive attestation center for AI agent trust owner signoff, evidence review, exception declaration, residual risk, and leadership defense.",
        body
    )


@app.route("/agenttrust/accountability-signoff-ledger")
@app.route("/agenttrust/signoff-ledger")
@app.route("/agenttrust/ai-signoff-ledger")
def agenttrust_accountability_signoff_ledger():
    rows = agenttrust_signoff_ledger_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Accountability Signoff Ledger</h2>
        <p>
            The ledger records who accepted which AI agent trust condition, with what restriction, and under which evidence basis.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Signoff ID</th>
                    <th>Agent</th>
                    <th>Signoff Owner</th>
                    <th>Attestation</th>
                    <th>Status</th>
                    <th>Restriction</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Ledger Rule</h2>
        <div class="answer">
            The signoff ledger prevents invisible accountability.
            Every AI reliance decision should show the owner, evidence basis, restriction, status, and review condition.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Accountability Signoff Ledger",
        "Signoff ledger for AI agent accountability, owner attestation, trust status, evidence basis, and operating restrictions.",
        body
    )


@app.route("/agenttrust/ai-reliance-attestation")
@app.route("/agenttrust/reliance-attestation")
@app.route("/agenttrust/agent-reliance-attestation")
def agenttrust_ai_reliance_attestation():
    rows = agenttrust_attestation_requirement_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ AI Reliance Attestation</h2>
        <p>
            AI reliance attestation defines the minimum conditions before a team may rely on an AI agent output.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Requirement ID</th>
                    <th>Requirement</th>
                    <th>Evidence</th>
                    <th>Owner</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Reliance Statement</h2>
        <div class="answer">
            Before relying on AI output, the owner must confirm that the agent is known, licensed, bounded,
            authorized, evidenced, human-governed, monitored, and subject to clear restrictions.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ AI Reliance Attestation",
        "AI reliance attestation requirements for trust decision, owner, evidence reviewed, restrictions, exceptions, residual risk, monitoring, and timestamped signoff.",
        body
    )


@app.route("/agenttrust/board-risk-attestation")
@app.route("/agenttrust/executive-risk-attestation")
@app.route("/agenttrust/leadership-risk-attestation")
def agenttrust_board_risk_attestation():
    body = """
    <section class="section">
        <h2>AgentTrust™ Board Risk Attestation</h2>
        <p>
            This page translates AI agent operational trust into board-level risk language.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Board Concern</th>
                    <th>Attestation Evidence</th>
                    <th>Risk Position</th>
                    <th>Leadership Statement</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Can AI act without accountability?</td><td>Agent Register, owner map, signoff ledger.</td><td><span class="badge green">Controlled if owner exists</span></td><td>AI agent accountability is assigned and reviewable.</td></tr>
                <tr><td>Can AI approve access or privileged actions?</td><td>Cyber route, access prohibition, CyberArk / PSM controls.</td><td><span class="badge red">Cyber-gated</span></td><td>AI cannot approve access or privileged execution by default.</td></tr>
                <tr><td>Can AI affect regulated decisions?</td><td>GxP route, QA signoff, regulated conclusion block.</td><td><span class="badge red">QA-governed</span></td><td>AI cannot make regulated conclusions without QA / validation review.</td></tr>
                <tr><td>Can AI evidence be audited?</td><td>Evidence ledger, audit dossier, decision replay.</td><td><span class="badge yellow">Evidence-dependent</span></td><td>Reliance is defensible only when evidence package is complete.</td></tr>
                <tr><td>Can AI drift after release?</td><td>Monitoring center, drift console, change gate.</td><td><span class="badge orange">Continuously monitored</span></td><td>Trust is refreshed when model, prompt, tool, data, or owner changes.</td></tr>
                <tr><td>Can vendor AI create hidden exposure?</td><td>Vendor register, data boundary, contract controls, exit plan.</td><td><span class="badge orange">Conditional</span></td><td>Vendor AI is restricted unless contract, evidence, and exit controls are complete.</td></tr>
                <tr><td>Are controls actually working?</td><td>Control effectiveness testing, deficiencies, retest, owner signoff.</td><td><span class="badge green">Testable</span></td><td>Controls are not only documented; they are tested and signed off.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Board Attestation Rule</h2>
        <div class="answer">
            Board assurance should not say “AI is governed” in general terms.
            It should show which risks are controlled, which are conditional, which are blocked, and which owners have signed off.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Board Risk Attestation",
        "Board risk attestation for AI accountability, access control, regulated decisions, audit evidence, drift, vendor AI, and control effectiveness.",
        body
    )


@app.route("/agenttrust/control-owner-certification")
@app.route("/agenttrust/control-owner-attestation")
@app.route("/agenttrust/owner-certification")
def agenttrust_control_owner_certification():
    body = """
    <section class="section">
        <h2>AgentTrust™ Control Owner Certification</h2>
        <p>
            Control owner certification confirms that the assigned owner has reviewed evidence and accepts the control conclusion.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Control Area</th>
                    <th>Certification Statement</th>
                    <th>Required Evidence</th>
                    <th>Cannot Certify If</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Identity Control</td><td>All active agents are known, owned, and lifecycle-classified.</td><td>Agent Register, passport, owner map.</td><td><span class="badge red">Owner or lifecycle missing</span></td></tr>
                <tr><td>Authority Control</td><td>High-impact actions cannot execute without pre-action authority.</td><td>Authority gate, policy decision, trust token.</td><td><span class="badge red">Tool call lacks authority ID</span></td></tr>
                <tr><td>Evidence Control</td><td>AI actions can be reconstructed from identity to outcome.</td><td>Evidence ledger, tool-call record, replay package.</td><td><span class="badge red">Replay evidence incomplete</span></td></tr>
                <tr><td>Cyber Control</td><td>Access and privileged impacts route to cybersecurity owner.</td><td>Cyber route, access decision, privileged impact record.</td><td><span class="badge red">AI can approve access</span></td></tr>
                <tr><td>GxP Control</td><td>Regulated impacts route to QA / validation owner.</td><td>GxP screen, QA decision, regulated evidence record.</td><td><span class="badge red">AI can make regulated conclusion</span></td></tr>
                <tr><td>Monitoring Control</td><td>Drift, exception, breach, and degradation signals are reviewed.</td><td>Monitoring register, drift alerts, exception watch.</td><td><span class="badge orange">Open alerts unreviewed</span></td></tr>
                <tr><td>Incident Control</td><td>AI incidents are contained, routed, remediated, retested, and closed with evidence.</td><td>Incident record, root cause, CAPA/deviation route, closure proof.</td><td><span class="badge red">Incident open or untested</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Certification Rule</h2>
        <div class="answer">
            Control owner certification should be evidence-based.
            A control owner certifies what they reviewed, what passed, what failed, and what remains restricted.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Control Owner Certification",
        "Control owner certification for AI identity, authority, evidence, cyber, GxP, monitoring, and incident controls.",
        body
    )


@app.route("/agenttrust/signoff-exception-register")
@app.route("/agenttrust/attestation-exception-register")
@app.route("/agenttrust/signoff-exceptions")
def agenttrust_signoff_exception_register():
    rows = agenttrust_signoff_exception_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Signoff Exception Register</h2>
        <p>
            This register captures exceptions that prevent full attestation or require conditional signoff.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Exception ID</th>
                    <th>Exception</th>
                    <th>Risk</th>
                    <th>Required Condition</th>
                    <th>Expiry</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Exception Rule</h2>
        <div class="answer">
            Exceptions must be declared before attestation.
            Hidden exceptions turn a signoff into a weak governance artifact.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Signoff Exception Register",
        "Signoff exception register for AI reliance evidence gaps, cyber review gaps, QA review gaps, control deficiencies, and vendor contract gaps.",
        body
    )


@app.route("/agenttrust/attestation-package-builder")
@app.route("/agenttrust/signoff-package-builder")
@app.route("/agenttrust/executive-attestation-package")
def agenttrust_attestation_package_builder():
    req_rows = agenttrust_attestation_requirement_rows()
    signoff_rows = agenttrust_signoff_ledger_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Attestation Package Builder</h2>
        <p>
            The package builder assembles the minimum evidence required for a defensible AI trust signoff.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Requirement ID</th>
                    <th>Requirement</th>
                    <th>Evidence</th>
                    <th>Owner</th>
                </tr>
            </thead>
            <tbody>
                {req_rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Current Sample Signoff Ledger</h2>
        <table>
            <thead>
                <tr>
                    <th>Signoff ID</th>
                    <th>Agent</th>
                    <th>Owner</th>
                    <th>Attestation</th>
                    <th>Status</th>
                    <th>Restriction</th>
                </tr>
            </thead>
            <tbody>
                {signoff_rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Package Rule</h2>
        <div class="answer">
            A complete attestation package includes the decision, owner, evidence, restrictions, exceptions,
            residual risk, monitoring plan, and timestamped owner signoff.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Attestation Package Builder",
        "Attestation package builder for AI trust decision, owner signoff, evidence reviewed, restrictions, exceptions, residual risk, monitoring, and reviewable signoff.",
        body
    )


@app.route("/agenttrust/attestation-simulator", methods=["GET", "POST"])
@app.route("/agenttrust/signoff-simulator", methods=["GET", "POST"])
@app.route("/agenttrust/ai-attestation-simulator", methods=["GET", "POST"])
def agenttrust_attestation_simulator():
    from flask import request

    owner = request.form.get("owner", "yes")
    evidence = request.form.get("evidence", "yes")
    controls = request.form.get("controls", "yes")
    exceptions = request.form.get("exceptions", "yes")
    cyber = request.form.get("cyber", "yes")
    gxp = request.form.get("gxp", "yes")
    privacy = request.form.get("privacy", "yes")
    vendor = request.form.get("vendor", "yes")
    incident = request.form.get("incident", "yes")
    executive = request.form.get("executive", "yes")

    score, decision, badge, reason = agenttrust_attestation_decision(
        owner, evidence, controls, exceptions, cyber, gxp, privacy, vendor, incident, executive
    )

    def selected(value, expected):
        return "selected" if value == expected else ""

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Attestation Score</div><div class="value" style="color:var(--green);">{score}%</div><div class="note">Calculated from signoff readiness.</div></div>
        <div class="metric"><div class="label">Attestation Decision</div><div class="value" style="color:var(--yellow);">{decision}</div><div class="note">{reason}</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Attestation Simulator</h2>
        <p>
            Simulate whether an AI trust decision is ready for owner, governance, and executive attestation.
        </p>

        <form method="POST" action="/agenttrust/attestation-simulator">
            <table>
                <tbody>
                    <tr><td><strong>Accountable Owner Assigned?</strong></td><td><select name="owner" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(owner, "yes")}>Yes</option><option value="no" {selected(owner, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Evidence Reviewed and Traceable?</strong></td><td><select name="evidence" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(evidence, "yes")}>Yes</option><option value="no" {selected(evidence, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Controls Tested / Effective?</strong></td><td><select name="controls" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(controls, "yes")}>Yes</option><option value="no" {selected(controls, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Exceptions Declared and Owned?</strong></td><td><select name="exceptions" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(exceptions, "yes")}>Yes</option><option value="no" {selected(exceptions, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Cyber / Access Signoff Complete?</strong></td><td><select name="cyber" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(cyber, "yes")}>Yes</option><option value="no" {selected(cyber, "no")}>No</option></select></td></tr>
                    <tr><td><strong>GxP / QA Signoff Complete?</strong></td><td><select name="gxp" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(gxp, "yes")}>Yes</option><option value="no" {selected(gxp, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Privacy / Data Signoff Complete?</strong></td><td><select name="privacy" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(privacy, "yes")}>Yes</option><option value="no" {selected(privacy, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Vendor AI Signoff Complete?</strong></td><td><select name="vendor" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(vendor, "yes")}>Yes</option><option value="no" {selected(vendor, "no")}>No</option></select></td></tr>
                    <tr><td><strong>AI Incidents Closed?</strong></td><td><select name="incident" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(incident, "yes")}>Yes</option><option value="no" {selected(incident, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Executive Sponsor Acknowledged?</strong></td><td><select name="executive" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(executive, "yes")}>Yes</option><option value="no" {selected(executive, "no")}>No</option></select></td></tr>
                </tbody>
            </table>

            <button type="submit" style="margin-top:16px;padding:12px 18px;border-radius:12px;border:0;background:#2563eb;color:white;font-weight:800;">Run Attestation Check</button>
        </form>
    </section>

    <section class="section">
        <h2>Attestation Decision</h2>
        <div class="answer">
            <strong>Score:</strong> {score}%<br>
            <strong>Decision:</strong> <span class="badge {badge}">{decision}</span><br>
            <strong>Reason:</strong> {reason}
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Attestation Simulator",
        "Simulator for AI trust attestation across owner, evidence, control effectiveness, exceptions, cyber, GxP, privacy, vendor, incidents, and executive signoff.",
        body
    )


@app.route("/agenttrust/attestation-json")
@app.route("/agenttrust/executive-attestation-json")
@app.route("/agenttrust/signoff-ledger-json")
def agenttrust_attestation_json():
    from flask import jsonify

    return jsonify({
        "module": "AgentTrust™",
        "capability": "Executive Attestation Center + Accountability Signoff Ledger",
        "primary_question": "Who has signed off that this AI agent trust decision is defensible?",
        "attestation_roles": AGENTTRUST_ATTESTATION_ROLES,
        "signoff_ledger": AGENTTRUST_SIGNOFF_LEDGER,
        "attestation_requirements": AGENTTRUST_ATTESTATION_REQUIREMENTS,
        "signoff_exceptions": AGENTTRUST_SIGNOFF_EXCEPTIONS,
        "minimum_attestation_conditions": [
            "Trust decision clearly stated",
            "Accountable owner assigned",
            "Evidence reviewed and traceable",
            "Controls tested and operating effectively",
            "Restrictions explicitly stated",
            "Exceptions declared, owned, and time-bound",
            "Cyber signoff completed where access or privileged impact exists",
            "QA signoff completed where GxP or regulated impact exists",
            "Privacy / data signoff completed where sensitive data exists",
            "Vendor signoff completed where third-party AI is involved",
            "Open AI incidents closed or explicitly accepted",
            "Executive sponsor acknowledges residual risk and operating restrictions"
        ],
        "default_decision": "Do not treat AI agent reliance as fully attested until accountable owners sign evidence, restrictions, exceptions, residual risk, monitoring, and review conditions"
    })

# ============================================================
# END AGENTTRUST_EXECUTIVE_ATTESTATION_CENTER_V1_ACTIVE
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

print("AgentTrust Executive Attestation Center installed.")
print(f"Inserted before: {target_found}")
