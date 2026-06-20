from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_PRIVACY_BOUNDARY_DPIA_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust Privacy Boundary Center already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base module not found. Install AgentTrust module first.")

nav_old = '<a href="/agenttrust/third-party-ai-governance" class="secondary">Vendor AI</a>'
nav_new = '''<a href="/agenttrust/third-party-ai-governance" class="secondary">Vendor AI</a>
                    <a href="/agenttrust/privacy-boundary-center" class="secondary">Privacy Boundary</a>
                    <a href="/agenttrust/ai-data-protection-impact-assessment" class="dark">AI DPIA</a>
                    <a href="/agenttrust/data-classification-router" class="dark">Data Router</a>
                    <a href="/agenttrust/privacy-risk-simulator" class="dark">Privacy Risk</a>'''

if nav_old in text and "/agenttrust/privacy-boundary-center" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# AGENTTRUST_PRIVACY_BOUNDARY_DPIA_V1_ACTIVE
# AgentTrust™ Privacy Boundary Center, AI Data Protection Impact Assessment,
# Data Classification Router, PII / Sensitive / Regulated Data Screen,
# Data Minimization Gate, Retention and Deletion Control,
# Cross-Border Data Transfer Screen, Privacy Risk Simulator,
# and Privacy Boundary JSON Export
# ============================================================

AGENTTRUST_DATA_CLASSIFICATIONS = [
    {
        "classification_id": "AT-DATA-001",
        "classification": "Public / Non-Sensitive Data",
        "examples": "Public documentation, approved public knowledge, non-sensitive published content.",
        "default_position": "Allowed within approved use case.",
        "required_owner": "Business Owner",
        "control": "Use case record and source traceability."
    },
    {
        "classification_id": "AT-DATA-002",
        "classification": "Internal Operational Metadata",
        "examples": "ServiceNow ticket metadata, CI names, support group fields, lifecycle state, non-sensitive workflow status.",
        "default_position": "Conditional.",
        "required_owner": "System / Process Owner",
        "control": "Approved boundary, evidence capture, and minimum necessary data."
    },
    {
        "classification_id": "AT-DATA-003",
        "classification": "Confidential Enterprise Data",
        "examples": "Architecture diagrams, internal plans, cutover details, system inventories, security-sensitive operational context.",
        "default_position": "Restricted.",
        "required_owner": "Data Owner / Security Owner",
        "control": "Data boundary, access control, retention rule, and evidence trace."
    },
    {
        "classification_id": "AT-DATA-004",
        "classification": "Personal Data / PII",
        "examples": "Names, emails, employee identifiers, access request details, user account information.",
        "default_position": "Privacy review required.",
        "required_owner": "Privacy / Legal / Data Owner",
        "control": "Privacy screen, minimization, retention, consent or lawful basis where applicable."
    },
    {
        "classification_id": "AT-DATA-005",
        "classification": "Access / Cybersecurity Data",
        "examples": "Entitlements, CyberArk / PSM context, privileged route, admin activity, security logs.",
        "default_position": "Cyber-gated.",
        "required_owner": "Cybersecurity / Access Owner",
        "control": "Cyber review, no autonomous access approval, privileged-data restrictions."
    },
    {
        "classification_id": "AT-DATA-006",
        "classification": "GxP / Regulated Quality Data",
        "examples": "Validation evidence, QA records, QC evidence, batch/release context, deviation, CAPA, inspection material.",
        "default_position": "QA-governed only.",
        "required_owner": "QA / Validation Owner",
        "control": "GxP review, regulated conclusion block, QA signoff before reliance."
    },
    {
        "classification_id": "AT-DATA-007",
        "classification": "Sensitive Personal or Health-Related Data",
        "examples": "Health-related, patient-related, clinical, safety, or sensitive HR context.",
        "default_position": "Blocked unless explicitly approved.",
        "required_owner": "Privacy / Legal / Compliance / Data Owner",
        "control": "Formal privacy impact assessment, strict minimization, retention, and audit evidence."
    },
    {
        "classification_id": "AT-DATA-008",
        "classification": "Vendor / Third-Party Processed Data",
        "examples": "Data sent to external AI tools, vendor copilots, document intelligence tools, external analytics.",
        "default_position": "Third-party assurance required.",
        "required_owner": "Vendor Owner / Data Owner / Security Owner",
        "control": "Vendor AI governance, data sharing boundary, contract controls, deletion and exit rights."
    }
]


AGENTTRUST_PRIVACY_ASSESSMENT_CONTROLS = [
    {
        "control_id": "AT-PRV-001",
        "control": "Purpose Limitation",
        "question": "Is the AI agent use case specific, approved, and limited?",
        "evidence": "Use case record, owner approval, approved purpose statement.",
        "failure_response": "Do not process data."
    },
    {
        "control_id": "AT-PRV-002",
        "control": "Data Minimization",
        "question": "Is the agent using only the minimum data needed?",
        "evidence": "Field list, source list, excluded data categories, minimization rationale.",
        "failure_response": "Reduce data scope before use."
    },
    {
        "control_id": "AT-PRV-003",
        "control": "Sensitive Data Screen",
        "question": "Does the input include personal, sensitive, access, cyber, or regulated data?",
        "evidence": "Data classification record and risk routing decision.",
        "failure_response": "Route to privacy, cyber, QA, or legal owner."
    },
    {
        "control_id": "AT-PRV-004",
        "control": "Retention and Deletion",
        "question": "How long are prompts, outputs, logs, tool calls, and evidence retained?",
        "evidence": "Retention schedule, deletion rule, evidence archive location.",
        "failure_response": "Restrict or block processing."
    },
    {
        "control_id": "AT-PRV-005",
        "control": "Training Use Restriction",
        "question": "Can input or output data be used to train, fine-tune, or improve an AI model?",
        "evidence": "Model training status, vendor terms, platform configuration.",
        "failure_response": "Block vendor or platform use until clarified."
    },
    {
        "control_id": "AT-PRV-006",
        "control": "Cross-Border / External Transfer",
        "question": "Will data leave the approved environment, region, tenant, system, or vendor boundary?",
        "evidence": "Hosting region, transfer path, vendor boundary, data residency review.",
        "failure_response": "Run transfer review before processing."
    },
    {
        "control_id": "AT-PRV-007",
        "control": "Access-to-Data Control",
        "question": "Can the AI agent access data beyond the user, workflow, or approved system boundary?",
        "evidence": "Access model, service account, tool scope, role mapping.",
        "failure_response": "Restrict tool, access route, or agent license."
    },
    {
        "control_id": "AT-PRV-008",
        "control": "Privacy Evidence Replay",
        "question": "Can the data use be reconstructed later?",
        "evidence": "Prompt, source, data category, purpose, owner, output, reviewer, deletion status.",
        "failure_response": "Do not rely on output."
    }
]


AGENTTRUST_RETENTION_RULES = [
    {
        "data_type": "Synthetic test data",
        "retention": "Keep only as needed for test evidence.",
        "deletion_rule": "Delete or archive after sandbox evidence is accepted.",
        "owner": "Sandbox / Test Owner"
    },
    {
        "data_type": "Operational metadata",
        "retention": "Follow source-system and evidence-retention policy.",
        "deletion_rule": "Retain evidence reference; avoid unnecessary prompt duplication.",
        "owner": "System Owner"
    },
    {
        "data_type": "Personal data / PII",
        "retention": "Minimum necessary retention only.",
        "deletion_rule": "Delete when purpose is complete unless evidence retention is required.",
        "owner": "Privacy / Data Owner"
    },
    {
        "data_type": "Cyber / access data",
        "retention": "Retain according to security logging and investigation requirements.",
        "deletion_rule": "Do not expose beyond approved cyber/security audience.",
        "owner": "Cybersecurity Owner"
    },
    {
        "data_type": "GxP / QA evidence",
        "retention": "Retain according to quality, validation, inspection, and record-retention requirements.",
        "deletion_rule": "Do not delete regulated evidence without QA-approved retention decision.",
        "owner": "QA / Validation Owner"
    },
    {
        "data_type": "Vendor AI prompts and outputs",
        "retention": "Must match vendor contract, data boundary, and approved use case.",
        "deletion_rule": "Deletion, export, and offboarding must be contractually supported.",
        "owner": "Vendor / Data Owner"
    }
]


def agenttrust_data_classification_rows():
    rows = ""

    for item in AGENTTRUST_DATA_CLASSIFICATIONS:
        badge = "blue"
        if "Blocked" in item["default_position"] or "QA-governed" in item["default_position"] or "Cyber-gated" in item["default_position"]:
            badge = "red"
        elif "Restricted" in item["default_position"]:
            badge = "orange"
        elif "Privacy" in item["default_position"] or "Third-party" in item["default_position"]:
            badge = "yellow"
        elif "Conditional" in item["default_position"]:
            badge = "orange"

        rows += f"""
        <tr>
            <td><strong>{item["classification_id"]}</strong></td>
            <td>{item["classification"]}</td>
            <td>{item["examples"]}</td>
            <td><span class="badge {badge}">{item["default_position"]}</span></td>
            <td>{item["required_owner"]}</td>
            <td>{item["control"]}</td>
        </tr>
        """

    return rows


def agenttrust_privacy_control_rows():
    rows = ""

    for item in AGENTTRUST_PRIVACY_ASSESSMENT_CONTROLS:
        rows += f"""
        <tr>
            <td><strong>{item["control_id"]}</strong></td>
            <td><span class="badge blue">{item["control"]}</span></td>
            <td>{item["question"]}</td>
            <td>{item["evidence"]}</td>
            <td><span class="badge red">{item["failure_response"]}</span></td>
        </tr>
        """

    return rows


def agenttrust_retention_rule_rows():
    rows = ""

    for item in AGENTTRUST_RETENTION_RULES:
        rows += f"""
        <tr>
            <td><strong>{item["data_type"]}</strong></td>
            <td>{item["retention"]}</td>
            <td>{item["deletion_rule"]}</td>
            <td>{item["owner"]}</td>
        </tr>
        """

    return rows


def agenttrust_privacy_risk_decision(purpose, minimization, sensitive, retention, training, transfer, access, replay):
    controls = [purpose, minimization, retention, training, transfer, access, replay]
    score = int((sum(1 for item in controls if item == "yes") / len(controls)) * 100)

    if purpose != "yes":
        return score, "Block Processing", "red", "No approved purpose exists for the AI agent data use."
    if minimization != "yes":
        return score, "Reduce Data Scope", "red", "Data minimization is not complete."
    if sensitive == "yes":
        return score, "Privacy / Legal / QA / Cyber Review Required", "red", "Sensitive, personal, regulated, access, or cybersecurity data requires owner review before use."
    if retention != "yes":
        return score, "Retention Review Required", "orange", "Retention and deletion rules are not defined."
    if training != "yes":
        return score, "Block Model Training Use", "red", "It is unclear whether data may be used for model training or improvement."
    if transfer != "yes":
        return score, "Transfer Review Required", "orange", "External, cross-border, vendor, or tenant transfer boundary is not approved."
    if access != "yes":
        return score, "Restrict Agent Access", "red", "The AI agent may access data beyond the approved boundary."
    if replay != "yes":
        return score, "Restrict Reliance", "orange", "Privacy evidence cannot be replayed."
    if score == 100:
        return score, "Approved Within Privacy Boundary", "green", "Data use is purpose-bound, minimized, retained correctly, transfer-reviewed, access-controlled, and replayable."
    return score, "Conditional Use", "yellow", "Data use may proceed only with restrictions and documented remediation."


try:
    AGENTTRUST_EXPECTED_ROUTES.extend([
        "/agenttrust/privacy-boundary-center",
        "/agenttrust/ai-data-protection-impact-assessment",
        "/agenttrust/data-classification-router",
        "/agenttrust/pii-regulated-data-screen",
        "/agenttrust/data-minimization-gate",
        "/agenttrust/retention-deletion-control",
        "/agenttrust/cross-border-data-transfer-screen",
        "/agenttrust/privacy-risk-simulator",
        "/agenttrust/privacy-boundary-json"
    ])
except Exception:
    pass


@app.route("/agenttrust/privacy-boundary-center")
@app.route("/agenttrust/privacy-boundary")
@app.route("/agenttrust/ai-privacy-boundary")
def agenttrust_privacy_boundary_center():
    rows = agenttrust_data_classification_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Privacy Boundary</div><div class="value" style="color:var(--green);">Active</div><div class="note">AI data boundary controls installed.</div></div>
        <div class="metric"><div class="label">Data Classes</div><div class="value" style="color:var(--blue);">8</div><div class="note">Public, internal, confidential, personal, cyber, GxP, sensitive, vendor.</div></div>
        <div class="metric"><div class="label">Minimization</div><div class="value" style="color:var(--yellow);">Required</div><div class="note">AI agent should use only minimum necessary data.</div></div>
        <div class="metric"><div class="label">Sensitive Data</div><div class="value" style="color:var(--red);">Screened</div><div class="note">Personal, regulated, cyber, and vendor data require routing.</div></div>
        <div class="metric"><div class="label">Retention</div><div class="value" style="color:var(--orange);">Controlled</div><div class="note">Prompt, output, log, and evidence retention must be defined.</div></div>
        <div class="metric"><div class="label">Replay</div><div class="value" style="color:var(--purple);">Required</div><div class="note">Data use must be reconstructable.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Privacy Boundary Center</h2>
        <div class="answer">
            <strong>Purpose:</strong> prevent AI agents from processing data outside approved privacy, data protection,
            cybersecurity, GxP, vendor, or confidentiality boundaries.
            The privacy boundary defines what data the agent may use, what must be minimized, what must be routed,
            what must be retained, what must be deleted, and what must never become hidden AI training or uncontrolled reuse.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Class ID</th>
                    <th>Data Classification</th>
                    <th>Examples</th>
                    <th>Default Position</th>
                    <th>Required Owner</th>
                    <th>Required Control</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Privacy Boundary Rule</h2>
        <div class="answer">
            AgentTrust™ treats data exposure as an operational trust issue.
            An AI agent cannot be trusted if it uses data without approved purpose, classification, minimization,
            retention, access boundary, transfer review, and replay evidence.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Privacy Boundary Center",
        "Privacy boundary center for AI agent data classification, minimization, sensitive data routing, retention, deletion, transfer review, access boundary, and replay evidence.",
        body
    )


@app.route("/agenttrust/ai-data-protection-impact-assessment")
@app.route("/agenttrust/ai-dpia")
@app.route("/agenttrust/data-protection-impact-assessment")
def agenttrust_ai_data_protection_impact_assessment():
    rows = agenttrust_privacy_control_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ AI Data Protection Impact Assessment</h2>
        <p>
            The AI DPIA checks whether the AI agent use case can be defended from a data protection and privacy perspective.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Control ID</th>
                    <th>Assessment Control</th>
                    <th>Question</th>
                    <th>Evidence</th>
                    <th>Failure Response</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>AI DPIA Rule</h2>
        <div class="answer">
            AI data protection assessment should happen before the agent processes real enterprise data,
            not after the data has already moved through the model, tool, workflow, or vendor boundary.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ AI Data Protection Impact Assessment",
        "AI data protection impact assessment for purpose limitation, data minimization, sensitive data screen, retention, training use restriction, transfer, access control, and replay.",
        body
    )


@app.route("/agenttrust/data-classification-router")
@app.route("/agenttrust/ai-data-router")
@app.route("/agenttrust/data-risk-router")
def agenttrust_data_classification_router():
    rows = agenttrust_data_classification_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Data Classification Router</h2>
        <p>
            The Data Classification Router sends AI agent data use to the right owner based on sensitivity and operational impact.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Class ID</th>
                    <th>Data Classification</th>
                    <th>Examples</th>
                    <th>Default Position</th>
                    <th>Required Owner</th>
                    <th>Control</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Routing Rule</h2>
        <div class="answer">
            Data classification determines route.
            Cyber data routes to cybersecurity, GxP data routes to QA / validation, personal data routes to privacy / legal,
            vendor-processed data routes to vendor assurance, and confidential data routes to the data owner.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Data Classification Router",
        "Data classification router for AI agent processing of public, internal, confidential, personal, cyber, GxP, sensitive, and vendor-processed data.",
        body
    )


@app.route("/agenttrust/pii-regulated-data-screen")
@app.route("/agenttrust/sensitive-data-screen")
@app.route("/agenttrust/personal-regulated-data-screen")
def agenttrust_pii_regulated_data_screen():
    body = """
    <section class="section">
        <h2>AgentTrust™ PII / Sensitive / Regulated Data Screen</h2>
        <p>
            This screen identifies data categories that should not be processed casually by AI agents.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Data Signal</th>
                    <th>AI Agent Risk</th>
                    <th>Required Route</th>
                    <th>Default Decision</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Names, emails, employee IDs, user records.</td><td>Personal data exposure.</td><td>Privacy / Data Owner.</td><td><span class="badge yellow">Minimize and review</span></td></tr>
                <tr><td>Access groups, entitlements, account data.</td><td>Access governance exposure.</td><td>Cybersecurity / Access Owner.</td><td><span class="badge red">Cyber-gated</span></td></tr>
                <tr><td>CyberArk, PSM, admin route, privileged logs.</td><td>Privileged access exposure.</td><td>Cybersecurity / CyberArk Owner.</td><td><span class="badge red">Restrict by default</span></td></tr>
                <tr><td>Validation, QA, QC, batch, deviation, CAPA, inspection evidence.</td><td>Regulated reliance risk.</td><td>QA / Validation Owner.</td><td><span class="badge red">QA-governed only</span></td></tr>
                <tr><td>Clinical, safety, patient, or health-related context.</td><td>Sensitive or regulated data exposure.</td><td>Privacy / Legal / Compliance / QA.</td><td><span class="badge red">Block unless approved</span></td></tr>
                <tr><td>Security architecture, network diagrams, privileged workflows.</td><td>Security-sensitive disclosure.</td><td>Security / Architecture Owner.</td><td><span class="badge red">Restricted</span></td></tr>
                <tr><td>Vendor AI data processing.</td><td>External data boundary and retention risk.</td><td>Vendor / Data / Security Owner.</td><td><span class="badge orange">Vendor assurance required</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Sensitive Data Rule</h2>
        <div class="answer">
            If the data category creates privacy, cybersecurity, GxP, legal, or vendor exposure,
            the AI agent must be routed before processing, not after output is generated.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ PII Sensitive Regulated Data Screen",
        "Sensitive data screen for personal data, access data, CyberArk / PSM context, GxP evidence, health-related context, security architecture, and vendor AI processing.",
        body
    )


@app.route("/agenttrust/data-minimization-gate")
@app.route("/agenttrust/minimization-gate")
@app.route("/agenttrust/ai-data-minimization")
def agenttrust_data_minimization_gate():
    body = """
    <section class="section">
        <h2>AgentTrust™ Data Minimization Gate</h2>
        <p>
            The Data Minimization Gate checks whether the AI agent really needs each data element before processing.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Minimization Question</th>
                    <th>Pass Condition</th>
                    <th>Failure Signal</th>
                    <th>Required Response</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Is this data required for the approved purpose?</td><td>Data directly supports use case.</td><td>Extra fields included without need.</td><td><span class="badge orange">Remove unnecessary fields</span></td></tr>
                <tr><td>Can the agent use metadata instead of full content?</td><td>Metadata is sufficient.</td><td>Full document or record copied unnecessarily.</td><td><span class="badge orange">Use metadata only</span></td></tr>
                <tr><td>Can sensitive identifiers be masked?</td><td>Names, IDs, emails, or sensitive values masked where possible.</td><td>Identifiable data included unnecessarily.</td><td><span class="badge red">Mask or exclude</span></td></tr>
                <tr><td>Can synthetic data be used for testing?</td><td>Sandbox uses synthetic examples.</td><td>Production data used during prototype.</td><td><span class="badge red">Move to synthetic sandbox</span></td></tr>
                <tr><td>Can the agent use reference links instead of copying data?</td><td>Evidence link preserved instead of full duplication.</td><td>Prompt stores large sensitive content.</td><td><span class="badge orange">Use source reference</span></td></tr>
                <tr><td>Is output limited to what the reviewer needs?</td><td>Output avoids unnecessary exposure.</td><td>Agent reveals irrelevant sensitive details.</td><td><span class="badge red">Restrict output</span></td></tr>
                <tr><td>Is data retained only as long as necessary?</td><td>Retention rule defined.</td><td>Prompt and output retained indefinitely.</td><td><span class="badge orange">Set retention rule</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Minimization Rule</h2>
        <div class="answer">
            The safest AI data is the data the agent never receives.
            AgentTrust™ requires minimum necessary data, masking where possible, synthetic data for testing, and source references instead of unnecessary duplication.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Data Minimization Gate",
        "Data minimization gate for AI agent purpose limitation, metadata-only processing, masking, synthetic testing, source references, restricted output, and retention.",
        body
    )


@app.route("/agenttrust/retention-deletion-control")
@app.route("/agenttrust/data-retention-control")
@app.route("/agenttrust/deletion-control")
def agenttrust_retention_deletion_control():
    rows = agenttrust_retention_rule_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Retention and Deletion Control</h2>
        <p>
            Retention and deletion controls define how long AI prompts, outputs, logs, evidence, and vendor-processed data may remain.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Data Type</th>
                    <th>Retention Position</th>
                    <th>Deletion Rule</th>
                    <th>Owner</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Retention Rule</h2>
        <div class="answer">
            AgentTrust™ separates operational evidence retention from unnecessary AI data retention.
            Keep what is needed for audit defense and delete or minimize what is not needed for the approved purpose.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Retention and Deletion Control",
        "Retention and deletion control for AI agent synthetic data, operational metadata, personal data, cyber data, GxP evidence, and vendor AI prompts and outputs.",
        body
    )


@app.route("/agenttrust/cross-border-data-transfer-screen")
@app.route("/agenttrust/data-transfer-screen")
@app.route("/agenttrust/external-data-transfer-screen")
def agenttrust_cross_border_data_transfer_screen():
    body = """
    <section class="section">
        <h2>AgentTrust™ Cross-Border / External Data Transfer Screen</h2>
        <p>
            This screen checks whether AI agent data leaves the approved environment, tenant, region, vendor boundary, or enterprise system.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Transfer Signal</th>
                    <th>Risk</th>
                    <th>Required Evidence</th>
                    <th>Default Decision</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Data sent to external vendor AI.</td><td>External processing and retention risk.</td><td>Vendor contract, data boundary, retention, deletion, audit support.</td><td><span class="badge orange">Vendor assurance required</span></td></tr>
                <tr><td>Data crosses hosting region.</td><td>Data residency and transfer exposure.</td><td>Hosting region, transfer path, owner approval.</td><td><span class="badge orange">Transfer review</span></td></tr>
                <tr><td>Data copied outside source system.</td><td>Duplicate retention and access risk.</td><td>Evidence storage location and retention rule.</td><td><span class="badge yellow">Minimize duplication</span></td></tr>
                <tr><td>Prompt or output retained by platform.</td><td>Unclear retention or reuse.</td><td>Platform retention setting and training-use status.</td><td><span class="badge red">Clarify before processing</span></td></tr>
                <tr><td>Regulated evidence exported.</td><td>Inspection and GxP defensibility risk.</td><td>QA approval and evidence control.</td><td><span class="badge red">QA-governed only</span></td></tr>
                <tr><td>Access or cyber data exported.</td><td>Privileged data exposure.</td><td>Cybersecurity approval.</td><td><span class="badge red">Cyber-gated</span></td></tr>
                <tr><td>Personal data exported.</td><td>Privacy and data protection risk.</td><td>Privacy / legal approval and minimization record.</td><td><span class="badge red">Privacy review required</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Transfer Rule</h2>
        <div class="answer">
            AI data movement must be visible.
            AgentTrust™ requires clear evidence of where data goes, who processes it, how long it remains,
            whether it trains models, and how it can be deleted or defended.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Cross-Border Data Transfer Screen",
        "Transfer screen for AI agent external vendor processing, hosting region, duplicated source data, platform retention, regulated evidence export, cyber data export, and personal data export.",
        body
    )


@app.route("/agenttrust/privacy-risk-simulator", methods=["GET", "POST"])
@app.route("/agenttrust/ai-privacy-risk-simulator", methods=["GET", "POST"])
@app.route("/agenttrust/data-protection-simulator", methods=["GET", "POST"])
def agenttrust_privacy_risk_simulator():
    from flask import request

    purpose = request.form.get("purpose", "yes")
    minimization = request.form.get("minimization", "yes")
    sensitive = request.form.get("sensitive", "no")
    retention = request.form.get("retention", "yes")
    training = request.form.get("training", "yes")
    transfer = request.form.get("transfer", "yes")
    access = request.form.get("access", "yes")
    replay = request.form.get("replay", "yes")

    score, decision, badge, reason = agenttrust_privacy_risk_decision(
        purpose, minimization, sensitive, retention, training, transfer, access, replay
    )

    def selected(value, expected):
        return "selected" if value == expected else ""

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Privacy Score</div><div class="value" style="color:var(--green);">{score}%</div><div class="note">Calculated from privacy boundary controls.</div></div>
        <div class="metric"><div class="label">Privacy Decision</div><div class="value" style="color:var(--yellow);">{decision}</div><div class="note">{reason}</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Privacy Risk Simulator</h2>
        <p>
            Simulate whether an AI agent can process a data set under AgentTrust™ privacy boundary controls.
        </p>

        <form method="POST" action="/agenttrust/privacy-risk-simulator">
            <table>
                <tbody>
                    <tr><td><strong>Approved Purpose Exists?</strong></td><td><select name="purpose" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(purpose, "yes")}>Yes</option><option value="no" {selected(purpose, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Data Minimization Complete?</strong></td><td><select name="minimization" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(minimization, "yes")}>Yes</option><option value="no" {selected(minimization, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Sensitive / Personal / Regulated / Cyber Data Present?</strong></td><td><select name="sensitive" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="no" {selected(sensitive, "no")}>No</option><option value="yes" {selected(sensitive, "yes")}>Yes</option></select></td></tr>
                    <tr><td><strong>Retention / Deletion Rule Defined?</strong></td><td><select name="retention" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(retention, "yes")}>Yes</option><option value="no" {selected(retention, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Model Training / Reuse Status Clear?</strong></td><td><select name="training" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(training, "yes")}>Yes</option><option value="no" {selected(training, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Transfer / Vendor / Region Boundary Approved?</strong></td><td><select name="transfer" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(transfer, "yes")}>Yes</option><option value="no" {selected(transfer, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Agent Access Boundary Controlled?</strong></td><td><select name="access" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(access, "yes")}>Yes</option><option value="no" {selected(access, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Privacy Evidence Replay Ready?</strong></td><td><select name="replay" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(replay, "yes")}>Yes</option><option value="no" {selected(replay, "no")}>No</option></select></td></tr>
                </tbody>
            </table>

            <button type="submit" style="margin-top:16px;padding:12px 18px;border-radius:12px;border:0;background:#2563eb;color:white;font-weight:800;">Run Privacy Risk Screen</button>
        </form>
    </section>

    <section class="section">
        <h2>Privacy Boundary Decision</h2>
        <div class="answer">
            <strong>Score:</strong> {score}%<br>
            <strong>Decision:</strong> <span class="badge {badge}">{decision}</span><br>
            <strong>Reason:</strong> {reason}
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Privacy Risk Simulator",
        "Privacy risk simulator for AI agent purpose, minimization, sensitive data, retention, training use, transfer, access boundary, and replay readiness.",
        body
    )


@app.route("/agenttrust/privacy-boundary-json")
@app.route("/agenttrust/privacy-json")
@app.route("/agenttrust/ai-dpia-json")
def agenttrust_privacy_boundary_json():
    from flask import jsonify

    return jsonify({
        "module": "AgentTrust™",
        "capability": "Privacy Boundary Center + AI Data Protection Impact Assessment",
        "primary_question": "Can this AI agent process this data within approved privacy, security, GxP, and data protection boundaries?",
        "data_classifications": AGENTTRUST_DATA_CLASSIFICATIONS,
        "privacy_assessment_controls": AGENTTRUST_PRIVACY_ASSESSMENT_CONTROLS,
        "retention_rules": AGENTTRUST_RETENTION_RULES,
        "minimum_conditions": [
            "Approved purpose exists",
            "Data classification is known",
            "Minimum necessary data is used",
            "Sensitive data is routed to the correct owner",
            "Retention and deletion rules are defined",
            "Model training or reuse status is clear",
            "External transfer or vendor processing is reviewed",
            "Agent access boundary is controlled",
            "Privacy evidence can be replayed"
        ],
        "default_decision": "Block, restrict, or route AI agent data processing until purpose, classification, minimization, retention, transfer, access, and replay controls are complete"
    })

# ============================================================
# END AGENTTRUST_PRIVACY_BOUNDARY_DPIA_V1_ACTIVE
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

print("AgentTrust Privacy Boundary Center installed.")
print(f"Inserted before: {target_found}")
