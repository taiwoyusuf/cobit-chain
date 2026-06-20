from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_THIRD_PARTY_AI_VENDOR_GOVERNANCE_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust Third-Party AI Governance already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base module not found. Install AgentTrust module first.")

nav_old = '<a href="/agenttrust/simulation-twin" class="secondary">Simulation Twin</a>'
nav_new = '''<a href="/agenttrust/simulation-twin" class="secondary">Simulation Twin</a>
                    <a href="/agenttrust/third-party-ai-governance" class="secondary">Vendor AI</a>
                    <a href="/agenttrust/third-party-ai-register" class="dark">Vendor Register</a>
                    <a href="/agenttrust/vendor-assurance-gateway" class="dark">Assurance Gateway</a>
                    <a href="/agenttrust/vendor-risk-simulator" class="dark">Vendor Risk</a>'''

if nav_old in text and "/agenttrust/third-party-ai-governance" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# AGENTTRUST_THIRD_PARTY_AI_VENDOR_GOVERNANCE_V1_ACTIVE
# AgentTrust™ Third-Party AI Governance, Vendor Agent Register,
# Vendor Assurance Gateway, Supplier AI Risk Screen,
# External Agent Contract Controls, Data Sharing Boundary,
# Vendor Evidence Dossier, Vendor Risk Simulator,
# and Vendor AI JSON Export
# ============================================================

AGENTTRUST_VENDOR_AI_REGISTER = [
    {
        "vendor_id": "AT-VAI-001",
        "vendor_ai": "Vendor ServiceNow AI Assistant",
        "use_case": "Summarizes tickets, CI records, change notes, and operational requests.",
        "enterprise_touchpoint": "ServiceNow / CMDB / Change / Request",
        "data_boundary": "Internal operational metadata; no regulated conclusion or privileged action.",
        "risk": "High",
        "owner": "ServiceNow Platform Owner",
        "status": "Human-Gated Review"
    },
    {
        "vendor_id": "AT-VAI-002",
        "vendor_ai": "External Access Review AI",
        "use_case": "Supports entitlement review, access group recommendation, or identity governance analysis.",
        "enterprise_touchpoint": "MyAccess / IAM / entitlement data",
        "data_boundary": "Access metadata; no autonomous approval, no entitlement activation.",
        "risk": "Critical",
        "owner": "Cybersecurity / Access Owner",
        "status": "Cyber Review Required"
    },
    {
        "vendor_id": "AT-VAI-003",
        "vendor_ai": "Vendor CyberArk Analytics AI",
        "use_case": "Analyzes privileged session patterns and admin route activity.",
        "enterprise_touchpoint": "CyberArk / PSM / privileged access",
        "data_boundary": "Privileged access logs; no credential action or session trigger.",
        "risk": "Critical",
        "owner": "Cybersecurity / CyberArk Owner",
        "status": "Privileged Review Required"
    },
    {
        "vendor_id": "AT-VAI-004",
        "vendor_ai": "Vendor MES / LIMS AI Assistant",
        "use_case": "Summarizes manufacturing, lab, QC, or batch-related evidence.",
        "enterprise_touchpoint": "MES / LIMS / QC / batch evidence",
        "data_boundary": "Regulated evidence; no QA conclusion, no batch release, no validation approval.",
        "risk": "Critical",
        "owner": "QA / Validation / System Owner",
        "status": "QA-Governed Only"
    },
    {
        "vendor_id": "AT-VAI-005",
        "vendor_ai": "Vendor Document Intelligence AI",
        "use_case": "Extracts and summarizes SOP, GSOP, validation, work order, or audit documents.",
        "enterprise_touchpoint": "Document repository / evidence vault",
        "data_boundary": "Document content; output must remain draft until human review.",
        "risk": "High",
        "owner": "Document / Quality Owner",
        "status": "Evidence Review Required"
    },
    {
        "vendor_id": "AT-VAI-006",
        "vendor_ai": "External AI Copilot for Reporting",
        "use_case": "Generates executive summaries, board packs, and operational dashboards.",
        "enterprise_touchpoint": "Power BI / reporting / leadership dashboard",
        "data_boundary": "Aggregated governance metrics; must distinguish evidence-backed trust from conditional trust.",
        "risk": "Medium",
        "owner": "Governance Reporting Owner",
        "status": "Conditional Use"
    }
]


AGENTTRUST_VENDOR_ASSURANCE_CONTROLS = [
    {
        "control_id": "AT-VCTRL-001",
        "control": "Vendor AI Identity",
        "requirement": "Vendor AI product, model, provider, version, hosting region, and enterprise owner must be known.",
        "evidence": "Vendor AI register, vendor architecture, owner assignment.",
        "failure_response": "Do not onboard."
    },
    {
        "control_id": "AT-VCTRL-002",
        "control": "Data Boundary",
        "requirement": "Allowed data, prohibited data, regulated data, access data, and retention behavior must be defined.",
        "evidence": "Data boundary assessment and data handling record.",
        "failure_response": "Restrict to non-sensitive synthetic testing."
    },
    {
        "control_id": "AT-VCTRL-003",
        "control": "No Hidden Approval",
        "requirement": "Vendor AI must not approve changes, access, validation, QA outcomes, release, or regulated conclusions.",
        "evidence": "Contract clause, workflow test, prohibited action evidence.",
        "failure_response": "Block operational use."
    },
    {
        "control_id": "AT-VCTRL-004",
        "control": "Security and Access Review",
        "requirement": "Any access, identity, CyberArk, PSM, admin, credential, or privileged context must route to cybersecurity.",
        "evidence": "Cyber review, privileged impact assessment, access owner decision.",
        "failure_response": "Cyber-gated only."
    },
    {
        "control_id": "AT-VCTRL-005",
        "control": "GxP / QA Review",
        "requirement": "Any regulated, GMP, QA, validation, QC, release, deviation, CAPA, or inspection context must route to QA.",
        "evidence": "QA impact assessment, validation review, regulated use decision.",
        "failure_response": "QA-governed only."
    },
    {
        "control_id": "AT-VCTRL-006",
        "control": "Evidence and Audit Replay",
        "requirement": "Vendor AI action must be traceable from input to output, reviewer, decision, and outcome.",
        "evidence": "Evidence dossier, replay log, audit package.",
        "failure_response": "Restrict reliance."
    },
    {
        "control_id": "AT-VCTRL-007",
        "control": "Vendor Contract Obligations",
        "requirement": "Vendor terms must address data use, model training, retention, audit support, breach notice, and exit rights.",
        "evidence": "Contract addendum, DPA, security review, vendor assurance pack.",
        "failure_response": "Do not approve for enterprise use."
    },
    {
        "control_id": "AT-VCTRL-008",
        "control": "Exit and Revocation",
        "requirement": "Enterprise must be able to revoke, restrict, offboard, and archive evidence when vendor AI risk changes.",
        "evidence": "Exit plan, revocation rule, offboarding evidence.",
        "failure_response": "Block production onboarding."
    }
]


AGENTTRUST_VENDOR_CONTRACT_CLAUSES = [
    {
        "clause": "Data Use Limitation",
        "requirement": "Vendor must not use enterprise data for model training unless explicitly approved.",
        "risk_if_missing": "Enterprise data may be reused outside approved boundary."
    },
    {
        "clause": "Data Retention and Deletion",
        "requirement": "Retention period, deletion process, evidence retention, and offboarding export must be defined.",
        "risk_if_missing": "Data may remain with vendor after use is revoked."
    },
    {
        "clause": "Audit Support",
        "requirement": "Vendor must support evidence requests, logs, model/version references, and incident investigation.",
        "risk_if_missing": "Enterprise cannot defend vendor AI action."
    },
    {
        "clause": "No Autonomous Approval",
        "requirement": "Vendor AI must not approve access, changes, validation, QA, release, deviation closure, or regulated conclusions.",
        "risk_if_missing": "AI may become hidden approver."
    },
    {
        "clause": "Security Incident Notice",
        "requirement": "Vendor must notify enterprise of security, data, model, or operational incidents affecting AI output.",
        "risk_if_missing": "Security or quality risk may remain hidden."
    },
    {
        "clause": "Model / Tool Change Notice",
        "requirement": "Vendor must disclose material model, tool, data, prompt, or system behavior changes.",
        "risk_if_missing": "Trust decision becomes stale."
    },
    {
        "clause": "Regulated Use Restriction",
        "requirement": "Vendor AI output cannot be used as regulated conclusion without QA / validation owner review.",
        "risk_if_missing": "Inspection or GxP defensibility risk."
    },
    {
        "clause": "Exit Rights",
        "requirement": "Enterprise must be able to terminate use, export evidence, delete data, and disable integrations.",
        "risk_if_missing": "Vendor lock-in and governance exposure."
    }
]


def agenttrust_vendor_ai_rows():
    rows = ""

    for item in AGENTTRUST_VENDOR_AI_REGISTER:
        badge = "blue"
        if item["risk"] == "Critical":
            badge = "red"
        elif item["risk"] == "High":
            badge = "orange"
        elif item["risk"] == "Medium":
            badge = "yellow"

        rows += f"""
        <tr>
            <td><strong>{item["vendor_id"]}</strong></td>
            <td>{item["vendor_ai"]}</td>
            <td>{item["use_case"]}</td>
            <td>{item["enterprise_touchpoint"]}</td>
            <td>{item["data_boundary"]}</td>
            <td><span class="badge {badge}">{item["risk"]}</span></td>
            <td>{item["owner"]}</td>
            <td>{item["status"]}</td>
        </tr>
        """

    return rows


def agenttrust_vendor_control_rows():
    rows = ""

    for item in AGENTTRUST_VENDOR_ASSURANCE_CONTROLS:
        rows += f"""
        <tr>
            <td><strong>{item["control_id"]}</strong></td>
            <td><span class="badge blue">{item["control"]}</span></td>
            <td>{item["requirement"]}</td>
            <td>{item["evidence"]}</td>
            <td><span class="badge red">{item["failure_response"]}</span></td>
        </tr>
        """

    return rows


def agenttrust_vendor_clause_rows():
    rows = ""

    for item in AGENTTRUST_VENDOR_CONTRACT_CLAUSES:
        rows += f"""
        <tr>
            <td><strong>{item["clause"]}</strong></td>
            <td>{item["requirement"]}</td>
            <td><span class="badge red">{item["risk_if_missing"]}</span></td>
        </tr>
        """

    return rows


def agenttrust_vendor_risk_decision(identity, data_boundary, security, gxp, access, evidence, contract, exit_plan):
    controls = [identity, data_boundary, security, gxp, access, evidence, contract, exit_plan]
    score = int((sum(1 for item in controls if item == "yes") / len(controls)) * 100)

    if identity != "yes":
        return score, "Block Vendor AI", "red", "Vendor AI identity, owner, model, provider, or version is not known."
    if data_boundary != "yes":
        return score, "Restrict to Synthetic Data", "red", "Data boundary is not approved."
    if security != "yes":
        return score, "Security Review Required", "red", "Security review is incomplete."
    if access != "yes":
        return score, "Cyber-Gated Only", "red", "Access, entitlement, CyberArk, PSM, or privileged impact is not fully controlled."
    if gxp != "yes":
        return score, "QA-Governed Only", "orange", "GxP / QA / validation impact is not fully reviewed."
    if evidence != "yes":
        return score, "Restrict Reliance", "orange", "Evidence and audit replay are incomplete."
    if contract != "yes":
        return score, "Do Not Approve", "red", "Vendor contract obligations are not complete."
    if exit_plan != "yes":
        return score, "Conditional Approval Only", "yellow", "Exit, revocation, deletion, or evidence archive plan is incomplete."
    if score == 100:
        return score, "Approved With Controls", "green", "Vendor AI may be used within approved boundary, owner route, evidence controls, and contract obligations."
    return score, "Conditional Use", "yellow", "Vendor AI may be used only under documented restrictions and remediation tracking."


try:
    AGENTTRUST_EXPECTED_ROUTES.extend([
        "/agenttrust/third-party-ai-governance",
        "/agenttrust/third-party-ai-register",
        "/agenttrust/vendor-assurance-gateway",
        "/agenttrust/supplier-ai-risk-screen",
        "/agenttrust/external-agent-contracts",
        "/agenttrust/data-sharing-boundary",
        "/agenttrust/vendor-evidence-dossier",
        "/agenttrust/vendor-risk-simulator",
        "/agenttrust/vendor-ai-json"
    ])
except Exception:
    pass


@app.route("/agenttrust/third-party-ai-governance")
@app.route("/agenttrust/vendor-ai-governance")
@app.route("/agenttrust/external-ai-governance")
def agenttrust_third_party_ai_governance():
    rows = agenttrust_vendor_ai_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Vendor AI</div><div class="value" style="color:var(--green);">Governed</div><div class="note">Third-party AI register and gateway active.</div></div>
        <div class="metric"><div class="label">Data Boundary</div><div class="value" style="color:var(--yellow);">Required</div><div class="note">Allowed and prohibited data must be defined.</div></div>
        <div class="metric"><div class="label">Cyber</div><div class="value" style="color:var(--red);">Gated</div><div class="note">Access and privileged contexts require cyber review.</div></div>
        <div class="metric"><div class="label">GxP / QA</div><div class="value" style="color:var(--orange);">QA Routed</div><div class="note">Regulated use requires QA / validation review.</div></div>
        <div class="metric"><div class="label">Contract</div><div class="value" style="color:var(--blue);">Obligations</div><div class="note">Vendor clauses preserve control and audit rights.</div></div>
        <div class="metric"><div class="label">Exit</div><div class="value" style="color:var(--purple);">Revocable</div><div class="note">Vendor AI use must be offboardable.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Third-Party AI Governance</h2>
        <div class="answer">
            <strong>Purpose:</strong> govern vendor AI tools before they touch enterprise workflows, regulated evidence,
            ServiceNow records, access routes, CyberArk / PSM context, or executive reporting.
            AgentTrust™ requires identity, owner, data boundary, cyber review, GxP review, evidence replay,
            contract obligations, and exit rights before vendor AI can be trusted.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Vendor ID</th>
                    <th>Vendor AI</th>
                    <th>Use Case</th>
                    <th>Enterprise Touchpoint</th>
                    <th>Data Boundary</th>
                    <th>Risk</th>
                    <th>Owner</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Third-Party AI Rule</h2>
        <div class="answer">
            A vendor AI tool should not be trusted simply because it is purchased or embedded in another platform.
            It must pass AgentTrust™ controls for identity, data boundary, owner accountability, evidence, cyber, GxP, contract, and exit.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Third-Party AI Governance",
        "Third-party and vendor AI governance for enterprise AI tools, data boundaries, cyber review, GxP review, evidence replay, contract obligations, and exit controls.",
        body
    )


@app.route("/agenttrust/third-party-ai-register")
@app.route("/agenttrust/vendor-ai-register")
@app.route("/agenttrust/external-agent-register")
def agenttrust_third_party_ai_register():
    rows = agenttrust_vendor_ai_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Third-Party AI Register</h2>
        <p>
            The Third-Party AI Register captures vendor AI systems that may influence enterprise workflows, access decisions,
            regulated evidence, ServiceNow records, or leadership reporting.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Vendor ID</th>
                    <th>Vendor AI</th>
                    <th>Use Case</th>
                    <th>Enterprise Touchpoint</th>
                    <th>Data Boundary</th>
                    <th>Risk</th>
                    <th>Owner</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Register Rule</h2>
        <div class="answer">
            No vendor AI should enter operational use without a register record, owner, use case, enterprise touchpoint,
            data boundary, risk tier, and review status.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Third-Party AI Register",
        "Register of vendor AI and external AI agents with use case, enterprise touchpoint, data boundary, risk, owner, and status.",
        body
    )


@app.route("/agenttrust/vendor-assurance-gateway")
@app.route("/agenttrust/third-party-assurance-gateway")
@app.route("/agenttrust/vendor-ai-gateway")
def agenttrust_vendor_assurance_gateway():
    rows = agenttrust_vendor_control_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Vendor Assurance Gateway</h2>
        <p>
            The Vendor Assurance Gateway defines the controls a third-party AI product must pass before enterprise use.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Control ID</th>
                    <th>Gateway Control</th>
                    <th>Requirement</th>
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
        <h2>Assurance Gateway Rule</h2>
        <div class="answer">
            Vendor AI must pass through a gateway before operational reliance.
            If identity, data boundary, security, GxP, evidence, contract, or exit controls are incomplete,
            the AI should be restricted, human-gated, or blocked.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Vendor Assurance Gateway",
        "Vendor assurance gateway for third-party AI identity, data boundary, hidden approval, security, GxP, evidence, contract obligations, and exit controls.",
        body
    )


@app.route("/agenttrust/supplier-ai-risk-screen")
@app.route("/agenttrust/vendor-risk-screen")
@app.route("/agenttrust/third-party-risk-screen")
def agenttrust_supplier_ai_risk_screen():
    body = """
    <section class="section">
        <h2>AgentTrust™ Supplier AI Risk Screen</h2>
        <p>
            This screen identifies supplier AI risk before data sharing, workflow integration, or operational reliance.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Risk Area</th>
                    <th>Screening Question</th>
                    <th>Required Owner</th>
                    <th>Decision Rule</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Data sensitivity</td><td>Will vendor AI process internal, confidential, regulated, personal, or access-related data?</td><td>Data Owner.</td><td><span class="badge red">Boundary approval required</span></td></tr>
                <tr><td>Model training</td><td>Can vendor use enterprise data to train, fine-tune, or improve models?</td><td>Legal / Privacy / Security.</td><td><span class="badge red">Explicit approval required</span></td></tr>
                <tr><td>Access impact</td><td>Does AI influence access, entitlement, CyberArk, PSM, or admin workflows?</td><td>Cybersecurity Owner.</td><td><span class="badge red">Cyber-gated</span></td></tr>
                <tr><td>Regulated impact</td><td>Does AI touch GMP, QA, validation, release, deviation, CAPA, QC, or inspection evidence?</td><td>QA / Validation Owner.</td><td><span class="badge red">QA-governed only</span></td></tr>
                <tr><td>Workflow action</td><td>Can AI create, update, trigger, approve, or route operational workflow?</td><td>Process Owner.</td><td><span class="badge red">Authority gate required</span></td></tr>
                <tr><td>Evidence</td><td>Can the vendor provide logs, source evidence, model/version reference, and outcome trace?</td><td>Audit / Governance Owner.</td><td><span class="badge orange">Restrict if incomplete</span></td></tr>
                <tr><td>Data retention</td><td>How long does vendor retain inputs, outputs, logs, and evidence?</td><td>Legal / Privacy / Data Owner.</td><td><span class="badge orange">Retention approval required</span></td></tr>
                <tr><td>Exit</td><td>Can the vendor AI be disabled and data deleted or exported?</td><td>Vendor Owner.</td><td><span class="badge red">No exit, no production</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Supplier Risk Rule</h2>
        <div class="answer">
            Vendor AI risk is created not only by the model, but by data use, workflow action, access influence,
            regulated reliance, evidence gaps, retention, and exit limitations.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Supplier AI Risk Screen",
        "Supplier AI risk screen for data sensitivity, model training, access impact, regulated impact, workflow action, evidence, retention, and exit.",
        body
    )


@app.route("/agenttrust/external-agent-contracts")
@app.route("/agenttrust/vendor-contract-controls")
@app.route("/agenttrust/vendor-ai-contracts")
def agenttrust_external_agent_contracts():
    rows = agenttrust_vendor_clause_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ External Agent Contract Controls</h2>
        <p>
            These clauses convert vendor AI governance expectations into contract-level obligations.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Contract Clause</th>
                    <th>Requirement</th>
                    <th>Risk If Missing</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Contract Control Rule</h2>
        <div class="answer">
            Vendor AI controls must be backed by contract language.
            If the vendor cannot support data boundaries, audit evidence, change notice, regulated restrictions, and exit rights,
            enterprise trust remains conditional or blocked.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ External Agent Contract Controls",
        "Contract controls for vendor AI data use, retention, audit support, no autonomous approval, incident notice, model change notice, regulated use restriction, and exit rights.",
        body
    )


@app.route("/agenttrust/data-sharing-boundary")
@app.route("/agenttrust/vendor-data-boundary")
@app.route("/agenttrust/third-party-data-boundary")
def agenttrust_data_sharing_boundary():
    body = """
    <section class="section">
        <h2>AgentTrust™ Data Sharing Boundary</h2>
        <p>
            The Data Sharing Boundary defines what information a vendor AI can receive, process, retain, generate, or return.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Data Category</th>
                    <th>Default Position</th>
                    <th>Required Control</th>
                    <th>Risk If Not Controlled</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Public / non-sensitive data</td><td>Allowed for approved use case.</td><td>Owner and use case record.</td><td>Low governance exposure.</td></tr>
                <tr><td>Internal operational metadata</td><td>Conditional.</td><td>Data owner approval and evidence capture.</td><td>Operational confidentiality risk.</td></tr>
                <tr><td>ServiceNow / CMDB records</td><td>Human-gated.</td><td>CMDB owner, CI boundary, no hidden update.</td><td>Incorrect CI governance reliance.</td></tr>
                <tr><td>Access / entitlement data</td><td>Cyber-gated.</td><td>Access owner and cybersecurity approval.</td><td>Access governance exposure.</td></tr>
                <tr><td>CyberArk / privileged context</td><td>Restricted by default.</td><td>CyberArk owner and privileged impact assessment.</td><td>Privileged access risk.</td></tr>
                <tr><td>GMP / QA / validation / QC data</td><td>QA-governed only.</td><td>QA / validation owner approval.</td><td>Regulated defensibility risk.</td></tr>
                <tr><td>Personal or sensitive data</td><td>Privacy / legal review required.</td><td>Privacy, legal, security, and retention review.</td><td>Privacy and compliance exposure.</td></tr>
                <tr><td>Confidential strategy or executive data</td><td>Restricted.</td><td>Executive owner and data handling approval.</td><td>Business confidentiality risk.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Data Boundary Rule</h2>
        <div class="answer">
            Vendor AI should only receive the minimum approved data needed for the approved use case.
            Data sharing must be bounded, owned, evidenced, retained appropriately, and revocable.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Data Sharing Boundary",
        "Data sharing boundary for vendor AI across public data, internal metadata, ServiceNow records, access data, CyberArk context, GxP data, sensitive data, and executive data.",
        body
    )


@app.route("/agenttrust/vendor-evidence-dossier")
@app.route("/agenttrust/third-party-evidence-dossier")
@app.route("/agenttrust/vendor-ai-dossier")
def agenttrust_vendor_evidence_dossier():
    body = """
    <section class="section">
        <h2>AgentTrust™ Vendor Evidence Dossier</h2>
        <p>
            The Vendor Evidence Dossier defines what evidence is needed to defend third-party AI use.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Dossier Section</th>
                    <th>Required Evidence</th>
                    <th>Owner</th>
                    <th>Why It Matters</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Vendor Identity</td><td>Vendor, AI product, model, version, hosting, owner.</td><td>Vendor Owner.</td><td>Shows what AI system is being used.</td></tr>
                <tr><td>Use Case</td><td>Approved use case, business purpose, workflow touchpoint.</td><td>Business Owner.</td><td>Prevents uncontrolled use expansion.</td></tr>
                <tr><td>Data Boundary</td><td>Allowed data, prohibited data, retention, deletion, model-training status.</td><td>Data Owner / Privacy.</td><td>Controls data exposure.</td></tr>
                <tr><td>Security Review</td><td>Security assessment, access impact, CyberArk / PSM impact if any.</td><td>Cybersecurity Owner.</td><td>Controls cyber and access risk.</td></tr>
                <tr><td>GxP Review</td><td>Regulated impact assessment and QA / validation review.</td><td>QA / Validation Owner.</td><td>Controls inspection and GMP risk.</td></tr>
                <tr><td>Evidence and Replay</td><td>Input, output, source, logs, reviewer, decision, outcome.</td><td>Audit Owner.</td><td>Supports investigation and audit defense.</td></tr>
                <tr><td>Contract Obligations</td><td>Data use, audit support, incident notice, change notice, exit rights.</td><td>Legal / Vendor Owner.</td><td>Preserves enforceable control.</td></tr>
                <tr><td>Exit Plan</td><td>Offboarding, disablement, data deletion, evidence archive.</td><td>Vendor Owner.</td><td>Prevents long-term uncontrolled exposure.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Dossier Rule</h2>
        <div class="answer">
            Vendor AI approval should leave behind a defensible evidence package.
            Without evidence, leadership cannot prove why the vendor AI was allowed, restricted, or blocked.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Vendor Evidence Dossier",
        "Vendor AI evidence dossier for identity, use case, data boundary, security review, GxP review, evidence replay, contract obligations, and exit plan.",
        body
    )


@app.route("/agenttrust/vendor-risk-simulator", methods=["GET", "POST"])
@app.route("/agenttrust/third-party-risk-simulator", methods=["GET", "POST"])
@app.route("/agenttrust/vendor-ai-risk-simulator", methods=["GET", "POST"])
def agenttrust_vendor_risk_simulator():
    from flask import request

    identity = request.form.get("identity", "yes")
    data_boundary = request.form.get("data_boundary", "yes")
    security = request.form.get("security", "yes")
    gxp = request.form.get("gxp", "yes")
    access = request.form.get("access", "yes")
    evidence = request.form.get("evidence", "yes")
    contract = request.form.get("contract", "yes")
    exit_plan = request.form.get("exit_plan", "yes")

    score, decision, badge, reason = agenttrust_vendor_risk_decision(
        identity, data_boundary, security, gxp, access, evidence, contract, exit_plan
    )

    def selected(value, expected):
        return "selected" if value == expected else ""

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Vendor Risk Score</div><div class="value" style="color:var(--green);">{score}%</div><div class="note">Calculated from vendor assurance controls.</div></div>
        <div class="metric"><div class="label">Vendor Decision</div><div class="value" style="color:var(--yellow);">{decision}</div><div class="note">{reason}</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Vendor Risk Simulator</h2>
        <p>
            Simulate whether a vendor AI tool should be approved, restricted, cyber-gated, QA-governed, or blocked.
        </p>

        <form method="POST" action="/agenttrust/vendor-risk-simulator">
            <table>
                <tbody>
                    <tr><td><strong>Vendor AI Identity Known?</strong></td><td><select name="identity" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(identity, "yes")}>Yes</option><option value="no" {selected(identity, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Data Boundary Approved?</strong></td><td><select name="data_boundary" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(data_boundary, "yes")}>Yes</option><option value="no" {selected(data_boundary, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Security Review Complete?</strong></td><td><select name="security" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(security, "yes")}>Yes</option><option value="no" {selected(security, "no")}>No</option></select></td></tr>
                    <tr><td><strong>GxP / QA Review Complete?</strong></td><td><select name="gxp" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(gxp, "yes")}>Yes</option><option value="no" {selected(gxp, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Access / CyberArk / Privileged Impact Controlled?</strong></td><td><select name="access" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(access, "yes")}>Yes</option><option value="no" {selected(access, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Evidence and Replay Ready?</strong></td><td><select name="evidence" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(evidence, "yes")}>Yes</option><option value="no" {selected(evidence, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Vendor Contract Controls Complete?</strong></td><td><select name="contract" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(contract, "yes")}>Yes</option><option value="no" {selected(contract, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Exit / Revocation Plan Ready?</strong></td><td><select name="exit_plan" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(exit_plan, "yes")}>Yes</option><option value="no" {selected(exit_plan, "no")}>No</option></select></td></tr>
                </tbody>
            </table>

            <button type="submit" style="margin-top:16px;padding:12px 18px;border-radius:12px;border:0;background:#2563eb;color:white;font-weight:800;">Run Vendor AI Risk Screen</button>
        </form>
    </section>

    <section class="section">
        <h2>Vendor AI Decision</h2>
        <div class="answer">
            <strong>Score:</strong> {score}%<br>
            <strong>Decision:</strong> <span class="badge {badge}">{decision}</span><br>
            <strong>Reason:</strong> {reason}
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Vendor Risk Simulator",
        "Simulator for third-party AI and vendor AI approval across identity, data boundary, security, GxP, access, evidence, contract, and exit controls.",
        body
    )


@app.route("/agenttrust/vendor-ai-json")
@app.route("/agenttrust/third-party-ai-json")
@app.route("/agenttrust/vendor-governance-json")
def agenttrust_vendor_ai_json():
    from flask import jsonify

    return jsonify({
        "module": "AgentTrust™",
        "capability": "Third-Party AI Governance + Vendor Agent Assurance Gateway",
        "primary_question": "Can this vendor AI be trusted inside enterprise workflows?",
        "vendor_ai_register": AGENTTRUST_VENDOR_AI_REGISTER,
        "vendor_assurance_controls": AGENTTRUST_VENDOR_ASSURANCE_CONTROLS,
        "vendor_contract_clauses": AGENTTRUST_VENDOR_CONTRACT_CLAUSES,
        "minimum_approval_conditions": [
            "Vendor AI identity is known",
            "Enterprise owner is assigned",
            "Approved use case is defined",
            "Data boundary is approved",
            "Security review is complete",
            "Access / CyberArk / privileged impact is controlled",
            "GxP / QA / validation impact is reviewed where applicable",
            "Evidence and audit replay are available",
            "Contract obligations are complete",
            "Exit, revocation, deletion, and evidence archive plan are ready"
        ],
        "default_decision": "Restrict or block vendor AI until identity, data boundary, security, GxP, access, evidence, contract, and exit controls are complete"
    })

# ============================================================
# END AGENTTRUST_THIRD_PARTY_AI_VENDOR_GOVERNANCE_V1_ACTIVE
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

print("AgentTrust Third-Party AI Governance installed.")
print(f"Inserted before: {target_found}")
