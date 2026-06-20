from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_AGENTIC_REGULATORY_TRACEABILITY_CROSSWALK_V1_ACTIVE"

if MARKER in text:
    print("CITrust Agentic Regulatory Traceability Crosswalk already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base shell not found. Install AgentTrust base module first.")

nav_old = '<a href="/citrust/agentic-executive-attestation-center" class="secondary">Attestation</a>'
nav_new = '''<a href="/citrust/agentic-executive-attestation-center" class="secondary">Attestation</a>
                    <a href="/citrust/agentic-regulatory-traceability-crosswalk" class="secondary">Reg Crosswalk</a>
                    <a href="/citrust/agentic-compliance-obligation-map" class="dark">Obligations</a>
                    <a href="/citrust/agentic-gxp-ai-governance-map" class="dark">GxP AI Map</a>
                    <a href="/citrust/agentic-regulatory-readiness-simulator" class="dark">Reg Sim</a>'''

if nav_old in text and "/citrust/agentic-regulatory-traceability-crosswalk" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# CITRUST_AGENTIC_REGULATORY_TRACEABILITY_CROSSWALK_V1_ACTIVE
# CITrust™ Agentic Regulatory Traceability Crosswalk
# Compliance Obligation Map, GxP AI Governance Map,
# AI Act / NIST / ISO / COBIT / ITIL Crosswalk,
# Regulatory Evidence Dossier, Readiness Simulator,
# and JSON Export
# ============================================================

CITRUST_AGENTIC_REGULATORY_CROSSWALK = [
    {
        "framework": "GxP / GMP Operational Assurance",
        "obligation_theme": "Regulated systems must preserve accountability, evidence, change control, validation context, and inspection defensibility.",
        "citrust_control": "GxP / Validation Guardrail, QA Attestation, Change Integration, Evidence Dossier.",
        "required_evidence": "GxP screen, validation status, QA decision, change record, rollback, post-check, owner signoff.",
        "owner": "QA / Validation Owner + Change Owner"
    },
    {
        "framework": "21 CFR Part 11 / Electronic Records Assurance",
        "obligation_theme": "Electronic records and decisions must be attributable, traceable, complete, and reviewable.",
        "citrust_control": "Observability Evidence Fabric, Agent Runtime Ledger, Attestation Package Builder.",
        "required_evidence": "Audit trail, correlation ID, tool-call evidence, reviewer signoff, electronic record linkage.",
        "owner": "Governance / Quality / System Owner"
    },
    {
        "framework": "GAMP 5 / Computerized System Assurance",
        "obligation_theme": "System risk, intended use, supplier/tool reliance, testing, change, and evidence must be proportionate and documented.",
        "citrust_control": "Control Library, Control Effectiveness Testing, AI-to-Change-Control Integration.",
        "required_evidence": "Risk classification, intended use, control test result, change route, deviation/exception route.",
        "owner": "Validation Owner + System Owner"
    },
    {
        "framework": "FDA CSA Thinking",
        "obligation_theme": "Assurance should focus on critical thinking, risk-based testing, intended use, and evidence that the process is controlled.",
        "citrust_control": "Control Effectiveness Testing Lab, Evidence Sampling Workbench, Remediation Tracker.",
        "required_evidence": "Test plan, sampled evidence, finding, remediation, retest, closure evidence.",
        "owner": "Validation / Governance Owner"
    },
    {
        "framework": "EU AI Act Readiness",
        "obligation_theme": "High-impact AI use requires governance, risk controls, human oversight, transparency, monitoring, and accountability.",
        "citrust_control": "Agent Registry, Human Approval Gate, Monitoring Center, Executive Attestation.",
        "required_evidence": "Agent purpose, risk classification, human oversight, monitoring, residual risk, owner signoff.",
        "owner": "AI Governance Owner"
    },
    {
        "framework": "NIST AI RMF Alignment",
        "obligation_theme": "AI risks should be governed, mapped, measured, managed, monitored, and communicated.",
        "citrust_control": "Control Tower, Risk Heatmap, Monitoring Center, Control Testing, Executive Brief.",
        "required_evidence": "Risk map, metrics, monitoring signals, control tests, remediation, leadership reporting.",
        "owner": "Governance / Risk Owner"
    },
    {
        "framework": "ISO/IEC 42001 AI Management System Alignment",
        "obligation_theme": "AI management requires roles, policies, risk management, lifecycle controls, monitoring, and continual improvement.",
        "citrust_control": "Operating Model, Policy Pack, RACI Matrix, Continuous Monitoring, Control Library.",
        "required_evidence": "Policy, RACI, owner route, monitoring KPI, control library, exception register.",
        "owner": "AI Management System Owner"
    },
    {
        "framework": "COBIT 2019 Governance Alignment",
        "obligation_theme": "Enterprise technology governance must define objectives, controls, ownership, performance metrics, risk response, and assurance.",
        "citrust_control": "Control Library, KPI Scorecard, RACI Authority Matrix, Attestation Center.",
        "required_evidence": "Control objective, owner, KPI, evidence, assurance result, executive attestation.",
        "owner": "Enterprise Governance Owner"
    },
    {
        "framework": "ITIL / Service Transition and Operation",
        "obligation_theme": "Operational changes, service mapping, support ownership, incidents, and change records must be controlled.",
        "citrust_control": "AI-to-Change Router, Support Route Attestation, Runtime Event Ledger, Change Closure Dossier.",
        "required_evidence": "Task/change record, support route, assignment group, rollback, post-check, closure.",
        "owner": "Service Owner / Change Owner"
    },
    {
        "framework": "ServiceNow CMDB Governance",
        "obligation_theme": "CI records must have trusted ownership, relationships, lifecycle state, support route, and evidence lineage.",
        "citrust_control": "CMDB Graph Trust Score, CI Passport, Agent-to-CI Impact Map, Relationship Confidence.",
        "required_evidence": "CI passport, owner/support/LCM fields, graph trust score, relationship confidence, orphan control.",
        "owner": "CMDB / LCM Owner"
    }
]


CITRUST_AGENTIC_COMPLIANCE_OBLIGATION_MAP = [
    {
        "obligation": "Known AI actor",
        "question": "Can we prove which AI agent acted or influenced the workflow?",
        "control": "AI Agent Registration Control",
        "evidence": "Agent ID, owner, operating license, approved use case."
    },
    {
        "obligation": "Known impacted CI",
        "question": "Can we prove which CI, CI field, relationship, service, or workflow was affected?",
        "control": "Agent-to-CI Impact Mapping Control",
        "evidence": "CI ID, field touched, relationship impact, CI passport."
    },
    {
        "obligation": "Human accountability",
        "question": "Can we prove the accountable human owner reviewed or approved the AI-influenced decision?",
        "control": "RACI Authority Matrix + Attestation Center",
        "evidence": "Owner signoff, reviewer decision, approval record."
    },
    {
        "obligation": "Regulated boundary preservation",
        "question": "Can we prove GxP, validation, QA, and inspection-sensitive boundaries were preserved?",
        "control": "GxP / Validation Guardrail",
        "evidence": "GxP screen, validation evidence, QA decision."
    },
    {
        "obligation": "Cyber and access governance",
        "question": "Can we prove MyAccess, CyberArk, PSM, privileged, and entitlement boundaries were governed?",
        "control": "Cyber / Access Guardrail",
        "evidence": "MyAccess route, CyberArk / PSM evidence, cyber decision."
    },
    {
        "obligation": "Change-control preservation",
        "question": "Can we prove material AI-assisted actions were routed to task/change/rollback/post-check?",
        "control": "AI-to-Change-Control Integration",
        "evidence": "Change/task record, rollback, post-check, closure dossier."
    },
    {
        "obligation": "Evidence replay",
        "question": "Can we replay trigger, context, prompt chain, tool call, ServiceNow log, telemetry, and outcome?",
        "control": "Observability Evidence Fabric",
        "evidence": "Correlation ID, runtime trace, ServiceNow log, tool-call log."
    },
    {
        "obligation": "Ongoing monitoring",
        "question": "Can we prove the AI workflow remains controlled after go-live?",
        "control": "Continuous Monitoring Center",
        "evidence": "Drift signals, threshold alerts, runtime KPIs, exception aging."
    },
    {
        "obligation": "Residual risk visibility",
        "question": "Can leadership see what risk remains and who accepted it?",
        "control": "Residual Risk Register",
        "evidence": "Risk owner, restriction, expiry, executive visibility."
    }
]


CITRUST_AGENTIC_GXP_AI_GOVERNANCE_MAP = [
    {
        "gxp_area": "Validation Status",
        "ai_risk": "AI may summarize, infer, or recommend validation status without approved evidence.",
        "required_guardrail": "QA / validation owner route before regulated reliance.",
        "evidence": "Validation status source, QA decision, approved evidence."
    },
    {
        "gxp_area": "GMP Classification",
        "ai_risk": "AI may misclassify regulated vs non-regulated CI or workflow.",
        "required_guardrail": "GxP screen and QA confirmation.",
        "evidence": "GMP class, system owner, QA owner, regulated impact decision."
    },
    {
        "gxp_area": "Deviation / CAPA Impact",
        "ai_risk": "Wrong AI output may create or hide a regulated deviation or CAPA implication.",
        "required_guardrail": "Deviation / CAPA assessment route.",
        "evidence": "Impact assessment, QA review, root cause, closure."
    },
    {
        "gxp_area": "Inspection Readiness",
        "ai_risk": "AI action may not be defensible during inspection because evidence chain is weak.",
        "required_guardrail": "Audit dossier and attestation package.",
        "evidence": "Evidence package, owner signoff, replay trail."
    },
    {
        "gxp_area": "Change Control",
        "ai_risk": "AI-assisted update may bypass formal change, rollback, or post-check.",
        "required_guardrail": "AI-to-change-control router.",
        "evidence": "Change record, approval, rollback, post-check."
    },
    {
        "gxp_area": "Computerized System Accountability",
        "ai_risk": "AI may become invisible contributor to a regulated computerized workflow.",
        "required_guardrail": "Agent identity, tool-call evidence, human approval, runtime ledger.",
        "evidence": "Agent ID, tool call, reviewer, decision, audit trail."
    }
]


CITRUST_AGENTIC_AI_ACT_READINESS_MAP = [
    {
        "readiness_area": "AI System Inventory",
        "citrust_response": "Agent Registry and Operating License.",
        "evidence": "Agent ID, owner, purpose, scope, affected workflows."
    },
    {
        "readiness_area": "Risk Classification",
        "citrust_response": "Risk Heatmap and Control Tower Simulator.",
        "evidence": "Risk tier, impacted CI, GxP/cyber/change impact, control decision."
    },
    {
        "readiness_area": "Human Oversight",
        "citrust_response": "Human Approval Gate, RACI Matrix, Executive Attestation.",
        "evidence": "Reviewer, owner decision, approval/rejection, escalation."
    },
    {
        "readiness_area": "Technical Documentation",
        "citrust_response": "Assurance Dossier and Attestation Package Builder.",
        "evidence": "Control library, evidence catalog, monitoring status, residual risk."
    },
    {
        "readiness_area": "Logging and Traceability",
        "citrust_response": "Observability Evidence Fabric and Runtime Event Ledger.",
        "evidence": "Telemetry, ServiceNow logs, tool-call logs, correlation ID."
    },
    {
        "readiness_area": "Post-Market / Post-Go-Live Monitoring",
        "citrust_response": "Continuous Monitoring Center and Drift Sentinel.",
        "evidence": "Runtime KPIs, threshold alerts, drift signals, exception aging."
    }
]


CITRUST_AGENTIC_NIST_ISO_COBIT_MAP = [
    {
        "governance_area": "Govern",
        "citrust_capability": "Operating Model, RACI, Policy Pack, Control Library.",
        "evidence": "Roles, authority map, policy rules, control objectives."
    },
    {
        "governance_area": "Map",
        "citrust_capability": "Agent-to-CI Impact Map, CMDB Graph Trust Score, Risk Heatmap.",
        "evidence": "CI impact, data quality, relationship confidence, risk tier."
    },
    {
        "governance_area": "Measure",
        "citrust_capability": "Runtime KPI Scorecard, Control Effectiveness Testing, Evidence Sampling.",
        "evidence": "KPI results, sample results, pass/fail findings."
    },
    {
        "governance_area": "Manage",
        "citrust_capability": "Change Integration, Remediation Tracker, Exception Register.",
        "evidence": "Task/change route, remediation, compensating control, closure."
    },
    {
        "governance_area": "Monitor",
        "citrust_capability": "Continuous Monitoring, Drift Sentinel, Threshold Alerts.",
        "evidence": "Monitoring signals, alerts, exception aging, escalation."
    },
    {
        "governance_area": "Assure",
        "citrust_capability": "Attestation Center, Audit Readiness Pack, Executive Risk Brief.",
        "evidence": "Owner certification, residual risk, leadership signoff."
    }
]


CITRUST_AGENTIC_REGULATORY_DOSSIER = [
    {
        "dossier_section": "Regulatory Scope",
        "contents": "AI agents, ServiceNow workflows, CMDB objects, GxP/cyber/change boundaries, intended use."
    },
    {
        "dossier_section": "Crosswalk Matrix",
        "contents": "Framework theme, CITrust control, required evidence, owner, testing cadence."
    },
    {
        "dossier_section": "Control Evidence",
        "contents": "Control library, evidence catalog, control test results, findings, remediation, retest."
    },
    {
        "dossier_section": "GxP / Cyber / Change Evidence",
        "contents": "QA review, validation evidence, MyAccess/CyberArk/PSM evidence, change/rollback/post-check."
    },
    {
        "dossier_section": "Monitoring Evidence",
        "contents": "Runtime KPIs, drift signals, threshold alerts, exception aging, escalation records."
    },
    {
        "dossier_section": "Attestation Evidence",
        "contents": "Control owner certifications, residual risks, executive brief, leadership signoff."
    }
]


def citrust_regulatory_crosswalk_rows():
    rows = ""
    for item in CITRUST_AGENTIC_REGULATORY_CROSSWALK:
        rows += f"""
        <tr>
            <td><strong>{item["framework"]}</strong></td>
            <td>{item["obligation_theme"]}</td>
            <td><span class="badge blue">{item["citrust_control"]}</span></td>
            <td>{item["required_evidence"]}</td>
            <td>{item["owner"]}</td>
        </tr>
        """
    return rows


def citrust_compliance_obligation_rows():
    rows = ""
    for item in CITRUST_AGENTIC_COMPLIANCE_OBLIGATION_MAP:
        rows += f"""
        <tr>
            <td><strong>{item["obligation"]}</strong></td>
            <td>{item["question"]}</td>
            <td><span class="badge blue">{item["control"]}</span></td>
            <td>{item["evidence"]}</td>
        </tr>
        """
    return rows


def citrust_gxp_ai_rows():
    rows = ""
    for item in CITRUST_AGENTIC_GXP_AI_GOVERNANCE_MAP:
        rows += f"""
        <tr>
            <td><strong>{item["gxp_area"]}</strong></td>
            <td><span class="badge red">{item["ai_risk"]}</span></td>
            <td>{item["required_guardrail"]}</td>
            <td>{item["evidence"]}</td>
        </tr>
        """
    return rows


def citrust_ai_act_rows():
    rows = ""
    for item in CITRUST_AGENTIC_AI_ACT_READINESS_MAP:
        rows += f"""
        <tr>
            <td><strong>{item["readiness_area"]}</strong></td>
            <td>{item["citrust_response"]}</td>
            <td>{item["evidence"]}</td>
        </tr>
        """
    return rows


def citrust_nist_iso_cobit_rows():
    rows = ""
    for item in CITRUST_AGENTIC_NIST_ISO_COBIT_MAP:
        rows += f"""
        <tr>
            <td><strong>{item["governance_area"]}</strong></td>
            <td><span class="badge blue">{item["citrust_capability"]}</span></td>
            <td>{item["evidence"]}</td>
        </tr>
        """
    return rows


def citrust_regulatory_dossier_rows():
    rows = ""
    for item in CITRUST_AGENTIC_REGULATORY_DOSSIER:
        rows += f"""
        <tr>
            <td><strong>{item["dossier_section"]}</strong></td>
            <td>{item["contents"]}</td>
        </tr>
        """
    return rows


def citrust_regulatory_readiness_decision(scope, crosswalk, evidence, gxp, cyber, change, monitoring, attestation, residual):
    checks = [scope, crosswalk, evidence, gxp, cyber, change, monitoring, attestation, residual]
    score = int((sum(1 for item in checks if item == "yes") / len(checks)) * 100)

    if scope != "yes":
        return score, "Regulatory Scope Missing", "red", "The AI workflow, CI scope, and regulated boundary are not defined."
    if crosswalk != "yes":
        return score, "Crosswalk Missing", "red", "Regulatory or governance obligations are not mapped to CITrust controls."
    if evidence != "yes":
        return score, "Evidence Gap", "red", "Required evidence is incomplete."
    if gxp != "yes":
        return score, "GxP Readiness Gap", "red", "GxP / validation / QA evidence is incomplete."
    if cyber != "yes":
        return score, "Cyber Readiness Gap", "red", "Access, CyberArk, PSM, or privileged evidence is incomplete."
    if change != "yes":
        return score, "Change Readiness Gap", "orange", "Task/change/rollback/post-check evidence is incomplete."
    if monitoring != "yes":
        return score, "Monitoring Gap", "orange", "Continuous monitoring and drift evidence are incomplete."
    if attestation != "yes":
        return score, "Attestation Gap", "red", "Control owner or executive attestation is missing."
    if residual != "yes":
        return score, "Residual Risk Gap", "red", "Residual risks are not accepted, restricted, or closed."
    if score == 100:
        return score, "Regulatory Traceability Ready", "green", "Obligations, controls, evidence, owners, monitoring, residual risk, and attestation are traceable."
    return score, "Conditional Regulatory Readiness", "yellow", "Regulatory traceability may proceed only with declared gaps and remediation tracking."


try:
    AGENTTRUST_EXPECTED_ROUTES.extend([
        "/citrust/agentic-regulatory-traceability-crosswalk",
        "/citrust/agentic-compliance-obligation-map",
        "/citrust/agentic-gxp-ai-governance-map",
        "/citrust/agentic-ai-act-readiness-map",
        "/citrust/agentic-nist-iso-cobit-map",
        "/citrust/agentic-regulatory-evidence-dossier",
        "/citrust/agentic-regulatory-readiness-simulator",
        "/citrust/agentic-regulatory-crosswalk-json"
    ])
except Exception:
    pass


@app.route("/citrust/agentic-regulatory-traceability-crosswalk")
@app.route("/citrust/agentic-regulatory-crosswalk")
@app.route("/citrust/ci-agentic-regulatory-crosswalk")
def citrust_agentic_regulatory_traceability_crosswalk():
    rows = citrust_regulatory_crosswalk_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Reg Crosswalk</div><div class="value" style="color:var(--green);">Active</div><div class="note">Regulatory themes mapped to CITrust controls.</div></div>
        <div class="metric"><div class="label">Framework Themes</div><div class="value" style="color:var(--blue);">10</div><div class="note">GxP, Part 11, GAMP, CSA, AI Act, NIST, ISO, COBIT, ITIL, CMDB.</div></div>
        <div class="metric"><div class="label">Evidence</div><div class="value" style="color:var(--yellow);">Traceable</div><div class="note">Each obligation maps to evidence and owner.</div></div>
        <div class="metric"><div class="label">GxP / Cyber</div><div class="value" style="color:var(--red);">Mapped</div><div class="note">Regulated and privileged boundaries are explicit.</div></div>
        <div class="metric"><div class="label">Monitoring</div><div class="value" style="color:var(--orange);">Included</div><div class="note">Post-go-live drift evidence included.</div></div>
        <div class="metric"><div class="label">Attestation</div><div class="value" style="color:var(--purple);">Linked</div><div class="note">Control owner and executive signoff included.</div></div>
    </section>

    <section class="section">
        <h2>CITrust™ Agentic Regulatory Traceability Crosswalk</h2>
        <div class="answer">
            <strong>Purpose:</strong> map external governance, regulatory, service-management, quality, and AI-risk themes
            to CITrust™ controls, evidence, owners, testing, monitoring, and attestation. This is a traceability layer,
            not a legal determination.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Framework / Domain</th>
                    <th>Obligation Theme</th>
                    <th>CITrust™ Control Response</th>
                    <th>Required Evidence</th>
                    <th>Owner</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Traceability Rule</h2>
        <div class="answer">
            A regulated AI workflow is not defensible because it uses a known platform. It becomes defensible when
            obligations are mapped to controls, controls are mapped to evidence, evidence is owned, tested, monitored,
            and attested.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Regulatory Traceability Crosswalk",
        "Regulatory traceability crosswalk for AI-assisted ServiceNow CMDB governance across GxP, Part 11, GAMP, CSA, AI Act readiness, NIST, ISO, COBIT, ITIL, and CMDB governance themes.",
        body
    )


@app.route("/citrust/agentic-compliance-obligation-map")
@app.route("/citrust/agentic-obligation-map")
@app.route("/citrust/ci-agentic-compliance-obligations")
def citrust_agentic_compliance_obligation_map():
    rows = citrust_compliance_obligation_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agentic Compliance Obligation Map</h2>
        <p>
            This map converts broad compliance obligations into CITrust™ questions, controls, and evidence.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Obligation</th>
                    <th>Question</th>
                    <th>CITrust™ Control</th>
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
        "CITrust™ Agentic Compliance Obligation Map",
        "Compliance obligation map for known AI actor, impacted CI, human accountability, regulated boundary, cyber governance, change control, evidence replay, monitoring, and residual risk.",
        body
    )


@app.route("/citrust/agentic-gxp-ai-governance-map")
@app.route("/citrust/agentic-gmp-ai-governance-map")
@app.route("/citrust/ci-agentic-gxp-ai-map")
def citrust_agentic_gxp_ai_governance_map():
    rows = citrust_gxp_ai_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ GxP AI Governance Map</h2>
        <p>
            This map focuses specifically on GxP, GMP, validation, QA, inspection, deviation, CAPA, and regulated computerized workflow risk.
        </p>

        <table>
            <thead>
                <tr>
                    <th>GxP Area</th>
                    <th>AI Risk</th>
                    <th>Required Guardrail</th>
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
        "CITrust™ GxP AI Governance Map",
        "GxP AI governance map for validation status, GMP classification, deviation/CAPA impact, inspection readiness, change control, and computerized system accountability.",
        body
    )


@app.route("/citrust/agentic-ai-act-readiness-map")
@app.route("/citrust/agentic-ai-act-map")
@app.route("/citrust/ci-agentic-ai-act-readiness")
def citrust_agentic_ai_act_readiness_map():
    rows = citrust_ai_act_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ AI Act Readiness Map</h2>
        <p>
            This map positions CITrust™ evidence against common AI governance readiness areas such as inventory,
            risk classification, human oversight, technical documentation, traceability, and post-go-live monitoring.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Readiness Area</th>
                    <th>CITrust™ Response</th>
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
        "CITrust™ AI Act Readiness Map",
        "AI governance readiness map for inventory, risk classification, human oversight, documentation, logging, traceability, and post-go-live monitoring.",
        body
    )


@app.route("/citrust/agentic-nist-iso-cobit-map")
@app.route("/citrust/agentic-governance-framework-map")
@app.route("/citrust/ci-agentic-nist-iso-cobit")
def citrust_agentic_nist_iso_cobit_map():
    rows = citrust_nist_iso_cobit_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ NIST / ISO / COBIT Governance Map</h2>
        <p>
            This map shows how CITrust™ capabilities support governance, mapping, measurement, management, monitoring, and assurance themes.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Governance Area</th>
                    <th>CITrust™ Capability</th>
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
        "CITrust™ NIST ISO COBIT Governance Map",
        "Governance map linking CITrust capabilities to govern, map, measure, manage, monitor, and assure themes.",
        body
    )


@app.route("/citrust/agentic-regulatory-evidence-dossier")
@app.route("/citrust/agentic-regulatory-dossier")
@app.route("/citrust/ci-agentic-regulatory-dossier")
def citrust_agentic_regulatory_evidence_dossier():
    rows = citrust_regulatory_dossier_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agentic Regulatory Evidence Dossier</h2>
        <p>
            This dossier organizes the evidence needed to show regulatory and governance traceability for AI-assisted CI workflows.
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
        <h2>Dossier Rule</h2>
        <div class="answer">
            The dossier must show scope, obligation mapping, control evidence, GxP/cyber/change evidence,
            monitoring evidence, residual risk, and attestation evidence.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Regulatory Evidence Dossier",
        "Regulatory evidence dossier for AI-assisted CITrust workflows including regulatory scope, crosswalk matrix, control evidence, GxP/cyber/change evidence, monitoring, and attestation.",
        body
    )


@app.route("/citrust/agentic-regulatory-readiness-simulator", methods=["GET", "POST"])
@app.route("/citrust/agentic-regulatory-simulator", methods=["GET", "POST"])
@app.route("/citrust/ci-agentic-regulatory-readiness-simulator", methods=["GET", "POST"])
def citrust_agentic_regulatory_readiness_simulator():
    from flask import request

    scope = request.form.get("scope", "yes")
    crosswalk = request.form.get("crosswalk", "yes")
    evidence = request.form.get("evidence", "yes")
    gxp = request.form.get("gxp", "yes")
    cyber = request.form.get("cyber", "yes")
    change = request.form.get("change", "yes")
    monitoring = request.form.get("monitoring", "yes")
    attestation = request.form.get("attestation", "yes")
    residual = request.form.get("residual", "yes")

    score, decision, badge, reason = citrust_regulatory_readiness_decision(
        scope, crosswalk, evidence, gxp, cyber, change, monitoring, attestation, residual
    )

    def selected(value, expected):
        return "selected" if value == expected else ""

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Regulatory Traceability Score</div><div class="value" style="color:var(--green);">{score}%</div><div class="note">Calculated from traceability domains.</div></div>
        <div class="metric"><div class="label">Readiness Decision</div><div class="value" style="color:var(--yellow);">{decision}</div><div class="note">{reason}</div></div>
    </section>

    <section class="section">
        <h2>CITrust™ Regulatory Readiness Simulator</h2>
        <p>
            Simulate whether AI-assisted ServiceNow / CMDB / GxP / cyber / change workflows have enough
            obligation-to-control-to-evidence traceability for governance review.
        </p>

        <form method="POST" action="/citrust/agentic-regulatory-readiness-simulator">
            <table>
                <tbody>
                    <tr><td><strong>Regulatory / Governance Scope Defined?</strong></td><td><select name="scope" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(scope, "yes")}>Yes</option><option value="no" {selected(scope, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Obligation-to-Control Crosswalk Complete?</strong></td><td><select name="crosswalk" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(crosswalk, "yes")}>Yes</option><option value="no" {selected(crosswalk, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Required Evidence Complete?</strong></td><td><select name="evidence" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(evidence, "yes")}>Yes</option><option value="no" {selected(evidence, "no")}>No</option></select></td></tr>
                    <tr><td><strong>GxP / QA / Validation Evidence Complete?</strong></td><td><select name="gxp" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(gxp, "yes")}>Yes</option><option value="no" {selected(gxp, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Cyber / Access / Privileged Evidence Complete?</strong></td><td><select name="cyber" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(cyber, "yes")}>Yes</option><option value="no" {selected(cyber, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Change / Rollback / Post-Check Evidence Complete?</strong></td><td><select name="change" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(change, "yes")}>Yes</option><option value="no" {selected(change, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Continuous Monitoring Evidence Complete?</strong></td><td><select name="monitoring" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(monitoring, "yes")}>Yes</option><option value="no" {selected(monitoring, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Control Owner / Executive Attestation Complete?</strong></td><td><select name="attestation" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(attestation, "yes")}>Yes</option><option value="no" {selected(attestation, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Residual Risk Accepted / Restricted / Closed?</strong></td><td><select name="residual" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(residual, "yes")}>Yes</option><option value="no" {selected(residual, "no")}>No</option></select></td></tr>
                </tbody>
            </table>

            <button type="submit" style="margin-top:16px;padding:12px 18px;border-radius:12px;border:0;background:#2563eb;color:white;font-weight:800;">Run Regulatory Traceability Check</button>
        </form>
    </section>

    <section class="section">
        <h2>Regulatory Traceability Decision</h2>
        <div class="answer">
            <strong>Score:</strong> {score}%<br>
            <strong>Decision:</strong> <span class="badge {badge}">{decision}</span><br>
            <strong>Reason:</strong> {reason}
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Regulatory Readiness Simulator",
        "Simulator for regulatory traceability across scope, crosswalk, evidence, GxP, cyber, change, monitoring, attestation, and residual risk.",
        body
    )


@app.route("/citrust/agentic-regulatory-crosswalk-json")
@app.route("/citrust/agentic-regulatory-json")
@app.route("/citrust/ci-agentic-regulatory-crosswalk-json")
def citrust_agentic_regulatory_crosswalk_json():
    from flask import jsonify

    return jsonify({
        "module": "CITrust™",
        "capability": "Agentic Regulatory Traceability Crosswalk + Compliance Obligation Map",
        "primary_question": "Can AI-assisted ServiceNow / CMDB / GxP / cyber / change workflows be traced from governance obligations to CITrust controls, evidence, owners, testing, monitoring, and attestation?",
        "regulatory_crosswalk": CITRUST_AGENTIC_REGULATORY_CROSSWALK,
        "compliance_obligation_map": CITRUST_AGENTIC_COMPLIANCE_OBLIGATION_MAP,
        "gxp_ai_governance_map": CITRUST_AGENTIC_GXP_AI_GOVERNANCE_MAP,
        "ai_act_readiness_map": CITRUST_AGENTIC_AI_ACT_READINESS_MAP,
        "nist_iso_cobit_map": CITRUST_AGENTIC_NIST_ISO_COBIT_MAP,
        "regulatory_dossier": CITRUST_AGENTIC_REGULATORY_DOSSIER,
        "minimum_conditions": [
            "Regulatory and governance scope is defined",
            "Obligations are mapped to CITrust controls",
            "Controls are mapped to evidence",
            "Evidence owners are assigned",
            "GxP / validation evidence is complete where applicable",
            "Cyber / access evidence is complete where applicable",
            "Change / rollback / post-check evidence is complete where applicable",
            "Continuous monitoring evidence is complete",
            "Residual risk is visible and owned",
            "Control owner and executive attestation are complete"
        ],
        "default_decision": "Do not represent an AI-assisted CITrust workflow as regulatory-traceable unless obligations, controls, evidence, owners, monitoring, residual risk, and attestation are linked"
    })

# ============================================================
# END CITRUST_AGENTIC_REGULATORY_TRACEABILITY_CROSSWALK_V1_ACTIVE
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

print("CITrust Agentic Regulatory Traceability Crosswalk installed.")
print(f"Inserted before: {target_found}")
