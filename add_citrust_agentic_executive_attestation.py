from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_AGENTIC_EXECUTIVE_ATTESTATION_CENTER_V1_ACTIVE"

if MARKER in text:
    print("CITrust Agentic Executive Attestation Center already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base shell not found. Install AgentTrust base module first.")

nav_old = '<a href="/citrust/agentic-continuous-monitoring-center" class="secondary">Monitoring</a>'
nav_new = '''<a href="/citrust/agentic-continuous-monitoring-center" class="secondary">Monitoring</a>
                    <a href="/citrust/agentic-executive-attestation-center" class="secondary">Attestation</a>
                    <a href="/citrust/agentic-control-owner-certification" class="dark">Owner Cert</a>
                    <a href="/citrust/agentic-residual-risk-register" class="dark">Residual Risk</a>
                    <a href="/citrust/agentic-attestation-simulator" class="dark">Attestation Sim</a>'''

if nav_old in text and "/citrust/agentic-executive-attestation-center" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# CITRUST_AGENTIC_EXECUTIVE_ATTESTATION_CENTER_V1_ACTIVE
# CITrust™ Agentic Executive Attestation Center
# Control Owner Certification Ledger, QA / Cyber / Change Attestation,
# Residual Risk Register, Executive Risk Brief,
# Attestation Package Builder, Signoff Simulator, and JSON Export
# ============================================================

CITRUST_AGENTIC_ATTESTATION_DOMAINS = [
    {
        "domain": "AI Agent Ownership",
        "attestor": "AI Agent Owner",
        "attestation_statement": "I confirm the AI agent is registered, owner-controlled, operating within approved scope, and has an active operating license.",
        "evidence_required": "Agent registry, operating license, use-case scope, owner signoff, review cadence.",
        "risk_if_unsigned": "Agent may operate without accountable ownership."
    },
    {
        "domain": "CI / CMDB Trust",
        "attestor": "CMDB / CI Owner",
        "attestation_statement": "I confirm the affected CIs have sufficient owner, support, LCM, lifecycle, relationship, and evidence completeness for AI-assisted reliance.",
        "evidence_required": "CI passport, graph trust score, ownership fields, support group, LCM, relationship confidence.",
        "risk_if_unsigned": "AI may rely on weak or ownerless CMDB data."
    },
    {
        "domain": "LCM / Lifecycle Accountability",
        "attestor": "LCM Owner",
        "attestation_statement": "I confirm lifecycle ownership, operational state, readiness route, and CI lifecycle accountability are assigned and current.",
        "evidence_required": "LCM assignment, lifecycle state, readiness evidence, owner confirmation.",
        "risk_if_unsigned": "Lifecycle and operational responsibility may be unclear."
    },
    {
        "domain": "System / Business Ownership",
        "attestor": "System Owner / Business Owner",
        "attestation_statement": "I confirm business and operational accountability for the system impact of AI-assisted CI workflow decisions.",
        "evidence_required": "System owner approval, operational impact review, readiness acceptance.",
        "risk_if_unsigned": "AI output may become operationally binding without business acceptance."
    },
    {
        "domain": "Support / Service Route",
        "attestor": "Support / Service Owner",
        "attestation_statement": "I confirm support group, assignment group, resolver route, escalation path, and service ownership are accurate.",
        "evidence_required": "Support group evidence, before/after support route, service owner confirmation.",
        "risk_if_unsigned": "AI may route incidents, requests, or operational issues to the wrong support group."
    },
    {
        "domain": "QA / Validation",
        "attestor": "QA / Validation Owner",
        "attestation_statement": "I confirm GxP, validation, QA, deviation, CAPA, inspection-sensitive, and regulated reliance boundaries are reviewed.",
        "evidence_required": "GxP screen, validation evidence, QA decision, regulated reliance decision.",
        "risk_if_unsigned": "Regulated AI reliance may be unsupported."
    },
    {
        "domain": "Cyber / Access / Privileged Route",
        "attestor": "Cybersecurity / Access Owner",
        "attestation_statement": "I confirm access, MyAccess, CyberArk, PSM, privileged route, entitlement, and least-privilege boundaries are governed.",
        "evidence_required": "MyAccess route, approver group, entitlement evidence, CyberArk / PSM evidence, cyber decision.",
        "risk_if_unsigned": "AI may influence access or privileged workflows without cyber control."
    },
    {
        "domain": "Change / Rollback / Post-Check",
        "attestor": "Change Owner",
        "attestation_statement": "I confirm material AI-assisted CI actions have required task/change route, rollback, post-check, and closure evidence.",
        "evidence_required": "Change/task record, approval, before/after, rollback, post-check, closure.",
        "risk_if_unsigned": "AI-influenced operational change may not be defensible."
    },
    {
        "domain": "Governance / Assurance Closure",
        "attestor": "Governance / Assurance Owner",
        "attestation_statement": "I confirm control evidence, testing, findings, remediation, monitoring, exceptions, residual risk, and attestation package are complete.",
        "evidence_required": "Control testing results, findings register, remediation tracker, monitoring status, residual risk register.",
        "risk_if_unsigned": "Leadership may not have a defensible assurance conclusion."
    }
]


CITRUST_CONTROL_OWNER_CERTIFICATION_LEDGER = [
    {
        "certification": "Control Design Certification",
        "certifier": "Governance / Assurance Owner",
        "certifies": "Control objective, owner, evidence requirement, test cadence, exception route, and audit replay are defined.",
        "evidence": "Control library, evidence catalog, testing cadence, exception register."
    },
    {
        "certification": "Control Operating Certification",
        "certifier": "Control Owner",
        "certifies": "Control is operating as designed for sampled AI-assisted CI workflows.",
        "evidence": "Control effectiveness test result, evidence sample, pass/fail outcome."
    },
    {
        "certification": "Evidence Completeness Certification",
        "certifier": "Evidence Owner / Governance Owner",
        "certifies": "Required evidence exists for agent identity, CI impact, GxP, cyber, memory, observability, change, and closure.",
        "evidence": "Assurance dossier, observability evidence, ServiceNow evidence, QA/cyber/change evidence."
    },
    {
        "certification": "Remediation Closure Certification",
        "certifier": "Finding Owner",
        "certifies": "Findings have been contained, remediated, retested, and closed with evidence.",
        "evidence": "Findings register, remediation tracker, retest evidence, closure signoff."
    },
    {
        "certification": "Exception Validity Certification",
        "certifier": "Risk Owner / Governance Owner",
        "certifies": "Open exceptions are owned, time-bound, restricted, monitored, and not expired.",
        "evidence": "Exception register, exception aging monitor, compensating control, expiry date."
    },
    {
        "certification": "Continuous Monitoring Certification",
        "certifier": "Monitoring Owner / Governance Owner",
        "certifies": "Runtime monitoring, drift signals, threshold alerts, exception aging, and escalation routes are active.",
        "evidence": "Monitoring dashboard, drift register, KPI scorecard, alert history."
    }
]


CITRUST_QA_CYBER_CHANGE_ATTESTATIONS = [
    {
        "attestation_type": "QA / Validation Attestation",
        "trigger": "AI output touches GMP, validation, QA, release, deviation, CAPA, or inspection-sensitive context.",
        "required_statement": "QA confirms whether AI output may be used, restricted, rejected, or routed to deviation/CAPA.",
        "required_evidence": "QA review, validation evidence, GxP screen, regulated reliance decision.",
        "default_if_missing": "No regulated reliance."
    },
    {
        "attestation_type": "Cyber / Access Attestation",
        "trigger": "AI output touches MyAccess, CyberArk, PSM, entitlement, admin, privileged route, or support-group access.",
        "required_statement": "Cyber confirms access path, least privilege, privileged route, and no autonomous AI approval.",
        "required_evidence": "MyAccess record, CyberArk / PSM evidence, entitlement approval, cyber decision.",
        "default_if_missing": "No access or privileged reliance."
    },
    {
        "attestation_type": "Change-Control Attestation",
        "trigger": "AI output becomes material CI update, relationship update, lifecycle update, support route update, or cutover-sensitive action.",
        "required_statement": "Change owner confirms task/change route, approval, rollback, post-check, and closure evidence.",
        "required_evidence": "Change/task record, approval, rollback, post-check, closure dossier.",
        "default_if_missing": "No execution or closure."
    },
    {
        "attestation_type": "CMDB / LCM Attestation",
        "trigger": "AI output relies on CI owner, support group, lifecycle, relationship, CI passport, or graph trust data.",
        "required_statement": "CMDB / LCM owner confirms CI data is complete enough for AI-assisted use.",
        "required_evidence": "CI passport, graph trust score, owner/support/LCM fields, relationship confidence.",
        "default_if_missing": "Restrict AI reliance."
    },
    {
        "attestation_type": "System Owner Attestation",
        "trigger": "AI output affects operational readiness, support model, service impact, or business process reliance.",
        "required_statement": "System owner confirms operational acceptance and impact awareness.",
        "required_evidence": "Operational impact review, owner decision, readiness acceptance.",
        "default_if_missing": "No operational reliance."
    }
]


CITRUST_RESIDUAL_RISK_REGISTER = [
    {
        "risk_id": "RR-001",
        "residual_risk": "AI recommendation used with incomplete CI ownership evidence",
        "risk_owner": "CMDB / LCM Owner",
        "restriction": "Advisory only; no CI update or operational reliance.",
        "expiry_condition": "CI owner, support group, LCM, and CI passport completed.",
        "executive_visibility": "Required if high-impact CI."
    },
    {
        "risk_id": "RR-002",
        "residual_risk": "AI output used while prompt chain evidence is incomplete",
        "risk_owner": "AI Agent Owner / Governance Owner",
        "restriction": "No audit-defensible closure; recommendation only.",
        "expiry_condition": "Prompt chain capture restored and sampled.",
        "executive_visibility": "Required if repeated."
    },
    {
        "risk_id": "RR-003",
        "residual_risk": "AI memory or context freshness cannot be fully proven",
        "risk_owner": "Data Owner / AI Agent Owner",
        "restriction": "Refresh context before reliance; suppress stale memory.",
        "expiry_condition": "Context provenance and freshness evidence complete.",
        "executive_visibility": "Required if GxP, cyber, or change impact exists."
    },
    {
        "risk_id": "RR-004",
        "residual_risk": "Telemetry correlation is incomplete",
        "risk_owner": "Observability / Governance Owner",
        "restriction": "No audit-ready closure until evidence is reconstructed.",
        "expiry_condition": "Correlation ID, ServiceNow log, runtime log, and tool-call evidence restored.",
        "executive_visibility": "Required for material CI actions."
    },
    {
        "risk_id": "RR-005",
        "residual_risk": "GxP evidence not yet reviewed",
        "risk_owner": "QA / Validation Owner",
        "restriction": "No regulated reliance.",
        "expiry_condition": "QA / validation owner decision complete.",
        "executive_visibility": "Always required for regulated impact."
    },
    {
        "risk_id": "RR-006",
        "residual_risk": "Cyber / access evidence not yet reviewed",
        "risk_owner": "Cybersecurity / Access Owner",
        "restriction": "No access, CyberArk, PSM, privileged, or entitlement action.",
        "expiry_condition": "Cyber / access owner decision complete.",
        "executive_visibility": "Always required for privileged impact."
    },
    {
        "risk_id": "RR-007",
        "residual_risk": "Change rollback or post-check incomplete",
        "risk_owner": "Change Owner / System Owner",
        "restriction": "No closure; reopen task or change route.",
        "expiry_condition": "Rollback and post-check evidence complete.",
        "executive_visibility": "Required for material operational impact."
    }
]


CITRUST_EXECUTIVE_RISK_BRIEF = [
    {
        "brief_section": "Executive Trust Question",
        "content": "Can leadership defend that AI-assisted ServiceNow / CMDB workflows are registered, owner-controlled, evidence-backed, monitored, and human-governed?"
    },
    {
        "brief_section": "Assurance Position",
        "content": "CITrust™ does not certify that an AI model is perfect. It certifies whether the operational governance around AI-assisted CI actions is defensible."
    },
    {
        "brief_section": "Leadership Risk View",
        "content": "Leadership should see unresolved risk across agent identity, CI trust, GxP, cyber, memory, observability, change, exceptions, and residual risk."
    },
    {
        "brief_section": "Signoff Standard",
        "content": "Executive signoff should only occur after control owners certify their domains and residual risks are accepted, restricted, or closed."
    },
    {
        "brief_section": "Audit Defense",
        "content": "The attestation package should show who approved what, based on what evidence, under what limitations, and with what residual risk."
    }
]


CITRUST_ATTESTATION_PACKAGE_BUILDER = [
    {
        "package_section": "Scope and Agent Inventory",
        "required_contents": "AI agents, use cases, ServiceNow workflows, affected CIs, CI classes, owners, operating licenses."
    },
    {
        "package_section": "CI / CMDB Assurance",
        "required_contents": "CI passports, graph trust scores, owner/support/LCM completeness, relationship confidence, orphan status."
    },
    {
        "package_section": "GxP / Cyber / Change Evidence",
        "required_contents": "QA decision, validation evidence, cyber/access decision, MyAccess, CyberArk/PSM evidence, change records."
    },
    {
        "package_section": "Control Testing and Findings",
        "required_contents": "Control test plan, evidence samples, findings register, remediation tracker, retest gate results."
    },
    {
        "package_section": "Continuous Monitoring",
        "required_contents": "Monitoring domains, drift signals, threshold alerts, runtime KPIs, exception aging, escalation routes."
    },
    {
        "package_section": "Residual Risk",
        "required_contents": "Open residual risks, restrictions, owners, expiry conditions, compensating controls, executive visibility."
    },
    {
        "package_section": "Control Owner Certifications",
        "required_contents": "Agent owner, CMDB, LCM, system owner, support, QA, cyber, change, governance certifications."
    },
    {
        "package_section": "Executive Attestation",
        "required_contents": "Executive conclusion, reliance boundary, accepted residual risks, limitations, next review date."
    }
]


def citrust_attestation_domain_rows():
    rows = ""
    for item in CITRUST_AGENTIC_ATTESTATION_DOMAINS:
        rows += f"""
        <tr>
            <td><strong>{item["domain"]}</strong></td>
            <td><span class="badge blue">{item["attestor"]}</span></td>
            <td>{item["attestation_statement"]}</td>
            <td>{item["evidence_required"]}</td>
            <td><span class="badge red">{item["risk_if_unsigned"]}</span></td>
        </tr>
        """
    return rows


def citrust_control_owner_certification_rows():
    rows = ""
    for item in CITRUST_CONTROL_OWNER_CERTIFICATION_LEDGER:
        rows += f"""
        <tr>
            <td><strong>{item["certification"]}</strong></td>
            <td>{item["certifier"]}</td>
            <td>{item["certifies"]}</td>
            <td>{item["evidence"]}</td>
        </tr>
        """
    return rows


def citrust_qa_cyber_change_attestation_rows():
    rows = ""
    for item in CITRUST_QA_CYBER_CHANGE_ATTESTATIONS:
        rows += f"""
        <tr>
            <td><strong>{item["attestation_type"]}</strong></td>
            <td>{item["trigger"]}</td>
            <td>{item["required_statement"]}</td>
            <td>{item["required_evidence"]}</td>
            <td><span class="badge red">{item["default_if_missing"]}</span></td>
        </tr>
        """
    return rows


def citrust_residual_risk_rows():
    rows = ""
    for item in CITRUST_RESIDUAL_RISK_REGISTER:
        rows += f"""
        <tr>
            <td><strong>{item["risk_id"]}</strong></td>
            <td>{item["residual_risk"]}</td>
            <td>{item["risk_owner"]}</td>
            <td><span class="badge orange">{item["restriction"]}</span></td>
            <td>{item["expiry_condition"]}</td>
            <td><span class="badge yellow">{item["executive_visibility"]}</span></td>
        </tr>
        """
    return rows


def citrust_executive_brief_rows():
    rows = ""
    for item in CITRUST_EXECUTIVE_RISK_BRIEF:
        rows += f"""
        <tr>
            <td><strong>{item["brief_section"]}</strong></td>
            <td>{item["content"]}</td>
        </tr>
        """
    return rows


def citrust_attestation_package_rows():
    rows = ""
    for item in CITRUST_ATTESTATION_PACKAGE_BUILDER:
        rows += f"""
        <tr>
            <td><strong>{item["package_section"]}</strong></td>
            <td>{item["required_contents"]}</td>
        </tr>
        """
    return rows


def citrust_attestation_decision(agent, cmdb, qa, cyber, change, testing, monitoring, residual, executive):
    checks = [agent, cmdb, qa, cyber, change, testing, monitoring, residual, executive]
    score = int((sum(1 for item in checks if item == "yes") / len(checks)) * 100)

    if agent != "yes":
        return score, "Agent Owner Attestation Missing", "red", "AI agent ownership and operating license are not certified."
    if cmdb != "yes":
        return score, "CMDB / CI Attestation Missing", "red", "CI trust, owner, support, LCM, and relationship evidence are not certified."
    if qa != "yes":
        return score, "QA Attestation Required", "red", "GxP / validation / regulated reliance has not been attested."
    if cyber != "yes":
        return score, "Cyber Attestation Required", "red", "Access, MyAccess, CyberArk, PSM, or privileged route has not been attested."
    if change != "yes":
        return score, "Change Attestation Required", "orange", "Material AI-assisted CI action does not have change, rollback, and post-check attestation."
    if testing != "yes":
        return score, "Control Testing Certification Missing", "orange", "Control effectiveness test, findings, remediation, or retest evidence is incomplete."
    if monitoring != "yes":
        return score, "Monitoring Certification Missing", "orange", "Continuous monitoring, drift, threshold, and exception aging evidence is incomplete."
    if residual != "yes":
        return score, "Residual Risk Signoff Missing", "red", "Residual risks are not accepted, restricted, or closed."
    if executive != "yes":
        return score, "Executive Signoff Missing", "red", "Executive attestation has not been completed."
    if score == 100:
        return score, "Attestation Complete", "green", "Control owners and leadership have certified evidence, residual risk, monitoring, and reliance boundary."
    return score, "Conditional Attestation", "yellow", "Attestation may proceed only with restrictions and remediation tracking."


try:
    AGENTTRUST_EXPECTED_ROUTES.extend([
        "/citrust/agentic-executive-attestation-center",
        "/citrust/agentic-control-owner-certification",
        "/citrust/agentic-qa-cyber-change-attestation",
        "/citrust/agentic-residual-risk-register",
        "/citrust/agentic-executive-risk-brief",
        "/citrust/agentic-attestation-package-builder",
        "/citrust/agentic-attestation-simulator",
        "/citrust/agentic-attestation-json"
    ])
except Exception:
    pass


@app.route("/citrust/agentic-executive-attestation-center")
@app.route("/citrust/agentic-attestation-center")
@app.route("/citrust/ci-agentic-executive-attestation")
def citrust_agentic_executive_attestation_center():
    rows = citrust_attestation_domain_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Attestation Center</div><div class="value" style="color:var(--green);">Active</div><div class="note">Control owner and executive certification layer installed.</div></div>
        <div class="metric"><div class="label">Attestation Domains</div><div class="value" style="color:var(--blue);">9</div><div class="note">Agent, CMDB, LCM, system, support, QA, cyber, change, governance.</div></div>
        <div class="metric"><div class="label">QA / Cyber / Change</div><div class="value" style="color:var(--red);">Required</div><div class="note">Regulated, privileged, and material CI impacts require owner attestation.</div></div>
        <div class="metric"><div class="label">Residual Risk</div><div class="value" style="color:var(--orange);">Visible</div><div class="note">Open risks must be accepted, restricted, or closed.</div></div>
        <div class="metric"><div class="label">Executive Brief</div><div class="value" style="color:var(--yellow);">Ready</div><div class="note">Leadership sees the trust boundary and limitations.</div></div>
        <div class="metric"><div class="label">Audit Defense</div><div class="value" style="color:var(--purple);">Signoff-Based</div><div class="note">Who approved what, based on what evidence.</div></div>
    </section>

    <section class="section">
        <h2>CITrust™ Agentic Executive Attestation Center</h2>
        <div class="answer">
            <strong>Purpose:</strong> convert CITrust™ testing, monitoring, residual risk, and evidence closure into
            formal control-owner and executive attestation for AI-assisted ServiceNow / CMDB / GxP / cyber / change workflows.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Domain</th>
                    <th>Attestor</th>
                    <th>Attestation Statement</th>
                    <th>Evidence Required</th>
                    <th>Risk If Unsigned</th>
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
            AI-assisted CI workflows should not be represented as trusted unless the relevant control owners have
            certified their evidence domains and leadership has visibility into residual risk and reliance boundaries.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Executive Attestation Center",
        "Executive attestation center for AI-assisted ServiceNow CMDB, CI trust, GxP, cyber, access, change, monitoring, control testing, residual risk, and evidence closure.",
        body
    )


@app.route("/citrust/agentic-control-owner-certification")
@app.route("/citrust/agentic-owner-certification")
@app.route("/citrust/ci-agentic-control-owner-certification")
def citrust_agentic_control_owner_certification():
    rows = citrust_control_owner_certification_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Control Owner Certification Ledger</h2>
        <p>
            This ledger defines what each control owner certifies before leadership relies on AI-assisted CITrust workflows.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Certification</th>
                    <th>Certifier</th>
                    <th>Certifies</th>
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
        "CITrust™ Control Owner Certification Ledger",
        "Control owner certification ledger for control design, operating effectiveness, evidence completeness, remediation closure, exception validity, and continuous monitoring.",
        body
    )


@app.route("/citrust/agentic-qa-cyber-change-attestation")
@app.route("/citrust/qa-cyber-change-attestation")
@app.route("/citrust/ci-agentic-domain-attestation")
def citrust_agentic_qa_cyber_change_attestation():
    rows = citrust_qa_cyber_change_attestation_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ QA / Cyber / Change Attestation</h2>
        <p>
            Regulated, access-sensitive, privileged, and material CI actions need domain-owner attestation before reliance.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Attestation Type</th>
                    <th>Trigger</th>
                    <th>Required Statement</th>
                    <th>Required Evidence</th>
                    <th>Default If Missing</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ QA Cyber Change Attestation",
        "QA, cyber, change, CMDB, LCM, and system-owner attestations for AI-assisted ServiceNow / CMDB workflows.",
        body
    )


@app.route("/citrust/agentic-residual-risk-register")
@app.route("/citrust/agentic-residual-risk")
@app.route("/citrust/ci-agentic-residual-risk-register")
def citrust_agentic_residual_risk_register():
    rows = citrust_residual_risk_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agentic Residual Risk Register</h2>
        <p>
            Residual risks are risks that remain after controls, testing, remediation, and monitoring have been applied.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Risk ID</th>
                    <th>Residual Risk</th>
                    <th>Risk Owner</th>
                    <th>Restriction</th>
                    <th>Expiry / Closure Condition</th>
                    <th>Executive Visibility</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Residual Risk Rule</h2>
        <div class="answer">
            Residual risk must not be hidden inside AI output. CITrust™ makes residual risk visible, owned, restricted,
            time-bound, and either accepted or closed.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Residual Risk Register",
        "Residual risk register for AI-assisted CITrust workflows with restrictions, owners, expiry conditions, and executive visibility.",
        body
    )


@app.route("/citrust/agentic-executive-risk-brief")
@app.route("/citrust/agentic-board-risk-brief")
@app.route("/citrust/ci-agentic-executive-risk-brief")
def citrust_agentic_executive_risk_brief():
    rows = citrust_executive_brief_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agentic Executive Risk Brief</h2>
        <p>
            This brief translates technical AI / CMDB / ServiceNow governance evidence into leadership-level risk language.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Brief Section</th>
                    <th>Content</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Executive Risk Brief",
        "Executive risk brief for AI-assisted ServiceNow / CMDB trust, evidence, residual risk, leadership signoff, and audit defense.",
        body
    )


@app.route("/citrust/agentic-attestation-package-builder")
@app.route("/citrust/agentic-signoff-package-builder")
@app.route("/citrust/ci-agentic-attestation-package")
def citrust_agentic_attestation_package_builder():
    rows = citrust_attestation_package_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agentic Attestation Package Builder</h2>
        <p>
            This package builder defines the evidence bundle required for control-owner and executive attestation.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Package Section</th>
                    <th>Required Contents</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Package Rule</h2>
        <div class="answer">
            A leadership signoff package must show scope, CI assurance, GxP/cyber/change evidence, control testing,
            monitoring, residual risk, control-owner certifications, and final executive attestation.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Attestation Package Builder",
        "Attestation package builder for scope, CI assurance, GxP/cyber/change evidence, control testing, monitoring, residual risk, owner certifications, and executive attestation.",
        body
    )


@app.route("/citrust/agentic-attestation-simulator", methods=["GET", "POST"])
@app.route("/citrust/agentic-signoff-simulator", methods=["GET", "POST"])
@app.route("/citrust/ci-agentic-attestation-simulator", methods=["GET", "POST"])
def citrust_agentic_attestation_simulator():
    from flask import request

    agent = request.form.get("agent", "yes")
    cmdb = request.form.get("cmdb", "yes")
    qa = request.form.get("qa", "yes")
    cyber = request.form.get("cyber", "yes")
    change = request.form.get("change", "yes")
    testing = request.form.get("testing", "yes")
    monitoring = request.form.get("monitoring", "yes")
    residual = request.form.get("residual", "yes")
    executive = request.form.get("executive", "yes")

    score, decision, badge, reason = citrust_attestation_decision(
        agent, cmdb, qa, cyber, change, testing, monitoring, residual, executive
    )

    def selected(value, expected):
        return "selected" if value == expected else ""

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Attestation Score</div><div class="value" style="color:var(--green);">{score}%</div><div class="note">Calculated from control owner and executive signoff domains.</div></div>
        <div class="metric"><div class="label">Attestation Decision</div><div class="value" style="color:var(--yellow);">{decision}</div><div class="note">{reason}</div></div>
    </section>

    <section class="section">
        <h2>CITrust™ Agentic Attestation Simulator</h2>
        <p>
            Simulate whether an AI-assisted CITrust workflow has enough owner certification, residual risk control,
            monitoring evidence, and executive signoff to be represented as trusted.
        </p>

        <form method="POST" action="/citrust/agentic-attestation-simulator">
            <table>
                <tbody>
                    <tr><td><strong>AI Agent Owner Attestation Complete?</strong></td><td><select name="agent" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(agent, "yes")}>Yes</option><option value="no" {selected(agent, "no")}>No</option></select></td></tr>
                    <tr><td><strong>CMDB / CI / LCM Attestation Complete?</strong></td><td><select name="cmdb" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(cmdb, "yes")}>Yes</option><option value="no" {selected(cmdb, "no")}>No</option></select></td></tr>
                    <tr><td><strong>QA / Validation Attestation Complete?</strong></td><td><select name="qa" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(qa, "yes")}>Yes</option><option value="no" {selected(qa, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Cyber / Access Attestation Complete?</strong></td><td><select name="cyber" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(cyber, "yes")}>Yes</option><option value="no" {selected(cyber, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Change / Rollback / Post-Check Attestation Complete?</strong></td><td><select name="change" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(change, "yes")}>Yes</option><option value="no" {selected(change, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Control Testing Certification Complete?</strong></td><td><select name="testing" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(testing, "yes")}>Yes</option><option value="no" {selected(testing, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Continuous Monitoring Certification Complete?</strong></td><td><select name="monitoring" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(monitoring, "yes")}>Yes</option><option value="no" {selected(monitoring, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Residual Risk Accepted / Restricted / Closed?</strong></td><td><select name="residual" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(residual, "yes")}>Yes</option><option value="no" {selected(residual, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Executive Signoff Complete?</strong></td><td><select name="executive" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(executive, "yes")}>Yes</option><option value="no" {selected(executive, "no")}>No</option></select></td></tr>
                </tbody>
            </table>

            <button type="submit" style="margin-top:16px;padding:12px 18px;border-radius:12px;border:0;background:#2563eb;color:white;font-weight:800;">Run Attestation Readiness Check</button>
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
        "CITrust™ Agentic Attestation Simulator",
        "Simulator for CITrust control-owner certification, QA/cyber/change attestation, residual risk, monitoring certification, and executive signoff.",
        body
    )


@app.route("/citrust/agentic-attestation-json")
@app.route("/citrust/agentic-executive-attestation-json")
@app.route("/citrust/ci-agentic-attestation-json")
def citrust_agentic_attestation_json():
    from flask import jsonify

    return jsonify({
        "module": "CITrust™",
        "capability": "Agentic Executive Attestation Center + Control Owner Certification Ledger",
        "primary_question": "Can leadership defensibly attest that AI-assisted ServiceNow / CMDB / GxP / cyber / change workflows are governed, evidenced, monitored, and residual-risk controlled?",
        "attestation_domains": CITRUST_AGENTIC_ATTESTATION_DOMAINS,
        "control_owner_certification_ledger": CITRUST_CONTROL_OWNER_CERTIFICATION_LEDGER,
        "qa_cyber_change_attestations": CITRUST_QA_CYBER_CHANGE_ATTESTATIONS,
        "residual_risk_register": CITRUST_RESIDUAL_RISK_REGISTER,
        "executive_risk_brief": CITRUST_EXECUTIVE_RISK_BRIEF,
        "attestation_package_builder": CITRUST_ATTESTATION_PACKAGE_BUILDER,
        "minimum_conditions": [
            "AI agent owner attestation is complete",
            "CMDB / CI / LCM attestation is complete",
            "System / business owner attestation is complete where operational reliance exists",
            "Support / service owner attestation is complete where support route is affected",
            "QA / validation attestation is complete where regulated impact exists",
            "Cyber / access attestation is complete where access or privileged impact exists",
            "Change / rollback / post-check attestation is complete where material CI impact exists",
            "Control testing and remediation certification is complete",
            "Continuous monitoring certification is complete",
            "Residual risks are accepted, restricted, or closed",
            "Executive signoff is complete with limitations and next review date"
        ],
        "default_decision": "Do not represent AI-assisted CITrust workflows as leadership-attested unless control owners certify evidence, QA/cyber/change attest where applicable, residual risks are visible, and executive signoff is complete"
    })

# ============================================================
# END CITRUST_AGENTIC_EXECUTIVE_ATTESTATION_CENTER_V1_ACTIVE
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

print("CITrust Agentic Executive Attestation Center installed.")
print(f"Inserted before: {target_found}")
