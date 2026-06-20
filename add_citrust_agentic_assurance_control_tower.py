from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_AGENTIC_ASSURANCE_CONTROL_TOWER_V1_ACTIVE"

if MARKER in text:
    print("CITrust Agentic Assurance Control Tower already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base shell not found. Install AgentTrust base module first.")

nav_old = '<a href="/citrust/agentic-change-integration-center" class="secondary">Change Integration</a>'
nav_new = '''<a href="/citrust/agentic-change-integration-center" class="secondary">Change Integration</a>
                    <a href="/citrust/agentic-ai-assurance-control-tower" class="secondary">Agentic Tower</a>
                    <a href="/citrust/agentic-governance-master-index" class="dark">Master Index</a>
                    <a href="/citrust/agentic-risk-heatmap" class="dark">Risk Heatmap</a>
                    <a href="/citrust/agentic-assurance-dossier-builder" class="dark">Dossier</a>'''

if nav_old in text and "/citrust/agentic-ai-assurance-control-tower" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# CITRUST_AGENTIC_ASSURANCE_CONTROL_TOWER_V1_ACTIVE
# CITrust™ Agentic Assurance Control Tower
# Master Index, Agentic Pattern Readiness Scorecard,
# Agentic Risk Heatmap, Executive Brief,
# Assurance Dossier Builder, Control Tower Simulator,
# and JSON Export
# ============================================================

CITRUST_AGENTIC_CONTROL_TOWER_DOMAINS = [
    {
        "domain": "AI Agent Registry",
        "primary_question": "Do we know which AI agents touch ServiceNow, CMDB, CIs, workflows, access, change, or regulated processes?",
        "evidence": "Agent ID, owner, purpose, operating license, CI touchpoint.",
        "route": "/citrust/ai-agent-registry",
        "risk_if_weak": "Unknown AI actor influencing CI or workflow decisions.",
        "status": "Required"
    },
    {
        "domain": "Agent-to-CI Impact Mapping",
        "primary_question": "Can we prove which CI, CI field, relationship, support group, or workflow the AI agent influenced?",
        "evidence": "Agent-to-CI map, field-risk matrix, CI passport, relationship confidence.",
        "route": "/citrust/agent-ci-impact-map",
        "risk_if_weak": "AI impact cannot be reconstructed or defended.",
        "status": "Required"
    },
    {
        "domain": "Agentic Workflow Governance Patterns",
        "primary_question": "Are Azure-style agentic workflow patterns governed before they touch ServiceNow / CMDB?",
        "evidence": "Trigger, prompt chain, router, supervisor, saga, parallel, evaluator, identity, observability, change controls.",
        "route": "/citrust/agentic-workflow-governance-patterns",
        "risk_if_weak": "Agentic workflow runs technically but not governably.",
        "status": "Required"
    },
    {
        "domain": "CMDB Graph Trust Score",
        "primary_question": "Is CMDB data trusted enough to feed AI, RAG, knowledge graph, or data fabric?",
        "evidence": "Identity completeness, owner coverage, relationship quality, GxP metadata, change state, orphan control.",
        "route": "/citrust/cmdb-graph-trust-score",
        "risk_if_weak": "Bad CMDB data becomes automated AI truth.",
        "status": "Required"
    },
    {
        "domain": "Agent Memory Governance",
        "primary_question": "Is the AI agent using approved, current, source-traceable, bounded, and correctable memory?",
        "evidence": "Memory source, freshness, authority, boundary, GxP/cyber preservation, correction workflow, replay link.",
        "route": "/citrust/agent-memory-governance",
        "risk_if_weak": "Stale or informal memory drives wrong CI, access, or GxP decision.",
        "status": "Required"
    },
    {
        "domain": "Agent Identity & Entitlement",
        "primary_question": "Is the AI agent governed like a controlled non-human identity?",
        "evidence": "Agent identity, owner, service account, entitlement, least privilege, MyAccess, CyberArk, SoD, recertification.",
        "route": "/citrust/agent-identity-entitlement-governance",
        "risk_if_weak": "Agent acts through overbroad, ownerless, or unauditable access.",
        "status": "Required"
    },
    {
        "domain": "Agent Observability Evidence Fabric",
        "primary_question": "Can we correlate what the AI agent did across ServiceNow, Azure, CyberArk, CMDB, QA, change, and human review evidence?",
        "evidence": "Correlation ID, runtime telemetry, ServiceNow logs, tool-call logs, CyberArk logs, QA evidence, change evidence.",
        "route": "/citrust/agent-observability-evidence-fabric",
        "risk_if_weak": "AI action cannot be audit-replayed.",
        "status": "Required"
    },
    {
        "domain": "Agentic Change Integration",
        "primary_question": "Does the AI-assisted action require a task, change record, access request, QA review, deviation/CAPA, exception, rollback, or closure dossier?",
        "evidence": "Action class, CI impact, record route, approval, rollback, post-check, closure dossier.",
        "route": "/citrust/agentic-change-integration-center",
        "risk_if_weak": "AI output becomes operationally binding without controlled change evidence.",
        "status": "Required"
    },
    {
        "domain": "GxP / Cyber Guardrails",
        "primary_question": "Are GMP, validation, QA, access, CyberArk, PSM, privileged, and cutover-sensitive contexts blocked or escalated?",
        "evidence": "GxP screen, QA route, cyber route, privileged access evidence, cutover status, rollback.",
        "route": "/citrust/gxp-agent-guardrails",
        "risk_if_weak": "AI bypasses regulated, cyber, or cutover control gates.",
        "status": "Required"
    }
]


CITRUST_AGENTIC_RISK_HEATMAP = [
    {
        "risk_area": "Unknown Agent",
        "severity": "Critical",
        "signal": "AI action has no registered agent identity or accountable owner.",
        "control_response": "Block operation and require Agent Registry entry."
    },
    {
        "risk_area": "Ownerless CI",
        "severity": "Critical",
        "signal": "CI owner, support group, LCM, or CMDB contact is missing.",
        "control_response": "Block AI reliance and route to CI ownership remediation."
    },
    {
        "risk_area": "GxP Metadata Gap",
        "severity": "Critical",
        "signal": "GMP class, validation status, QA owner, or regulated impact is unknown.",
        "control_response": "QA-governed block before regulated reliance."
    },
    {
        "risk_area": "Privileged / Access Exposure",
        "severity": "Critical",
        "signal": "AI action touches MyAccess, CyberArk, PSM, admin, entitlement, or support group access.",
        "control_response": "Cyber-gated route; no autonomous AI approval."
    },
    {
        "risk_area": "Untrusted CMDB Graph",
        "severity": "High",
        "signal": "CMDB data is stale, orphaned, incomplete, or relationship confidence is weak.",
        "control_response": "Do not feed AI, RAG, graph, or data fabric."
    },
    {
        "risk_area": "Prompt Chain Missing",
        "severity": "High",
        "signal": "Multi-step AI reasoning cannot be reconstructed.",
        "control_response": "Restrict reliance until prompt chain evidence is complete."
    },
    {
        "risk_area": "Stale Agent Memory",
        "severity": "High",
        "signal": "Agent uses old owner, support group, validation, access, relationship, or change context.",
        "control_response": "Suppress memory and refresh from approved source."
    },
    {
        "risk_area": "No Rollback",
        "severity": "Critical",
        "signal": "AI-influenced material action has no recovery route.",
        "control_response": "No execution."
    },
    {
        "risk_area": "Telemetry Gap",
        "severity": "High",
        "signal": "ServiceNow, Azure, CyberArk, CMDB, QA, or change evidence cannot be correlated.",
        "control_response": "Do not close as audit-defensible."
    },
    {
        "risk_area": "Hidden AI Approval",
        "severity": "Critical",
        "signal": "AI recommends, approves, executes, or closes the same action.",
        "control_response": "Segregation of duties failure; require human owner approval."
    }
]


CITRUST_AGENTIC_MASTER_INDEX = [
    {
        "section": "Agentic CMDB Assurance Bridge",
        "purpose": "Connects AgentTrust™ AI governance to CITrust™ ServiceNow / CMDB assurance.",
        "route": "/citrust/agentic-cmdb-assurance"
    },
    {
        "section": "AI Agent Registry",
        "purpose": "Registers AI agents that touch CMDB, CIs, workflows, access, GxP, and change processes.",
        "route": "/citrust/ai-agent-registry"
    },
    {
        "section": "Agent-to-CI Impact Map",
        "purpose": "Maps AI agents to impacted CIs, fields, workflows, ownership, support, GxP, and evidence.",
        "route": "/citrust/agent-ci-impact-map"
    },
    {
        "section": "CMDB Graph Trust Score",
        "purpose": "Scores CMDB data before it feeds AI, RAG, knowledge graph, analytics, or data fabric.",
        "route": "/citrust/cmdb-graph-trust-score"
    },
    {
        "section": "Agentic Change-Control Gate",
        "purpose": "Controls whether AI may read, recommend, route, update, trigger, or influence CI actions.",
        "route": "/citrust/agentic-change-control-gate"
    },
    {
        "section": "Agentic Workflow Governance Patterns",
        "purpose": "Maps Azure agentic patterns to CITrust™ regulated ServiceNow / CMDB governance questions.",
        "route": "/citrust/agentic-workflow-governance-patterns"
    },
    {
        "section": "Agent Memory Governance",
        "purpose": "Governs agent memory, context provenance, stale memory suppression, and correction workflow.",
        "route": "/citrust/agent-memory-governance"
    },
    {
        "section": "Agent Observability Evidence Fabric",
        "purpose": "Correlates runtime telemetry, ServiceNow logs, Azure evidence, CyberArk logs, QA evidence, and change records.",
        "route": "/citrust/agent-observability-evidence-fabric"
    },
    {
        "section": "Agent Identity & Entitlement Governance",
        "purpose": "Controls AI agents as governed identities with owner, entitlement, MyAccess route, CyberArk route, SoD, and review cadence.",
        "route": "/citrust/agent-identity-entitlement-governance"
    },
    {
        "section": "Agentic Change Integration Center",
        "purpose": "Routes AI-assisted actions to task, change, access request, QA review, deviation/CAPA, exception, rollback, and closure.",
        "route": "/citrust/agentic-change-integration-center"
    }
]


CITRUST_AGENTIC_EXECUTIVE_BRIEF_ITEMS = [
    {
        "brief_item": "Executive Question",
        "content": "Can this AI agent safely interact with ServiceNow CMDB, CIs, ownership, support groups, access routes, change control, validation state, and GMP-impacting systems?"
    },
    {
        "brief_item": "Strategic Positioning",
        "content": "Azure, ServiceNow, OpenAI, and agent platforms explain how to build agentic workflows. CITrust™ explains whether those workflows are operationally trusted for regulated CMDB and GMP environments."
    },
    {
        "brief_item": "Governance Novelty",
        "content": "CITrust™ converts agentic workflow architecture into ServiceNow-specific assurance questions, evidence requirements, owner routes, guardrails, scoring, and audit replay."
    },
    {
        "brief_item": "Regulated Differentiator",
        "content": "The platform protects GMP, validation, QA, access, CyberArk, PSM, change-control, cutover, and CMDB data-quality boundaries before AI can influence operational decisions."
    },
    {
        "brief_item": "Assurance Outcome",
        "content": "Leadership can see whether AI-assisted CI workflows are registered, mapped, governed, evidenced, human-approved, rollback-ready, and audit-defensible."
    }
]


CITRUST_AGENTIC_ASSURANCE_DOSSIER = [
    {
        "dossier_section": "Agent Identity",
        "required_contents": "Agent ID, owner, purpose, approved use case, operating license, service account."
    },
    {
        "dossier_section": "CI Impact",
        "required_contents": "CI ID, CI passport, field touched, relationship touched, owner, support group, LCM, lifecycle."
    },
    {
        "dossier_section": "Regulated / Cyber Screen",
        "required_contents": "GxP status, validation status, QA owner, access impact, MyAccess route, CyberArk / PSM route."
    },
    {
        "dossier_section": "Workflow Pattern Evidence",
        "required_contents": "Trigger, prompt chain, router decision, supervisor result, evaluator score, parallel conflict control, saga rollback."
    },
    {
        "dossier_section": "Memory / Context Evidence",
        "required_contents": "Source provenance, freshness, authority, context boundary, stale memory suppression, correction workflow."
    },
    {
        "dossier_section": "Observability Evidence",
        "required_contents": "ServiceNow log, Azure telemetry, tool-call evidence, CyberArk log if applicable, QA evidence, change evidence."
    },
    {
        "dossier_section": "Change / Task / Deviation Route",
        "required_contents": "Task, change record, access request, QA review, deviation/CAPA, exception, rollback, post-check."
    },
    {
        "dossier_section": "Human Review and Closure",
        "required_contents": "Reviewer, owner decision, approval/rejection, conditions, closure record, signoff."
    }
]


def citrust_control_tower_domain_rows():
    rows = ""
    for item in CITRUST_AGENTIC_CONTROL_TOWER_DOMAINS:
        rows += f"""
        <tr>
            <td><strong>{item["domain"]}</strong></td>
            <td>{item["primary_question"]}</td>
            <td>{item["evidence"]}</td>
            <td><a href="{item["route"]}" class="badge blue">Open</a></td>
            <td><span class="badge red">{item["risk_if_weak"]}</span></td>
            <td><span class="badge green">{item["status"]}</span></td>
        </tr>
        """
    return rows


def citrust_master_index_rows():
    rows = ""
    for item in CITRUST_AGENTIC_MASTER_INDEX:
        rows += f"""
        <tr>
            <td><strong>{item["section"]}</strong></td>
            <td>{item["purpose"]}</td>
            <td><a href="{item["route"]}" class="badge blue">Open Page</a></td>
        </tr>
        """
    return rows


def citrust_risk_heatmap_rows():
    rows = ""
    for item in CITRUST_AGENTIC_RISK_HEATMAP:
        badge = "orange"
        if item["severity"] == "Critical":
            badge = "red"
        elif item["severity"] == "High":
            badge = "orange"

        rows += f"""
        <tr>
            <td><strong>{item["risk_area"]}</strong></td>
            <td><span class="badge {badge}">{item["severity"]}</span></td>
            <td>{item["signal"]}</td>
            <td>{item["control_response"]}</td>
        </tr>
        """
    return rows


def citrust_exec_brief_rows():
    rows = ""
    for item in CITRUST_AGENTIC_EXECUTIVE_BRIEF_ITEMS:
        rows += f"""
        <tr>
            <td><strong>{item["brief_item"]}</strong></td>
            <td>{item["content"]}</td>
        </tr>
        """
    return rows


def citrust_assurance_dossier_rows():
    rows = ""
    for item in CITRUST_AGENTIC_ASSURANCE_DOSSIER:
        rows += f"""
        <tr>
            <td><strong>{item["dossier_section"]}</strong></td>
            <td>{item["required_contents"]}</td>
        </tr>
        """
    return rows


def citrust_control_tower_decision(registry, impact, workflow, graph, memory, identity, observability, change, gxpc yber):
    checks = [registry, impact, workflow, graph, memory, identity, observability, change, gxpcyber]
    score = int((sum(1 for item in checks if item == "yes") / len(checks)) * 100)

    if registry != "yes":
        return score, "Block Agentic Reliance", "red", "AI agent is not registered or owner-controlled."
    if identity != "yes":
        return score, "Identity Governance Required", "red", "Agent identity, entitlement, least privilege, MyAccess, CyberArk, or SoD control is incomplete."
    if impact != "yes":
        return score, "CI Impact Mapping Required", "red", "Agent-to-CI impact is not mapped."
    if gxpc yber != "yes":
        return score, "GxP / Cyber Guardrail Required", "red", "Regulated or privileged boundary is not governed."
    if graph != "yes":
        return score, "CMDB Data Not AI-Ready", "red", "CMDB graph trust score is not ready for AI reliance."
    if workflow != "yes":
        return score, "Workflow Pattern Governance Required", "orange", "Agentic workflow pattern controls are incomplete."
    if memory != "yes":
        return score, "Memory Governance Required", "orange", "Agent memory or context provenance is incomplete."
    if observability != "yes":
        return score, "Audit Replay Gap", "red", "Observability evidence fabric is incomplete."
    if change != "yes":
        return score, "Change Integration Required", "red", "AI-to-change/task/QA/cyber/deviation/exception route is incomplete."
    if score == 100:
        return score, "Agentic CI Workflow Trusted", "green", "Agentic workflow is registered, mapped, governed, evidenced, identity-controlled, change-integrated, and guardrailed."
    return score, "Conditional Agentic Assurance", "yellow", "Workflow may proceed only with restrictions, owner approval, and remediation tracking."


try:
    AGENTTRUST_EXPECTED_ROUTES.extend([
        "/citrust/agentic-ai-assurance-control-tower",
        "/citrust/agentic-assurance-dashboard",
        "/citrust/agentic-governance-master-index",
        "/citrust/agentic-pattern-readiness-scorecard",
        "/citrust/agentic-risk-heatmap",
        "/citrust/agentic-executive-brief",
        "/citrust/agentic-assurance-dossier-builder",
        "/citrust/agentic-control-tower-simulator",
        "/citrust/agentic-control-tower-json"
    ])
except Exception:
    pass


@app.route("/citrust/agentic-ai-assurance-control-tower")
@app.route("/citrust/agentic-assurance-dashboard")
@app.route("/citrust/ci-agentic-control-tower")
def citrust_agentic_ai_assurance_control_tower():
    rows = citrust_control_tower_domain_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Agentic Tower</div><div class="value" style="color:var(--green);">Active</div><div class="note">CITrust™ agentic assurance dashboard installed.</div></div>
        <div class="metric"><div class="label">Assurance Domains</div><div class="value" style="color:var(--blue);">9</div><div class="note">Registry, CI impact, workflow, graph, memory, identity, observability, change, guardrails.</div></div>
        <div class="metric"><div class="label">GxP / Cyber</div><div class="value" style="color:var(--red);">Guarded</div><div class="note">GMP, validation, MyAccess, CyberArk, PSM, privileged context routed.</div></div>
        <div class="metric"><div class="label">Evidence Fabric</div><div class="value" style="color:var(--yellow);">Replayable</div><div class="note">Runtime, CMDB, QA, cyber, change, and human review evidence linked.</div></div>
        <div class="metric"><div class="label">Change Integration</div><div class="value" style="color:var(--orange);">Controlled</div><div class="note">AI action routed to task, change, access, QA, deviation, exception, rollback.</div></div>
        <div class="metric"><div class="label">Executive Answer</div><div class="value" style="color:var(--purple);">Defensible</div><div class="note">Can this agentic workflow be trusted against regulated CIs?</div></div>
    </section>

    <section class="section">
        <h2>CITrust™ Agentic Assurance Control Tower</h2>
        <div class="answer">
            <strong>Purpose:</strong> provide one command center showing whether an AI agentic workflow is trusted enough
            to interact with ServiceNow CMDB, CIs, ownership, support groups, access routes, change records, validation state,
            GMP-impacting systems, and cutover-sensitive processes.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Assurance Domain</th>
                    <th>Primary Question</th>
                    <th>Evidence Required</th>
                    <th>Route</th>
                    <th>Risk If Weak</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Control Tower Rule</h2>
        <div class="answer">
            CITrust™ does not compete with Azure AI, ServiceNow AI, OpenAI, Semantic Kernel, or NVIDIA-style agentic platforms.
            CITrust™ sits above them as the regulated assurance layer that proves whether agentic workflows are safe,
            approved, observable, evidence-backed, human-governed, rollback-ready, and operationally trusted.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Assurance Control Tower",
        "Executive control tower for CITrust™ AI agentic assurance across ServiceNow CMDB, CIs, GxP, cyber, access, change-control, observability, memory, identity, and evidence.",
        body
    )


@app.route("/citrust/agentic-governance-master-index")
@app.route("/citrust/agentic-master-index")
@app.route("/citrust/ci-agentic-master-index")
def citrust_agentic_governance_master_index():
    rows = citrust_master_index_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agentic Governance Master Index</h2>
        <p>
            This index links all CITrust™ agentic governance pages created from the Azure / ServiceNow / CMDB assurance pattern.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Section</th>
                    <th>Purpose</th>
                    <th>Route</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Governance Master Index",
        "Master index for CITrust™ agentic CMDB assurance, AI agent registry, agent-to-CI impact, graph trust, workflow patterns, memory, observability, identity, and change integration.",
        body
    )


@app.route("/citrust/agentic-pattern-readiness-scorecard")
@app.route("/citrust/agentic-readiness-scorecard")
@app.route("/citrust/ci-agentic-readiness-scorecard")
def citrust_agentic_pattern_readiness_scorecard():
    rows = citrust_control_tower_domain_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agentic Pattern Readiness Scorecard</h2>
        <p>
            This scorecard checks whether the agentic workflow pattern has all required control domains before operational reliance.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Domain</th>
                    <th>Readiness Question</th>
                    <th>Evidence</th>
                    <th>Route</th>
                    <th>Risk</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Pattern Readiness Scorecard",
        "Readiness scorecard for AI agentic workflow assurance across registry, CI impact, workflow patterns, graph trust, memory, identity, observability, change, and guardrails.",
        body
    )


@app.route("/citrust/agentic-risk-heatmap")
@app.route("/citrust/ai-agentic-risk-heatmap")
@app.route("/citrust/ci-agentic-risk-heatmap")
def citrust_agentic_risk_heatmap():
    rows = citrust_risk_heatmap_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agentic Risk Heatmap</h2>
        <p>
            This heatmap identifies the highest-risk failure modes when AI agents interact with ServiceNow, CMDB, GxP,
            access, change, or cutover-sensitive workflows.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Risk Area</th>
                    <th>Severity</th>
                    <th>Signal</th>
                    <th>Control Response</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Risk Heatmap",
        "Risk heatmap for unknown agents, ownerless CIs, GxP metadata gaps, privileged exposure, untrusted CMDB graph, stale memory, missing rollback, telemetry gaps, and hidden AI approval.",
        body
    )


@app.route("/citrust/agentic-executive-brief")
@app.route("/citrust/ci-agentic-executive-brief")
@app.route("/citrust/agentic-assurance-brief")
def citrust_agentic_executive_brief():
    rows = citrust_exec_brief_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agentic Executive Brief</h2>
        <p>
            Executive positioning for CITrust™ as the regulated assurance layer over agentic AI workflows.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Brief Item</th>
                    <th>Content</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>One-Line Positioning</h2>
        <div class="answer">
            CITrust™ answers whether an AI agentic workflow can be trusted to interact with regulated CIs,
            ServiceNow workflows, ownership, support groups, access routes, change control, validation state,
            and GMP-impacting systems.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Executive Brief",
        "Executive brief positioning CITrust™ as the regulated assurance layer over Azure, ServiceNow, OpenAI, Semantic Kernel, NVIDIA-style, and enterprise agentic AI workflows.",
        body
    )


@app.route("/citrust/agentic-assurance-dossier-builder")
@app.route("/citrust/ci-agentic-dossier-builder")
@app.route("/citrust/agentic-dossier-builder")
def citrust_agentic_assurance_dossier_builder():
    rows = citrust_assurance_dossier_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agentic Assurance Dossier Builder</h2>
        <p>
            The dossier builder defines the evidence package needed to defend an AI-assisted CI workflow.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Dossier Section</th>
                    <th>Required Contents</th>
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
            AI-assisted CI workflows should not close with only a generated summary. Closure requires an evidence dossier
            with identity, CI impact, regulated/cyber screen, workflow pattern evidence, memory/context evidence,
            observability evidence, change route, human review, and signoff.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Assurance Dossier Builder",
        "Dossier builder for AI-assisted CI workflows covering agent identity, CI impact, GxP/cyber screen, workflow pattern evidence, memory, observability, change route, human review, and closure.",
        body
    )


@app.route("/citrust/agentic-control-tower-simulator", methods=["GET", "POST"])
@app.route("/citrust/agentic-assurance-simulator", methods=["GET", "POST"])
@app.route("/citrust/ci-agentic-trust-simulator", methods=["GET", "POST"])
def citrust_agentic_control_tower_simulator():
    from flask import request

    registry = request.form.get("registry", "yes")
    impact = request.form.get("impact", "yes")
    workflow = request.form.get("workflow", "yes")
    graph = request.form.get("graph", "yes")
    memory = request.form.get("memory", "yes")
    identity = request.form.get("identity", "yes")
    observability = request.form.get("observability", "yes")
    change = request.form.get("change", "yes")
    gxpcyber = request.form.get("gxpcyber", "yes")

    checks = [registry, impact, workflow, graph, memory, identity, observability, change, gxpcyber]
    score = int((sum(1 for item in checks if item == "yes") / len(checks)) * 100)

    if registry != "yes":
        decision, badge, reason = "Block Agentic Reliance", "red", "AI agent is not registered or owner-controlled."
    elif identity != "yes":
        decision, badge, reason = "Identity Governance Required", "red", "Agent identity, entitlement, least privilege, MyAccess, CyberArk, or SoD control is incomplete."
    elif impact != "yes":
        decision, badge, reason = "CI Impact Mapping Required", "red", "Agent-to-CI impact is not mapped."
    elif gxpcyber != "yes":
        decision, badge, reason = "GxP / Cyber Guardrail Required", "red", "Regulated or privileged boundary is not governed."
    elif graph != "yes":
        decision, badge, reason = "CMDB Data Not AI-Ready", "red", "CMDB graph trust score is not ready for AI reliance."
    elif workflow != "yes":
        decision, badge, reason = "Workflow Pattern Governance Required", "orange", "Agentic workflow pattern controls are incomplete."
    elif memory != "yes":
        decision, badge, reason = "Memory Governance Required", "orange", "Agent memory or context provenance is incomplete."
    elif observability != "yes":
        decision, badge, reason = "Audit Replay Gap", "red", "Observability evidence fabric is incomplete."
    elif change != "yes":
        decision, badge, reason = "Change Integration Required", "red", "AI-to-change/task/QA/cyber/deviation/exception route is incomplete."
    elif score == 100:
        decision, badge, reason = "Agentic CI Workflow Trusted", "green", "Agentic workflow is registered, mapped, governed, evidenced, identity-controlled, change-integrated, and guardrailed."
    else:
        decision, badge, reason = "Conditional Agentic Assurance", "yellow", "Workflow may proceed only with restrictions, owner approval, and remediation tracking."

    def selected(value, expected):
        return "selected" if value == expected else ""

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Agentic Trust Score</div><div class="value" style="color:var(--green);">{score}%</div><div class="note">Calculated from CITrust™ agentic assurance domains.</div></div>
        <div class="metric"><div class="label">Trust Decision</div><div class="value" style="color:var(--yellow);">{decision}</div><div class="note">{reason}</div></div>
    </section>

    <section class="section">
        <h2>CITrust™ Agentic Control Tower Simulator</h2>
        <p>
            Simulate whether an AI agentic workflow is trusted enough to interact with ServiceNow CMDB, CIs,
            ownership, support groups, access routes, change control, validation state, and GMP-impacting systems.
        </p>

        <form method="POST" action="/citrust/agentic-control-tower-simulator">
            <table>
                <tbody>
                    <tr><td><strong>AI Agent Registry Ready?</strong></td><td><select name="registry" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(registry, "yes")}>Yes</option><option value="no" {selected(registry, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Agent-to-CI Impact Mapped?</strong></td><td><select name="impact" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(impact, "yes")}>Yes</option><option value="no" {selected(impact, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Workflow Pattern Governance Ready?</strong></td><td><select name="workflow" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(workflow, "yes")}>Yes</option><option value="no" {selected(workflow, "no")}>No</option></select></td></tr>
                    <tr><td><strong>CMDB Graph Trust Ready?</strong></td><td><select name="graph" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(graph, "yes")}>Yes</option><option value="no" {selected(graph, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Agent Memory Governance Ready?</strong></td><td><select name="memory" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(memory, "yes")}>Yes</option><option value="no" {selected(memory, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Agent Identity / Entitlement Governance Ready?</strong></td><td><select name="identity" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(identity, "yes")}>Yes</option><option value="no" {selected(identity, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Observability Evidence Fabric Ready?</strong></td><td><select name="observability" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(observability, "yes")}>Yes</option><option value="no" {selected(observability, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Change Integration Ready?</strong></td><td><select name="change" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(change, "yes")}>Yes</option><option value="no" {selected(change, "no")}>No</option></select></td></tr>
                    <tr><td><strong>GxP / Cyber Guardrails Ready?</strong></td><td><select name="gxpcyber" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(gxpcyber, "yes")}>Yes</option><option value="no" {selected(gxpcyber, "no")}>No</option></select></td></tr>
                </tbody>
            </table>

            <button type="submit" style="margin-top:16px;padding:12px 18px;border-radius:12px;border:0;background:#2563eb;color:white;font-weight:800;">Run Agentic Assurance Check</button>
        </form>
    </section>

    <section class="section">
        <h2>Agentic Assurance Decision</h2>
        <div class="answer">
            <strong>Score:</strong> {score}%<br>
            <strong>Decision:</strong> <span class="badge {badge}">{decision}</span><br>
            <strong>Reason:</strong> {reason}
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Control Tower Simulator",
        "Simulator for CITrust™ agentic assurance across registry, CI impact, workflow patterns, graph trust, memory, identity, observability, change integration, and GxP/cyber guardrails.",
        body
    )


@app.route("/citrust/agentic-control-tower-json")
@app.route("/citrust/agentic-assurance-json")
@app.route("/citrust/ci-agentic-control-tower-json")
def citrust_agentic_control_tower_json():
    from flask import jsonify

    return jsonify({
        "module": "CITrust™",
        "capability": "Agentic Assurance Control Tower + Master Index",
        "primary_question": "Can this AI agentic workflow be trusted to interact with ServiceNow CMDB, CIs, ownership, support groups, access routes, change control, validation state, and GMP-impacting systems?",
        "control_tower_domains": CITRUST_AGENTIC_CONTROL_TOWER_DOMAINS,
        "master_index": CITRUST_AGENTIC_MASTER_INDEX,
        "risk_heatmap": CITRUST_AGENTIC_RISK_HEATMAP,
        "executive_brief": CITRUST_AGENTIC_EXECUTIVE_BRIEF_ITEMS,
        "assurance_dossier": CITRUST_AGENTIC_ASSURANCE_DOSSIER,
        "minimum_conditions": [
            "AI agent is registered and owner-controlled",
            "Agent-to-CI impact is mapped",
            "Agentic workflow pattern is governed",
            "CMDB graph trust score is ready",
            "Agent memory and context provenance are governed",
            "Agent identity and entitlement are least-privilege and reviewable",
            "Observability evidence fabric is correlated",
            "AI-to-change-control integration is complete",
            "GxP, QA, cyber, access, CyberArk, PSM, and cutover guardrails are active",
            "Human review, rollback, post-check, and closure dossier are available"
        ],
        "default_decision": "Do not allow AI agentic workflow reliance against regulated CIs, ServiceNow workflows, access routes, change control, or GMP-impacting systems unless the control tower domains are complete and evidence-backed"
    })

# ============================================================
# END CITRUST_AGENTIC_ASSURANCE_CONTROL_TOWER_V1_ACTIVE
# ============================================================

'''

block = block.replace("gxpc yber", "gxpcyber")

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

print("CITrust Agentic Assurance Control Tower installed.")
print(f"Inserted before: {target_found}")
