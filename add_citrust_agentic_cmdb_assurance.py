from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_AGENTIC_CMDB_ASSURANCE_BRIDGE_V1_ACTIVE"

if MARKER in text:
    print("CITrust Agentic CMDB Assurance Bridge already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base shell not found. Install AgentTrust base module first.")

nav_old = '<a href="/agenttrust/policy-control-compiler" class="secondary">Policy Compiler</a>'
nav_new = '''<a href="/agenttrust/policy-control-compiler" class="secondary">Policy Compiler</a>
                    <a href="/citrust/agentic-cmdb-assurance" class="secondary">CI Agent Assurance</a>
                    <a href="/citrust/ai-agent-registry" class="dark">CI Agent Registry</a>
                    <a href="/citrust/agent-ci-impact-map" class="dark">Agent-CI Map</a>
                    <a href="/citrust/knowledge-graph-data-fabric-readiness" class="dark">Graph Readiness</a>'''

if nav_old in text and "/citrust/agentic-cmdb-assurance" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# CITRUST_AGENTIC_CMDB_ASSURANCE_BRIDGE_V1_ACTIVE
# CITrust™ Agentic CMDB Assurance Bridge
# AI Agent Registry, Agent-to-CI Impact Mapping,
# AI Control Tower Assurance Overlay, Agent Runtime Evidence,
# GxP Agent Guardrails, Knowledge Graph / Data Fabric Readiness,
# Agentic Readiness Simulator, and JSON Export
# ============================================================

CITRUST_AGENTIC_GAP_COVERAGE = [
    {
        "gap": "AI Agent Registry",
        "coverage": "Covered in AgentTrust™, now mirrored into CITrust™ for ServiceNow / CMDB context.",
        "citrust_addition": "Register which AI agents touch which CI, workflow, service, system, owner, and regulated process.",
        "status": "Now CITrust-native"
    },
    {
        "gap": "Agent-to-CI Impact Mapping",
        "coverage": "Partially covered before through AgentBOM and ServiceNow adapter logic.",
        "citrust_addition": "Explicitly maps AI agents to CI owner, support group, validation state, lifecycle state, change state, and GxP impact.",
        "status": "Strengthened"
    },
    {
        "gap": "AI Control Tower equivalent",
        "coverage": "Covered in AgentTrust™ Command Center, Runtime Control Plane, and Executive Dashboard.",
        "citrust_addition": "Adds regulated-pharma assurance overlay for ServiceNow AI/agentic workflows.",
        "status": "Strengthened"
    },
    {
        "gap": "Agent Runtime Evidence",
        "coverage": "Covered in AgentTrust™ Evidence Lineage, Runtime Control Plane, and Decision Replay.",
        "citrust_addition": "Adds CI-specific runtime evidence: CI touched, field touched, owner approval, rollback, change link, and GxP route.",
        "status": "Strengthened"
    },
    {
        "gap": "GxP Agent Guardrails",
        "coverage": "Covered in AgentTrust™ GxP routing and incident response.",
        "citrust_addition": "Adds CMDB-specific blocks for GMP CI, validated CI, cutover-sensitive CI, orphan CI, ownerless CI, and change-uncontrolled CI.",
        "status": "Strengthened"
    },
    {
        "gap": "Knowledge Graph / Data Fabric readiness",
        "coverage": "Partially covered in Governance Graph and Data Model API.",
        "citrust_addition": "Adds CMDB trust readiness scoring before CMDB data feeds AI agents, knowledge graph, or data fabric.",
        "status": "New CITrust layer"
    }
]


CITRUST_AI_AGENT_REGISTER = [
    {
        "agent_id": "CIAG-001",
        "agent": "CI Ownership Recommendation Agent™",
        "touchpoint": "ServiceNow CMDB CI record",
        "ci_impact": "Recommends CI owner, technical owner, support group, and LCM review.",
        "risk": "High",
        "required_guardrail": "Recommendation-only; no direct CI update without LCM / CMDB owner approval.",
        "required_evidence": "CI record, source fields, recommendation rationale, reviewer, final decision."
    },
    {
        "agent_id": "CIAG-002",
        "agent": "CI Relationship Mapping Agent™",
        "touchpoint": "Business Application, Application Service, Infrastructure CI, Business Service",
        "ci_impact": "Suggests relationships between application, infrastructure, service, and support model.",
        "risk": "High",
        "required_guardrail": "Human-gated mapping; no relationship commit without owner review.",
        "required_evidence": "Source CIs, relationship rationale, mapping owner, approval decision."
    },
    {
        "agent_id": "CIAG-003",
        "agent": "MyAccess / Support Group Routing Agent™",
        "touchpoint": "MyAccess, support group, assignment group, access route",
        "ci_impact": "Suggests access routing and support group alignment for CI.",
        "risk": "Critical",
        "required_guardrail": "Cyber-gated; no access approval, no entitlement activation, no privileged action.",
        "required_evidence": "Access context, CI owner, support group, cyber owner route, final decision."
    },
    {
        "agent_id": "CIAG-004",
        "agent": "GxP CI Readiness Agent™",
        "touchpoint": "GMP / validated CI, validation status, change state, cutover readiness",
        "ci_impact": "Checks whether CI is ready for regulated operational reliance.",
        "risk": "Critical",
        "required_guardrail": "QA-governed; no regulated conclusion, no validation approval, no cutover approval.",
        "required_evidence": "Validation status, GMP class, change link, QA review, readiness decision."
    },
    {
        "agent_id": "CIAG-005",
        "agent": "CMDB Knowledge Graph Feeder Agent™",
        "touchpoint": "CMDB export, data fabric, knowledge graph, AI retrieval layer",
        "ci_impact": "Prepares CI data for graph, AI retrieval, reporting, or data fabric use.",
        "risk": "Critical",
        "required_guardrail": "Do not feed untrusted CMDB data into AI graph or data fabric.",
        "required_evidence": "Completeness score, owner coverage, relationship quality, orphan status, validation coverage."
    }
]


CITRUST_AGENT_CI_IMPACT_CONTROLS = [
    {
        "control_id": "CIT-AI-CI-001",
        "control": "Agent-to-CI Link",
        "assurance_question": "Which AI agent touched or influenced this CI?",
        "required_evidence": "Agent ID, CI ID, workflow, field touched, timestamp, action type.",
        "block_condition": "No agent identity or CI reference."
    },
    {
        "control_id": "CIT-AI-CI-002",
        "control": "CI Ownership Gate",
        "assurance_question": "Does the CI have a valid owner, technical owner, support group, and LCM?",
        "required_evidence": "Owner fields, support group, LCM, reviewer.",
        "block_condition": "Ownerless, orphaned, or unsupported CI."
    },
    {
        "control_id": "CIT-AI-CI-003",
        "control": "GxP / Validation Gate",
        "assurance_question": "Is the CI GMP, validated, QA-owned, or regulated?",
        "required_evidence": "GMP class, validation status, QA owner, regulated impact decision.",
        "block_condition": "GMP or validated CI without QA / validation route."
    },
    {
        "control_id": "CIT-AI-CI-004",
        "control": "Change-Control Gate",
        "assurance_question": "Does the AI action require change control or change record linkage?",
        "required_evidence": "Change record, impact analysis, rollback, approval.",
        "block_condition": "Update or mapping change without change-control route."
    },
    {
        "control_id": "CIT-AI-CI-005",
        "control": "Runtime Evidence Gate",
        "assurance_question": "Can we prove what the AI agent did, why, who reviewed it, and what happened?",
        "required_evidence": "Prompt, source CI, tool call, recommendation, reviewer, outcome, rollback status.",
        "block_condition": "Missing runtime evidence or replay gap."
    },
    {
        "control_id": "CIT-AI-CI-006",
        "control": "Knowledge Graph Trust Gate",
        "assurance_question": "Is CMDB data trusted enough to feed AI, graph, reporting, or data fabric?",
        "required_evidence": "CI completeness, relationship quality, owner coverage, lifecycle state, orphan check.",
        "block_condition": "Low-quality CMDB data or unvalidated relationship map."
    }
]


CITRUST_KNOWLEDGE_GRAPH_READINESS = [
    {
        "readiness_area": "CI Identity Completeness",
        "question": "Does each CI have name, class, environment, lifecycle state, owner, support group, and LCM?",
        "ai_risk": "AI may reason over incomplete or misclassified CIs.",
        "required_control": "Completeness score and CI passport."
    },
    {
        "readiness_area": "Relationship Quality",
        "question": "Are application, infrastructure, database, business service, and mapped application service relationships validated?",
        "ai_risk": "AI may infer wrong operational dependency.",
        "required_control": "Relationship validation and owner confirmation."
    },
    {
        "readiness_area": "GxP / Validation Metadata",
        "question": "Does the CI show GMP class, validation status, QA owner, change state, and regulated impact?",
        "ai_risk": "AI may treat regulated CI as normal operational CI.",
        "required_control": "GxP metadata and QA route."
    },
    {
        "readiness_area": "Orphan / Ownerless Detection",
        "question": "Are orphaned, ownerless, supportless, or stale CIs excluded from AI reliance?",
        "ai_risk": "AI may trust unowned operational records.",
        "required_control": "Orphan detection and ownership remediation."
    },
    {
        "readiness_area": "Change-Control Alignment",
        "question": "Are CI changes linked to change control and cutover readiness where required?",
        "ai_risk": "AI may recommend or trigger action outside approved change process.",
        "required_control": "Change linkage, rollback, and approval evidence."
    },
    {
        "readiness_area": "Runtime Evidence Readiness",
        "question": "Can agentic CI decisions be replayed from source CI to final decision?",
        "ai_risk": "Leadership cannot defend AI-assisted CI decisions.",
        "required_control": "Runtime evidence ledger and decision replay."
    }
]


def citrust_agentic_gap_rows():
    rows = ""
    for item in CITRUST_AGENTIC_GAP_COVERAGE:
        rows += f"""
        <tr>
            <td><strong>{item["gap"]}</strong></td>
            <td>{item["coverage"]}</td>
            <td>{item["citrust_addition"]}</td>
            <td><span class="badge green">{item["status"]}</span></td>
        </tr>
        """
    return rows


def citrust_ai_agent_rows():
    rows = ""
    for item in CITRUST_AI_AGENT_REGISTER:
        badge = "orange"
        if item["risk"] == "Critical":
            badge = "red"
        elif item["risk"] == "High":
            badge = "yellow"

        rows += f"""
        <tr>
            <td><strong>{item["agent_id"]}</strong></td>
            <td>{item["agent"]}</td>
            <td>{item["touchpoint"]}</td>
            <td>{item["ci_impact"]}</td>
            <td><span class="badge {badge}">{item["risk"]}</span></td>
            <td>{item["required_guardrail"]}</td>
            <td>{item["required_evidence"]}</td>
        </tr>
        """
    return rows


def citrust_agent_ci_control_rows():
    rows = ""
    for item in CITRUST_AGENT_CI_IMPACT_CONTROLS:
        rows += f"""
        <tr>
            <td><strong>{item["control_id"]}</strong></td>
            <td><span class="badge blue">{item["control"]}</span></td>
            <td>{item["assurance_question"]}</td>
            <td>{item["required_evidence"]}</td>
            <td><span class="badge red">{item["block_condition"]}</span></td>
        </tr>
        """
    return rows


def citrust_kg_readiness_rows():
    rows = ""
    for item in CITRUST_KNOWLEDGE_GRAPH_READINESS:
        rows += f"""
        <tr>
            <td><strong>{item["readiness_area"]}</strong></td>
            <td>{item["question"]}</td>
            <td><span class="badge red">{item["ai_risk"]}</span></td>
            <td>{item["required_control"]}</td>
        </tr>
        """
    return rows


def citrust_agentic_readiness_decision(owner, support, validation, change, gxp, runtime, rollback, graph):
    checks = [owner, support, validation, change, runtime, rollback, graph]
    score = int((sum(1 for item in checks if item == "yes") / len(checks)) * 100)

    if owner != "yes":
        return score, "Block AI Reliance", "red", "CI owner / LCM accountability is missing."
    if support != "yes":
        return score, "Block AI Reliance", "red", "Support group or operational owner is missing."
    if gxp == "yes" and validation != "yes":
        return score, "QA-Governed Block", "red", "GMP / validated CI requires validation status and QA route before AI reliance."
    if change != "yes":
        return score, "Change-Control Required", "orange", "AI action may affect CI state or relationship without change-control evidence."
    if runtime != "yes":
        return score, "Restrict to Advisory", "orange", "Runtime evidence is incomplete."
    if rollback != "yes":
        return score, "No Execution", "red", "Rollback or recovery evidence is missing."
    if graph != "yes":
        return score, "Do Not Feed Graph / Data Fabric", "red", "CMDB data is not trusted enough for AI, knowledge graph, or data fabric use."
    if score == 100:
        return score, "CI Agentically Trusted", "green", "CI is sufficiently owned, supported, validated, change-controlled, evidenced, rollback-ready, and graph-ready."
    return score, "Conditional Agentic Trust", "yellow", "CI may support limited AI advisory use with restrictions and remediation tracking."


try:
    AGENTTRUST_EXPECTED_ROUTES.extend([
        "/citrust/agentic-cmdb-assurance",
        "/citrust/ai-agent-registry",
        "/citrust/agent-ci-impact-map",
        "/citrust/ai-control-tower-assurance",
        "/citrust/agent-runtime-evidence",
        "/citrust/gxp-agent-guardrails",
        "/citrust/knowledge-graph-data-fabric-readiness",
        "/citrust/agentic-readiness-simulator",
        "/citrust/agentic-cmdb-json"
    ])
except Exception:
    pass


@app.route("/citrust/agentic-cmdb-assurance")
@app.route("/citrust/ai-agent-readiness")
@app.route("/agenttrust/citrust-agentic-cmdb-assurance")
def citrust_agentic_cmdb_assurance():
    gap_rows = citrust_agentic_gap_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">CITrust™ Agentic Layer</div><div class="value" style="color:var(--green);">Active</div><div class="note">AI agent assurance added to CI governance.</div></div>
        <div class="metric"><div class="label">Agent Registry</div><div class="value" style="color:var(--blue);">Mapped</div><div class="note">Agents linked to CI and workflow touchpoints.</div></div>
        <div class="metric"><div class="label">Runtime Evidence</div><div class="value" style="color:var(--yellow);">Required</div><div class="note">What acted, why, who approved, what changed.</div></div>
        <div class="metric"><div class="label">GxP Guardrails</div><div class="value" style="color:var(--red);">Enforced</div><div class="note">GMP, validated, cutover-sensitive CIs require QA route.</div></div>
        <div class="metric"><div class="label">Control Tower Overlay</div><div class="value" style="color:var(--orange);">Assurance</div><div class="note">Regulated-pharma governance layer over agentic workflow.</div></div>
        <div class="metric"><div class="label">Graph Readiness</div><div class="value" style="color:var(--purple);">Scored</div><div class="note">CMDB data must be trusted before feeding AI.</div></div>
    </section>

    <section class="section">
        <h2>CITrust™ Agentic CMDB Assurance Bridge</h2>
        <div class="answer">
            <strong>Purpose:</strong> extend CITrust™ from traditional CMDB readiness into AI-agentic CMDB assurance.
            This answers: <strong>Can this CI be trusted enough for an AI agent to read, recommend, route, map, summarize, or act on it?</strong>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Gap</th>
                    <th>Coverage</th>
                    <th>CITrust™ Addition</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {gap_rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Core Rule</h2>
        <div class="answer">
            Bad CMDB data creates bad AI decisions. CITrust™ now prevents AI agents from relying on CIs that are ownerless,
            supportless, orphaned, validation-unclear, change-uncontrolled, evidence-weak, or not ready for graph/data-fabric use.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic CMDB Assurance",
        "AI agent assurance bridge for ServiceNow CMDB, CI impact mapping, runtime evidence, GxP guardrails, control tower overlay, and knowledge graph readiness.",
        body
    )


@app.route("/citrust/ai-agent-registry")
@app.route("/citrust/agent-registry")
@app.route("/citrust/service-now-ai-agent-registry")
def citrust_ai_agent_registry():
    rows = citrust_ai_agent_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ AI Agent Registry</h2>
        <p>
            This registry identifies AI agents that may touch, influence, recommend, route, map, or summarize CI and ServiceNow records.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Agent ID</th>
                    <th>AI Agent</th>
                    <th>Touchpoint</th>
                    <th>CI Impact</th>
                    <th>Risk</th>
                    <th>Required Guardrail</th>
                    <th>Required Evidence</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Registry Rule</h2>
        <div class="answer">
            CITrust™ should know which AI agents touch which CI, workflow, system, support model, validation record,
            change process, and regulated operation.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ AI Agent Registry",
        "AI agent registry for CMDB, ServiceNow, MyAccess, CyberArk, GxP, readiness, and knowledge graph touchpoints.",
        body
    )


@app.route("/citrust/agent-ci-impact-map")
@app.route("/citrust/agent-to-ci-impact-map")
@app.route("/citrust/ci-agent-impact-map")
def citrust_agent_ci_impact_map():
    rows = citrust_agent_ci_control_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agent-to-CI Impact Mapping</h2>
        <p>
            This map defines the controls required before an AI agent can influence a CI, CI relationship, support group,
            validation state, change state, or regulated process.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Control ID</th>
                    <th>Control</th>
                    <th>Assurance Question</th>
                    <th>Required Evidence</th>
                    <th>Block Condition</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Impact Mapping Rule</h2>
        <div class="answer">
            An AI agent should not act on or recommend changes to a GMP CI without knowing CI impact,
            validation status, owner, support group, lifecycle state, and change-control state.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agent-to-CI Impact Map",
        "Agent-to-CI impact mapping for AI actions touching CI ownership, support group, GxP status, change control, runtime evidence, and knowledge graph readiness.",
        body
    )


@app.route("/citrust/ai-control-tower-assurance")
@app.route("/citrust/control-tower-assurance")
@app.route("/citrust/agent-control-tower-assurance")
def citrust_ai_control_tower_assurance():
    body = """
    <section class="section">
        <h2>CITrust™ AI Control Tower Assurance Overlay</h2>
        <p>
            CITrust™ does not need to replace an enterprise AI control tower. It adds a regulated CMDB assurance layer
            focused on ServiceNow, CI trust, GxP readiness, owner accountability, and runtime evidence.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Control Tower Area</th>
                    <th>CITrust™ Assurance Overlay</th>
                    <th>Evidence Required</th>
                    <th>Decision</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent inventory</td><td>Which AI agents touch CMDB, CI, MyAccess, CyberArk, GxP, or cutover workflows?</td><td>AI Agent Registry and agent-to-CI map.</td><td><span class="badge green">Register and govern</span></td></tr>
                <tr><td>Agent action</td><td>What CI did the agent read, recommend, update, route, or summarize?</td><td>Runtime evidence, CI ID, action type, reviewer, outcome.</td><td><span class="badge yellow">Evidence required</span></td></tr>
                <tr><td>Risk routing</td><td>Does the action touch GMP, validation, QA, cyber, access, privileged route, or change control?</td><td>GxP/cyber/change routing record.</td><td><span class="badge red">Escalate or block</span></td></tr>
                <tr><td>Data quality</td><td>Is the CMDB reliable enough for AI reasoning?</td><td>Completeness, owner coverage, relationship quality, orphan check.</td><td><span class="badge orange">Score before use</span></td></tr>
                <tr><td>Audit defense</td><td>Can the AI-assisted CI decision be replayed?</td><td>Decision replay, evidence lineage, approval record.</td><td><span class="badge purple">Audit-ready only if replayable</span></td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ AI Control Tower Assurance",
        "Regulated CMDB assurance overlay for AI control tower, agent inventory, runtime evidence, risk routing, data quality, and audit defense.",
        body
    )


@app.route("/citrust/agent-runtime-evidence")
@app.route("/citrust/ai-agent-runtime-evidence")
@app.route("/citrust/ci-agent-runtime-evidence")
def citrust_agent_runtime_evidence():
    body = """
    <section class="section">
        <h2>CITrust™ Agent Runtime Evidence</h2>
        <p>
            Runtime evidence proves what the AI agent did, why it acted, who reviewed it, what CI it touched,
            whether change control exists, and whether rollback exists.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Evidence Element</th>
                    <th>Required Content</th>
                    <th>Why It Matters</th>
                    <th>If Missing</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent identity</td><td>Agent ID, model, owner, operating license.</td><td>Shows which AI actor influenced CI.</td><td><span class="badge red">Unknown actor</span></td></tr>
                <tr><td>CI identity</td><td>CI ID, CI class, lifecycle state, owner, support group, LCM.</td><td>Shows operational object touched.</td><td><span class="badge red">Cannot defend CI impact</span></td></tr>
                <tr><td>Source evidence</td><td>Fields, records, relationships, documents, or tickets used.</td><td>Shows why AI made recommendation.</td><td><span class="badge red">Unsupported recommendation</span></td></tr>
                <tr><td>Action type</td><td>Read, summarize, recommend, route, map, draft, update, trigger.</td><td>Determines authority level.</td><td><span class="badge orange">Authority unclear</span></td></tr>
                <tr><td>Human decision</td><td>Reviewer, owner, approval/rejection, timestamp, comment.</td><td>Preserves human accountability.</td><td><span class="badge red">Hidden approval risk</span></td></tr>
                <tr><td>Change linkage</td><td>Change record, impact, approval, rollback, post-check.</td><td>Protects validated and operational state.</td><td><span class="badge red">Change-control gap</span></td></tr>
                <tr><td>Rollback / recovery</td><td>How to undo or correct AI-influenced action.</td><td>Supports safe execution.</td><td><span class="badge red">No execution</span></td></tr>
                <tr><td>Outcome</td><td>Accepted, rejected, escalated, blocked, updated, rolled back.</td><td>Closes audit trail.</td><td><span class="badge orange">Incomplete replay</span></td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agent Runtime Evidence",
        "Runtime evidence for AI agents touching CMDB CIs, CI fields, CI relationships, change records, human decisions, rollback, and outcomes.",
        body
    )


@app.route("/citrust/gxp-agent-guardrails")
@app.route("/citrust/ai-gxp-guardrails")
@app.route("/citrust/gmp-ci-agent-guardrails")
def citrust_gxp_agent_guardrails():
    body = """
    <section class="section">
        <h2>CITrust™ GxP Agent Guardrails</h2>
        <p>
            These guardrails block or escalate AI actions when the CI is GMP, validated, cutover-sensitive,
            ownerless, supportless, orphaned, or missing change-control evidence.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Guardrail Trigger</th>
                    <th>Risk</th>
                    <th>Required Route</th>
                    <th>Default Decision</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>CI is GMP or validated.</td><td>Regulated operational reliance risk.</td><td>QA / Validation Owner.</td><td><span class="badge red">QA-governed only</span></td></tr>
                <tr><td>CI validation status is unknown.</td><td>AI may treat validated system as normal CI.</td><td>Validation Owner.</td><td><span class="badge red">Block regulated reliance</span></td></tr>
                <tr><td>CI owner, support group, or LCM missing.</td><td>No accountable owner.</td><td>CMDB / LCM Owner.</td><td><span class="badge red">Block AI reliance</span></td></tr>
                <tr><td>CI is cutover-sensitive.</td><td>AI recommendation may affect go-live readiness.</td><td>Cutover / QA / System Owner.</td><td><span class="badge orange">Human-gated only</span></td></tr>
                <tr><td>CI relationship mapping incomplete.</td><td>AI may infer wrong service impact.</td><td>Service Owner / Technical Owner.</td><td><span class="badge orange">Restrict graph use</span></td></tr>
                <tr><td>Change-control link missing.</td><td>AI-influenced action may bypass controlled change.</td><td>Change Owner.</td><td><span class="badge red">No update or trigger</span></td></tr>
                <tr><td>Rollback not defined.</td><td>Unsafe AI-influenced operational action.</td><td>System Owner / Change Owner.</td><td><span class="badge red">No execution</span></td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ GxP Agent Guardrails",
        "GxP and GMP guardrails for AI agents acting on validated, cutover-sensitive, ownerless, supportless, orphaned, or change-uncontrolled CIs.",
        body
    )


@app.route("/citrust/knowledge-graph-data-fabric-readiness")
@app.route("/citrust/knowledge-graph-readiness")
@app.route("/citrust/data-fabric-readiness")
def citrust_knowledge_graph_data_fabric_readiness():
    rows = citrust_kg_readiness_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Knowledge Graph / Data Fabric Readiness</h2>
        <p>
            This determines whether CMDB data is trusted enough to feed AI agents, knowledge graph, reporting,
            data fabric, or retrieval-augmented workflows.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Readiness Area</th>
                    <th>Question</th>
                    <th>AI Risk</th>
                    <th>Required Control</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Graph Readiness Rule</h2>
        <div class="answer">
            Do not feed weak CMDB data into AI. Knowledge graph and data fabric readiness require complete CI identity,
            validated relationships, GxP metadata, ownership, change alignment, and runtime replay.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Knowledge Graph Data Fabric Readiness",
        "CMDB data readiness screen for AI agents, knowledge graph, data fabric, relationship quality, ownership, GxP metadata, and evidence replay.",
        body
    )


@app.route("/citrust/agentic-readiness-simulator", methods=["GET", "POST"])
@app.route("/citrust/ci-agent-readiness-simulator", methods=["GET", "POST"])
@app.route("/citrust/agentic-ci-simulator", methods=["GET", "POST"])
def citrust_agentic_readiness_simulator():
    from flask import request

    owner = request.form.get("owner", "yes")
    support = request.form.get("support", "yes")
    validation = request.form.get("validation", "yes")
    change = request.form.get("change", "yes")
    gxp = request.form.get("gxp", "yes")
    runtime = request.form.get("runtime", "yes")
    rollback = request.form.get("rollback", "yes")
    graph = request.form.get("graph", "yes")

    score, decision, badge, reason = citrust_agentic_readiness_decision(
        owner, support, validation, change, gxp, runtime, rollback, graph
    )

    def selected(value, expected):
        return "selected" if value == expected else ""

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Agentic CI Score</div><div class="value" style="color:var(--green);">{score}%</div><div class="note">Calculated from CI agentic readiness controls.</div></div>
        <div class="metric"><div class="label">Decision</div><div class="value" style="color:var(--yellow);">{decision}</div><div class="note">{reason}</div></div>
    </section>

    <section class="section">
        <h2>CITrust™ Agentic Readiness Simulator</h2>
        <p>
            Simulate whether a CI is trusted enough for AI agent reliance, recommendation, mapping, graph feed, or controlled action.
        </p>

        <form method="POST" action="/citrust/agentic-readiness-simulator">
            <table>
                <tbody>
                    <tr><td><strong>CI Owner / LCM Ready?</strong></td><td><select name="owner" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(owner, "yes")}>Yes</option><option value="no" {selected(owner, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Support Group Ready?</strong></td><td><select name="support" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(support, "yes")}>Yes</option><option value="no" {selected(support, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Validation Status Known?</strong></td><td><select name="validation" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(validation, "yes")}>Yes</option><option value="no" {selected(validation, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Change-Control Route Ready?</strong></td><td><select name="change" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(change, "yes")}>Yes</option><option value="no" {selected(change, "no")}>No</option></select></td></tr>
                    <tr><td><strong>CI is GMP / GxP / Validated?</strong></td><td><select name="gxp" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(gxp, "yes")}>Yes</option><option value="no" {selected(gxp, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Runtime Evidence Ready?</strong></td><td><select name="runtime" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(runtime, "yes")}>Yes</option><option value="no" {selected(runtime, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Rollback / Recovery Ready?</strong></td><td><select name="rollback" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(rollback, "yes")}>Yes</option><option value="no" {selected(rollback, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Knowledge Graph / Data Fabric Ready?</strong></td><td><select name="graph" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(graph, "yes")}>Yes</option><option value="no" {selected(graph, "no")}>No</option></select></td></tr>
                </tbody>
            </table>

            <button type="submit" style="margin-top:16px;padding:12px 18px;border-radius:12px;border:0;background:#2563eb;color:white;font-weight:800;">Run Agentic CI Readiness Check</button>
        </form>
    </section>

    <section class="section">
        <h2>Agentic CI Decision</h2>
        <div class="answer">
            <strong>Score:</strong> {score}%<br>
            <strong>Decision:</strong> <span class="badge {badge}">{decision}</span><br>
            <strong>Reason:</strong> {reason}
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Readiness Simulator",
        "Simulator for AI agent readiness against CI ownership, support group, validation status, change control, GxP impact, runtime evidence, rollback, and knowledge graph readiness.",
        body
    )


@app.route("/citrust/agentic-cmdb-json")
@app.route("/citrust/ai-agent-cmdb-json")
@app.route("/citrust/agentic-readiness-json")
def citrust_agentic_cmdb_json():
    from flask import jsonify

    return jsonify({
        "module": "CITrust™",
        "capability": "Agentic CMDB Assurance Bridge",
        "primary_question": "Can this CI be trusted enough for AI agent reliance or action?",
        "gap_coverage": CITRUST_AGENTIC_GAP_COVERAGE,
        "ai_agent_register": CITRUST_AI_AGENT_REGISTER,
        "agent_ci_impact_controls": CITRUST_AGENT_CI_IMPACT_CONTROLS,
        "knowledge_graph_readiness": CITRUST_KNOWLEDGE_GRAPH_READINESS,
        "minimum_conditions": [
            "AI agent is registered and owned",
            "Agent-to-CI touchpoint is known",
            "CI owner, support group, and LCM are present",
            "GMP / validation / QA status is known",
            "Change-control route exists where required",
            "Runtime evidence captures action, rationale, reviewer, outcome, and rollback",
            "GxP, cyber, access, and cutover guardrails are active",
            "CMDB data is complete enough for knowledge graph or data fabric use",
            "Weak CMDB data is blocked from AI reliance"
        ],
        "default_decision": "Do not allow AI agent reliance on a CI unless ownership, support, validation, change-control, runtime evidence, rollback, and graph readiness are established"
    })

# ============================================================
# END CITRUST_AGENTIC_CMDB_ASSURANCE_BRIDGE_V1_ACTIVE
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

print("CITrust Agentic CMDB Assurance Bridge installed.")
print(f"Inserted before: {target_found}")
