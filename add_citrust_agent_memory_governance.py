from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_AGENT_MEMORY_CONTEXT_PROVENANCE_V1_ACTIVE"

if MARKER in text:
    print("CITrust Agent Memory Governance already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base shell not found. Install AgentTrust base module first.")

nav_old = '<a href="/citrust/agentic-workflow-governance-patterns" class="secondary">Workflow Patterns</a>'
nav_new = '''<a href="/citrust/agentic-workflow-governance-patterns" class="secondary">Workflow Patterns</a>
                    <a href="/citrust/agent-memory-governance" class="secondary">Agent Memory</a>
                    <a href="/citrust/context-provenance-center" class="dark">Context Provenance</a>
                    <a href="/citrust/stale-memory-suppression" class="dark">Stale Memory</a>
                    <a href="/citrust/memory-governance-simulator" class="dark">Memory Sim</a>'''

if nav_old in text and "/citrust/agent-memory-governance" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# CITRUST_AGENT_MEMORY_CONTEXT_PROVENANCE_V1_ACTIVE
# CITrust™ Agent Memory Governance + Context Provenance Center
# CMDB Memory Trust Gate, Stale Memory Suppression,
# RAG Memory Evidence, Agent Context Boundary,
# Memory Correction Workflow, Context Freshness Control,
# GxP / Cyber Memory Boundary, Memory Governance Simulator,
# and JSON Export
# ============================================================

CITRUST_AGENT_MEMORY_DOMAINS = [
    {
        "domain_id": "MEM-001",
        "memory_domain": "CMDB Memory",
        "description": "Historical CI names, owners, support groups, lifecycle states, relationships, and service mappings used by an AI agent.",
        "risk": "Agent may rely on stale, orphaned, ownerless, or incorrect CI memory.",
        "required_control": "Memory must be linked to current ServiceNow CI record and graph trust score.",
        "default_decision": "Suppress if CI trust score is weak."
    },
    {
        "domain_id": "MEM-002",
        "memory_domain": "Ownership Memory",
        "description": "Remembered business owner, technical owner, LCM, support group, assignment group, or approver route.",
        "risk": "Agent may route action to an outdated owner or wrong support group.",
        "required_control": "Verify owner fields against current CMDB and MyAccess / support group route.",
        "default_decision": "Refresh before recommendation."
    },
    {
        "domain_id": "MEM-003",
        "memory_domain": "GxP / Validation Memory",
        "description": "Remembered GMP class, validation status, QA owner, validation owner, regulated impact, or inspection sensitivity.",
        "risk": "Agent may treat a regulated CI as non-regulated because memory is stale.",
        "required_control": "QA / validation metadata must be pulled from approved current source.",
        "default_decision": "QA-governed if GxP memory is missing or stale."
    },
    {
        "domain_id": "MEM-004",
        "memory_domain": "Access / Cyber Memory",
        "description": "Remembered access route, MyAccess group, CyberArk / PSM requirement, privileged access context, or admin route.",
        "risk": "Agent may recommend access based on outdated cyber route.",
        "required_control": "Cybersecurity / access route must be verified from approved identity and access source.",
        "default_decision": "Cyber-gated."
    },
    {
        "domain_id": "MEM-005",
        "memory_domain": "Change / Cutover Memory",
        "description": "Remembered change state, cutover status, rollback plan, implementation window, or migration dependency.",
        "risk": "Agent may recommend action during unstable cutover or change-control state.",
        "required_control": "Change record and cutover state must be current and linked.",
        "default_decision": "Change-controlled."
    },
    {
        "domain_id": "MEM-006",
        "memory_domain": "Relationship Memory",
        "description": "Remembered CI dependency, application service mapping, business service mapping, infrastructure link, or database dependency.",
        "risk": "Agent may infer wrong impact or wrong downstream dependency.",
        "required_control": "Relationship confidence score and owner confirmation required.",
        "default_decision": "Human-gated if relationship confidence is weak."
    },
    {
        "domain_id": "MEM-007",
        "memory_domain": "Incident / Exception Memory",
        "description": "Remembered incidents, deviations, CAPAs, exceptions, control deficiencies, or open risks affecting a CI.",
        "risk": "Agent may ignore unresolved risk or repeat a known failure.",
        "required_control": "Open incident, deviation, CAPA, and exception state must be checked before reliance.",
        "default_decision": "Restrict if open risk exists."
    },
    {
        "domain_id": "MEM-008",
        "memory_domain": "User / Reviewer Memory",
        "description": "Remembered reviewer behavior, approver preference, local practice, or team decision pattern.",
        "risk": "Agent may over-personalize or bypass formal owner route.",
        "required_control": "Formal owner route overrides memory of informal preference.",
        "default_decision": "Use only as context, never as approval."
    }
]


CITRUST_CONTEXT_PROVENANCE_CONTROLS = [
    {
        "control_id": "CTX-001",
        "control": "Source Provenance",
        "question": "Where did the agent memory or context come from?",
        "required_evidence": "Source system, source record, source timestamp, extractor, owner.",
        "block_condition": "Unknown or unofficial source."
    },
    {
        "control_id": "CTX-002",
        "control": "Freshness Check",
        "question": "Is the memory current enough for CI, access, GxP, or change decision support?",
        "required_evidence": "Last verified date, current ServiceNow record, refresh timestamp.",
        "block_condition": "Stale memory or unverified historical context."
    },
    {
        "control_id": "CTX-003",
        "control": "Authority of Source",
        "question": "Is the memory based on an approved source of truth?",
        "required_evidence": "ServiceNow, MyAccess, CyberArk, QA validation source, change record, or approved evidence vault.",
        "block_condition": "Memory is based on informal note, chat, draft, or unsupported export."
    },
    {
        "control_id": "CTX-004",
        "control": "Context Boundary",
        "question": "Is the memory allowed for this agent, workflow, data class, and regulated use?",
        "required_evidence": "Approved use case, data classification, access scope, privacy boundary.",
        "block_condition": "Memory crosses privacy, cyber, vendor, GxP, or workflow boundary."
    },
    {
        "control_id": "CTX-005",
        "control": "GxP / Cyber Preservation",
        "question": "Does the memory preserve GMP, validation, QA, access, CyberArk, PSM, and privileged context?",
        "required_evidence": "GxP flag, validation status, QA owner, access route, cyber owner.",
        "block_condition": "Context strips regulated or cyber-critical flags."
    },
    {
        "control_id": "CTX-006",
        "control": "Correction Workflow",
        "question": "Can wrong memory be corrected, suppressed, and prevented from reuse?",
        "required_evidence": "Correction record, suppression rule, owner approval, retest evidence.",
        "block_condition": "No correction or suppression route."
    },
    {
        "control_id": "CTX-007",
        "control": "Replay Link",
        "question": "Can the agent memory be replayed back to the source and decision outcome?",
        "required_evidence": "Memory ID, source ID, agent action, reviewer decision, outcome.",
        "block_condition": "Memory cannot be traced to source or decision."
    }
]


CITRUST_STALE_MEMORY_SUPPRESSION_RULES = [
    {
        "memory_signal": "CI owner changed",
        "risk": "Agent may recommend old owner or wrong LCM.",
        "suppression_rule": "Suppress old owner memory and refresh from CMDB before recommendation.",
        "owner": "CMDB / LCM Owner"
    },
    {
        "memory_signal": "Support group changed",
        "risk": "Agent may route ticket or access request to wrong group.",
        "suppression_rule": "Suppress old support group and validate assignment group.",
        "owner": "Support / Service Owner"
    },
    {
        "memory_signal": "Validation status changed",
        "risk": "Agent may misclassify regulated state.",
        "suppression_rule": "Suppress old validation memory and route to QA / validation owner.",
        "owner": "QA / Validation Owner"
    },
    {
        "memory_signal": "CI relationship changed",
        "risk": "Agent may infer wrong service or infrastructure dependency.",
        "suppression_rule": "Suppress old relationship memory until relationship confidence is revalidated.",
        "owner": "Technical / Service Owner"
    },
    {
        "memory_signal": "Access route changed",
        "risk": "Agent may recommend wrong MyAccess or CyberArk route.",
        "suppression_rule": "Suppress old access memory and route to cybersecurity owner.",
        "owner": "Cybersecurity / Access Owner"
    },
    {
        "memory_signal": "Change or cutover state changed",
        "risk": "Agent may recommend action during unstable state.",
        "suppression_rule": "Suppress stable-state memory and refresh from change/cutover source.",
        "owner": "Change / Cutover Owner"
    },
    {
        "memory_signal": "Incident, exception, deviation, or CAPA opened",
        "risk": "Agent may ignore unresolved operational or regulated risk.",
        "suppression_rule": "Restrict AI reliance until open issue is reviewed.",
        "owner": "Risk / QA / Governance Owner"
    }
]


CITRUST_MEMORY_CORRECTION_WORKFLOW = [
    {
        "step": "Detect wrong memory",
        "action": "Identify stale, incorrect, unsupported, or unsafe context used by agent.",
        "evidence": "Agent output, memory source, source-of-truth comparison.",
        "owner": "Reviewer / Governance Owner"
    },
    {
        "step": "Suppress unsafe memory",
        "action": "Prevent reuse of wrong owner, support group, relationship, validation, access, or change context.",
        "evidence": "Suppression rule, affected agent, affected CI, expiry or correction condition.",
        "owner": "Platform / Agent Owner"
    },
    {
        "step": "Correct source context",
        "action": "Update or reconcile approved source if the source system is wrong.",
        "evidence": "ServiceNow correction, owner approval, change/control record if needed.",
        "owner": "CMDB / Source Owner"
    },
    {
        "step": "Refresh agent context",
        "action": "Reload approved CI, relationship, GxP, cyber, change, or evidence context.",
        "evidence": "Refresh timestamp, source record, context version.",
        "owner": "Agent / Data Owner"
    },
    {
        "step": "Retest recommendation",
        "action": "Run simulator or evaluator loop to confirm corrected context changes output.",
        "evidence": "Before/after output, evaluator score, reviewer decision.",
        "owner": "Control Testing Owner"
    },
    {
        "step": "Close correction",
        "action": "Capture closure evidence and owner signoff.",
        "evidence": "Correction record, signoff, replay package, monitoring condition.",
        "owner": "Governance / Audit Owner"
    }
]


def citrust_agent_memory_domain_rows():
    rows = ""
    for item in CITRUST_AGENT_MEMORY_DOMAINS:
        rows += f"""
        <tr>
            <td><strong>{item["domain_id"]}</strong></td>
            <td><span class="badge blue">{item["memory_domain"]}</span></td>
            <td>{item["description"]}</td>
            <td><span class="badge red">{item["risk"]}</span></td>
            <td>{item["required_control"]}</td>
            <td><span class="badge orange">{item["default_decision"]}</span></td>
        </tr>
        """
    return rows


def citrust_context_provenance_rows():
    rows = ""
    for item in CITRUST_CONTEXT_PROVENANCE_CONTROLS:
        rows += f"""
        <tr>
            <td><strong>{item["control_id"]}</strong></td>
            <td><span class="badge blue">{item["control"]}</span></td>
            <td>{item["question"]}</td>
            <td>{item["required_evidence"]}</td>
            <td><span class="badge red">{item["block_condition"]}</span></td>
        </tr>
        """
    return rows


def citrust_stale_memory_rows():
    rows = ""
    for item in CITRUST_STALE_MEMORY_SUPPRESSION_RULES:
        rows += f"""
        <tr>
            <td><strong>{item["memory_signal"]}</strong></td>
            <td><span class="badge red">{item["risk"]}</span></td>
            <td>{item["suppression_rule"]}</td>
            <td>{item["owner"]}</td>
        </tr>
        """
    return rows


def citrust_memory_correction_rows():
    rows = ""
    for item in CITRUST_MEMORY_CORRECTION_WORKFLOW:
        rows += f"""
        <tr>
            <td><strong>{item["step"]}</strong></td>
            <td>{item["action"]}</td>
            <td>{item["evidence"]}</td>
            <td>{item["owner"]}</td>
        </tr>
        """
    return rows


def citrust_memory_governance_decision(source, freshness, authority, boundary, gxpcyber, correction, replay):
    checks = [source, freshness, authority, boundary, gxpcyber, correction, replay]
    score = int((sum(1 for item in checks if item == "yes") / len(checks)) * 100)

    if source != "yes":
        return score, "Suppress Memory", "red", "Memory source is unknown or not traceable."
    if authority != "yes":
        return score, "Do Not Rely", "red", "Memory is not from an approved source of truth."
    if freshness != "yes":
        return score, "Refresh Required", "orange", "Memory may be stale and must be refreshed before use."
    if boundary != "yes":
        return score, "Boundary Review Required", "red", "Memory may cross privacy, cyber, GxP, vendor, or workflow boundary."
    if gxpcyber != "yes":
        return score, "QA / Cyber Route Required", "red", "Memory does not preserve GxP, validation, access, or privileged context."
    if correction != "yes":
        return score, "Correction Workflow Required", "orange", "Wrong memory cannot be corrected or suppressed."
    if replay != "yes":
        return score, "Not Audit-Defensible", "red", "Memory cannot be replayed to source and decision outcome."
    if score == 100:
        return score, "Memory Trusted With Controls", "green", "Memory is source-traceable, current, authorized, bounded, GxP/cyber-aware, correctable, and replayable."
    return score, "Conditional Memory Use", "yellow", "Memory may be used only with restrictions and remediation tracking."


try:
    AGENTTRUST_EXPECTED_ROUTES.extend([
        "/citrust/agent-memory-governance",
        "/citrust/context-provenance-center",
        "/citrust/cmdb-memory-trust-gate",
        "/citrust/stale-memory-suppression",
        "/citrust/rag-memory-evidence",
        "/citrust/agent-context-boundary",
        "/citrust/memory-correction-workflow",
        "/citrust/memory-governance-simulator",
        "/citrust/agent-memory-json"
    ])
except Exception:
    pass


@app.route("/citrust/agent-memory-governance")
@app.route("/citrust/ai-agent-memory-governance")
@app.route("/citrust/agent-memory-control")
def citrust_agent_memory_governance():
    rows = citrust_agent_memory_domain_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Agent Memory</div><div class="value" style="color:var(--green);">Governed</div><div class="note">Memory source, freshness, and boundary controls installed.</div></div>
        <div class="metric"><div class="label">Memory Domains</div><div class="value" style="color:var(--blue);">8</div><div class="note">CMDB, owner, GxP, cyber, change, relationship, incident, reviewer.</div></div>
        <div class="metric"><div class="label">Freshness</div><div class="value" style="color:var(--yellow);">Checked</div><div class="note">Stale memory is suppressed before reliance.</div></div>
        <div class="metric"><div class="label">GxP / Cyber</div><div class="value" style="color:var(--red);">Preserved</div><div class="note">Regulated and access context must not be stripped.</div></div>
        <div class="metric"><div class="label">Correction</div><div class="value" style="color:var(--orange);">Workflow</div><div class="note">Wrong memory can be corrected and retested.</div></div>
        <div class="metric"><div class="label">Replay</div><div class="value" style="color:var(--purple);">Required</div><div class="note">Memory must trace back to source and decision.</div></div>
    </section>

    <section class="section">
        <h2>CITrust™ Agent Memory Governance</h2>
        <div class="answer">
            <strong>Purpose:</strong> govern the memory and historical context AI agents use when reasoning about ServiceNow CIs,
            ownership, support groups, validation status, access routes, relationships, incidents, and change state.
            CITrust™ prevents stale CMDB memory from becoming trusted AI output.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Domain ID</th>
                    <th>Memory Domain</th>
                    <th>Description</th>
                    <th>Risk</th>
                    <th>Required Control</th>
                    <th>Default Decision</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Memory Governance Rule</h2>
        <div class="answer">
            AI memory is not automatically trusted. CITrust™ requires memory to be source-traceable, current,
            authorized, bounded, GxP/cyber-aware, correctable, and replayable before it can influence CI decisions.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agent Memory Governance",
        "Agent memory governance for CMDB context, ownership memory, GxP memory, cyber memory, change memory, relationship memory, incident memory, and reviewer memory.",
        body
    )


@app.route("/citrust/context-provenance-center")
@app.route("/citrust/context-provenance")
@app.route("/citrust/agent-context-provenance")
def citrust_context_provenance_center():
    rows = citrust_context_provenance_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Context Provenance Center</h2>
        <p>
            The Context Provenance Center proves where an AI agent's memory, context, or retrieved information came from.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Control ID</th>
                    <th>Control</th>
                    <th>Question</th>
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
        <h2>Provenance Rule</h2>
        <div class="answer">
            Context without provenance is not safe for regulated operations.
            Every memory item must link back to an approved source, timestamp, owner, boundary, and decision trail.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Context Provenance Center",
        "Context provenance center for AI agent memory source, freshness, authority, boundary, GxP/cyber preservation, correction workflow, and replay link.",
        body
    )


@app.route("/citrust/cmdb-memory-trust-gate")
@app.route("/citrust/ci-memory-trust-gate")
@app.route("/citrust/cmdb-context-trust-gate")
def citrust_cmdb_memory_trust_gate():
    body = """
    <section class="section">
        <h2>CITrust™ CMDB Memory Trust Gate</h2>
        <p>
            This gate decides whether AI agent memory about a CI can be trusted before recommendation or action.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Memory Check</th>
                    <th>Pass Condition</th>
                    <th>Failure Risk</th>
                    <th>Decision</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>CI identity memory</td><td>CI ID, class, environment, lifecycle state match current CMDB.</td><td>Wrong CI or stale CI.</td><td><span class="badge red">Refresh required</span></td></tr>
                <tr><td>Owner memory</td><td>Owner, technical owner, support group, and LCM match current record.</td><td>Wrong accountability route.</td><td><span class="badge red">Suppress if mismatch</span></td></tr>
                <tr><td>Relationship memory</td><td>Dependency map matches current validated relationship.</td><td>Wrong impact inference.</td><td><span class="badge orange">Human-gated</span></td></tr>
                <tr><td>GxP memory</td><td>GMP class, validation status, QA owner, and inspection sensitivity current.</td><td>Regulated CI under-controlled.</td><td><span class="badge red">QA-governed</span></td></tr>
                <tr><td>Change memory</td><td>Change state, cutover state, rollback, and post-check current.</td><td>AI acts during unstable state.</td><td><span class="badge red">Change-controlled</span></td></tr>
                <tr><td>Evidence memory</td><td>Memory links to approved source and replay evidence.</td><td>Audit trail gap.</td><td><span class="badge red">No reliance</span></td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ CMDB Memory Trust Gate",
        "CMDB memory trust gate for AI agent context about CI identity, ownership, relationships, GxP metadata, change state, and evidence lineage.",
        body
    )


@app.route("/citrust/stale-memory-suppression")
@app.route("/citrust/ai-stale-memory-suppression")
@app.route("/citrust/stale-context-suppression")
def citrust_stale_memory_suppression():
    rows = citrust_stale_memory_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Stale Memory Suppression</h2>
        <p>
            This suppresses historical AI memory when current ServiceNow, MyAccess, CyberArk, QA, or change-control evidence has changed.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Memory Signal</th>
                    <th>Risk</th>
                    <th>Suppression Rule</th>
                    <th>Owner</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Suppression Rule</h2>
        <div class="answer">
            Stale memory must not be treated as knowledge.
            CITrust™ suppresses old CI ownership, support, validation, relationship, access, change, and incident context until refreshed.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Stale Memory Suppression",
        "Stale memory suppression for AI agent memory about CI owners, support groups, validation status, relationships, access routes, change state, incidents, exceptions, deviations, and CAPAs.",
        body
    )


@app.route("/citrust/rag-memory-evidence")
@app.route("/citrust/agent-rag-memory-evidence")
@app.route("/citrust/rag-context-evidence")
def citrust_rag_memory_evidence():
    body = """
    <section class="section">
        <h2>CITrust™ RAG Memory Evidence</h2>
        <p>
            RAG memory must preserve source lineage, trust score, context boundary, and current-state confirmation.
        </p>

        <table>
            <thead>
                <tr>
                    <th>RAG Memory Element</th>
                    <th>Required Evidence</th>
                    <th>Risk If Missing</th>
                    <th>Default Decision</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Retrieved CI source</td><td>ServiceNow CI ID, record timestamp, extract timestamp.</td><td>Unverified retrieval.</td><td><span class="badge red">No reliance</span></td></tr>
                <tr><td>Trust score</td><td>CI completeness, ownership, relationship, GxP, change, orphan score.</td><td>Low-quality CMDB data becomes AI truth.</td><td><span class="badge red">Suppress if low score</span></td></tr>
                <tr><td>GxP context</td><td>GMP class, validation status, QA owner, regulated impact.</td><td>Regulated context stripped.</td><td><span class="badge red">QA route</span></td></tr>
                <tr><td>Cyber context</td><td>Access route, privileged flag, CyberArk / PSM requirement.</td><td>Access risk hidden.</td><td><span class="badge red">Cyber route</span></td></tr>
                <tr><td>Relationship confidence</td><td>Validated relationship, confidence score, owner confirmation.</td><td>False dependency inference.</td><td><span class="badge orange">Label or exclude</span></td></tr>
                <tr><td>Memory correction link</td><td>How wrong retrieval is corrected and suppressed.</td><td>Wrong output repeats.</td><td><span class="badge orange">Correction workflow</span></td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ RAG Memory Evidence",
        "RAG memory evidence for AI retrieval across ServiceNow CI source, graph trust score, GxP context, cyber context, relationship confidence, and correction workflow.",
        body
    )


@app.route("/citrust/agent-context-boundary")
@app.route("/citrust/ai-context-boundary")
@app.route("/citrust/context-boundary-control")
def citrust_agent_context_boundary():
    body = """
    <section class="section">
        <h2>CITrust™ Agent Context Boundary</h2>
        <p>
            The context boundary defines what memory or retrieved information an AI agent may use for a CI workflow.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Boundary Area</th>
                    <th>Allowed Use</th>
                    <th>Restricted Use</th>
                    <th>Owner Route</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>CMDB context</td><td>Current CI identity, owner, support, relationship, lifecycle state.</td><td>Stale exports or unsupported manual lists.</td><td>CMDB / LCM Owner.</td></tr>
                <tr><td>GxP context</td><td>Current QA-approved validation metadata.</td><td>Assumed validation status or informal notes.</td><td>QA / Validation Owner.</td></tr>
                <tr><td>Cyber context</td><td>Approved access route and privileged-impact decision.</td><td>Remembered access path or old CyberArk route.</td><td>Cybersecurity / Access Owner.</td></tr>
                <tr><td>Change context</td><td>Current change record, rollback, implementation state.</td><td>Old cutover plan or unapproved change notes.</td><td>Change / Cutover Owner.</td></tr>
                <tr><td>Reviewer context</td><td>Named formal reviewer route.</td><td>Memory of informal preference or prior behavior.</td><td>Process / Governance Owner.</td></tr>
                <tr><td>Vendor / external memory</td><td>Approved vendor evidence with contract boundary.</td><td>External AI memory without deletion or audit rights.</td><td>Vendor / Security / Legal Owner.</td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agent Context Boundary",
        "Agent context boundary for AI memory across CMDB context, GxP context, cyber context, change context, reviewer context, and vendor memory.",
        body
    )


@app.route("/citrust/memory-correction-workflow")
@app.route("/citrust/agent-memory-correction")
@app.route("/citrust/context-correction-workflow")
def citrust_memory_correction_workflow():
    rows = citrust_memory_correction_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Memory Correction Workflow</h2>
        <p>
            This workflow defines how wrong or stale AI memory is detected, suppressed, corrected, refreshed, retested, and closed.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Step</th>
                    <th>Action</th>
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
        <h2>Correction Rule</h2>
        <div class="answer">
            Wrong AI memory must be corrected at the source, suppressed in the agent, refreshed in context,
            retested, and closed with owner signoff.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Memory Correction Workflow",
        "Memory correction workflow for detecting, suppressing, correcting, refreshing, retesting, and closing wrong AI memory or stale context.",
        body
    )


@app.route("/citrust/memory-governance-simulator", methods=["GET", "POST"])
@app.route("/citrust/agent-memory-simulator", methods=["GET", "POST"])
@app.route("/citrust/context-provenance-simulator", methods=["GET", "POST"])
def citrust_memory_governance_simulator():
    from flask import request

    source = request.form.get("source", "yes")
    freshness = request.form.get("freshness", "yes")
    authority = request.form.get("authority", "yes")
    boundary = request.form.get("boundary", "yes")
    gxpcyber = request.form.get("gxpcyber", "yes")
    correction = request.form.get("correction", "yes")
    replay = request.form.get("replay", "yes")

    score, decision, badge, reason = citrust_memory_governance_decision(
        source, freshness, authority, boundary, gxpcyber, correction, replay
    )

    def selected(value, expected):
        return "selected" if value == expected else ""

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Memory Trust Score</div><div class="value" style="color:var(--green);">{score}%</div><div class="note">Calculated from memory governance controls.</div></div>
        <div class="metric"><div class="label">Memory Decision</div><div class="value" style="color:var(--yellow);">{decision}</div><div class="note">{reason}</div></div>
    </section>

    <section class="section">
        <h2>CITrust™ Memory Governance Simulator</h2>
        <p>
            Simulate whether AI agent memory or retrieved context can be trusted for ServiceNow / CMDB / GxP / access / change workflows.
        </p>

        <form method="POST" action="/citrust/memory-governance-simulator">
            <table>
                <tbody>
                    <tr><td><strong>Memory Source Traceable?</strong></td><td><select name="source" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(source, "yes")}>Yes</option><option value="no" {selected(source, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Memory Fresh / Current?</strong></td><td><select name="freshness" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(freshness, "yes")}>Yes</option><option value="no" {selected(freshness, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Approved Source of Truth?</strong></td><td><select name="authority" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(authority, "yes")}>Yes</option><option value="no" {selected(authority, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Context Boundary Approved?</strong></td><td><select name="boundary" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(boundary, "yes")}>Yes</option><option value="no" {selected(boundary, "no")}>No</option></select></td></tr>
                    <tr><td><strong>GxP / Cyber Context Preserved?</strong></td><td><select name="gxpcyber" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(gxpcyber, "yes")}>Yes</option><option value="no" {selected(gxpcyber, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Correction / Suppression Workflow Ready?</strong></td><td><select name="correction" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(correction, "yes")}>Yes</option><option value="no" {selected(correction, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Replay Link Ready?</strong></td><td><select name="replay" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(replay, "yes")}>Yes</option><option value="no" {selected(replay, "no")}>No</option></select></td></tr>
                </tbody>
            </table>

            <button type="submit" style="margin-top:16px;padding:12px 18px;border-radius:12px;border:0;background:#2563eb;color:white;font-weight:800;">Run Memory Trust Check</button>
        </form>
    </section>

    <section class="section">
        <h2>Memory Governance Decision</h2>
        <div class="answer">
            <strong>Score:</strong> {score}%<br>
            <strong>Decision:</strong> <span class="badge {badge}">{decision}</span><br>
            <strong>Reason:</strong> {reason}
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Memory Governance Simulator",
        "Simulator for AI agent memory governance across source, freshness, authority, boundary, GxP/cyber context, correction workflow, and replay link.",
        body
    )


@app.route("/citrust/agent-memory-json")
@app.route("/citrust/context-provenance-json")
@app.route("/citrust/memory-governance-json")
def citrust_agent_memory_json():
    from flask import jsonify

    return jsonify({
        "module": "CITrust™",
        "capability": "Agent Memory Governance + Context Provenance Center",
        "primary_question": "Can this AI agent memory or context be trusted for ServiceNow / CMDB / GxP / access / change workflows?",
        "agent_memory_domains": CITRUST_AGENT_MEMORY_DOMAINS,
        "context_provenance_controls": CITRUST_CONTEXT_PROVENANCE_CONTROLS,
        "stale_memory_suppression_rules": CITRUST_STALE_MEMORY_SUPPRESSION_RULES,
        "memory_correction_workflow": CITRUST_MEMORY_CORRECTION_WORKFLOW,
        "minimum_conditions": [
            "Memory source is traceable",
            "Memory is current and freshness-checked",
            "Memory comes from approved source of truth",
            "Context boundary is approved",
            "GxP, validation, cyber, access, and change context are preserved",
            "Stale memory is suppressed before reliance",
            "Wrong memory can be corrected and retested",
            "Memory can be replayed from source to AI decision outcome"
        ],
        "default_decision": "Do not allow AI memory or retrieved context to influence CI, access, GxP, relationship, or change decisions unless provenance, freshness, authority, boundary, correction, and replay controls are complete"
    })

# ============================================================
# END CITRUST_AGENT_MEMORY_CONTEXT_PROVENANCE_V1_ACTIVE
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

print("CITrust Agent Memory Governance installed.")
print(f"Inserted before: {target_found}")
