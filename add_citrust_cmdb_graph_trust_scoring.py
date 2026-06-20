from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_CMDB_GRAPH_TRUST_SCORING_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("CITrust CMDB Graph Trust Scoring Engine already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base shell not found. Install AgentTrust base module first.")

nav_old = '<a href="/citrust/knowledge-graph-data-fabric-readiness" class="dark">Graph Readiness</a>'
nav_new = '''<a href="/citrust/knowledge-graph-data-fabric-readiness" class="dark">Graph Readiness</a>
                    <a href="/citrust/cmdb-graph-trust-score" class="secondary">Graph Trust Score</a>
                    <a href="/citrust/ai-data-fabric-gate" class="dark">Data Fabric Gate</a>
                    <a href="/citrust/rag-readiness-gate" class="dark">RAG Gate</a>
                    <a href="/citrust/graph-trust-simulator" class="dark">Graph Sim</a>'''

if nav_old in text and "/citrust/cmdb-graph-trust-score" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# CITRUST_CMDB_GRAPH_TRUST_SCORING_ENGINE_V1_ACTIVE
# CITrust™ CMDB Graph Trust Scoring Engine,
# AI Data Fabric Gate, RAG Readiness Gate,
# CI Data Quality Scorecard, Relationship Confidence Score,
# GxP Metadata Trust Gate, Graph Export Control,
# Graph Trust Simulator, and JSON Export
# ============================================================

CITRUST_GRAPH_TRUST_DOMAINS = [
    {
        "domain_id": "CGT-001",
        "domain": "CI Identity Completeness",
        "trust_question": "Does the CI have complete identity fields required for AI reasoning?",
        "required_fields": "CI name, class, environment, lifecycle state, owner, technical owner, support group, LCM.",
        "ai_failure_mode": "AI reasons over incomplete, duplicated, stale, or misclassified CI records.",
        "minimum_score": "90%"
    },
    {
        "domain_id": "CGT-002",
        "domain": "Ownership and Accountability",
        "trust_question": "Can every CI in the graph be traced to accountable human owners?",
        "required_fields": "Business owner, technical owner, support group, LCM, CMDB contact, assignment group.",
        "ai_failure_mode": "AI recommends action on ownerless or supportless CI.",
        "minimum_score": "95%"
    },
    {
        "domain_id": "CGT-003",
        "domain": "Relationship Confidence",
        "trust_question": "Are relationships between application, service, infrastructure, database, and business service validated?",
        "required_fields": "Depends on, runs on, supports, hosted on, mapped application service, business service.",
        "ai_failure_mode": "AI infers wrong dependency, wrong impact, or wrong support route.",
        "minimum_score": "85%"
    },
    {
        "domain_id": "CGT-004",
        "domain": "GxP / Validation Metadata",
        "trust_question": "Does the CI show whether it is GMP, validated, QA-relevant, or inspection-sensitive?",
        "required_fields": "GMP class, validation status, QA owner, validation owner, regulated impact flag.",
        "ai_failure_mode": "AI treats regulated CI as ordinary operational CI.",
        "minimum_score": "100% for regulated CIs"
    },
    {
        "domain_id": "CGT-005",
        "domain": "Change-Control Alignment",
        "trust_question": "Are CI changes, mappings, and cutover-sensitive updates tied to change-control evidence?",
        "required_fields": "Change record, implementation state, rollback, post-change verification, cutover status.",
        "ai_failure_mode": "AI suggests or triggers action outside controlled change process.",
        "minimum_score": "90%"
    },
    {
        "domain_id": "CGT-006",
        "domain": "Runtime Evidence Readiness",
        "trust_question": "Can AI-assisted CI decisions be replayed from source to outcome?",
        "required_fields": "Source CI, agent ID, prompt, tool-call, reviewer, decision, outcome, rollback.",
        "ai_failure_mode": "AI-assisted decision cannot be defended during audit or investigation.",
        "minimum_score": "95%"
    },
    {
        "domain_id": "CGT-007",
        "domain": "Orphan / Stale CI Control",
        "trust_question": "Are orphaned, stale, unsupported, or unowned CIs excluded from AI reliance?",
        "required_fields": "Orphan status, last verified date, owner confirmation, stale flag, remediation status.",
        "ai_failure_mode": "AI trusts abandoned or inaccurate CI records.",
        "minimum_score": "95%"
    },
    {
        "domain_id": "CGT-008",
        "domain": "Graph Export Control",
        "trust_question": "Is the CMDB data approved for export into AI, RAG, knowledge graph, or data fabric?",
        "required_fields": "Export owner, approved purpose, data boundary, graph trust score, exception status.",
        "ai_failure_mode": "Untrusted CMDB data contaminates downstream AI and analytics.",
        "minimum_score": "90%"
    }
]


CITRUST_AI_DATA_FABRIC_GATES = [
    {
        "gate_id": "CDF-001",
        "gate": "Source System Trust",
        "question": "Is ServiceNow CMDB the approved source for the CI data being exported?",
        "required_evidence": "CMDB source confirmation, extract owner, extract date, export scope.",
        "decision": "Block if source is unclear."
    },
    {
        "gate_id": "CDF-002",
        "gate": "Data Boundary Approval",
        "question": "Is the exported CI data allowed for AI, graph, dashboard, or data fabric use?",
        "required_evidence": "Approved purpose, data classification, sensitive field review.",
        "decision": "Restrict if boundary is unclear."
    },
    {
        "gate_id": "CDF-003",
        "gate": "Graph Trust Score",
        "question": "Does the CI set meet minimum graph trust threshold?",
        "required_evidence": "Completeness, ownership, relationship, GxP, change, evidence, orphan scores.",
        "decision": "Do not feed graph if score is below threshold."
    },
    {
        "gate_id": "CDF-004",
        "gate": "GxP Exclusion / QA Route",
        "question": "Does the export contain GMP, validated, QA, or inspection-sensitive CIs?",
        "required_evidence": "GxP metadata screen, QA owner decision, regulated-data boundary.",
        "decision": "QA-governed export only."
    },
    {
        "gate_id": "CDF-005",
        "gate": "Relationship Validation",
        "question": "Are exported relationships validated enough for downstream AI inference?",
        "required_evidence": "Relationship confidence score, owner review, exception list.",
        "decision": "Exclude weak relationships from graph reasoning."
    },
    {
        "gate_id": "CDF-006",
        "gate": "Exception Declaration",
        "question": "Are known CMDB gaps visible before export?",
        "required_evidence": "Ownerless CI list, orphan list, stale CI list, incomplete relationship list.",
        "decision": "Conditional export only with declared exceptions."
    },
    {
        "gate_id": "CDF-007",
        "gate": "Refresh and Drift Control",
        "question": "Will graph/data fabric be refreshed when CMDB changes?",
        "required_evidence": "Refresh cadence, drift trigger, change linkage, owner.",
        "decision": "Do not rely on stale graph data."
    }
]


CITRUST_RAG_READINESS_CONTROLS = [
    {
        "control_id": "RAG-001",
        "control": "Retrieval Source Control",
        "requirement": "AI retrieval must know whether the CI source is approved, current, and owner-confirmed.",
        "risk_if_missing": "RAG returns stale or unowned CI data."
    },
    {
        "control_id": "RAG-002",
        "control": "Citation and Source Lineage",
        "requirement": "AI answer must cite or link back to source CI, relationship, owner, and evidence reference.",
        "risk_if_missing": "AI output cannot be verified."
    },
    {
        "control_id": "RAG-003",
        "control": "GxP Context Preservation",
        "requirement": "GMP, validation, QA, and regulated flags must travel with retrieved CI data.",
        "risk_if_missing": "AI may give unrestricted advice about regulated CI."
    },
    {
        "control_id": "RAG-004",
        "control": "Relationship Confidence Filter",
        "requirement": "Low-confidence CI relationships must be excluded or clearly labelled.",
        "risk_if_missing": "AI may infer false dependency."
    },
    {
        "control_id": "RAG-005",
        "control": "Ownerless CI Suppression",
        "requirement": "Ownerless or orphaned CIs must not be treated as trusted retrieval facts.",
        "risk_if_missing": "AI may route action to no accountable owner."
    },
    {
        "control_id": "RAG-006",
        "control": "Change-State Awareness",
        "requirement": "AI retrieval must know whether the CI is in change, cutover, migration, validation, or decommission state.",
        "risk_if_missing": "AI may recommend action during unstable state."
    }
]


def citrust_graph_trust_domain_rows():
    rows = ""
    for item in CITRUST_GRAPH_TRUST_DOMAINS:
        rows += f"""
        <tr>
            <td><strong>{item["domain_id"]}</strong></td>
            <td><span class="badge blue">{item["domain"]}</span></td>
            <td>{item["trust_question"]}</td>
            <td>{item["required_fields"]}</td>
            <td><span class="badge red">{item["ai_failure_mode"]}</span></td>
            <td><span class="badge green">{item["minimum_score"]}</span></td>
        </tr>
        """
    return rows


def citrust_data_fabric_gate_rows():
    rows = ""
    for item in CITRUST_AI_DATA_FABRIC_GATES:
        rows += f"""
        <tr>
            <td><strong>{item["gate_id"]}</strong></td>
            <td><span class="badge blue">{item["gate"]}</span></td>
            <td>{item["question"]}</td>
            <td>{item["required_evidence"]}</td>
            <td><span class="badge orange">{item["decision"]}</span></td>
        </tr>
        """
    return rows


def citrust_rag_readiness_rows():
    rows = ""
    for item in CITRUST_RAG_READINESS_CONTROLS:
        rows += f"""
        <tr>
            <td><strong>{item["control_id"]}</strong></td>
            <td><span class="badge blue">{item["control"]}</span></td>
            <td>{item["requirement"]}</td>
            <td><span class="badge red">{item["risk_if_missing"]}</span></td>
        </tr>
        """
    return rows


def citrust_graph_trust_decision(identity, ownership, relationships, gxp, change, evidence, orphan, export):
    checks = [identity, ownership, relationships, gxp, change, evidence, orphan, export]
    score = int((sum(1 for item in checks if item == "yes") / len(checks)) * 100)

    if identity != "yes":
        return score, "Block Graph Feed", "red", "CI identity is incomplete."
    if ownership != "yes":
        return score, "Block AI Reliance", "red", "CI ownership and accountability are incomplete."
    if gxp != "yes":
        return score, "QA-Governed Only", "red", "GxP / validation metadata is missing or not approved."
    if orphan != "yes":
        return score, "Exclude From AI Graph", "red", "Orphan, stale, or unsupported CI risk exists."
    if relationships != "yes":
        return score, "Relationship-Limited Graph", "orange", "CI relationships are not validated enough for AI inference."
    if change != "yes":
        return score, "Change-Control Restriction", "orange", "Change-control alignment is incomplete."
    if evidence != "yes":
        return score, "No Audit-Defensible AI Use", "red", "Runtime evidence and decision replay are incomplete."
    if export != "yes":
        return score, "Do Not Export", "red", "AI, graph, RAG, or data fabric export is not approved."
    if score == 100:
        return score, "Graph Trusted for Governed AI Use", "green", "CMDB data is ready for governed AI, RAG, graph, and data fabric use."
    if score >= 75:
        return score, "Conditional Graph Use", "yellow", "CMDB data may support limited AI use with declared restrictions."
    return score, "Not Graph Ready", "red", "CMDB data quality is too weak for AI graph or data fabric reliance."


try:
    AGENTTRUST_EXPECTED_ROUTES.extend([
        "/citrust/cmdb-graph-trust-score",
        "/citrust/ci-data-quality-scorecard",
        "/citrust/relationship-confidence-score",
        "/citrust/ai-data-fabric-gate",
        "/citrust/rag-readiness-gate",
        "/citrust/gxp-metadata-trust-gate",
        "/citrust/graph-export-control",
        "/citrust/graph-trust-simulator",
        "/citrust/cmdb-graph-trust-json"
    ])
except Exception:
    pass


@app.route("/citrust/cmdb-graph-trust-score")
@app.route("/citrust/graph-trust-score")
@app.route("/citrust/cmdb-ai-trust-score")
def citrust_cmdb_graph_trust_score():
    rows = citrust_graph_trust_domain_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Graph Trust Engine</div><div class="value" style="color:var(--green);">Active</div><div class="note">CMDB AI-readiness scoring enabled.</div></div>
        <div class="metric"><div class="label">Trust Domains</div><div class="value" style="color:var(--blue);">8</div><div class="note">Identity, ownership, relationship, GxP, change, evidence, orphan, export.</div></div>
        <div class="metric"><div class="label">Graph Feed</div><div class="value" style="color:var(--yellow);">Gated</div><div class="note">Weak CMDB data blocked from AI graph.</div></div>
        <div class="metric"><div class="label">GxP Metadata</div><div class="value" style="color:var(--red);">Mandatory</div><div class="note">Regulated CIs need QA-visible metadata.</div></div>
        <div class="metric"><div class="label">RAG Readiness</div><div class="value" style="color:var(--orange);">Controlled</div><div class="note">Retrieval must preserve source and confidence.</div></div>
        <div class="metric"><div class="label">Data Fabric</div><div class="value" style="color:var(--purple);">Approved Only</div><div class="note">Export requires trust score and owner approval.</div></div>
    </section>

    <section class="section">
        <h2>CITrust™ CMDB Graph Trust Scoring Engine</h2>
        <div class="answer">
            <strong>Purpose:</strong> score whether CMDB data is trusted enough to feed AI agents, RAG, knowledge graph,
            reporting, and enterprise data fabric. This prevents bad CI data from becoming automated AI reasoning.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Domain ID</th>
                    <th>Trust Domain</th>
                    <th>Trust Question</th>
                    <th>Required Fields</th>
                    <th>AI Failure Mode</th>
                    <th>Minimum Score</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Graph Trust Rule</h2>
        <div class="answer">
            CMDB data should not feed AI agents, graph, RAG, or data fabric until identity, ownership,
            relationships, GxP metadata, change state, runtime evidence, orphan status, and export approval are trusted.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ CMDB Graph Trust Score",
        "CMDB graph trust scoring engine for AI, RAG, knowledge graph, and data fabric readiness.",
        body
    )


@app.route("/citrust/ci-data-quality-scorecard")
@app.route("/citrust/cmdb-data-quality-scorecard")
@app.route("/citrust/ai-cmdb-data-quality")
def citrust_ci_data_quality_scorecard():
    body = """
    <section class="section">
        <h2>CITrust™ CI Data Quality Scorecard</h2>
        <p>
            This scorecard checks whether CI data is complete enough for AI-assisted reasoning.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Quality Area</th>
                    <th>Required Field / Evidence</th>
                    <th>AI Risk</th>
                    <th>Decision</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>CI identity</td><td>Name, class, environment, lifecycle state.</td><td>AI may confuse duplicate or stale records.</td><td><span class="badge red">Block if missing</span></td></tr>
                <tr><td>Ownership</td><td>Business owner, technical owner, support group, LCM.</td><td>AI may recommend action without accountability.</td><td><span class="badge red">Block if ownerless</span></td></tr>
                <tr><td>Service context</td><td>Business service, application service, mapped application service.</td><td>AI may misread service impact.</td><td><span class="badge orange">Restrict if incomplete</span></td></tr>
                <tr><td>Infrastructure context</td><td>Server, database, network, hosting, dependency relationship.</td><td>AI may infer wrong technical route.</td><td><span class="badge orange">Relationship review</span></td></tr>
                <tr><td>Regulated context</td><td>GMP class, validation status, QA owner, inspection sensitivity.</td><td>AI may bypass QA route.</td><td><span class="badge red">QA-governed</span></td></tr>
                <tr><td>Change context</td><td>Change record, cutover state, rollback, post-check.</td><td>AI may act during unstable state.</td><td><span class="badge red">Change gate</span></td></tr>
                <tr><td>Freshness</td><td>Last verified date, stale flag, reconciliation state.</td><td>AI may reason over old data.</td><td><span class="badge orange">Refresh required</span></td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ CI Data Quality Scorecard",
        "CI data quality scorecard for AI readiness across identity, ownership, service context, infrastructure context, regulated context, change context, and freshness.",
        body
    )


@app.route("/citrust/relationship-confidence-score")
@app.route("/citrust/cmdb-relationship-confidence")
@app.route("/citrust/ci-relationship-confidence")
def citrust_relationship_confidence_score():
    body = """
    <section class="section">
        <h2>CITrust™ Relationship Confidence Score</h2>
        <p>
            Relationship confidence determines whether AI can safely infer dependency, impact, support route, or service impact.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Relationship Type</th>
                    <th>Confidence Evidence</th>
                    <th>AI Use</th>
                    <th>If Confidence Is Weak</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Business Application → Application Service</td><td>Application owner and service owner confirmation.</td><td>Service impact reasoning.</td><td><span class="badge orange">Human-gated only</span></td></tr>
                <tr><td>Application Service → Infrastructure CI</td><td>Validated hosting / dependency map.</td><td>Technical dependency reasoning.</td><td><span class="badge red">Do not infer impact</span></td></tr>
                <tr><td>Application → Database</td><td>DB owner, connection evidence, support route.</td><td>Data dependency reasoning.</td><td><span class="badge orange">Require technical owner review</span></td></tr>
                <tr><td>CI → Business Service</td><td>Business service owner confirmation.</td><td>Operational impact routing.</td><td><span class="badge red">No service-impact claim</span></td></tr>
                <tr><td>CI → MyAccess / Support Group</td><td>Support group, assignment group, approver route.</td><td>Access and support routing.</td><td><span class="badge red">No access recommendation</span></td></tr>
                <tr><td>CI → Change Record</td><td>Change link, implementation window, rollback, post-check.</td><td>Change-aware AI reasoning.</td><td><span class="badge red">No update or trigger</span></td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Relationship Confidence Score",
        "Relationship confidence score for CMDB AI reasoning across application, service, infrastructure, database, support, access, and change relationships.",
        body
    )


@app.route("/citrust/ai-data-fabric-gate")
@app.route("/citrust/cmdb-data-fabric-gate")
@app.route("/citrust/data-fabric-gate")
def citrust_ai_data_fabric_gate():
    rows = citrust_data_fabric_gate_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ AI Data Fabric Gate</h2>
        <p>
            The AI Data Fabric Gate decides whether CMDB data can be exported to AI, analytics, graph, dashboard, or data fabric layers.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Gate ID</th>
                    <th>Gate</th>
                    <th>Question</th>
                    <th>Required Evidence</th>
                    <th>Decision</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Data Fabric Rule</h2>
        <div class="answer">
            Data fabric should not amplify untrusted CMDB data. CITrust™ requires source confirmation,
            boundary approval, trust scoring, GxP screen, relationship confidence, exception declaration, and refresh control.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ AI Data Fabric Gate",
        "Data fabric gate for exporting CMDB data into AI, knowledge graph, RAG, dashboard, or enterprise data fabric.",
        body
    )


@app.route("/citrust/rag-readiness-gate")
@app.route("/citrust/cmdb-rag-readiness")
@app.route("/citrust/ai-rag-readiness")
def citrust_rag_readiness_gate():
    rows = citrust_rag_readiness_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ RAG Readiness Gate</h2>
        <p>
            This gate determines whether CMDB data can be used in AI retrieval-augmented workflows.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Control ID</th>
                    <th>RAG Control</th>
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
        <h2>RAG Rule</h2>
        <div class="answer">
            RAG should not retrieve CMDB records as trusted facts unless source, owner, relationship confidence,
            GxP context, change state, and evidence lineage are preserved.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ RAG Readiness Gate",
        "RAG readiness gate for CMDB retrieval with source lineage, GxP context, owner suppression, relationship confidence, and change-state awareness.",
        body
    )


@app.route("/citrust/gxp-metadata-trust-gate")
@app.route("/citrust/gmp-metadata-trust-gate")
@app.route("/citrust/validation-metadata-trust-gate")
def citrust_gxp_metadata_trust_gate():
    body = """
    <section class="section">
        <h2>CITrust™ GxP Metadata Trust Gate</h2>
        <p>
            This gate protects GMP, validated, QA-relevant, and inspection-sensitive CI data before AI use.
        </p>

        <table>
            <thead>
                <tr>
                    <th>GxP Metadata</th>
                    <th>Required Field</th>
                    <th>AI Risk</th>
                    <th>Default Decision</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>GMP classification</td><td>GMP / non-GMP / unknown.</td><td>AI may under-control regulated CI.</td><td><span class="badge red">Block if unknown</span></td></tr>
                <tr><td>Validation status</td><td>Validated / not validated / in validation / unknown.</td><td>AI may recommend action against validated state.</td><td><span class="badge red">QA route required</span></td></tr>
                <tr><td>QA owner</td><td>Named QA or validation owner.</td><td>No regulated reviewer.</td><td><span class="badge red">No regulated reliance</span></td></tr>
                <tr><td>Inspection sensitivity</td><td>Inspection-relevant yes/no.</td><td>AI may create weak inspection evidence.</td><td><span class="badge orange">Evidence review</span></td></tr>
                <tr><td>Change state</td><td>In change / stable / cutover / migration / retired.</td><td>AI may act during unstable period.</td><td><span class="badge red">Change gate</span></td></tr>
                <tr><td>Evidence location</td><td>Validation evidence, change evidence, QA review evidence.</td><td>AI output cannot be defended.</td><td><span class="badge red">Evidence required</span></td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ GxP Metadata Trust Gate",
        "GxP metadata trust gate for CMDB AI use across GMP classification, validation status, QA owner, inspection sensitivity, change state, and evidence location.",
        body
    )


@app.route("/citrust/graph-export-control")
@app.route("/citrust/cmdb-graph-export-control")
@app.route("/citrust/ai-graph-export-control")
def citrust_graph_export_control():
    body = """
    <section class="section">
        <h2>CITrust™ Graph Export Control</h2>
        <p>
            Graph Export Control decides what CMDB data may leave ServiceNow into graph, AI, RAG, analytics, or data fabric environments.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Export Control</th>
                    <th>Required Evidence</th>
                    <th>Risk Controlled</th>
                    <th>Decision</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Export purpose</td><td>Approved AI, graph, reporting, or data fabric purpose.</td><td>Uncontrolled reuse.</td><td><span class="badge yellow">Purpose-bound</span></td></tr>
                <tr><td>Export owner</td><td>Named data owner and CMDB owner.</td><td>No accountability.</td><td><span class="badge red">Block if ownerless</span></td></tr>
                <tr><td>Field-level boundary</td><td>Included fields, excluded fields, sensitive field screen.</td><td>Data overexposure.</td><td><span class="badge orange">Minimize fields</span></td></tr>
                <tr><td>Trust score threshold</td><td>Graph trust score and exception list.</td><td>Bad data contaminates AI.</td><td><span class="badge red">Block low-score data</span></td></tr>
                <tr><td>GxP filter</td><td>GMP/validation/QA metadata and QA route.</td><td>Regulated data misuse.</td><td><span class="badge red">QA-governed</span></td></tr>
                <tr><td>Refresh control</td><td>Refresh cadence, stale data control, drift trigger.</td><td>AI uses old CMDB state.</td><td><span class="badge orange">Refresh required</span></td></tr>
                <tr><td>Replay link</td><td>Source CI reference and export audit record.</td><td>No lineage back to ServiceNow.</td><td><span class="badge red">No export if not traceable</span></td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Graph Export Control",
        "Graph export control for CMDB data moving into AI, RAG, knowledge graph, analytics, and data fabric layers.",
        body
    )


@app.route("/citrust/graph-trust-simulator", methods=["GET", "POST"])
@app.route("/citrust/cmdb-graph-simulator", methods=["GET", "POST"])
@app.route("/citrust/data-fabric-readiness-simulator", methods=["GET", "POST"])
def citrust_graph_trust_simulator():
    from flask import request

    identity = request.form.get("identity", "yes")
    ownership = request.form.get("ownership", "yes")
    relationships = request.form.get("relationships", "yes")
    gxp = request.form.get("gxp", "yes")
    change = request.form.get("change", "yes")
    evidence = request.form.get("evidence", "yes")
    orphan = request.form.get("orphan", "yes")
    export = request.form.get("export", "yes")

    score, decision, badge, reason = citrust_graph_trust_decision(
        identity, ownership, relationships, gxp, change, evidence, orphan, export
    )

    def selected(value, expected):
        return "selected" if value == expected else ""

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Graph Trust Score</div><div class="value" style="color:var(--green);">{score}%</div><div class="note">Calculated from CMDB graph readiness controls.</div></div>
        <div class="metric"><div class="label">Graph Decision</div><div class="value" style="color:var(--yellow);">{decision}</div><div class="note">{reason}</div></div>
    </section>

    <section class="section">
        <h2>CITrust™ Graph Trust Simulator</h2>
        <p>
            Simulate whether CMDB data is trusted enough for AI, RAG, graph, analytics, or data fabric use.
        </p>

        <form method="POST" action="/citrust/graph-trust-simulator">
            <table>
                <tbody>
                    <tr><td><strong>CI Identity Complete?</strong></td><td><select name="identity" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(identity, "yes")}>Yes</option><option value="no" {selected(identity, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Ownership / Accountability Complete?</strong></td><td><select name="ownership" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(ownership, "yes")}>Yes</option><option value="no" {selected(ownership, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Relationships Validated?</strong></td><td><select name="relationships" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(relationships, "yes")}>Yes</option><option value="no" {selected(relationships, "no")}>No</option></select></td></tr>
                    <tr><td><strong>GxP / Validation Metadata Ready?</strong></td><td><select name="gxp" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(gxp, "yes")}>Yes</option><option value="no" {selected(gxp, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Change-Control Alignment Ready?</strong></td><td><select name="change" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(change, "yes")}>Yes</option><option value="no" {selected(change, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Runtime Evidence / Replay Ready?</strong></td><td><select name="evidence" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(evidence, "yes")}>Yes</option><option value="no" {selected(evidence, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Orphan / Stale CI Control Ready?</strong></td><td><select name="orphan" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(orphan, "yes")}>Yes</option><option value="no" {selected(orphan, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Graph / RAG / Data Fabric Export Approved?</strong></td><td><select name="export" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(export, "yes")}>Yes</option><option value="no" {selected(export, "no")}>No</option></select></td></tr>
                </tbody>
            </table>

            <button type="submit" style="margin-top:16px;padding:12px 18px;border-radius:12px;border:0;background:#2563eb;color:white;font-weight:800;">Run Graph Trust Check</button>
        </form>
    </section>

    <section class="section">
        <h2>Graph Trust Decision</h2>
        <div class="answer">
            <strong>Score:</strong> {score}%<br>
            <strong>Decision:</strong> <span class="badge {badge}">{decision}</span><br>
            <strong>Reason:</strong> {reason}
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Graph Trust Simulator",
        "Simulator for CMDB graph trust, AI data fabric readiness, RAG readiness, relationship confidence, GxP metadata, and export approval.",
        body
    )


@app.route("/citrust/cmdb-graph-trust-json")
@app.route("/citrust/graph-trust-json")
@app.route("/citrust/data-fabric-gate-json")
def citrust_cmdb_graph_trust_json():
    from flask import jsonify

    return jsonify({
        "module": "CITrust™",
        "capability": "CMDB Graph Trust Scoring Engine + AI Data Fabric Gate",
        "primary_question": "Is this CMDB data trusted enough to feed AI agents, RAG, knowledge graph, analytics, or data fabric?",
        "graph_trust_domains": CITRUST_GRAPH_TRUST_DOMAINS,
        "ai_data_fabric_gates": CITRUST_AI_DATA_FABRIC_GATES,
        "rag_readiness_controls": CITRUST_RAG_READINESS_CONTROLS,
        "minimum_conditions": [
            "CI identity fields are complete",
            "CI ownership and accountability are complete",
            "CI relationships are validated or confidence-labelled",
            "GxP and validation metadata are preserved",
            "Change-control state is known",
            "Runtime evidence and replay are available",
            "Orphan, stale, and unsupported CIs are excluded",
            "Export purpose and owner are approved",
            "Graph, RAG, and data fabric feeds preserve source lineage and trust score"
        ],
        "default_decision": "Do not feed CMDB data into AI, RAG, graph, analytics, or data fabric until CI identity, ownership, relationships, GxP metadata, change state, evidence, orphan status, and export controls are trusted"
    })

# ============================================================
# END CITRUST_CMDB_GRAPH_TRUST_SCORING_ENGINE_V1_ACTIVE
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

print("CITrust CMDB Graph Trust Scoring Engine installed.")
print(f"Inserted before: {target_found}")
