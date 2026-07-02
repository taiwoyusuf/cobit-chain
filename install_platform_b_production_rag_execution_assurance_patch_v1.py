from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_PLATFORM_B_PRODUCTION_RAG_EXECUTION_ASSURANCE_PATCH_V1_ACTIVE"
LIFECYCLE_SEQUENCE = "Discovery -> Visibility -> Governance -> Operationalization -> Execution Assurance -> Evidence -> Continuous Assurance -> Operational Trust"

PRODUCTION_RAG_ASSURANCE = {
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "new_lifecycle": False,
    "new_module": False,
    "architecture_instruction": "Do not create a new lifecycle or new module. Strengthen existing Operationalization, Execution Assurance, Evidence, Continuous Assurance, and Operational Trust capabilities.",
    "capability_name": "Production RAG Execution Assurance Enrichment",
    "lifecycle_sequence": LIFECYCLE_SEQUENCE,
    "enriched_stages": [
        "Operationalization",
        "Execution Assurance",
        "Evidence",
        "Continuous Assurance",
        "Operational Trust"
    ],
    "operating_system_principle": "Enterprise AI architectures should be evaluated as complete operational systems. Assurance Engineering continuously demonstrates that orchestration, retrieval, security, execution, evidence generation, and runtime infrastructure operate together in a trustworthy manner.",
    "core_question": "Can this production RAG workflow be operationally trusted across orchestration, retrieval, runtime execution, evidence generation, and continuous monitoring?",
    "operationalization_support": [
        "Semantic Kernel orchestration",
        "AI agent orchestration",
        "Plug-in execution",
        "Vector database integration",
        "Azure OpenAI integration",
        "Enterprise knowledge connectors",
        "Managed identities",
        "Secure runtime execution"
    ],
    "execution_assurance_domains": [
        {
            "domain": "Orchestration Assurance",
            "controls": [
                "Semantic Kernel workflow integrity",
                "Agent coordination",
                "Plug-in invocation",
                "Execution sequencing",
                "Failure recovery"
            ],
            "question": "Was the production RAG workflow orchestrated correctly from request to retrieval to response?"
        },
        {
            "domain": "Retrieval Assurance",
            "controls": [
                "Vector index freshness",
                "Change-feed synchronization",
                "Embedding integrity",
                "Retrieval accuracy",
                "Context relevance",
                "Source provenance"
            ],
            "question": "Was the retrieved knowledge current, relevant, traceable, and supported by trustworthy vector and source evidence?"
        },
        {
            "domain": "Runtime Assurance",
            "controls": [
                "Managed identity authentication",
                "Secretless execution",
                "Runtime authorization",
                "Infrastructure resilience",
                "Container health",
                "API reliability"
            ],
            "question": "Did runtime infrastructure, identity, authorization, APIs, containers, and services operate securely and reliably?"
        }
    ],
    "rag_execution_evidence_questions": [
        "Which documents were retrieved?",
        "Which vector index was used?",
        "Was the index current?",
        "Which embeddings supported retrieval?",
        "Which orchestrator executed the workflow?",
        "Which plug-ins were invoked?",
        "Which AI model generated the response?",
        "Which enterprise systems were accessed?",
        "What evidence supports the final answer?"
    ],
    "continuous_assurance_monitors": [
        "Index freshness",
        "Retrieval quality",
        "Embedding drift",
        "Knowledge synchronization",
        "Runtime health",
        "Security posture",
        "Operational trust"
    ],
    "operational_trust_evidence": [
        "RAG execution trace",
        "Retrieved document list",
        "Vector index identifier",
        "Index freshness evidence",
        "Embedding lineage",
        "Orchestrator execution trace",
        "Plug-in invocation trace",
        "Model invocation record",
        "Enterprise system access record",
        "Source provenance package",
        "Runtime identity evidence",
        "Infrastructure health evidence",
        "Final answer evidence package"
    ],
    "positioning_statement": "Platform B does not evaluate production RAG as a model-only risk. It evaluates the complete operational system: orchestration, retrieval, security, execution, evidence generation, and runtime infrastructure.",
    "principle": "Production RAG trust is achieved only when orchestration, retrieval, runtime security, execution evidence, and infrastructure health operate together reliably, securely, traceably, and continuously under governance."
}

def load_json(path):
    p = Path(path)
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8-sig"))

def save_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

def add_unique(items, additions):
    if not isinstance(items, list):
        items = []
    result = []
    seen = set()
    for item in items + additions:
        key = json.dumps(item, sort_keys=True) if isinstance(item, dict) else str(item)
        if key not in seen:
            result.append(item)
            seen.add(key)
    return result

def patch_seed(path):
    p = Path(path)
    if not p.exists():
        print(f"SKIP: {path}")
        return

    data = load_json(path)
    if not isinstance(data, dict):
        print(f"SKIP: {path} is not JSON object")
        return

    data["platform_b_production_rag_execution_assurance_patch"] = PRODUCTION_RAG_ASSURANCE
    data["platform_b_architecture_change"] = False
    data["platform_b_new_lifecycle"] = False
    data["platform_b_new_module"] = False
    data["platform_b_lifecycle_sequence"] = LIFECYCLE_SEQUENCE

    if "blueprints" in data and isinstance(data["blueprints"], list):
        for bp in data["blueprints"]:
            if not isinstance(bp, dict):
                continue

            bp["architecture_change"] = False
            bp["new_lifecycle"] = False
            bp["new_module"] = False
            bp["production_rag_execution_assurance"] = PRODUCTION_RAG_ASSURANCE

            bp["questions_answered"] = add_unique(
                bp.get("questions_answered", []),
                [PRODUCTION_RAG_ASSURANCE["core_question"]] + PRODUCTION_RAG_ASSURANCE["rag_execution_evidence_questions"]
            )

            assessment = bp.get("sample_blueprint_assessment", {})
            if not isinstance(assessment, dict):
                assessment = {}

            assessment["production_rag_execution_assurance_state"] = "ENRICH_EXISTING_OPERATIONALIZATION_EXECUTION_ASSURANCE_EVIDENCE_CONTINUOUS_ASSURANCE"
            assessment["architecture_change"] = False
            assessment["new_lifecycle"] = False
            assessment["new_module"] = False
            assessment["semantic_kernel_orchestration_supported"] = True
            assessment["ai_agent_orchestration_supported"] = True
            assessment["plugin_execution_supported"] = True
            assessment["vector_database_integration_supported"] = True
            assessment["azure_openai_integration_supported"] = True
            assessment["enterprise_knowledge_connectors_supported"] = True
            assessment["managed_identity_required"] = True
            assessment["secure_runtime_execution_required"] = True
            assessment["orchestration_assurance_required"] = True
            assessment["retrieval_assurance_required"] = True
            assessment["runtime_assurance_required"] = True
            assessment["rag_execution_evidence_required"] = True
            assessment["continuous_rag_monitoring_required"] = True
            bp["sample_blueprint_assessment"] = assessment

    if "sample_integration_assessment" in data and isinstance(data["sample_integration_assessment"], dict):
        assessment = data["sample_integration_assessment"]
        assessment["production_rag_execution_assurance_state"] = "ACTIVE"
        assessment["architecture_change"] = False
        assessment["new_lifecycle"] = False
        assessment["new_module"] = False
        assessment["production_rag_execution_assurance"] = PRODUCTION_RAG_ASSURANCE
        assessment["evidence_automation_targets"] = add_unique(
            assessment.get("evidence_automation_targets", []),
            PRODUCTION_RAG_ASSURANCE["operational_trust_evidence"]
        )
        assessment["continuous_monitoring_targets"] = add_unique(
            assessment.get("continuous_monitoring_targets", []),
            PRODUCTION_RAG_ASSURANCE["continuous_assurance_monitors"]
        )
        assessment["implementation_priority"] = add_unique(
            assessment.get("implementation_priority", []),
            [
                "Support production RAG operationalization through orchestration, plug-ins, vector databases, Azure OpenAI, enterprise connectors, managed identities, and secure runtime execution.",
                "Evaluate orchestration assurance, retrieval assurance, and runtime assurance inside Execution Assurance.",
                "Generate RAG execution evidence for retrieved documents, vector index, embeddings, orchestrator, plug-ins, AI model, enterprise systems, and final answer support.",
                "Continuously monitor index freshness, retrieval quality, embedding drift, knowledge synchronization, runtime health, security posture, and operational trust."
            ]
        )

    save_json(path, data)
    print(f"PATCHED: {path}")

def html_escape(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def domain_cards():
    cards = []
    for item in PRODUCTION_RAG_ASSURANCE["execution_assurance_domains"]:
        controls = "".join([f"<li>{html_escape(x)}</li>" for x in item["controls"]])
        cards.append(f"""
        <div class="rag-assurance-card">
            <div class="rag-assurance-domain">{html_escape(item["domain"])}</div>
            <h3>{html_escape(item["question"])}</h3>
            <ul>{controls}</ul>
        </div>
        """)
    return "\n".join(cards)

def pill_list(items, cls):
    return "".join([f'<span class="{cls}">{html_escape(x)}</span>' for x in items])

HTML_BLOCK = f"""
<style>
.platform-b-rag-wrap {{
    margin: 28px 0;
    padding: 24px;
    border-radius: 24px;
    border: 1px solid rgba(255,255,255,.12);
    background: linear-gradient(135deg, rgba(16,185,129,.10), rgba(59,130,246,.08));
}}
.platform-b-rag-head {{
    display: flex;
    justify-content: space-between;
    gap: 18px;
    align-items: flex-start;
    margin-bottom: 18px;
}}
.platform-b-rag-head h2 {{
    margin: 0;
    font-size: 28px;
}}
.platform-b-rag-head p {{
    color: #cbd5e1;
    line-height: 1.65;
    max-width: 980px;
}}
.platform-b-rag-tag {{
    border: 1px solid rgba(110,231,183,.45);
    color: #6ee7b7;
    border-radius: 999px;
    padding: 8px 12px;
    font-size: 12px;
    white-space: nowrap;
    background: rgba(16,185,129,.10);
}}
.platform-b-rag-principle {{
    margin: 18px 0;
    padding: 16px;
    border-left: 4px solid #6ee7b7;
    color: #e5e7eb;
    background: rgba(255,255,255,.045);
    border-radius: 14px;
    line-height: 1.6;
}}
.platform-b-rag-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 16px;
}}
.rag-assurance-card {{
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(255,255,255,.045);
    border-radius: 18px;
    padding: 18px;
}}
.rag-assurance-card h3 {{
    margin: 8px 0 12px;
    color: #fff;
    font-size: 16px;
    line-height: 1.35;
}}
.rag-assurance-card ul {{
    margin: 0;
    padding-left: 18px;
    color: #cbd5e1;
    line-height: 1.6;
}}
.rag-assurance-domain {{
    color: #6ee7b7;
    font-weight: 800;
    letter-spacing: .04em;
    text-transform: uppercase;
    font-size: 12px;
}}
.platform-b-rag-pills {{
    margin-top: 18px;
    display: flex;
    flex-wrap: wrap;
    gap: 9px;
}}
.platform-b-rag-pill {{
    border: 1px solid rgba(255,255,255,.12);
    background: rgba(255,255,255,.045);
    border-radius: 999px;
    padding: 8px 12px;
    color: #d8dee9;
    font-size: 13px;
}}
</style>

<section class="platform-b-rag-wrap">
    <div class="platform-b-rag-head">
        <div>
            <h2>Production RAG Execution Assurance</h2>
            <p>
                No new lifecycle and no new module. Platform B evaluates production RAG as a complete operational system:
                orchestration, retrieval, security, execution, evidence generation, and runtime infrastructure operating
                together in a trustworthy manner.
            </p>
        </div>
        <span class="platform-b-rag-tag">Operationalization + Execution Assurance + Evidence</span>
    </div>

    <div class="platform-b-rag-principle">
        {html_escape(PRODUCTION_RAG_ASSURANCE["principle"])}
    </div>

    <div class="platform-b-rag-grid">
        {domain_cards()}
    </div>

    <div class="platform-b-rag-pills">
        {pill_list(PRODUCTION_RAG_ASSURANCE["operationalization_support"], "platform-b-rag-pill")}
    </div>

    <div class="platform-b-rag-pills">
        {pill_list(PRODUCTION_RAG_ASSURANCE["rag_execution_evidence_questions"], "platform-b-rag-pill")}
    </div>

    <div class="platform-b-rag-pills">
        {pill_list(PRODUCTION_RAG_ASSURANCE["continuous_assurance_monitors"], "platform-b-rag-pill")}
    </div>
</section>
"""

def remove_old_block(text):
    start = f"<!-- {PATCH_MARKER} -->"
    end = f"<!-- END {PATCH_MARKER} -->"
    return re.sub(re.escape(start) + r".*?" + re.escape(end), "", text, flags=re.DOTALL)

def clean_trailing_whitespace(text):
    lines = text.splitlines(keepends=True)
    cleaned = []
    for line in lines:
        if line.endswith("\r\n"):
            cleaned.append(line[:-2].rstrip(" \t") + "\r\n")
        elif line.endswith("\n"):
            cleaned.append(line[:-1].rstrip(" \t") + "\n")
        else:
            cleaned.append(line.rstrip(" \t"))
    return "".join(cleaned)

def patch_html(path):
    p = Path(path)
    if not p.exists():
        print(f"SKIP: {path}")
        return

    text = p.read_text(encoding="utf-8-sig")
    text = remove_old_block(text)

    wrapped = f"\n<!-- {PATCH_MARKER} -->\n{HTML_BLOCK}\n<!-- END {PATCH_MARKER} -->\n"

    anchors = [
        "<!-- COBITCHAIN_PLATFORM_B_GOVERNANCE_SUSTAINED_COMPLIANCE_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_PRODUCTION_OWNERSHIP_CONTINUITY_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_BUSINESS_VALUE_KPI_EVIDENCE_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_EXISTING_CAPABILITY_DEEPENING_PATCH_V1_ACTIVE -->",
        "<div class=\"footer\">",
        "</main>",
        "</body>"
    ]

    inserted = False
    for anchor in anchors:
        if anchor in text:
            text = text.replace(anchor, wrapped + "\n" + anchor, 1)
            inserted = True
            break

    if not inserted:
        text = text.rstrip() + wrapped

    p.write_text(clean_trailing_whitespace(text), encoding="utf-8")
    print(f"PATCHED: {path}")

patch_seed("platform_blueprint_library_seed.json")
patch_seed("platform_lifecycle_integration_seed.json")

for html in [
    "platform_ab_command_center.html",
    "platform_blueprint_library.html",
    "platform_ai_enabled_cmc_blueprint.html",
    "platform_agentic_enterprise_blueprint.html",
    "platform_enterprise_execution_assurance.html",
    "platform_route_registry_command_center.html"
]:
    patch_html(html)

Path("platform_b_production_rag_execution_assurance_patch_v1_summary.json").write_text(
    json.dumps(PRODUCTION_RAG_ASSURANCE, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("platform_b_production_rag_execution_assurance_patch_v1_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform",
        "http://127.0.0.1:5000/platform/blueprints",
        "http://127.0.0.1:5000/platform/blueprints/ai-enabled-cmc",
        "http://127.0.0.1:5000/platform/blueprints/agentic-enterprise",
        "http://127.0.0.1:5000/platform/lifecycle-integration",
        "http://127.0.0.1:5000/platform/enterprise-execution-assurance",
        "http://127.0.0.1:5000/platform/execution-assurance",
        "http://127.0.0.1:5000/platform/routes",
        "http://127.0.0.1:5000/api/platform/blueprints/model/demo",
        "http://127.0.0.1:5000/api/platform/lifecycle-integration/model/demo",
        "http://127.0.0.1:5000/api/platform/enterprise-execution-assurance/demo",
        "http://127.0.0.1:5000/api/platform/execution-assurance/demo"
    ]),
    encoding="utf-8"
)

print("")
print("Platform B Production RAG Execution Assurance Patch completed.")
print("Marker:", PATCH_MARKER)
print("Architecture change: False")
print("New lifecycle: False")
print("New module: False")
print("Lifecycle:", LIFECYCLE_SEQUENCE)
