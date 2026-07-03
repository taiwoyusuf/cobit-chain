from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_PLATFORM_B_AI_FRAMEWORK_RUNTIME_OPERATIONALIZATION_PATCH_V1_ACTIVE"
LIFECYCLE_SEQUENCE = "Discovery -> Visibility -> Governance -> Operationalization -> Execution Assurance -> Evidence -> Continuous Assurance -> Operational Trust"

PATCH = {
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "new_module": False,
    "capability_name": "AI Framework and Runtime Operationalization Support",
    "architecture_instruction": "Do not create LangChain Assurance, CrewAI Assurance, Ollama Assurance, n8n Assurance, Dify Assurance, or separate framework-specific assurance modules. Extend Operationalization and assure the resulting workflow consistently through Execution Assurance, Evidence, and Continuous Assurance.",
    "lifecycle_sequence": LIFECYCLE_SEQUENCE,
    "platform_statement": "Platform B operationalizes diverse enterprise AI frameworks, runtimes, development platforms, workflow platforms, local runtimes, and retrieval platforms without creating separate assurance modules for each technology.",
    "core_question": "Can the AI workflow be operationally trusted regardless of the framework, runtime, workflow platform, development tool, or retrieval platform used?",
    "primary_stage": "Operationalization",
    "supporting_stages": [
        "Retrieval Assurance",
        "Execution Assurance",
        "Evidence",
        "Continuous Assurance",
        "Operational Trust"
    ],
    "do_not_create": [
        "LangChain Assurance",
        "CrewAI Assurance",
        "Ollama Assurance",
        "n8n Assurance",
        "Dify Assurance",
        "Framework-specific assurance modules",
        "Runtime-specific assurance modules"
    ],
    "operationalization": {
        "ai_framework_support": [
            "Semantic Kernel",
            "LangChain",
            "CrewAI",
            "LangGraph",
            "AutoGen",
            "Dify",
            "Langflow",
            "OpenAI Agents SDK",
            "n8n AI",
            "Azure AI Foundry",
            "Azure AI Studio"
        ],
        "ai_runtime_support": [
            "Azure OpenAI",
            "OpenAI",
            "Claude",
            "Gemini",
            "Ollama",
            "DeepSeek",
            "Llama",
            "Mistral",
            "Qwen"
        ],
        "local_ai_runtime_support": [
            "Ollama",
            "Open WebUI",
            "Local inference",
            "Edge deployment",
            "Air-gapped deployment"
        ],
        "ai_development_platform_support": [
            "NotebookLM",
            "Claude Code",
            "Gemini CLI",
            "GitHub Copilot",
            "Cursor",
            "Windsurf"
        ],
        "workflow_platform_support": [
            "n8n",
            "Langflow",
            "Dify",
            "Microsoft Power Automate",
            "ServiceNow AI workflows"
        ],
        "retrieval_platform_support": [
            "RAGFlow",
            "Azure AI Search",
            "Pinecone",
            "Weaviate",
            "Milvus",
            "Chroma",
            "Cosmos DB Vector Search"
        ]
    },
    "retrieval_assurance_extension": [
        "RAGFlow",
        "Azure AI Search",
        "Pinecone",
        "Weaviate",
        "Milvus",
        "Chroma",
        "Cosmos DB Vector Search",
        "Vector index provenance",
        "Retrieval platform lineage",
        "Retrieval platform access control"
    ],
    "continuous_assurance_evaluates_regardless_of_framework": [
        "Orchestration",
        "Evidence",
        "Retrieval",
        "Memory",
        "Tool calls",
        "Approvals",
        "Runtime",
        "Security"
    ],
    "evidence_questions": [
        "Which framework orchestrated the workflow?",
        "Which runtime executed the model?",
        "Which model generated the output?",
        "Which local or cloud runtime was used?",
        "Which development platform produced or modified the workflow?",
        "Which workflow platform executed the process?",
        "Which retrieval platform was used?",
        "Which tools were called?",
        "Which memory or context store was used?",
        "Which approvals occurred?",
        "What evidence was generated?",
        "Was security enforced regardless of framework?"
    ],
    "operational_trust_statement": "Operational Trust is not based on the framework brand. It is based on demonstrated orchestration integrity, retrieval trust, memory governance, tool-call control, approval evidence, runtime security, and continuous assurance.",
    "principle": "Framework choice does not create trust. Platform B operationalizes diverse AI technologies, then assures orchestration, retrieval, memory, tools, approvals, runtime, security, evidence, and operational trust consistently across them."
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

    data["platform_b_ai_framework_runtime_operationalization_patch"] = PATCH
    data["platform_b_architecture_change"] = False
    data["platform_b_new_module"] = False
    data["platform_b_lifecycle_sequence"] = LIFECYCLE_SEQUENCE

    if "blueprints" in data and isinstance(data["blueprints"], list):
        for bp in data["blueprints"]:
            if not isinstance(bp, dict):
                continue

            bp["architecture_change"] = False
            bp["new_module"] = False
            bp["ai_framework_runtime_operationalization"] = PATCH

            bp["operationalization_support"] = add_unique(
                bp.get("operationalization_support", []),
                PATCH["operationalization"]["ai_framework_support"]
                + PATCH["operationalization"]["ai_runtime_support"]
                + PATCH["operationalization"]["local_ai_runtime_support"]
                + PATCH["operationalization"]["ai_development_platform_support"]
                + PATCH["operationalization"]["workflow_platform_support"]
                + PATCH["operationalization"]["retrieval_platform_support"]
            )

            bp["retrieval_assurance"] = add_unique(
                bp.get("retrieval_assurance", []),
                PATCH["retrieval_assurance_extension"]
            )

            bp["questions_answered"] = add_unique(
                bp.get("questions_answered", []),
                [PATCH["core_question"]] + PATCH["evidence_questions"]
            )

            assessment = bp.get("sample_blueprint_assessment", {})
            if not isinstance(assessment, dict):
                assessment = {}

            assessment["ai_framework_runtime_operationalization_state"] = "EXTEND_OPERATIONALIZATION_ONLY"
            assessment["architecture_change"] = False
            assessment["new_module"] = False
            assessment["framework_specific_modules_created"] = False
            assessment["operationalization_extended"] = True
            assessment["retrieval_assurance_extended"] = True
            assessment["continuous_assurance_framework_agnostic"] = True
            assessment["operational_trust_framework_agnostic"] = True
            bp["sample_blueprint_assessment"] = assessment

    if "sample_integration_assessment" in data and isinstance(data["sample_integration_assessment"], dict):
        assessment = data["sample_integration_assessment"]
        assessment["ai_framework_runtime_operationalization_state"] = "ACTIVE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["framework_specific_modules_created"] = False
        assessment["ai_framework_runtime_operationalization"] = PATCH
        assessment["operationalization_support"] = add_unique(
            assessment.get("operationalization_support", []),
            PATCH["operationalization"]["ai_framework_support"]
            + PATCH["operationalization"]["ai_runtime_support"]
            + PATCH["operationalization"]["local_ai_runtime_support"]
            + PATCH["operationalization"]["ai_development_platform_support"]
            + PATCH["operationalization"]["workflow_platform_support"]
        )
        assessment["retrieval_platform_support"] = add_unique(
            assessment.get("retrieval_platform_support", []),
            PATCH["operationalization"]["retrieval_platform_support"]
        )
        assessment["continuous_monitoring_targets"] = add_unique(
            assessment.get("continuous_monitoring_targets", []),
            PATCH["continuous_assurance_evaluates_regardless_of_framework"]
        )
        assessment["evidence_automation_targets"] = add_unique(
            assessment.get("evidence_automation_targets", []),
            PATCH["evidence_questions"]
        )

    save_json(path, data)
    print(f"PATCHED: {path}")

def html_escape(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def card(title, items):
    lis = "".join([f"<li>{html_escape(x)}</li>" for x in items])
    return f"""
    <div class="framework-runtime-card">
        <div class="framework-runtime-domain">{html_escape(title)}</div>
        <ul>{lis}</ul>
    </div>
    """

def pill_list(items, cls):
    return "".join([f'<span class="{cls}">{html_escape(x)}</span>' for x in items])

HTML_BLOCK = f"""
<style>
.platform-b-framework-runtime-wrap {{
    margin: 28px 0;
    padding: 24px;
    border-radius: 24px;
    border: 1px solid rgba(255,255,255,.12);
    background: linear-gradient(135deg, rgba(14,165,233,.10), rgba(168,85,247,.08));
}}
.platform-b-framework-runtime-head {{
    display: flex;
    justify-content: space-between;
    gap: 18px;
    align-items: flex-start;
    margin-bottom: 18px;
}}
.platform-b-framework-runtime-head h2 {{
    margin: 0;
    font-size: 28px;
}}
.platform-b-framework-runtime-head p {{
    color: #cbd5e1;
    line-height: 1.65;
    max-width: 980px;
}}
.platform-b-framework-runtime-tag {{
    border: 1px solid rgba(125,211,252,.45);
    color: #bae6fd;
    border-radius: 999px;
    padding: 8px 12px;
    font-size: 12px;
    white-space: nowrap;
    background: rgba(14,165,233,.10);
}}
.platform-b-framework-runtime-principle {{
    margin: 18px 0;
    padding: 16px;
    border-left: 4px solid #7dd3fc;
    color: #e5e7eb;
    background: rgba(255,255,255,.045);
    border-radius: 14px;
    line-height: 1.6;
}}
.platform-b-framework-runtime-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 16px;
}}
.framework-runtime-card {{
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(255,255,255,.045);
    border-radius: 18px;
    padding: 18px;
}}
.framework-runtime-card ul {{
    margin: 10px 0 0;
    padding-left: 18px;
    color: #cbd5e1;
    line-height: 1.6;
}}
.framework-runtime-domain {{
    color: #bae6fd;
    font-weight: 800;
    letter-spacing: .04em;
    text-transform: uppercase;
    font-size: 12px;
}}
.platform-b-framework-runtime-pills {{
    margin-top: 18px;
    display: flex;
    flex-wrap: wrap;
    gap: 9px;
}}
.platform-b-framework-runtime-pill {{
    border: 1px solid rgba(255,255,255,.12);
    background: rgba(255,255,255,.045);
    border-radius: 999px;
    padding: 8px 12px;
    color: #d8dee9;
    font-size: 13px;
}}
.platform-b-framework-runtime-warning {{
    margin-top: 18px;
    padding: 14px 16px;
    border-radius: 14px;
    background: rgba(248,113,113,.08);
    border: 1px solid rgba(248,113,113,.18);
    color: #fecaca;
    line-height: 1.55;
}}
</style>

<section class="platform-b-framework-runtime-wrap">
    <div class="platform-b-framework-runtime-head">
        <div>
            <h2>AI Framework and Runtime Operationalization Support</h2>
            <p>
                No new module. Platform B extends Operationalization so diverse frameworks, runtimes,
                local AI deployments, development platforms, workflow platforms, and retrieval platforms can be used
                while Execution Assurance, Evidence, and Continuous Assurance evaluate the workflow consistently.
            </p>
        </div>
        <span class="platform-b-framework-runtime-tag">Operationalization Extension</span>
    </div>

    <div class="platform-b-framework-runtime-principle">
        {html_escape(PATCH["principle"])}
    </div>

    <div class="platform-b-framework-runtime-warning">
        Do not create LangChain Assurance, CrewAI Assurance, Ollama Assurance, n8n Assurance, Dify Assurance,
        or framework-specific assurance modules. Assurance remains framework-agnostic and evidence-based.
    </div>

    <div class="platform-b-framework-runtime-grid">
        {card("AI Framework Support", PATCH["operationalization"]["ai_framework_support"])}
        {card("AI Runtime Support", PATCH["operationalization"]["ai_runtime_support"])}
        {card("Local AI Runtime Support", PATCH["operationalization"]["local_ai_runtime_support"])}
        {card("AI Development Platforms", PATCH["operationalization"]["ai_development_platform_support"])}
        {card("Workflow Platforms", PATCH["operationalization"]["workflow_platform_support"])}
        {card("Retrieval Platform Support", PATCH["operationalization"]["retrieval_platform_support"])}
    </div>

    <div class="platform-b-framework-runtime-pills">
        {pill_list(PATCH["continuous_assurance_evaluates_regardless_of_framework"], "platform-b-framework-runtime-pill")}
    </div>

    <div class="platform-b-framework-runtime-pills">
        {pill_list(PATCH["evidence_questions"], "platform-b-framework-runtime-pill")}
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
        "<!-- COBITCHAIN_PLATFORM_B_IDENTITY_PERMISSION_AWARE_EXECUTION_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_PRODUCTION_RAG_EXECUTION_ASSURANCE_PATCH_V1_ACTIVE -->",
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

Path("platform_b_ai_framework_runtime_operationalization_patch_v1_summary.json").write_text(
    json.dumps(PATCH, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("platform_b_ai_framework_runtime_operationalization_patch_v1_urls.txt").write_text(
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
print("Platform B AI Framework and Runtime Operationalization Patch completed.")
print("Marker:", PATCH_MARKER)
print("Architecture change: False")
print("New module: False")
print("Primary stage: Operationalization")
print("Lifecycle:", LIFECYCLE_SEQUENCE)
