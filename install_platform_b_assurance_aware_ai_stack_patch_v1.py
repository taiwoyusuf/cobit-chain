from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_PLATFORM_B_ASSURANCE_AWARE_AI_STACK_PATCH_V1_ACTIVE"
LOCKED_LIFECYCLE_SEQUENCE = "Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust"

CAPABILITIES = [
    "Audit Survival Assurance",
    "AI Stack Assurance Graph",
    "Assurance-Ready Stack Selection",
    "Component-to-Obligation Traceability",
    "Stack Drift Assurance",
    "Compliance Benchmark-to-Evidence Mapping"
]

PATCH = {
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "new_module": False,
    "new_stage": False,
    "new_pillar": False,
    "new_architecture": False,
    "capability_type": "Assurance-Aware AI Stack as cross-cutting Platform B capabilities",
    "locked_lifecycle_sequence": LOCKED_LIFECYCLE_SEQUENCE,
    "architecture_instruction": "Do not create a new module, stage, pillar, or architecture. Keep the lifecycle locked as Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust. Add Audit Survival Assurance, AI Stack Assurance Graph, Assurance-Ready Stack Selection, Component-to-Obligation Traceability, Stack Drift Assurance, and Compliance Benchmark-to-Evidence Mapping as cross-cutting capabilities.",
    "cross_cutting_capabilities": CAPABILITIES,
    "discovery_extension": [
        "Selected LLM/model",
        "Agent framework",
        "RAG framework",
        "Embedding model",
        "Vector database",
        "MCP servers",
        "Tool/API connectors",
        "Memory system",
        "Automation engine",
        "Observability platform",
        "Guardrails/security tools",
        "System of record",
        "Human approval points",
        "Compliance obligations",
        "Evidence sources",
        "Stack owner",
        "Data owner",
        "Model owner",
        "Workflow owner"
    ],
    "visibility_extension": [
        "AI stack map",
        "Compliance benchmark score",
        "Audit survival score",
        "Component risk score",
        "Data provenance status",
        "MCP/tool exposure",
        "Memory risk",
        "RAG trust state",
        "Observability coverage",
        "Evidence completeness",
        "Human oversight coverage",
        "Stack drift alerts",
        "Operational Trust Score"
    ],
    "governance_extension": [
        "Approved AI stack patterns",
        "Prohibited stack combinations",
        "Model selection criteria",
        "RAG source approval rules",
        "Memory governance",
        "MCP/tool access rules",
        "Observability requirements",
        "Audit evidence requirements",
        "Human oversight requirements",
        "Stack change-control rules",
        "Compliance benchmark thresholds"
    ],
    "operationalization_extension": [
        "Approved model/use-case pairing",
        "Approved RAG sources",
        "Permission-aware retrieval",
        "MCP/tool authorization",
        "Memory write controls",
        "Prompt/version controls",
        "Observability hooks",
        "Human approval gates",
        "AI Action Firewall",
        "Evidence capture before execution",
        "Stack change approval before production use"
    ],
    "manufacturing_monitoring_extension": [
        "AI recommendations affecting regulated operations",
        "RAG retrieval quality",
        "Tool/API use",
        "MCP invocation",
        "Memory changes",
        "Stack latency",
        "Model behavior",
        "Workflow execution",
        "Human review activity",
        "Security events",
        "Audit evidence gaps"
    ],
    "evidence_extension": [
        "Why the model was selected",
        "Why the stack was selected",
        "What compliance benchmark was used",
        "What data was retrieved",
        "What tool/MCP server was invoked",
        "What memory was read/written",
        "What human reviewed",
        "What system was affected",
        "What evidence was generated",
        "What changed in the stack",
        "Whether re-assessment was required"
    ],
    "continuous_assurance_extension": [
        "Stack drift",
        "Model drift",
        "Prompt drift",
        "Retrieval drift",
        "Memory contamination",
        "MCP/tool misuse",
        "Missing logs",
        "Weak evidence",
        "Human oversight gaps",
        "Compliance degradation",
        "Security control failure",
        "Audit readiness decline"
    ],
    "operational_trust_question": "Can this AI stack be trusted, audited, defended, and used safely in this regulated context right now?",
    "platform_principle": "Platform B treats the AI stack itself as an assurance object: every model, framework, RAG source, MCP server, tool connector, memory system, observability control, owner, obligation, and evidence source must be traceable, governed, monitored, and audit-survivable.",
    "capability_profiles": {
        "Audit Survival Assurance": [
            "Audit survival score",
            "Audit evidence requirement",
            "Compliance benchmark linkage",
            "Human oversight evidence",
            "Evidence completeness",
            "Stack selection rationale",
            "Regulated context defensibility"
        ],
        "AI Stack Assurance Graph": [
            "Model-to-use-case relationship",
            "Agent framework relationship",
            "RAG framework relationship",
            "Vector database relationship",
            "MCP/tool connector relationship",
            "Memory system relationship",
            "Owner-to-obligation relationship"
        ],
        "Assurance-Ready Stack Selection": [
            "Approved model/use-case pairing",
            "Approved stack pattern",
            "Prohibited stack combination check",
            "Model selection criteria",
            "Stack selection rationale",
            "Compliance threshold check",
            "Production-use approval"
        ],
        "Component-to-Obligation Traceability": [
            "Component risk score",
            "Compliance obligation mapping",
            "Evidence source mapping",
            "System-of-record linkage",
            "Data owner linkage",
            "Model owner linkage",
            "Workflow owner linkage"
        ],
        "Stack Drift Assurance": [
            "Stack drift alert",
            "Model drift detection",
            "Prompt drift detection",
            "Retrieval drift detection",
            "Memory contamination detection",
            "MCP/tool misuse detection",
            "Re-assessment requirement"
        ],
        "Compliance Benchmark-to-Evidence Mapping": [
            "Compliance benchmark score",
            "Benchmark threshold",
            "Evidence generated",
            "Observability coverage",
            "Missing log detection",
            "Weak evidence detection",
            "Audit readiness decline detection"
        ]
    }
}

def load_json(path):
    p = Path(path)
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8-sig"))

def save_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

def stable_key(item):
    if isinstance(item, dict):
        return json.dumps(item, sort_keys=True, ensure_ascii=False)
    return str(item)

def add_unique(items, additions):
    if not isinstance(items, list):
        items = []
    result = []
    seen = set()
    for item in items + additions:
        key = stable_key(item)
        if key not in seen:
            result.append(item)
            seen.add(key)
    return result

def flatten_profiles(profiles):
    out = []
    for name, controls in profiles.items():
        out.append(name)
        out.extend(controls)
    return out

def capability_key(name):
    return (
        name.lower()
        .replace("-", "_")
        .replace("/", "_")
        .replace(" ", "_")
        .replace("(", "")
        .replace(")", "")
    )

def patch_seed(path):
    p = Path(path)
    if not p.exists():
        print(f"SKIP: {path}")
        return

    data = load_json(path)
    if not isinstance(data, dict):
        print(f"SKIP: {path} is not JSON object")
        return

    data["platform_b_assurance_aware_ai_stack_patch"] = PATCH
    data["platform_b_architecture_change"] = False
    data["platform_b_new_module"] = False
    data["platform_b_new_stage"] = False
    data["platform_b_new_pillar"] = False
    data["platform_b_new_architecture"] = False
    data["platform_b_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE

    for capability in CAPABILITIES:
        data[f"platform_b_{capability_key(capability)}_module_created"] = False

    profile_items = flatten_profiles(PATCH["capability_profiles"])

    if "blueprints" in data and isinstance(data["blueprints"], list):
        for bp in data["blueprints"]:
            if not isinstance(bp, dict):
                continue

            bp["architecture_change"] = False
            bp["new_module"] = False
            bp["new_stage"] = False
            bp["new_pillar"] = False
            bp["new_architecture"] = False
            bp["locked_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
            bp["assurance_aware_ai_stack"] = PATCH

            bp["discovery_scope"] = add_unique(
                bp.get("discovery_scope", []),
                PATCH["discovery_extension"] + CAPABILITIES
            )

            bp["visibility_scope"] = add_unique(
                bp.get("visibility_scope", []),
                PATCH["visibility_extension"]
            )

            bp["governance_scope"] = add_unique(
                bp.get("governance_scope", []),
                PATCH["governance_extension"]
            )

            bp["operationalization_scope"] = add_unique(
                bp.get("operationalization_scope", []),
                PATCH["operationalization_extension"] + profile_items
            )

            bp["manufacturing_monitoring_scope"] = add_unique(
                bp.get("manufacturing_monitoring_scope", []),
                PATCH["manufacturing_monitoring_extension"]
            )

            bp["evidence_assurance"] = add_unique(
                bp.get("evidence_assurance", []),
                PATCH["evidence_extension"]
            )

            bp["continuous_assurance"] = add_unique(
                bp.get("continuous_assurance", []),
                PATCH["continuous_assurance_extension"]
            )

            bp["operational_trust_scope"] = add_unique(
                bp.get("operational_trust_scope", []),
                [PATCH["operational_trust_question"], PATCH["platform_principle"]] + CAPABILITIES
            )

            bp["questions_answered"] = add_unique(
                bp.get("questions_answered", []),
                [PATCH["operational_trust_question"]]
            )

            assessment = bp.get("sample_blueprint_assessment", {})
            if not isinstance(assessment, dict):
                assessment = {}

            assessment["assurance_aware_ai_stack_state"] = "ACTIVE"
            assessment["architecture_change"] = False
            assessment["new_module"] = False
            assessment["new_stage"] = False
            assessment["new_pillar"] = False
            assessment["new_architecture"] = False
            assessment["locked_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
            assessment["audit_survival_assurance_active"] = True
            assessment["ai_stack_assurance_graph_active"] = True
            assessment["assurance_ready_stack_selection_active"] = True
            assessment["component_to_obligation_traceability_active"] = True
            assessment["stack_drift_assurance_active"] = True
            assessment["compliance_benchmark_to_evidence_mapping_active"] = True
            assessment["operational_trust_question"] = PATCH["operational_trust_question"]

            for capability in CAPABILITIES:
                key = capability_key(capability)
                assessment[f"{key}_active"] = True
                assessment[f"{key}_module_created"] = False

            bp["sample_blueprint_assessment"] = assessment

    if "sample_integration_assessment" in data and isinstance(data["sample_integration_assessment"], dict):
        assessment = data["sample_integration_assessment"]
        assessment["assurance_aware_ai_stack_state"] = "ACTIVE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["new_stage"] = False
        assessment["new_pillar"] = False
        assessment["new_architecture"] = False
        assessment["locked_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
        assessment["assurance_aware_ai_stack"] = PATCH

        assessment["operationalization_targets"] = add_unique(
            assessment.get("operationalization_targets", []),
            PATCH["operationalization_extension"] + profile_items
        )

        assessment["manufacturing_monitoring_targets"] = add_unique(
            assessment.get("manufacturing_monitoring_targets", []),
            PATCH["manufacturing_monitoring_extension"]
        )

        assessment["evidence_automation_targets"] = add_unique(
            assessment.get("evidence_automation_targets", []),
            PATCH["evidence_extension"]
        )

        assessment["continuous_monitoring_targets"] = add_unique(
            assessment.get("continuous_monitoring_targets", []),
            PATCH["continuous_assurance_extension"]
        )

        assessment["implementation_priority"] = add_unique(
            assessment.get("implementation_priority", []),
            [
                "Do not create a new module, stage, pillar, or architecture for Assurance-Aware AI Stack.",
                "Keep the lifecycle locked as Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust.",
                "Implement Audit Survival Assurance, AI Stack Assurance Graph, Assurance-Ready Stack Selection, Component-to-Obligation Traceability, Stack Drift Assurance, and Compliance Benchmark-to-Evidence Mapping as cross-cutting capabilities.",
                "Continuously answer whether the AI stack can be trusted, audited, defended, and used safely in this regulated context right now."
            ]
        )

    save_json(path, data)
    print(f"PATCHED: {path}")

def html_escape(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def card(title, items):
    lis = "".join([f"<li>{html_escape(x)}</li>" for x in items])
    return f"""
    <div class="ai-stack-card">
        <div class="ai-stack-title">{html_escape(title)}</div>
        <ul>{lis}</ul>
    </div>
    """

def profile_cards(profiles):
    return "\n".join([card(name, controls) for name, controls in profiles.items()])

HTML_BLOCK = f"""
<style>
.platform-b-ai-stack-wrap {{
    margin: 28px 0;
    padding: 24px;
    border-radius: 24px;
    border: 1px solid rgba(255,255,255,.12);
    background: linear-gradient(135deg, rgba(59,130,246,.10), rgba(16,185,129,.08));
}}
.platform-b-ai-stack-wrap h2 {{
    margin: 0 0 12px 0;
    font-size: 28px;
}}
.platform-b-ai-stack-wrap p {{
    color: #cbd5e1;
    line-height: 1.65;
    max-width: 1120px;
}}
.platform-b-ai-stack-warning {{
    margin: 18px 0;
    padding: 14px 16px;
    border-radius: 14px;
    background: rgba(248,113,113,.08);
    border: 1px solid rgba(248,113,113,.18);
    color: #fecaca;
    line-height: 1.55;
    font-weight: 800;
}}
.platform-b-ai-stack-question {{
    margin: 18px 0;
    padding: 16px;
    border-radius: 16px;
    background: rgba(14,165,233,.10);
    border: 1px solid rgba(125,211,252,.22);
    color: #e0f2fe;
    font-weight: 800;
    font-size: 18px;
}}
.platform-b-ai-stack-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 16px;
}}
.ai-stack-card {{
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(255,255,255,.045);
    border-radius: 18px;
    padding: 18px;
}}
.ai-stack-card ul {{
    margin: 10px 0 0;
    padding-left: 18px;
    color: #cbd5e1;
    line-height: 1.6;
}}
.ai-stack-title {{
    color: #bfdbfe;
    font-weight: 800;
    letter-spacing: .04em;
    text-transform: uppercase;
    font-size: 12px;
}}
</style>

<section class="platform-b-ai-stack-wrap">
    <h2>Assurance-Aware AI Stack</h2>
    <p><strong>No new module, stage, pillar, or architecture.</strong> Platform B implements Audit Survival Assurance, AI Stack Assurance Graph, Assurance-Ready Stack Selection, Component-to-Obligation Traceability, Stack Drift Assurance, and Compliance Benchmark-to-Evidence Mapping as cross-cutting capabilities inside the existing lifecycle.</p>
    <p>{html_escape(PATCH["platform_principle"])}</p>

    <div class="platform-b-ai-stack-warning">
        The AI stack is not treated as a neutral technical choice. The selected model, agent framework, RAG framework, vector database, MCP servers, tools, memory, observability, owners, obligations, and evidence sources must be assurance-ready before regulated use.
    </div>

    <div class="platform-b-ai-stack-question">
        Operational Trust asks: {html_escape(PATCH["operational_trust_question"])}
    </div>

    <div class="platform-b-ai-stack-grid">
        {card("Discovery", PATCH["discovery_extension"])}
        {card("Visibility", PATCH["visibility_extension"])}
        {card("Governance", PATCH["governance_extension"])}
        {card("Operationalization", PATCH["operationalization_extension"])}
        {card("Manufacturing Monitoring", PATCH["manufacturing_monitoring_extension"])}
        {card("Evidence", PATCH["evidence_extension"])}
        {card("Continuous Assurance", PATCH["continuous_assurance_extension"])}
        {card("Cross-Cutting Capabilities", CAPABILITIES)}
        {profile_cards(PATCH["capability_profiles"])}
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
        "<!-- COBITCHAIN_PLATFORM_B_AUDIT_SURVIVABLE_SAFETY_BOUNDED_CYBER_PHYSICAL_AI_ASSURANCE_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_CONTEXT_ASSURED_WEARABLE_PRE_DEVIATION_ASSURANCE_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_PRE_DEVIATION_CAPA_EFFECTIVENESS_ASSURANCE_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_ADVANCED_CROSS_CUTTING_CAPABILITIES_LOCKED_LIFECYCLE_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_AI_CAPABILITY_ASSURANCE_LIBRARY_PATCH_V1_ACTIVE -->",
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

Path("platform_b_assurance_aware_ai_stack_patch_v1_summary.json").write_text(
    json.dumps(PATCH, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("platform_b_assurance_aware_ai_stack_patch_v1_urls.txt").write_text(
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
print("Platform B Assurance-Aware AI Stack Patch completed.")
print("Marker:", PATCH_MARKER)
print("Architecture change: False")
print("New module: False")
print("New stage: False")
print("New pillar: False")
print("New architecture: False")
print("Locked lifecycle:", LOCKED_LIFECYCLE_SEQUENCE)
print("Operational Trust question:", PATCH["operational_trust_question"])
