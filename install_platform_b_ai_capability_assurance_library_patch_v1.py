from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_PLATFORM_B_AI_CAPABILITY_ASSURANCE_LIBRARY_PATCH_V1_ACTIVE"
LIFECYCLE_SEQUENCE = "Discovery -> Visibility -> Governance -> Operationalization -> Execution Assurance -> Evidence -> Continuous Assurance -> Operational Trust"

PATCH = {
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "new_lifecycle": False,
    "new_module": False,
    "capability_name": "AI Capability Assurance Library",
    "capability_type": "Capability library inside the existing Platform B lifecycle",
    "architecture_instruction": "Do not create a new module and do not create new lifecycle stages. Add AI Capability Assurance Library inside Platform B as capability profiles mapped across the existing lifecycle.",
    "lifecycle_sequence": LIFECYCLE_SEQUENCE,
    "core_question": "Can this AI capability, and its interaction with other AI capabilities, be operationally trusted across the existing assurance lifecycle?",
    "principle": "Capabilities do not become lifecycle stages. Platform B profiles AI capabilities inside the existing lifecycle and assures their handoffs, evidence lineage, compound risk, controls, monitoring, and operational trust.",
    "platform_statement": "Enterprise AI rarely operates as one isolated model. It combines classification, similarity, clustering, prediction, retrieval, discovery, reasoning, and execution. Platform B does not convert these capabilities into lifecycle stages. Platform B profiles each capability inside the existing lifecycle and assures its context, controls, handoffs, evidence lineage, compound risk, ownership, monitoring, and operational trust.",
    "not_lifecycle_stages": [
        "Classification",
        "Similarity",
        "Clustering",
        "Prediction",
        "Retrieval",
        "Discovery",
        "Reasoning",
        "Execution"
    ],
    "capability_profiles": {
        "Classification Assurance": [
            "Classification objective",
            "Class definitions",
            "Input source quality",
            "Label authority",
            "Confidence threshold",
            "Reviewer decision",
            "Misclassification risk",
            "Downstream decision impact",
            "Monitoring and drift"
        ],
        "Similarity Assurance": [
            "Similarity objective",
            "Embedding model/version",
            "Reference corpus",
            "Similarity threshold",
            "Distance metric",
            "False match risk",
            "False non-match risk",
            "Reviewer confirmation",
            "Evidence lineage"
        ],
        "Clustering Assurance": [
            "Clustering objective",
            "Feature selection",
            "Cluster rationale",
            "Cluster stability",
            "Outlier handling",
            "Bias/coverage review",
            "Human interpretation",
            "Operational use boundary",
            "Monitoring"
        ],
        "Prediction Assurance": [
            "Prediction context",
            "Input quality",
            "Model version",
            "Prediction horizon",
            "Uncertainty",
            "Decision threshold",
            "Reviewer decision",
            "Decision impact",
            "Monitoring and drift"
        ],
        "Retrieval Assurance": [
            "Source authority",
            "Retrieval permissions",
            "Context relevance",
            "Citation/source traceability",
            "Chunk provenance",
            "Recency",
            "Retrieval confidence",
            "Hallucination guardrails",
            "Reviewer verification"
        ],
        "Discovery Assurance": [
            "Discovery scope",
            "Signal provenance",
            "Search criteria",
            "Comparison criteria",
            "Candidate selection rationale",
            "Coverage completeness",
            "Bias review",
            "Source completeness",
            "Escalation criteria"
        ],
        "Reasoning Assurance": [
            "Reasoning objective",
            "Assumptions",
            "Intermediate evidence",
            "Decision logic",
            "Constraint adherence",
            "Challenge/override",
            "Human review",
            "Explanation adequacy",
            "Reasoning-to-action handoff"
        ],
        "Execution Assurance": [
            "Tool/action authorization",
            "Execution boundary",
            "System of record",
            "Approval gate",
            "Runtime trace",
            "Rollback condition",
            "Post-execution verification",
            "Exception handling",
            "Execution evidence"
        ],
        "Cross-Capability Interaction Assurance": [
            "Prediction to retrieval handoff",
            "Retrieval to reasoning handoff",
            "Reasoning to execution handoff",
            "Discovery to governance handoff",
            "Compound risk",
            "Evidence lineage",
            "Ownership continuity",
            "Control inheritance",
            "Monitoring continuity"
        ]
    },
    "discovery_extension": [
        "AI capability type",
        "Capability purpose",
        "Capability interaction map",
        "Input sources",
        "Output consumers",
        "Model/tool dependencies",
        "Capability ownership",
        "Compound risk profile"
    ],
    "visibility_extension": [
        "Capability inventory",
        "Capability interaction view",
        "Evidence lineage map",
        "Capability risk status",
        "Handoff health",
        "Control coverage",
        "Monitoring coverage",
        "Operational Trust Score"
    ],
    "governance_extension": [
        "Capability use boundaries",
        "Capability ownership rules",
        "Capability handoff rules",
        "Human review rules",
        "Evidence requirements",
        "Control inheritance rules",
        "Risk escalation rules",
        "Approval requirements"
    ],
    "operationalization_extension": [
        "Capability profile selection",
        "Input validation",
        "Permission validation",
        "Capability handoff checks",
        "Reviewer checkpoints",
        "Runtime control enforcement",
        "Exception handling",
        "Post-output verification"
    ],
    "execution_assurance_extension": [
        "Execution authorization",
        "Tool/action boundary validation",
        "Reasoning-to-action verification",
        "Human approval gate",
        "Runtime traceability",
        "Rollback verification",
        "Post-execution confirmation",
        "Execution evidence generation"
    ],
    "evidence_extension": [
        "Capability profiled",
        "Input validated",
        "Source authority verified",
        "Permission verified",
        "Handoff verified",
        "Reviewer decision captured",
        "Output verified",
        "Action authorized",
        "Runtime trace captured",
        "Post-execution verification completed",
        "Evidence lineage generated"
    ],
    "continuous_assurance_extension": [
        "Capability drift",
        "Input drift",
        "Retrieval drift",
        "Reasoning drift",
        "Execution drift",
        "Handoff degradation",
        "Compound risk increase",
        "Control coverage gaps",
        "Evidence lineage gaps",
        "Ownership gaps"
    ],
    "operational_trust_extension": [
        "Capability-level Operational Trust Score",
        "Cross-capability Operational Trust Score",
        "Evidence lineage completeness",
        "Control coverage completeness",
        "Handoff reliability",
        "Recovery readiness",
        "Ownership clarity"
    ],
    "operational_trust_question": "Can this AI capability, and its interaction with other AI capabilities, be operationally trusted right now?",
    "evidence_questions": [
        "What AI capability is being used?",
        "What is the capability purpose?",
        "Which lifecycle stage is using the capability?",
        "What input source was used?",
        "Who owns the capability?",
        "What downstream workflow consumes the output?",
        "What model, tool, or framework dependency exists?",
        "What is the compound risk profile?",
        "Was the capability profile selected?",
        "Was the input validated?",
        "Was source authority verified?",
        "Were permissions verified?",
        "Was the capability handoff verified?",
        "Was reviewer decision captured?",
        "Was output verified?",
        "Was action authorized?",
        "Was runtime trace captured?",
        "Was post-execution verification completed?",
        "Was evidence lineage generated?",
        "Is capability drift present?",
        "Is handoff degradation present?",
        "Is compound risk increasing?",
        "Are control coverage gaps present?",
        "Are evidence lineage gaps present?",
        "Are ownership gaps present?",
        "Can this AI capability, and its interaction with other AI capabilities, be operationally trusted right now?"
    ]
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
    items = []
    for name, controls in profiles.items():
        items.append(name)
        items.extend(controls)
    return items

def patch_seed(path):
    p = Path(path)
    if not p.exists():
        print(f"SKIP: {path}")
        return

    data = load_json(path)
    if not isinstance(data, dict):
        print(f"SKIP: {path} is not JSON object")
        return

    data["platform_b_ai_capability_assurance_library_patch"] = PATCH
    data["platform_b_architecture_change"] = False
    data["platform_b_new_lifecycle"] = False
    data["platform_b_new_module"] = False
    data["platform_b_ai_capability_module_created"] = False
    data["platform_b_capabilities_as_lifecycle_stages"] = False
    data["platform_b_lifecycle_sequence"] = LIFECYCLE_SEQUENCE

    profile_items = flatten_profiles(PATCH["capability_profiles"])

    if "blueprints" in data and isinstance(data["blueprints"], list):
        for bp in data["blueprints"]:
            if not isinstance(bp, dict):
                continue

            bp["architecture_change"] = False
            bp["new_lifecycle"] = False
            bp["new_module"] = False
            bp["ai_capability_module_created"] = False
            bp["capabilities_as_lifecycle_stages"] = False
            bp["ai_capability_assurance_library"] = PATCH

            bp["discovery_scope"] = add_unique(
                bp.get("discovery_scope", []),
                PATCH["discovery_extension"] + ["Capabilities do not become lifecycle stages"] + PATCH["not_lifecycle_stages"]
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

            bp["execution_assurance_scope"] = add_unique(
                bp.get("execution_assurance_scope", []),
                PATCH["execution_assurance_extension"]
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
                [PATCH["operational_trust_question"]] + PATCH["operational_trust_extension"]
            )

            bp["questions_answered"] = add_unique(
                bp.get("questions_answered", []),
                PATCH["evidence_questions"]
            )

            assessment = bp.get("sample_blueprint_assessment", {})
            if not isinstance(assessment, dict):
                assessment = {}

            assessment["ai_capability_assurance_library_state"] = "ACTIVE"
            assessment["architecture_change"] = False
            assessment["new_lifecycle"] = False
            assessment["new_module"] = False
            assessment["ai_capability_module_created"] = False
            assessment["capabilities_as_lifecycle_stages"] = False
            assessment["classification_assurance_profiled"] = True
            assessment["similarity_assurance_profiled"] = True
            assessment["clustering_assurance_profiled"] = True
            assessment["prediction_assurance_profiled"] = True
            assessment["retrieval_assurance_profiled"] = True
            assessment["discovery_assurance_profiled"] = True
            assessment["reasoning_assurance_profiled"] = True
            assessment["execution_assurance_profiled"] = True
            assessment["cross_capability_interaction_assured"] = True
            assessment["handoff_assurance_required"] = True
            assessment["evidence_lineage_required"] = True
            assessment["compound_risk_tracked"] = True
            assessment["ownership_continuity_required"] = True
            assessment["capability_level_operational_trust_score"] = True
            assessment["cross_capability_operational_trust_score"] = True
            assessment["operational_trust_question"] = PATCH["operational_trust_question"]
            bp["sample_blueprint_assessment"] = assessment

    if "sample_integration_assessment" in data and isinstance(data["sample_integration_assessment"], dict):
        assessment = data["sample_integration_assessment"]
        assessment["ai_capability_assurance_library_state"] = "ACTIVE"
        assessment["architecture_change"] = False
        assessment["new_lifecycle"] = False
        assessment["new_module"] = False
        assessment["ai_capability_module_created"] = False
        assessment["capabilities_as_lifecycle_stages"] = False
        assessment["ai_capability_assurance_library"] = PATCH

        assessment["operationalization_targets"] = add_unique(
            assessment.get("operationalization_targets", []),
            PATCH["operationalization_extension"] + flatten_profiles(PATCH["capability_profiles"])
        )

        assessment["execution_assurance_targets"] = add_unique(
            assessment.get("execution_assurance_targets", []),
            PATCH["execution_assurance_extension"]
        )

        assessment["evidence_automation_targets"] = add_unique(
            assessment.get("evidence_automation_targets", []),
            PATCH["evidence_extension"] + PATCH["evidence_questions"]
        )

        assessment["continuous_monitoring_targets"] = add_unique(
            assessment.get("continuous_monitoring_targets", []),
            PATCH["continuous_assurance_extension"]
        )

        assessment["implementation_priority"] = add_unique(
            assessment.get("implementation_priority", []),
            [
                "Do not create a new module for AI Capability Assurance Library.",
                "Do not create classification, similarity, clustering, prediction, retrieval, discovery, reasoning, or execution as lifecycle stages.",
                "Add AI Capability Assurance Library as capability profiles inside the existing Platform B lifecycle.",
                "Profile classification, similarity, clustering, prediction, retrieval, discovery, reasoning, execution, and cross-capability interaction.",
                "Assure capability handoffs, evidence lineage, compound risk, control coverage, monitoring continuity, and ownership continuity.",
                "Ask whether the AI capability and its interaction with other AI capabilities can be operationally trusted right now."
            ]
        )

    save_json(path, data)
    print(f"PATCHED: {path}")

def html_escape(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def card(title, items):
    lis = "".join([f"<li>{html_escape(x)}</li>" for x in items])
    return f"""
    <div class="ai-capability-library-card">
        <div class="ai-capability-library-domain">{html_escape(title)}</div>
        <ul>{lis}</ul>
    </div>
    """

def profile_cards(profiles):
    blocks = []
    for name, controls in profiles.items():
        blocks.append(card(name, controls))
    return "\n".join(blocks)

def pill_list(items, cls):
    return "".join([f'<span class="{cls}">{html_escape(x)}</span>' for x in items])

HTML_BLOCK = f"""
<style>
.platform-b-ai-capability-library-wrap {{
    margin: 28px 0;
    padding: 24px;
    border-radius: 24px;
    border: 1px solid rgba(255,255,255,.12);
    background: linear-gradient(135deg, rgba(99,102,241,.10), rgba(14,165,233,.08));
}}
.platform-b-ai-capability-library-head {{
    display: flex;
    justify-content: space-between;
    gap: 18px;
    align-items: flex-start;
    margin-bottom: 18px;
}}
.platform-b-ai-capability-library-head h2 {{
    margin: 0;
    font-size: 28px;
}}
.platform-b-ai-capability-library-head p {{
    color: #cbd5e1;
    line-height: 1.65;
    max-width: 980px;
}}
.platform-b-ai-capability-library-tag {{
    border: 1px solid rgba(165,180,252,.45);
    color: #c7d2fe;
    border-radius: 999px;
    padding: 8px 12px;
    font-size: 12px;
    white-space: nowrap;
    background: rgba(99,102,241,.10);
}}
.platform-b-ai-capability-library-warning {{
    margin: 18px 0;
    padding: 14px 16px;
    border-radius: 14px;
    background: rgba(248,113,113,.08);
    border: 1px solid rgba(248,113,113,.18);
    color: #fecaca;
    line-height: 1.55;
}}
.platform-b-ai-capability-library-principle {{
    margin: 18px 0;
    padding: 18px;
    border-left: 4px solid #a5b4fc;
    color: #e0e7ff;
    background: rgba(255,255,255,.055);
    border-radius: 16px;
    line-height: 1.65;
    font-size: 17px;
    font-weight: 800;
}}
.platform-b-ai-capability-library-question {{
    margin: 18px 0;
    padding: 16px;
    border-radius: 16px;
    background: rgba(14,165,233,.10);
    border: 1px solid rgba(125,211,252,.22);
    color: #e0f2fe;
    font-weight: 800;
    font-size: 18px;
}}
.platform-b-ai-capability-library-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 16px;
}}
.ai-capability-library-card {{
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(255,255,255,.045);
    border-radius: 18px;
    padding: 18px;
}}
.ai-capability-library-card ul {{
    margin: 10px 0 0;
    padding-left: 18px;
    color: #cbd5e1;
    line-height: 1.6;
}}
.ai-capability-library-domain {{
    color: #c7d2fe;
    font-weight: 800;
    letter-spacing: .04em;
    text-transform: uppercase;
    font-size: 12px;
}}
.platform-b-ai-capability-library-pills {{
    margin-top: 18px;
    display: flex;
    flex-wrap: wrap;
    gap: 9px;
}}
.platform-b-ai-capability-library-pill {{
    border: 1px solid rgba(255,255,255,.12);
    background: rgba(255,255,255,.045);
    border-radius: 999px;
    padding: 8px 12px;
    color: #d8dee9;
    font-size: 13px;
}}
</style>

<section class="platform-b-ai-capability-library-wrap">
    <div class="platform-b-ai-capability-library-head">
        <div>
            <h2>AI Capability Assurance Library</h2>
            <p>
                No new lifecycle. No new module. Platform B profiles AI capabilities inside the existing lifecycle
                and assures capability context, handoffs, evidence lineage, compound risk, ownership, controls,
                monitoring, and operational trust.
            </p>
        </div>
        <span class="platform-b-ai-capability-library-tag">Capability Profiles</span>
    </div>

    <div class="platform-b-ai-capability-library-warning">
        Classification, similarity, clustering, prediction, retrieval, discovery, reasoning, and execution are not lifecycle stages.
        They are capability profiles inside the existing Platform B Assurance Lifecycle.
    </div>

    <div class="platform-b-ai-capability-library-question">
        Operational Trust asks: {html_escape(PATCH["operational_trust_question"])}
    </div>

    <div class="platform-b-ai-capability-library-principle">
        {html_escape(PATCH["principle"])}
    </div>

    <div class="platform-b-ai-capability-library-grid">
        {card("Discovery", PATCH["discovery_extension"])}
        {card("Visibility", PATCH["visibility_extension"])}
        {card("Governance", PATCH["governance_extension"])}
        {card("Operationalization", PATCH["operationalization_extension"])}
        {card("Execution Assurance", PATCH["execution_assurance_extension"])}
        {card("Evidence", PATCH["evidence_extension"])}
        {card("Continuous Assurance", PATCH["continuous_assurance_extension"])}
        {card("Operational Trust", PATCH["operational_trust_extension"])}
        {profile_cards(PATCH["capability_profiles"])}
    </div>

    <div class="platform-b-ai-capability-library-pills">
        {pill_list(PATCH["evidence_questions"], "platform-b-ai-capability-library-pill")}
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
        "<!-- COBITCHAIN_PLATFORM_B_ASSURED_AUTONOMY_CROSS_CUTTING_CAPABILITY_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_AGENT_FAILURE_ASSURANCE_CONTROL_SET_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_ENTERPRISE_AI_ADOPTION_AGENT_OPERATIONAL_TRUST_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_AI_SECURITY_RUNTIME_GOVERNANCE_ASSURANCE_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_ISO42001_LIFECYCLE_MAPPING_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_GOVERNANCE_FRAMEWORK_MAPPING_CONSOLE_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_AI_COMPETENCY_GOVERNANCE_ASSURANCE_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_REGULATORY_AI_EVIDENCE_ASSURANCE_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_AI_FRAMEWORK_RUNTIME_OPERATIONALIZATION_PATCH_V1_ACTIVE -->",
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

Path("platform_b_ai_capability_assurance_library_patch_v1_summary.json").write_text(
    json.dumps(PATCH, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("platform_b_ai_capability_assurance_library_patch_v1_urls.txt").write_text(
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
print("Platform B AI Capability Assurance Library Patch completed.")
print("Marker:", PATCH_MARKER)
print("Architecture change: False")
print("New lifecycle: False")
print("New module: False")
print("Capabilities as lifecycle stages: False")
print("Capability type:", PATCH["capability_type"])
print("Lifecycle:", LIFECYCLE_SEQUENCE)
print("Operational Trust question:", PATCH["operational_trust_question"])
