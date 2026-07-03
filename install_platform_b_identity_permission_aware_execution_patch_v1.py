from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_PLATFORM_B_IDENTITY_PERMISSION_AWARE_EXECUTION_PATCH_V1_ACTIVE"
LIFECYCLE_SEQUENCE = "Discovery -> Visibility -> Governance -> Operationalization -> Execution Assurance -> Evidence -> Continuous Assurance -> Operational Trust"

IDENTITY_PERMISSION_ASSURANCE = {
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "new_module": False,
    "architecture_instruction": "Do not add a new module. Extend existing Platform B capabilities across Discovery, Visibility, Governance, Retrieval Assurance, Tool Assurance, Human Oversight Assurance, Security Assurance, Operationalization, Evidence, and Continuous Assurance.",
    "capability_name": "Identity, Authorization, and Permission-Aware Execution Assurance",
    "lifecycle_sequence": LIFECYCLE_SEQUENCE,
    "core_question": "Was this AI action executed by the right identity, with the right permissions, against authorized records and tools, under least privilege, with required human approval, and with complete evidence?",
    "enriched_stages": [
        "Discovery",
        "Visibility",
        "Governance",
        "Operationalization",
        "Execution Assurance",
        "Evidence",
        "Continuous Assurance",
        "Operational Trust"
    ],
    "discovery": [
        "Agent identities",
        "Service identities",
        "Tool identities",
        "External connectors",
        "Permission boundaries",
        "Access policies",
        "Human approval workflows"
    ],
    "visibility": [
        "Agent identity",
        "Active permissions",
        "Tool permissions",
        "Retrieval permissions",
        "Human approval points",
        "Runtime access chain"
    ],
    "governance": {
        "identity_assurance": [
            "Agent identity",
            "Service identity",
            "Human identity",
            "Federated identity",
            "Managed identities"
        ],
        "authorization_assurance": [
            "RBAC",
            "ABAC",
            "Least privilege",
            "Permission inheritance",
            "Scoped authorization",
            "Temporary access"
        ]
    },
    "retrieval_assurance_extension": [
        "Permission-aware retrieval",
        "Authorization filtering",
        "Evidence filtering",
        "Security trimming",
        "Access validation"
    ],
    "tool_assurance_extension": [
        "Tool authorization",
        "API permissions",
        "Action authorization",
        "Allowed operations",
        "Execution scope"
    ],
    "human_oversight_assurance": [
        "Approval checkpoints",
        "Escalation",
        "Human intervention",
        "Override evidence",
        "Challenge evidence"
    ],
    "security_assurance": [
        "Secrets",
        "Credentials",
        "Token rotation",
        "Managed identities",
        "Zero Trust",
        "Runtime authentication"
    ],
    "operationalization_support": [
        "ServiceNow ACLs",
        "Record-level security",
        "Field security",
        "Permission-aware RAG",
        "MCP authentication",
        "Semantic Kernel authorization",
        "Azure Managed Identity",
        "OpenAI authentication",
        "Microsoft Entra ID",
        "CyberArk",
        "Service accounts"
    ],
    "execution_evidence_questions": [
        "Which identity executed?",
        "Which permissions were active?",
        "Which records were retrieved?",
        "Which records were filtered?",
        "Which tools were authorized?",
        "Which approvals occurred?",
        "Which credentials were used?",
        "Was least privilege enforced?",
        "Was human approval required?",
        "What evidence demonstrates compliance?"
    ],
    "continuous_assurance_monitors": [
        "Privilege drift",
        "Permission drift",
        "Unauthorized access",
        "Tool misuse",
        "Identity anomalies",
        "Policy violations",
        "Approval failures"
    ],
    "operational_trust_evidence": [
        "Executing identity record",
        "Active permission snapshot",
        "Retrieved record list",
        "Filtered record list",
        "Authorized tool list",
        "Approval checkpoint record",
        "Credential or managed identity evidence",
        "Least privilege evaluation",
        "Human approval evidence",
        "Compliance evidence package",
        "Runtime access chain"
    ],
    "positioning_statement": "Platform B does not add a separate identity or access module. It extends existing capabilities so every AI execution can prove identity, authorization, permission-aware retrieval, tool authorization, human oversight, security posture, and compliance evidence.",
    "principle": "AI execution cannot be operationally trusted unless identity, authorization, retrieval permissions, tool permissions, credentials, human approval, and least privilege are continuously assured."
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

    data["platform_b_identity_permission_aware_execution_patch"] = IDENTITY_PERMISSION_ASSURANCE
    data["platform_b_architecture_change"] = False
    data["platform_b_new_module"] = False
    data["platform_b_lifecycle_sequence"] = LIFECYCLE_SEQUENCE

    if "blueprints" in data and isinstance(data["blueprints"], list):
        for bp in data["blueprints"]:
            if not isinstance(bp, dict):
                continue

            bp["architecture_change"] = False
            bp["new_module"] = False
            bp["identity_permission_aware_execution_assurance"] = IDENTITY_PERMISSION_ASSURANCE

            bp["questions_answered"] = add_unique(
                bp.get("questions_answered", []),
                [IDENTITY_PERMISSION_ASSURANCE["core_question"]] + IDENTITY_PERMISSION_ASSURANCE["execution_evidence_questions"]
            )

            assessment = bp.get("sample_blueprint_assessment", {})
            if not isinstance(assessment, dict):
                assessment = {}

            assessment["identity_permission_aware_execution_state"] = "EXTEND_EXISTING_CAPABILITIES"
            assessment["architecture_change"] = False
            assessment["new_module"] = False
            assessment["identity_assurance_required"] = True
            assessment["authorization_assurance_required"] = True
            assessment["permission_aware_retrieval_required"] = True
            assessment["tool_authorization_required"] = True
            assessment["human_oversight_required"] = True
            assessment["security_assurance_required"] = True
            assessment["least_privilege_required"] = True
            assessment["continuous_permission_monitoring_required"] = True
            bp["sample_blueprint_assessment"] = assessment

    if "sample_integration_assessment" in data and isinstance(data["sample_integration_assessment"], dict):
        assessment = data["sample_integration_assessment"]
        assessment["identity_permission_aware_execution_state"] = "ACTIVE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["identity_permission_aware_execution_assurance"] = IDENTITY_PERMISSION_ASSURANCE
        assessment["evidence_automation_targets"] = add_unique(
            assessment.get("evidence_automation_targets", []),
            IDENTITY_PERMISSION_ASSURANCE["operational_trust_evidence"]
        )
        assessment["continuous_monitoring_targets"] = add_unique(
            assessment.get("continuous_monitoring_targets", []),
            IDENTITY_PERMISSION_ASSURANCE["continuous_assurance_monitors"]
        )
        assessment["implementation_priority"] = add_unique(
            assessment.get("implementation_priority", []),
            [
                "Discover agent, service, tool, connector, permission, policy, and approval workflow identities.",
                "Visualize active permissions, tool permissions, retrieval permissions, approval points, and runtime access chain.",
                "Extend Retrieval Assurance with permission-aware retrieval, security trimming, authorization filtering, and access validation.",
                "Extend Tool Assurance with tool authorization, API permissions, action authorization, allowed operations, and execution scope.",
                "Generate execution evidence for identity, permissions, retrieved and filtered records, tools, approvals, credentials, least privilege, and compliance."
            ]
        )

    save_json(path, data)
    print(f"PATCHED: {path}")

def html_escape(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def card(title, items):
    lis = "".join([f"<li>{html_escape(x)}</li>" for x in items])
    return f"""
    <div class="identity-assurance-card">
        <div class="identity-assurance-domain">{html_escape(title)}</div>
        <ul>{lis}</ul>
    </div>
    """

def pill_list(items, cls):
    return "".join([f'<span class="{cls}">{html_escape(x)}</span>' for x in items])

HTML_BLOCK = f"""
<style>
.platform-b-identity-wrap {{
    margin: 28px 0;
    padding: 24px;
    border-radius: 24px;
    border: 1px solid rgba(255,255,255,.12);
    background: linear-gradient(135deg, rgba(99,102,241,.10), rgba(16,185,129,.08));
}}
.platform-b-identity-head {{
    display: flex;
    justify-content: space-between;
    gap: 18px;
    align-items: flex-start;
    margin-bottom: 18px;
}}
.platform-b-identity-head h2 {{
    margin: 0;
    font-size: 28px;
}}
.platform-b-identity-head p {{
    color: #cbd5e1;
    line-height: 1.65;
    max-width: 980px;
}}
.platform-b-identity-tag {{
    border: 1px solid rgba(165,180,252,.45);
    color: #c4b5fd;
    border-radius: 999px;
    padding: 8px 12px;
    font-size: 12px;
    white-space: nowrap;
    background: rgba(99,102,241,.10);
}}
.platform-b-identity-principle {{
    margin: 18px 0;
    padding: 16px;
    border-left: 4px solid #c4b5fd;
    color: #e5e7eb;
    background: rgba(255,255,255,.045);
    border-radius: 14px;
    line-height: 1.6;
}}
.platform-b-identity-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 16px;
}}
.identity-assurance-card {{
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(255,255,255,.045);
    border-radius: 18px;
    padding: 18px;
}}
.identity-assurance-card ul {{
    margin: 10px 0 0;
    padding-left: 18px;
    color: #cbd5e1;
    line-height: 1.6;
}}
.identity-assurance-domain {{
    color: #c4b5fd;
    font-weight: 800;
    letter-spacing: .04em;
    text-transform: uppercase;
    font-size: 12px;
}}
.platform-b-identity-pills {{
    margin-top: 18px;
    display: flex;
    flex-wrap: wrap;
    gap: 9px;
}}
.platform-b-identity-pill {{
    border: 1px solid rgba(255,255,255,.12);
    background: rgba(255,255,255,.045);
    border-radius: 999px;
    padding: 8px 12px;
    color: #d8dee9;
    font-size: 13px;
}}
</style>

<section class="platform-b-identity-wrap">
    <div class="platform-b-identity-head">
        <div>
            <h2>Identity, Authorization, and Permission-Aware Execution Assurance</h2>
            <p>
                No new module. Platform B extends existing capabilities so every AI execution can prove identity,
                authorization, permission-aware retrieval, tool authorization, human oversight, security posture,
                least privilege, and compliance evidence.
            </p>
        </div>
        <span class="platform-b-identity-tag">Identity + Authorization + Permission-Aware Execution</span>
    </div>

    <div class="platform-b-identity-principle">
        {html_escape(IDENTITY_PERMISSION_ASSURANCE["principle"])}
    </div>

    <div class="platform-b-identity-grid">
        {card("Discovery", IDENTITY_PERMISSION_ASSURANCE["discovery"])}
        {card("Visibility", IDENTITY_PERMISSION_ASSURANCE["visibility"])}
        {card("Identity Assurance", IDENTITY_PERMISSION_ASSURANCE["governance"]["identity_assurance"])}
        {card("Authorization Assurance", IDENTITY_PERMISSION_ASSURANCE["governance"]["authorization_assurance"])}
        {card("Retrieval Assurance Extension", IDENTITY_PERMISSION_ASSURANCE["retrieval_assurance_extension"])}
        {card("Tool Assurance Extension", IDENTITY_PERMISSION_ASSURANCE["tool_assurance_extension"])}
        {card("Human Oversight Assurance", IDENTITY_PERMISSION_ASSURANCE["human_oversight_assurance"])}
        {card("Security Assurance", IDENTITY_PERMISSION_ASSURANCE["security_assurance"])}
    </div>

    <div class="platform-b-identity-pills">
        {pill_list(IDENTITY_PERMISSION_ASSURANCE["operationalization_support"], "platform-b-identity-pill")}
    </div>

    <div class="platform-b-identity-pills">
        {pill_list(IDENTITY_PERMISSION_ASSURANCE["execution_evidence_questions"], "platform-b-identity-pill")}
    </div>

    <div class="platform-b-identity-pills">
        {pill_list(IDENTITY_PERMISSION_ASSURANCE["continuous_assurance_monitors"], "platform-b-identity-pill")}
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

Path("platform_b_identity_permission_aware_execution_patch_v1_summary.json").write_text(
    json.dumps(IDENTITY_PERMISSION_ASSURANCE, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("platform_b_identity_permission_aware_execution_patch_v1_urls.txt").write_text(
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
print("Platform B Identity, Authorization, and Permission-Aware Execution Assurance Patch completed.")
print("Marker:", PATCH_MARKER)
print("Architecture change: False")
print("New module: False")
print("Lifecycle:", LIFECYCLE_SEQUENCE)
