from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_PLATFORM_B_AI_SECURITY_RUNTIME_GOVERNANCE_ASSURANCE_PATCH_V1_ACTIVE"
LIFECYCLE_SEQUENCE = "Discovery -> Visibility -> Governance -> Operationalization -> Execution Assurance -> Evidence -> Continuous Assurance -> Operational Trust"

PATCH = {
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "new_module": False,
    "capability_name": "AI Security Runtime Governance Assurance",
    "primary_stage": "Operationalization",
    "architecture_instruction": "Do not create a separate AI security framework module. Extend existing Discovery, Visibility, Governance, Operationalization, Evidence, Continuous Assurance, and Operational Trust capabilities so AI security governance is translated into runtime controls, evidence, and operational trust.",
    "lifecycle_sequence": LIFECYCLE_SEQUENCE,
    "discovery_extension": [
        "AI security frameworks used",
        "NIST AI RMF adoption",
        "MITRE ATT&CK/ATLAS mappings",
        "OWASP LLM coverage",
        "OWASP Agent coverage",
        "OWASP MCP coverage",
        "Security control inventory",
        "Runtime security capabilities"
    ],
    "visibility_extension": [
        "AI Security Posture",
        "Governance maturity",
        "Vulnerability coverage",
        "Threat coverage",
        "Runtime enforcement",
        "Evidence completeness",
        "Security gaps"
    ],
    "governance_extension": [
        "AI Security Governance",
        "Security policies",
        "Runtime policies",
        "Identity policies",
        "Tool authorization",
        "Agent authorization",
        "MCP governance",
        "Human approval policies",
        "Secure deployment policies"
    ],
    "operationalization_extension": [
        "Runtime authorization",
        "Runtime identity",
        "Policy enforcement",
        "Prompt filtering",
        "Model routing",
        "Tool permissions",
        "Human approval",
        "Segmentation",
        "Secrets management",
        "Sandbox execution"
    ],
    "evidence_extension": [
        "Prompt injection blocked",
        "Tool invocation approved",
        "MCP request authenticated",
        "Agent identity verified",
        "Human approval completed",
        "Secret rotation performed",
        "Policy enforcement executed",
        "Runtime exception handled"
    ],
    "continuous_assurance_extension": [
        "Prompt attacks",
        "Tool misuse",
        "Agent drift",
        "Permission drift",
        "Identity misuse",
        "Runtime anomalies",
        "New OWASP findings",
        "New MITRE techniques"
    ],
    "operational_trust_question": "Can this AI system be operationally trusted?",
    "not_the_primary_question": "Are we NIST compliant?",
    "platform_statement": "Most frameworks stop at governance mapping or compliance posture. Platform B extends further by translating AI security governance into operational controls such as runtime authorization, runtime identity, policy enforcement, prompt filtering, model routing, tool permissions, human approval, segmentation, secrets management, and sandbox execution, then continuously evidencing whether those controls actually operated.",
    "principle": "AI security is not operationally trusted because a framework is mapped. AI security is operationally trusted when runtime controls operate, evidence is captured, threats are monitored, and trust can be demonstrated continuously.",
    "evidence_questions": [
        "Which AI security frameworks are used?",
        "Is NIST AI RMF adopted?",
        "Which MITRE ATT&CK/ATLAS mappings apply?",
        "What OWASP LLM coverage exists?",
        "What OWASP Agent coverage exists?",
        "What OWASP MCP coverage exists?",
        "Which security controls are inventoried?",
        "Which runtime security capabilities are enabled?",
        "What is the AI security posture?",
        "Where are security gaps?",
        "Are runtime authorization controls operating?",
        "Is runtime identity verified?",
        "Is policy enforcement executed?",
        "Are prompts filtered?",
        "Is model routing governed?",
        "Are tool permissions enforced?",
        "Was human approval completed?",
        "Is segmentation enforced?",
        "Are secrets managed and rotated?",
        "Was sandbox execution used?",
        "Was prompt injection blocked?",
        "Was tool invocation approved?",
        "Was the MCP request authenticated?",
        "Was agent identity verified?",
        "Was a runtime exception handled?",
        "Are prompt attacks being monitored?",
        "Is tool misuse being monitored?",
        "Is agent drift being monitored?",
        "Is permission drift being monitored?",
        "Is identity misuse being monitored?",
        "Are runtime anomalies being evaluated?",
        "Are new OWASP findings reviewed?",
        "Are new MITRE techniques reviewed?",
        "Can this AI system be operationally trusted?"
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

def patch_seed(path):
    p = Path(path)
    if not p.exists():
        print(f"SKIP: {path}")
        return

    data = load_json(path)
    if not isinstance(data, dict):
        print(f"SKIP: {path} is not JSON object")
        return

    data["platform_b_ai_security_runtime_governance_assurance_patch"] = PATCH
    data["platform_b_architecture_change"] = False
    data["platform_b_new_module"] = False
    data["platform_b_security_framework_module_created"] = False
    data["platform_b_lifecycle_sequence"] = LIFECYCLE_SEQUENCE

    if "blueprints" in data and isinstance(data["blueprints"], list):
        for bp in data["blueprints"]:
            if not isinstance(bp, dict):
                continue

            bp["architecture_change"] = False
            bp["new_module"] = False
            bp["security_framework_module_created"] = False
            bp["ai_security_runtime_governance_assurance"] = PATCH

            bp["discovery_scope"] = add_unique(
                bp.get("discovery_scope", []),
                PATCH["discovery_extension"]
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
                PATCH["operationalization_extension"]
            )

            bp["evidence_assurance"] = add_unique(
                bp.get("evidence_assurance", []),
                PATCH["evidence_extension"]
            )

            bp["continuous_assurance"] = add_unique(
                bp.get("continuous_assurance", []),
                PATCH["continuous_assurance_extension"]
            )

            bp["questions_answered"] = add_unique(
                bp.get("questions_answered", []),
                [PATCH["operational_trust_question"]] + PATCH["evidence_questions"]
            )

            assessment = bp.get("sample_blueprint_assessment", {})
            if not isinstance(assessment, dict):
                assessment = {}

            assessment["ai_security_runtime_governance_assurance_state"] = "ACTIVE"
            assessment["architecture_change"] = False
            assessment["new_module"] = False
            assessment["security_framework_module_created"] = False
            assessment["ai_security_governance_extended"] = True
            assessment["runtime_authorization_required"] = True
            assessment["runtime_identity_required"] = True
            assessment["policy_enforcement_required"] = True
            assessment["prompt_filtering_required"] = True
            assessment["tool_permissions_required"] = True
            assessment["mcp_governance_required"] = True
            assessment["human_approval_required"] = True
            assessment["secrets_management_required"] = True
            assessment["sandbox_execution_required"] = True
            assessment["security_control_operation_evidence_required"] = True
            assessment["prompt_attacks_monitored"] = True
            assessment["tool_misuse_monitored"] = True
            assessment["agent_drift_monitored"] = True
            assessment["permission_drift_monitored"] = True
            assessment["identity_misuse_monitored"] = True
            assessment["runtime_anomalies_monitored"] = True
            assessment["operational_trust_question"] = PATCH["operational_trust_question"]
            bp["sample_blueprint_assessment"] = assessment

    if "sample_integration_assessment" in data and isinstance(data["sample_integration_assessment"], dict):
        assessment = data["sample_integration_assessment"]
        assessment["ai_security_runtime_governance_assurance_state"] = "ACTIVE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["security_framework_module_created"] = False
        assessment["ai_security_runtime_governance_assurance"] = PATCH
        assessment["operationalization_targets"] = add_unique(
            assessment.get("operationalization_targets", []),
            PATCH["operationalization_extension"]
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
                "Discover AI security frameworks used, NIST AI RMF adoption, MITRE ATT&CK/ATLAS mappings, OWASP LLM coverage, OWASP Agent coverage, OWASP MCP coverage, security control inventory, and runtime security capabilities.",
                "Add AI Security Posture visibility showing governance maturity, vulnerability coverage, threat coverage, runtime enforcement, evidence completeness, and security gaps.",
                "Extend Governance with AI Security Governance for security policies, runtime policies, identity policies, tool authorization, agent authorization, MCP governance, human approval policies, and secure deployment policies.",
                "Translate governance into runtime authorization, runtime identity, policy enforcement, prompt filtering, model routing, tool permissions, human approval, segmentation, secrets management, and sandbox execution.",
                "Capture evidence that security controls actually operated, including prompt injection blocked, tool invocation approved, MCP request authenticated, agent identity verified, human approval completed, secret rotation performed, policy enforcement executed, and runtime exception handled.",
                "Continuously evaluate prompt attacks, tool misuse, agent drift, permission drift, identity misuse, runtime anomalies, new OWASP findings, and new MITRE techniques.",
                "Ask whether the AI system can be operationally trusted, not merely whether it is NIST compliant."
            ]
        )

    save_json(path, data)
    print(f"PATCHED: {path}")

def html_escape(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def card(title, items):
    lis = "".join([f"<li>{html_escape(x)}</li>" for x in items])
    return f"""
    <div class="ai-security-runtime-card">
        <div class="ai-security-runtime-domain">{html_escape(title)}</div>
        <ul>{lis}</ul>
    </div>
    """

def pill_list(items, cls):
    return "".join([f'<span class="{cls}">{html_escape(x)}</span>' for x in items])

HTML_BLOCK = f"""
<style>
.platform-b-ai-security-runtime-wrap {{
    margin: 28px 0;
    padding: 24px;
    border-radius: 24px;
    border: 1px solid rgba(255,255,255,.12);
    background: linear-gradient(135deg, rgba(239,68,68,.10), rgba(59,130,246,.08));
}}
.platform-b-ai-security-runtime-head {{
    display: flex;
    justify-content: space-between;
    gap: 18px;
    align-items: flex-start;
    margin-bottom: 18px;
}}
.platform-b-ai-security-runtime-head h2 {{
    margin: 0;
    font-size: 28px;
}}
.platform-b-ai-security-runtime-head p {{
    color: #cbd5e1;
    line-height: 1.65;
    max-width: 980px;
}}
.platform-b-ai-security-runtime-tag {{
    border: 1px solid rgba(252,165,165,.45);
    color: #fecaca;
    border-radius: 999px;
    padding: 8px 12px;
    font-size: 12px;
    white-space: nowrap;
    background: rgba(239,68,68,.10);
}}
.platform-b-ai-security-runtime-warning {{
    margin: 18px 0;
    padding: 14px 16px;
    border-radius: 14px;
    background: rgba(248,113,113,.08);
    border: 1px solid rgba(248,113,113,.18);
    color: #fecaca;
    line-height: 1.55;
}}
.platform-b-ai-security-runtime-principle {{
    margin: 18px 0;
    padding: 18px;
    border-left: 4px solid #fca5a5;
    color: #fee2e2;
    background: rgba(255,255,255,.055);
    border-radius: 16px;
    line-height: 1.65;
    font-size: 17px;
    font-weight: 800;
}}
.platform-b-ai-security-runtime-question {{
    margin: 18px 0;
    padding: 16px;
    border-radius: 16px;
    background: rgba(59,130,246,.10);
    border: 1px solid rgba(147,197,253,.22);
    color: #dbeafe;
    font-weight: 800;
    font-size: 18px;
}}
.platform-b-ai-security-runtime-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 16px;
}}
.ai-security-runtime-card {{
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(255,255,255,.045);
    border-radius: 18px;
    padding: 18px;
}}
.ai-security-runtime-card ul {{
    margin: 10px 0 0;
    padding-left: 18px;
    color: #cbd5e1;
    line-height: 1.6;
}}
.ai-security-runtime-domain {{
    color: #fecaca;
    font-weight: 800;
    letter-spacing: .04em;
    text-transform: uppercase;
    font-size: 12px;
}}
.platform-b-ai-security-runtime-pills {{
    margin-top: 18px;
    display: flex;
    flex-wrap: wrap;
    gap: 9px;
}}
.platform-b-ai-security-runtime-pill {{
    border: 1px solid rgba(255,255,255,.12);
    background: rgba(255,255,255,.045);
    border-radius: 999px;
    padding: 8px 12px;
    color: #d8dee9;
    font-size: 13px;
}}
</style>

<section class="platform-b-ai-security-runtime-wrap">
    <div class="platform-b-ai-security-runtime-head">
        <div>
            <h2>AI Security Runtime Governance Assurance</h2>
            <p>
                No security framework module. Platform B extends Governance into operational security controls and
                continuously evidences whether runtime authorization, identity, policy enforcement, prompt filtering,
                model routing, tool permissions, MCP governance, human approval, secrets management, segmentation,
                and sandbox execution actually operated.
            </p>
        </div>
        <span class="platform-b-ai-security-runtime-tag">Security Runtime Extension</span>
    </div>

    <div class="platform-b-ai-security-runtime-warning">
        Do not stop at NIST AI RMF, MITRE ATT&CK/ATLAS, OWASP LLM, OWASP Agent, or OWASP MCP mapping.
        Platform B maps security expectations into Governance, then operationalizes controls and captures evidence of control operation.
    </div>

    <div class="platform-b-ai-security-runtime-question">
        Operational Trust asks: {html_escape(PATCH["operational_trust_question"])}
    </div>

    <div class="platform-b-ai-security-runtime-principle">
        {html_escape(PATCH["principle"])}
    </div>

    <div class="platform-b-ai-security-runtime-grid">
        {card("Discovery", PATCH["discovery_extension"])}
        {card("Visibility: AI Security Posture", PATCH["visibility_extension"])}
        {card("AI Security Governance", PATCH["governance_extension"])}
        {card("Operationalization Controls", PATCH["operationalization_extension"])}
        {card("Evidence of Control Operation", PATCH["evidence_extension"])}
        {card("Continuous Assurance", PATCH["continuous_assurance_extension"])}
    </div>

    <div class="platform-b-ai-security-runtime-pills">
        {pill_list(PATCH["evidence_questions"], "platform-b-ai-security-runtime-pill")}
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

Path("platform_b_ai_security_runtime_governance_assurance_patch_v1_summary.json").write_text(
    json.dumps(PATCH, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("platform_b_ai_security_runtime_governance_assurance_patch_v1_urls.txt").write_text(
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
print("Platform B AI Security Runtime Governance Assurance Patch completed.")
print("Marker:", PATCH_MARKER)
print("Architecture change: False")
print("New module: False")
print("Security framework module created: False")
print("Primary stage: Operationalization")
print("Lifecycle:", LIFECYCLE_SEQUENCE)
print("Operational Trust question:", PATCH["operational_trust_question"])
