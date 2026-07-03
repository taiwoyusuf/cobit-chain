from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_PLATFORM_B_GOVERNANCE_FRAMEWORK_MAPPING_CONSOLE_PATCH_V1_ACTIVE"
LIFECYCLE_SEQUENCE = "Discovery -> Visibility -> Governance -> Operationalization -> Execution Assurance -> Evidence -> Continuous Assurance -> Operational Trust"

PATCH = {
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "new_module": False,
    "capability_name": "Governance Framework Mapping Console",
    "primary_stage": "Governance",
    "architecture_instruction": "Do not add another framework module. Extend the existing Governance capability so multiple governance, risk, compliance, quality, and AI assurance frameworks can be mapped simultaneously.",
    "lifecycle_sequence": LIFECYCLE_SEQUENCE,
    "core_question": "Can the organization demonstrate that governance expectations, risk controls, compliance obligations, human oversight, evidence, monitoring, and operational trust are operating across multiple frameworks at the same time?",
    "ai_governance_framework_mapping": [
        "ISO/IEC 42001",
        "NIST AI RMF",
        "EU AI Act",
        "FDA CSA",
        "GAMP 5 Second Edition",
        "MHRA AI Guidance",
        "WHO AI Guidance",
        "OECD AI Principles",
        "Organization-specific governance policies"
    ],
    "governance_mapping_console_maps": [
        "Policies",
        "Controls",
        "Risks",
        "Evidence",
        "Monitoring",
        "Roles",
        "Approvals",
        "Compliance obligations"
    ],
    "evidence_outputs": [
        "Governance controls operating",
        "Risks continuously monitored",
        "Regulatory obligations satisfied",
        "Human oversight demonstrated",
        "AI decisions traceable",
        "Operational trust maintained"
    ],
    "continuous_assurance_evaluates": [
        "Governance effectiveness",
        "Risk effectiveness",
        "Compliance effectiveness",
        "Operational effectiveness"
    ],
    "operational_trust_foundational_statement": "Governance defines expectations. Risk Management identifies uncertainty. Compliance satisfies regulations. Assurance continuously demonstrates operational trust.",
    "not_enough": [
        "Framework implementation alone",
        "Policy existence alone",
        "Static compliance checklist",
        "One-time risk assessment",
        "Unverified governance mapping"
    ],
    "evidence_questions": [
        "Which governance frameworks apply?",
        "Which policies map to each framework?",
        "Which controls map to each framework?",
        "Which risks map to each framework?",
        "Which evidence supports each control?",
        "Which monitoring activities demonstrate control operation?",
        "Which roles own each governance obligation?",
        "Which approvals demonstrate human accountability?",
        "Which compliance obligations are satisfied?",
        "Which governance controls are operating?",
        "Which risks are continuously monitored?",
        "Which regulatory obligations are satisfied?",
        "How is human oversight demonstrated?",
        "How are AI decisions traceable?",
        "How is operational trust maintained?"
    ],
    "principle": "Governance defines expectations. Risk Management identifies uncertainty. Compliance satisfies regulations. Assurance continuously demonstrates operational trust."
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

    data["platform_b_governance_framework_mapping_console_patch"] = PATCH
    data["platform_b_architecture_change"] = False
    data["platform_b_new_module"] = False
    data["platform_b_lifecycle_sequence"] = LIFECYCLE_SEQUENCE
    data["platform_b_governance_foundational_statement"] = PATCH["operational_trust_foundational_statement"]

    if "blueprints" in data and isinstance(data["blueprints"], list):
        for bp in data["blueprints"]:
            if not isinstance(bp, dict):
                continue

            bp["architecture_change"] = False
            bp["new_module"] = False
            bp["governance_framework_mapping_console"] = PATCH

            bp["governance_frameworks"] = add_unique(
                bp.get("governance_frameworks", []),
                PATCH["ai_governance_framework_mapping"]
            )

            bp["governance_mapping_scope"] = add_unique(
                bp.get("governance_mapping_scope", []),
                PATCH["governance_mapping_console_maps"]
            )

            bp["evidence_assurance"] = add_unique(
                bp.get("evidence_assurance", []),
                PATCH["evidence_outputs"]
            )

            bp["continuous_assurance"] = add_unique(
                bp.get("continuous_assurance", []),
                PATCH["continuous_assurance_evaluates"]
            )

            bp["questions_answered"] = add_unique(
                bp.get("questions_answered", []),
                [PATCH["core_question"]] + PATCH["evidence_questions"]
            )

            assessment = bp.get("sample_blueprint_assessment", {})
            if not isinstance(assessment, dict):
                assessment = {}

            assessment["governance_framework_mapping_console_state"] = "ACTIVE"
            assessment["architecture_change"] = False
            assessment["new_module"] = False
            assessment["framework_module_created"] = False
            assessment["governance_capability_extended"] = True
            assessment["multi_framework_mapping_supported"] = True
            assessment["policies_controls_risks_evidence_monitoring_roles_approvals_obligations_mapped"] = True
            assessment["governance_effectiveness_evaluated"] = True
            assessment["risk_effectiveness_evaluated"] = True
            assessment["compliance_effectiveness_evaluated"] = True
            assessment["operational_effectiveness_evaluated"] = True
            assessment["operational_trust_statement"] = PATCH["operational_trust_foundational_statement"]
            bp["sample_blueprint_assessment"] = assessment

    if "sample_integration_assessment" in data and isinstance(data["sample_integration_assessment"], dict):
        assessment = data["sample_integration_assessment"]
        assessment["governance_framework_mapping_console_state"] = "ACTIVE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["framework_module_created"] = False
        assessment["governance_framework_mapping_console"] = PATCH
        assessment["governance_frameworks"] = add_unique(
            assessment.get("governance_frameworks", []),
            PATCH["ai_governance_framework_mapping"]
        )
        assessment["governance_mapping_scope"] = add_unique(
            assessment.get("governance_mapping_scope", []),
            PATCH["governance_mapping_console_maps"]
        )
        assessment["evidence_automation_targets"] = add_unique(
            assessment.get("evidence_automation_targets", []),
            PATCH["evidence_outputs"] + PATCH["evidence_questions"]
        )
        assessment["continuous_monitoring_targets"] = add_unique(
            assessment.get("continuous_monitoring_targets", []),
            PATCH["continuous_assurance_evaluates"]
        )
        assessment["operational_trust_statement"] = PATCH["operational_trust_foundational_statement"]

    save_json(path, data)
    print(f"PATCHED: {path}")

def html_escape(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def card(title, items):
    lis = "".join([f"<li>{html_escape(x)}</li>" for x in items])
    return f"""
    <div class="gov-map-card">
        <div class="gov-map-domain">{html_escape(title)}</div>
        <ul>{lis}</ul>
    </div>
    """

def pill_list(items, cls):
    return "".join([f'<span class="{cls}">{html_escape(x)}</span>' for x in items])

HTML_BLOCK = f"""
<style>
.platform-b-gov-map-wrap {{
    margin: 28px 0;
    padding: 24px;
    border-radius: 24px;
    border: 1px solid rgba(255,255,255,.12);
    background: linear-gradient(135deg, rgba(16,185,129,.10), rgba(14,165,233,.08));
}}
.platform-b-gov-map-head {{
    display: flex;
    justify-content: space-between;
    gap: 18px;
    align-items: flex-start;
    margin-bottom: 18px;
}}
.platform-b-gov-map-head h2 {{
    margin: 0;
    font-size: 28px;
}}
.platform-b-gov-map-head p {{
    color: #cbd5e1;
    line-height: 1.65;
    max-width: 980px;
}}
.platform-b-gov-map-tag {{
    border: 1px solid rgba(110,231,183,.45);
    color: #a7f3d0;
    border-radius: 999px;
    padding: 8px 12px;
    font-size: 12px;
    white-space: nowrap;
    background: rgba(16,185,129,.10);
}}
.platform-b-gov-map-principle {{
    margin: 18px 0;
    padding: 18px;
    border-left: 4px solid #6ee7b7;
    color: #ecfeff;
    background: rgba(255,255,255,.055);
    border-radius: 16px;
    line-height: 1.65;
    font-size: 18px;
    font-weight: 800;
}}
.platform-b-gov-map-warning {{
    margin: 18px 0;
    padding: 14px 16px;
    border-radius: 14px;
    background: rgba(248,113,113,.08);
    border: 1px solid rgba(248,113,113,.18);
    color: #fecaca;
    line-height: 1.55;
}}
.platform-b-gov-map-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 16px;
}}
.gov-map-card {{
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(255,255,255,.045);
    border-radius: 18px;
    padding: 18px;
}}
.gov-map-card ul {{
    margin: 10px 0 0;
    padding-left: 18px;
    color: #cbd5e1;
    line-height: 1.6;
}}
.gov-map-domain {{
    color: #a7f3d0;
    font-weight: 800;
    letter-spacing: .04em;
    text-transform: uppercase;
    font-size: 12px;
}}
.platform-b-gov-map-pills {{
    margin-top: 18px;
    display: flex;
    flex-wrap: wrap;
    gap: 9px;
}}
.platform-b-gov-map-pill {{
    border: 1px solid rgba(255,255,255,.12);
    background: rgba(255,255,255,.045);
    border-radius: 999px;
    padding: 8px 12px;
    color: #d8dee9;
    font-size: 13px;
}}
</style>

<section class="platform-b-gov-map-wrap">
    <div class="platform-b-gov-map-head">
        <div>
            <h2>Governance Framework Mapping Console</h2>
            <p>
                No new framework module. Platform B extends the existing Governance capability so policies,
                controls, risks, evidence, monitoring, roles, approvals, and compliance obligations can be mapped
                to multiple frameworks simultaneously while Evidence and Continuous Assurance demonstrate operational trust.
            </p>
        </div>
        <span class="platform-b-gov-map-tag">Governance Extension</span>
    </div>

    <div class="platform-b-gov-map-warning">
        Do not treat ISO/IEC 42001, NIST AI RMF, EU AI Act, FDA CSA, GAMP 5 Second Edition,
        MHRA AI Guidance, WHO AI Guidance, OECD AI Principles, or organization-specific governance policies
        as separate platform modules. They map into Governance and are continuously evidenced downstream.
    </div>

    <div class="platform-b-gov-map-principle">
        {html_escape(PATCH["operational_trust_foundational_statement"])}
    </div>

    <div class="platform-b-gov-map-grid">
        {card("AI Governance Framework Mapping", PATCH["ai_governance_framework_mapping"])}
        {card("Governance Mapping Console", PATCH["governance_mapping_console_maps"])}
        {card("Evidence Generated", PATCH["evidence_outputs"])}
        {card("Continuous Assurance Evaluates", PATCH["continuous_assurance_evaluates"])}
        {card("Not Enough", PATCH["not_enough"])}
    </div>

    <div class="platform-b-gov-map-pills">
        {pill_list(PATCH["evidence_questions"], "platform-b-gov-map-pill")}
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

Path("platform_b_governance_framework_mapping_console_patch_v1_summary.json").write_text(
    json.dumps(PATCH, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("platform_b_governance_framework_mapping_console_patch_v1_urls.txt").write_text(
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
print("Platform B Governance Framework Mapping Console Patch completed.")
print("Marker:", PATCH_MARKER)
print("Architecture change: False")
print("New module: False")
print("Primary stage: Governance")
print("Lifecycle:", LIFECYCLE_SEQUENCE)
print("Foundational statement:", PATCH["operational_trust_foundational_statement"])
