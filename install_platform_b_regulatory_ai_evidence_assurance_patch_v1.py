from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_PLATFORM_B_REGULATORY_AI_EVIDENCE_ASSURANCE_PATCH_V1_ACTIVE"
LIFECYCLE_SEQUENCE = "Discovery -> Visibility -> Governance -> Operationalization -> Execution Assurance -> Evidence -> Continuous Assurance -> Operational Trust"

PATCH = {
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "new_module": False,
    "capability_name": "Regulatory AI Evidence Assurance",
    "architecture_instruction": "Do not create a new module for AI-generated regulatory content. Extend existing Discovery, Visibility, AI Governance, Evidence Assurance, Continuous Assurance, and Operational Trust capabilities.",
    "lifecycle_sequence": LIFECYCLE_SEQUENCE,
    "core_question": "Can this AI-generated regulatory evidence be operationally trusted?",
    "not_the_primary_question": "Did AI generate this?",
    "platform_statement": "Platform B does not only identify AI-generated regulatory content. Platform B continuously assures whether AI-generated inspection responses, regulatory submissions, CMC documentation, validation documentation, CAPAs, deviations, change controls, and quality records are scientifically verified, human-reviewed, source-traceable, ALCOA+ aligned, approval-supported, and operationally trustworthy.",
    "discovery": [
        "AI systems used to generate inspection responses",
        "AI systems used to generate regulatory submissions",
        "AI systems used to generate CMC documentation",
        "AI systems used to generate validation documentation",
        "AI systems used to generate CAPAs",
        "AI systems used to generate deviations",
        "AI systems used to generate change controls",
        "AI systems used to generate quality records"
    ],
    "visibility": [
        "Which AI generated content",
        "Model version",
        "Prompt history where retained",
        "Human reviewer",
        "Review status",
        "Approval history",
        "Supporting evidence",
        "Source documents"
    ],
    "governance_extension": {
        "name": "Regulatory AI Governance",
        "evaluates": [
            "Human accountability",
            "Regulatory ownership",
            "Scientific review",
            "GxP compliance",
            "AI use policy",
            "AI disclosure requirements"
        ]
    },
    "evidence_assurance_extension": [
        "Evidence provenance",
        "Scientific verification",
        "Human verification",
        "Source traceability",
        "Citation integrity",
        "ALCOA+",
        "Evidence completeness",
        "Approval records"
    ],
    "continuous_assurance": [
        "AI-generated regulatory content remains valid",
        "Supporting evidence has not changed",
        "Source documents remain current",
        "Human approvals remain complete",
        "Regulatory evidence remains trustworthy"
    ],
    "execution_evidence_questions": [
        "Which AI system generated the regulatory content?",
        "Which model version generated the content?",
        "What prompt history was retained?",
        "Which source documents supported the content?",
        "Which evidence supports each claim?",
        "Was the evidence scientifically verified?",
        "Was the content human verified?",
        "Who reviewed the content?",
        "What was the review status?",
        "Who approved the content?",
        "What approval history exists?",
        "Are citations traceable to approved source documents?",
        "Is the evidence ALCOA+ aligned?",
        "Is the evidence complete?",
        "Does the evidence remain current?",
        "Can accountability be demonstrated?"
    ],
    "regulated_content_types": [
        "Inspection responses",
        "Regulatory submissions",
        "CMC documentation",
        "Validation documentation",
        "CAPAs",
        "Deviations",
        "Change Controls",
        "Quality records"
    ],
    "operational_trust_statement": "Operational Trust should not stop at identifying AI-generated content. Operational Trust should determine whether AI-generated regulatory evidence is scientifically verified, human-reviewed, source-traceable, approval-supported, ALCOA+ aligned, current, complete, and trustworthy.",
    "principle": "AI-generated evidence does not reduce organizational accountability. Platform B extends Evidence Assurance to continuously evaluate scientific validity, evidence lineage, human verification, traceability, approval completeness, and operational trust before and after regulatory use."
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

    data["platform_b_regulatory_ai_evidence_assurance_patch"] = PATCH
    data["platform_b_architecture_change"] = False
    data["platform_b_new_module"] = False
    data["platform_b_lifecycle_sequence"] = LIFECYCLE_SEQUENCE

    if "blueprints" in data and isinstance(data["blueprints"], list):
        for bp in data["blueprints"]:
            if not isinstance(bp, dict):
                continue

            bp["architecture_change"] = False
            bp["new_module"] = False
            bp["regulatory_ai_evidence_assurance"] = PATCH

            bp["discovery_scope"] = add_unique(
                bp.get("discovery_scope", []),
                PATCH["discovery"]
            )

            bp["visibility_scope"] = add_unique(
                bp.get("visibility_scope", []),
                PATCH["visibility"]
            )

            bp["governance_scope"] = add_unique(
                bp.get("governance_scope", []),
                PATCH["governance_extension"]["evaluates"]
            )

            bp["evidence_assurance"] = add_unique(
                bp.get("evidence_assurance", []),
                PATCH["evidence_assurance_extension"]
            )

            bp["continuous_assurance"] = add_unique(
                bp.get("continuous_assurance", []),
                PATCH["continuous_assurance"]
            )

            bp["questions_answered"] = add_unique(
                bp.get("questions_answered", []),
                [PATCH["core_question"]] + PATCH["execution_evidence_questions"]
            )

            assessment = bp.get("sample_blueprint_assessment", {})
            if not isinstance(assessment, dict):
                assessment = {}

            assessment["regulatory_ai_evidence_assurance_state"] = "EXTEND_EXISTING_CAPABILITIES"
            assessment["architecture_change"] = False
            assessment["new_module"] = False
            assessment["regulatory_ai_governance_extended"] = True
            assessment["evidence_assurance_extended"] = True
            assessment["scientific_verification_required"] = True
            assessment["human_verification_required"] = True
            assessment["source_traceability_required"] = True
            assessment["alcoa_plus_alignment_required"] = True
            assessment["approval_records_required"] = True
            assessment["continuous_evidence_trust_required"] = True
            bp["sample_blueprint_assessment"] = assessment

    if "sample_integration_assessment" in data and isinstance(data["sample_integration_assessment"], dict):
        assessment = data["sample_integration_assessment"]
        assessment["regulatory_ai_evidence_assurance_state"] = "ACTIVE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["regulatory_ai_evidence_assurance"] = PATCH
        assessment["evidence_automation_targets"] = add_unique(
            assessment.get("evidence_automation_targets", []),
            PATCH["evidence_assurance_extension"] + PATCH["execution_evidence_questions"]
        )
        assessment["continuous_monitoring_targets"] = add_unique(
            assessment.get("continuous_monitoring_targets", []),
            PATCH["continuous_assurance"]
        )
        assessment["implementation_priority"] = add_unique(
            assessment.get("implementation_priority", []),
            [
                "Discover AI systems used to generate inspection responses, regulatory submissions, CMC documentation, validation documentation, CAPAs, deviations, change controls, and quality records.",
                "Show model version, retained prompt history, human reviewer, review status, approval history, supporting evidence, and source documents.",
                "Extend AI Governance with Regulatory AI Governance for accountability, regulatory ownership, scientific review, GxP compliance, AI use policy, and disclosure requirements.",
                "Extend Evidence Assurance to evaluate provenance, scientific verification, human verification, source traceability, citation integrity, ALCOA+, completeness, and approval records.",
                "Continuously verify regulatory evidence remains valid, current, approved, and trustworthy."
            ]
        )

    save_json(path, data)
    print(f"PATCHED: {path}")

def html_escape(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def card(title, items):
    lis = "".join([f"<li>{html_escape(x)}</li>" for x in items])
    return f"""
    <div class="reg-ai-evidence-card">
        <div class="reg-ai-evidence-domain">{html_escape(title)}</div>
        <ul>{lis}</ul>
    </div>
    """

def pill_list(items, cls):
    return "".join([f'<span class="{cls}">{html_escape(x)}</span>' for x in items])

HTML_BLOCK = f"""
<style>
.platform-b-reg-ai-evidence-wrap {{
    margin: 28px 0;
    padding: 24px;
    border-radius: 24px;
    border: 1px solid rgba(255,255,255,.12);
    background: linear-gradient(135deg, rgba(34,197,94,.10), rgba(59,130,246,.08));
}}
.platform-b-reg-ai-evidence-head {{
    display: flex;
    justify-content: space-between;
    gap: 18px;
    align-items: flex-start;
    margin-bottom: 18px;
}}
.platform-b-reg-ai-evidence-head h2 {{
    margin: 0;
    font-size: 28px;
}}
.platform-b-reg-ai-evidence-head p {{
    color: #cbd5e1;
    line-height: 1.65;
    max-width: 980px;
}}
.platform-b-reg-ai-evidence-tag {{
    border: 1px solid rgba(134,239,172,.45);
    color: #bbf7d0;
    border-radius: 999px;
    padding: 8px 12px;
    font-size: 12px;
    white-space: nowrap;
    background: rgba(34,197,94,.10);
}}
.platform-b-reg-ai-evidence-principle {{
    margin: 18px 0;
    padding: 16px;
    border-left: 4px solid #86efac;
    color: #e5e7eb;
    background: rgba(255,255,255,.045);
    border-radius: 14px;
    line-height: 1.6;
}}
.platform-b-reg-ai-evidence-question {{
    margin: 18px 0;
    padding: 16px;
    border-radius: 16px;
    background: rgba(59,130,246,.10);
    border: 1px solid rgba(147,197,253,.22);
    color: #dbeafe;
    font-weight: 800;
    font-size: 18px;
}}
.platform-b-reg-ai-evidence-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 16px;
}}
.reg-ai-evidence-card {{
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(255,255,255,.045);
    border-radius: 18px;
    padding: 18px;
}}
.reg-ai-evidence-card ul {{
    margin: 10px 0 0;
    padding-left: 18px;
    color: #cbd5e1;
    line-height: 1.6;
}}
.reg-ai-evidence-domain {{
    color: #bbf7d0;
    font-weight: 800;
    letter-spacing: .04em;
    text-transform: uppercase;
    font-size: 12px;
}}
.platform-b-reg-ai-evidence-pills {{
    margin-top: 18px;
    display: flex;
    flex-wrap: wrap;
    gap: 9px;
}}
.platform-b-reg-ai-evidence-pill {{
    border: 1px solid rgba(255,255,255,.12);
    background: rgba(255,255,255,.045);
    border-radius: 999px;
    padding: 8px 12px;
    color: #d8dee9;
    font-size: 13px;
}}
</style>

<section class="platform-b-reg-ai-evidence-wrap">
    <div class="platform-b-reg-ai-evidence-head">
        <div>
            <h2>Regulatory AI Evidence Assurance</h2>
            <p>
                No new module. Platform B extends AI Governance and Evidence Assurance so AI-generated inspection responses,
                regulatory submissions, CMC documentation, validation documentation, CAPAs, deviations, change controls,
                and quality records can be scientifically verified, human-reviewed, source-traceable, approval-supported,
                ALCOA+ aligned, and continuously trusted.
            </p>
        </div>
        <span class="platform-b-reg-ai-evidence-tag">Evidence Assurance Extension</span>
    </div>

    <div class="platform-b-reg-ai-evidence-question">
        {html_escape(PATCH["core_question"])}
    </div>

    <div class="platform-b-reg-ai-evidence-principle">
        {html_escape(PATCH["principle"])}
    </div>

    <div class="platform-b-reg-ai-evidence-grid">
        {card("Discovery", PATCH["discovery"])}
        {card("Visibility", PATCH["visibility"])}
        {card("Regulatory AI Governance", PATCH["governance_extension"]["evaluates"])}
        {card("Evidence Assurance", PATCH["evidence_assurance_extension"])}
        {card("Continuous Assurance", PATCH["continuous_assurance"])}
        {card("Regulated Content Types", PATCH["regulated_content_types"])}
    </div>

    <div class="platform-b-reg-ai-evidence-pills">
        {pill_list(PATCH["execution_evidence_questions"], "platform-b-reg-ai-evidence-pill")}
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

Path("platform_b_regulatory_ai_evidence_assurance_patch_v1_summary.json").write_text(
    json.dumps(PATCH, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("platform_b_regulatory_ai_evidence_assurance_patch_v1_urls.txt").write_text(
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
print("Platform B Regulatory AI Evidence Assurance Patch completed.")
print("Marker:", PATCH_MARKER)
print("Architecture change: False")
print("New module: False")
print("Lifecycle:", LIFECYCLE_SEQUENCE)
