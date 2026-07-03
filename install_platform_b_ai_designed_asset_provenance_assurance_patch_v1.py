from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_PLATFORM_B_AI_DESIGNED_ASSET_PROVENANCE_ASSURANCE_PATCH_V1_ACTIVE"
LOCKED_LIFECYCLE_SEQUENCE = "Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust"

CAPABILITIES = [
    "AI-Designed Asset Provenance Assurance",
    "Discovery-to-Regulatory Evidence Continuity",
    "Partner AI Due Diligence Passport",
    "Discovery Method Reproducibility Capsule",
    "Cross-Border Evidence Equivalence",
    "AI-Origin Traceability",
    "AI-Designed Asset Trust Passport"
]

PATCH = {
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "new_module": False,
    "new_stage": False,
    "new_pillar": False,
    "new_architecture": False,
    "capability_type": "AI-Designed Asset Provenance Assurance as cross-cutting Platform B capabilities",
    "locked_lifecycle_sequence": LOCKED_LIFECYCLE_SEQUENCE,
    "architecture_instruction": "Do not create a new module, stage, pillar, or architecture. Keep the lifecycle locked as Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust. Add AI-Designed Asset Provenance Assurance, Discovery-to-Regulatory Evidence Continuity, Partner AI Due Diligence Passport, Discovery Method Reproducibility Capsule, Cross-Border Evidence Equivalence, AI-Origin Traceability, and AI-Designed Asset Trust Passport as cross-cutting capabilities.",
    "cross_cutting_capabilities": CAPABILITIES,
    "discovery_extension": [
        "AI-designed asset/candidate",
        "Target",
        "Molecule/sequence/formulation",
        "AI platform used",
        "Partner organization",
        "Jurisdiction of origin",
        "Training/input data sources",
        "Model/platform version",
        "Assay/experimental data",
        "Human scientific reviewer",
        "CMC relevance",
        "Clinical relevance",
        "Regulatory filing relevance",
        "IP/data-rights constraints",
        "Evidence owner"
    ],
    "visibility_extension": [
        "AI-origin status",
        "Partner provenance status",
        "Data provenance completeness",
        "Model/method traceability",
        "Discovery reproducibility status",
        "Cross-border evidence risk",
        "CMC impact",
        "Regulatory risk",
        "Scientific confidence score",
        "Human review status",
        "AI-designed asset trust passport",
        "Operational Trust Score"
    ],
    "governance_extension": [
        "Acceptable AI-discovery use",
        "Partner due-diligence requirements",
        "Evidence requirements for AI-designed assets",
        "Source-data requirements",
        "Model/method documentation expectations",
        "Human scientific review rules",
        "Cross-border evidence review rules",
        "IP/data-rights governance",
        "Regulatory filing readiness criteria",
        "Escalation rules for weak provenance"
    ],
    "operationalization_extension": [
        "No asset advancement without provenance review",
        "No regulatory use without source/method evidence",
        "Partner AI due-diligence workflow",
        "Reproducibility capsule creation",
        "Human scientific approval",
        "Cross-border evidence review",
        "CMC/regulatory impact assessment",
        "Evidence package generation before submission use"
    ],
    "manufacturing_monitoring_extension": [
        "AI-origin assets entering development",
        "CMC process assumptions derived from AI discovery",
        "Method changes",
        "Partner evidence updates",
        "Assay reproducibility issues",
        "Discovery-to-CMC translation risks",
        "Cross-border evidence gaps",
        "Regulatory-readiness issues"
    ],
    "evidence_extension": [
        "AI platform used",
        "Partner documentation",
        "Model/method version",
        "Data provenance",
        "Target rationale",
        "Ranking/selection criteria",
        "Optimization history",
        "Assay evidence",
        "Rejected alternatives",
        "Uncertainty and limitations",
        "Human scientific review",
        "CMC/regulatory rationale",
        "Cross-border evidence assessment",
        "Final advancement decision"
    ],
    "continuous_assurance_extension": [
        "Weak provenance",
        "Missing partner evidence",
        "Model/method changes",
        "Unverified discovery claims",
        "Assay mismatch",
        "CMC translation risk",
        "Regulatory evidence gaps",
        "IP/data-rights concerns",
        "Cross-border evidence weakness",
        "Trust degradation before filing"
    ],
    "operational_trust_question": "Can this AI-designed asset be scientifically trusted, regulatorily defended, and traced from discovery decision to regulatory evidence right now?",
    "platform_principle": "Platform B treats AI-designed assets as provenance-sensitive regulated assets whose discovery method, partner evidence, source data, reproducibility, CMC translation, cross-border equivalence, IP/data rights, and regulatory evidence continuity must remain traceable from discovery decision to filing readiness.",
    "capability_profiles": {
        "AI-Designed Asset Provenance Assurance": [
            "AI-designed asset/candidate",
            "AI-origin status",
            "AI platform used",
            "Training/input data sources",
            "Model/platform version",
            "Partner provenance status",
            "Weak provenance detection"
        ],
        "Discovery-to-Regulatory Evidence Continuity": [
            "Discovery decision",
            "CMC relevance",
            "Clinical relevance",
            "Regulatory filing relevance",
            "CMC/regulatory rationale",
            "Evidence package generation before submission use",
            "Discovery-to-CMC translation risk monitoring"
        ],
        "Partner AI Due Diligence Passport": [
            "Partner organization",
            "Jurisdiction of origin",
            "Partner documentation",
            "Partner due-diligence requirements",
            "Partner AI due-diligence workflow",
            "Missing partner evidence detection",
            "Partner evidence update monitoring"
        ],
        "Discovery Method Reproducibility Capsule": [
            "Model/method traceability",
            "Discovery reproducibility status",
            "Assay/experimental data",
            "Assay evidence",
            "Rejected alternatives",
            "Uncertainty and limitations",
            "Assay mismatch detection"
        ],
        "Cross-Border Evidence Equivalence": [
            "Jurisdiction of origin",
            "Cross-border evidence risk",
            "Cross-border evidence review rules",
            "Cross-border evidence assessment",
            "Cross-border evidence gaps",
            "Cross-border evidence weakness detection",
            "Regulatory evidence equivalence state"
        ],
        "AI-Origin Traceability": [
            "AI-origin status",
            "Target",
            "Molecule/sequence/formulation",
            "Target rationale",
            "Ranking/selection criteria",
            "Optimization history",
            "Unverified discovery claim detection"
        ],
        "AI-Designed Asset Trust Passport": [
            "Scientific confidence score",
            "Human scientific reviewer",
            "Human scientific approval",
            "Data provenance completeness",
            "Regulatory risk",
            "IP/data-rights constraints",
            "Final advancement decision"
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

    data["platform_b_ai_designed_asset_provenance_assurance_patch"] = PATCH
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
            bp["ai_designed_asset_provenance_assurance"] = PATCH

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

            assessment["ai_designed_asset_provenance_assurance_state"] = "ACTIVE"
            assessment["architecture_change"] = False
            assessment["new_module"] = False
            assessment["new_stage"] = False
            assessment["new_pillar"] = False
            assessment["new_architecture"] = False
            assessment["locked_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
            assessment["ai_designed_asset_provenance_assurance_active"] = True
            assessment["discovery_to_regulatory_evidence_continuity_active"] = True
            assessment["partner_ai_due_diligence_passport_active"] = True
            assessment["discovery_method_reproducibility_capsule_active"] = True
            assessment["cross_border_evidence_equivalence_active"] = True
            assessment["ai_origin_traceability_active"] = True
            assessment["ai_designed_asset_trust_passport_active"] = True
            assessment["operational_trust_question"] = PATCH["operational_trust_question"]

            for capability in CAPABILITIES:
                key = capability_key(capability)
                assessment[f"{key}_active"] = True
                assessment[f"{key}_module_created"] = False

            bp["sample_blueprint_assessment"] = assessment

    if "sample_integration_assessment" in data and isinstance(data["sample_integration_assessment"], dict):
        assessment = data["sample_integration_assessment"]
        assessment["ai_designed_asset_provenance_assurance_state"] = "ACTIVE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["new_stage"] = False
        assessment["new_pillar"] = False
        assessment["new_architecture"] = False
        assessment["locked_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
        assessment["ai_designed_asset_provenance_assurance"] = PATCH

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
                "Do not create a new module, stage, pillar, or architecture for AI-Designed Asset Provenance Assurance.",
                "Keep the lifecycle locked as Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust.",
                "Implement AI-designed asset provenance, discovery-to-regulatory evidence continuity, partner AI due diligence, method reproducibility, cross-border evidence equivalence, AI-origin traceability, and AI-designed asset trust passport as cross-cutting capabilities.",
                "Continuously answer whether this AI-designed asset can be scientifically trusted, regulatorily defended, and traced from discovery decision to regulatory evidence right now."
            ]
        )

    save_json(path, data)
    print(f"PATCHED: {path}")

def html_escape(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def card(title, items):
    lis = "".join([f"<li>{html_escape(x)}</li>" for x in items])
    return f"""
    <div class="asset-provenance-card">
        <div class="asset-provenance-title">{html_escape(title)}</div>
        <ul>{lis}</ul>
    </div>
    """

def profile_cards(profiles):
    return "\n".join([card(name, controls) for name, controls in profiles.items()])

HTML_BLOCK = f"""
<style>
.platform-b-asset-provenance-wrap {{
    margin: 28px 0;
    padding: 24px;
    border-radius: 24px;
    border: 1px solid rgba(255,255,255,.12);
    background: linear-gradient(135deg, rgba(236,72,153,.10), rgba(14,165,233,.08));
}}
.platform-b-asset-provenance-wrap h2 {{
    margin: 0 0 12px 0;
    font-size: 28px;
}}
.platform-b-asset-provenance-wrap p {{
    color: #cbd5e1;
    line-height: 1.65;
    max-width: 1120px;
}}
.platform-b-asset-provenance-warning {{
    margin: 18px 0;
    padding: 14px 16px;
    border-radius: 14px;
    background: rgba(248,113,113,.08);
    border: 1px solid rgba(248,113,113,.18);
    color: #fecaca;
    line-height: 1.55;
    font-weight: 800;
}}
.platform-b-asset-provenance-question {{
    margin: 18px 0;
    padding: 16px;
    border-radius: 16px;
    background: rgba(14,165,233,.10);
    border: 1px solid rgba(125,211,252,.22);
    color: #e0f2fe;
    font-weight: 800;
    font-size: 18px;
}}
.platform-b-asset-provenance-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 16px;
}}
.asset-provenance-card {{
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(255,255,255,.045);
    border-radius: 18px;
    padding: 18px;
}}
.asset-provenance-card ul {{
    margin: 10px 0 0;
    padding-left: 18px;
    color: #cbd5e1;
    line-height: 1.6;
}}
.asset-provenance-title {{
    color: #fbcfe8;
    font-weight: 800;
    letter-spacing: .04em;
    text-transform: uppercase;
    font-size: 12px;
}}
</style>

<section class="platform-b-asset-provenance-wrap">
    <h2>AI-Designed Asset Provenance Assurance</h2>
    <p><strong>No new module, stage, pillar, or architecture.</strong> Platform B implements AI-Designed Asset Provenance Assurance, Discovery-to-Regulatory Evidence Continuity, Partner AI Due Diligence Passport, Discovery Method Reproducibility Capsule, Cross-Border Evidence Equivalence, AI-Origin Traceability, and AI-Designed Asset Trust Passport as cross-cutting capabilities inside the existing lifecycle.</p>
    <p>{html_escape(PATCH["platform_principle"])}</p>

    <div class="platform-b-asset-provenance-warning">
        AI-designed candidates cannot advance on scientific promise alone. Platform B requires provenance, reproducibility, partner due diligence, source-data confidence, CMC translation logic, cross-border evidence equivalence, and filing-ready evidence continuity.
    </div>

    <div class="platform-b-asset-provenance-question">
        Operational Trust asks: {html_escape(PATCH["operational_trust_question"])}
    </div>

    <div class="platform-b-asset-provenance-grid">
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
        "<!-- COBITCHAIN_PLATFORM_B_CONTROLLED_ADAPTATION_AGENTICITY_AI_CONFIGURATION_ASSURANCE_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_REGULATORY_EVIDENCE_ASSURANCE_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_ACCOUNTABILITY_PRESENCE_GOVERNANCE_OPERATING_ASSURANCE_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_ASSURANCE_AWARE_AI_STACK_PATCH_V1_ACTIVE -->",
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

Path("platform_b_ai_designed_asset_provenance_assurance_patch_v1_summary.json").write_text(
    json.dumps(PATCH, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("platform_b_ai_designed_asset_provenance_assurance_patch_v1_urls.txt").write_text(
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
print("Platform B AI-Designed Asset Provenance Assurance Patch completed.")
print("Marker:", PATCH_MARKER)
print("Architecture change: False")
print("New module: False")
print("New stage: False")
print("New pillar: False")
print("New architecture: False")
print("Locked lifecycle:", LOCKED_LIFECYCLE_SEQUENCE)
print("Operational Trust question:", PATCH["operational_trust_question"])
