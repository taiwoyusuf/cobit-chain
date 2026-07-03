from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_PLATFORM_B_PRE_DEVIATION_CAPA_EFFECTIVENESS_ASSURANCE_PATCH_V1_ACTIVE"
LOCKED_LIFECYCLE_SEQUENCE = "Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust"

CAPABILITIES = [
    "Pre-Deviation Signal Graph",
    "Deviation Forecasting Window",
    "Root Cause Confidence Score",
    "CAPA Effectiveness Ledger",
    "Preventive Action Firewall",
    "Deviation Debt Register",
    "Quality Nervous System"
]

PATCH = {
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "new_module": False,
    "new_stage": False,
    "new_architecture": False,
    "capability_type": "Pre-Deviation Assurance and CAPA Effectiveness Assurance as cross-cutting Platform B capabilities",
    "locked_lifecycle_sequence": LOCKED_LIFECYCLE_SEQUENCE,
    "architecture_instruction": "Do not create a new module, stage, or architecture. Add Pre-Deviation Signal Graph, Deviation Forecasting Window, Root Cause Confidence Score, CAPA Effectiveness Ledger, Preventive Action Firewall, Deviation Debt Register, and Quality Nervous System as cross-cutting capabilities across the existing Platform B lifecycle.",
    "cross_cutting_capabilities": CAPABILITIES,
    "discovery_extension": [
        "Deviations",
        "CAPAs",
        "Recurring events",
        "Near misses",
        "Alarms",
        "Audit findings",
        "Complaints",
        "OOS/OOT",
        "Training gaps",
        "Equipment issues",
        "Access issues",
        "Change controls",
        "SOP ambiguity",
        "Batch/process/equipment relationships"
    ],
    "visibility_extension": [
        "Deviation clusters",
        "Repeat deviation patterns",
        "Pre-deviation signals",
        "CAPA recurrence risk",
        "CAPA effectiveness state",
        "Root cause confidence",
        "Deviation debt",
        "Weak-signal heatmap",
        "Process control confidence"
    ],
    "governance_extension": [
        "Deviation escalation rules",
        "CAPA approval rules",
        "AI-generated CAPA review requirements",
        "Root-cause evidence requirements",
        "Preventive action thresholds",
        "Recurrence definitions",
        "Effectiveness-check rules",
        "Forbidden auto-approval rules"
    ],
    "operationalization_extension": [
        "Preventive action before deviation",
        "High-risk action blocking",
        "Human review for AI-generated CAPA",
        "Evidence checks before CAPA closure",
        "CAPA connection to change control/training/validation",
        "Escalation when recurrence risk remains high"
    ],
    "manufacturing_monitoring_extension": [
        "Weak signals",
        "Alarm trends",
        "Operator workarounds",
        "Equipment drift",
        "Process drift",
        "Batch timing pressure",
        "Access failures",
        "Repeated exceptions",
        "Pre-deviation conditions"
    ],
    "evidence_extension": [
        "Root-cause evidence",
        "CAPA rationale",
        "AI-generated recommendation",
        "Human review",
        "Rejected alternatives",
        "Approval records",
        "Effectiveness evidence",
        "Recurrence monitoring",
        "Preventive intervention evidence"
    ],
    "continuous_assurance_extension": [
        "CAPA effectiveness after closure",
        "Recurrence detection",
        "Deviation debt detection",
        "Weak control signal detection",
        "False AI-generated CAPA confidence detection",
        "Stale effectiveness check detection"
    ],
    "operational_trust_question": "Is this process still under control, or is it entering a pre-deviation state?",
    "platform_principle": "Platform B extends operational trust from post-event investigation to pre-deviation prevention by linking weak signals, root-cause confidence, CAPA effectiveness, recurrence risk, and evidence integrity across the existing lifecycle.",
    "capability_profiles": {
        "Pre-Deviation Signal Graph": [
            "Weak signal relationship map",
            "Near-miss linkage",
            "Alarm trend linkage",
            "Recurring event linkage",
            "Batch/process/equipment relationship",
            "Access and training signal linkage",
            "Pre-deviation condition map"
        ],
        "Deviation Forecasting Window": [
            "Deviation likelihood window",
            "Batch timing pressure",
            "Equipment drift horizon",
            "Process drift horizon",
            "Repeated exception trend",
            "Operator workaround signal",
            "Escalation timing threshold"
        ],
        "Root Cause Confidence Score": [
            "Root-cause evidence completeness",
            "Alternative cause rejection",
            "Evidence strength score",
            "Human review state",
            "AI confidence challenge",
            "Recurrence evidence linkage",
            "Root-cause confidence rating"
        ],
        "CAPA Effectiveness Ledger": [
            "CAPA rationale record",
            "Approval record",
            "Effectiveness check record",
            "Post-closure monitoring record",
            "Recurrence tracking",
            "Evidence refresh status",
            "Effectiveness state history"
        ],
        "Preventive Action Firewall": [
            "High-risk action block",
            "Preventive intervention trigger",
            "CAPA closure evidence gate",
            "Forbidden auto-approval block",
            "Escalation trigger",
            "Change control/training/validation linkage",
            "Residual recurrence risk block"
        ],
        "Deviation Debt Register": [
            "Open deviation debt",
            "Repeated event debt",
            "Weak CAPA debt",
            "Late effectiveness check",
            "Unresolved root-cause uncertainty",
            "Owner assignment",
            "Remediation due date"
        ],
        "Quality Nervous System": [
            "Weak control signal detection",
            "Deviation cluster sensing",
            "CAPA recurrence sensing",
            "Process control confidence",
            "Quality signal escalation",
            "Manufacturing control feedback",
            "Operational trust degradation alert"
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

    data["platform_b_pre_deviation_capa_effectiveness_assurance_patch"] = PATCH
    data["platform_b_architecture_change"] = False
    data["platform_b_new_module"] = False
    data["platform_b_new_stage"] = False
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
            bp["new_architecture"] = False
            bp["locked_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
            bp["pre_deviation_capa_effectiveness_assurance"] = PATCH

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

            assessment["pre_deviation_capa_effectiveness_assurance_state"] = "ACTIVE"
            assessment["architecture_change"] = False
            assessment["new_module"] = False
            assessment["new_stage"] = False
            assessment["new_architecture"] = False
            assessment["locked_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
            assessment["operational_trust_question"] = PATCH["operational_trust_question"]
            assessment["process_under_control_question_active"] = True

            for capability in CAPABILITIES:
                key = capability_key(capability)
                assessment[f"{key}_active"] = True
                assessment[f"{key}_module_created"] = False

            bp["sample_blueprint_assessment"] = assessment

    if "sample_integration_assessment" in data and isinstance(data["sample_integration_assessment"], dict):
        assessment = data["sample_integration_assessment"]
        assessment["pre_deviation_capa_effectiveness_assurance_state"] = "ACTIVE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["new_stage"] = False
        assessment["new_architecture"] = False
        assessment["locked_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
        assessment["pre_deviation_capa_effectiveness_assurance"] = PATCH

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
                "Do not create a new module, stage, or architecture for Pre-Deviation Assurance or CAPA Effectiveness Assurance.",
                "Implement Pre-Deviation Signal Graph, Deviation Forecasting Window, Root Cause Confidence Score, CAPA Effectiveness Ledger, Preventive Action Firewall, Deviation Debt Register, and Quality Nervous System as cross-cutting capabilities.",
                "Continuously answer whether the process is still under control or entering a pre-deviation state."
            ]
        )

    save_json(path, data)
    print(f"PATCHED: {path}")

def html_escape(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def card(title, items):
    lis = "".join([f"<li>{html_escape(x)}</li>" for x in items])
    return f"""
    <div class="predev-capa-card">
        <div class="predev-capa-title">{html_escape(title)}</div>
        <ul>{lis}</ul>
    </div>
    """

def profile_cards(profiles):
    return "\n".join([card(name, controls) for name, controls in profiles.items()])

HTML_BLOCK = f"""
<style>
.platform-b-predev-capa-wrap {{
    margin: 28px 0;
    padding: 24px;
    border-radius: 24px;
    border: 1px solid rgba(255,255,255,.12);
    background: linear-gradient(135deg, rgba(245,158,11,.10), rgba(14,165,233,.08));
}}
.platform-b-predev-capa-wrap h2 {{
    margin: 0 0 12px 0;
    font-size: 28px;
}}
.platform-b-predev-capa-wrap p {{
    color: #cbd5e1;
    line-height: 1.65;
    max-width: 1120px;
}}
.platform-b-predev-capa-warning {{
    margin: 18px 0;
    padding: 14px 16px;
    border-radius: 14px;
    background: rgba(248,113,113,.08);
    border: 1px solid rgba(248,113,113,.18);
    color: #fecaca;
    line-height: 1.55;
    font-weight: 800;
}}
.platform-b-predev-capa-question {{
    margin: 18px 0;
    padding: 16px;
    border-radius: 16px;
    background: rgba(14,165,233,.10);
    border: 1px solid rgba(125,211,252,.22);
    color: #e0f2fe;
    font-weight: 800;
    font-size: 18px;
}}
.platform-b-predev-capa-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 16px;
}}
.predev-capa-card {{
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(255,255,255,.045);
    border-radius: 18px;
    padding: 18px;
}}
.predev-capa-card ul {{
    margin: 10px 0 0;
    padding-left: 18px;
    color: #cbd5e1;
    line-height: 1.6;
}}
.predev-capa-title {{
    color: #fde68a;
    font-weight: 800;
    letter-spacing: .04em;
    text-transform: uppercase;
    font-size: 12px;
}}
</style>

<section class="platform-b-predev-capa-wrap">
    <h2>Pre-Deviation Assurance and CAPA Effectiveness Assurance</h2>
    <p><strong>No new module, stage, or architecture.</strong> Platform B implements Pre-Deviation Signal Graph, Deviation Forecasting Window, Root Cause Confidence Score, CAPA Effectiveness Ledger, Preventive Action Firewall, Deviation Debt Register, and Quality Nervous System as cross-cutting capabilities across the existing lifecycle.</p>
    <p>{html_escape(PATCH["platform_principle"])}</p>

    <div class="platform-b-predev-capa-warning">
        These capabilities move quality assurance upstream: from deviation response to pre-deviation prevention and CAPA effectiveness verification.
    </div>

    <div class="platform-b-predev-capa-question">
        Operational Trust asks: {html_escape(PATCH["operational_trust_question"])}
    </div>

    <div class="platform-b-predev-capa-grid">
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
        "<!-- COBITCHAIN_PLATFORM_B_ADVANCED_CROSS_CUTTING_CAPABILITIES_LOCKED_LIFECYCLE_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_AI_CAPABILITY_ASSURANCE_LIBRARY_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_ASSURED_AUTONOMY_CROSS_CUTTING_CAPABILITY_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_AGENT_FAILURE_ASSURANCE_CONTROL_SET_PATCH_V1_ACTIVE -->",
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

Path("platform_b_pre_deviation_capa_effectiveness_assurance_patch_v1_summary.json").write_text(
    json.dumps(PATCH, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("platform_b_pre_deviation_capa_effectiveness_assurance_patch_v1_urls.txt").write_text(
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
print("Platform B Pre-Deviation + CAPA Effectiveness Assurance Patch completed.")
print("Marker:", PATCH_MARKER)
print("Architecture change: False")
print("New module: False")
print("New stage: False")
print("New architecture: False")
print("Locked lifecycle:", LOCKED_LIFECYCLE_SEQUENCE)
print("Operational Trust question:", PATCH["operational_trust_question"])
