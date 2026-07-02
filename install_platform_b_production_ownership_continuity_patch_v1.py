from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_PLATFORM_B_PRODUCTION_OWNERSHIP_CONTINUITY_PATCH_V1_ACTIVE"
LIFECYCLE_SEQUENCE = "Discovery -> Visibility -> Governance -> Operationalization -> Execution Assurance -> Evidence -> Continuous Assurance -> Operational Trust"

OWNERSHIP_CONTINUITY = {
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "architecture_instruction": "Do not change Platform B architecture. Deepen existing Governance, Operationalization, and Continuous Assurance capabilities only.",
    "capability_name": "Production Ownership Continuity Assurance",
    "capability_layer": ["Governance", "Operationalization", "Continuous Assurance"],
    "lifecycle_sequence": LIFECYCLE_SEQUENCE,
    "core_question": "Who owns this AI after the demonstration ends?",
    "production_question": "Is ownership continuous from pilot through production operations?",
    "continuous_assurance_question": "Are ownership gaps, support gaps, adoption gaps, and platform accountability gaps being detected after go-live?",
    "ownership_domains": [
        {
            "domain": "Business Ownership",
            "question": "Who owns the business outcome the AI is supposed to improve?",
            "evidence": [
                "Business owner assigned",
                "Business problem approved",
                "Success KPI approved",
                "Business value attestation",
                "Post-go-live decision accountability"
            ]
        },
        {
            "domain": "Support Ownership",
            "question": "Who supports the AI when production users need help?",
            "evidence": [
                "Support owner assigned",
                "Support group identified",
                "Runbook available",
                "Incident path defined",
                "Escalation path defined",
                "SLA or response expectation defined"
            ]
        },
        {
            "domain": "Adoption Ownership",
            "question": "Who is accountable for business adoption after deployment?",
            "evidence": [
                "Adoption owner assigned",
                "Training plan available",
                "Usage monitoring enabled",
                "Adoption target defined",
                "User feedback loop active"
            ]
        },
        {
            "domain": "Platform Ownership",
            "question": "Who owns the platform services the AI depends on?",
            "evidence": [
                "Platform owner assigned",
                "Integration owner identified",
                "Data owner identified",
                "Security owner identified",
                "Monitoring owner identified",
                "Lifecycle owner identified"
            ]
        },
        {
            "domain": "Governance Continuity",
            "question": "Does governance continue after the pilot team leaves?",
            "evidence": [
                "Pilot-to-production handoff completed",
                "Production approval recorded",
                "Change control path defined",
                "Periodic review cadence defined",
                "Exception ownership defined",
                "Retirement owner identified"
            ]
        }
    ],
    "ownership_gap_signals": [
        "Business owner missing",
        "Support owner missing",
        "Adoption owner missing",
        "Platform owner missing",
        "Data owner missing",
        "Integration owner missing",
        "Security owner missing",
        "No production runbook",
        "No support escalation path",
        "No post-go-live review cadence",
        "Pilot team remains only owner",
        "Ownership changed without evidence",
        "KPI owner missing",
        "Incident owner missing",
        "Retirement owner missing"
    ],
    "evidence_objects": [
        "Business owner assignment",
        "Support owner assignment",
        "Adoption owner assignment",
        "Platform owner assignment",
        "Data owner assignment",
        "Integration owner assignment",
        "Security owner assignment",
        "Lifecycle owner assignment",
        "Pilot-to-production handoff record",
        "Production accountability matrix",
        "Operational support model",
        "Runbook",
        "Escalation path",
        "Training and adoption plan",
        "Post-go-live review record",
        "Ownership change history",
        "Business KPI ownership record",
        "Incident ownership record",
        "Retirement ownership record"
    ],
    "positioning_statement": "Platform B should not treat a demo owner as a production owner. It must prove that business, support, adoption, platform, data, integration, security, lifecycle, incident, KPI, and retirement ownership continue after the AI capability enters production.",
    "principle": "AI ownership is not proven by naming a sponsor for a pilot. It is proven by continuous accountability across business value, support, adoption, platform operation, incidents, changes, KPIs, and retirement."
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

    data["platform_b_production_ownership_continuity_patch"] = OWNERSHIP_CONTINUITY
    data["platform_b_architecture_change"] = False
    data["platform_b_lifecycle_sequence"] = LIFECYCLE_SEQUENCE

    if "blueprints" in data and isinstance(data["blueprints"], list):
        for bp in data["blueprints"]:
            if not isinstance(bp, dict):
                continue

            bp["architecture_change"] = False
            bp["production_ownership_continuity_assurance"] = OWNERSHIP_CONTINUITY
            bp["questions_answered"] = add_unique(
                bp.get("questions_answered", []),
                [
                    "Who owns this AI after the demonstration ends?",
                    "Is ownership continuous from pilot through production operations?",
                    "Are ownership gaps, support gaps, adoption gaps, and platform accountability gaps being detected after go-live?"
                ]
            )

            assessment = bp.get("sample_blueprint_assessment", {})
            if not isinstance(assessment, dict):
                assessment = {}

            assessment["production_ownership_continuity_state"] = "OWNERSHIP_CONTINUITY_REQUIRED_FROM_PILOT_TO_PRODUCTION"
            assessment["architecture_change"] = False
            assessment["business_owner_required"] = True
            assessment["support_owner_required"] = True
            assessment["adoption_owner_required"] = True
            assessment["platform_owner_required"] = True
            assessment["data_owner_required"] = True
            assessment["integration_owner_required"] = True
            assessment["security_owner_required"] = True
            assessment["lifecycle_owner_required"] = True
            assessment["runbook_required"] = True
            assessment["escalation_path_required"] = True
            assessment["post_go_live_review_required"] = True
            bp["sample_blueprint_assessment"] = assessment

    if "sample_integration_assessment" in data and isinstance(data["sample_integration_assessment"], dict):
        assessment = data["sample_integration_assessment"]
        assessment["production_ownership_continuity_state"] = "ACTIVE"
        assessment["architecture_change"] = False
        assessment["production_ownership_continuity_assurance"] = OWNERSHIP_CONTINUITY
        assessment["evidence_automation_targets"] = add_unique(
            assessment.get("evidence_automation_targets", []),
            OWNERSHIP_CONTINUITY["evidence_objects"]
        )
        assessment["continuous_monitoring_targets"] = add_unique(
            assessment.get("continuous_monitoring_targets", []),
            OWNERSHIP_CONTINUITY["ownership_gap_signals"]
        )
        assessment["implementation_priority"] = add_unique(
            assessment.get("implementation_priority", []),
            [
                "Assign production business owner before go-live.",
                "Assign support owner and support group before production deployment.",
                "Assign adoption owner and adoption target before release.",
                "Assign platform, data, integration, security, and lifecycle owners.",
                "Create runbook and escalation path before operational handoff.",
                "Monitor ownership gaps after go-live."
            ]
        )

    save_json(path, data)
    print(f"PATCHED: {path}")

def html_escape(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def ownership_cards():
    cards = []
    for item in OWNERSHIP_CONTINUITY["ownership_domains"]:
        evidence = "".join([f"<li>{html_escape(x)}</li>" for x in item["evidence"]])
        cards.append(f"""
        <div class="ownership-card">
            <div class="ownership-domain">{html_escape(item["domain"])}</div>
            <h3>{html_escape(item["question"])}</h3>
            <ul>{evidence}</ul>
        </div>
        """)
    return "\n".join(cards)

HTML_BLOCK = f"""
<style>
.platform-b-ownership-wrap {{
    margin: 28px 0;
    padding: 24px;
    border-radius: 24px;
    border: 1px solid rgba(255,255,255,.12);
    background: linear-gradient(135deg, rgba(99,102,241,.11), rgba(255,122,24,.08));
}}
.platform-b-ownership-head {{
    display: flex;
    justify-content: space-between;
    gap: 18px;
    align-items: flex-start;
    margin-bottom: 18px;
}}
.platform-b-ownership-head h2 {{
    margin: 0;
    font-size: 28px;
}}
.platform-b-ownership-head p {{
    color: #cbd5e1;
    line-height: 1.65;
    max-width: 980px;
}}
.platform-b-ownership-tag {{
    border: 1px solid rgba(165,180,252,.45);
    color: #c4b5fd;
    border-radius: 999px;
    padding: 8px 12px;
    font-size: 12px;
    white-space: nowrap;
    background: rgba(99,102,241,.10);
}}
.platform-b-ownership-principle {{
    margin: 18px 0;
    padding: 16px;
    border-left: 4px solid #c4b5fd;
    color: #e5e7eb;
    background: rgba(255,255,255,.045);
    border-radius: 14px;
    line-height: 1.6;
}}
.platform-b-ownership-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(270px, 1fr));
    gap: 16px;
}}
.ownership-card {{
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(255,255,255,.045);
    border-radius: 18px;
    padding: 18px;
}}
.ownership-card h3 {{
    margin: 8px 0 12px;
    color: #fff;
    font-size: 16px;
    line-height: 1.35;
}}
.ownership-card ul {{
    margin: 0;
    padding-left: 18px;
    color: #cbd5e1;
    line-height: 1.6;
}}
.ownership-domain {{
    color: #c4b5fd;
    font-weight: 800;
    letter-spacing: .04em;
    text-transform: uppercase;
    font-size: 12px;
}}
.platform-b-ownership-signals {{
    margin-top: 18px;
    display: flex;
    flex-wrap: wrap;
    gap: 9px;
}}
.platform-b-ownership-signal {{
    border: 1px solid rgba(255,255,255,.12);
    background: rgba(255,255,255,.045);
    border-radius: 999px;
    padding: 8px 12px;
    color: #d8dee9;
    font-size: 13px;
}}
</style>

<section class="platform-b-ownership-wrap">
    <div class="platform-b-ownership-head">
        <div>
            <h2>Production Ownership Continuity Assurance</h2>
            <p>
                No architecture change. This deepens the existing Governance, Operationalization, and Continuous Assurance
                layers by proving that ownership does not stop at the pilot or demonstration stage. Platform B now checks
                business, support, adoption, platform, data, integration, security, lifecycle, KPI, incident, and retirement
                ownership after production deployment.
            </p>
        </div>
        <span class="platform-b-ownership-tag">Governance + Operationalization + Continuous Assurance</span>
    </div>
    <div class="platform-b-ownership-principle">
        {html_escape(OWNERSHIP_CONTINUITY["principle"])}
    </div>
    <div class="platform-b-ownership-grid">
        {ownership_cards()}
    </div>
    <div class="platform-b-ownership-signals">
        {"".join([f'<span class="platform-b-ownership-signal">{html_escape(x)}</span>' for x in OWNERSHIP_CONTINUITY["ownership_gap_signals"]])}
    </div>
</section>
"""

def remove_old_block(text):
    start = f"<!-- {PATCH_MARKER} -->"
    end = f"<!-- END {PATCH_MARKER} -->"
    return re.sub(re.escape(start) + r".*?" + re.escape(end), "", text, flags=re.DOTALL)

def patch_html(path):
    p = Path(path)
    if not p.exists():
        print(f"SKIP: {path}")
        return

    text = p.read_text(encoding="utf-8-sig")
    text = remove_old_block(text)
    wrapped = f"\n<!-- {PATCH_MARKER} -->\n{HTML_BLOCK}\n<!-- END {PATCH_MARKER} -->\n"

    anchors = [
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

    lines = text.splitlines(keepends=True)
    cleaned = []
    for line in lines:
        if line.endswith("\r\n"):
            cleaned.append(line[:-2].rstrip(" \t") + "\r\n")
        elif line.endswith("\n"):
            cleaned.append(line[:-1].rstrip(" \t") + "\n")
        else:
            cleaned.append(line.rstrip(" \t"))

    p.write_text("".join(cleaned), encoding="utf-8")
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

Path("platform_b_production_ownership_continuity_patch_v1_summary.json").write_text(
    json.dumps(OWNERSHIP_CONTINUITY, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("platform_b_production_ownership_continuity_patch_v1_urls.txt").write_text(
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
print("Platform B Production Ownership Continuity Assurance Patch completed.")
print("Marker:", PATCH_MARKER)
print("Architecture change: False")
print("Lifecycle:", LIFECYCLE_SEQUENCE)
