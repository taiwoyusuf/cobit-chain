from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_BLUEPRINT_UX_LIFECYCLE_INTEGRATION_PATCH_V1_ACTIVE"

patch_summary = {
    "patch_marker": PATCH_MARKER,
    "patch_type": "blueprint_ux_lifecycle_integration_not_new_module",
    "architecture_change": False,
    "new_module": False,
    "new_route": False,
    "platform_rule": "No new module. No new architecture. Make the existing Blueprint Library easier to navigate, execute, and connect to the lifecycle.",
    "purpose": "Expose AI-enabled CMC Blueprint and Agentic Enterprise Blueprint inside the existing platform spine, lifecycle integration model, and route registry.",
    "blueprint_layer": {
        "layer_name": "Blueprint Library",
        "layer_type": "industry_and_enterprise_blueprints",
        "uses_existing_lifecycle": True,
        "routes": [
            "/platform/blueprints",
            "/platform/blueprints/ai-enabled-cmc",
            "/platform/blueprints/agentic-enterprise"
        ],
        "blueprints": [
            {
                "blueprint_name": "AI-enabled CMC Blueprint",
                "route": "/platform/blueprints/ai-enabled-cmc",
                "lifecycle": "Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust",
                "purpose": "Apply the existing lifecycle to AI-assisted CMC activities across literature review, hypothesis generation, formulation design, process development, regulatory authoring, manufacturing optimization, monitoring, evidence, change control, and operational trust."
            },
            {
                "blueprint_name": "Agentic Enterprise Blueprint",
                "route": "/platform/blueprints/agentic-enterprise",
                "lifecycle": "AI Discovery -> Visibility -> Governance -> Operating Model -> Operationalization -> Evidence -> Continuous Assurance -> Operational Trust",
                "purpose": "Apply the existing lifecycle to agent-supported business processes, autonomous decisions, human approvals, workflow changes, control execution, evidence generation, boundary crossings, and operational trust."
            }
        ]
    },
    "integration_question": "Can industry and enterprise blueprints be navigated, evidenced, and demonstrated through the existing lifecycle without adding new architecture?",
    "implementation_focus": [
        "Expose blueprint links in the platform command center.",
        "Expose blueprint links in the route registry.",
        "Connect Blueprint Library to lifecycle integration seed data.",
        "Connect blueprint evidence expectations to the existing Evidence stage.",
        "Preserve no-new-module rule."
    ]
}

def load_json(path):
    p = Path(path)
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))

def save_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

def add_unique_list(target, values):
    if target is None:
        target = []
    existing = set()
    result = []
    for item in target:
        key = json.dumps(item, sort_keys=True) if isinstance(item, dict) else str(item)
        if key not in existing:
            result.append(item)
            existing.add(key)
    for value in values:
        key = json.dumps(value, sort_keys=True) if isinstance(value, dict) else str(value)
        if key not in existing:
            result.append(value)
            existing.add(key)
    return result

def patch_lifecycle_seed():
    path = Path("platform_lifecycle_integration_seed.json")
    if not path.exists():
        print("SKIP: platform_lifecycle_integration_seed.json not found.")
        return False

    data = load_json(path)
    data["blueprint_ux_lifecycle_integration_patch"] = patch_summary
    data["blueprint_application_layer"] = patch_summary["blueprint_layer"]

    assessment = data.get("sample_integration_assessment", {})
    assessment["blueprint_application_layer"] = {
        "status": "BLUEPRINT_LAYER_CONNECTED_TO_EXISTING_LIFECYCLE",
        "architecture_change": False,
        "new_module": False,
        "blueprints_connected": [
            "AI-enabled CMC Blueprint",
            "Agentic Enterprise Blueprint"
        ],
        "routes_connected": [
            "/platform/blueprints",
            "/platform/blueprints/ai-enabled-cmc",
            "/platform/blueprints/agentic-enterprise"
        ],
        "integration_question": patch_summary["integration_question"]
    }

    assessment["implementation_priority"] = add_unique_list(
        assessment.get("implementation_priority", []),
        [
            "Expose Blueprint Library in the platform command center.",
            "Expose AI-enabled CMC and Agentic Enterprise blueprint routes in the route registry.",
            "Use blueprints to demonstrate existing lifecycle application without creating new top-level modules.",
            "Bind blueprint evidence expectations to the existing Evidence stage."
        ]
    )

    assessment["ux_targets"] = add_unique_list(
        assessment.get("ux_targets", []),
        [
            "Blueprint Library entry point from /platform.",
            "Blueprint route cards from /platform/routes.",
            "One-click access to AI-enabled CMC Blueprint.",
            "One-click access to Agentic Enterprise Blueprint.",
            "Clear no-new-module banner on blueprint pages."
        ]
    )

    data["sample_integration_assessment"] = assessment

    for stage in data.get("integration_flow", []) or []:
        if stage.get("stage_id") == "discovery_visibility":
            stage["blueprint_examples"] = add_unique_list(
                stage.get("blueprint_examples", []),
                [
                    "AI-enabled CMC Blueprint discovery examples",
                    "Agentic Enterprise Blueprint AI discovery examples"
                ]
            )
            stage["evidence_outputs"] = add_unique_list(
                stage.get("evidence_outputs", []),
                [
                    "Blueprint discovery mapping record",
                    "Industry blueprint visibility record",
                    "Enterprise blueprint visibility record"
                ]
            )

        if stage.get("stage_id") == "governance_operationalization":
            stage["blueprint_examples"] = add_unique_list(
                stage.get("blueprint_examples", []),
                [
                    "AI-enabled CMC governance operationalization",
                    "Agentic enterprise governance operationalization"
                ]
            )
            stage["evidence_outputs"] = add_unique_list(
                stage.get("evidence_outputs", []),
                [
                    "Blueprint governance mapping record",
                    "Blueprint control implementation record"
                ]
            )

        if stage.get("stage_id") == "evidence_contract":
            stage["blueprint_examples"] = add_unique_list(
                stage.get("blueprint_examples", []),
                [
                    "AI-enabled CMC evidence package",
                    "Agentic enterprise evidence package"
                ]
            )
            stage["evidence_outputs"] = add_unique_list(
                stage.get("evidence_outputs", []),
                [
                    "Blueprint evidence mapping record",
                    "Blueprint assurance case record",
                    "Blueprint evidence replay package"
                ]
            )

    save_json(path, data)
    print("PATCHED: platform_lifecycle_integration_seed.json")
    return True

def patch_blueprint_seed():
    path = Path("platform_blueprint_library_seed.json")
    if not path.exists():
        print("SKIP: platform_blueprint_library_seed.json not found.")
        return False

    data = load_json(path)
    data["blueprint_ux_lifecycle_integration_patch"] = patch_summary
    data["blueprint_library_status"] = {
        "architecture_change": False,
        "new_module": False,
        "new_route": False,
        "integration_status": "BLUEPRINT_LIBRARY_CONNECTED_TO_PLATFORM_SPINE",
        "implementation_focus": patch_summary["implementation_focus"]
    }

    for bp in data.get("blueprints", []) or []:
        bp["platform_spine_visibility"] = {
            "visible_from_platform": True,
            "visible_from_route_registry": True,
            "visible_from_lifecycle_integration": True,
            "architecture_change": False,
            "new_module": False
        }

        bp["existing_lifecycle_application_statement"] = (
            "This blueprint applies the existing Platform A assurance lifecycle to a specific operational domain. It does not create a new architecture or new platform capability."
        )

        bp["questions_answered"] = add_unique_list(
            bp.get("questions_answered", []),
            [
                "Which existing lifecycle stage does this blueprint demonstrate?",
                "Which evidence objects support this blueprint?",
                "Which lifecycle gaps remain open?",
                "Can this blueprint be used without creating a new architecture?"
            ]
        )

    save_json(path, data)
    print("PATCHED: platform_blueprint_library_seed.json")
    return True

def remove_marker_block(text):
    start = f"<!-- {PATCH_MARKER} -->"
    end = f"<!-- END {PATCH_MARKER} -->"
    return re.sub(re.escape(start) + r".*?" + re.escape(end), "", text, flags=re.DOTALL)

def patch_platform_html():
    path = Path("platform_ab_command_center.html")
    if not path.exists():
        print("SKIP: platform_ab_command_center.html not found.")
        return False

    text = path.read_text(encoding="utf-8")
    text = remove_marker_block(text)

    block = r'''
<!-- COBITCHAIN_BLUEPRINT_UX_LIFECYCLE_INTEGRATION_PATCH_V1_ACTIVE -->
<section class="section">
    <div class="section-head">
        <div>
            <h2>Blueprint Library</h2>
            <p>Blueprints demonstrate how the existing assurance lifecycle applies to specific operating domains. They do not create new architecture, new modules, or new foundational platform capabilities.</p>
        </div>
        <span class="tag">Blueprint layer</span>
    </div>

    <div class="grid-4">
        <a class="card" href="/platform/blueprints"><strong>Blueprint Library</strong><span>Entry point for industry and enterprise blueprints that reuse the existing lifecycle.</span><small>Open library</small></a>
        <a class="card" href="/platform/blueprints/ai-enabled-cmc"><strong>AI-enabled CMC Blueprint</strong><span>Applies the lifecycle to AI-assisted literature review, hypothesis generation, formulation design, process development, regulatory authoring, manufacturing optimization, evidence, monitoring, and operational trust.</span><small>Open blueprint</small></a>
        <a class="card" href="/platform/blueprints/agentic-enterprise"><strong>Agentic Enterprise Blueprint</strong><span>Applies the lifecycle to agents, business processes, autonomous decisions, human approvals, workflow changes, control execution, evidence, and operational trust.</span><small>Open blueprint</small></a>
        <a class="card" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Connects blueprint examples back to the executable lifecycle, evidence automation, route status, and operational workflow integration.</span><small>Open integration</small></a>
    </div>
</section>
<!-- END COBITCHAIN_BLUEPRINT_UX_LIFECYCLE_INTEGRATION_PATCH_V1_ACTIVE -->
'''

    anchor = '<div class="footer">'
    if anchor in text:
        text = text.replace(anchor, block + "\n\n" + anchor, 1)
    else:
        text = text.replace("</body>", block + "\n</body>", 1)

    path.write_text(text, encoding="utf-8")
    print("PATCHED: platform_ab_command_center.html")
    return True

def patch_route_registry_html():
    path = Path("platform_route_registry_command_center.html")
    if not path.exists():
        print("SKIP: platform_route_registry_command_center.html not found.")
        return False

    text = path.read_text(encoding="utf-8")
    text = remove_marker_block(text)

    block = r'''
<!-- COBITCHAIN_BLUEPRINT_UX_LIFECYCLE_INTEGRATION_PATCH_V1_ACTIVE -->
<section class="section">
    <div class="section-head">
        <div>
            <h2>Blueprint Library Routes</h2>
            <p>These routes expose blueprints that reuse the existing Platform A lifecycle. They are not new modules and do not introduce architecture changes.</p>
        </div>
        <span class="tag">Blueprint routes</span>
    </div>
    <div class="route-grid">
        <a class="route" href="/platform/blueprints"><strong>Blueprint Library</strong><span>Central library for industry and enterprise blueprints that demonstrate lifecycle application.</span><code>/platform/blueprints</code></a>
        <a class="route" href="/platform/blueprints/ai-enabled-cmc"><strong>AI-enabled CMC Blueprint</strong><span>CMC blueprint covering discovery, visibility, governance, operationalization, manufacturing monitoring, evidence, continuous assurance, and operational trust.</span><code>/platform/blueprints/ai-enabled-cmc</code></a>
        <a class="route" href="/platform/blueprints/agentic-enterprise"><strong>Agentic Enterprise Blueprint</strong><span>Enterprise blueprint covering AI discovery, visibility, governance, operating model, operationalization, evidence, continuous assurance, and operational trust.</span><code>/platform/blueprints/agentic-enterprise</code></a>
        <a class="route" href="/api/platform/blueprints/model/demo"><strong>Blueprint Library API</strong><span>Returns the blueprint library model, blueprint states, lifecycle mappings, and no-new-architecture validation.</span><code>/api/platform/blueprints/model/demo</code></a>
    </div>
</section>
<!-- END COBITCHAIN_BLUEPRINT_UX_LIFECYCLE_INTEGRATION_PATCH_V1_ACTIVE -->
'''

    anchor = '<div class="footer">'
    if anchor in text:
        text = text.replace(anchor, block + "\n\n" + anchor, 1)
    else:
        text = text.replace("</body>", block + "\n</body>", 1)

    path.write_text(text, encoding="utf-8")
    print("PATCHED: platform_route_registry_command_center.html")
    return True

patch_lifecycle_seed()
patch_blueprint_seed()
patch_platform_html()
patch_route_registry_html()

Path("blueprint_ux_lifecycle_integration_patch_v1_summary.json").write_text(
    json.dumps(patch_summary, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("blueprint_ux_lifecycle_integration_patch_v1_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform",
        "http://127.0.0.1:5000/platform/routes",
        "http://127.0.0.1:5000/platform/blueprints",
        "http://127.0.0.1:5000/platform/blueprints/ai-enabled-cmc",
        "http://127.0.0.1:5000/platform/blueprints/agentic-enterprise",
        "http://127.0.0.1:5000/platform/lifecycle-integration",
        "http://127.0.0.1:5000/api/platform/blueprints/model/demo",
        "http://127.0.0.1:5000/api/platform/lifecycle-integration/model/demo"
    ]),
    encoding="utf-8"
)

print("")
print("Blueprint UX + Lifecycle Integration Patch completed.")
print("Marker:")
print("  " + PATCH_MARKER)
print("No new module. No new route. No architecture change.")
