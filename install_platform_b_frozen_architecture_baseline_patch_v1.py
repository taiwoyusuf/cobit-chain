from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_PLATFORM_B_FROZEN_ARCHITECTURE_BASELINE_PATCH_V1_ACTIVE"

permanent_lifecycle = [
    "Discovery",
    "Visibility",
    "Governance",
    "Operationalization",
    "Manufacturing Monitoring",
    "Evidence",
    "Continuous Assurance",
    "Operational Trust"
]

build_rules = [
    "Do not create new modules.",
    "Do not create new stages.",
    "Do not create new pillars.",
    "Do not create new lifecycle phases.",
    "Do not create new architectures.",
    "Do not create new foundational concepts.",
    "Do not insert stages.",
    "Do not rename stages.",
    "Do not reorganize the lifecycle.",
    "Every future enhancement must strengthen one or more existing stages only."
]

stage_strengthening_catalog = {
    "Discovery": [
        "AI systems",
        "AI models",
        "AI agents",
        "MCP servers",
        "A2A connections",
        "AI tools",
        "Digital twins",
        "Data products",
        "AI ownership",
        "Intended use",
        "Risk classification"
    ],
    "Visibility": [
        "AI asset visibility",
        "Runtime visibility",
        "Workflow visibility",
        "Cross-agent observability",
        "Cross-model observability",
        "Telemetry",
        "Execution visibility",
        "Dependency visibility"
    ],
    "Governance": [
        "Infrastructure governance",
        "Data governance",
        "Model governance",
        "Identity governance",
        "Risk governance",
        "Compliance governance",
        "Policy governance",
        "Executive governance",
        "Inventories",
        "Permissions",
        "Observability",
        "Telemetry",
        "Policy enforcement"
    ],
    "Operationalization": [
        "AI Control Towers",
        "Agent orchestration",
        "MCP",
        "A2A",
        "Multi-model execution",
        "Workflow orchestration",
        "Human approval",
        "Runtime policy enforcement"
    ],
    "Manufacturing Monitoring": [
        "Agent monitoring",
        "Model monitoring",
        "Workflow monitoring",
        "Runtime telemetry",
        "Decision monitoring",
        "Execution monitoring"
    ],
    "Evidence": [
        "Which AI acted?",
        "Which model?",
        "Which workflow?",
        "Which tool?",
        "Which policy?",
        "Which evidence?",
        "Which approval?",
        "Which outcome?"
    ],
    "Continuous Assurance": [
        "Runtime trust",
        "Evidence integrity",
        "Policy compliance",
        "Agent behavior",
        "Operational assurance",
        "Trust reconstruction"
    ],
    "Operational Trust": [
        "Outcome of the entire lifecycle",
        "Do not expand beyond this outcome role"
    ]
}

baseline = {
    "patch_marker": PATCH_MARKER,
    "baseline_name": "Platform B Frozen Architecture Baseline",
    "architecture_status": "FROZEN",
    "architecture_change": False,
    "new_module": False,
    "new_route": False,
    "lifecycle_change": False,
    "stage_rename_allowed": False,
    "stage_insertion_allowed": False,
    "lifecycle_reorganization_allowed": False,
    "permanent_lifecycle": permanent_lifecycle,
    "permanent_lifecycle_sequence": "Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust",
    "build_rules": build_rules,
    "stage_strengthening_catalog": stage_strengthening_catalog,
    "platform_positioning": {
        "control_tower_statement": "Enterprise AI is converging around governance control towers.",
        "assurance_engineering_statement": "Assurance Engineering complements those control towers by continuously demonstrating that AI-enabled operations remain trustworthy throughout their lifecycle.",
        "operating_distinction": "Control towers manage AI. Assurance Engineering demonstrates trust."
    },
    "operational_trust_rule": "Operational Trust is the outcome of the entire lifecycle.",
    "future_build_rule": "Future enhancements must strengthen existing lifecycle stages only."
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

def normalized_stage_name(name):
    if not name:
        return ""
    n = str(name).strip()
    if n in stage_strengthening_catalog:
        return n
    if "Discovery" in n:
        return "Discovery"
    if "Visibility" in n:
        return "Visibility"
    if "Governance" in n:
        return "Governance"
    if "Operationalization" in n:
        return "Operationalization"
    if "Manufacturing Monitoring" in n or "Monitoring" in n:
        return "Manufacturing Monitoring"
    if "Evidence" in n:
        return "Evidence"
    if "Continuous Assurance" in n or "Assurance" in n:
        return "Continuous Assurance"
    if "Operational Trust" in n or "Trust" in n:
        return "Operational Trust"
    return ""

def patch_blueprint_seed():
    path = Path("platform_blueprint_library_seed.json")
    if not path.exists():
        print("SKIP: platform_blueprint_library_seed.json not found.")
        return False

    data = load_json(path)
    data["platform_b_frozen_architecture_baseline"] = baseline

    for bp in data.get("blueprints", []) or []:
        bp["platform_b_frozen_architecture_baseline"] = {
            "architecture_status": "FROZEN",
            "architecture_change": False,
            "new_module": False,
            "new_route": False,
            "lifecycle_change": False,
            "permanent_lifecycle": permanent_lifecycle,
            "future_enhancements_must_strengthen_existing_stages_only": True,
            "stage_rename_allowed": False,
            "stage_insertion_allowed": False,
            "lifecycle_reorganization_allowed": False
        }

        bp["questions_answered"] = add_unique_list(
            bp.get("questions_answered", []),
            [
                "Which existing lifecycle stage does this enhancement strengthen?",
                "Does this enhancement avoid creating a new module?",
                "Does this enhancement preserve the frozen lifecycle sequence?",
                "Does this enhancement strengthen Discovery, Visibility, Governance, Operationalization, Manufacturing Monitoring, Evidence, Continuous Assurance, or Operational Trust?",
                "Does Operational Trust remain the outcome of the lifecycle?"
            ]
        )

        assessment = bp.get("sample_blueprint_assessment", {})
        assessment["platform_b_frozen_architecture_state"] = "FROZEN_BASELINE_APPLIED"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["new_route"] = False
        assessment["lifecycle_change"] = False
        assessment["permanent_lifecycle_sequence"] = baseline["permanent_lifecycle_sequence"]
        assessment["future_build_rule"] = baseline["future_build_rule"]
        assessment["operational_trust_rule"] = baseline["operational_trust_rule"]
        bp["sample_blueprint_assessment"] = assessment

        for stage in bp.get("lifecycle", []) or []:
            stage_name = normalized_stage_name(stage.get("stage_name", ""))
            if stage_name:
                stage["platform_b_frozen_stage_guidance"] = {
                    "stage_name": stage_name,
                    "do_not_rename_stage": True,
                    "do_not_insert_new_stage": True,
                    "strengthen_existing_stage_only": True,
                    "strengthening_scope": stage_strengthening_catalog.get(stage_name, [])
                }

                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    [
                        f"{stage_name} strengthening record",
                        f"{stage_name} baseline alignment record"
                    ]
                )

                if stage_name == "Operational Trust":
                    stage["operational_trust_outcome_rule"] = "Operational Trust is the outcome of the entire lifecycle and should not expand beyond this outcome role."

    save_json(path, data)
    print("PATCHED: platform_blueprint_library_seed.json")
    return True

def patch_lifecycle_seed():
    path = Path("platform_lifecycle_integration_seed.json")
    if not path.exists():
        print("SKIP: platform_lifecycle_integration_seed.json not found.")
        return False

    data = load_json(path)
    data["platform_b_frozen_architecture_baseline"] = baseline

    assessment = data.get("sample_integration_assessment", {})
    assessment["platform_b_frozen_architecture_baseline"] = {
        "state": "FROZEN_BASELINE_APPLIED",
        "architecture_change": False,
        "new_module": False,
        "new_route": False,
        "lifecycle_change": False,
        "permanent_lifecycle": permanent_lifecycle,
        "permanent_lifecycle_sequence": baseline["permanent_lifecycle_sequence"],
        "future_build_rule": baseline["future_build_rule"],
        "operational_trust_rule": baseline["operational_trust_rule"]
    }

    assessment["implementation_priority"] = add_unique_list(
        assessment.get("implementation_priority", []),
        [
            "Strengthen existing lifecycle stages only.",
            "Do not create new modules, stages, pillars, lifecycle phases, architectures, or foundational concepts.",
            "Preserve Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust.",
            "Treat Operational Trust as the outcome of the full lifecycle."
        ]
    )

    assessment["evidence_automation_targets"] = add_unique_list(
        assessment.get("evidence_automation_targets", []),
        [
            "Stage strengthening evidence binder",
            "Frozen lifecycle alignment checker",
            "No-new-module compliance record",
            "Operational Trust outcome evidence binder"
        ]
    )

    data["sample_integration_assessment"] = assessment

    for stage in data.get("integration_flow", []) or []:
        stage["platform_b_frozen_architecture_guardrail"] = {
            "architecture_status": "FROZEN",
            "new_module_allowed": False,
            "new_stage_allowed": False,
            "lifecycle_change_allowed": False,
            "strengthen_existing_stage_only": True
        }

        stage_name = normalized_stage_name(stage.get("stage_name", "")) or normalized_stage_name(stage.get("stage_id", ""))
        if stage_name:
            stage["platform_b_stage_strengthening_scope"] = stage_strengthening_catalog.get(stage_name, [])
            stage["evidence_outputs"] = add_unique_list(
                stage.get("evidence_outputs", []),
                [
                    f"{stage_name} strengthening evidence",
                    f"{stage_name} frozen baseline alignment evidence"
                ]
            )

    save_json(path, data)
    print("PATCHED: platform_lifecycle_integration_seed.json")
    return True

def remove_marker_block(text):
    start = f"<!-- {PATCH_MARKER} -->"
    end = f"<!-- END {PATCH_MARKER} -->"
    return re.sub(re.escape(start) + r".*?" + re.escape(end), "", text, flags=re.DOTALL)

def patch_html(path, block, anchor):
    p = Path(path)
    if not p.exists():
        print(f"SKIP: {path} not found.")
        return False

    text = p.read_text(encoding="utf-8")
    text = remove_marker_block(text)

    wrapped = f"\n<!-- {PATCH_MARKER} -->\n{block}\n<!-- END {PATCH_MARKER} -->\n"

    if anchor in text:
        text = text.replace(anchor, wrapped + "\n" + anchor, 1)
    else:
        text = text.replace("</body>", wrapped + "\n</body>", 1)

    p.write_text(text, encoding="utf-8")
    print(f"PATCHED: {path}")
    return True

blueprint_block = r'''
<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">Platform B Architecture Frozen</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                The Platform B architecture is now the permanent baseline. Future enhancements must strengthen existing stages only. No new modules, stages, pillars, lifecycle phases, architectures, or foundational concepts are allowed.
            </div>
        </div>
        <span class="tag">Frozen baseline</span>
    </div>
    <div class="grid">
        <div class="panel"><strong>Permanent Lifecycle</strong><div>Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust</div></div>
        <div class="panel"><strong>Build Rule</strong><div>Every future enhancement must strengthen one or more existing stages. Never insert stages, rename stages, or reorganize the lifecycle.</div></div>
        <div class="panel"><strong>Operational Trust</strong><div>Operational Trust remains the outcome of the entire lifecycle and should not expand beyond this outcome role.</div></div>
    </div>
</section>
'''

platform_block = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>Platform B Frozen Architecture Baseline</h2>
            <p>The architecture is frozen. The permanent lifecycle is Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust. Future work must strengthen existing stages only. No new modules, stages, pillars, lifecycle phases, architectures, or foundational concepts.</p>
        </div>
        <span class="tag">Architecture frozen</span>
    </div>
    <div class="grid-4">
        <a class="card" href="/platform/blueprints/ai-enabled-cmc"><strong>AI-enabled CMC Blueprint</strong><span>Uses the frozen lifecycle and may only be strengthened through existing stages.</span><small>Open blueprint</small></a>
        <a class="card" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Maintains the permanent stage sequence and future build guardrails.</span><small>Open lifecycle</small></a>
        <a class="card" href="/platform/evidence-packages"><strong>Evidence</strong><span>Every execution should answer which AI, model, workflow, tool, policy, evidence, approval, and outcome were involved.</span><small>Open evidence</small></a>
        <a class="card" href="/platform/routes"><strong>Route Registry</strong><span>Existing routes remain; future work strengthens current lifecycle stages only.</span><small>Open routes</small></a>
    </div>
</section>
'''

library_block = r'''
<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">Frozen Baseline for All Blueprints</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Blueprints are examples of the existing lifecycle. They do not create new architecture. Future blueprint enhancements must strengthen Discovery, Visibility, Governance, Operationalization, Manufacturing Monitoring, Evidence, Continuous Assurance, or Operational Trust only.
            </div>
        </div>
        <span class="tag">Blueprint guardrail</span>
    </div>
</section>
'''

route_registry_block = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>Platform B Frozen Architecture Guardrail</h2>
            <p>The route registry remains inside the current architecture. Do not create new modules or new stage routes. Future route work should expose or improve existing lifecycle stages only.</p>
        </div>
        <span class="tag">No new modules</span>
    </div>
    <div class="route-grid">
        <a class="route" href="/platform"><strong>Platform Command Center</strong><span>Displays the frozen Platform B lifecycle and future build rules.</span><code>/platform</code></a>
        <a class="route" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Preserves Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust.</span><code>/platform/lifecycle-integration</code></a>
        <a class="route" href="/platform/blueprints/ai-enabled-cmc"><strong>AI-enabled CMC Blueprint</strong><span>Strengthens existing stages only; no new module or architecture change.</span><code>/platform/blueprints/ai-enabled-cmc</code></a>
        <a class="route" href="/api/platform/lifecycle-integration/model/demo"><strong>Lifecycle API</strong><span>Returns frozen baseline guardrails through the existing lifecycle API.</span><code>/api/platform/lifecycle-integration/model/demo</code></a>
    </div>
</section>
'''

patch_blueprint_seed()
patch_lifecycle_seed()

patch_html(
    "platform_ai_enabled_cmc_blueprint.html",
    blueprint_block,
    "<div class=\"footer\">"
)

patch_html(
    "platform_agentic_enterprise_blueprint.html",
    blueprint_block,
    "<div class=\"footer\">"
)

patch_html(
    "platform_blueprint_library.html",
    library_block,
    "<div class=\"footer\">"
)

patch_html(
    "platform_ab_command_center.html",
    platform_block,
    "<div class=\"footer\">"
)

patch_html(
    "platform_route_registry_command_center.html",
    route_registry_block,
    "<div class=\"footer\">"
)

Path("platform_b_frozen_architecture_baseline_patch_v1_summary.json").write_text(
    json.dumps(baseline, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("platform_b_frozen_architecture_baseline_patch_v1_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform",
        "http://127.0.0.1:5000/platform/routes",
        "http://127.0.0.1:5000/platform/blueprints",
        "http://127.0.0.1:5000/platform/blueprints/ai-enabled-cmc",
        "http://127.0.0.1:5000/platform/blueprints/agentic-enterprise",
        "http://127.0.0.1:5000/platform/lifecycle-integration",
        "http://127.0.0.1:5000/api/platform/blueprints/model/demo",
        "http://127.0.0.1:5000/api/platform/blueprints/ai-enabled-cmc/demo",
        "http://127.0.0.1:5000/api/platform/lifecycle-integration/model/demo"
    ]),
    encoding="utf-8"
)

print("")
print("Platform B Frozen Architecture Baseline Patch completed.")
print("Marker:")
print("  " + PATCH_MARKER)
print("Architecture frozen. No new module. No new route. Lifecycle unchanged.")
