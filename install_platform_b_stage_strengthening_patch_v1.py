from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_PLATFORM_B_STAGE_STRENGTHENING_PATCH_V1_ACTIVE"

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

stage_enrichment = {
    "Discovery": {
        "stage_rule": "Strengthen Discovery by expanding complete enterprise AI inventory coverage.",
        "explicitly_includes": [
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
        "stage_question": "Have all AI systems, models, agents, MCP servers, A2A connections, tools, digital twins, data products, owners, intended uses, and risk classifications been discovered?",
        "evidence_outputs": [
            "AI system inventory record",
            "AI model inventory record",
            "AI agent inventory record",
            "MCP server inventory record",
            "A2A connection inventory record",
            "AI tool inventory record",
            "Digital twin inventory record",
            "Data product inventory record",
            "AI ownership record",
            "Intended-use record",
            "Risk classification record"
        ]
    },
    "Visibility": {
        "stage_rule": "Strengthen Visibility by expanding observability, telemetry, runtime, workflow, execution, and dependency visibility.",
        "explicitly_includes": [
            "AI asset visibility",
            "Runtime visibility",
            "Workflow visibility",
            "Cross-agent observability",
            "Cross-model observability",
            "Telemetry",
            "Execution visibility",
            "Dependency visibility"
        ],
        "stage_question": "Can AI assets, runtimes, workflows, agents, models, telemetry, execution paths, and dependencies be observed across the enterprise?",
        "evidence_outputs": [
            "AI asset visibility record",
            "Runtime visibility record",
            "Workflow visibility record",
            "Cross-agent observability record",
            "Cross-model observability record",
            "Telemetry record",
            "Execution visibility record",
            "Dependency visibility record"
        ]
    },
    "Governance": {
        "stage_rule": "Strengthen Governance as the coordination layer for enterprise AI governance domains.",
        "explicitly_coordinates": [
            "Infrastructure governance",
            "Data governance",
            "Model governance",
            "Identity governance",
            "Risk governance",
            "Compliance governance",
            "Policy governance",
            "Executive governance"
        ],
        "uses": [
            "Inventories",
            "Permissions",
            "Observability",
            "Telemetry",
            "Policy enforcement"
        ],
        "stage_question": "Are infrastructure, data, model, identity, risk, compliance, policy, and executive governance coordinated using inventories, permissions, observability, telemetry, and policy enforcement?",
        "evidence_outputs": [
            "Infrastructure governance coordination record",
            "Data governance coordination record",
            "Model governance coordination record",
            "Identity governance coordination record",
            "Risk governance coordination record",
            "Compliance governance coordination record",
            "Policy governance coordination record",
            "Executive governance coordination record",
            "Inventory-to-governance mapping record",
            "Permission-to-policy mapping record",
            "Observability-to-governance record",
            "Telemetry-to-governance record",
            "Policy enforcement record"
        ]
    },
    "Operationalization": {
        "stage_rule": "Strengthen Operationalization with implementation examples only.",
        "explicitly_includes": [
            "AI Control Towers",
            "Agent orchestration",
            "MCP",
            "A2A",
            "Multi-model execution",
            "Workflow orchestration",
            "Human approval",
            "Runtime policy enforcement",
            "Enterprise workflow execution"
        ],
        "stage_question": "Are AI Control Towers, agent orchestration, MCP, A2A, multi-model execution, workflow orchestration, human approval, runtime policy enforcement, and enterprise workflow execution governed before operation?",
        "evidence_outputs": [
            "AI Control Tower integration record",
            "Agent orchestration record",
            "MCP execution record",
            "A2A execution record",
            "Multi-model execution record",
            "Workflow orchestration record",
            "Human approval record",
            "Runtime policy enforcement record",
            "Enterprise workflow execution record"
        ]
    },
    "Manufacturing Monitoring": {
        "stage_rule": "Strengthen Manufacturing Monitoring with runtime and execution monitoring.",
        "explicitly_includes": [
            "Agent monitoring",
            "Model monitoring",
            "Workflow monitoring",
            "Runtime telemetry",
            "Decision monitoring",
            "Execution monitoring",
            "Cross-agent monitoring",
            "Cross-model monitoring"
        ],
        "stage_question": "Are agents, models, workflows, runtime telemetry, decisions, executions, cross-agent behavior, and cross-model behavior monitored?",
        "evidence_outputs": [
            "Agent monitoring record",
            "Model monitoring record",
            "Workflow monitoring record",
            "Runtime telemetry record",
            "Decision monitoring record",
            "Execution monitoring record",
            "Cross-agent monitoring record",
            "Cross-model monitoring record"
        ]
    },
    "Evidence": {
        "stage_rule": "Strengthen Evidence so every execution can be reconstructed.",
        "execution_questions": [
            "Which AI acted?",
            "Which model?",
            "Which workflow?",
            "Which tool?",
            "Which policy?",
            "Which evidence?",
            "Which approval?",
            "Which outcome?"
        ],
        "stage_question": "Can every execution answer which AI acted, which model was used, which workflow executed, which tool was called, which policy approved execution, which evidence was generated, which approval occurred, and which outcome resulted?",
        "evidence_outputs": [
            "AI actor evidence record",
            "Model execution evidence record",
            "Workflow execution evidence record",
            "Tool-call evidence record",
            "Policy approval evidence record",
            "Generated evidence record",
            "Approval evidence record",
            "Outcome evidence record",
            "Execution reconstruction package"
        ]
    },
    "Continuous Assurance": {
        "stage_rule": "Strengthen Continuous Assurance by continuously demonstrating runtime trust, evidence integrity, and operational assurance.",
        "explicitly_validates": [
            "Runtime trust",
            "Evidence integrity",
            "Policy compliance",
            "Agent behavior",
            "Operational assurance",
            "Trust reconstruction"
        ],
        "stage_question": "Are runtime trust, evidence integrity, policy compliance, agent behavior, operational assurance, and trust reconstruction continuously validated?",
        "evidence_outputs": [
            "Runtime trust validation record",
            "Evidence integrity validation record",
            "Policy compliance validation record",
            "Agent behavior validation record",
            "Operational assurance record",
            "Trust reconstruction record"
        ]
    },
    "Operational Trust": {
        "stage_rule": "Operational Trust remains unchanged as the outcome of the entire lifecycle.",
        "outcome_role": "Operational Trust is the outcome of Discovery, Visibility, Governance, Operationalization, Manufacturing Monitoring, Evidence, and Continuous Assurance.",
        "do_not_expand_beyond_outcome_role": True,
        "stage_question": "Can operational trust be justified from the full lifecycle evidence?",
        "evidence_outputs": [
            "Operational trust outcome record",
            "Lifecycle trust justification record",
            "Trust decision record"
        ]
    }
}

stage_strengthening_patch = {
    "patch_marker": PATCH_MARKER,
    "patch_type": "platform_b_stage_strengthening_not_new_module",
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
    "platform_rule": "Strengthen existing lifecycle stages only. Do not create new modules, stages, pillars, lifecycle phases, architectures, or foundational concepts.",
    "stage_enrichment": stage_enrichment,
    "positioning": {
        "control_tower_statement": "Enterprise AI is converging around governance control towers.",
        "assurance_engineering_statement": "Assurance Engineering complements those control towers by continuously demonstrating that AI-enabled operations remain trustworthy throughout their lifecycle.",
        "distinction": "Control towers manage AI. Assurance Engineering demonstrates trust."
    }
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

def normalize_stage_name(value):
    if not value:
        return ""
    text = str(value)
    for stage in permanent_lifecycle:
        if stage.lower() == text.lower():
            return stage
    if "discovery" in text.lower():
        return "Discovery"
    if "visibility" in text.lower():
        return "Visibility"
    if "governance" in text.lower():
        return "Governance"
    if "operationalization" in text.lower():
        return "Operationalization"
    if "manufacturing" in text.lower() or "monitoring" in text.lower():
        return "Manufacturing Monitoring"
    if "evidence" in text.lower():
        return "Evidence"
    if "continuous" in text.lower() or "assurance" in text.lower():
        return "Continuous Assurance"
    if "trust" in text.lower():
        return "Operational Trust"
    return ""

def patch_blueprint_seed():
    path = Path("platform_blueprint_library_seed.json")
    if not path.exists():
        print("SKIP: platform_blueprint_library_seed.json not found.")
        return False

    data = load_json(path)
    data["platform_b_stage_strengthening_patch"] = stage_strengthening_patch

    for bp in data.get("blueprints", []) or []:
        bp["platform_b_stage_strengthening"] = {
            "architecture_status": "FROZEN",
            "architecture_change": False,
            "new_module": False,
            "new_route": False,
            "lifecycle_change": False,
            "stage_rename_allowed": False,
            "stage_insertion_allowed": False,
            "permanent_lifecycle": permanent_lifecycle,
            "stage_strengthening_only": True
        }

        bp["questions_answered"] = add_unique_list(
            bp.get("questions_answered", []),
            [
                "Have all enterprise AI assets been discovered?",
                "Are AI assets, runtimes, workflows, telemetry, and dependencies visible?",
                "Are governance domains coordinated using inventories, permissions, observability, telemetry, and policy enforcement?",
                "Are AI Control Towers, agents, MCP, A2A, multi-model execution, workflows, approvals, and runtime policies operationalized?",
                "Are agents, models, workflows, runtime telemetry, decisions, and executions monitored?",
                "Can every execution answer which AI, model, workflow, tool, policy, evidence, approval, and outcome were involved?",
                "Are runtime trust, evidence integrity, policy compliance, agent behavior, operational assurance, and trust reconstruction continuously validated?"
            ]
        )

        assessment = bp.get("sample_blueprint_assessment", {})
        assessment["platform_b_stage_strengthening_state"] = "EXISTING_STAGES_STRENGTHENED_NO_ARCHITECTURE_CHANGE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["new_route"] = False
        assessment["lifecycle_change"] = False
        assessment["stage_strengthening_only"] = True
        assessment["permanent_lifecycle_sequence"] = stage_strengthening_patch["permanent_lifecycle_sequence"]
        assessment["stage_enrichment_count"] = len(stage_enrichment)
        bp["sample_blueprint_assessment"] = assessment

        for stage in bp.get("lifecycle", []) or []:
            stage_name = normalize_stage_name(stage.get("stage_name", ""))
            if not stage_name:
                continue

            enrichment = stage_enrichment.get(stage_name, {})
            stage["platform_b_stage_strengthening"] = enrichment
            stage["stage_rename_allowed"] = False
            stage["stage_insertion_allowed"] = False
            stage["lifecycle_reorganization_allowed"] = False
            stage["stage_question"] = enrichment.get("stage_question", stage.get("stage_question", ""))
            stage["evidence_outputs"] = add_unique_list(
                stage.get("evidence_outputs", []),
                enrichment.get("evidence_outputs", [])
            )

            if stage_name == "Discovery":
                stage["discovery_inventory_scope"] = enrichment["explicitly_includes"]
                stage["operational_focus"] = "Discovery now includes complete enterprise AI inventory coverage: AI systems, models, agents, MCP servers, A2A connections, tools, digital twins, data products, ownership, intended use, and risk classification."

            if stage_name == "Visibility":
                stage["visibility_scope"] = enrichment["explicitly_includes"]
                stage["operational_focus"] = "Visibility now includes AI asset visibility, runtime visibility, workflow visibility, cross-agent observability, cross-model observability, telemetry, execution visibility, and dependency visibility."

            if stage_name == "Governance":
                stage["governance_coordination_scope"] = enrichment["explicitly_coordinates"]
                stage["governance_inputs"] = enrichment["uses"]
                stage["operational_focus"] = "Governance coordinates infrastructure, data, model, identity, risk, compliance, policy, and executive governance using inventories, permissions, observability, telemetry, and policy enforcement."

            if stage_name == "Operationalization":
                stage["operationalization_examples"] = enrichment["explicitly_includes"]
                stage["operational_focus"] = "Operationalization includes AI Control Towers, agent orchestration, MCP, A2A, multi-model execution, workflow orchestration, human approval, runtime policy enforcement, and enterprise workflow execution."

            if stage_name == "Manufacturing Monitoring":
                stage["monitoring_scope"] = enrichment["explicitly_includes"]
                stage["operational_focus"] = "Manufacturing Monitoring includes agent monitoring, model monitoring, workflow monitoring, runtime telemetry, decision monitoring, execution monitoring, cross-agent monitoring, and cross-model monitoring."

            if stage_name == "Evidence":
                stage["execution_reconstruction_questions"] = enrichment["execution_questions"]
                stage["operational_focus"] = "Evidence ensures every execution can answer which AI acted, which model was used, which workflow executed, which tool was called, which policy approved execution, which evidence was generated, which approval occurred, and which outcome resulted."

            if stage_name == "Continuous Assurance":
                stage["continuous_assurance_validation_scope"] = enrichment["explicitly_validates"]
                stage["operational_focus"] = "Continuous Assurance validates runtime trust, evidence integrity, policy compliance, agent behavior, operational assurance, and trust reconstruction."

            if stage_name == "Operational Trust":
                stage["operational_trust_outcome_rule"] = enrichment["outcome_role"]
                stage["do_not_expand_beyond_outcome_role"] = True
                stage["operational_focus"] = "Operational Trust remains the outcome of the entire lifecycle."

    save_json(path, data)
    print("PATCHED: platform_blueprint_library_seed.json")
    return True

def patch_lifecycle_seed():
    path = Path("platform_lifecycle_integration_seed.json")
    if not path.exists():
        print("SKIP: platform_lifecycle_integration_seed.json not found.")
        return False

    data = load_json(path)
    data["platform_b_stage_strengthening_patch"] = stage_strengthening_patch

    assessment = data.get("sample_integration_assessment", {})
    assessment["platform_b_stage_strengthening"] = {
        "state": "EXISTING_LIFECYCLE_STAGES_STRENGTHENED",
        "architecture_status": "FROZEN",
        "architecture_change": False,
        "new_module": False,
        "new_route": False,
        "lifecycle_change": False,
        "stage_strengthening_only": True,
        "permanent_lifecycle": permanent_lifecycle,
        "stage_enrichment": stage_enrichment
    }

    assessment["implementation_priority"] = add_unique_list(
        assessment.get("implementation_priority", []),
        [
            "Strengthen Discovery with complete enterprise AI inventories.",
            "Strengthen Visibility with cross-agent, cross-model, runtime, workflow, execution, telemetry, and dependency visibility.",
            "Strengthen Governance as the coordination layer for infrastructure, data, model, identity, risk, compliance, policy, and executive governance.",
            "Strengthen Operationalization with AI Control Towers, agent orchestration, MCP, A2A, multi-model execution, workflow orchestration, human approval, and runtime policy enforcement.",
            "Strengthen Manufacturing Monitoring with agent, model, workflow, runtime telemetry, decision, and execution monitoring.",
            "Strengthen Evidence so every execution can be reconstructed.",
            "Strengthen Continuous Assurance with runtime trust, evidence integrity, policy compliance, agent behavior, operational assurance, and trust reconstruction.",
            "Keep Operational Trust as the outcome of the entire lifecycle."
        ]
    )

    assessment["evidence_automation_targets"] = add_unique_list(
        assessment.get("evidence_automation_targets", []),
        [
            "AI inventory evidence binder",
            "Runtime visibility evidence binder",
            "Governance coordination evidence binder",
            "Operationalization execution evidence binder",
            "Runtime monitoring evidence binder",
            "Execution reconstruction evidence binder",
            "Continuous assurance evidence binder",
            "Operational Trust outcome evidence binder"
        ]
    )

    data["sample_integration_assessment"] = assessment

    for stage in data.get("integration_flow", []) or []:
        stage_name = normalize_stage_name(stage.get("stage_name", "")) or normalize_stage_name(stage.get("stage_id", ""))
        stage["platform_b_stage_strengthening_guardrail"] = {
            "architecture_status": "FROZEN",
            "new_module_allowed": False,
            "new_route_allowed": False,
            "lifecycle_change_allowed": False,
            "stage_strengthening_only": True
        }

        if stage_name and stage_name in stage_enrichment:
            enrichment = stage_enrichment[stage_name]
            stage["platform_b_stage_strengthening"] = enrichment
            stage["operational_question"] = enrichment.get("stage_question", stage.get("operational_question", ""))
            stage["expected_objects"] = add_unique_list(
                stage.get("expected_objects", []),
                [x.replace(" ", "").replace("/", "").replace("-", "") for x in enrichment.get("evidence_outputs", [])]
            )
            stage["evidence_outputs"] = add_unique_list(
                stage.get("evidence_outputs", []),
                enrichment.get("evidence_outputs", [])
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
            <h2 style="margin:0;font-size:30px;">Platform B Stage Strengthening</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                This blueprint now strengthens the frozen lifecycle stages only. No new modules, routes, architectures, stages, pillars, lifecycle phases, or foundational concepts were added.
            </div>
        </div>
        <span class="tag">Frozen lifecycle</span>
    </div>
    <div class="grid">
        <div class="panel"><strong>Discovery</strong><div>AI systems, AI models, AI agents, MCP servers, A2A connections, AI tools, digital twins, data products, ownership, intended use, and risk classification.</div></div>
        <div class="panel"><strong>Visibility</strong><div>AI asset visibility, runtime visibility, workflow visibility, cross-agent observability, cross-model observability, telemetry, execution visibility, and dependency visibility.</div></div>
        <div class="panel"><strong>Governance</strong><div>Coordinates infrastructure, data, model, identity, risk, compliance, policy, and executive governance using inventories, permissions, observability, telemetry, and policy enforcement.</div></div>
        <div class="panel"><strong>Operationalization</strong><div>AI Control Towers, agent orchestration, MCP, A2A, multi-model execution, workflow orchestration, human approval, runtime policy enforcement, and enterprise workflow execution.</div></div>
        <div class="panel"><strong>Manufacturing Monitoring</strong><div>Agent monitoring, model monitoring, workflow monitoring, runtime telemetry, decision monitoring, execution monitoring, cross-agent monitoring, and cross-model monitoring.</div></div>
        <div class="panel"><strong>Evidence</strong><div>Which AI acted? Which model? Which workflow? Which tool? Which policy? Which evidence? Which approval? Which outcome?</div></div>
        <div class="panel"><strong>Continuous Assurance</strong><div>Runtime trust, evidence integrity, policy compliance, agent behavior, operational assurance, and trust reconstruction.</div></div>
        <div class="panel"><strong>Operational Trust</strong><div>Operational Trust remains the outcome of the entire lifecycle.</div></div>
    </div>
</section>
'''

platform_block = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>Platform B Stage Strengthening</h2>
            <p>The frozen Platform B lifecycle has been strengthened without adding new modules or changing the architecture. Discovery, Visibility, Governance, Operationalization, Manufacturing Monitoring, Evidence, and Continuous Assurance were expanded. Operational Trust remains the outcome.</p>
        </div>
        <span class="tag">No new module</span>
    </div>
    <div class="grid-4">
        <a class="card" href="/platform/blueprints/ai-enabled-cmc"><strong>AI-enabled CMC Blueprint</strong><span>Shows stage-strengthened Discovery, Visibility, Governance, Operationalization, Monitoring, Evidence, and Continuous Assurance.</span><small>Open blueprint</small></a>
        <a class="card" href="/platform/blueprints/agentic-enterprise"><strong>Agentic Enterprise Blueprint</strong><span>Applies the same frozen lifecycle strengthening to enterprise AI, agents, models, workflows, tools, policies, evidence, and trust.</span><small>Open blueprint</small></a>
        <a class="card" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Connects strengthened stages to evidence automation and operational trust.</span><small>Open lifecycle</small></a>
        <a class="card" href="/platform/evidence-packages"><strong>Evidence</strong><span>Every execution must answer which AI, model, workflow, tool, policy, evidence, approval, and outcome were involved.</span><small>Open evidence</small></a>
    </div>
</section>
'''

library_block = r'''
<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">Blueprints Use the Strengthened Frozen Lifecycle</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Blueprints remain examples of the existing lifecycle. They may only strengthen Discovery, Visibility, Governance, Operationalization, Manufacturing Monitoring, Evidence, Continuous Assurance, and Operational Trust.
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
            <h2>Platform B Stage Strengthening Routes</h2>
            <p>Stage strengthening is visible through existing routes only. No new route was added.</p>
        </div>
        <span class="tag">Existing routes only</span>
    </div>
    <div class="route-grid">
        <a class="route" href="/platform"><strong>Platform Command Center</strong><span>Displays the strengthened frozen lifecycle.</span><code>/platform</code></a>
        <a class="route" href="/platform/blueprints/ai-enabled-cmc"><strong>AI-enabled CMC Blueprint</strong><span>Shows strengthened lifecycle stages for AI-enabled CMC.</span><code>/platform/blueprints/ai-enabled-cmc</code></a>
        <a class="route" href="/platform/blueprints/agentic-enterprise"><strong>Agentic Enterprise Blueprint</strong><span>Shows strengthened lifecycle stages for enterprise AI and agentic operations.</span><code>/platform/blueprints/agentic-enterprise</code></a>
        <a class="route" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Connects strengthened stages to evidence automation, continuous assurance, and operational trust.</span><code>/platform/lifecycle-integration</code></a>
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

Path("platform_b_stage_strengthening_patch_v1_summary.json").write_text(
    json.dumps(stage_strengthening_patch, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("platform_b_stage_strengthening_patch_v1_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform",
        "http://127.0.0.1:5000/platform/routes",
        "http://127.0.0.1:5000/platform/blueprints",
        "http://127.0.0.1:5000/platform/blueprints/ai-enabled-cmc",
        "http://127.0.0.1:5000/platform/blueprints/agentic-enterprise",
        "http://127.0.0.1:5000/platform/lifecycle-integration",
        "http://127.0.0.1:5000/api/platform/blueprints/model/demo",
        "http://127.0.0.1:5000/api/platform/blueprints/ai-enabled-cmc/demo",
        "http://127.0.0.1:5000/api/platform/blueprints/agentic-enterprise/demo",
        "http://127.0.0.1:5000/api/platform/lifecycle-integration/model/demo"
    ]),
    encoding="utf-8"
)

print("")
print("Platform B Stage Strengthening Patch completed.")
print("Marker:")
print("  " + PATCH_MARKER)
print("No new module. No new route. No architecture change. Lifecycle unchanged.")
