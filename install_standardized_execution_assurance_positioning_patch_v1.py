from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_STANDARDIZED_EXECUTION_ASSURANCE_POSITIONING_PATCH_V1_ACTIVE"

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

positioning_statement = {
    "headline": "Standardized execution needs standardized assurance.",
    "thesis": "Enterprise AI is converging around standardized execution technologies: MCP, AI Gateways, A2A, and agent orchestration. Assurance Engineering complements these technologies by continuously demonstrating that AI-enabled execution remains trustworthy throughout its lifecycle.",
    "short_version": "MCP, AI Gateways, A2A, and agent orchestration standardize AI execution. Assurance Engineering standardizes trust in that execution.",
    "distinction": "Execution technologies enable AI to act. Assurance Engineering proves those actions can be trusted.",
    "architecture_change": False,
    "new_module": False,
    "new_route": False,
    "lifecycle_change": False
}

stage_mapping = {
    "Discovery": {
        "execution_positioning": "Inventory standardized execution technologies before operation.",
        "includes": [
            "MCP Servers",
            "AI Gateways",
            "A2A Connections",
            "AI Agents",
            "Agent orchestration services",
            "MCP Tools",
            "Tool Connectors",
            "AI Models",
            "Enterprise APIs",
            "Digital Twins"
        ],
        "stage_question": "Have MCP servers, AI gateways, A2A connections, AI agents, orchestration services, tools, models, enterprise APIs, and digital twins been discovered before execution?",
        "evidence_outputs": [
            "Standardized execution inventory record",
            "MCP server discovery record",
            "AI gateway discovery record",
            "A2A connection discovery record",
            "Agent orchestration discovery record"
        ]
    },
    "Visibility": {
        "execution_positioning": "Make standardized execution visible through topology, telemetry, and workflow observability.",
        "includes": [
            "MCP visibility",
            "AI Gateway visibility",
            "A2A visibility",
            "Agent topology",
            "Orchestration visibility",
            "Runtime telemetry",
            "Workflow visibility",
            "Execution visibility"
        ],
        "stage_question": "Can MCP activity, AI gateway routing, A2A interactions, agent topology, orchestration flow, runtime telemetry, workflow behavior, and execution paths be observed?",
        "evidence_outputs": [
            "Standardized execution visibility record",
            "MCP visibility record",
            "AI gateway visibility record",
            "A2A visibility record",
            "Agent orchestration visibility record",
            "Runtime telemetry visibility record"
        ]
    },
    "Governance": {
        "execution_positioning": "Coordinate governance over the technologies that standardize execution.",
        "coordinates": [
            "MCP governance",
            "AI Gateway governance",
            "A2A governance",
            "Agent governance",
            "Tool governance",
            "API governance",
            "Identity governance",
            "Policy governance",
            "Risk governance"
        ],
        "stage_question": "Are MCP, AI Gateway, A2A, agent, tool, API, identity, policy, and risk governance coordinated before AI-enabled execution?",
        "evidence_outputs": [
            "Standardized execution governance record",
            "MCP governance record",
            "AI gateway governance record",
            "A2A governance record",
            "Agent orchestration governance record",
            "Policy-to-execution governance record",
            "Risk-to-execution governance record"
        ]
    },
    "Operationalization": {
        "execution_positioning": "Govern how standardized execution technologies are implemented in real workflows.",
        "includes": [
            "MCP integration",
            "AI Gateway integration",
            "A2A collaboration",
            "Agent orchestration",
            "Multi-agent execution",
            "Multi-model execution",
            "Runtime authorization",
            "Policy enforcement",
            "Human approval workflow",
            "Enterprise workflow execution"
        ],
        "stage_question": "Are MCP integration, AI gateway routing, A2A collaboration, agent orchestration, multi-agent execution, multi-model execution, runtime authorization, policy enforcement, human approval, and enterprise workflow execution governed before operation?",
        "evidence_outputs": [
            "Standardized execution operationalization record",
            "MCP integration evidence",
            "AI gateway integration evidence",
            "A2A collaboration evidence",
            "Agent orchestration evidence",
            "Runtime authorization evidence",
            "Policy enforcement evidence",
            "Human approval workflow evidence"
        ]
    },
    "Manufacturing Monitoring": {
        "execution_positioning": "Monitor standardized execution while AI-enabled operations run.",
        "monitors": [
            "MCP calls",
            "AI Gateway routing",
            "A2A interactions",
            "Agent execution",
            "Tool calls",
            "Model execution",
            "Runtime telemetry",
            "Workflow execution",
            "Policy enforcement events"
        ],
        "stage_question": "Are MCP calls, AI gateway routing, A2A interactions, agent execution, tool calls, model execution, runtime telemetry, workflow execution, and policy enforcement events monitored?",
        "evidence_outputs": [
            "Standardized execution monitoring record",
            "MCP call monitoring record",
            "AI gateway routing monitoring record",
            "A2A interaction monitoring record",
            "Agent execution monitoring record",
            "Runtime telemetry monitoring record",
            "Policy enforcement monitoring record"
        ]
    },
    "Evidence": {
        "execution_positioning": "Reconstruct standardized execution from evidence.",
        "execution_questions": [
            "Which agent executed?",
            "Which MCP server was used?",
            "Which AI gateway routed execution?",
            "Which A2A interaction occurred?",
            "Which tool was called?",
            "Which model generated the output?",
            "Which workflow executed?",
            "Which policy was evaluated?",
            "Which human approval occurred?",
            "What runtime evidence was produced?"
        ],
        "stage_question": "Can every AI-enabled execution be reconstructed from agent, MCP, gateway, A2A, tool, model, workflow, policy, approval, and runtime evidence?",
        "evidence_outputs": [
            "Standardized execution evidence package",
            "Agent execution evidence",
            "MCP server usage evidence",
            "AI gateway routing evidence",
            "A2A interaction evidence",
            "Tool-call evidence",
            "Model generation evidence",
            "Workflow execution evidence",
            "Policy evaluation evidence",
            "Human approval evidence",
            "Runtime evidence"
        ]
    },
    "Continuous Assurance": {
        "execution_positioning": "Continuously prove that standardized execution remains trustworthy.",
        "validates": [
            "MCP interaction integrity",
            "AI Gateway control effectiveness",
            "A2A interaction integrity",
            "Agent behavior",
            "Workflow integrity",
            "Runtime trust",
            "Policy compliance",
            "Evidence integrity",
            "Trust reconstruction"
        ],
        "stage_question": "Are MCP interactions, AI gateway controls, A2A interactions, agent behavior, workflow integrity, runtime trust, policy compliance, evidence integrity, and trust reconstruction continuously validated?",
        "evidence_outputs": [
            "Standardized execution assurance record",
            "MCP interaction assurance record",
            "AI gateway control assurance record",
            "A2A interaction assurance record",
            "Agent behavior assurance record",
            "Workflow integrity assurance record",
            "Runtime trust assurance record",
            "Policy compliance assurance record",
            "Evidence integrity assurance record",
            "Trust reconstruction record"
        ]
    },
    "Operational Trust": {
        "execution_positioning": "Operational Trust remains the lifecycle outcome.",
        "outcome_role": "Operational Trust is the outcome of the entire frozen lifecycle. It is not a new stage, module, or architecture.",
        "do_not_expand_beyond_outcome_role": True,
        "stage_question": "Can operational trust be justified from the full lifecycle evidence generated by standardized AI execution?",
        "evidence_outputs": [
            "Operational trust outcome record",
            "Standardized execution trust justification record",
            "Lifecycle trust decision record"
        ]
    }
}

traceability_map = [
    {
        "execution_technology": "MCP",
        "execution_function": "Standardizes tool and context access.",
        "assurance_function": "Proves which MCP server was used, which tool was called, what context was supplied, which policy was evaluated, and what runtime evidence was produced.",
        "lifecycle_path": "Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust"
    },
    {
        "execution_technology": "AI Gateways",
        "execution_function": "Standardize routing, access, policy checkpoints, and model/API mediation.",
        "assurance_function": "Proves which gateway routed execution, which policy was enforced, which model or service was invoked, and whether routing remained compliant.",
        "lifecycle_path": "Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust"
    },
    {
        "execution_technology": "A2A",
        "execution_function": "Standardizes agent-to-agent collaboration and distributed execution.",
        "assurance_function": "Proves which A2A interaction occurred, which agents participated, what workflow step executed, which approval was required, and whether collaboration remained trustworthy.",
        "lifecycle_path": "Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust"
    },
    {
        "execution_technology": "Agent orchestration",
        "execution_function": "Standardizes planning, delegation, sequencing, escalation, and workflow execution.",
        "assurance_function": "Proves which agent executed, which workflow ran, which tool was called, which policy approved execution, and what outcome resulted.",
        "lifecycle_path": "Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust"
    }
]

patch_model = {
    "patch_marker": PATCH_MARKER,
    "patch_type": "standardized_execution_assurance_positioning_not_new_module",
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
    "positioning_statement": positioning_statement,
    "stage_mapping": stage_mapping,
    "traceability_map": traceability_map,
    "operational_trust_rule": "Operational Trust remains the outcome of the entire lifecycle."
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
    text = str(value).strip()
    low = text.lower()
    for stage in permanent_lifecycle:
        if stage.lower() == low:
            return stage
    if "discovery" in low:
        return "Discovery"
    if "visibility" in low:
        return "Visibility"
    if "governance" in low:
        return "Governance"
    if "operationalization" in low:
        return "Operationalization"
    if "manufacturing" in low or "monitoring" in low:
        return "Manufacturing Monitoring"
    if "evidence" in low:
        return "Evidence"
    if "continuous" in low or "assurance" in low:
        return "Continuous Assurance"
    if "trust" in low:
        return "Operational Trust"
    return ""

def patch_blueprint_seed():
    path = Path("platform_blueprint_library_seed.json")
    if not path.exists():
        print("SKIP: platform_blueprint_library_seed.json not found.")
        return False

    data = load_json(path)
    data["standardized_execution_assurance_positioning_patch"] = patch_model

    existing_positioning = data.get("platform_positioning", {})
    if not isinstance(existing_positioning, dict):
        existing_positioning = {}
    existing_positioning["standardized_execution_assurance"] = positioning_statement
    data["platform_positioning"] = existing_positioning

    for bp in data.get("blueprints", []) or []:
        bp["standardized_execution_assurance_positioning"] = {
            "architecture_status": "FROZEN",
            "architecture_change": False,
            "new_module": False,
            "new_route": False,
            "lifecycle_change": False,
            "stage_strengthening_only": True,
            "thesis": positioning_statement["thesis"],
            "headline": positioning_statement["headline"],
            "permanent_lifecycle": permanent_lifecycle,
            "operational_trust_unchanged": True
        }

        bp["questions_answered"] = add_unique_list(
            bp.get("questions_answered", []),
            [
                "How does Assurance Engineering complement MCP, AI Gateways, A2A, and agent orchestration?",
                "How is standardized AI execution continuously demonstrated as trustworthy?",
                "Which execution technology enabled the action?",
                "Which assurance evidence proves the execution was governed, monitored, evidenced, and trustworthy?",
                "Can the AI-enabled execution be reconstructed across the full lifecycle?"
            ]
        )

        assessment = bp.get("sample_blueprint_assessment", {})
        if not isinstance(assessment, dict):
            assessment = {}
        assessment["standardized_execution_assurance_state"] = "EXECUTION_TECHNOLOGIES_COMPLEMENTED_BY_ASSURANCE_ENGINEERING"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["new_route"] = False
        assessment["lifecycle_change"] = False
        assessment["stage_strengthening_only"] = True
        assessment["permanent_lifecycle_sequence"] = patch_model["permanent_lifecycle_sequence"]
        assessment["execution_positioning_headline"] = positioning_statement["headline"]
        assessment["execution_positioning_thesis"] = positioning_statement["thesis"]
        assessment["operational_trust_rule"] = patch_model["operational_trust_rule"]
        assessment["traceability_map_count"] = len(traceability_map)
        bp["sample_blueprint_assessment"] = assessment

        for stage in bp.get("lifecycle", []) or []:
            stage_name = normalize_stage_name(stage.get("stage_name", ""))
            if not stage_name:
                continue

            mapping = stage_mapping.get(stage_name, {})
            stage["standardized_execution_assurance_positioning"] = mapping
            stage["stage_rename_allowed"] = False
            stage["stage_insertion_allowed"] = False
            stage["lifecycle_reorganization_allowed"] = False
            stage["stage_question"] = mapping.get("stage_question", stage.get("stage_question", ""))
            stage["evidence_outputs"] = add_unique_list(stage.get("evidence_outputs", []), mapping.get("evidence_outputs", []))

            if stage_name == "Discovery":
                stage["standardized_execution_inventory_scope"] = mapping["includes"]
                stage["operational_focus"] = "Discovery inventories MCP Servers, AI Gateways, A2A Connections, AI Agents, orchestration services, tools, models, enterprise APIs, and Digital Twins before execution."

            if stage_name == "Visibility":
                stage["standardized_execution_visibility_scope"] = mapping["includes"]
                stage["operational_focus"] = "Visibility observes MCP activity, AI Gateway routing, A2A interactions, agent topology, orchestration flow, runtime telemetry, workflow behavior, and execution paths."

            if stage_name == "Governance":
                stage["standardized_execution_governance_scope"] = mapping["coordinates"]
                stage["operational_focus"] = "Governance coordinates MCP, AI Gateway, A2A, agent, tool, API, identity, policy, and risk governance."

            if stage_name == "Operationalization":
                stage["standardized_execution_operationalization_scope"] = mapping["includes"]
                stage["operational_focus"] = "Operationalization governs MCP integration, AI Gateway routing, A2A collaboration, agent orchestration, multi-agent execution, multi-model execution, runtime authorization, policy enforcement, human approval, and enterprise workflow execution."

            if stage_name == "Manufacturing Monitoring":
                stage["standardized_execution_monitoring_scope"] = mapping["monitors"]
                stage["operational_focus"] = "Manufacturing Monitoring monitors MCP calls, AI Gateway routing, A2A interactions, agent execution, tool calls, model execution, runtime telemetry, workflow execution, and policy enforcement events."

            if stage_name == "Evidence":
                stage["standardized_execution_reconstruction_questions"] = mapping["execution_questions"]
                stage["operational_focus"] = "Evidence reconstructs standardized execution from agent, MCP, gateway, A2A, tool, model, workflow, policy, approval, and runtime evidence."

            if stage_name == "Continuous Assurance":
                stage["standardized_execution_assurance_validation_scope"] = mapping["validates"]
                stage["operational_focus"] = "Continuous Assurance proves MCP interactions, AI gateway controls, A2A interactions, agent behavior, workflow integrity, runtime trust, policy compliance, evidence integrity, and trust reconstruction."

            if stage_name == "Operational Trust":
                stage["operational_trust_outcome_rule"] = mapping["outcome_role"]
                stage["do_not_expand_beyond_outcome_role"] = True
                stage["operational_focus"] = "Operational Trust remains the outcome of the entire frozen lifecycle."

    save_json(path, data)
    print("PATCHED: platform_blueprint_library_seed.json")
    return True

def patch_lifecycle_seed():
    path = Path("platform_lifecycle_integration_seed.json")
    if not path.exists():
        print("SKIP: platform_lifecycle_integration_seed.json not found.")
        return False

    data = load_json(path)
    data["standardized_execution_assurance_positioning_patch"] = patch_model

    assessment = data.get("sample_integration_assessment", {})
    if not isinstance(assessment, dict):
        assessment = {}

    assessment["standardized_execution_assurance_positioning"] = {
        "state": "EXECUTION_TECHNOLOGIES_COMPLEMENTED_BY_ASSURANCE_ENGINEERING",
        "architecture_status": "FROZEN",
        "architecture_change": False,
        "new_module": False,
        "new_route": False,
        "lifecycle_change": False,
        "stage_strengthening_only": True,
        "positioning_statement": positioning_statement,
        "stage_mapping": stage_mapping,
        "traceability_map": traceability_map
    }

    assessment["implementation_priority"] = add_unique_list(
        assessment.get("implementation_priority", []),
        [
            "Position MCP, AI Gateways, A2A, and agent orchestration as standardized execution technologies.",
            "Position Assurance Engineering as the continuous demonstration that AI-enabled execution remains trustworthy throughout its lifecycle.",
            "Strengthen Discovery with standardized execution technology inventory.",
            "Strengthen Visibility with topology, telemetry, workflow, gateway, MCP, and A2A observability.",
            "Strengthen Governance with execution technology governance coordination.",
            "Strengthen Operationalization with governed implementation of MCP, gateways, A2A, orchestration, authorization, policy enforcement, and human approval.",
            "Strengthen Manufacturing Monitoring with runtime monitoring of MCP calls, gateway routing, A2A interactions, agent execution, workflows, and policy events.",
            "Strengthen Evidence with execution reconstruction across agent, MCP, gateway, A2A, tool, model, workflow, policy, approval, and runtime evidence.",
            "Strengthen Continuous Assurance with ongoing validation of execution trust.",
            "Keep Operational Trust unchanged as the lifecycle outcome."
        ]
    )

    assessment["evidence_automation_targets"] = add_unique_list(
        assessment.get("evidence_automation_targets", []),
        [
            "Standardized execution evidence package",
            "MCP execution assurance record",
            "AI Gateway routing assurance record",
            "A2A interaction assurance record",
            "Agent orchestration assurance record",
            "Runtime trust assurance record",
            "Policy compliance assurance record",
            "Execution trust reconstruction package"
        ]
    )

    data["sample_integration_assessment"] = assessment

    lifecycle_object_map = {
        "Discovery": [
            "StandardizedExecutionInventoryRecord",
            "MCPServerDiscoveryRecord",
            "AIGatewayDiscoveryRecord",
            "A2AConnectionDiscoveryRecord",
            "AgentOrchestrationDiscoveryRecord"
        ],
        "Visibility": [
            "StandardizedExecutionVisibilityRecord",
            "MCPVisibilityRecord",
            "AIGatewayVisibilityRecord",
            "A2AVisibilityRecord",
            "AgentOrchestrationVisibilityRecord",
            "RuntimeTelemetryVisibilityRecord"
        ],
        "Governance": [
            "StandardizedExecutionGovernanceRecord",
            "MCPGovernanceRecord",
            "AIGatewayGovernanceRecord",
            "A2AGovernanceRecord",
            "AgentOrchestrationGovernanceRecord",
            "PolicyToExecutionGovernanceRecord",
            "RiskToExecutionGovernanceRecord"
        ],
        "Operationalization": [
            "StandardizedExecutionOperationalizationRecord",
            "MCPIntegrationEvidence",
            "AIGatewayIntegrationEvidence",
            "A2ACollaborationEvidence",
            "AgentOrchestrationEvidence",
            "RuntimeAuthorizationEvidence",
            "PolicyEnforcementEvidence",
            "HumanApprovalWorkflowEvidence"
        ],
        "Manufacturing Monitoring": [
            "StandardizedExecutionMonitoringRecord",
            "MCPCallMonitoringRecord",
            "AIGatewayRoutingMonitoringRecord",
            "A2AInteractionMonitoringRecord",
            "AgentExecutionMonitoringRecord",
            "RuntimeTelemetryMonitoringRecord",
            "PolicyEnforcementMonitoringRecord"
        ],
        "Evidence": [
            "StandardizedExecutionEvidencePackage",
            "AgentExecutionEvidence",
            "MCPServerUsageEvidence",
            "AIGatewayRoutingEvidence",
            "A2AInteractionEvidence",
            "ToolCallEvidence",
            "ModelGenerationEvidence",
            "WorkflowExecutionEvidence",
            "PolicyEvaluationEvidence",
            "HumanApprovalEvidence",
            "RuntimeEvidence"
        ],
        "Continuous Assurance": [
            "StandardizedExecutionAssuranceRecord",
            "MCPInteractionAssuranceRecord",
            "AIGatewayControlAssuranceRecord",
            "A2AInteractionAssuranceRecord",
            "AgentBehaviorAssuranceRecord",
            "WorkflowIntegrityAssuranceRecord",
            "RuntimeTrustAssuranceRecord",
            "PolicyComplianceAssuranceRecord",
            "EvidenceIntegrityAssuranceRecord",
            "TrustReconstructionRecord"
        ],
        "Operational Trust": [
            "OperationalTrustOutcomeRecord",
            "StandardizedExecutionTrustJustificationRecord",
            "LifecycleTrustDecisionRecord"
        ]
    }

    for stage in data.get("integration_flow", []) or []:
        stage_name = normalize_stage_name(stage.get("stage_name", "")) or normalize_stage_name(stage.get("stage_id", ""))
        stage["standardized_execution_assurance_guardrail"] = {
            "architecture_status": "FROZEN",
            "new_module_allowed": False,
            "new_route_allowed": False,
            "lifecycle_change_allowed": False,
            "stage_strengthening_only": True
        }

        if stage_name and stage_name in stage_mapping:
            mapping = stage_mapping[stage_name]
            stage["standardized_execution_assurance_positioning"] = mapping
            stage["operational_question"] = mapping.get("stage_question", stage.get("operational_question", ""))
            stage["expected_objects"] = add_unique_list(stage.get("expected_objects", []), lifecycle_object_map.get(stage_name, []))
            stage["evidence_outputs"] = add_unique_list(stage.get("evidence_outputs", []), mapping.get("evidence_outputs", []))

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
            <h2 style="margin:0;font-size:30px;">Standardized Execution Assurance</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Enterprise AI is converging around standardized execution technologies: MCP, AI Gateways, A2A, and agent orchestration. Assurance Engineering complements these technologies by continuously demonstrating that AI-enabled execution remains trustworthy throughout its lifecycle.
            </div>
        </div>
        <span class="tag">No new module</span>
    </div>
    <div class="grid">
        <div class="panel"><strong>Core thesis</strong><div>MCP, AI Gateways, A2A, and agent orchestration standardize AI execution. Assurance Engineering standardizes trust in that execution.</div></div>
        <div class="panel"><strong>Discovery</strong><div>Inventory MCP Servers, AI Gateways, A2A Connections, AI Agents, orchestration services, tools, models, enterprise APIs, and Digital Twins.</div></div>
        <div class="panel"><strong>Visibility</strong><div>Observe MCP activity, gateway routing, A2A interactions, agent topology, orchestration flow, runtime telemetry, workflow behavior, and execution paths.</div></div>
        <div class="panel"><strong>Governance</strong><div>Coordinate MCP, AI Gateway, A2A, agent, tool, API, identity, policy, and risk governance.</div></div>
        <div class="panel"><strong>Operationalization</strong><div>Govern MCP integration, AI Gateway routing, A2A collaboration, agent orchestration, multi-agent execution, multi-model execution, runtime authorization, policy enforcement, human approval, and enterprise workflow execution.</div></div>
        <div class="panel"><strong>Manufacturing Monitoring</strong><div>Monitor MCP calls, AI Gateway routing, A2A interactions, agent execution, tool calls, model execution, runtime telemetry, workflow execution, and policy enforcement events.</div></div>
        <div class="panel"><strong>Evidence</strong><div>Reconstruct execution from agent, MCP, gateway, A2A, tool, model, workflow, policy, approval, and runtime evidence.</div></div>
        <div class="panel"><strong>Continuous Assurance</strong><div>Continuously validate MCP interactions, AI gateway controls, A2A interactions, agent behavior, workflow integrity, runtime trust, policy compliance, evidence integrity, and trust reconstruction.</div></div>
        <div class="panel"><strong>Operational Trust</strong><div>Operational Trust remains the outcome of the frozen lifecycle.</div></div>
    </div>
</section>
'''

platform_block = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>Standardized Execution Assurance</h2>
            <p>Enterprise AI is converging around standardized execution technologies: MCP, AI Gateways, A2A, and agent orchestration. Assurance Engineering complements these technologies by continuously demonstrating that AI-enabled execution remains trustworthy throughout its lifecycle.</p>
        </div>
        <span class="tag">Frozen lifecycle</span>
    </div>
    <div class="grid-4">
        <a class="card" href="/platform/blueprints/ai-enabled-cmc"><strong>AI-enabled CMC Blueprint</strong><span>Shows how standardized execution technologies are governed, monitored, evidenced, and continuously assured inside the existing lifecycle.</span><small>Open blueprint</small></a>
        <a class="card" href="/platform/blueprints/agentic-enterprise"><strong>Agentic Enterprise Blueprint</strong><span>Connects MCP, AI Gateways, A2A, and orchestration to operational trust without creating a new module.</span><small>Open blueprint</small></a>
        <a class="card" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Maps standardized execution to Discovery, Visibility, Governance, Operationalization, Manufacturing Monitoring, Evidence, Continuous Assurance, and Operational Trust.</span><small>Open lifecycle</small></a>
        <a class="card" href="/platform/evidence-packages"><strong>Evidence</strong><span>Execution evidence proves which agent, MCP server, gateway, A2A interaction, tool, model, workflow, policy, approval, and runtime evidence supported the action.</span><small>Open evidence</small></a>
    </div>
</section>
'''

library_block = r'''
<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">Standardized Execution Needs Standardized Assurance</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Blueprints may use MCP, AI Gateways, A2A, and agent orchestration as execution examples, but only within the frozen lifecycle. Assurance Engineering proves that execution remains governed, monitored, evidenced, and trustworthy.
            </div>
        </div>
        <span class="tag">Blueprint positioning</span>
    </div>
</section>
'''

route_registry_block = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>Standardized Execution Assurance Routes</h2>
            <p>The positioning is exposed through existing routes only. No new module or route was added.</p>
        </div>
        <span class="tag">Existing routes only</span>
    </div>
    <div class="route-grid">
        <a class="route" href="/platform"><strong>Platform Command Center</strong><span>Shows the standardized execution assurance thesis inside the frozen Platform B lifecycle.</span><code>/platform</code></a>
        <a class="route" href="/platform/blueprints/ai-enabled-cmc"><strong>AI-enabled CMC Blueprint</strong><span>Applies standardized execution assurance to CMC examples through existing lifecycle stages.</span><code>/platform/blueprints/ai-enabled-cmc</code></a>
        <a class="route" href="/platform/blueprints/agentic-enterprise"><strong>Agentic Enterprise Blueprint</strong><span>Applies standardized execution assurance to agentic enterprise execution through existing lifecycle stages.</span><code>/platform/blueprints/agentic-enterprise</code></a>
        <a class="route" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Maps MCP, AI Gateways, A2A, and agent orchestration to evidence, continuous assurance, and operational trust.</span><code>/platform/lifecycle-integration</code></a>
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

Path("standardized_execution_assurance_positioning_patch_v1_summary.json").write_text(
    json.dumps(patch_model, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("standardized_execution_assurance_positioning_patch_v1_urls.txt").write_text(
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
print("Standardized Execution Assurance Positioning Patch completed.")
print("Marker:")
print("  " + PATCH_MARKER)
print("No new module. No new route. No architecture change. Lifecycle unchanged.")
