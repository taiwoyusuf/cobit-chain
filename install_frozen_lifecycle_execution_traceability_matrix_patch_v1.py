from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_FROZEN_LIFECYCLE_EXECUTION_TRACEABILITY_MATRIX_PATCH_V1_ACTIVE"

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

traceability_principle = {
    "headline": "Every AI-enabled execution must be reconstructable across the frozen lifecycle.",
    "platform_question": "Can the execution be traced from discovered AI asset to visibility signal, governance decision, operational execution, monitoring event, evidence record, assurance validation, and operational trust outcome?",
    "architecture_change": False,
    "new_module": False,
    "new_route": False,
    "lifecycle_change": False
}

execution_traceability_matrix = [
    {
        "execution_case": "Agent execution",
        "discovery": "AI Agent inventory record",
        "visibility": "Agent topology and cross-agent observability",
        "governance": "Agent governance, identity governance, policy governance, and risk governance",
        "operationalization": "Agent orchestration, runtime authorization, and policy enforcement",
        "manufacturing_monitoring": "Agent execution monitoring and runtime telemetry",
        "evidence": "Which agent executed? Which policy approved execution? What runtime evidence was produced?",
        "continuous_assurance": "Agent behavior, runtime trust, policy compliance, and evidence integrity",
        "operational_trust": "Agent action can be trusted because execution is inventoried, visible, governed, monitored, evidenced, and continuously assured."
    },
    {
        "execution_case": "MCP execution",
        "discovery": "MCP Server and MCP Tool inventory records",
        "visibility": "MCP visibility and runtime telemetry",
        "governance": "MCP governance, tool governance, identity governance, policy governance, and risk governance",
        "operationalization": "MCP integration, tool authorization, runtime authorization, and policy enforcement",
        "manufacturing_monitoring": "MCP call monitoring and tool execution monitoring",
        "evidence": "Which MCP server was used? Which tool was called? Which policies were evaluated?",
        "continuous_assurance": "MCP interaction integrity, tool-use compliance, runtime trust, and policy compliance",
        "operational_trust": "MCP execution can be trusted because server use, tool calls, policies, and runtime evidence are reconstructable."
    },
    {
        "execution_case": "AI Gateway routing",
        "discovery": "AI Gateway inventory record",
        "visibility": "Gateway visibility, route visibility, and runtime telemetry",
        "governance": "Gateway governance, API governance, identity governance, policy governance, and risk governance",
        "operationalization": "AI Gateway integration, routing policy, runtime authorization, and policy enforcement",
        "manufacturing_monitoring": "Gateway execution monitoring, routing events, and policy enforcement events",
        "evidence": "Which gateway routed execution? Which model or service was invoked? Which policy was enforced?",
        "continuous_assurance": "Gateway control effectiveness, routing integrity, runtime trust, and policy compliance",
        "operational_trust": "Gateway-mediated execution can be trusted because routing, authorization, policy evaluation, and runtime evidence are reconstructable."
    },
    {
        "execution_case": "A2A collaboration",
        "discovery": "A2A Connection and AI Agent inventory records",
        "visibility": "A2A visibility, agent topology, workflow visibility, and cross-agent observability",
        "governance": "Agent governance, API governance, identity governance, policy governance, and risk governance",
        "operationalization": "A2A collaboration, multi-agent execution, workflow orchestration, human approval workflow, and policy enforcement",
        "manufacturing_monitoring": "A2A collaboration monitoring, workflow execution monitoring, and runtime telemetry",
        "evidence": "Which A2A interaction occurred? Which agents participated? Which workflow executed? Which approvals occurred?",
        "continuous_assurance": "A2A interaction integrity, agent behavior, workflow integrity, runtime trust, and policy compliance",
        "operational_trust": "A2A collaboration can be trusted because agent interaction, workflow execution, approvals, and evidence are reconstructable."
    },
    {
        "execution_case": "Multi-model execution",
        "discovery": "AI Model and AI Service inventory records",
        "visibility": "Cross-model observability, model route visibility, and runtime telemetry",
        "governance": "Model governance, risk governance, compliance governance, policy governance, and executive governance where required",
        "operationalization": "Multi-model execution, model routing, runtime authorization, policy enforcement, and human approval workflow",
        "manufacturing_monitoring": "Model execution monitoring, cross-model monitoring, and runtime telemetry",
        "evidence": "Which model generated the output? Which model route was used? Which policy approved execution?",
        "continuous_assurance": "Model behavior, model route integrity, runtime trust, policy compliance, and evidence integrity",
        "operational_trust": "Multi-model execution can be trusted because model selection, routing, output generation, and policy decisions are reconstructable."
    },
    {
        "execution_case": "Digital Twin recommendation",
        "discovery": "Digital Twin inventory record",
        "visibility": "Digital Twin visibility, simulation visibility, dependency visibility, and runtime telemetry",
        "governance": "Model governance, data governance, infrastructure governance, risk governance, compliance governance, and policy governance",
        "operationalization": "Digital Twin execution, simulation approval, AI-to-Twin orchestration, human approval, and policy enforcement",
        "manufacturing_monitoring": "Digital Twin monitoring, simulation monitoring, process monitoring, and recommendation monitoring",
        "evidence": "Which Digital Twin produced the recommendation? Which simulation influenced the decision? Was the recommendation reviewed?",
        "continuous_assurance": "Digital Twin performance, simulation integrity, workflow integrity, runtime trust, and evidence integrity",
        "operational_trust": "Digital Twin recommendations can be trusted because simulations, approvals, runtime signals, and evidence are reconstructable."
    },
    {
        "execution_case": "AI-enabled CMC recommendation",
        "discovery": "AI system, AI model, AI service, data product, and workflow inventory records",
        "visibility": "AI asset visibility, workflow visibility, runtime telemetry, and dependency visibility",
        "governance": "Model governance, data governance, risk governance, compliance governance, policy governance, and executive governance where required",
        "operationalization": "Enterprise workflow execution, human approval workflow, runtime authorization, and policy enforcement",
        "manufacturing_monitoring": "Decision monitoring, workflow monitoring, runtime telemetry, and execution monitoring",
        "evidence": "Which AI recommended the formulation, CPP, CQA, regulatory content, or supply chain decision? Was it reviewed? What evidence supports the decision?",
        "continuous_assurance": "Runtime trust, evidence integrity, policy compliance, workflow integrity, and trust reconstruction",
        "operational_trust": "AI-enabled CMC decisions can be trusted because the recommendation is inventoried, visible, governed, monitored, evidenced, reviewed, and continuously assured."
    },
    {
        "execution_case": "AI-enabled supply chain decision",
        "discovery": "Supplier, raw material, inventory, cold chain, logistics, blood and biologics planning AI activity records",
        "visibility": "Supplier recommendation visibility, raw material visibility, inventory visibility, logistics visibility, workflow visibility, and dependency visibility",
        "governance": "Supplier governance, raw material governance, inventory governance, cold chain governance, logistics governance, quality risk governance, and policy governance",
        "operationalization": "Supply chain workflow execution, human approval workflow, runtime authorization, and policy enforcement",
        "manufacturing_monitoring": "Supplier recommendation monitoring, shortage prediction monitoring, inventory monitoring, cold chain execution monitoring, and logistics monitoring",
        "evidence": "Which AI recommended this supplier? Which AI predicted this shortage? Which AI optimized inventory? Was the recommendation reviewed?",
        "continuous_assurance": "Supply chain evidence integrity, recommendation trust, shortage prediction reliability, workflow integrity, and policy compliance",
        "operational_trust": "AI-enabled supply chain decisions can be trusted because decision lineage, review, evidence, monitoring, and assurance are reconstructable."
    }
]

stage_strengthening = {
    "Visibility": {
        "stage_rule": "Strengthen Visibility by linking topology, telemetry, runtime visibility, workflow visibility, dependency visibility, and observability to execution reconstruction.",
        "traceability_outputs": [
            "Execution visibility trace record",
            "Runtime telemetry trace record",
            "Workflow visibility trace record",
            "Dependency visibility trace record",
            "Cross-agent observability trace record",
            "Cross-model observability trace record"
        ]
    },
    "Governance": {
        "stage_rule": "Strengthen Governance by linking governance decisions, permissions, policies, risks, and approvals to execution reconstruction.",
        "traceability_outputs": [
            "Governance decision trace record",
            "Permission trace record",
            "Policy evaluation trace record",
            "Risk decision trace record",
            "Approval authority trace record",
            "Governance-to-execution trace record"
        ]
    },
    "Operationalization": {
        "stage_rule": "Strengthen Operationalization by linking runtime authorization, workflow execution, orchestration, human approval, and policy enforcement to evidence.",
        "traceability_outputs": [
            "Operational execution trace record",
            "Runtime authorization trace record",
            "Workflow execution trace record",
            "Orchestration trace record",
            "Human approval workflow trace record",
            "Policy enforcement trace record"
        ]
    },
    "Manufacturing Monitoring": {
        "stage_rule": "Strengthen Manufacturing Monitoring by linking execution monitoring, runtime telemetry, workflow monitoring, and decision monitoring to evidence.",
        "traceability_outputs": [
            "Execution monitoring trace record",
            "Runtime telemetry monitoring trace record",
            "Workflow monitoring trace record",
            "Decision monitoring trace record",
            "Agent monitoring trace record",
            "Model monitoring trace record"
        ]
    },
    "Evidence": {
        "stage_rule": "Strengthen Evidence by building reconstructable execution evidence across AI, model, workflow, tool, gateway, MCP, A2A, policy, approval, and outcome.",
        "traceability_outputs": [
            "Frozen lifecycle execution trace package",
            "AI actor trace evidence",
            "Model trace evidence",
            "Workflow trace evidence",
            "Tool-call trace evidence",
            "Gateway routing trace evidence",
            "MCP usage trace evidence",
            "A2A interaction trace evidence",
            "Policy evaluation trace evidence",
            "Human approval trace evidence",
            "Outcome trace evidence"
        ]
    },
    "Continuous Assurance": {
        "stage_rule": "Strengthen Continuous Assurance by continuously validating trace completeness, evidence integrity, policy compliance, workflow integrity, runtime trust, and trust reconstruction.",
        "traceability_outputs": [
            "Trace completeness validation record",
            "Evidence integrity validation record",
            "Policy compliance validation record",
            "Workflow integrity validation record",
            "Runtime trust validation record",
            "Trust reconstruction validation record"
        ]
    }
}

patch_model = {
    "patch_marker": PATCH_MARKER,
    "patch_type": "frozen_lifecycle_execution_traceability_matrix_not_new_module",
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
    "traceability_principle": traceability_principle,
    "execution_traceability_matrix": execution_traceability_matrix,
    "stage_strengthening": stage_strengthening,
    "operational_trust_rule": "Operational Trust remains unchanged as the outcome of the entire lifecycle."
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
    data["frozen_lifecycle_execution_traceability_matrix_patch"] = patch_model

    for bp in data.get("blueprints", []) or []:
        bp["frozen_lifecycle_execution_traceability"] = {
            "architecture_status": "FROZEN",
            "architecture_change": False,
            "new_module": False,
            "new_route": False,
            "lifecycle_change": False,
            "stage_strengthening_only": True,
            "traceability_principle": traceability_principle,
            "traceability_matrix_count": len(execution_traceability_matrix),
            "permanent_lifecycle": permanent_lifecycle,
            "operational_trust_unchanged": True
        }

        bp["questions_answered"] = add_unique_list(
            bp.get("questions_answered", []),
            [
                "Can the execution be traced across the frozen lifecycle?",
                "Which discovered AI asset initiated or supported execution?",
                "Which visibility signal showed execution behavior?",
                "Which governance decision permitted execution?",
                "Which operational workflow executed?",
                "Which monitoring signal confirmed runtime behavior?",
                "Which evidence record reconstructs the action?",
                "Which continuous assurance check validates trust?",
                "Can the operational trust outcome be justified from the lifecycle trace?"
            ]
        )

        assessment = bp.get("sample_blueprint_assessment", {})
        if not isinstance(assessment, dict):
            assessment = {}
        assessment["frozen_lifecycle_execution_traceability_state"] = "TRACEABILITY_MATRIX_APPLIED_NO_NEW_MODULE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["new_route"] = False
        assessment["lifecycle_change"] = False
        assessment["stage_strengthening_only"] = True
        assessment["traceability_matrix_count"] = len(execution_traceability_matrix)
        assessment["permanent_lifecycle_sequence"] = patch_model["permanent_lifecycle_sequence"]
        assessment["platform_question"] = traceability_principle["platform_question"]
        assessment["operational_trust_rule"] = patch_model["operational_trust_rule"]
        bp["sample_blueprint_assessment"] = assessment

        for stage in bp.get("lifecycle", []) or []:
            stage_name = normalize_stage_name(stage.get("stage_name", ""))
            if not stage_name:
                continue

            stage["frozen_lifecycle_traceability_guardrail"] = {
                "architecture_status": "FROZEN",
                "new_module_allowed": False,
                "new_route_allowed": False,
                "lifecycle_change_allowed": False,
                "stage_rename_allowed": False,
                "stage_strengthening_only": True
            }

            if stage_name in stage_strengthening:
                strengthening = stage_strengthening[stage_name]
                stage["frozen_lifecycle_execution_traceability"] = strengthening
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    strengthening["traceability_outputs"]
                )
                stage["operational_focus"] = strengthening["stage_rule"]

            if stage_name == "Evidence":
                stage["execution_traceability_matrix"] = execution_traceability_matrix
                stage["stage_question"] = traceability_principle["platform_question"]

            if stage_name == "Operational Trust":
                stage["operational_trust_outcome_rule"] = "Operational Trust remains the outcome of the entire lifecycle."
                stage["do_not_expand_beyond_outcome_role"] = True

    save_json(path, data)
    print("PATCHED: platform_blueprint_library_seed.json")
    return True

def patch_lifecycle_seed():
    path = Path("platform_lifecycle_integration_seed.json")
    if not path.exists():
        print("SKIP: platform_lifecycle_integration_seed.json not found.")
        return False

    data = load_json(path)
    data["frozen_lifecycle_execution_traceability_matrix_patch"] = patch_model

    assessment = data.get("sample_integration_assessment", {})
    if not isinstance(assessment, dict):
        assessment = {}

    assessment["frozen_lifecycle_execution_traceability"] = {
        "state": "TRACEABILITY_MATRIX_APPLIED_NO_NEW_MODULE",
        "architecture_status": "FROZEN",
        "architecture_change": False,
        "new_module": False,
        "new_route": False,
        "lifecycle_change": False,
        "stage_strengthening_only": True,
        "traceability_principle": traceability_principle,
        "execution_traceability_matrix": execution_traceability_matrix,
        "stage_strengthening": stage_strengthening
    }

    assessment["implementation_priority"] = add_unique_list(
        assessment.get("implementation_priority", []),
        [
            "Trace every AI-enabled execution across the frozen lifecycle.",
            "Connect discovered AI assets to visibility signals.",
            "Connect visibility signals to governance decisions.",
            "Connect governance decisions to operational execution.",
            "Connect operational execution to manufacturing monitoring.",
            "Connect monitoring signals to evidence records.",
            "Connect evidence records to continuous assurance checks.",
            "Connect continuous assurance checks to Operational Trust."
        ]
    )

    assessment["evidence_automation_targets"] = add_unique_list(
        assessment.get("evidence_automation_targets", []),
        [
            "Frozen lifecycle execution trace package",
            "AI actor trace evidence binder",
            "Model trace evidence binder",
            "Workflow trace evidence binder",
            "Tool-call trace evidence binder",
            "Gateway routing trace evidence binder",
            "MCP usage trace evidence binder",
            "A2A interaction trace evidence binder",
            "Policy evaluation trace evidence binder",
            "Human approval trace evidence binder",
            "Outcome trace evidence binder",
            "Trace completeness validation binder"
        ]
    )

    data["sample_integration_assessment"] = assessment

    lifecycle_object_map = {
        "Visibility": [
            "ExecutionVisibilityTraceRecord",
            "RuntimeTelemetryTraceRecord",
            "WorkflowVisibilityTraceRecord",
            "DependencyVisibilityTraceRecord",
            "CrossAgentObservabilityTraceRecord",
            "CrossModelObservabilityTraceRecord"
        ],
        "Governance": [
            "GovernanceDecisionTraceRecord",
            "PermissionTraceRecord",
            "PolicyEvaluationTraceRecord",
            "RiskDecisionTraceRecord",
            "ApprovalAuthorityTraceRecord",
            "GovernanceToExecutionTraceRecord"
        ],
        "Operationalization": [
            "OperationalExecutionTraceRecord",
            "RuntimeAuthorizationTraceRecord",
            "WorkflowExecutionTraceRecord",
            "OrchestrationTraceRecord",
            "HumanApprovalWorkflowTraceRecord",
            "PolicyEnforcementTraceRecord"
        ],
        "Manufacturing Monitoring": [
            "ExecutionMonitoringTraceRecord",
            "RuntimeTelemetryMonitoringTraceRecord",
            "WorkflowMonitoringTraceRecord",
            "DecisionMonitoringTraceRecord",
            "AgentMonitoringTraceRecord",
            "ModelMonitoringTraceRecord"
        ],
        "Evidence": [
            "FrozenLifecycleExecutionTracePackage",
            "AIActorTraceEvidence",
            "ModelTraceEvidence",
            "WorkflowTraceEvidence",
            "ToolCallTraceEvidence",
            "GatewayRoutingTraceEvidence",
            "MCPUsageTraceEvidence",
            "A2AInteractionTraceEvidence",
            "PolicyEvaluationTraceEvidence",
            "HumanApprovalTraceEvidence",
            "OutcomeTraceEvidence"
        ],
        "Continuous Assurance": [
            "TraceCompletenessValidationRecord",
            "EvidenceIntegrityValidationRecord",
            "PolicyComplianceValidationRecord",
            "WorkflowIntegrityValidationRecord",
            "RuntimeTrustValidationRecord",
            "TrustReconstructionValidationRecord"
        ]
    }

    for stage in data.get("integration_flow", []) or []:
        stage_name = normalize_stage_name(stage.get("stage_name", "")) or normalize_stage_name(stage.get("stage_id", ""))

        stage["frozen_lifecycle_traceability_guardrail"] = {
            "architecture_status": "FROZEN",
            "new_module_allowed": False,
            "new_route_allowed": False,
            "lifecycle_change_allowed": False,
            "stage_strengthening_only": True
        }

        if stage_name in stage_strengthening:
            strengthening = stage_strengthening[stage_name]
            stage["frozen_lifecycle_execution_traceability"] = strengthening
            stage["expected_objects"] = add_unique_list(
                stage.get("expected_objects", []),
                lifecycle_object_map.get(stage_name, [])
            )
            stage["evidence_outputs"] = add_unique_list(
                stage.get("evidence_outputs", []),
                strengthening["traceability_outputs"]
            )

        if stage_name == "Evidence":
            stage["execution_traceability_matrix"] = execution_traceability_matrix
            stage["operational_question"] = traceability_principle["platform_question"]

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
            <h2 style="margin:0;font-size:30px;">Frozen Lifecycle Execution Traceability Matrix</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Every AI-enabled execution must be reconstructable across Discovery, Visibility, Governance, Operationalization, Manufacturing Monitoring, Evidence, Continuous Assurance, and Operational Trust. No new module, route, architecture, stage, pillar, or lifecycle phase was created.
            </div>
        </div>
        <span class="tag">Traceability only</span>
    </div>
    <div class="grid">
        <div class="panel"><strong>Agent execution</strong><div>AI Agent inventory -> agent topology -> agent governance -> agent orchestration -> agent monitoring -> agent execution evidence -> agent behavior validation -> Operational Trust.</div></div>
        <div class="panel"><strong>MCP execution</strong><div>MCP Server and MCP Tool inventory -> MCP visibility -> MCP governance -> MCP integration -> MCP call monitoring -> MCP usage evidence -> MCP interaction assurance -> Operational Trust.</div></div>
        <div class="panel"><strong>AI Gateway routing</strong><div>AI Gateway inventory -> gateway visibility -> gateway governance -> gateway integration -> gateway execution monitoring -> gateway routing evidence -> gateway control assurance -> Operational Trust.</div></div>
        <div class="panel"><strong>A2A collaboration</strong><div>A2A Connection inventory -> A2A visibility -> agent and API governance -> A2A collaboration -> A2A monitoring -> A2A interaction evidence -> A2A interaction integrity -> Operational Trust.</div></div>
        <div class="panel"><strong>Multi-model execution</strong><div>AI Model inventory -> cross-model observability -> model governance -> multi-model execution -> cross-model monitoring -> model generation evidence -> runtime trust validation -> Operational Trust.</div></div>
        <div class="panel"><strong>Digital Twin recommendation</strong><div>Digital Twin inventory -> simulation visibility -> model and data governance -> simulation approval -> twin monitoring -> simulation evidence -> simulation integrity -> Operational Trust.</div></div>
        <div class="panel"><strong>AI-enabled CMC decision</strong><div>AI system inventory -> workflow visibility -> governance coordination -> enterprise workflow execution -> decision monitoring -> decision evidence -> trust reconstruction -> Operational Trust.</div></div>
        <div class="panel"><strong>Supply chain decision</strong><div>Supply chain AI activity -> supplier and workflow visibility -> supply chain governance -> supply chain workflow execution -> shortage and inventory monitoring -> decision evidence -> evidence integrity -> Operational Trust.</div></div>
    </div>
</section>
'''

platform_block = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>Frozen Lifecycle Execution Traceability Matrix</h2>
            <p>Every AI-enabled execution is now traceable from discovered AI asset to visibility signal, governance decision, operational execution, monitoring event, evidence record, continuous assurance validation, and Operational Trust outcome. No new module or architecture change.</p>
        </div>
        <span class="tag">Frozen lifecycle</span>
    </div>
    <div class="grid-4">
        <a class="card" href="/platform/blueprints/ai-enabled-cmc"><strong>AI-enabled CMC Blueprint</strong><span>Shows execution traceability for CMC, digital twin, and supply chain decisions.</span><small>Open blueprint</small></a>
        <a class="card" href="/platform/blueprints/agentic-enterprise"><strong>Agentic Enterprise Blueprint</strong><span>Shows traceability for agents, MCP, gateways, A2A, tools, models, workflows, policies, and approvals.</span><small>Open blueprint</small></a>
        <a class="card" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Maps traceability objects into the frozen lifecycle.</span><small>Open lifecycle</small></a>
        <a class="card" href="/platform/evidence-packages"><strong>Evidence</strong><span>Builds reconstructable execution evidence and trace completeness validation.</span><small>Open evidence</small></a>
    </div>
</section>
'''

library_block = r'''
<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">Blueprint Traceability Across the Frozen Lifecycle</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Blueprints may strengthen traceability only inside the existing lifecycle. Execution must be reconstructable from Discovery through Operational Trust.
            </div>
        </div>
        <span class="tag">Existing lifecycle</span>
    </div>
</section>
'''

route_registry_block = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>Frozen Lifecycle Traceability Routes</h2>
            <p>Execution traceability is exposed through existing routes only. No new module or route was added.</p>
        </div>
        <span class="tag">Existing routes only</span>
    </div>
    <div class="route-grid">
        <a class="route" href="/platform"><strong>Platform Command Center</strong><span>Shows frozen lifecycle execution traceability.</span><code>/platform</code></a>
        <a class="route" href="/platform/blueprints/ai-enabled-cmc"><strong>AI-enabled CMC Blueprint</strong><span>Displays traceability for CMC, digital twin, and supply chain decisions.</span><code>/platform/blueprints/ai-enabled-cmc</code></a>
        <a class="route" href="/platform/blueprints/agentic-enterprise"><strong>Agentic Enterprise Blueprint</strong><span>Displays traceability for agents, MCP, gateways, A2A, models, workflows, policies, and evidence.</span><code>/platform/blueprints/agentic-enterprise</code></a>
        <a class="route" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Connects traceability records to evidence automation and operational trust.</span><code>/platform/lifecycle-integration</code></a>
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

Path("frozen_lifecycle_execution_traceability_matrix_patch_v1_summary.json").write_text(
    json.dumps(patch_model, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("frozen_lifecycle_execution_traceability_matrix_patch_v1_urls.txt").write_text(
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
print("Frozen Lifecycle Execution Traceability Matrix Patch completed.")
print("Marker:")
print("  " + PATCH_MARKER)
print("No new module. No new route. No architecture change. Lifecycle unchanged.")
