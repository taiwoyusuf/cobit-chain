from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_AI_RUNTIME_GOVERNANCE_OPERATIONALIZATION_PATCH_V1_ACTIVE"

locked_lifecycle = [
    "Discovery",
    "Visibility",
    "Governance",
    "Operationalization",
    "Manufacturing Monitoring",
    "Evidence",
    "Continuous Assurance",
    "Operational Trust"
]

ai_execution_governance = [
    "Agent execution policies",
    "Workflow orchestration",
    "Tool authorization",
    "Permission management",
    "Secure runtime policies",
    "Runtime isolation",
    "Sandbox execution",
    "Zero-trust execution",
    "Action authorization",
    "Agent escalation policies"
]

ai_infrastructure_governance = [
    "AI runtimes",
    "AI Control Towers",
    "Agent runtimes",
    "GPU infrastructure",
    "Inference infrastructure",
    "AI gateways",
    "AI workflow engines"
]

manufacturing_runtime_monitoring = [
    "Agent execution",
    "Workflow execution",
    "Runtime events",
    "Tool calls",
    "Policy violations",
    "Human interventions",
    "Runtime exceptions"
]

runtime_evidence_capture = [
    "Runtime evidence",
    "Agent execution logs",
    "Tool-call evidence",
    "Workflow evidence",
    "Runtime authorization evidence",
    "Human approval evidence",
    "Policy evaluation evidence",
    "Audit evidence"
]

runtime_governance_traceability = [
    {
        "governance_area": "Agent execution policies",
        "operationalization_question": "Are agent execution policies approved before agents operate in regulated or enterprise workflows?",
        "monitoring_signal": "Agent execution event",
        "evidence_expected": "Agent execution policy record",
        "trust_impact": "Confirms agent behavior is governed before execution."
    },
    {
        "governance_area": "Workflow orchestration",
        "operationalization_question": "Is workflow orchestration controlled, sequenced, and reviewable?",
        "monitoring_signal": "Workflow execution event",
        "evidence_expected": "Workflow orchestration record",
        "trust_impact": "Confirms AI-enabled workflow execution can be reconstructed."
    },
    {
        "governance_area": "Tool authorization",
        "operationalization_question": "Was tool access authorized before the AI or agent invoked the tool?",
        "monitoring_signal": "Tool-call event",
        "evidence_expected": "Tool authorization record",
        "trust_impact": "Confirms tools are not used outside approved authority."
    },
    {
        "governance_area": "Permission management",
        "operationalization_question": "Were permissions aligned to role, context, risk, and intended use?",
        "monitoring_signal": "Permission evaluation event",
        "evidence_expected": "Permission management record",
        "trust_impact": "Confirms execution authority is bounded."
    },
    {
        "governance_area": "Secure runtime policies",
        "operationalization_question": "Were secure runtime policies evaluated before and during execution?",
        "monitoring_signal": "Runtime policy evaluation event",
        "evidence_expected": "Secure runtime policy record",
        "trust_impact": "Confirms runtime behavior is policy-governed."
    },
    {
        "governance_area": "Runtime isolation",
        "operationalization_question": "Was the runtime isolated based on risk, function criticality, and execution scope?",
        "monitoring_signal": "Runtime isolation status",
        "evidence_expected": "Runtime isolation evidence",
        "trust_impact": "Confirms execution boundaries are maintained."
    },
    {
        "governance_area": "Sandbox execution",
        "operationalization_question": "Was sandbox execution required before production or regulated workflow execution?",
        "monitoring_signal": "Sandbox execution result",
        "evidence_expected": "Sandbox execution evidence",
        "trust_impact": "Confirms risky execution paths are tested before release."
    },
    {
        "governance_area": "Zero-trust execution",
        "operationalization_question": "Was every action evaluated under least privilege, context, identity, and policy?",
        "monitoring_signal": "Zero-trust authorization event",
        "evidence_expected": "Zero-trust execution evidence",
        "trust_impact": "Confirms execution is continuously authorized, not assumed."
    },
    {
        "governance_area": "Action authorization",
        "operationalization_question": "Was the action authorized before execution?",
        "monitoring_signal": "Action authorization event",
        "evidence_expected": "Runtime authorization evidence",
        "trust_impact": "Confirms consequential actions are approved or policy-authorized."
    },
    {
        "governance_area": "Agent escalation policies",
        "operationalization_question": "Did agent behavior escalate to a human when required?",
        "monitoring_signal": "Human intervention or escalation event",
        "evidence_expected": "Agent escalation and human approval evidence",
        "trust_impact": "Confirms human accountability is preserved."
    },
    {
        "governance_area": "AI infrastructure governance",
        "operationalization_question": "Are AI runtimes, AI Control Towers, agent runtimes, GPU infrastructure, inference infrastructure, AI gateways, and AI workflow engines governed as execution infrastructure?",
        "monitoring_signal": "AI runtime and infrastructure governance status",
        "evidence_expected": "AI infrastructure governance record",
        "trust_impact": "Confirms this is governance of AI infrastructure, not infrastructure engineering."
    }
]

runtime_governance_patch = {
    "patch_marker": PATCH_MARKER,
    "patch_type": "ai_runtime_governance_operationalization_enrichment_not_new_module",
    "architecture_change": False,
    "new_module": False,
    "new_route": False,
    "lifecycle_change": False,
    "locked_lifecycle": locked_lifecycle,
    "platform_rule": "No new module. No new architecture. No lifecycle change. Enrich existing Operationalization, Manufacturing Monitoring, and Evidence only.",
    "operationalization_enrichment": {
        "AI Execution Governance": ai_execution_governance,
        "AI Infrastructure Governance": ai_infrastructure_governance,
        "distinction": "This is not infrastructure engineering. It is governance of AI infrastructure."
    },
    "manufacturing_monitoring_enrichment": manufacturing_runtime_monitoring,
    "evidence_enrichment": runtime_evidence_capture,
    "runtime_governance_traceability": runtime_governance_traceability,
    "platform_question": "Were agent execution, workflow execution, tool use, runtime authorization, policy evaluation, human intervention, and runtime exceptions governed, monitored, and evidenced before operational trust was claimed?"
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

def patch_blueprint_seed():
    path = Path("platform_blueprint_library_seed.json")
    if not path.exists():
        print("SKIP: platform_blueprint_library_seed.json not found.")
        return False

    data = load_json(path)
    data["ai_runtime_governance_operationalization_patch"] = runtime_governance_patch

    for bp in data.get("blueprints", []) or []:
        bp["ai_runtime_governance_operationalization_patch"] = {
            "architecture_change": False,
            "new_module": False,
            "new_route": False,
            "lifecycle_change": False,
            "distinction": "This is not infrastructure engineering. It is governance of AI infrastructure."
        }

        bp["questions_answered"] = add_unique_list(
            bp.get("questions_answered", []),
            [
                "Were agent execution policies governed before execution?",
                "Was workflow orchestration approved and monitored?",
                "Were tools authorized before use?",
                "Were runtime permissions evaluated?",
                "Were secure runtime policies enforced?",
                "Was runtime isolation or sandbox execution required?",
                "Was zero-trust execution applied?",
                "Were consequential actions authorized?",
                "Were agent escalation policies applied?",
                "Were AI runtimes, AI Control Towers, agent runtimes, GPU infrastructure, inference infrastructure, AI gateways, and AI workflow engines governed?"
            ]
        )

        assessment = bp.get("sample_blueprint_assessment", {})
        assessment["ai_runtime_governance_state"] = "AI_RUNTIME_GOVERNANCE_CONNECTED_TO_EXISTING_OPERATIONALIZATION_MONITORING_AND_EVIDENCE_STAGES"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["new_route"] = False
        assessment["lifecycle_change"] = False
        assessment["ai_execution_governance_count"] = len(ai_execution_governance)
        assessment["ai_infrastructure_governance_count"] = len(ai_infrastructure_governance)
        assessment["runtime_monitoring_signal_count"] = len(manufacturing_runtime_monitoring)
        assessment["runtime_evidence_capture_count"] = len(runtime_evidence_capture)
        assessment["runtime_governance_next_actions"] = [
            "Bind agent execution policies to execution events.",
            "Bind workflow orchestration records to workflow execution events.",
            "Bind tool authorization records to tool-call evidence.",
            "Bind permission management and action authorization records to runtime authorization evidence.",
            "Bind secure runtime policy evaluations to policy evaluation evidence.",
            "Bind human interventions to escalation and approval evidence.",
            "Bind runtime exceptions to audit evidence and continuous assurance."
        ]
        bp["sample_blueprint_assessment"] = assessment

        for stage in bp.get("lifecycle", []) or []:
            stage_name = stage.get("stage_name", "")

            if stage_name == "Operationalization":
                stage["ai_runtime_governance"] = runtime_governance_patch["operationalization_enrichment"]
                stage["ai_execution_governance"] = ai_execution_governance
                stage["ai_infrastructure_governance"] = ai_infrastructure_governance
                stage["runtime_governance_traceability"] = runtime_governance_traceability
                stage["stage_question"] = (
                    "Were agent execution policies, workflow orchestration, tool authorization, permission management, secure runtime policies, runtime isolation, sandbox execution, zero-trust execution, action authorization, agent escalation policies, and AI infrastructure governance approved before execution?"
                )
                stage["operational_focus"] = (
                    "Operationalization now governs AI execution and AI infrastructure: agent execution policies, workflow orchestration, tool authorization, permission management, secure runtime policies, runtime isolation, sandbox execution, zero-trust execution, action authorization, agent escalation policies, AI runtimes, AI Control Towers, agent runtimes, GPU infrastructure, inference infrastructure, AI gateways, and AI workflow engines. This is governance of AI infrastructure, not infrastructure engineering."
                )
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    [
                        "Agent execution policy record",
                        "Workflow orchestration record",
                        "Tool authorization record",
                        "Permission management record",
                        "Secure runtime policy record",
                        "Runtime isolation evidence",
                        "Sandbox execution evidence",
                        "Zero-trust execution evidence",
                        "Action authorization record",
                        "Agent escalation policy record",
                        "AI runtime governance record",
                        "AI Control Tower governance record",
                        "Agent runtime governance record",
                        "GPU infrastructure governance record",
                        "Inference infrastructure governance record",
                        "AI gateway governance record",
                        "AI workflow engine governance record"
                    ]
                )

            if stage_name == "Manufacturing Monitoring":
                stage["ai_runtime_monitoring"] = manufacturing_runtime_monitoring
                stage["stage_question"] = (
                    "Are agent execution, workflow execution, runtime events, tool calls, policy violations, human interventions, and runtime exceptions monitored?"
                )
                stage["operational_focus"] = (
                    "Manufacturing Monitoring now explicitly monitors agent execution, workflow execution, runtime events, tool calls, policy violations, human interventions, and runtime exceptions."
                )
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    [
                        "Agent execution monitoring record",
                        "Workflow execution monitoring record",
                        "Runtime event monitoring record",
                        "Tool-call monitoring record",
                        "Policy violation monitoring record",
                        "Human intervention monitoring record",
                        "Runtime exception monitoring record"
                    ]
                )

            if stage_name == "Evidence":
                stage["ai_runtime_evidence_capture"] = runtime_evidence_capture
                stage["stage_question"] = (
                    "Can runtime evidence, agent execution logs, tool-call evidence, workflow evidence, runtime authorization evidence, human approval evidence, policy evaluation evidence, and audit evidence be reconstructed?"
                )
                stage["operational_focus"] = (
                    "Evidence now captures runtime evidence, agent execution logs, tool-call evidence, workflow evidence, runtime authorization evidence, human approval evidence, policy evaluation evidence, and audit evidence."
                )
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    runtime_evidence_capture + [
                        "Runtime replay package",
                        "Agent execution evidence package",
                        "Tool-call lineage evidence package",
                        "Policy evaluation audit package",
                        "Runtime authorization audit package"
                    ]
                )

            if stage_name == "Continuous Assurance":
                stage["ai_runtime_assurance_inputs"] = add_unique_list(
                    stage.get("ai_runtime_assurance_inputs", []),
                    manufacturing_runtime_monitoring + runtime_evidence_capture
                )
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    [
                        "Runtime assurance review record",
                        "Runtime exception assurance record",
                        "Policy violation assurance record",
                        "Human intervention assurance record"
                    ]
                )

            if stage_name == "Operational Trust":
                stage["ai_runtime_trust_inputs"] = add_unique_list(
                    stage.get("ai_runtime_trust_inputs", []),
                    [
                        "Agent execution status",
                        "Workflow execution status",
                        "Tool authorization status",
                        "Runtime authorization status",
                        "Policy evaluation status",
                        "Human intervention status",
                        "Runtime exception status"
                    ]
                )
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    [
                        "Runtime operational trust record",
                        "Agent execution trust impact record",
                        "Tool-call trust impact record",
                        "Policy violation trust impact record"
                    ]
                )

    save_json(path, data)
    print("PATCHED: platform_blueprint_library_seed.json")
    return True

def patch_lifecycle_seed():
    path = Path("platform_lifecycle_integration_seed.json")
    if not path.exists():
        print("SKIP: platform_lifecycle_integration_seed.json not found.")
        return False

    data = load_json(path)
    data["ai_runtime_governance_operationalization_patch"] = runtime_governance_patch

    assessment = data.get("sample_integration_assessment", {})
    assessment["ai_runtime_governance"] = {
        "state": "AI_RUNTIME_GOVERNANCE_CONNECTED_TO_EXISTING_LIFECYCLE",
        "architecture_change": False,
        "new_module": False,
        "new_route": False,
        "lifecycle_change": False,
        "ai_execution_governance": ai_execution_governance,
        "ai_infrastructure_governance": ai_infrastructure_governance,
        "manufacturing_runtime_monitoring": manufacturing_runtime_monitoring,
        "runtime_evidence_capture": runtime_evidence_capture,
        "distinction": "This is not infrastructure engineering. It is governance of AI infrastructure."
    }

    assessment["evidence_automation_targets"] = add_unique_list(
        assessment.get("evidence_automation_targets", []),
        [
            "Agent execution log binder",
            "Workflow evidence binder",
            "Tool-call evidence binder",
            "Runtime authorization evidence binder",
            "Human approval evidence binder",
            "Policy evaluation evidence binder",
            "Runtime exception evidence binder",
            "Audit evidence binder"
        ]
    )

    data["sample_integration_assessment"] = assessment

    runtime_objects = [
        "AgentExecutionPolicyRecord",
        "WorkflowOrchestrationRecord",
        "ToolAuthorizationRecord",
        "PermissionManagementRecord",
        "SecureRuntimePolicyRecord",
        "RuntimeIsolationEvidence",
        "SandboxExecutionEvidence",
        "ZeroTrustExecutionEvidence",
        "ActionAuthorizationRecord",
        "AgentEscalationPolicyRecord",
        "AIRuntimeGovernanceRecord",
        "AIControlTowerGovernanceRecord",
        "AgentRuntimeGovernanceRecord",
        "GPUInfrastructureGovernanceRecord",
        "InferenceInfrastructureGovernanceRecord",
        "AIGatewayGovernanceRecord",
        "AIWorkflowEngineGovernanceRecord",
        "AgentExecutionLog",
        "WorkflowEvidence",
        "ToolCallEvidence",
        "RuntimeAuthorizationEvidence",
        "HumanApprovalEvidence",
        "PolicyEvaluationEvidence",
        "AuditEvidence"
    ]

    for stage in data.get("integration_flow", []) or []:
        stage_id = stage.get("stage_id", "")

        if stage_id in ["governance_operationalization", "workflow_intake", "output_clearance", "decision_approval_release"]:
            stage["ai_runtime_governance"] = runtime_governance_patch["operationalization_enrichment"]
            stage["runtime_governance_traceability"] = runtime_governance_traceability
            stage["expected_objects"] = add_unique_list(stage.get("expected_objects", []), runtime_objects)
            stage["evidence_outputs"] = add_unique_list(
                stage.get("evidence_outputs", []),
                [
                    "Agent execution policy record",
                    "Workflow orchestration record",
                    "Tool authorization record",
                    "Permission management record",
                    "Secure runtime policy record",
                    "Runtime isolation evidence",
                    "Sandbox execution evidence",
                    "Zero-trust execution evidence",
                    "Action authorization record",
                    "Agent escalation policy record",
                    "AI runtime governance record",
                    "AI Control Tower governance record",
                    "Agent runtime governance record",
                    "GPU infrastructure governance record",
                    "Inference infrastructure governance record",
                    "AI gateway governance record",
                    "AI workflow engine governance record"
                ]
            )

        if stage_id in ["evidence_contract", "monitoring_response_learning"]:
            stage["ai_runtime_monitoring"] = manufacturing_runtime_monitoring
            stage["ai_runtime_evidence_capture"] = runtime_evidence_capture
            stage["expected_objects"] = add_unique_list(stage.get("expected_objects", []), runtime_objects)
            stage["evidence_outputs"] = add_unique_list(
                stage.get("evidence_outputs", []),
                runtime_evidence_capture + [
                    "Agent execution monitoring record",
                    "Workflow execution monitoring record",
                    "Runtime event monitoring record",
                    "Tool-call monitoring record",
                    "Policy violation monitoring record",
                    "Human intervention monitoring record",
                    "Runtime exception monitoring record"
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

blueprint_runtime_block = r'''
<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">AI Runtime Governance in Operationalization</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Operationalization now explicitly governs AI Execution Governance: agent execution policies, workflow orchestration, tool authorization, permission management, secure runtime policies, runtime isolation, sandbox execution, zero-trust execution, action authorization, and agent escalation policies.
            </div>
        </div>
        <span class="tag">No new module</span>
    </div>
    <div class="grid">
        <div class="panel"><strong>AI Infrastructure Governance</strong><div>Governance now covers AI runtimes, AI Control Towers, agent runtimes, GPU infrastructure, inference infrastructure, AI gateways, and AI workflow engines.</div></div>
        <div class="panel"><strong>Important Boundary</strong><div>This is not infrastructure engineering. It is governance of AI infrastructure.</div></div>
    </div>
</section>

<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">AI Runtime Monitoring</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Manufacturing Monitoring now explicitly monitors agent execution, workflow execution, runtime events, tool calls, policy violations, human interventions, and runtime exceptions.
            </div>
        </div>
        <span class="tag">Monitoring enriched</span>
    </div>
</section>

<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">AI Runtime Evidence Capture</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Evidence now captures runtime evidence, agent execution logs, tool-call evidence, workflow evidence, runtime authorization evidence, human approval evidence, policy evaluation evidence, and audit evidence.
            </div>
        </div>
        <span class="tag">Evidence enriched</span>
    </div>
</section>
'''

platform_block = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>AI Runtime Governance Operationalization</h2>
            <p>Operationalization now governs AI execution and AI infrastructure without creating a new module. This includes agent execution policies, workflow orchestration, tool authorization, permission management, secure runtime policies, runtime isolation, sandbox execution, zero-trust execution, action authorization, escalation policies, AI runtimes, AI Control Towers, agent runtimes, GPU infrastructure, inference infrastructure, AI gateways, and AI workflow engines.</p>
        </div>
        <span class="tag">Existing lifecycle</span>
    </div>
    <div class="grid-4">
        <a class="card" href="/platform/blueprints/ai-enabled-cmc"><strong>CMC Runtime Governance</strong><span>Operationalization, Manufacturing Monitoring, and Evidence now include runtime governance, monitoring, and evidence capture.</span><small>Open CMC blueprint</small></a>
        <a class="card" href="/platform/blueprints/agentic-enterprise"><strong>Agentic Runtime Governance</strong><span>Agent execution, workflow execution, tool authorization, escalation, and runtime exceptions are governed and evidenced.</span><small>Open Agentic blueprint</small></a>
        <a class="card" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Runtime governance binds to existing lifecycle integration, evidence automation, and operational trust.</span><small>Open lifecycle</small></a>
        <a class="card" href="/platform/evidence-packages"><strong>Evidence Vault</strong><span>Captures runtime evidence, agent execution logs, tool-call evidence, workflow evidence, runtime authorization evidence, and audit evidence.</span><small>Open evidence</small></a>
    </div>
</section>
'''

route_registry_block = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>AI Runtime Governance Enrichment</h2>
            <p>AI runtime governance was added to existing Operationalization, Manufacturing Monitoring, and Evidence stages. This is not a new module, new route, or architecture change.</p>
        </div>
        <span class="tag">No new route</span>
    </div>
    <div class="route-grid">
        <a class="route" href="/platform/blueprints/ai-enabled-cmc"><strong>AI-enabled CMC Blueprint</strong><span>Includes AI execution governance, AI infrastructure governance, runtime monitoring, and runtime evidence capture inside the existing lifecycle.</span><code>/platform/blueprints/ai-enabled-cmc</code></a>
        <a class="route" href="/platform/blueprints/agentic-enterprise"><strong>Agentic Enterprise Blueprint</strong><span>Includes agent execution policies, workflow orchestration, tool authorization, permission management, runtime isolation, escalation, monitoring, and evidence capture.</span><code>/platform/blueprints/agentic-enterprise</code></a>
        <a class="route" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Runtime governance evidence objects connect to the existing lifecycle integration model.</span><code>/platform/lifecycle-integration</code></a>
        <a class="route" href="/api/platform/blueprints/model/demo"><strong>Blueprint API</strong><span>Existing API returns ai_runtime_governance_operationalization_patch fields.</span><code>/api/platform/blueprints/model/demo</code></a>
    </div>
</section>
'''

patch_blueprint_seed()
patch_lifecycle_seed()

patch_html(
    "platform_ai_enabled_cmc_blueprint.html",
    blueprint_runtime_block,
    "<div class=\"footer\">"
)

patch_html(
    "platform_agentic_enterprise_blueprint.html",
    blueprint_runtime_block,
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

summary = {
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "new_module": False,
    "new_route": False,
    "lifecycle_change": False,
    "locked_lifecycle": locked_lifecycle,
    "ai_execution_governance": ai_execution_governance,
    "ai_infrastructure_governance": ai_infrastructure_governance,
    "manufacturing_runtime_monitoring": manufacturing_runtime_monitoring,
    "runtime_evidence_capture": runtime_evidence_capture,
    "runtime_governance_traceability": runtime_governance_traceability,
    "distinction": "This is not infrastructure engineering. It is governance of AI infrastructure."
}

Path("ai_runtime_governance_operationalization_patch_v1_summary.json").write_text(
    json.dumps(summary, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("ai_runtime_governance_operationalization_patch_v1_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform",
        "http://127.0.0.1:5000/platform/routes",
        "http://127.0.0.1:5000/platform/blueprints/ai-enabled-cmc",
        "http://127.0.0.1:5000/platform/blueprints/agentic-enterprise",
        "http://127.0.0.1:5000/platform/lifecycle-integration",
        "http://127.0.0.1:5000/platform/evidence-packages",
        "http://127.0.0.1:5000/api/platform/blueprints/model/demo",
        "http://127.0.0.1:5000/api/platform/blueprints/ai-enabled-cmc/demo",
        "http://127.0.0.1:5000/api/platform/blueprints/agentic-enterprise/demo",
        "http://127.0.0.1:5000/api/platform/lifecycle-integration/model/demo"
    ]),
    encoding="utf-8"
)

print("")
print("AI Runtime Governance Operationalization Patch completed.")
print("Marker:")
print("  " + PATCH_MARKER)
print("No new module. No new route. No architecture change. Lifecycle unchanged.")
