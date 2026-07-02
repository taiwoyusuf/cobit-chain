from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_GOVERNANCE_STACK_COORDINATION_PATCH_V1_ACTIVE"

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

governance_stack_domains = [
    "Infrastructure governance",
    "Data governance",
    "Model governance",
    "Identity governance",
    "Risk governance",
    "Compliance governance",
    "Policy governance",
    "Executive governance"
]

governance_coordination_inputs = [
    "Inventories",
    "Permissions",
    "Observability",
    "Telemetry",
    "Policy enforcement"
]

governance_stack_coordination = [
    {
        "domain": "Infrastructure governance",
        "coordinates": "AI runtimes, compute, network, gateway, execution environment, resiliency, and infrastructure guardrails.",
        "uses": ["AI inventories", "runtime telemetry", "gateway visibility", "execution visibility"],
        "handoff_to_operationalization": "Approved runtime constraints, gateway controls, infrastructure readiness, and execution environment boundaries.",
        "continuous_assurance_signal": "Infrastructure drift, runtime exceptions, access anomalies, resiliency events, and environment control failures."
    },
    {
        "domain": "Data governance",
        "coordinates": "Data products, context sources, lineage, quality, retention, privacy, and regulated data-use boundaries.",
        "uses": ["data product inventory", "context visibility", "workflow visibility", "telemetry"],
        "handoff_to_operationalization": "Approved data sources, context boundaries, retrieval limits, retention rules, and data-use constraints.",
        "continuous_assurance_signal": "Data drift, lineage gaps, unapproved context use, quality exceptions, privacy exceptions, and retention gaps."
    },
    {
        "domain": "Model governance",
        "coordinates": "AI models, model versions, intended use, model routing, performance limits, approved model use, and model-change controls.",
        "uses": ["AI model inventory", "cross-model observability", "runtime telemetry", "policy enforcement"],
        "handoff_to_operationalization": "Approved model routes, model-use constraints, model version controls, and model risk thresholds.",
        "continuous_assurance_signal": "Model drift, performance degradation, model route exceptions, version mismatch, and intended-use boundary crossing."
    },
    {
        "domain": "Identity governance",
        "coordinates": "Agent identity, human identity, service identity, tool permissions, API permissions, approval authority, and runtime authorization.",
        "uses": ["agent inventory", "tool inventory", "permissions", "runtime authorization evidence"],
        "handoff_to_operationalization": "Approved identities, least-privilege permissions, approval roles, runtime authorization rules, and escalation paths.",
        "continuous_assurance_signal": "Unauthorized action attempts, permission drift, orphaned identities, approval gaps, and privilege exceptions."
    },
    {
        "domain": "Risk governance",
        "coordinates": "Risk classification, process risk, AI risk, operational risk, supplier or workflow risk, residual risk, and risk acceptance.",
        "uses": ["risk classification", "inventories", "observability", "telemetry", "evidence records"],
        "handoff_to_operationalization": "Risk-based control requirements, approval thresholds, testing rigor, monitoring requirements, and residual risk decisions.",
        "continuous_assurance_signal": "Risk threshold breach, risk acceptance expiry, emerging risk, high-risk execution, and unresolved exceptions."
    },
    {
        "domain": "Compliance governance",
        "coordinates": "Regulatory obligations, framework mappings, GxP expectations, internal SOPs, validation expectations, and audit readiness.",
        "uses": ["control mappings", "policy enforcement", "evidence packages", "audit telemetry"],
        "handoff_to_operationalization": "Mapped compliance controls, required evidence objects, review requirements, and audit-ready execution constraints.",
        "continuous_assurance_signal": "Control gaps, evidence gaps, SOP deviation, validation evidence gap, and audit readiness deterioration."
    },
    {
        "domain": "Policy governance",
        "coordinates": "Execution policies, routing policies, tool-use policies, approval policies, escalation policies, monitoring policies, and exception policies.",
        "uses": ["policy library", "policy evaluation records", "permissions", "runtime telemetry"],
        "handoff_to_operationalization": "Approved runtime policies, policy enforcement rules, exception paths, approval gates, and policy evaluation requirements.",
        "continuous_assurance_signal": "Policy violation, policy bypass, exception misuse, policy conflict, and policy enforcement failure."
    },
    {
        "domain": "Executive governance",
        "coordinates": "Decision rights, accountability, risk appetite, funding priorities, enterprise oversight, escalation authority, and operational trust decisions.",
        "uses": ["trust scores", "risk posture", "evidence summaries", "exception trends", "continuous assurance signals"],
        "handoff_to_operationalization": "Executive thresholds, accountability mapping, escalation criteria, decision rights, and operational release expectations.",
        "continuous_assurance_signal": "Trust score deterioration, unresolved enterprise risk, recurring exceptions, major control failure, and high-impact assurance breakdown."
    }
]

governance_stage_enrichment = {
    "stage_rule": "Governance is the coordination layer for the enterprise AI governance stack.",
    "coordination_principle": "Governance is the coordination point. The governance stack feeds Operationalization, Manufacturing Monitoring, Evidence, Continuous Assurance, and Operational Trust.",
    "governance_stack_domains": governance_stack_domains,
    "uses": governance_coordination_inputs,
    "stage_question": "Are infrastructure, data, model, identity, risk, compliance, policy, and executive governance coordinated using inventories, permissions, observability, telemetry, and policy enforcement before AI-enabled execution flows into Operationalization?",
    "coordination_records": [
        "Infrastructure governance alignment record",
        "Data governance alignment record",
        "Model governance alignment record",
        "Identity governance alignment record",
        "Risk governance alignment record",
        "Compliance governance alignment record",
        "Policy governance alignment record",
        "Executive governance alignment record",
        "Governance stack coordination record",
        "Governance-to-operationalization handoff record",
        "Governance-to-continuous-assurance signal record"
    ],
    "coordination_model": governance_stack_coordination
}

operationalization_handoff = [
    "Infrastructure runtime constraints",
    "Approved data and context boundaries",
    "Approved model routes",
    "Identity and permission rules",
    "Risk-based control requirements",
    "Compliance evidence requirements",
    "Runtime policy enforcement rules",
    "Executive escalation thresholds"
]

continuous_assurance_signals = [
    "Infrastructure drift",
    "Data drift",
    "Model drift",
    "Permission drift",
    "Risk threshold breach",
    "Compliance evidence gap",
    "Policy violation",
    "Executive escalation event"
]

patch_model = {
    "patch_marker": PATCH_MARKER,
    "patch_type": "governance_stack_coordination_not_new_module",
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
    "strengthened_stage": "Governance",
    "governance_stage_enrichment": governance_stage_enrichment,
    "operationalization_handoff": operationalization_handoff,
    "continuous_assurance_signals": continuous_assurance_signals,
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
    data["governance_stack_coordination_patch"] = patch_model

    for bp in data.get("blueprints", []) or []:
        bp["governance_stack_coordination"] = {
            "architecture_status": "FROZEN",
            "architecture_change": False,
            "new_module": False,
            "new_route": False,
            "lifecycle_change": False,
            "stage_strengthening_only": True,
            "strengthened_stage": "Governance",
            "governance_stack_domains": governance_stack_domains,
            "uses": governance_coordination_inputs,
            "coordination_principle": governance_stage_enrichment["coordination_principle"],
            "operational_trust_unchanged": True
        }

        bp["questions_answered"] = add_unique_list(
            bp.get("questions_answered", []),
            [
                "Are infrastructure, data, model, identity, risk, compliance, policy, and executive governance coordinated?",
                "Which inventories, permissions, observability signals, telemetry, and policy enforcement records informed governance?",
                "What governance stack handoff was sent into Operationalization?",
                "What governance signals must be monitored through Continuous Assurance?",
                "Can the governance stack explain why the AI-enabled execution was permitted?"
            ]
        )

        assessment = bp.get("sample_blueprint_assessment", {})
        if not isinstance(assessment, dict):
            assessment = {}

        assessment["governance_stack_coordination_state"] = "GOVERNANCE_STAGE_STRENGTHENED_NO_NEW_MODULE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["new_route"] = False
        assessment["lifecycle_change"] = False
        assessment["stage_strengthening_only"] = True
        assessment["strengthened_stage"] = "Governance"
        assessment["governance_stack_domain_count"] = len(governance_stack_domains)
        assessment["permanent_lifecycle_sequence"] = patch_model["permanent_lifecycle_sequence"]
        assessment["operational_trust_rule"] = patch_model["operational_trust_rule"]
        bp["sample_blueprint_assessment"] = assessment

        for stage in bp.get("lifecycle", []) or []:
            stage_name = normalize_stage_name(stage.get("stage_name", ""))
            if not stage_name:
                continue

            stage["governance_stack_coordination_guardrail"] = {
                "architecture_status": "FROZEN",
                "new_module_allowed": False,
                "new_route_allowed": False,
                "lifecycle_change_allowed": False,
                "stage_rename_allowed": False,
                "stage_strengthening_only": True
            }

            if stage_name == "Governance":
                stage["governance_stack_coordination"] = governance_stage_enrichment
                stage["governance_stack_domains"] = governance_stack_domains
                stage["governance_coordination_inputs"] = governance_coordination_inputs
                stage["governance_stack_coordination_model"] = governance_stack_coordination
                stage["stage_question"] = governance_stage_enrichment["stage_question"]
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    governance_stage_enrichment["coordination_records"]
                )
                stage["operational_focus"] = "Governance coordinates infrastructure, data, model, identity, risk, compliance, policy, and executive governance using inventories, permissions, observability, telemetry, and policy enforcement."

            if stage_name == "Operationalization":
                stage["governance_stack_handoff_inputs"] = add_unique_list(
                    stage.get("governance_stack_handoff_inputs", []),
                    operationalization_handoff
                )
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    [
                        "Governance stack handoff record",
                        "Governance-to-operationalization control record",
                        "Runtime policy handoff record",
                        "Permission handoff record",
                        "Risk-based operationalization handoff record"
                    ]
                )

            if stage_name == "Continuous Assurance":
                stage["governance_stack_continuous_assurance_signals"] = add_unique_list(
                    stage.get("governance_stack_continuous_assurance_signals", []),
                    continuous_assurance_signals
                )
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    [
                        "Governance stack continuous assurance signal record",
                        "Governance signal monitoring record",
                        "Policy compliance signal record",
                        "Risk escalation signal record",
                        "Executive escalation signal record"
                    ]
                )

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
    data["governance_stack_coordination_patch"] = patch_model

    assessment = data.get("sample_integration_assessment", {})
    if not isinstance(assessment, dict):
        assessment = {}

    assessment["governance_stack_coordination"] = {
        "state": "GOVERNANCE_STAGE_STRENGTHENED_NO_NEW_MODULE",
        "architecture_status": "FROZEN",
        "architecture_change": False,
        "new_module": False,
        "new_route": False,
        "lifecycle_change": False,
        "stage_strengthening_only": True,
        "strengthened_stage": "Governance",
        "governance_stack_domains": governance_stack_domains,
        "coordination_inputs": governance_coordination_inputs,
        "governance_stack_coordination_model": governance_stack_coordination,
        "operationalization_handoff": operationalization_handoff,
        "continuous_assurance_signals": continuous_assurance_signals
    }

    assessment["implementation_priority"] = add_unique_list(
        assessment.get("implementation_priority", []),
        [
            "Strengthen Governance as the coordination layer for infrastructure governance.",
            "Strengthen Governance as the coordination layer for data governance.",
            "Strengthen Governance as the coordination layer for model governance.",
            "Strengthen Governance as the coordination layer for identity governance.",
            "Strengthen Governance as the coordination layer for risk governance.",
            "Strengthen Governance as the coordination layer for compliance governance.",
            "Strengthen Governance as the coordination layer for policy governance.",
            "Strengthen Governance as the coordination layer for executive governance.",
            "Use inventories, permissions, observability, telemetry, and policy enforcement as governance coordination inputs.",
            "Feed governance handoffs into Operationalization and governance signals into Continuous Assurance.",
            "Keep Operational Trust unchanged as the lifecycle outcome."
        ]
    )

    assessment["evidence_automation_targets"] = add_unique_list(
        assessment.get("evidence_automation_targets", []),
        [
            "Governance stack coordination evidence binder",
            "Infrastructure governance alignment evidence binder",
            "Data governance alignment evidence binder",
            "Model governance alignment evidence binder",
            "Identity governance alignment evidence binder",
            "Risk governance alignment evidence binder",
            "Compliance governance alignment evidence binder",
            "Policy governance alignment evidence binder",
            "Executive governance alignment evidence binder",
            "Governance-to-operationalization handoff evidence binder",
            "Governance-to-continuous-assurance signal evidence binder"
        ]
    )

    data["sample_integration_assessment"] = assessment

    lifecycle_object_map = {
        "Governance": [
            "InfrastructureGovernanceAlignmentRecord",
            "DataGovernanceAlignmentRecord",
            "ModelGovernanceAlignmentRecord",
            "IdentityGovernanceAlignmentRecord",
            "RiskGovernanceAlignmentRecord",
            "ComplianceGovernanceAlignmentRecord",
            "PolicyGovernanceAlignmentRecord",
            "ExecutiveGovernanceAlignmentRecord",
            "GovernanceStackCoordinationRecord",
            "GovernanceToOperationalizationHandoffRecord",
            "GovernanceToContinuousAssuranceSignalRecord"
        ],
        "Operationalization": [
            "GovernanceStackHandoffRecord",
            "GovernanceToOperationalizationControlRecord",
            "RuntimePolicyHandoffRecord",
            "PermissionHandoffRecord",
            "RiskBasedOperationalizationHandoffRecord"
        ],
        "Continuous Assurance": [
            "GovernanceStackContinuousAssuranceSignalRecord",
            "GovernanceSignalMonitoringRecord",
            "PolicyComplianceSignalRecord",
            "RiskEscalationSignalRecord",
            "ExecutiveEscalationSignalRecord"
        ]
    }

    for stage in data.get("integration_flow", []) or []:
        stage_name = normalize_stage_name(stage.get("stage_name", "")) or normalize_stage_name(stage.get("stage_id", ""))

        stage["governance_stack_coordination_guardrail"] = {
            "architecture_status": "FROZEN",
            "new_module_allowed": False,
            "new_route_allowed": False,
            "lifecycle_change_allowed": False,
            "stage_strengthening_only": True
        }

        if stage_name == "Governance":
            stage["governance_stack_coordination"] = governance_stage_enrichment
            stage["operational_question"] = governance_stage_enrichment["stage_question"]
            stage["expected_objects"] = add_unique_list(
                stage.get("expected_objects", []),
                lifecycle_object_map["Governance"]
            )
            stage["evidence_outputs"] = add_unique_list(
                stage.get("evidence_outputs", []),
                governance_stage_enrichment["coordination_records"]
            )

        if stage_name == "Operationalization":
            stage["governance_stack_handoff_inputs"] = add_unique_list(
                stage.get("governance_stack_handoff_inputs", []),
                operationalization_handoff
            )
            stage["expected_objects"] = add_unique_list(
                stage.get("expected_objects", []),
                lifecycle_object_map["Operationalization"]
            )

        if stage_name == "Continuous Assurance":
            stage["governance_stack_continuous_assurance_signals"] = add_unique_list(
                stage.get("governance_stack_continuous_assurance_signals", []),
                continuous_assurance_signals
            )
            stage["expected_objects"] = add_unique_list(
                stage.get("expected_objects", []),
                lifecycle_object_map["Continuous Assurance"]
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
            <h2 style="margin:0;font-size:30px;">Governance Stack Coordination</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Governance is the coordination point. The governance stack feeds Operationalization, Manufacturing Monitoring, Evidence, Continuous Assurance, and Operational Trust. No new module, route, architecture, stage, pillar, or lifecycle phase was created.
            </div>
        </div>
        <span class="tag">Governance strengthened</span>
    </div>
    <div class="grid">
        <div class="panel"><strong>Infrastructure governance</strong><div>Coordinates AI runtimes, compute, network, gateways, execution environments, resiliency, and infrastructure guardrails.</div></div>
        <div class="panel"><strong>Data governance</strong><div>Coordinates data products, context sources, lineage, quality, retention, privacy, and regulated data-use boundaries.</div></div>
        <div class="panel"><strong>Model governance</strong><div>Coordinates AI models, model versions, intended use, model routing, performance limits, and model-change controls.</div></div>
        <div class="panel"><strong>Identity governance</strong><div>Coordinates agent identity, human identity, service identity, tool permissions, API permissions, approval authority, and runtime authorization.</div></div>
        <div class="panel"><strong>Risk governance</strong><div>Coordinates risk classification, process risk, AI risk, operational risk, residual risk, and risk acceptance.</div></div>
        <div class="panel"><strong>Compliance governance</strong><div>Coordinates regulatory obligations, framework mappings, GxP expectations, internal SOPs, validation expectations, and audit readiness.</div></div>
        <div class="panel"><strong>Policy governance</strong><div>Coordinates execution policies, routing policies, tool-use policies, approval policies, escalation policies, monitoring policies, and exception policies.</div></div>
        <div class="panel"><strong>Executive governance</strong><div>Coordinates decision rights, accountability, risk appetite, enterprise oversight, escalation authority, and operational trust decisions.</div></div>
        <div class="panel"><strong>Inputs</strong><div>Inventories, permissions, observability, telemetry, and policy enforcement.</div></div>
        <div class="panel"><strong>Handoff</strong><div>Governance feeds approved constraints, permissions, evidence requirements, policy rules, risk thresholds, and escalation paths into Operationalization and Continuous Assurance.</div></div>
    </div>
</section>
'''

platform_block = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>Governance Stack Coordination</h2>
            <p>Governance now acts as the coordination layer for infrastructure, data, model, identity, risk, compliance, policy, and executive governance using inventories, permissions, observability, telemetry, and policy enforcement. No new module or architecture change.</p>
        </div>
        <span class="tag">Existing Governance stage</span>
    </div>
    <div class="grid-4">
        <a class="card" href="/platform/blueprints/ai-enabled-cmc"><strong>AI-enabled CMC Blueprint</strong><span>Shows governance stack coordination inside the existing lifecycle.</span><small>Open blueprint</small></a>
        <a class="card" href="/platform/blueprints/agentic-enterprise"><strong>Agentic Enterprise Blueprint</strong><span>Applies governance stack coordination to enterprise AI execution.</span><small>Open blueprint</small></a>
        <a class="card" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Maps governance handoffs into Operationalization and governance signals into Continuous Assurance.</span><small>Open lifecycle</small></a>
        <a class="card" href="/platform/evidence-packages"><strong>Evidence</strong><span>Captures governance stack coordination, handoff, policy, risk, and escalation evidence.</span><small>Open evidence</small></a>
    </div>
</section>
'''

library_block = r'''
<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">Governance as the Coordination Layer</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Blueprints may strengthen Governance by coordinating infrastructure, data, model, identity, risk, compliance, policy, and executive governance. This remains inside the frozen lifecycle.
            </div>
        </div>
        <span class="tag">No new architecture</span>
    </div>
</section>
'''

route_registry_block = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>Governance Stack Coordination Routes</h2>
            <p>Governance stack coordination is exposed through existing routes only. No new module or route was added.</p>
        </div>
        <span class="tag">Existing routes only</span>
    </div>
    <div class="route-grid">
        <a class="route" href="/platform"><strong>Platform Command Center</strong><span>Shows Governance as the coordination layer for the enterprise AI governance stack.</span><code>/platform</code></a>
        <a class="route" href="/platform/blueprints/ai-enabled-cmc"><strong>AI-enabled CMC Blueprint</strong><span>Displays governance coordination inside the existing AI-enabled CMC lifecycle.</span><code>/platform/blueprints/ai-enabled-cmc</code></a>
        <a class="route" href="/platform/blueprints/agentic-enterprise"><strong>Agentic Enterprise Blueprint</strong><span>Displays governance coordination for enterprise AI execution.</span><code>/platform/blueprints/agentic-enterprise</code></a>
        <a class="route" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Connects governance handoffs to operationalization and continuous assurance.</span><code>/platform/lifecycle-integration</code></a>
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

Path("governance_stack_coordination_patch_v1_summary.json").write_text(
    json.dumps(patch_model, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("governance_stack_coordination_patch_v1_urls.txt").write_text(
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
print("Governance Stack Coordination Patch completed.")
print("Marker:")
print("  " + PATCH_MARKER)
print("No new module. No new route. No architecture change. Lifecycle unchanged.")
