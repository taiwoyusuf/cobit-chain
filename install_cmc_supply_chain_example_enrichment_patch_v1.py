from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_CMC_SUPPLY_CHAIN_EXAMPLE_ENRICHMENT_PATCH_V1_ACTIVE"

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

supply_chain_examples = [
    "AI-assisted supplier qualification",
    "AI-assisted raw material sourcing",
    "AI-assisted inventory optimization",
    "AI-assisted cold chain planning",
    "AI-assisted logistics optimization",
    "AI-assisted blood and biologics supply planning"
]

supply_chain_questions = [
    "Which AI recommended this supplier?",
    "Which AI predicted this shortage?",
    "Which AI optimized inventory?",
    "Which AI generated this supply chain recommendation?",
    "Was the recommendation reviewed?",
    "What evidence supports the decision?"
]

stage_enrichment = {
    "Discovery": {
        "stage_rule": "Strengthen Discovery with AI-enabled pharmaceutical supply chain examples inside the existing AI-enabled CMC Blueprint.",
        "supply_chain_examples": supply_chain_examples,
        "stage_question": "Have AI-assisted supplier qualification, raw material sourcing, inventory optimization, cold chain planning, logistics optimization, and blood and biologics supply planning activities been discovered and inventoried?",
        "evidence_outputs": [
            "AI-assisted supplier qualification discovery record",
            "AI-assisted raw material sourcing discovery record",
            "AI-assisted inventory optimization discovery record",
            "AI-assisted cold chain planning discovery record",
            "AI-assisted logistics optimization discovery record",
            "AI-assisted blood and biologics supply planning discovery record"
        ]
    },
    "Visibility": {
        "stage_rule": "Strengthen Visibility by making AI-enabled supply chain recommendations, dependencies, telemetry, workflows, and review status visible.",
        "visibility_scope": [
            "Supplier recommendation visibility",
            "Raw material sourcing visibility",
            "Inventory optimization visibility",
            "Cold chain planning visibility",
            "Logistics recommendation visibility",
            "Blood and biologics supply planning visibility",
            "Supply chain dependency visibility",
            "Supply chain workflow visibility"
        ],
        "stage_question": "Can supplier recommendations, sourcing recommendations, inventory optimization, cold chain planning, logistics optimization, blood and biologics supply planning, dependencies, and workflows be observed?",
        "evidence_outputs": [
            "Supplier recommendation visibility record",
            "Raw material sourcing visibility record",
            "Inventory optimization visibility record",
            "Cold chain planning visibility record",
            "Logistics optimization visibility record",
            "Blood and biologics supply planning visibility record",
            "Supply chain dependency visibility record",
            "Supply chain workflow visibility record"
        ]
    },
    "Governance": {
        "stage_rule": "Strengthen Governance by applying the existing governance stage to AI-enabled supply chain decisions.",
        "coordination_scope": [
            "Supplier governance",
            "Raw material governance",
            "Inventory governance",
            "Cold chain governance",
            "Logistics governance",
            "Blood and biologics supply governance",
            "Quality risk governance",
            "Policy governance",
            "Human review governance"
        ],
        "stage_question": "Were AI-enabled supplier, sourcing, inventory, cold chain, logistics, and blood or biologics supply recommendations governed before use?",
        "evidence_outputs": [
            "Supplier recommendation governance record",
            "Raw material sourcing governance record",
            "Inventory optimization governance record",
            "Cold chain planning governance record",
            "Logistics optimization governance record",
            "Blood and biologics supply governance record",
            "Quality risk governance record",
            "Human review governance record"
        ]
    },
    "Operationalization": {
        "stage_rule": "Strengthen Operationalization with AI-enabled CMC supply chain workflow examples only.",
        "implementation_examples": [
            "Supplier qualification workflow execution",
            "Raw material sourcing workflow execution",
            "Inventory optimization workflow execution",
            "Cold chain planning workflow execution",
            "Logistics optimization workflow execution",
            "Blood and biologics supply planning workflow execution",
            "Human approval workflow",
            "Runtime policy enforcement"
        ],
        "stage_question": "Were AI-assisted supply chain recommendations operationalized through governed workflows, human review, approval, runtime authorization, and policy enforcement?",
        "evidence_outputs": [
            "Supplier qualification workflow record",
            "Raw material sourcing workflow record",
            "Inventory optimization workflow record",
            "Cold chain planning workflow record",
            "Logistics optimization workflow record",
            "Blood and biologics supply planning workflow record",
            "Supply chain human approval record",
            "Supply chain policy enforcement record"
        ]
    },
    "Manufacturing Monitoring": {
        "stage_rule": "Strengthen Manufacturing Monitoring by monitoring AI-enabled supply chain impacts on manufacturing readiness and continuity.",
        "monitoring_scope": [
            "Supplier recommendation monitoring",
            "Raw material availability monitoring",
            "Inventory optimization monitoring",
            "Cold chain execution monitoring",
            "Logistics execution monitoring",
            "Blood and biologics supply monitoring",
            "Shortage prediction monitoring",
            "Supply chain decision monitoring"
        ],
        "stage_question": "Are supplier recommendations, raw material availability, inventory optimization, cold chain execution, logistics execution, blood and biologics supply planning, shortage predictions, and supply chain decisions monitored?",
        "evidence_outputs": [
            "Supplier recommendation monitoring record",
            "Raw material availability monitoring record",
            "Inventory optimization monitoring record",
            "Cold chain execution monitoring record",
            "Logistics execution monitoring record",
            "Blood and biologics supply monitoring record",
            "Shortage prediction monitoring record",
            "Supply chain decision monitoring record"
        ]
    },
    "Evidence": {
        "stage_rule": "Strengthen Evidence so AI-enabled supply chain decisions can be reconstructed.",
        "execution_questions": supply_chain_questions,
        "stage_question": "Can every AI-enabled supply chain decision answer which AI recommended the supplier, predicted the shortage, optimized inventory, generated the recommendation, who reviewed it, and what evidence supports the decision?",
        "evidence_outputs": [
            "Supplier recommendation evidence record",
            "Shortage prediction evidence record",
            "Inventory optimization evidence record",
            "Supply chain recommendation evidence record",
            "Human review evidence record",
            "Supply chain decision support evidence record",
            "Supply chain execution reconstruction package"
        ]
    },
    "Continuous Assurance": {
        "stage_rule": "Strengthen Continuous Assurance by continuously validating AI-enabled supply chain trust, evidence, review, and operational impact.",
        "validation_scope": [
            "Supplier recommendation trust",
            "Shortage prediction reliability",
            "Inventory optimization integrity",
            "Cold chain recommendation integrity",
            "Logistics recommendation integrity",
            "Blood and biologics supply planning integrity",
            "Human review completeness",
            "Supply chain evidence integrity"
        ],
        "stage_question": "Are supplier recommendation trust, shortage prediction reliability, inventory optimization integrity, cold chain recommendation integrity, logistics recommendation integrity, blood and biologics supply planning integrity, human review completeness, and supply chain evidence integrity continuously validated?",
        "evidence_outputs": [
            "Supplier recommendation trust validation record",
            "Shortage prediction reliability validation record",
            "Inventory optimization integrity validation record",
            "Cold chain recommendation integrity validation record",
            "Logistics recommendation integrity validation record",
            "Blood and biologics supply planning integrity validation record",
            "Human review completeness validation record",
            "Supply chain evidence integrity validation record"
        ]
    },
    "Operational Trust": {
        "stage_rule": "Operational Trust remains unchanged as the outcome of the entire lifecycle.",
        "outcome_role": "Operational Trust is the outcome of Discovery, Visibility, Governance, Operationalization, Manufacturing Monitoring, Evidence, and Continuous Assurance.",
        "do_not_expand_beyond_outcome_role": True,
        "stage_question": "Can operational trust be justified from the full AI-enabled supply chain lifecycle evidence?",
        "evidence_outputs": [
            "AI-enabled supply chain operational trust outcome record",
            "Supply chain lifecycle trust justification record",
            "Supply chain trust decision record"
        ]
    }
}

traceability_map = [
    {
        "supply_chain_activity": "AI-assisted supplier qualification",
        "discovery_object": "Supplier qualification AI activity",
        "visibility_object": "Supplier recommendation visibility",
        "governance_object": "Supplier governance / quality risk governance",
        "operationalization_object": "Supplier qualification workflow execution",
        "monitoring_signal": "Supplier recommendation monitoring",
        "evidence_question": "Which AI recommended this supplier?",
        "continuous_assurance_check": "Supplier recommendation trust"
    },
    {
        "supply_chain_activity": "AI-assisted raw material sourcing",
        "discovery_object": "Raw material sourcing AI activity",
        "visibility_object": "Raw material sourcing visibility",
        "governance_object": "Raw material governance",
        "operationalization_object": "Raw material sourcing workflow execution",
        "monitoring_signal": "Raw material availability monitoring",
        "evidence_question": "Which AI generated this supply chain recommendation?",
        "continuous_assurance_check": "Supply chain evidence integrity"
    },
    {
        "supply_chain_activity": "AI-assisted inventory optimization",
        "discovery_object": "Inventory optimization AI activity",
        "visibility_object": "Inventory optimization visibility",
        "governance_object": "Inventory governance",
        "operationalization_object": "Inventory optimization workflow execution",
        "monitoring_signal": "Inventory optimization monitoring",
        "evidence_question": "Which AI optimized inventory?",
        "continuous_assurance_check": "Inventory optimization integrity"
    },
    {
        "supply_chain_activity": "AI-assisted cold chain planning",
        "discovery_object": "Cold chain planning AI activity",
        "visibility_object": "Cold chain planning visibility",
        "governance_object": "Cold chain governance",
        "operationalization_object": "Cold chain planning workflow execution",
        "monitoring_signal": "Cold chain execution monitoring",
        "evidence_question": "What evidence supports the decision?",
        "continuous_assurance_check": "Cold chain recommendation integrity"
    },
    {
        "supply_chain_activity": "AI-assisted logistics optimization",
        "discovery_object": "Logistics optimization AI activity",
        "visibility_object": "Logistics recommendation visibility",
        "governance_object": "Logistics governance",
        "operationalization_object": "Logistics optimization workflow execution",
        "monitoring_signal": "Logistics execution monitoring",
        "evidence_question": "Was the recommendation reviewed?",
        "continuous_assurance_check": "Logistics recommendation integrity"
    },
    {
        "supply_chain_activity": "AI-assisted blood and biologics supply planning",
        "discovery_object": "Blood and biologics supply planning AI activity",
        "visibility_object": "Blood and biologics supply planning visibility",
        "governance_object": "Blood and biologics supply governance",
        "operationalization_object": "Blood and biologics supply planning workflow execution",
        "monitoring_signal": "Blood and biologics supply monitoring",
        "evidence_question": "Which AI predicted this shortage?",
        "continuous_assurance_check": "Blood and biologics supply planning integrity"
    }
]

patch_model = {
    "patch_marker": PATCH_MARKER,
    "patch_type": "ai_enabled_cmc_supply_chain_example_enrichment_not_new_module",
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
    "blueprint_scope": "Existing AI-enabled CMC Blueprint only",
    "supply_chain_examples": supply_chain_examples,
    "supply_chain_questions": supply_chain_questions,
    "stage_enrichment": stage_enrichment,
    "traceability_map": traceability_map,
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

def is_cmc_blueprint(bp):
    blob = json.dumps(bp, ensure_ascii=False).lower()
    return "cmc" in blob or "chemistry" in blob or "manufacturing and controls" in blob or "ai-enabled cmc" in blob

def patch_blueprint_seed():
    path = Path("platform_blueprint_library_seed.json")
    if not path.exists():
        print("SKIP: platform_blueprint_library_seed.json not found.")
        return False

    data = load_json(path)
    data["cmc_supply_chain_example_enrichment_patch"] = patch_model

    for bp in data.get("blueprints", []) or []:
        if not is_cmc_blueprint(bp):
            continue

        bp["cmc_supply_chain_example_enrichment"] = {
            "architecture_status": "FROZEN",
            "architecture_change": False,
            "new_module": False,
            "new_route": False,
            "lifecycle_change": False,
            "stage_strengthening_only": True,
            "supply_chain_examples_added_to_discovery": supply_chain_examples,
            "supply_chain_questions": supply_chain_questions,
            "permanent_lifecycle": permanent_lifecycle,
            "operational_trust_unchanged": True
        }

        bp["questions_answered"] = add_unique_list(
            bp.get("questions_answered", []),
            supply_chain_questions
        )

        assessment = bp.get("sample_blueprint_assessment", {})
        if not isinstance(assessment, dict):
            assessment = {}
        assessment["cmc_supply_chain_example_state"] = "EXISTING_CMC_BLUEPRINT_STRENGTHENED_NO_NEW_MODULE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["new_route"] = False
        assessment["lifecycle_change"] = False
        assessment["stage_strengthening_only"] = True
        assessment["supply_chain_examples_count"] = len(supply_chain_examples)
        assessment["supply_chain_traceability_count"] = len(traceability_map)
        assessment["permanent_lifecycle_sequence"] = patch_model["permanent_lifecycle_sequence"]
        assessment["operational_trust_rule"] = patch_model["operational_trust_rule"]
        bp["sample_blueprint_assessment"] = assessment

        for stage in bp.get("lifecycle", []) or []:
            stage_name = normalize_stage_name(stage.get("stage_name", ""))
            if not stage_name:
                continue

            enrichment = stage_enrichment.get(stage_name, {})
            stage["cmc_supply_chain_example_enrichment"] = enrichment
            stage["stage_rename_allowed"] = False
            stage["stage_insertion_allowed"] = False
            stage["lifecycle_reorganization_allowed"] = False
            stage["stage_question"] = enrichment.get("stage_question", stage.get("stage_question", ""))
            stage["evidence_outputs"] = add_unique_list(stage.get("evidence_outputs", []), enrichment.get("evidence_outputs", []))

            if stage_name == "Discovery":
                stage["supply_chain_discovery_examples"] = add_unique_list(stage.get("supply_chain_discovery_examples", []), supply_chain_examples)
                stage["operational_focus"] = "Discovery now includes AI-assisted supplier qualification, raw material sourcing, inventory optimization, cold chain planning, logistics optimization, and blood and biologics supply planning."

            if stage_name == "Visibility":
                stage["supply_chain_visibility_scope"] = enrichment["visibility_scope"]
                stage["operational_focus"] = "Visibility shows supplier recommendations, raw material sourcing, inventory optimization, cold chain planning, logistics optimization, blood and biologics supply planning, dependencies, and workflows."

            if stage_name == "Governance":
                stage["supply_chain_governance_scope"] = enrichment["coordination_scope"]
                stage["operational_focus"] = "Governance coordinates AI-enabled supplier, raw material, inventory, cold chain, logistics, blood and biologics supply, quality risk, policy, and human review governance."

            if stage_name == "Operationalization":
                stage["supply_chain_operationalization_examples"] = enrichment["implementation_examples"]
                stage["operational_focus"] = "Operationalization includes governed supplier qualification, raw material sourcing, inventory optimization, cold chain planning, logistics optimization, blood and biologics supply planning, human approval, and runtime policy enforcement workflows."

            if stage_name == "Manufacturing Monitoring":
                stage["supply_chain_monitoring_scope"] = enrichment["monitoring_scope"]
                stage["operational_focus"] = "Manufacturing Monitoring monitors supplier recommendations, raw material availability, inventory optimization, cold chain execution, logistics execution, blood and biologics supply planning, shortage predictions, and supply chain decisions."

            if stage_name == "Evidence":
                stage["supply_chain_evidence_questions"] = enrichment["execution_questions"]
                stage["operational_focus"] = "Evidence answers which AI recommended the supplier, predicted the shortage, optimized inventory, generated the supply chain recommendation, whether it was reviewed, and what evidence supports the decision."

            if stage_name == "Continuous Assurance":
                stage["supply_chain_continuous_assurance_scope"] = enrichment["validation_scope"]
                stage["operational_focus"] = "Continuous Assurance validates supplier recommendation trust, shortage prediction reliability, inventory optimization integrity, cold chain recommendation integrity, logistics recommendation integrity, blood and biologics supply planning integrity, human review completeness, and evidence integrity."

            if stage_name == "Operational Trust":
                stage["operational_trust_outcome_rule"] = enrichment["outcome_role"]
                stage["do_not_expand_beyond_outcome_role"] = True
                stage["operational_focus"] = "Operational Trust remains unchanged as the outcome of the entire lifecycle."

    save_json(path, data)
    print("PATCHED: platform_blueprint_library_seed.json")
    return True

def patch_lifecycle_seed():
    path = Path("platform_lifecycle_integration_seed.json")
    if not path.exists():
        print("SKIP: platform_lifecycle_integration_seed.json not found.")
        return False

    data = load_json(path)
    data["cmc_supply_chain_example_enrichment_patch"] = patch_model

    assessment = data.get("sample_integration_assessment", {})
    if not isinstance(assessment, dict):
        assessment = {}

    assessment["cmc_supply_chain_example_enrichment"] = {
        "state": "EXISTING_CMC_BLUEPRINT_STRENGTHENED_NO_NEW_MODULE",
        "architecture_status": "FROZEN",
        "architecture_change": False,
        "new_module": False,
        "new_route": False,
        "lifecycle_change": False,
        "stage_strengthening_only": True,
        "supply_chain_examples": supply_chain_examples,
        "supply_chain_questions": supply_chain_questions,
        "stage_enrichment": stage_enrichment,
        "traceability_map": traceability_map
    }

    assessment["implementation_priority"] = add_unique_list(
        assessment.get("implementation_priority", []),
        [
            "Strengthen the existing AI-enabled CMC Blueprint Discovery stage with AI-assisted supplier qualification.",
            "Strengthen the existing AI-enabled CMC Blueprint Discovery stage with AI-assisted raw material sourcing.",
            "Strengthen the existing AI-enabled CMC Blueprint Discovery stage with AI-assisted inventory optimization.",
            "Strengthen the existing AI-enabled CMC Blueprint Discovery stage with AI-assisted cold chain planning.",
            "Strengthen the existing AI-enabled CMC Blueprint Discovery stage with AI-assisted logistics optimization.",
            "Strengthen the existing AI-enabled CMC Blueprint Discovery stage with AI-assisted blood and biologics supply planning.",
            "Use existing Evidence stage to answer which AI recommended the supplier, predicted shortage, optimized inventory, generated recommendation, whether it was reviewed, and what evidence supports the decision.",
            "Keep Operational Trust unchanged as the lifecycle outcome."
        ]
    )

    assessment["evidence_automation_targets"] = add_unique_list(
        assessment.get("evidence_automation_targets", []),
        [
            "Supplier recommendation evidence package",
            "Shortage prediction evidence package",
            "Inventory optimization evidence package",
            "Cold chain planning evidence package",
            "Logistics optimization evidence package",
            "Blood and biologics supply planning evidence package",
            "Supply chain human review evidence package",
            "Supply chain decision reconstruction package"
        ]
    )

    data["sample_integration_assessment"] = assessment

    lifecycle_object_map = {
        "Discovery": [
            "SupplierQualificationAIDiscoveryRecord",
            "RawMaterialSourcingAIDiscoveryRecord",
            "InventoryOptimizationAIDiscoveryRecord",
            "ColdChainPlanningAIDiscoveryRecord",
            "LogisticsOptimizationAIDiscoveryRecord",
            "BloodAndBiologicsSupplyPlanningAIDiscoveryRecord"
        ],
        "Visibility": [
            "SupplierRecommendationVisibilityRecord",
            "RawMaterialSourcingVisibilityRecord",
            "InventoryOptimizationVisibilityRecord",
            "ColdChainPlanningVisibilityRecord",
            "LogisticsOptimizationVisibilityRecord",
            "BloodAndBiologicsSupplyPlanningVisibilityRecord",
            "SupplyChainDependencyVisibilityRecord",
            "SupplyChainWorkflowVisibilityRecord"
        ],
        "Governance": [
            "SupplierRecommendationGovernanceRecord",
            "RawMaterialSourcingGovernanceRecord",
            "InventoryOptimizationGovernanceRecord",
            "ColdChainPlanningGovernanceRecord",
            "LogisticsOptimizationGovernanceRecord",
            "BloodAndBiologicsSupplyGovernanceRecord",
            "QualityRiskGovernanceRecord",
            "HumanReviewGovernanceRecord"
        ],
        "Operationalization": [
            "SupplierQualificationWorkflowRecord",
            "RawMaterialSourcingWorkflowRecord",
            "InventoryOptimizationWorkflowRecord",
            "ColdChainPlanningWorkflowRecord",
            "LogisticsOptimizationWorkflowRecord",
            "BloodAndBiologicsSupplyPlanningWorkflowRecord",
            "SupplyChainHumanApprovalRecord",
            "SupplyChainPolicyEnforcementRecord"
        ],
        "Manufacturing Monitoring": [
            "SupplierRecommendationMonitoringRecord",
            "RawMaterialAvailabilityMonitoringRecord",
            "InventoryOptimizationMonitoringRecord",
            "ColdChainExecutionMonitoringRecord",
            "LogisticsExecutionMonitoringRecord",
            "BloodAndBiologicsSupplyMonitoringRecord",
            "ShortagePredictionMonitoringRecord",
            "SupplyChainDecisionMonitoringRecord"
        ],
        "Evidence": [
            "SupplierRecommendationEvidenceRecord",
            "ShortagePredictionEvidenceRecord",
            "InventoryOptimizationEvidenceRecord",
            "SupplyChainRecommendationEvidenceRecord",
            "HumanReviewEvidenceRecord",
            "SupplyChainDecisionSupportEvidenceRecord",
            "SupplyChainExecutionReconstructionPackage"
        ],
        "Continuous Assurance": [
            "SupplierRecommendationTrustValidationRecord",
            "ShortagePredictionReliabilityValidationRecord",
            "InventoryOptimizationIntegrityValidationRecord",
            "ColdChainRecommendationIntegrityValidationRecord",
            "LogisticsRecommendationIntegrityValidationRecord",
            "BloodAndBiologicsSupplyPlanningIntegrityValidationRecord",
            "HumanReviewCompletenessValidationRecord",
            "SupplyChainEvidenceIntegrityValidationRecord"
        ],
        "Operational Trust": [
            "AIEnabledSupplyChainOperationalTrustOutcomeRecord",
            "SupplyChainLifecycleTrustJustificationRecord",
            "SupplyChainTrustDecisionRecord"
        ]
    }

    for stage in data.get("integration_flow", []) or []:
        stage_name = normalize_stage_name(stage.get("stage_name", "")) or normalize_stage_name(stage.get("stage_id", ""))
        stage["cmc_supply_chain_example_guardrail"] = {
            "architecture_status": "FROZEN",
            "new_module_allowed": False,
            "new_route_allowed": False,
            "lifecycle_change_allowed": False,
            "stage_strengthening_only": True
        }

        if stage_name and stage_name in stage_enrichment:
            enrichment = stage_enrichment[stage_name]
            stage["cmc_supply_chain_example_enrichment"] = enrichment
            stage["operational_question"] = enrichment.get("stage_question", stage.get("operational_question", ""))
            stage["expected_objects"] = add_unique_list(stage.get("expected_objects", []), lifecycle_object_map.get(stage_name, []))
            stage["evidence_outputs"] = add_unique_list(stage.get("evidence_outputs", []), enrichment.get("evidence_outputs", []))

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

cmc_blueprint_block = r'''
<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">AI-enabled CMC Supply Chain Examples</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                This expands the existing AI-enabled CMC Blueprint with supply chain examples. No new module, route, architecture, stage, pillar, or lifecycle phase was created.
            </div>
        </div>
        <span class="tag">No new module</span>
    </div>
    <div class="grid">
        <div class="panel"><strong>Discovery</strong><div>AI-assisted supplier qualification, AI-assisted raw material sourcing, AI-assisted inventory optimization, AI-assisted cold chain planning, AI-assisted logistics optimization, and AI-assisted blood and biologics supply planning.</div></div>
        <div class="panel"><strong>Visibility</strong><div>Supplier recommendation visibility, raw material sourcing visibility, inventory optimization visibility, cold chain planning visibility, logistics recommendation visibility, blood and biologics supply planning visibility, dependency visibility, and workflow visibility.</div></div>
        <div class="panel"><strong>Governance</strong><div>Supplier governance, raw material governance, inventory governance, cold chain governance, logistics governance, blood and biologics supply governance, quality risk governance, policy governance, and human review governance.</div></div>
        <div class="panel"><strong>Operationalization</strong><div>Supplier qualification workflow execution, raw material sourcing workflow execution, inventory optimization workflow execution, cold chain planning workflow execution, logistics optimization workflow execution, blood and biologics supply planning workflow execution, human approval, and runtime policy enforcement.</div></div>
        <div class="panel"><strong>Manufacturing Monitoring</strong><div>Supplier recommendation monitoring, raw material availability monitoring, inventory optimization monitoring, cold chain execution monitoring, logistics execution monitoring, blood and biologics supply monitoring, shortage prediction monitoring, and supply chain decision monitoring.</div></div>
        <div class="panel"><strong>Evidence</strong><div>Which AI recommended this supplier? Which AI predicted this shortage? Which AI optimized inventory? Which AI generated this supply chain recommendation? Was the recommendation reviewed? What evidence supports the decision?</div></div>
        <div class="panel"><strong>Continuous Assurance</strong><div>Supplier recommendation trust, shortage prediction reliability, inventory optimization integrity, cold chain recommendation integrity, logistics recommendation integrity, blood and biologics supply planning integrity, human review completeness, and supply chain evidence integrity.</div></div>
        <div class="panel"><strong>Operational Trust</strong><div>Operational Trust remains the outcome of the lifecycle.</div></div>
    </div>
</section>
'''

platform_block = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>AI-enabled CMC Supply Chain Example Enrichment</h2>
            <p>The existing AI-enabled CMC Blueprint now includes AI-assisted supplier qualification, raw material sourcing, inventory optimization, cold chain planning, logistics optimization, and blood and biologics supply planning. No new module or architecture change.</p>
        </div>
        <span class="tag">CMC blueprint enrichment</span>
    </div>
    <div class="grid-4">
        <a class="card" href="/platform/blueprints/ai-enabled-cmc"><strong>AI-enabled CMC Blueprint</strong><span>Shows supply chain examples inside the existing frozen lifecycle.</span><small>Open blueprint</small></a>
        <a class="card" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Maps supply chain examples to Discovery, Visibility, Governance, Operationalization, Manufacturing Monitoring, Evidence, Continuous Assurance, and Operational Trust.</span><small>Open lifecycle</small></a>
        <a class="card" href="/platform/evidence-packages"><strong>Evidence</strong><span>Supply chain decisions answer supplier, shortage, inventory, recommendation, review, and evidence questions.</span><small>Open evidence</small></a>
        <a class="card" href="/platform/routes"><strong>Route Registry</strong><span>Existing routes only. No new supply chain module.</span><small>Open routes</small></a>
    </div>
</section>
'''

library_block = r'''
<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">CMC Blueprint Supply Chain Examples</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                The AI-enabled CMC Blueprint may include supply chain examples only as stage strengthening. It remains the same blueprint and the lifecycle is unchanged.
            </div>
        </div>
        <span class="tag">Existing blueprint</span>
    </div>
</section>
'''

route_registry_block = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>CMC Supply Chain Example Enrichment</h2>
            <p>Supply chain examples are exposed through existing routes only. No supply chain module or route was added.</p>
        </div>
        <span class="tag">Existing routes only</span>
    </div>
    <div class="route-grid">
        <a class="route" href="/platform"><strong>Platform Command Center</strong><span>Shows the CMC supply chain enrichment as part of the frozen lifecycle.</span><code>/platform</code></a>
        <a class="route" href="/platform/blueprints/ai-enabled-cmc"><strong>AI-enabled CMC Blueprint</strong><span>Displays AI-assisted supplier, sourcing, inventory, cold chain, logistics, and blood/biologics planning examples.</span><code>/platform/blueprints/ai-enabled-cmc</code></a>
        <a class="route" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Connects supply chain examples to evidence automation and operational trust.</span><code>/platform/lifecycle-integration</code></a>
        <a class="route" href="/api/platform/blueprints/ai-enabled-cmc/demo"><strong>CMC Blueprint API</strong><span>Returns the existing CMC blueprint data with supply chain enrichment.</span><code>/api/platform/blueprints/ai-enabled-cmc/demo</code></a>
    </div>
</section>
'''

patch_blueprint_seed()
patch_lifecycle_seed()

patch_html(
    "platform_ai_enabled_cmc_blueprint.html",
    cmc_blueprint_block,
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

Path("cmc_supply_chain_example_enrichment_patch_v1_summary.json").write_text(
    json.dumps(patch_model, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("cmc_supply_chain_example_enrichment_patch_v1_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform",
        "http://127.0.0.1:5000/platform/routes",
        "http://127.0.0.1:5000/platform/blueprints",
        "http://127.0.0.1:5000/platform/blueprints/ai-enabled-cmc",
        "http://127.0.0.1:5000/platform/lifecycle-integration",
        "http://127.0.0.1:5000/api/platform/blueprints/model/demo",
        "http://127.0.0.1:5000/api/platform/blueprints/ai-enabled-cmc/demo",
        "http://127.0.0.1:5000/api/platform/lifecycle-integration/model/demo"
    ]),
    encoding="utf-8"
)

print("")
print("AI-enabled CMC Supply Chain Example Enrichment Patch completed.")
print("Marker:")
print("  " + PATCH_MARKER)
print("No new module. No new route. No architecture change. Lifecycle unchanged.")
