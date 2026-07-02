from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_AI_TO_MES_EXECUTION_ASSURANCE_PATCH_V1_ACTIVE"

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

manufacturing_assurance_thesis = {
    "headline": "The assurance boundary is moving from AI recommendation validation to AI execution assurance inside regulated manufacturing systems.",
    "statement": "As AI becomes embedded within pharmaceutical manufacturing, the assurance boundary shifts from validating AI recommendations to continuously assuring their execution within regulated manufacturing systems such as MES.",
    "platform_interpretation": "AI recommendation assurance is no longer enough. Assurance Engineering must prove that AI recommendations are governed, approved, executed, monitored, evidenced, and reconstructable inside MES, EBR, batch execution, recipe execution, and GxP workflows.",
    "architecture_change": False,
    "new_module": False,
    "new_route": False,
    "lifecycle_change": False
}

operationalization_enrichment = {
    "stage_rule": "Strengthen Operationalization by explicitly supporting AI integration with regulated manufacturing execution systems.",
    "ai_to_mes_operationalization_scope": [
        "MES integration",
        "Batch execution orchestration",
        "Electronic Batch Records (EBR)",
        "Recipe execution",
        "Manufacturing workflow execution",
        "AI-to-MES orchestration",
        "Human approval before execution",
        "Runtime authorization",
        "Electronic signatures",
        "GxP workflow integration"
    ],
    "stage_question": "Were AI recommendations integrated into MES, EBR, batch execution, recipe execution, and GxP manufacturing workflows through approved orchestration, human approval, runtime authorization, electronic signatures, and policy enforcement?",
    "evidence_outputs": [
        "MES integration record",
        "Batch execution orchestration record",
        "Electronic Batch Record integration record",
        "Recipe execution orchestration record",
        "Manufacturing workflow execution record",
        "AI-to-MES orchestration record",
        "Human approval before execution record",
        "Runtime authorization record",
        "Electronic signature record",
        "GxP workflow integration record"
    ]
}

manufacturing_monitoring_enrichment = {
    "stage_rule": "Strengthen Manufacturing Monitoring by explicitly monitoring AI-to-MES execution, batch execution, EBR, CPPs, CQAs, equipment status, deviations, and runtime manufacturing telemetry.",
    "monitoring_scope": [
        "MES execution",
        "Batch execution",
        "Electronic Batch Records",
        "AI recommendations executed in MES",
        "CPP monitoring",
        "CQA monitoring",
        "Equipment status",
        "Manufacturing deviations",
        "Runtime manufacturing telemetry",
        "AI-to-MES execution traceability"
    ],
    "stage_question": "Are MES execution, batch execution, EBR activity, AI recommendations executed in MES, CPPs, CQAs, equipment status, deviations, runtime manufacturing telemetry, and AI-to-MES execution traceability monitored?",
    "evidence_outputs": [
        "MES execution monitoring record",
        "Batch execution monitoring record",
        "Electronic Batch Record monitoring record",
        "AI recommendation executed in MES monitoring record",
        "CPP monitoring record",
        "CQA monitoring record",
        "Equipment status monitoring record",
        "Manufacturing deviation monitoring record",
        "Runtime manufacturing telemetry record",
        "AI-to-MES execution traceability monitoring record"
    ]
}

evidence_enrichment = {
    "stage_rule": "Strengthen Evidence so AI-to-MES execution can be reconstructed during inspection.",
    "execution_questions": [
        "Which AI generated the recommendation?",
        "Which Digital Twin, if any, influenced the recommendation?",
        "Which MES workflow executed it?",
        "Which batch was affected?",
        "Which CPPs/CQAs changed?",
        "Who approved execution?",
        "Which electronic signatures were applied?",
        "What evidence supports the execution?",
        "Can the complete execution be reconstructed during inspection?"
    ],
    "stage_question": "Can the complete AI-to-MES execution be reconstructed during inspection from AI recommendation, Digital Twin influence, MES workflow, batch, CPP/CQA change, approval, electronic signature, runtime telemetry, monitoring, and evidence records?",
    "evidence_outputs": [
        "AI recommendation evidence record",
        "Digital Twin influence evidence record",
        "MES workflow execution evidence record",
        "Batch impact evidence record",
        "CPP/CQA change evidence record",
        "Human approval evidence record",
        "Electronic signature evidence record",
        "Execution support evidence record",
        "Inspection-ready execution reconstruction package"
    ]
}

continuous_assurance_enrichment = {
    "stage_rule": "Strengthen Continuous Assurance by continuously validating AI-to-MES execution integrity, batch execution trustworthiness, human oversight, runtime compliance, evidence completeness, and operational trust.",
    "validation_scope": [
        "AI-to-MES execution integrity",
        "Batch execution trustworthiness",
        "Human oversight",
        "Runtime compliance",
        "Manufacturing evidence completeness",
        "Operational trust"
    ],
    "stage_question": "Are AI-to-MES execution integrity, batch execution trustworthiness, human oversight, runtime compliance, manufacturing evidence completeness, and operational trust continuously validated?",
    "evidence_outputs": [
        "AI-to-MES execution integrity validation record",
        "Batch execution trustworthiness validation record",
        "Human oversight validation record",
        "Runtime compliance validation record",
        "Manufacturing evidence completeness validation record",
        "Operational trust validation record"
    ]
}

traceability_map = [
    {
        "execution_area": "AI recommendation to MES workflow",
        "operationalization_object": "AI-to-MES orchestration record",
        "monitoring_signal": "AI recommendations executed in MES",
        "evidence_question": "Which AI generated the recommendation?",
        "continuous_assurance_check": "AI-to-MES execution integrity",
        "inspection_relevance": "Shows how the AI recommendation moved from recommendation to controlled MES execution."
    },
    {
        "execution_area": "Digital Twin influenced execution",
        "operationalization_object": "Digital Twin to MES workflow reference",
        "monitoring_signal": "Runtime manufacturing telemetry",
        "evidence_question": "Which Digital Twin, if any, influenced the recommendation?",
        "continuous_assurance_check": "Manufacturing evidence completeness",
        "inspection_relevance": "Shows whether simulation or twin output influenced regulated execution."
    },
    {
        "execution_area": "Batch execution",
        "operationalization_object": "Batch execution orchestration record",
        "monitoring_signal": "Batch execution monitoring record",
        "evidence_question": "Which batch was affected?",
        "continuous_assurance_check": "Batch execution trustworthiness",
        "inspection_relevance": "Links AI-enabled execution to the affected batch record."
    },
    {
        "execution_area": "EBR and electronic signature",
        "operationalization_object": "Electronic Batch Record integration record",
        "monitoring_signal": "Electronic Batch Record monitoring record",
        "evidence_question": "Which electronic signatures were applied?",
        "continuous_assurance_check": "Runtime compliance",
        "inspection_relevance": "Supports regulated review of approvals, signatures, and execution records."
    },
    {
        "execution_area": "CPP/CQA change",
        "operationalization_object": "Recipe execution orchestration record",
        "monitoring_signal": "CPP monitoring record / CQA monitoring record",
        "evidence_question": "Which CPPs/CQAs changed?",
        "continuous_assurance_check": "Runtime compliance and manufacturing evidence completeness",
        "inspection_relevance": "Connects AI-enabled execution to critical process and quality attributes."
    },
    {
        "execution_area": "Human approval before execution",
        "operationalization_object": "Human approval before execution record",
        "monitoring_signal": "Workflow execution and approval telemetry",
        "evidence_question": "Who approved execution?",
        "continuous_assurance_check": "Human oversight",
        "inspection_relevance": "Demonstrates qualified human oversight before regulated manufacturing execution."
    }
]

patch_model = {
    "patch_marker": PATCH_MARKER,
    "patch_type": "ai_to_mes_execution_assurance_not_new_module",
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
    "manufacturing_assurance_thesis": manufacturing_assurance_thesis,
    "strengthened_stages": [
        "Operationalization",
        "Manufacturing Monitoring",
        "Evidence",
        "Continuous Assurance"
    ],
    "operationalization_enrichment": operationalization_enrichment,
    "manufacturing_monitoring_enrichment": manufacturing_monitoring_enrichment,
    "evidence_enrichment": evidence_enrichment,
    "continuous_assurance_enrichment": continuous_assurance_enrichment,
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

def patch_blueprint_seed():
    path = Path("platform_blueprint_library_seed.json")
    if not path.exists():
        print("SKIP: platform_blueprint_library_seed.json not found.")
        return False

    data = load_json(path)
    data["ai_to_mes_execution_assurance_patch"] = patch_model

    for bp in data.get("blueprints", []) or []:
        bp["ai_to_mes_execution_assurance"] = {
            "architecture_status": "FROZEN",
            "architecture_change": False,
            "new_module": False,
            "new_route": False,
            "lifecycle_change": False,
            "stage_strengthening_only": True,
            "strengthened_stages": [
                "Operationalization",
                "Manufacturing Monitoring",
                "Evidence",
                "Continuous Assurance"
            ],
            "thesis": manufacturing_assurance_thesis["statement"],
            "headline": manufacturing_assurance_thesis["headline"],
            "operational_trust_unchanged": True
        }

        bp["questions_answered"] = add_unique_list(
            bp.get("questions_answered", []),
            evidence_enrichment["execution_questions"] + [
                "Was the AI recommendation governed before MES execution?",
                "Was human approval captured before execution?",
                "Was MES execution monitored?",
                "Was the complete execution reconstructable during inspection?"
            ]
        )

        assessment = bp.get("sample_blueprint_assessment", {})
        if not isinstance(assessment, dict):
            assessment = {}

        assessment["ai_to_mes_execution_assurance_state"] = "OPERATIONALIZATION_MONITORING_EVIDENCE_ASSURANCE_STRENGTHENED_NO_NEW_MODULE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["new_route"] = False
        assessment["lifecycle_change"] = False
        assessment["stage_strengthening_only"] = True
        assessment["strengthened_stages"] = [
            "Operationalization",
            "Manufacturing Monitoring",
            "Evidence",
            "Continuous Assurance"
        ]
        assessment["permanent_lifecycle_sequence"] = patch_model["permanent_lifecycle_sequence"]
        assessment["manufacturing_assurance_thesis"] = manufacturing_assurance_thesis["statement"]
        assessment["operational_trust_rule"] = patch_model["operational_trust_rule"]
        bp["sample_blueprint_assessment"] = assessment

        for stage in bp.get("lifecycle", []) or []:
            stage_name = normalize_stage_name(stage.get("stage_name", ""))
            if not stage_name:
                continue

            stage["ai_to_mes_execution_assurance_guardrail"] = {
                "architecture_status": "FROZEN",
                "new_module_allowed": False,
                "new_route_allowed": False,
                "lifecycle_change_allowed": False,
                "stage_rename_allowed": False,
                "stage_strengthening_only": True
            }

            if stage_name == "Operationalization":
                stage["ai_to_mes_operationalization"] = operationalization_enrichment
                stage["ai_to_mes_operationalization_scope"] = operationalization_enrichment["ai_to_mes_operationalization_scope"]
                stage["stage_question"] = operationalization_enrichment["stage_question"]
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    operationalization_enrichment["evidence_outputs"]
                )
                stage["operational_focus"] = "Operationalization supports MES integration, batch execution orchestration, EBR, recipe execution, manufacturing workflow execution, AI-to-MES orchestration, human approval before execution, runtime authorization, electronic signatures, and GxP workflow integration."

            if stage_name == "Manufacturing Monitoring":
                stage["ai_to_mes_manufacturing_monitoring"] = manufacturing_monitoring_enrichment
                stage["ai_to_mes_monitoring_scope"] = manufacturing_monitoring_enrichment["monitoring_scope"]
                stage["stage_question"] = manufacturing_monitoring_enrichment["stage_question"]
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    manufacturing_monitoring_enrichment["evidence_outputs"]
                )
                stage["operational_focus"] = "Manufacturing Monitoring monitors MES execution, batch execution, EBR, AI recommendations executed in MES, CPPs, CQAs, equipment status, deviations, runtime manufacturing telemetry, and AI-to-MES traceability."

            if stage_name == "Evidence":
                stage["ai_to_mes_evidence"] = evidence_enrichment
                stage["ai_to_mes_execution_questions"] = evidence_enrichment["execution_questions"]
                stage["stage_question"] = evidence_enrichment["stage_question"]
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    evidence_enrichment["evidence_outputs"]
                )
                stage["ai_to_mes_traceability_map"] = traceability_map
                stage["operational_focus"] = "Evidence reconstructs which AI generated the recommendation, which Digital Twin influenced it, which MES workflow executed it, which batch was affected, which CPPs/CQAs changed, who approved execution, which e-signatures applied, and what evidence supports inspection reconstruction."

            if stage_name == "Continuous Assurance":
                stage["ai_to_mes_continuous_assurance"] = continuous_assurance_enrichment
                stage["ai_to_mes_validation_scope"] = continuous_assurance_enrichment["validation_scope"]
                stage["stage_question"] = continuous_assurance_enrichment["stage_question"]
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    continuous_assurance_enrichment["evidence_outputs"]
                )
                stage["operational_focus"] = "Continuous Assurance validates AI-to-MES execution integrity, batch execution trustworthiness, human oversight, runtime compliance, manufacturing evidence completeness, and operational trust."

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
    data["ai_to_mes_execution_assurance_patch"] = patch_model

    assessment = data.get("sample_integration_assessment", {})
    if not isinstance(assessment, dict):
        assessment = {}

    assessment["ai_to_mes_execution_assurance"] = {
        "state": "OPERATIONALIZATION_MONITORING_EVIDENCE_ASSURANCE_STRENGTHENED_NO_NEW_MODULE",
        "architecture_status": "FROZEN",
        "architecture_change": False,
        "new_module": False,
        "new_route": False,
        "lifecycle_change": False,
        "stage_strengthening_only": True,
        "manufacturing_assurance_thesis": manufacturing_assurance_thesis,
        "operationalization_enrichment": operationalization_enrichment,
        "manufacturing_monitoring_enrichment": manufacturing_monitoring_enrichment,
        "evidence_enrichment": evidence_enrichment,
        "continuous_assurance_enrichment": continuous_assurance_enrichment,
        "traceability_map": traceability_map
    }

    assessment["implementation_priority"] = add_unique_list(
        assessment.get("implementation_priority", []),
        [
            "Strengthen Operationalization with MES integration.",
            "Strengthen Operationalization with batch execution orchestration.",
            "Strengthen Operationalization with Electronic Batch Records.",
            "Strengthen Operationalization with recipe execution.",
            "Strengthen Operationalization with AI-to-MES orchestration.",
            "Strengthen Operationalization with human approval before execution.",
            "Strengthen Operationalization with runtime authorization and electronic signatures.",
            "Strengthen Manufacturing Monitoring with MES execution, batch execution, EBR, CPP, CQA, equipment, deviation, telemetry, and AI-to-MES traceability monitoring.",
            "Strengthen Evidence with inspection-ready AI-to-MES execution reconstruction.",
            "Strengthen Continuous Assurance with AI-to-MES execution integrity, batch trustworthiness, human oversight, runtime compliance, manufacturing evidence completeness, and operational trust.",
            "Keep Operational Trust unchanged as the lifecycle outcome."
        ]
    )

    assessment["evidence_automation_targets"] = add_unique_list(
        assessment.get("evidence_automation_targets", []),
        [
            "AI-to-MES orchestration evidence package",
            "MES workflow execution evidence package",
            "Batch impact evidence package",
            "EBR evidence package",
            "Recipe execution evidence package",
            "CPP/CQA change evidence package",
            "Electronic signature evidence package",
            "Human approval evidence package",
            "Runtime manufacturing telemetry evidence package",
            "Inspection-ready execution reconstruction package"
        ]
    )

    data["sample_integration_assessment"] = assessment

    lifecycle_object_map = {
        "Operationalization": [
            "MESIntegrationRecord",
            "BatchExecutionOrchestrationRecord",
            "ElectronicBatchRecordIntegrationRecord",
            "RecipeExecutionOrchestrationRecord",
            "ManufacturingWorkflowExecutionRecord",
            "AIToMESOrchestrationRecord",
            "HumanApprovalBeforeExecutionRecord",
            "RuntimeAuthorizationRecord",
            "ElectronicSignatureRecord",
            "GxPWorkflowIntegrationRecord"
        ],
        "Manufacturing Monitoring": [
            "MESExecutionMonitoringRecord",
            "BatchExecutionMonitoringRecord",
            "ElectronicBatchRecordMonitoringRecord",
            "AIRecommendationExecutedInMESMonitoringRecord",
            "CPPMonitoringRecord",
            "CQAMonitoringRecord",
            "EquipmentStatusMonitoringRecord",
            "ManufacturingDeviationMonitoringRecord",
            "RuntimeManufacturingTelemetryRecord",
            "AIToMESExecutionTraceabilityMonitoringRecord"
        ],
        "Evidence": [
            "AIRecommendationEvidenceRecord",
            "DigitalTwinInfluenceEvidenceRecord",
            "MESWorkflowExecutionEvidenceRecord",
            "BatchImpactEvidenceRecord",
            "CPPCQAChangeEvidenceRecord",
            "HumanApprovalEvidenceRecord",
            "ElectronicSignatureEvidenceRecord",
            "ExecutionSupportEvidenceRecord",
            "InspectionReadyExecutionReconstructionPackage"
        ],
        "Continuous Assurance": [
            "AIToMESExecutionIntegrityValidationRecord",
            "BatchExecutionTrustworthinessValidationRecord",
            "HumanOversightValidationRecord",
            "RuntimeComplianceValidationRecord",
            "ManufacturingEvidenceCompletenessValidationRecord",
            "OperationalTrustValidationRecord"
        ]
    }

    for stage in data.get("integration_flow", []) or []:
        stage_name = normalize_stage_name(stage.get("stage_name", "")) or normalize_stage_name(stage.get("stage_id", ""))

        stage["ai_to_mes_execution_assurance_guardrail"] = {
            "architecture_status": "FROZEN",
            "new_module_allowed": False,
            "new_route_allowed": False,
            "lifecycle_change_allowed": False,
            "stage_strengthening_only": True
        }

        if stage_name == "Operationalization":
            stage["ai_to_mes_operationalization"] = operationalization_enrichment
            stage["operational_question"] = operationalization_enrichment["stage_question"]
            stage["expected_objects"] = add_unique_list(
                stage.get("expected_objects", []),
                lifecycle_object_map["Operationalization"]
            )
            stage["evidence_outputs"] = add_unique_list(
                stage.get("evidence_outputs", []),
                operationalization_enrichment["evidence_outputs"]
            )

        if stage_name == "Manufacturing Monitoring":
            stage["ai_to_mes_manufacturing_monitoring"] = manufacturing_monitoring_enrichment
            stage["operational_question"] = manufacturing_monitoring_enrichment["stage_question"]
            stage["expected_objects"] = add_unique_list(
                stage.get("expected_objects", []),
                lifecycle_object_map["Manufacturing Monitoring"]
            )
            stage["evidence_outputs"] = add_unique_list(
                stage.get("evidence_outputs", []),
                manufacturing_monitoring_enrichment["evidence_outputs"]
            )

        if stage_name == "Evidence":
            stage["ai_to_mes_evidence"] = evidence_enrichment
            stage["ai_to_mes_traceability_map"] = traceability_map
            stage["operational_question"] = evidence_enrichment["stage_question"]
            stage["expected_objects"] = add_unique_list(
                stage.get("expected_objects", []),
                lifecycle_object_map["Evidence"]
            )
            stage["evidence_outputs"] = add_unique_list(
                stage.get("evidence_outputs", []),
                evidence_enrichment["evidence_outputs"]
            )

        if stage_name == "Continuous Assurance":
            stage["ai_to_mes_continuous_assurance"] = continuous_assurance_enrichment
            stage["operational_question"] = continuous_assurance_enrichment["stage_question"]
            stage["expected_objects"] = add_unique_list(
                stage.get("expected_objects", []),
                lifecycle_object_map["Continuous Assurance"]
            )
            stage["evidence_outputs"] = add_unique_list(
                stage.get("evidence_outputs", []),
                continuous_assurance_enrichment["evidence_outputs"]
            )

    save_json(path, data)
    print("PATCHED: platform_lifecycle_integration_seed.json")
    return True

def html_escape(s):
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )

def build_trace_rows():
    rows = []
    for item in traceability_map:
        rows.append(
            "<tr>"
            f"<td><strong>{html_escape(item['execution_area'])}</strong></td>"
            f"<td>{html_escape(item['operationalization_object'])}</td>"
            f"<td>{html_escape(item['monitoring_signal'])}</td>"
            f"<td>{html_escape(item['evidence_question'])}</td>"
            f"<td>{html_escape(item['continuous_assurance_check'])}</td>"
            f"<td>{html_escape(item['inspection_relevance'])}</td>"
            "</tr>"
        )
    return "\n".join(rows)

trace_rows = build_trace_rows()

ux_styles = r'''
<style>
.ai-mes-table-wrap {
    overflow-x: auto;
    border: 1px solid rgba(255,255,255,.12);
    border-radius: 18px;
    background: rgba(255,255,255,.035);
    box-shadow: 0 18px 50px rgba(0,0,0,.28);
}
.ai-mes-table {
    width: 100%;
    min-width: 1150px;
    border-collapse: collapse;
    font-size: 13px;
}
.ai-mes-table th {
    background: #111827;
    color: #ffb25f;
    text-align: left;
    padding: 14px;
    border-bottom: 1px solid rgba(255,255,255,.14);
}
.ai-mes-table td {
    vertical-align: top;
    padding: 14px;
    border-bottom: 1px solid rgba(255,255,255,.08);
    color: #d8dee9;
    line-height: 1.5;
}
.ai-mes-table tr:hover td {
    background: rgba(255,122,24,.06);
}
</style>
'''

blueprint_block = f'''
{ux_styles}
<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">AI-to-MES Execution Assurance</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                As AI becomes embedded within pharmaceutical manufacturing, the assurance boundary shifts from validating AI recommendations to continuously assuring their execution within regulated manufacturing systems such as MES.
            </div>
        </div>
        <span class="tag">No new module</span>
    </div>

    <div class="grid">
        <div class="panel"><strong>Operationalization</strong><div>MES integration, batch execution orchestration, Electronic Batch Records (EBR), recipe execution, manufacturing workflow execution, AI-to-MES orchestration, human approval before execution, runtime authorization, electronic signatures, and GxP workflow integration.</div></div>
        <div class="panel"><strong>Manufacturing Monitoring</strong><div>MES execution, batch execution, EBR, AI recommendations executed in MES, CPP monitoring, CQA monitoring, equipment status, manufacturing deviations, runtime manufacturing telemetry, and AI-to-MES execution traceability.</div></div>
        <div class="panel"><strong>Evidence</strong><div>Which AI generated the recommendation? Which Digital Twin influenced it? Which MES workflow executed it? Which batch was affected? Which CPPs/CQAs changed? Who approved execution? Which electronic signatures were applied? Can the complete execution be reconstructed during inspection?</div></div>
        <div class="panel"><strong>Continuous Assurance</strong><div>AI-to-MES execution integrity, batch execution trustworthiness, human oversight, runtime compliance, manufacturing evidence completeness, and operational trust.</div></div>
    </div>

    <div class="topbar" style="margin-top:24px;">
        <div>
            <h3 style="margin:0;font-size:22px;">AI-to-MES Inspection Traceability</h3>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                This table links manufacturing execution to monitoring, evidence, continuous assurance, and inspection relevance.
            </div>
        </div>
    </div>

    <div class="ai-mes-table-wrap">
        <table class="ai-mes-table">
            <thead>
                <tr>
                    <th>Execution Area</th>
                    <th>Operationalization Object</th>
                    <th>Monitoring Signal</th>
                    <th>Evidence Question</th>
                    <th>Continuous Assurance Check</th>
                    <th>Inspection Relevance</th>
                </tr>
            </thead>
            <tbody>
                {trace_rows}
            </tbody>
        </table>
    </div>
</section>
'''

platform_block = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>AI-to-MES Execution Assurance</h2>
            <p>The assurance boundary now extends from validating AI recommendations to continuously assuring their execution within regulated manufacturing systems such as MES, EBR, batch execution, recipe execution, electronic signatures, and GxP workflows.</p>
        </div>
        <span class="tag">Execution assurance</span>
    </div>
    <div class="grid-4">
        <a class="card" href="/platform/blueprints/ai-enabled-cmc"><strong>AI-enabled CMC Blueprint</strong><span>Shows AI-to-MES execution, EBR, batch, CPP/CQA, approval, signature, and inspection reconstruction evidence.</span><small>Open blueprint</small></a>
        <a class="card" href="/platform/blueprints/agentic-enterprise"><strong>Agentic Enterprise Blueprint</strong><span>Connects agentic execution assurance to regulated manufacturing execution workflows.</span><small>Open blueprint</small></a>
        <a class="card" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Maps AI-to-MES records into Operationalization, Manufacturing Monitoring, Evidence, and Continuous Assurance.</span><small>Open lifecycle</small></a>
        <a class="card" href="/platform/evidence-packages"><strong>Evidence</strong><span>Builds inspection-ready execution reconstruction packages.</span><small>Open evidence</small></a>
    </div>
</section>
'''

library_block = r'''
<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">AI-to-MES Assurance Boundary</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Blueprints may strengthen AI-to-MES execution assurance only inside the existing lifecycle. This is not a new MES module.
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
            <h2>AI-to-MES Execution Assurance Routes</h2>
            <p>AI-to-MES execution assurance is exposed through existing routes only. No new module or route was added.</p>
        </div>
        <span class="tag">Existing routes only</span>
    </div>
    <div class="route-grid">
        <a class="route" href="/platform"><strong>Platform Command Center</strong><span>Shows AI-to-MES execution assurance inside the frozen lifecycle.</span><code>/platform</code></a>
        <a class="route" href="/platform/blueprints/ai-enabled-cmc"><strong>AI-enabled CMC Blueprint</strong><span>Displays MES, EBR, batch, recipe, CPP/CQA, approval, signature, and inspection reconstruction traceability.</span><code>/platform/blueprints/ai-enabled-cmc</code></a>
        <a class="route" href="/platform/blueprints/agentic-enterprise"><strong>Agentic Enterprise Blueprint</strong><span>Displays regulated execution assurance for agentic enterprise workflows.</span><code>/platform/blueprints/agentic-enterprise</code></a>
        <a class="route" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Connects AI-to-MES execution records to lifecycle evidence and assurance.</span><code>/platform/lifecycle-integration</code></a>
    </div>
</section>
'''

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

Path("ai_to_mes_execution_assurance_patch_v1_summary.json").write_text(
    json.dumps(patch_model, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("ai_to_mes_execution_assurance_patch_v1_urls.txt").write_text(
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
print("AI-to-MES Execution Assurance Patch completed.")
print("Marker:")
print("  " + PATCH_MARKER)
print("No new module. No new route. No architecture change. Lifecycle unchanged.")
