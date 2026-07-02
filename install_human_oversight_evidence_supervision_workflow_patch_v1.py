from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_HUMAN_OVERSIGHT_EVIDENCE_SUPERVISION_WORKFLOW_PATCH_V1_ACTIVE"

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

human_oversight_feature = {
    "feature_name": "Human Oversight Evidence",
    "feature_type": "Existing-lifecycle feature, not a module",
    "architecture_status": "FROZEN",
    "architecture_change": False,
    "new_module": False,
    "new_route": False,
    "lifecycle_change": False,
    "purpose": "Ensure every AI execution produces a reconstructable human oversight evidence record when human review, challenge, override, approval, rejection, or escalation occurs or is required.",
    "platform_rule": "Every AI execution should be able to answer whether human review was required, whether review occurred, who challenged the AI, whether the recommendation was accepted, modified, rejected, or escalated, and why."
}

human_oversight_capture_fields = [
    "Human review",
    "Human challenge",
    "Human override",
    "Human approval",
    "Human rejection",
    "Human escalation",
    "Human accountability",
    "Review timestamps",
    "Reviewer identity",
    "Decision rationale"
]

human_oversight_execution_questions = [
    "Was human review required?",
    "Did human review occur?",
    "Who challenged the AI?",
    "Was the recommendation accepted?",
    "Was it modified?",
    "Was it rejected?",
    "Why?"
]

operationalization_enrichment = {
    "stage_rule": "Strengthen Operationalization with human oversight workflows for AI execution.",
    "workflow_scope": [
        "Human approval workflows",
        "Escalation workflows",
        "Human-AI collaboration",
        "Agent supervision",
        "Multi-agent supervision"
    ],
    "execution_flow": [
        "AI generates recommendation",
        "Platform B checks whether human review is required",
        "Human reviewer accepts, modifies, rejects, challenges, overrides, or escalates",
        "Platform B captures reviewer identity, timestamp, rationale, and decision outcome",
        "Evidence links the human decision to the AI execution",
        "Continuous Assurance validates oversight completeness",
        "Operational Trust is justified only when oversight evidence is complete"
    ],
    "stage_question": "Were human approval workflows, escalation workflows, Human-AI collaboration, agent supervision, and multi-agent supervision operationalized before or during AI execution?",
    "evidence_outputs": [
        "Human approval workflow record",
        "Escalation workflow record",
        "Human-AI collaboration record",
        "Agent supervision workflow record",
        "Multi-agent supervision workflow record",
        "Human review requirement record",
        "Human decision workflow record"
    ]
}

evidence_enrichment = {
    "stage_rule": "Strengthen Evidence with Human Oversight Evidence records for every AI execution.",
    "capture_fields": human_oversight_capture_fields,
    "execution_questions": human_oversight_execution_questions,
    "stage_question": "Does every AI execution have sufficient Human Oversight Evidence to reconstruct review requirement, review occurrence, challenge, acceptance, modification, rejection, escalation, accountability, timestamp, reviewer identity, and rationale?",
    "evidence_outputs": [
        "Human Oversight Evidence Record",
        "Human review evidence record",
        "Human challenge evidence record",
        "Human override evidence record",
        "Human approval evidence record",
        "Human rejection evidence record",
        "Human escalation evidence record",
        "Human accountability evidence record",
        "Review timestamp evidence record",
        "Reviewer identity evidence record",
        "Decision rationale evidence record",
        "AI execution human decision reconstruction package"
    ]
}

continuous_assurance_enrichment = {
    "stage_rule": "Strengthen Continuous Assurance by validating human oversight completeness and effectiveness.",
    "validation_scope": [
        "Human review completeness",
        "Human challenge traceability",
        "Human override integrity",
        "Human approval completeness",
        "Human rejection traceability",
        "Escalation effectiveness",
        "Reviewer identity completeness",
        "Decision rationale completeness",
        "Agent supervision effectiveness",
        "Multi-agent supervision effectiveness",
        "Runtime policy compliance",
        "Operational trust support"
    ],
    "stage_question": "Are human review completeness, challenge traceability, override integrity, approval completeness, rejection traceability, escalation effectiveness, reviewer identity, decision rationale, agent supervision, multi-agent supervision, runtime policy compliance, and operational trust support continuously validated?",
    "evidence_outputs": [
        "Human oversight completeness validation record",
        "Human review effectiveness validation record",
        "Challenge traceability validation record",
        "Override integrity validation record",
        "Approval completeness validation record",
        "Rejection traceability validation record",
        "Escalation effectiveness validation record",
        "Reviewer identity completeness validation record",
        "Decision rationale completeness validation record",
        "Agent supervision effectiveness validation record",
        "Multi-agent supervision effectiveness validation record",
        "Human oversight operational trust validation record"
    ]
}

human_oversight_decision_outcomes = [
    {
        "decision_outcome": "Accepted",
        "meaning": "The human reviewer accepted the AI recommendation as proposed.",
        "required_evidence": [
            "Reviewer identity",
            "Review timestamp",
            "Approval decision",
            "Decision rationale",
            "Applicable policy"
        ],
        "trust_effect": "Execution may proceed if approval authority, policy, and runtime authorization are valid."
    },
    {
        "decision_outcome": "Modified",
        "meaning": "The human reviewer changed the AI recommendation before execution.",
        "required_evidence": [
            "Original AI recommendation",
            "Modified recommendation",
            "Reviewer identity",
            "Review timestamp",
            "Modification rationale",
            "Applicable policy"
        ],
        "trust_effect": "Execution can be trusted only if the modification is traceable, justified, and authorized."
    },
    {
        "decision_outcome": "Rejected",
        "meaning": "The human reviewer rejected the AI recommendation.",
        "required_evidence": [
            "Rejected AI recommendation",
            "Reviewer identity",
            "Review timestamp",
            "Rejection rationale",
            "Escalation decision if needed"
        ],
        "trust_effect": "Execution should not proceed unless a new approved decision path is created."
    },
    {
        "decision_outcome": "Challenged",
        "meaning": "The human reviewer challenged the AI recommendation and required clarification, additional evidence, or escalation.",
        "required_evidence": [
            "Challenge record",
            "Reviewer identity",
            "Challenge timestamp",
            "Reason for challenge",
            "AI response or supporting evidence",
            "Resolution decision"
        ],
        "trust_effect": "Trust is conditional until challenge resolution is evidenced."
    },
    {
        "decision_outcome": "Overridden",
        "meaning": "The human reviewer overrode the AI recommendation or AI-supported workflow.",
        "required_evidence": [
            "Override record",
            "Reviewer identity",
            "Override timestamp",
            "Override rationale",
            "Approval authority",
            "Risk impact"
        ],
        "trust_effect": "Trust depends on override authority, rationale, risk review, and evidence completeness."
    },
    {
        "decision_outcome": "Escalated",
        "meaning": "The human reviewer escalated the AI recommendation to another authority or review path.",
        "required_evidence": [
            "Escalation record",
            "Escalating reviewer identity",
            "Escalation timestamp",
            "Escalation rationale",
            "Escalation recipient or authority",
            "Final disposition"
        ],
        "trust_effect": "Trust cannot be finalized until escalation disposition is captured."
    }
]

traceability_map = [
    {
        "oversight_area": "Human review requirement",
        "operationalization_object": "Human review requirement record",
        "evidence_question": "Was human review required?",
        "evidence_object": "Human Oversight Evidence Record",
        "continuous_assurance_check": "Human review completeness"
    },
    {
        "oversight_area": "Human review occurrence",
        "operationalization_object": "Human approval workflow record",
        "evidence_question": "Did human review occur?",
        "evidence_object": "Human review evidence record",
        "continuous_assurance_check": "Human review effectiveness"
    },
    {
        "oversight_area": "Human challenge",
        "operationalization_object": "Human-AI collaboration record",
        "evidence_question": "Who challenged the AI?",
        "evidence_object": "Human challenge evidence record",
        "continuous_assurance_check": "Challenge traceability"
    },
    {
        "oversight_area": "Human approval or rejection",
        "operationalization_object": "Human decision workflow record",
        "evidence_question": "Was the recommendation accepted, modified, or rejected?",
        "evidence_object": "Human approval / rejection / modification evidence record",
        "continuous_assurance_check": "Approval completeness and rejection traceability"
    },
    {
        "oversight_area": "Escalation",
        "operationalization_object": "Escalation workflow record",
        "evidence_question": "Why was the recommendation escalated?",
        "evidence_object": "Human escalation evidence record",
        "continuous_assurance_check": "Escalation effectiveness"
    },
    {
        "oversight_area": "Agent and multi-agent supervision",
        "operationalization_object": "Agent supervision and multi-agent supervision workflow records",
        "evidence_question": "Which human supervised the agent or multi-agent workflow?",
        "evidence_object": "Agent supervision evidence record",
        "continuous_assurance_check": "Agent supervision effectiveness and multi-agent supervision effectiveness"
    }
]

patch_model = {
    "patch_marker": PATCH_MARKER,
    "patch_type": "human_oversight_evidence_supervision_workflow_not_new_module",
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
    "feature": human_oversight_feature,
    "strengthened_stages": [
        "Operationalization",
        "Evidence",
        "Continuous Assurance"
    ],
    "operationalization_enrichment": operationalization_enrichment,
    "evidence_enrichment": evidence_enrichment,
    "continuous_assurance_enrichment": continuous_assurance_enrichment,
    "human_oversight_decision_outcomes": human_oversight_decision_outcomes,
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
    data["human_oversight_evidence_supervision_workflow_patch"] = patch_model

    for bp in data.get("blueprints", []) or []:
        bp["human_oversight_evidence_feature"] = {
            "feature_name": "Human Oversight Evidence",
            "feature_type": "Existing-lifecycle feature, not a module",
            "architecture_status": "FROZEN",
            "architecture_change": False,
            "new_module": False,
            "new_route": False,
            "lifecycle_change": False,
            "stage_strengthening_only": True,
            "strengthened_stages": [
                "Operationalization",
                "Evidence",
                "Continuous Assurance"
            ],
            "human_oversight_capture_fields": human_oversight_capture_fields,
            "human_oversight_execution_questions": human_oversight_execution_questions,
            "operational_trust_unchanged": True
        }

        bp["questions_answered"] = add_unique_list(
            bp.get("questions_answered", []),
            human_oversight_execution_questions + [
                "Which human reviewer was accountable?",
                "What was the review timestamp?",
                "What was the decision rationale?",
                "Was the AI recommendation challenged, overridden, approved, rejected, modified, or escalated?",
                "Can human oversight be reconstructed for this AI execution?"
            ]
        )

        assessment = bp.get("sample_blueprint_assessment", {})
        if not isinstance(assessment, dict):
            assessment = {}

        assessment["human_oversight_evidence_state"] = "HUMAN_OVERSIGHT_EVIDENCE_FEATURE_BUILT_NO_NEW_MODULE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["new_route"] = False
        assessment["lifecycle_change"] = False
        assessment["stage_strengthening_only"] = True
        assessment["strengthened_stages"] = [
            "Operationalization",
            "Evidence",
            "Continuous Assurance"
        ]
        assessment["feature_name"] = "Human Oversight Evidence"
        assessment["permanent_lifecycle_sequence"] = patch_model["permanent_lifecycle_sequence"]
        assessment["operational_trust_rule"] = patch_model["operational_trust_rule"]
        bp["sample_blueprint_assessment"] = assessment

        for stage in bp.get("lifecycle", []) or []:
            stage_name = normalize_stage_name(stage.get("stage_name", ""))
            if not stage_name:
                continue

            stage["human_oversight_evidence_guardrail"] = {
                "architecture_status": "FROZEN",
                "new_module_allowed": False,
                "new_route_allowed": False,
                "lifecycle_change_allowed": False,
                "stage_rename_allowed": False,
                "stage_strengthening_only": True
            }

            if stage_name == "Operationalization":
                stage["human_oversight_operationalization"] = operationalization_enrichment
                stage["human_oversight_workflow_scope"] = operationalization_enrichment["workflow_scope"]
                stage["human_oversight_execution_flow"] = operationalization_enrichment["execution_flow"]
                stage["stage_question"] = operationalization_enrichment["stage_question"]
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    operationalization_enrichment["evidence_outputs"]
                )
                stage["operational_focus"] = "Operationalization includes human approval workflows, escalation workflows, Human-AI collaboration, agent supervision, and multi-agent supervision."

            if stage_name == "Evidence":
                stage["human_oversight_evidence"] = evidence_enrichment
                stage["human_oversight_capture_fields"] = human_oversight_capture_fields
                stage["human_oversight_execution_questions"] = human_oversight_execution_questions
                stage["human_oversight_decision_outcomes"] = human_oversight_decision_outcomes
                stage["human_oversight_traceability_map"] = traceability_map
                stage["stage_question"] = evidence_enrichment["stage_question"]
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    evidence_enrichment["evidence_outputs"]
                )
                stage["operational_focus"] = "Evidence captures human review, challenge, override, approval, rejection, escalation, accountability, review timestamps, reviewer identity, and decision rationale for every AI execution."

            if stage_name == "Continuous Assurance":
                stage["human_oversight_continuous_assurance"] = continuous_assurance_enrichment
                stage["human_oversight_validation_scope"] = continuous_assurance_enrichment["validation_scope"]
                stage["stage_question"] = continuous_assurance_enrichment["stage_question"]
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    continuous_assurance_enrichment["evidence_outputs"]
                )
                stage["operational_focus"] = "Continuous Assurance validates human oversight completeness, challenge traceability, override integrity, approval completeness, escalation effectiveness, reviewer identity, decision rationale, agent supervision, multi-agent supervision, runtime policy compliance, and operational trust support."

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
    data["human_oversight_evidence_supervision_workflow_patch"] = patch_model

    assessment = data.get("sample_integration_assessment", {})
    if not isinstance(assessment, dict):
        assessment = {}

    assessment["human_oversight_evidence_feature"] = {
        "state": "HUMAN_OVERSIGHT_EVIDENCE_FEATURE_BUILT_NO_NEW_MODULE",
        "architecture_status": "FROZEN",
        "architecture_change": False,
        "new_module": False,
        "new_route": False,
        "lifecycle_change": False,
        "stage_strengthening_only": True,
        "feature_name": "Human Oversight Evidence",
        "operationalization_enrichment": operationalization_enrichment,
        "evidence_enrichment": evidence_enrichment,
        "continuous_assurance_enrichment": continuous_assurance_enrichment,
        "decision_outcomes": human_oversight_decision_outcomes,
        "traceability_map": traceability_map
    }

    assessment["implementation_priority"] = add_unique_list(
        assessment.get("implementation_priority", []),
        [
            "Build Human Oversight Evidence as an existing-lifecycle feature, not a module.",
            "Strengthen Operationalization with human approval workflows.",
            "Strengthen Operationalization with escalation workflows.",
            "Strengthen Operationalization with Human-AI collaboration.",
            "Strengthen Operationalization with agent supervision.",
            "Strengthen Operationalization with multi-agent supervision.",
            "Strengthen Evidence with human review, challenge, override, approval, rejection, escalation, accountability, timestamps, reviewer identity, and decision rationale.",
            "Strengthen Continuous Assurance with human oversight completeness and effectiveness validation.",
            "Keep Operational Trust unchanged as the lifecycle outcome."
        ]
    )

    assessment["evidence_automation_targets"] = add_unique_list(
        assessment.get("evidence_automation_targets", []),
        [
            "Human Oversight Evidence Record",
            "Human review evidence record",
            "Human challenge evidence record",
            "Human override evidence record",
            "Human approval evidence record",
            "Human rejection evidence record",
            "Human escalation evidence record",
            "Human accountability evidence record",
            "Review timestamp evidence record",
            "Reviewer identity evidence record",
            "Decision rationale evidence record",
            "AI execution human decision reconstruction package"
        ]
    )

    data["sample_integration_assessment"] = assessment

    lifecycle_object_map = {
        "Operationalization": [
            "HumanApprovalWorkflowRecord",
            "EscalationWorkflowRecord",
            "HumanAICollaborationRecord",
            "AgentSupervisionWorkflowRecord",
            "MultiAgentSupervisionWorkflowRecord",
            "HumanReviewRequirementRecord",
            "HumanDecisionWorkflowRecord"
        ],
        "Evidence": [
            "HumanOversightEvidenceRecord",
            "HumanReviewEvidenceRecord",
            "HumanChallengeEvidenceRecord",
            "HumanOverrideEvidenceRecord",
            "HumanApprovalEvidenceRecord",
            "HumanRejectionEvidenceRecord",
            "HumanEscalationEvidenceRecord",
            "HumanAccountabilityEvidenceRecord",
            "ReviewTimestampEvidenceRecord",
            "ReviewerIdentityEvidenceRecord",
            "DecisionRationaleEvidenceRecord",
            "AIExecutionHumanDecisionReconstructionPackage"
        ],
        "Continuous Assurance": [
            "HumanOversightCompletenessValidationRecord",
            "HumanReviewEffectivenessValidationRecord",
            "ChallengeTraceabilityValidationRecord",
            "OverrideIntegrityValidationRecord",
            "ApprovalCompletenessValidationRecord",
            "RejectionTraceabilityValidationRecord",
            "EscalationEffectivenessValidationRecord",
            "ReviewerIdentityCompletenessValidationRecord",
            "DecisionRationaleCompletenessValidationRecord",
            "AgentSupervisionEffectivenessValidationRecord",
            "MultiAgentSupervisionEffectivenessValidationRecord",
            "HumanOversightOperationalTrustValidationRecord"
        ]
    }

    for stage in data.get("integration_flow", []) or []:
        stage_name = normalize_stage_name(stage.get("stage_name", "")) or normalize_stage_name(stage.get("stage_id", ""))

        stage["human_oversight_evidence_guardrail"] = {
            "architecture_status": "FROZEN",
            "new_module_allowed": False,
            "new_route_allowed": False,
            "lifecycle_change_allowed": False,
            "stage_strengthening_only": True
        }

        if stage_name == "Operationalization":
            stage["human_oversight_operationalization"] = operationalization_enrichment
            stage["operational_question"] = operationalization_enrichment["stage_question"]
            stage["expected_objects"] = add_unique_list(
                stage.get("expected_objects", []),
                lifecycle_object_map["Operationalization"]
            )
            stage["evidence_outputs"] = add_unique_list(
                stage.get("evidence_outputs", []),
                operationalization_enrichment["evidence_outputs"]
            )

        if stage_name == "Evidence":
            stage["human_oversight_evidence"] = evidence_enrichment
            stage["human_oversight_decision_outcomes"] = human_oversight_decision_outcomes
            stage["human_oversight_traceability_map"] = traceability_map
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
            stage["human_oversight_continuous_assurance"] = continuous_assurance_enrichment
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

def build_outcome_rows():
    rows = []
    for item in human_oversight_decision_outcomes:
        rows.append(
            "<tr>"
            f"<td><strong>{html_escape(item['decision_outcome'])}</strong></td>"
            f"<td>{html_escape(item['meaning'])}</td>"
            f"<td>{html_escape(', '.join(item['required_evidence']))}</td>"
            f"<td>{html_escape(item['trust_effect'])}</td>"
            "</tr>"
        )
    return "\n".join(rows)

def build_trace_rows():
    rows = []
    for item in traceability_map:
        rows.append(
            "<tr>"
            f"<td><strong>{html_escape(item['oversight_area'])}</strong></td>"
            f"<td>{html_escape(item['operationalization_object'])}</td>"
            f"<td>{html_escape(item['evidence_question'])}</td>"
            f"<td>{html_escape(item['evidence_object'])}</td>"
            f"<td>{html_escape(item['continuous_assurance_check'])}</td>"
            "</tr>"
        )
    return "\n".join(rows)

outcome_rows = build_outcome_rows()
trace_rows = build_trace_rows()

ux_styles = r'''
<style>
.human-oversight-table-wrap {
    overflow-x: auto;
    border: 1px solid rgba(255,255,255,.12);
    border-radius: 18px;
    background: rgba(255,255,255,.035);
    box-shadow: 0 18px 50px rgba(0,0,0,.28);
}
.human-oversight-table {
    width: 100%;
    min-width: 1050px;
    border-collapse: collapse;
    font-size: 13px;
}
.human-oversight-table th {
    background: #111827;
    color: #ffb25f;
    text-align: left;
    padding: 14px;
    border-bottom: 1px solid rgba(255,255,255,.14);
}
.human-oversight-table td {
    vertical-align: top;
    padding: 14px;
    border-bottom: 1px solid rgba(255,255,255,.08);
    color: #d8dee9;
    line-height: 1.5;
}
.human-oversight-table tr:hover td {
    background: rgba(255,122,24,.06);
}
.human-oversight-list {
    columns: 2;
    column-gap: 34px;
    margin: 0;
    padding-left: 22px;
    color: #d8dee9;
    line-height: 1.7;
}
.human-oversight-list li {
    break-inside: avoid;
    margin-bottom: 8px;
}
</style>
'''

capture_items = "\n".join([f"<li>{html_escape(x)}</li>" for x in human_oversight_capture_fields])
question_items = "\n".join([f"<li>{html_escape(x)}</li>" for x in human_oversight_execution_questions])
workflow_items = "\n".join([f"<li>{html_escape(x)}</li>" for x in operationalization_enrichment["workflow_scope"]])

blueprint_block = f'''
{ux_styles}
<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">Human Oversight Evidence</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Human Oversight Evidence is built as a Platform B feature inside the existing lifecycle. No new module, route, architecture, stage, or lifecycle phase was created.
            </div>
        </div>
        <span class="tag">Feature, not module</span>
    </div>

    <div class="grid">
        <div class="panel"><strong>Operationalization</strong><div>Human approval workflows, escalation workflows, Human-AI collaboration, agent supervision, and multi-agent supervision.</div></div>
        <div class="panel"><strong>Evidence</strong><div>Human review, challenge, override, approval, rejection, escalation, accountability, timestamps, reviewer identity, and decision rationale.</div></div>
        <div class="panel"><strong>Continuous Assurance</strong><div>Validates oversight completeness, challenge traceability, override integrity, approval completeness, escalation effectiveness, supervision effectiveness, runtime policy compliance, and operational trust support.</div></div>
        <div class="panel"><strong>Operational Trust</strong><div>Operational Trust remains the outcome of the entire lifecycle.</div></div>
    </div>

    <div class="topbar" style="margin-top:24px;">
        <div>
            <h3 style="margin:0;font-size:22px;">Evidence Capture Fields</h3>
        </div>
    </div>
    <ul class="human-oversight-list">
        {capture_items}
    </ul>

    <div class="topbar" style="margin-top:24px;">
        <div>
            <h3 style="margin:0;font-size:22px;">Every AI Execution Must Answer</h3>
        </div>
    </div>
    <ul class="human-oversight-list">
        {question_items}
    </ul>

    <div class="topbar" style="margin-top:24px;">
        <div>
            <h3 style="margin:0;font-size:22px;">Operationalization Workflows</h3>
        </div>
    </div>
    <ul class="human-oversight-list">
        {workflow_items}
    </ul>

    <div class="topbar" style="margin-top:24px;">
        <div>
            <h3 style="margin:0;font-size:22px;">Human Decision Outcomes</h3>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">Each outcome must produce reviewable evidence before Operational Trust can be justified.</div>
        </div>
    </div>
    <div class="human-oversight-table-wrap">
        <table class="human-oversight-table">
            <thead>
                <tr>
                    <th>Decision Outcome</th>
                    <th>Meaning</th>
                    <th>Required Evidence</th>
                    <th>Trust Effect</th>
                </tr>
            </thead>
            <tbody>
                {outcome_rows}
            </tbody>
        </table>
    </div>

    <div class="topbar" style="margin-top:24px;">
        <div>
            <h3 style="margin:0;font-size:22px;">Oversight Traceability</h3>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">This links operational workflows to evidence and continuous assurance.</div>
        </div>
    </div>
    <div class="human-oversight-table-wrap">
        <table class="human-oversight-table">
            <thead>
                <tr>
                    <th>Oversight Area</th>
                    <th>Operationalization Object</th>
                    <th>Evidence Question</th>
                    <th>Evidence Object</th>
                    <th>Continuous Assurance Check</th>
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
            <h2>Human Oversight Evidence</h2>
            <p>Platform B now treats Human Oversight Evidence as an existing-lifecycle feature. Every AI execution should capture whether human review was required, whether it occurred, who challenged the AI, whether the recommendation was accepted, modified, rejected, overridden, or escalated, and why.</p>
        </div>
        <span class="tag">Feature, not module</span>
    </div>
    <div class="grid-4">
        <a class="card" href="/platform/blueprints/ai-enabled-cmc"><strong>AI-enabled CMC Blueprint</strong><span>Applies human oversight evidence to CMC, MES, EBR, batch, Digital Twin, and supply chain execution.</span><small>Open blueprint</small></a>
        <a class="card" href="/platform/blueprints/agentic-enterprise"><strong>Agentic Enterprise Blueprint</strong><span>Applies supervision evidence to agents, multi-agent workflows, delegation, escalation, and policy execution.</span><small>Open blueprint</small></a>
        <a class="card" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Maps human oversight records into Operationalization, Evidence, and Continuous Assurance.</span><small>Open lifecycle</small></a>
        <a class="card" href="/platform/evidence-packages"><strong>Evidence</strong><span>Builds AI execution human decision reconstruction packages.</span><small>Open evidence</small></a>
    </div>
</section>
'''

library_block = r'''
<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">Human Oversight Evidence Feature</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Blueprints may build Human Oversight Evidence only inside the existing lifecycle. It is a feature, not a new module or route.
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
            <h2>Human Oversight Evidence Routes</h2>
            <p>Human Oversight Evidence is shown through existing routes only. No new route was added.</p>
        </div>
        <span class="tag">Existing routes only</span>
    </div>
    <div class="route-grid">
        <a class="route" href="/platform"><strong>Platform Command Center</strong><span>Shows Human Oversight Evidence as an existing-lifecycle feature.</span><code>/platform</code></a>
        <a class="route" href="/platform/blueprints/ai-enabled-cmc"><strong>AI-enabled CMC Blueprint</strong><span>Displays human review, challenge, override, approval, rejection, escalation, accountability, timestamp, reviewer identity, and rationale evidence.</span><code>/platform/blueprints/ai-enabled-cmc</code></a>
        <a class="route" href="/platform/blueprints/agentic-enterprise"><strong>Agentic Enterprise Blueprint</strong><span>Displays agent supervision and multi-agent supervision evidence.</span><code>/platform/blueprints/agentic-enterprise</code></a>
        <a class="route" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Connects oversight workflow records to evidence and continuous assurance.</span><code>/platform/lifecycle-integration</code></a>
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

Path("human_oversight_evidence_supervision_workflow_patch_v1_summary.json").write_text(
    json.dumps(patch_model, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("human_oversight_evidence_supervision_workflow_patch_v1_urls.txt").write_text(
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
print("Human Oversight Evidence and Supervision Workflow Patch completed.")
print("Marker:")
print("  " + PATCH_MARKER)
print("No new module. No new route. No architecture change. Lifecycle unchanged.")
