from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_CSA_ALIGNED_PROPORTIONALITY_PATCH_V1_ACTIVE"

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

csa_aligned_principle = {
    "headline": "Assurance evidence must be proportional to risk and intended use.",
    "platform_question": "Was the assurance evidence proportional to the risk and intended use of the automated or AI-enabled function?",
    "scope_rule": "No CSA module is created. CSA-aligned thinking strengthens existing Operationalization and Evidence stages only.",
    "architecture_change": False,
    "new_module": False,
    "new_route": False,
    "lifecycle_change": False
}

operationalization_enrichment = {
    "stage_rule": "Strengthen Operationalization with CSA-aligned implementation discipline for automated and AI-enabled functions.",
    "csa_aligned_operationalization_scope": [
        "Intended use",
        "Process risk",
        "Function-level criticality",
        "Risk-based testing rigor",
        "Vendor reliance rationale",
        "Objective evidence rationale",
        "Change impact",
        "Evidence proportionality",
        "Validated state",
        "Maintained assurance"
    ],
    "stage_question": "Was the automated or AI-enabled function operationalized according to intended use, process risk, function-level criticality, risk-based testing rigor, vendor reliance rationale, objective evidence rationale, change impact, evidence proportionality, validated state, and maintained assurance?",
    "evidence_outputs": [
        "Intended-use operationalization record",
        "Process-risk operationalization record",
        "Function-level criticality record",
        "Risk-based testing rigor record",
        "Vendor reliance rationale record",
        "Objective evidence rationale record",
        "Change impact record",
        "Evidence proportionality record",
        "Validated state record",
        "Maintained assurance record"
    ]
}

evidence_enrichment = {
    "stage_rule": "Strengthen Evidence so assurance packages justify why the evidence is proportional to risk and intended use.",
    "csa_aligned_evidence_scope": [
        "Intended-use evidence",
        "Process-risk evidence",
        "Function-level criticality evidence",
        "Risk-based testing evidence",
        "Vendor reliance evidence",
        "Objective evidence rationale",
        "Change impact evidence",
        "Evidence proportionality rationale",
        "Validated-state evidence",
        "Maintained-assurance evidence"
    ],
    "execution_questions": [
        "What is the intended use of the automated or AI-enabled function?",
        "What process risk does the function introduce or control?",
        "What is the function-level criticality?",
        "Was testing rigor proportional to risk?",
        "What vendor reliance rationale was used?",
        "What objective evidence supports the decision?",
        "What change impact was assessed?",
        "Why is the evidence proportional?",
        "Is the function in a validated state?",
        "How is assurance maintained after implementation?"
    ],
    "stage_question": "Can the evidence package justify intended use, process risk, function-level criticality, testing rigor, vendor reliance, objective evidence, change impact, proportionality, validated state, and maintained assurance?",
    "evidence_outputs": [
        "Intended-use evidence record",
        "Process-risk evidence record",
        "Function-level criticality evidence record",
        "Risk-based testing evidence record",
        "Vendor reliance evidence record",
        "Objective evidence rationale evidence record",
        "Change impact evidence record",
        "Evidence proportionality rationale record",
        "Validated-state evidence record",
        "Maintained-assurance evidence record",
        "CSA-aligned evidence proportionality package"
    ]
}

traceability_map = [
    {
        "csa_aligned_dimension": "Intended use",
        "operationalization_question": "What is the function intended to do in the regulated or operational process?",
        "evidence_question": "What evidence proves the function was implemented and used within its intended use?",
        "trust_impact": "Prevents assurance from drifting beyond the approved context of use."
    },
    {
        "csa_aligned_dimension": "Process risk",
        "operationalization_question": "What process risk is introduced, reduced, or controlled by the automated or AI-enabled function?",
        "evidence_question": "What evidence shows that assurance activities are aligned to process risk?",
        "trust_impact": "Links testing and evidence to operational and patient-quality impact."
    },
    {
        "csa_aligned_dimension": "Function-level criticality",
        "operationalization_question": "Which functions are critical, important, or lower risk?",
        "evidence_question": "What evidence shows the critical functions received the right assurance rigor?",
        "trust_impact": "Focuses assurance effort on functions that matter most."
    },
    {
        "csa_aligned_dimension": "Risk-based testing rigor",
        "operationalization_question": "Was testing depth proportional to risk and function criticality?",
        "evidence_question": "What evidence supports the selected testing rigor?",
        "trust_impact": "Prevents both under-testing and unnecessary over-documentation."
    },
    {
        "csa_aligned_dimension": "Vendor reliance rationale",
        "operationalization_question": "What vendor documentation, testing, certification, or prior use is being relied upon?",
        "evidence_question": "What evidence supports the decision to rely on vendor information?",
        "trust_impact": "Makes external reliance explicit, reviewed, and auditable."
    },
    {
        "csa_aligned_dimension": "Objective evidence rationale",
        "operationalization_question": "What objective evidence is needed to demonstrate fitness for intended use?",
        "evidence_question": "What objective evidence was produced, reviewed, and retained?",
        "trust_impact": "Keeps assurance evidence factual, reviewable, and reconstructable."
    },
    {
        "csa_aligned_dimension": "Change impact",
        "operationalization_question": "What changed, what functions are affected, and what assurance must be refreshed?",
        "evidence_question": "What evidence shows the change impact was assessed and addressed?",
        "trust_impact": "Maintains the validated state across operational change."
    },
    {
        "csa_aligned_dimension": "Evidence proportionality",
        "operationalization_question": "Is the evidence burden proportional to risk, intended use, and function criticality?",
        "evidence_question": "Why is the collected evidence sufficient and proportionate?",
        "trust_impact": "Supports lean, risk-based, defensible assurance."
    },
    {
        "csa_aligned_dimension": "Validated state",
        "operationalization_question": "Is the function ready for controlled use in the operational environment?",
        "evidence_question": "What evidence confirms the validated state?",
        "trust_impact": "Supports controlled release into operation."
    },
    {
        "csa_aligned_dimension": "Maintained assurance",
        "operationalization_question": "How will assurance be maintained after release?",
        "evidence_question": "What evidence shows ongoing assurance is maintained?",
        "trust_impact": "Connects operationalization to continuous assurance and operational trust."
    }
]

patch_model = {
    "patch_marker": PATCH_MARKER,
    "patch_type": "csa_aligned_operationalization_evidence_proportionality_not_new_module",
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
    "csa_aligned_principle": csa_aligned_principle,
    "operationalization_enrichment": operationalization_enrichment,
    "evidence_enrichment": evidence_enrichment,
    "traceability_map": traceability_map,
    "stage_strengthening_scope": [
        "Operationalization",
        "Evidence"
    ],
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
    data["csa_aligned_proportionality_patch"] = patch_model

    for bp in data.get("blueprints", []) or []:
        bp["csa_aligned_proportionality"] = {
            "architecture_status": "FROZEN",
            "architecture_change": False,
            "new_module": False,
            "new_route": False,
            "lifecycle_change": False,
            "stage_strengthening_only": True,
            "strengthened_stages": ["Operationalization", "Evidence"],
            "platform_question": csa_aligned_principle["platform_question"],
            "scope_rule": csa_aligned_principle["scope_rule"],
            "operational_trust_unchanged": True
        }

        bp["questions_answered"] = add_unique_list(
            bp.get("questions_answered", []),
            [
                "Was the assurance evidence proportional to the risk and intended use of the automated or AI-enabled function?",
                "What is the intended use of the automated or AI-enabled function?",
                "What is the process risk?",
                "What is the function-level criticality?",
                "Was testing rigor proportional to risk?",
                "What vendor reliance rationale was used?",
                "What objective evidence supports the decision?",
                "What change impact was assessed?",
                "Is the function in a validated state?",
                "How is assurance maintained after implementation?"
            ]
        )

        assessment = bp.get("sample_blueprint_assessment", {})
        if not isinstance(assessment, dict):
            assessment = {}
        assessment["csa_aligned_proportionality_state"] = "OPERATIONALIZATION_AND_EVIDENCE_STRENGTHENED_NO_NEW_MODULE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["new_route"] = False
        assessment["lifecycle_change"] = False
        assessment["stage_strengthening_only"] = True
        assessment["strengthened_stages"] = ["Operationalization", "Evidence"]
        assessment["platform_question"] = csa_aligned_principle["platform_question"]
        assessment["permanent_lifecycle_sequence"] = patch_model["permanent_lifecycle_sequence"]
        assessment["operational_trust_rule"] = patch_model["operational_trust_rule"]
        assessment["traceability_dimension_count"] = len(traceability_map)
        bp["sample_blueprint_assessment"] = assessment

        for stage in bp.get("lifecycle", []) or []:
            stage_name = normalize_stage_name(stage.get("stage_name", ""))
            if not stage_name:
                continue

            stage["csa_aligned_guardrail"] = {
                "new_module_allowed": False,
                "new_route_allowed": False,
                "lifecycle_change_allowed": False,
                "stage_rename_allowed": False,
                "stage_strengthening_only": True
            }

            if stage_name == "Operationalization":
                stage["csa_aligned_operationalization"] = operationalization_enrichment
                stage["stage_question"] = operationalization_enrichment["stage_question"]
                stage["csa_aligned_scope"] = operationalization_enrichment["csa_aligned_operationalization_scope"]
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    operationalization_enrichment["evidence_outputs"]
                )
                stage["operational_focus"] = "Operationalization now includes CSA-aligned intended use, process risk, function-level criticality, risk-based testing rigor, vendor reliance rationale, objective evidence rationale, change impact, evidence proportionality, validated state, and maintained assurance."

            if stage_name == "Evidence":
                stage["csa_aligned_evidence"] = evidence_enrichment
                stage["stage_question"] = evidence_enrichment["stage_question"]
                stage["csa_aligned_evidence_scope"] = evidence_enrichment["csa_aligned_evidence_scope"]
                stage["csa_aligned_execution_questions"] = evidence_enrichment["execution_questions"]
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    evidence_enrichment["evidence_outputs"]
                )
                stage["operational_focus"] = "Evidence now justifies whether assurance evidence is proportional to the risk and intended use of the automated or AI-enabled function."

            if stage_name == "Continuous Assurance":
                stage["csa_aligned_continuous_assurance_reference"] = {
                    "maintained_assurance": "Continuous Assurance uses maintained-assurance evidence from Operationalization and Evidence to support runtime trust and operational trust.",
                    "evidence_integrity": "Continuous Assurance checks that proportionality rationale, validated-state evidence, and maintained-assurance evidence remain current."
                }

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
    data["csa_aligned_proportionality_patch"] = patch_model

    assessment = data.get("sample_integration_assessment", {})
    if not isinstance(assessment, dict):
        assessment = {}

    assessment["csa_aligned_proportionality"] = {
        "state": "OPERATIONALIZATION_AND_EVIDENCE_STRENGTHENED_NO_NEW_MODULE",
        "architecture_status": "FROZEN",
        "architecture_change": False,
        "new_module": False,
        "new_route": False,
        "lifecycle_change": False,
        "stage_strengthening_only": True,
        "strengthened_stages": ["Operationalization", "Evidence"],
        "platform_question": csa_aligned_principle["platform_question"],
        "operationalization_enrichment": operationalization_enrichment,
        "evidence_enrichment": evidence_enrichment,
        "traceability_map": traceability_map
    }

    assessment["implementation_priority"] = add_unique_list(
        assessment.get("implementation_priority", []),
        [
            "Strengthen Operationalization with intended use.",
            "Strengthen Operationalization with process risk.",
            "Strengthen Operationalization with function-level criticality.",
            "Strengthen Operationalization with risk-based testing rigor.",
            "Strengthen Operationalization with vendor reliance rationale.",
            "Strengthen Operationalization with objective evidence rationale.",
            "Strengthen Operationalization with change impact.",
            "Strengthen Operationalization with evidence proportionality.",
            "Strengthen Operationalization with validated state.",
            "Strengthen Operationalization with maintained assurance.",
            "Strengthen Evidence so assurance evidence is proportional to risk and intended use.",
            "Keep Operational Trust unchanged as the lifecycle outcome."
        ]
    )

    assessment["evidence_automation_targets"] = add_unique_list(
        assessment.get("evidence_automation_targets", []),
        [
            "Intended-use evidence binder",
            "Process-risk evidence binder",
            "Function-level criticality evidence binder",
            "Risk-based testing evidence binder",
            "Vendor reliance evidence binder",
            "Objective evidence rationale binder",
            "Change impact evidence binder",
            "Evidence proportionality rationale binder",
            "Validated-state evidence binder",
            "Maintained-assurance evidence binder",
            "CSA-aligned evidence proportionality package"
        ]
    )

    data["sample_integration_assessment"] = assessment

    lifecycle_object_map = {
        "Operationalization": [
            "IntendedUseOperationalizationRecord",
            "ProcessRiskOperationalizationRecord",
            "FunctionLevelCriticalityRecord",
            "RiskBasedTestingRigorRecord",
            "VendorRelianceRationaleRecord",
            "ObjectiveEvidenceRationaleRecord",
            "ChangeImpactRecord",
            "EvidenceProportionalityRecord",
            "ValidatedStateRecord",
            "MaintainedAssuranceRecord"
        ],
        "Evidence": [
            "IntendedUseEvidenceRecord",
            "ProcessRiskEvidenceRecord",
            "FunctionLevelCriticalityEvidenceRecord",
            "RiskBasedTestingEvidenceRecord",
            "VendorRelianceEvidenceRecord",
            "ObjectiveEvidenceRationaleEvidenceRecord",
            "ChangeImpactEvidenceRecord",
            "EvidenceProportionalityRationaleRecord",
            "ValidatedStateEvidenceRecord",
            "MaintainedAssuranceEvidenceRecord",
            "CSAAlignedEvidenceProportionalityPackage"
        ]
    }

    for stage in data.get("integration_flow", []) or []:
        stage_name = normalize_stage_name(stage.get("stage_name", "")) or normalize_stage_name(stage.get("stage_id", ""))

        stage["csa_aligned_proportionality_guardrail"] = {
            "architecture_status": "FROZEN",
            "new_module_allowed": False,
            "new_route_allowed": False,
            "lifecycle_change_allowed": False,
            "stage_strengthening_only": True
        }

        if stage_name == "Operationalization":
            stage["csa_aligned_operationalization"] = operationalization_enrichment
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
            stage["csa_aligned_evidence"] = evidence_enrichment
            stage["operational_question"] = evidence_enrichment["stage_question"]
            stage["expected_objects"] = add_unique_list(
                stage.get("expected_objects", []),
                lifecycle_object_map["Evidence"]
            )
            stage["evidence_outputs"] = add_unique_list(
                stage.get("evidence_outputs", []),
                evidence_enrichment["evidence_outputs"]
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
            <h2 style="margin:0;font-size:30px;">CSA-Aligned Evidence Proportionality</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                This strengthens Operationalization and Evidence only. No CSA module, route, architecture, stage, pillar, or lifecycle phase was created.
            </div>
        </div>
        <span class="tag">No new module</span>
    </div>
    <div class="grid">
        <div class="panel"><strong>Platform question</strong><div>Was the assurance evidence proportional to the risk and intended use of the automated or AI-enabled function?</div></div>
        <div class="panel"><strong>Operationalization</strong><div>Intended use, process risk, function-level criticality, risk-based testing rigor, vendor reliance rationale, objective evidence rationale, change impact, evidence proportionality, validated state, and maintained assurance.</div></div>
        <div class="panel"><strong>Evidence</strong><div>Intended-use evidence, process-risk evidence, function-level criticality evidence, risk-based testing evidence, vendor reliance evidence, objective evidence rationale, change impact evidence, evidence proportionality rationale, validated-state evidence, and maintained-assurance evidence.</div></div>
        <div class="panel"><strong>Operational Trust</strong><div>Operational Trust remains unchanged as the outcome of Discovery, Visibility, Governance, Operationalization, Manufacturing Monitoring, Evidence, and Continuous Assurance.</div></div>
    </div>
</section>
'''

platform_block = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>CSA-Aligned Operationalization and Evidence Proportionality</h2>
            <p>Operationalization and Evidence now include intended use, process risk, function-level criticality, risk-based testing rigor, vendor reliance rationale, objective evidence rationale, change impact, evidence proportionality, validated state, and maintained assurance. No CSA module or architecture change.</p>
        </div>
        <span class="tag">Stage strengthening only</span>
    </div>
    <div class="grid-4">
        <a class="card" href="/platform/blueprints/ai-enabled-cmc"><strong>AI-enabled CMC Blueprint</strong><span>Shows CSA-aligned proportionality inside the existing lifecycle.</span><small>Open blueprint</small></a>
        <a class="card" href="/platform/blueprints/agentic-enterprise"><strong>Agentic Enterprise Blueprint</strong><span>Applies proportionality logic to AI-enabled execution evidence.</span><small>Open blueprint</small></a>
        <a class="card" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Maps proportionality records to Operationalization and Evidence.</span><small>Open lifecycle</small></a>
        <a class="card" href="/platform/evidence-packages"><strong>Evidence</strong><span>Evidence packages justify why assurance is proportional to risk and intended use.</span><small>Open evidence</small></a>
    </div>
</section>
'''

library_block = r'''
<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">CSA-Aligned Thinking Without a CSA Module</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Blueprints may apply CSA-aligned proportionality only by strengthening existing Operationalization and Evidence stages. The lifecycle remains unchanged.
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
            <h2>CSA-Aligned Proportionality Routes</h2>
            <p>CSA-aligned proportionality is exposed through existing routes only. No CSA module or route was added.</p>
        </div>
        <span class="tag">Existing routes only</span>
    </div>
    <div class="route-grid">
        <a class="route" href="/platform"><strong>Platform Command Center</strong><span>Shows proportionality as stage strengthening only.</span><code>/platform</code></a>
        <a class="route" href="/platform/blueprints/ai-enabled-cmc"><strong>AI-enabled CMC Blueprint</strong><span>Displays CSA-aligned Operationalization and Evidence enrichment.</span><code>/platform/blueprints/ai-enabled-cmc</code></a>
        <a class="route" href="/platform/blueprints/agentic-enterprise"><strong>Agentic Enterprise Blueprint</strong><span>Displays proportionality logic for AI-enabled execution.</span><code>/platform/blueprints/agentic-enterprise</code></a>
        <a class="route" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Connects proportionality evidence to lifecycle assurance.</span><code>/platform/lifecycle-integration</code></a>
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

Path("csa_aligned_proportionality_patch_v1_summary.json").write_text(
    json.dumps(patch_model, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("csa_aligned_proportionality_patch_v1_urls.txt").write_text(
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
print("CSA-Aligned Operationalization and Evidence Proportionality Patch completed.")
print("Marker:")
print("  " + PATCH_MARKER)
print("No new module. No new route. No architecture change. Lifecycle unchanged.")
