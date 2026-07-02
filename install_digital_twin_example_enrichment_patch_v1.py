from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_DIGITAL_TWIN_EXAMPLE_ENRICHMENT_PATCH_V1_ACTIVE"

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

digital_twin_discovery_examples = [
    "AI-assisted Digital Twin",
    "AI-assisted formulation simulation",
    "AI-assisted process simulation",
    "Digital Twin optimization",
    "Manufacturing Digital Twin",
    "Process Digital Twin",
    "Scale-up Digital Twin",
    "AI-assisted technology transfer",
    "AI-assisted facility optimization"
]

digital_twin_lifecycle_questions = [
    "Which Digital Twin produced this recommendation?",
    "Which Digital Twin modified these CPPs?",
    "Which simulation influenced this decision?",
    "Was the Digital Twin reviewed before execution?",
    "What evidence supports the Digital Twin recommendation?"
]

digital_twin_operationalization_governance = [
    "Digital Twin registration",
    "Twin version control",
    "Twin approval",
    "Twin validation status",
    "Simulation lineage",
    "Simulation approval",
    "AI-to-Twin orchestration",
    "Twin runtime monitoring",
    "Twin performance monitoring"
]

manufacturing_monitoring_expansion = [
    "AI monitoring",
    "Digital Twin monitoring",
    "Process monitoring",
    "Model monitoring",
    "Recommendation monitoring",
    "Runtime monitoring"
]

digital_twin_evidence_capture = [
    "Digital Twin evidence",
    "Simulation evidence",
    "Recommendation evidence",
    "Execution evidence",
    "Parameter changes",
    "CPP/CQA optimization evidence",
    "Human approvals",
    "Runtime evidence"
]

digital_twin_traceability = [
    {
        "lifecycle_stage": "Discovery",
        "digital_twin_focus": "AI-assisted Digital Twin discovery",
        "question": "Which Digital Twin produced this recommendation?",
        "evidence_expected": "Digital Twin discovery record",
        "trust_impact": "Confirms the Digital Twin is identified before recommendations are trusted."
    },
    {
        "lifecycle_stage": "Discovery",
        "digital_twin_focus": "Formulation and process simulation",
        "question": "Which simulation influenced this decision?",
        "evidence_expected": "Simulation evidence record",
        "trust_impact": "Confirms formulation or process decisions can be traced to the simulation that influenced them."
    },
    {
        "lifecycle_stage": "Operationalization",
        "digital_twin_focus": "Digital Twin Governance",
        "question": "Was the Digital Twin reviewed before execution?",
        "evidence_expected": "Twin approval and validation status record",
        "trust_impact": "Confirms the Digital Twin was approved, version-controlled, and suitable for operational use."
    },
    {
        "lifecycle_stage": "Operationalization",
        "digital_twin_focus": "AI-to-Twin orchestration",
        "question": "Which AI or agent interacted with the Digital Twin?",
        "evidence_expected": "AI-to-Twin orchestration record",
        "trust_impact": "Confirms AI-to-Twin execution can be reconstructed."
    },
    {
        "lifecycle_stage": "Manufacturing Monitoring",
        "digital_twin_focus": "CPP/CQA and runtime monitoring",
        "question": "Which Digital Twin modified these CPPs?",
        "evidence_expected": "CPP/CQA optimization evidence record",
        "trust_impact": "Confirms process parameter changes and quality attribute optimization are monitored and evidence-bound."
    },
    {
        "lifecycle_stage": "Evidence",
        "digital_twin_focus": "Digital Twin recommendation evidence",
        "question": "What evidence supports the Digital Twin recommendation?",
        "evidence_expected": "Digital Twin recommendation evidence package",
        "trust_impact": "Confirms the recommendation, simulation, execution, parameter change, approval, and runtime evidence can be replayed."
    }
]

digital_twin_enrichment = {
    "patch_marker": PATCH_MARKER,
    "patch_type": "digital_twin_example_enrichment_not_new_module",
    "architecture_change": False,
    "new_module": False,
    "new_route": False,
    "lifecycle_change": False,
    "platform_rule": "No new Digital Twin module. No new architecture. No lifecycle change. Enrich existing AI-enabled CMC Blueprint examples only.",
    "locked_lifecycle": locked_lifecycle,
    "discovery_examples": digital_twin_discovery_examples,
    "lifecycle_questions": digital_twin_lifecycle_questions,
    "operationalization_governance": digital_twin_operationalization_governance,
    "manufacturing_monitoring_expansion": manufacturing_monitoring_expansion,
    "evidence_capture": digital_twin_evidence_capture,
    "traceability": digital_twin_traceability,
    "core_statement": "Digital Twin assurance fits inside the existing AI-enabled CMC lifecycle by making simulations, recommendations, CPP/CQA changes, approvals, runtime behavior, and evidence replayable without adding a new module."
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
    data["digital_twin_example_enrichment_patch"] = digital_twin_enrichment

    for bp in data.get("blueprints", []) or []:
        if bp.get("blueprint_id") != "ai_enabled_cmc":
            continue

        bp["digital_twin_example_enrichment"] = digital_twin_enrichment
        bp["locked_lifecycle"] = locked_lifecycle
        bp["questions_answered"] = add_unique_list(
            bp.get("questions_answered", []),
            digital_twin_lifecycle_questions + [
                "Which AI-assisted formulation simulation influenced formulation design?",
                "Which AI-assisted process simulation influenced process design?",
                "Which Digital Twin optimization changed process understanding?",
                "Which Manufacturing Digital Twin or Process Digital Twin was used?",
                "Which Scale-up Digital Twin supported scale-up or technology transfer?",
                "Which AI-assisted facility optimization recommendation influenced operations?"
            ]
        )

        assessment = bp.get("sample_blueprint_assessment", {})
        assessment["digital_twin_enrichment_state"] = "DIGITAL_TWIN_EXAMPLES_CONNECTED_TO_EXISTING_CMC_LIFECYCLE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["new_route"] = False
        assessment["lifecycle_change"] = False
        assessment["digital_twin_discovery_example_count"] = len(digital_twin_discovery_examples)
        assessment["digital_twin_operationalization_governance_count"] = len(digital_twin_operationalization_governance)
        assessment["digital_twin_monitoring_signal_count"] = len(manufacturing_monitoring_expansion)
        assessment["digital_twin_evidence_capture_count"] = len(digital_twin_evidence_capture)
        assessment["digital_twin_next_actions"] = [
            "Bind each Digital Twin recommendation to the Digital Twin identity and version.",
            "Bind simulation outputs to decisions, CPP/CQA changes, and human approvals.",
            "Bind Twin validation status and approval status to operational execution.",
            "Bind AI-to-Twin orchestration evidence to agent/tool-call lineage.",
            "Bind Twin runtime and performance monitoring to Continuous Assurance and Operational Trust."
        ]
        bp["sample_blueprint_assessment"] = assessment

        for stage in bp.get("lifecycle", []) or []:
            stage_name = stage.get("stage_name", "")

            if stage_name == "Discovery":
                stage["digital_twin_discovery_examples"] = digital_twin_discovery_examples
                stage["stage_question"] = (
                    "Which AI-assisted Digital Twin, formulation simulation, process simulation, manufacturing twin, process twin, scale-up twin, technology transfer simulation, or facility optimization capability exists in the CMC workflow?"
                )
                stage["operational_focus"] = (
                    "Discover AI-assisted Digital Twin activity, including formulation simulation, process simulation, Digital Twin optimization, Manufacturing Digital Twin, Process Digital Twin, Scale-up Digital Twin, AI-assisted technology transfer, and AI-assisted facility optimization."
                )
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    [
                        "AI-assisted Digital Twin discovery record",
                        "Formulation simulation discovery record",
                        "Process simulation discovery record",
                        "Manufacturing Digital Twin discovery record",
                        "Process Digital Twin discovery record",
                        "Scale-up Digital Twin discovery record",
                        "Technology transfer simulation record",
                        "Facility optimization discovery record"
                    ]
                )

            if stage_name == "Visibility":
                stage["digital_twin_lifecycle_questions"] = digital_twin_lifecycle_questions
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    [
                        "Digital Twin inventory record",
                        "Twin ownership record",
                        "Twin version visibility record",
                        "Simulation-to-decision visibility record"
                    ]
                )

            if stage_name == "Governance":
                stage["digital_twin_lifecycle_questions"] = digital_twin_lifecycle_questions
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    [
                        "Digital Twin governance control mapping",
                        "Twin approval governance record",
                        "Twin validation status governance record",
                        "Simulation governance record"
                    ]
                )

            if stage_name == "Operationalization":
                stage["digital_twin_governance"] = digital_twin_operationalization_governance
                stage["digital_twin_traceability"] = digital_twin_traceability
                stage["stage_question"] = (
                    "Were Digital Twin registration, version control, approval, validation status, simulation lineage, simulation approval, AI-to-Twin orchestration, runtime monitoring, and performance monitoring governed before execution?"
                )
                stage["operational_focus"] = (
                    "Operationalization now includes Digital Twin Governance: registration, version control, approval, validation status, simulation lineage, simulation approval, AI-to-Twin orchestration, Twin runtime monitoring, and Twin performance monitoring."
                )
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    [
                        "Digital Twin registration record",
                        "Twin version control record",
                        "Twin approval record",
                        "Twin validation status record",
                        "Simulation lineage record",
                        "Simulation approval record",
                        "AI-to-Twin orchestration record",
                        "Twin runtime monitoring record",
                        "Twin performance monitoring record"
                    ]
                )

            if stage_name == "Manufacturing Monitoring":
                stage["manufacturing_monitoring_expansion"] = manufacturing_monitoring_expansion
                stage["digital_twin_monitoring"] = [
                    "Monitor AI behavior",
                    "Monitor Digital Twin behavior",
                    "Monitor process behavior",
                    "Monitor model behavior",
                    "Monitor recommendations",
                    "Monitor runtime execution"
                ]
                stage["stage_question"] = (
                    "Are AI behavior, Digital Twin behavior, process behavior, model behavior, recommendations, and runtime execution monitored for trust, drift, and evidence gaps?"
                )
                stage["operational_focus"] = (
                    "Manufacturing Monitoring now includes AI monitoring, Digital Twin monitoring, process monitoring, model monitoring, recommendation monitoring, and runtime monitoring."
                )
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    [
                        "AI monitoring record",
                        "Digital Twin monitoring record",
                        "Process monitoring record",
                        "Model monitoring record",
                        "Recommendation monitoring record",
                        "Runtime monitoring record",
                        "CPP/CQA monitoring record",
                        "Twin performance monitoring record"
                    ]
                )

            if stage_name == "Evidence":
                stage["digital_twin_evidence_capture"] = digital_twin_evidence_capture
                stage["digital_twin_lifecycle_questions"] = digital_twin_lifecycle_questions
                stage["stage_question"] = (
                    "Can Digital Twin evidence, simulation evidence, recommendation evidence, execution evidence, parameter changes, CPP/CQA optimization evidence, human approvals, and runtime evidence be reconstructed?"
                )
                stage["operational_focus"] = (
                    "Evidence now captures Digital Twin evidence, simulation evidence, recommendation evidence, execution evidence, parameter changes, CPP/CQA optimization evidence, human approvals, and runtime evidence."
                )
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    digital_twin_evidence_capture + [
                        "Digital Twin recommendation evidence package",
                        "Simulation-to-decision evidence map",
                        "Twin-to-CPP/CQA change evidence map",
                        "Twin execution evidence record"
                    ]
                )

            if stage_name == "Continuous Assurance":
                stage["digital_twin_lifecycle_questions"] = digital_twin_lifecycle_questions
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    [
                        "Digital Twin monitoring trend record",
                        "Twin performance assurance record",
                        "Twin drift or deviation record",
                        "Twin lifecycle assurance record"
                    ]
                )

            if stage_name == "Operational Trust":
                stage["digital_twin_lifecycle_questions"] = digital_twin_lifecycle_questions
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    [
                        "Digital Twin operational trust record",
                        "Twin recommendation trust impact record",
                        "Simulation trust justification record"
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
    data["digital_twin_example_enrichment_patch"] = digital_twin_enrichment

    assessment = data.get("sample_integration_assessment", {})
    assessment["digital_twin_enrichment"] = {
        "state": "DIGITAL_TWIN_EXAMPLES_CONNECTED_TO_EXISTING_LIFECYCLE",
        "architecture_change": False,
        "new_module": False,
        "new_route": False,
        "lifecycle_change": False,
        "digital_twin_discovery_examples": digital_twin_discovery_examples,
        "digital_twin_lifecycle_questions": digital_twin_lifecycle_questions,
        "digital_twin_operationalization_governance": digital_twin_operationalization_governance,
        "manufacturing_monitoring_expansion": manufacturing_monitoring_expansion,
        "digital_twin_evidence_capture": digital_twin_evidence_capture
    }

    assessment["evidence_automation_targets"] = add_unique_list(
        assessment.get("evidence_automation_targets", []),
        [
            "Digital Twin evidence binder",
            "Simulation evidence binder",
            "Recommendation evidence binder",
            "Twin execution evidence binder",
            "Parameter change evidence binder",
            "CPP/CQA optimization evidence binder",
            "Twin approval evidence binder",
            "Twin runtime evidence binder"
        ]
    )

    data["sample_integration_assessment"] = assessment

    digital_twin_objects = [
        "DigitalTwinRegistrationRecord",
        "TwinVersionControlRecord",
        "TwinApprovalRecord",
        "TwinValidationStatusRecord",
        "SimulationLineageRecord",
        "SimulationApprovalRecord",
        "AIToTwinOrchestrationRecord",
        "TwinRuntimeMonitoringRecord",
        "TwinPerformanceMonitoringRecord",
        "DigitalTwinEvidenceRecord",
        "SimulationEvidenceRecord",
        "RecommendationEvidenceRecord",
        "TwinExecutionEvidenceRecord",
        "ParameterChangeEvidenceRecord",
        "CPPCQAOptimizationEvidenceRecord"
    ]

    for stage in data.get("integration_flow", []) or []:
        stage_id = stage.get("stage_id", "")

        if stage_id == "discovery_visibility":
            stage["digital_twin_discovery_examples"] = digital_twin_discovery_examples
            stage["digital_twin_lifecycle_questions"] = digital_twin_lifecycle_questions
            stage["expected_objects"] = add_unique_list(stage.get("expected_objects", []), digital_twin_objects)
            stage["evidence_outputs"] = add_unique_list(
                stage.get("evidence_outputs", []),
                [
                    "Digital Twin discovery record",
                    "Simulation discovery record",
                    "Twin visibility record",
                    "Simulation-to-decision visibility record"
                ]
            )

        if stage_id in ["governance_operationalization", "output_clearance"]:
            stage["digital_twin_operationalization_governance"] = digital_twin_operationalization_governance
            stage["digital_twin_traceability"] = digital_twin_traceability
            stage["expected_objects"] = add_unique_list(stage.get("expected_objects", []), digital_twin_objects)
            stage["evidence_outputs"] = add_unique_list(
                stage.get("evidence_outputs", []),
                [
                    "Digital Twin registration record",
                    "Twin version control record",
                    "Twin approval record",
                    "Twin validation status record",
                    "Simulation lineage record",
                    "Simulation approval record",
                    "AI-to-Twin orchestration record"
                ]
            )

        if stage_id in ["evidence_contract", "monitoring_response_learning"]:
            stage["digital_twin_evidence_capture"] = digital_twin_evidence_capture
            stage["manufacturing_monitoring_expansion"] = manufacturing_monitoring_expansion
            stage["expected_objects"] = add_unique_list(stage.get("expected_objects", []), digital_twin_objects)
            stage["evidence_outputs"] = add_unique_list(
                stage.get("evidence_outputs", []),
                [
                    "Digital Twin evidence",
                    "Simulation evidence",
                    "Recommendation evidence",
                    "Execution evidence",
                    "Parameter changes",
                    "CPP/CQA optimization evidence",
                    "Human approvals",
                    "Runtime evidence"
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

cmc_digital_twin_block = r'''
<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">Digital Twin Examples Added to Existing Lifecycle</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Discovery now includes AI-assisted Digital Twin, AI-assisted formulation simulation, AI-assisted process simulation, Digital Twin optimization, Manufacturing Digital Twin, Process Digital Twin, Scale-up Digital Twin, AI-assisted technology transfer, and AI-assisted facility optimization. No Digital Twin module was added.
            </div>
        </div>
        <span class="tag">No new module</span>
    </div>
    <div class="grid">
        <div class="panel"><strong>Lifecycle Questions</strong><div>Which Digital Twin produced this recommendation?<br>Which Digital Twin modified these CPPs?<br>Which simulation influenced this decision?<br>Was the Digital Twin reviewed before execution?<br>What evidence supports the Digital Twin recommendation?</div></div>
        <div class="panel"><strong>Lifecycle Locked</strong><div>Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust</div></div>
    </div>
</section>

<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">Digital Twin Governance in Operationalization</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Operationalization now includes Digital Twin registration, Twin version control, Twin approval, Twin validation status, simulation lineage, simulation approval, AI-to-Twin orchestration, Twin runtime monitoring, and Twin performance monitoring.
            </div>
        </div>
        <span class="tag">Operationalization enriched</span>
    </div>
</section>

<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">Digital Twin Monitoring and Evidence</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Manufacturing Monitoring now includes AI monitoring, Digital Twin monitoring, process monitoring, model monitoring, recommendation monitoring, and runtime monitoring. Evidence now captures Digital Twin evidence, simulation evidence, recommendation evidence, execution evidence, parameter changes, CPP/CQA optimization evidence, human approvals, and runtime evidence.
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
            <h2>Digital Twin Examples Enriched</h2>
            <p>The AI-enabled CMC Blueprint now includes Digital Twin examples inside the existing lifecycle. Discovery, Operationalization, Manufacturing Monitoring, and Evidence were enriched without adding a Digital Twin module, route, architecture, or lifecycle stage.</p>
        </div>
        <span class="tag">Existing lifecycle</span>
    </div>
    <div class="grid-4">
        <a class="card" href="/platform/blueprints/ai-enabled-cmc"><strong>CMC Digital Twin Examples</strong><span>Discovery includes AI-assisted formulation simulation, process simulation, Digital Twin optimization, manufacturing twin, process twin, scale-up twin, technology transfer, and facility optimization.</span><small>Open CMC blueprint</small></a>
        <a class="card" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Digital Twin evidence binds to existing lifecycle integration, evidence automation, monitoring, and operational trust.</span><small>Open lifecycle</small></a>
        <a class="card" href="/platform/evidence-packages"><strong>Evidence Vault</strong><span>Evidence captures simulation evidence, recommendations, execution evidence, parameter changes, CPP/CQA optimization, approvals, and runtime evidence.</span><small>Open evidence</small></a>
        <a class="card" href="/platform/ai-output-clearance"><strong>Output Clearance</strong><span>Digital Twin recommendations can be reviewed before execution and tied to evidence.</span><small>Open clearance</small></a>
    </div>
</section>
'''

route_registry_block = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>Digital Twin Example Enrichment</h2>
            <p>Digital Twin examples were added to the existing AI-enabled CMC Blueprint lifecycle. This is not a new module or new route.</p>
        </div>
        <span class="tag">No new route</span>
    </div>
    <div class="route-grid">
        <a class="route" href="/platform/blueprints/ai-enabled-cmc"><strong>AI-enabled CMC Blueprint</strong><span>Includes Digital Twin discovery examples, Digital Twin Governance in Operationalization, expanded Manufacturing Monitoring, and Digital Twin evidence capture.</span><code>/platform/blueprints/ai-enabled-cmc</code></a>
        <a class="route" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Digital Twin evidence objects connect to the existing lifecycle integration model.</span><code>/platform/lifecycle-integration</code></a>
        <a class="route" href="/api/platform/blueprints/ai-enabled-cmc/demo"><strong>CMC Blueprint API</strong><span>Existing API returns digital_twin_example_enrichment fields.</span><code>/api/platform/blueprints/ai-enabled-cmc/demo</code></a>
        <a class="route" href="/api/platform/lifecycle-integration/model/demo"><strong>Lifecycle API</strong><span>Existing API returns Digital Twin enrichment status inside lifecycle integration.</span><code>/api/platform/lifecycle-integration/model/demo</code></a>
    </div>
</section>
'''

patch_blueprint_seed()
patch_lifecycle_seed()

patch_html(
    "platform_ai_enabled_cmc_blueprint.html",
    cmc_digital_twin_block,
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
    "digital_twin_discovery_examples": digital_twin_discovery_examples,
    "digital_twin_lifecycle_questions": digital_twin_lifecycle_questions,
    "digital_twin_operationalization_governance": digital_twin_operationalization_governance,
    "manufacturing_monitoring_expansion": manufacturing_monitoring_expansion,
    "digital_twin_evidence_capture": digital_twin_evidence_capture,
    "digital_twin_traceability": digital_twin_traceability
}

Path("digital_twin_example_enrichment_patch_v1_summary.json").write_text(
    json.dumps(summary, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("digital_twin_example_enrichment_patch_v1_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform",
        "http://127.0.0.1:5000/platform/routes",
        "http://127.0.0.1:5000/platform/blueprints/ai-enabled-cmc",
        "http://127.0.0.1:5000/platform/lifecycle-integration",
        "http://127.0.0.1:5000/platform/evidence-packages",
        "http://127.0.0.1:5000/platform/ai-output-clearance",
        "http://127.0.0.1:5000/api/platform/blueprints/ai-enabled-cmc/demo",
        "http://127.0.0.1:5000/api/platform/blueprints/model/demo",
        "http://127.0.0.1:5000/api/platform/lifecycle-integration/model/demo"
    ]),
    encoding="utf-8"
)

print("")
print("Digital Twin Example Enrichment Patch completed.")
print("Marker:")
print("  " + PATCH_MARKER)
print("No Digital Twin module. No new route. No architecture change. Lifecycle unchanged.")
