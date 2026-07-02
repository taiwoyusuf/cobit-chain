from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_GOVERNANCE_MULTIFRAMEWORK_MAPPING_PATCH_V1_ACTIVE"

supported_frameworks = [
    "ISO 42001",
    "ISO 27001",
    "EU AI Act",
    "GDPR",
    "NIS2",
    "GAMP 5",
    "GxP",
    "FDA",
    "ICH",
    "Internal SOPs"
]

governance_capabilities = [
    "Multi-framework control mapping",
    "Multi-framework evidence mapping",
    "Unified governance implementation"
]

multi_framework_control_mapping = [
    {
        "control_name": "AI intended use control",
        "control_purpose": "Define and maintain approved intended use, excluded use, and operational boundaries.",
        "supports_frameworks": ["ISO 42001", "EU AI Act", "FDA", "GxP", "ICH", "Internal SOPs"],
        "implementation_model": "One intended-use control mapped to multiple obligations instead of separate framework-by-framework implementations.",
        "evidence_expected": ["Intended-use record", "Excluded-use boundary record", "Lifecycle synchronization record"]
    },
    {
        "control_name": "Human approval control",
        "control_purpose": "Require qualified human approval for consequential AI outputs, regulated workflow use, or governance boundary crossings.",
        "supports_frameworks": ["ISO 42001", "EU AI Act", "FDA", "GxP", "Internal SOPs"],
        "implementation_model": "One human approval control supports AI governance, regulated workflow accountability, quality review, and internal QA obligations.",
        "evidence_expected": ["Human approval record", "Qualified reviewer record", "Approval timestamp", "Approval rationale"]
    },
    {
        "control_name": "Evidence traceability control",
        "control_purpose": "Ensure AI decisions, outputs, approvals, model versions, prompt versions, runtime logs, and lifecycle events are traceable and reconstructable.",
        "supports_frameworks": ["ISO 42001", "EU AI Act", "FDA", "GAMP 5", "GxP", "ICH", "Internal SOPs"],
        "implementation_model": "One traceability control supports auditability, validation, AI governance, quality evidence, and regulatory defense.",
        "evidence_expected": ["Decision record", "Prompt version record", "Model/version record", "Runtime evidence record", "Lifecycle evidence record"]
    },
    {
        "control_name": "Access and identity control",
        "control_purpose": "Control who can access AI systems, prompts, tools, evidence, data, APIs, and regulated workflow functions.",
        "supports_frameworks": ["ISO 27001", "GDPR", "NIS2", "GxP", "Internal SOPs"],
        "implementation_model": "One access control supports cybersecurity, privacy, resilience, quality system, and internal authorization obligations.",
        "evidence_expected": ["Access control record", "Identity record", "Role authorization record", "Access review evidence"]
    },
    {
        "control_name": "Third-party AI oversight control",
        "control_purpose": "Govern vendors, external models, external APIs, tool providers, data providers, cloud services, and managed AI services.",
        "supports_frameworks": ["ISO 42001", "ISO 27001", "EU AI Act", "GDPR", "NIS2", "GxP", "Internal SOPs"],
        "implementation_model": "One third-party oversight control supports vendor governance, AI provider oversight, security oversight, privacy obligations, and quality supplier controls.",
        "evidence_expected": ["Third-party dependency register", "Vendor oversight record", "External API oversight record", "Third-party evidence requirement"]
    },
    {
        "control_name": "Change control and revalidation control",
        "control_purpose": "Trigger review, approval, revalidation, and evidence refresh when model, prompt, process, data, intended use, routing, retrieval, or workflow behavior changes.",
        "supports_frameworks": ["ISO 42001", "EU AI Act", "FDA", "GAMP 5", "GxP", "ICH", "Internal SOPs"],
        "implementation_model": "One lifecycle change control supports regulated change governance, validation, AI lifecycle management, and continuous assurance.",
        "evidence_expected": ["Change control record", "Revalidation trigger record", "Approval record", "Updated evidence package"]
    },
    {
        "control_name": "Incident and CAPA response control",
        "control_purpose": "Respond to AI incidents, deviations, drift, unsafe outputs, boundary crossings, evidence gaps, and operational failures.",
        "supports_frameworks": ["ISO 42001", "ISO 27001", "EU AI Act", "GDPR", "NIS2", "FDA", "GxP", "Internal SOPs"],
        "implementation_model": "One incident and CAPA response control supports AI incident handling, cybersecurity incident response, privacy incident response, quality deviation handling, and corrective action.",
        "evidence_expected": ["Incident evidence record", "Deviation record", "CAPA evidence record", "Root cause record", "Effectiveness check"]
    }
]

multi_framework_evidence_mapping = [
    {
        "evidence_item": "Human approval",
        "supports_frameworks": ["ISO 42001", "EU AI Act", "FDA", "GxP", "Internal QA"],
        "why_it_matters": "One human approval record can prove oversight, accountability, quality review, and regulated workflow control.",
        "reuse_rule": "One evidence item supports many regulations."
    },
    {
        "evidence_item": "Risk classification",
        "supports_frameworks": ["ISO 42001", "EU AI Act", "FDA", "GxP", "ICH", "Internal SOPs"],
        "why_it_matters": "One risk classification record can support AI risk governance, regulated impact assessment, and quality risk management.",
        "reuse_rule": "One evidence item supports many regulations."
    },
    {
        "evidence_item": "Prompt version record",
        "supports_frameworks": ["ISO 42001", "EU AI Act", "FDA", "GAMP 5", "GxP", "Internal SOPs"],
        "why_it_matters": "One prompt version record can support AI lifecycle control, validation traceability, output reconstruction, and change control.",
        "reuse_rule": "One evidence item supports many regulations."
    },
    {
        "evidence_item": "Model/version information",
        "supports_frameworks": ["ISO 42001", "EU AI Act", "FDA", "GAMP 5", "GxP", "Internal SOPs"],
        "why_it_matters": "One model/version record can support AI governance, validation state, change impact analysis, and operational trust recalculation.",
        "reuse_rule": "One evidence item supports many regulations."
    },
    {
        "evidence_item": "Data lineage record",
        "supports_frameworks": ["ISO 42001", "EU AI Act", "GDPR", "ISO 27001", "FDA", "GxP", "ICH"],
        "why_it_matters": "One data lineage record can support transparency, privacy, security, regulated decision reconstruction, and scientific/quality traceability.",
        "reuse_rule": "One evidence item supports many regulations."
    },
    {
        "evidence_item": "Runtime evidence",
        "supports_frameworks": ["ISO 42001", "ISO 27001", "EU AI Act", "NIS2", "FDA", "GxP", "Internal SOPs"],
        "why_it_matters": "One runtime evidence record can support operational monitoring, resilience, cybersecurity visibility, regulated auditability, and trust defense.",
        "reuse_rule": "One evidence item supports many regulations."
    },
    {
        "evidence_item": "Incident evidence",
        "supports_frameworks": ["ISO 42001", "ISO 27001", "EU AI Act", "GDPR", "NIS2", "FDA", "GxP", "Internal SOPs"],
        "why_it_matters": "One incident record can support AI incident response, security incident response, privacy response, quality deviation handling, and CAPA linkage.",
        "reuse_rule": "One evidence item supports many regulations."
    },
    {
        "evidence_item": "CAPA evidence",
        "supports_frameworks": ["FDA", "GxP", "ICH", "ISO 42001", "Internal QA", "Internal SOPs"],
        "why_it_matters": "One CAPA record can support regulated quality remediation, AI governance learning, effectiveness verification, and continuous assurance.",
        "reuse_rule": "One evidence item supports many regulations."
    },
    {
        "evidence_item": "Third-party oversight record",
        "supports_frameworks": ["ISO 42001", "ISO 27001", "EU AI Act", "GDPR", "NIS2", "GxP", "Internal SOPs"],
        "why_it_matters": "One third-party oversight record can support provider oversight, vendor risk management, privacy governance, security governance, and supplier quality controls.",
        "reuse_rule": "One evidence item supports many regulations."
    }
]

governance_multiframework_mapping = {
    "patch_marker": PATCH_MARKER,
    "patch_type": "governance_layer_enrichment_not_new_module",
    "architecture_change": False,
    "new_module": False,
    "new_route": False,
    "lifecycle_change": False,
    "platform_rule": "No new framework module. No new architecture. Strengthen the existing Governance layer only.",
    "governance_explicitly_supports": supported_frameworks,
    "governance_capabilities": governance_capabilities,
    "multi_framework_control_mapping": multi_framework_control_mapping,
    "multi_framework_evidence_mapping": multi_framework_evidence_mapping,
    "unified_governance_implementation": {
        "principle": "One AI control can satisfy many frameworks. One evidence item can support many regulations.",
        "wrong_model": [
            "Separate ISO 42001 implementation",
            "Separate EU AI Act implementation",
            "Separate FDA implementation",
            "Separate GxP implementation",
            "Separate Internal SOP implementation"
        ],
        "correct_model": [
            "Unified AI governance control",
            "Mapped to many framework obligations",
            "Supported by reusable evidence objects",
            "Continuously synchronized through the existing lifecycle"
        ]
    },
    "governance_question": "Which AI controls and evidence objects satisfy multiple framework obligations through one unified governance implementation?"
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
    data["governance_multiframework_mapping_patch"] = governance_multiframework_mapping

    for bp in data.get("blueprints", []) or []:
        bp["governance_multiframework_mapping"] = governance_multiframework_mapping
        bp["questions_answered"] = add_unique_list(
            bp.get("questions_answered", []),
            [
                "Which AI controls satisfy multiple frameworks simultaneously?",
                "Which evidence items support multiple regulations?",
                "Which governance obligations can be implemented once and mapped many times?",
                "Which framework obligations are satisfied by human approval evidence?",
                "Which framework obligations are satisfied by risk classification evidence?",
                "Which framework obligations are satisfied by prompt, model, runtime, incident, CAPA, and third-party evidence?"
            ]
        )

        assessment = bp.get("sample_blueprint_assessment", {})
        assessment["governance_multiframework_state"] = "GOVERNANCE_MULTIFRAMEWORK_MAPPING_CONNECTED_TO_EXISTING_GOVERNANCE_LAYER"
        assessment["governance_multiframework_question"] = governance_multiframework_mapping["governance_question"]
        assessment["supported_framework_count"] = len(supported_frameworks)
        assessment["multi_framework_control_mapping_count"] = len(multi_framework_control_mapping)
        assessment["multi_framework_evidence_mapping_count"] = len(multi_framework_evidence_mapping)
        assessment["unified_governance_principle"] = governance_multiframework_mapping["unified_governance_implementation"]["principle"]
        bp["sample_blueprint_assessment"] = assessment

        for stage in bp.get("lifecycle", []) or []:
            if stage.get("stage_name") == "Governance":
                stage["governance_multiframework_mapping"] = governance_multiframework_mapping
                stage["governance_explicitly_supports"] = supported_frameworks
                stage["governance_capabilities"] = governance_capabilities
                stage["stage_question"] = (
                    "Which AI controls and evidence objects satisfy ISO 42001, ISO 27001, EU AI Act, GDPR, NIS2, GAMP 5, GxP, FDA, ICH, and Internal SOP obligations through one unified governance implementation?"
                )
                stage["operational_focus"] = (
                    "Strengthen Governance by mapping one AI control to many frameworks and one evidence object to many regulatory obligations. This avoids separate framework-by-framework implementations and supports unified governance execution."
                )
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    [
                        "Multi-framework control map",
                        "Multi-framework evidence map",
                        "Unified governance implementation record",
                        "Framework obligation traceability record",
                        "Reusable evidence-to-framework mapping record",
                        "Human approval evidence mapping",
                        "Risk classification evidence mapping",
                        "Prompt/model/runtime evidence mapping",
                        "Incident and CAPA evidence mapping",
                        "Third-party oversight evidence mapping"
                    ]
                )

            if stage.get("stage_name") == "Evidence":
                stage["multi_framework_evidence_mapping"] = multi_framework_evidence_mapping
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    [
                        "Multi-framework evidence map",
                        "Evidence reuse record",
                        "Human approval multi-framework evidence record",
                        "Risk classification multi-framework evidence record",
                        "Prompt version multi-framework evidence record",
                        "Model/version multi-framework evidence record",
                        "Runtime multi-framework evidence record",
                        "Incident multi-framework evidence record",
                        "CAPA multi-framework evidence record"
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
    data["governance_multiframework_mapping_patch"] = governance_multiframework_mapping

    assessment = data.get("sample_integration_assessment", {})
    assessment["governance_multiframework_mapping"] = {
        "state": "MULTIFRAMEWORK_MAPPING_CONNECTED_TO_EXISTING_GOVERNANCE_LAYER",
        "architecture_change": False,
        "new_module": False,
        "new_route": False,
        "lifecycle_change": False,
        "supported_frameworks": supported_frameworks,
        "governance_capabilities": governance_capabilities,
        "control_mapping_count": len(multi_framework_control_mapping),
        "evidence_mapping_count": len(multi_framework_evidence_mapping),
        "principle": governance_multiframework_mapping["unified_governance_implementation"]["principle"]
    }
    assessment["implementation_priority"] = add_unique_list(
        assessment.get("implementation_priority", []),
        [
            "Implement one AI control and map it to many framework obligations.",
            "Bind one evidence item to many framework evidence expectations.",
            "Avoid separate framework-by-framework implementations.",
            "Use Governance as the unified mapping layer for ISO 42001, ISO 27001, EU AI Act, GDPR, NIS2, GAMP 5, GxP, FDA, ICH, and Internal SOPs."
        ]
    )
    assessment["evidence_automation_targets"] = add_unique_list(
        assessment.get("evidence_automation_targets", []),
        [
            "Multi-framework control map generator",
            "Multi-framework evidence map generator",
            "Evidence reuse matrix",
            "Human approval evidence-to-framework mapping",
            "Risk classification evidence-to-framework mapping",
            "Incident and CAPA evidence-to-framework mapping"
        ]
    )
    data["sample_integration_assessment"] = assessment

    governance_objects = [
        "MultiFrameworkControlMap",
        "MultiFrameworkEvidenceMap",
        "UnifiedGovernanceImplementation",
        "FrameworkObligationTraceability",
        "EvidenceReuseRecord",
        "HumanApprovalFrameworkEvidenceMap",
        "RiskClassificationFrameworkEvidenceMap",
        "PromptModelRuntimeEvidenceMap",
        "IncidentCAPAEvidenceMap",
        "ThirdPartyOversightEvidenceMap"
    ]

    for stage in data.get("integration_flow", []) or []:
        stage_id = stage.get("stage_id", "")

        if stage_id in ["governance_operationalization", "governance_lifecycle"]:
            stage["governance_multiframework_mapping"] = governance_multiframework_mapping
            stage["governance_explicitly_supports"] = supported_frameworks
            stage["governance_capabilities"] = governance_capabilities
            stage["operational_question"] = governance_multiframework_mapping["governance_question"]
            stage["expected_objects"] = add_unique_list(stage.get("expected_objects", []), governance_objects)
            stage["evidence_outputs"] = add_unique_list(
                stage.get("evidence_outputs", []),
                [
                    "Multi-framework control map",
                    "Multi-framework evidence map",
                    "Unified governance implementation record",
                    "Framework obligation traceability record",
                    "Evidence reuse record",
                    "Human approval evidence-to-framework map",
                    "Risk classification evidence-to-framework map",
                    "Incident and CAPA evidence-to-framework map",
                    "Third-party oversight evidence-to-framework map"
                ]
            )

        if stage_id in ["evidence_contract", "decision_approval_release", "monitoring_response_learning"]:
            stage["multi_framework_evidence_mapping"] = multi_framework_evidence_mapping
            stage["expected_objects"] = add_unique_list(stage.get("expected_objects", []), governance_objects)
            stage["evidence_outputs"] = add_unique_list(
                stage.get("evidence_outputs", []),
                [
                    "Multi-framework evidence map",
                    "Evidence reuse record",
                    "Human approval multi-framework evidence record",
                    "Risk classification multi-framework evidence record",
                    "Runtime multi-framework evidence record",
                    "Incident multi-framework evidence record",
                    "CAPA multi-framework evidence record"
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

blueprint_governance_block = r'''
<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">Governance Multi-Framework Mapping</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Governance now explicitly supports ISO 42001, ISO 27001, EU AI Act, GDPR, NIS2, GAMP 5, GxP, FDA, ICH, and Internal SOPs through one unified implementation. One AI control can satisfy many frameworks. One evidence item can support many regulations.
            </div>
        </div>
        <span class="tag">No new module</span>
    </div>
    <div class="grid">
        <div class="panel"><strong>Multi-framework Control Mapping</strong><div>One AI control may satisfy ISO 42001, EU AI Act, FDA, ISO 27001, GxP, ICH, and Internal SOP obligations simultaneously.</div></div>
        <div class="panel"><strong>Multi-framework Evidence Mapping</strong><div>One evidence item, such as human approval, can support ISO 42001, EU AI Act, FDA, GxP, and Internal QA at the same time.</div></div>
    </div>
</section>
'''

platform_block = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>Governance Multi-Framework Mapping</h2>
            <p>The existing Governance layer now supports ISO 42001, ISO 27001, EU AI Act, GDPR, NIS2, GAMP 5, GxP, FDA, ICH, and Internal SOPs through unified control and evidence mapping. One AI control can satisfy many frameworks. One evidence item can support many regulations. No new framework module was added.</p>
        </div>
        <span class="tag">Governance strengthened</span>
    </div>
    <div class="grid-4">
        <a class="card" href="/platform/lifecycle-integration"><strong>Unified Governance Implementation</strong><span>Governance now maps controls and evidence across multiple frameworks without separate framework-by-framework implementations.</span><small>Open lifecycle</small></a>
        <a class="card" href="/platform/blueprints/ai-enabled-cmc"><strong>CMC Governance Mapping</strong><span>CMC blueprint Governance now supports multi-framework control and evidence mapping across AI, GMP, quality, regulatory, and internal SOP obligations.</span><small>Open CMC blueprint</small></a>
        <a class="card" href="/platform/blueprints/agentic-enterprise"><strong>Agentic Governance Mapping</strong><span>Agentic Enterprise blueprint Governance now supports unified control and evidence mapping for agentic operations.</span><small>Open Agentic blueprint</small></a>
        <a class="card" href="/platform/evidence-packages"><strong>Evidence Reuse</strong><span>One evidence object can support multiple regulatory and governance obligations.</span><small>Open evidence</small></a>
    </div>
</section>
'''

route_registry_block = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>Governance Multi-Framework Mapping</h2>
            <p>Existing Governance now explicitly supports multi-framework control mapping, multi-framework evidence mapping, and unified governance implementation. This strengthens Governance without adding a new framework module, new route, or architecture change.</p>
        </div>
        <span class="tag">Existing Governance</span>
    </div>
    <div class="route-grid">
        <a class="route" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Governance stages now include multi-framework control maps, evidence maps, unified implementation records, and evidence reuse records.</span><code>/platform/lifecycle-integration</code></a>
        <a class="route" href="/platform/blueprints/ai-enabled-cmc"><strong>AI-enabled CMC Blueprint</strong><span>Governance maps one control and one evidence item across ISO 42001, ISO 27001, EU AI Act, GDPR, NIS2, GAMP 5, GxP, FDA, ICH, and Internal SOPs.</span><code>/platform/blueprints/ai-enabled-cmc</code></a>
        <a class="route" href="/api/platform/blueprints/model/demo"><strong>Blueprint API</strong><span>Existing Blueprint API returns multi-framework mapping data through the existing model response.</span><code>/api/platform/blueprints/model/demo</code></a>
        <a class="route" href="/api/platform/lifecycle-integration/model/demo"><strong>Lifecycle API</strong><span>Existing Lifecycle API returns Governance multi-framework mapping status.</span><code>/api/platform/lifecycle-integration/model/demo</code></a>
    </div>
</section>
'''

patch_blueprint_seed()
patch_lifecycle_seed()

patch_html(
    "platform_ai_enabled_cmc_blueprint.html",
    blueprint_governance_block,
    "<div class=\"footer\">"
)

patch_html(
    "platform_agentic_enterprise_blueprint.html",
    blueprint_governance_block,
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
    "supported_frameworks": supported_frameworks,
    "governance_capabilities": governance_capabilities,
    "multi_framework_control_mapping_count": len(multi_framework_control_mapping),
    "multi_framework_evidence_mapping_count": len(multi_framework_evidence_mapping),
    "governance_multiframework_mapping": governance_multiframework_mapping
}

Path("governance_multiframework_mapping_patch_v1_summary.json").write_text(
    json.dumps(summary, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("governance_multiframework_mapping_patch_v1_urls.txt").write_text(
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
print("Governance Multi-Framework Mapping Patch completed.")
print("Marker:")
print("  " + PATCH_MARKER)
print("No new module. No new route. No architecture change. Lifecycle unchanged.")
