from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_CMC_DISCOVERY_EVIDENCE_ENRICHMENT_PATCH_V1_ACTIVE"

cmc_discovery_expansion = {
    "patch_marker": PATCH_MARKER,
    "patch_type": "blueprint_content_expansion_not_new_module",
    "architecture_change": False,
    "new_module": False,
    "new_route": False,
    "lifecycle_change": False,
    "platform_rule": "No new module. No new architecture. No lifecycle change. Expand the existing AI-enabled CMC Blueprint Discovery examples only.",
    "blueprint": "AI-enabled CMC Blueprint",
    "stage": "Discovery",
    "discovery_explicit_examples": [
        "AI-assisted literature review",
        "AI-assisted hypothesis generation",
        "AI-assisted formulation design",
        "AI-assisted process development",
        "AI-assisted regulatory authoring",
        "AI-assisted manufacturing optimization"
    ],
    "expanded_discovery_scope": [
        "Scientific knowledge discovery",
        "Hypothesis formation",
        "Formulation design",
        "Process development",
        "Regulatory authoring",
        "Manufacturing optimization"
    ],
    "discovery_question": "Which AI-assisted CMC activities exist across literature review, hypothesis generation, formulation design, process development, regulatory authoring, and manufacturing optimization?"
}

evidence_stage_enrichment = {
    "patch_marker": PATCH_MARKER,
    "patch_type": "evidence_stage_enrichment_not_records_module",
    "architecture_change": False,
    "new_module": False,
    "new_records_module": False,
    "lifecycle_change": False,
    "platform_rule": "Do not add a new Records module. Enrich the existing Evidence stage without changing the architecture.",
    "stage": "Evidence",
    "evidence_explicitly_includes": [
        "Decision records",
        "Human approvals",
        "AI inputs and outputs",
        "Prompt and context lineage, where appropriate",
        "Policy evaluation records",
        "Runtime logs",
        "Model/version information",
        "Change history",
        "Human overrides",
        "Monitoring evidence",
        "Incident evidence",
        "CAPA evidence",
        "Lifecycle evidence"
    ],
    "evidence_operational_question": "Can every AI-assisted action, decision, output, approval, override, change, monitoring signal, incident, CAPA, and lifecycle event be evidenced and reconstructed?",
    "evidence_outputs_to_bind": [
        "Decision record",
        "Human approval record",
        "AI input/output record",
        "Prompt and context lineage record",
        "Policy evaluation record",
        "Runtime log",
        "Model/version record",
        "Change history record",
        "Human override record",
        "Monitoring evidence record",
        "Incident evidence record",
        "CAPA evidence record",
        "Lifecycle evidence record"
    ],
    "evidence_stage_statement": "Evidence supports audit reconstruction and operational trust defense by binding decisions, approvals, AI inputs and outputs, lineage, policy evaluations, runtime logs, model/version information, change history, overrides, monitoring evidence, incident evidence, CAPA evidence, and lifecycle evidence."
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
    existing = set(target)
    for value in values:
        if value not in existing:
            target.append(value)
            existing.add(value)
    return target

def append_once(text, addition):
    if addition in text:
        return text
    if text and not text.endswith(" "):
        text += " "
    return text + addition

def patch_blueprint_seed():
    path = Path("platform_blueprint_library_seed.json")
    if not path.exists():
        print("SKIP: platform_blueprint_library_seed.json not found.")
        return False

    data = load_json(path)
    data["cmc_discovery_expansion"] = cmc_discovery_expansion
    data["evidence_stage_enrichment"] = evidence_stage_enrichment

    for bp in data.get("blueprints", []) or []:
        bp["evidence_stage_enrichment"] = evidence_stage_enrichment

        if bp.get("blueprint_id") == "ai_enabled_cmc":
            bp["cmc_discovery_expansion"] = cmc_discovery_expansion
            bp["questions_answered"] = add_unique_list(bp.get("questions_answered", []), [
                "Which AI-assisted literature review informed the CMC strategy?",
                "Which AI-assisted hypothesis generation influenced formulation or process direction?",
                "Which AI-assisted formulation design activity occurred?",
                "Which AI-assisted process development activity occurred?",
                "Which AI-assisted regulatory authoring activity occurred?",
                "Which AI-assisted manufacturing optimization activity occurred?"
            ])

        for stage in bp.get("lifecycle", []) or []:
            stage_name = stage.get("stage_name", "")

            if bp.get("blueprint_id") == "ai_enabled_cmc" and stage_name == "Discovery":
                stage["discovery_explicit_examples"] = cmc_discovery_expansion["discovery_explicit_examples"]
                stage["expanded_discovery_scope"] = cmc_discovery_expansion["expanded_discovery_scope"]
                stage["stage_question"] = cmc_discovery_expansion["discovery_question"]
                stage["operational_focus"] = (
                    "Identify AI used across CMC discovery and development, including AI-assisted literature review, AI-assisted hypothesis generation, AI-assisted formulation design, AI-assisted process development, AI-assisted regulatory authoring, and AI-assisted manufacturing optimization."
                )
                stage["evidence_outputs"] = add_unique_list(stage.get("evidence_outputs", []), [
                    "AI-assisted literature review record",
                    "AI-assisted hypothesis generation record",
                    "AI-assisted formulation design record",
                    "AI-assisted process development record",
                    "AI-assisted regulatory authoring record",
                    "AI-assisted manufacturing optimization record"
                ])

            if stage_name == "Evidence":
                stage["evidence_stage_enrichment"] = evidence_stage_enrichment
                stage["evidence_explicitly_includes"] = evidence_stage_enrichment["evidence_explicitly_includes"]
                stage["stage_question"] = evidence_stage_enrichment["evidence_operational_question"]
                stage["operational_focus"] = evidence_stage_enrichment["evidence_stage_statement"]
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    evidence_stage_enrichment["evidence_outputs_to_bind"]
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
    data["evidence_stage_enrichment"] = evidence_stage_enrichment
    data["cmc_discovery_expansion_reference"] = cmc_discovery_expansion

    evidence_expected_objects = [
        "DecisionRecord",
        "HumanApprovalRecord",
        "AIInputOutputRecord",
        "PromptContextLineageRecord",
        "PolicyEvaluationRecord",
        "RuntimeLog",
        "ModelVersionRecord",
        "ChangeHistoryRecord",
        "HumanOverrideRecord",
        "MonitoringEvidenceRecord",
        "IncidentEvidenceRecord",
        "CAPAEvidenceRecord",
        "LifecycleEvidenceRecord"
    ]

    for stage in data.get("integration_flow", []) or []:
        stage_id = stage.get("stage_id", "")

        if stage_id == "evidence_contract":
            stage["stage_name"] = "AI Assurance Evidence Contract"
            stage["evidence_stage_enrichment"] = evidence_stage_enrichment
            stage["stage_purpose"] = (
                "Define proof obligations, evidence freshness, evidence owners, replay requirements, approval evidence, decision records, AI input/output evidence, lineage, policy evaluation records, runtime logs, model/version information, change history, human overrides, monitoring evidence, incident evidence, CAPA evidence, and lifecycle evidence before trust is claimed."
            )
            stage["operational_question"] = evidence_stage_enrichment["evidence_operational_question"]
            stage["expected_objects"] = add_unique_list(stage.get("expected_objects", []), evidence_expected_objects)
            stage["evidence_outputs"] = add_unique_list(
                stage.get("evidence_outputs", []),
                evidence_stage_enrichment["evidence_outputs_to_bind"]
            )

        if stage_id in ["output_clearance", "decision_approval_release", "monitoring_response_learning"]:
            stage["evidence_explicitly_includes"] = evidence_stage_enrichment["evidence_explicitly_includes"]
            stage["evidence_outputs"] = add_unique_list(
                stage.get("evidence_outputs", []),
                [
                    "Decision record",
                    "Human approval record",
                    "AI input/output record",
                    "Model/version record",
                    "Change history record",
                    "Monitoring evidence record",
                    "Lifecycle evidence record"
                ]
            )

    save_json(path, data)
    print("PATCHED: platform_lifecycle_integration_seed.json")
    return True

def patch_html_block(path, block_html, anchor):
    p = Path(path)
    if not p.exists():
        print(f"SKIP: {path} not found.")
        return False

    text = p.read_text(encoding="utf-8")

    start = f"<!-- {PATCH_MARKER} -->"
    end = f"<!-- END {PATCH_MARKER} -->"

    text = re.sub(
        re.escape(start) + r".*?" + re.escape(end),
        "",
        text,
        flags=re.DOTALL
    )

    block = f"\n{start}\n{block_html}\n{end}\n"

    if anchor in text:
        text = text.replace(anchor, block + "\n" + anchor, 1)
    else:
        text = text.replace("</body>", block + "\n</body>", 1)

    p.write_text(text, encoding="utf-8")
    print(f"PATCHED: {path}")
    return True

cmc_banner = r'''
<div class="section" style="border-color:rgba(255,138,31,.38);">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">CMC Discovery Examples Expanded</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Discovery now explicitly includes AI-assisted literature review, AI-assisted hypothesis generation, AI-assisted formulation design, AI-assisted process development, AI-assisted regulatory authoring, and AI-assisted manufacturing optimization. The lifecycle remains unchanged.
            </div>
        </div>
        <span class="tag">No new module</span>
    </div>
</div>
'''

evidence_banner = r'''
<div class="section" style="border-color:rgba(255,138,31,.38);">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">Evidence Stage Enriched</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Evidence now explicitly includes decision records, human approvals, AI inputs and outputs, prompt and context lineage where appropriate, policy evaluation records, runtime logs, model/version information, change history, human overrides, monitoring evidence, incident evidence, CAPA evidence, and lifecycle evidence. No Records module was added.
            </div>
        </div>
        <span class="tag">Evidence enriched</span>
    </div>
</div>
'''

platform_banner = r'''
<div class="statement" style="margin-top:22px;">
    <strong>Blueprint and Evidence enriched:</strong> the AI-enabled CMC Blueprint Discovery stage now includes AI-assisted literature review, hypothesis generation, formulation design, process development, regulatory authoring, and manufacturing optimization. The existing Evidence stage now includes decision records, human approvals, AI inputs and outputs, lineage, policy evaluation records, runtime logs, model/version information, change history, overrides, monitoring evidence, incident evidence, CAPA evidence, and lifecycle evidence. No new module or architecture change.
</div>
'''

route_registry_section = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>CMC Blueprint Discovery and Evidence Enrichment</h2>
            <p>The AI-enabled CMC Blueprint Discovery stage now explicitly includes AI-assisted literature review, hypothesis generation, formulation design, process development, regulatory authoring, and manufacturing optimization. The existing Evidence stage now includes decision records, human approvals, AI inputs and outputs, prompt/context lineage, policy evaluation records, runtime logs, model/version information, change history, overrides, monitoring evidence, incident evidence, CAPA evidence, and lifecycle evidence. This is not a new module.</p>
        </div>
        <span class="tag">No architecture change</span>
    </div>
    <div class="route-grid">
        <a class="route" href="/platform/blueprints/ai-enabled-cmc"><strong>AI-enabled CMC Blueprint</strong><span>Discovery examples expanded across early scientific discovery, formulation, process development, regulatory authoring, and manufacturing optimization.</span><code>/platform/blueprints/ai-enabled-cmc</code></a>
        <a class="route" href="/platform/blueprints/agentic-enterprise"><strong>Agentic Enterprise Blueprint</strong><span>Evidence stage enriched for agent actions, approvals, workflow changes, monitoring, incidents, and lifecycle proof.</span><code>/platform/blueprints/agentic-enterprise</code></a>
        <a class="route" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Evidence integration now includes decision records, inputs/outputs, logs, versions, changes, overrides, incidents, CAPA, and lifecycle evidence.</span><code>/platform/lifecycle-integration</code></a>
        <a class="route" href="/platform/evidence-packages"><strong>Evidence Vault</strong><span>Evidence packages can now represent richer operational evidence without adding a Records module.</span><code>/platform/evidence-packages</code></a>
    </div>
</section>
'''

patch_blueprint_seed()
patch_lifecycle_seed()

patch_html_block(
    "platform_ai_enabled_cmc_blueprint.html",
    cmc_banner + "\n" + evidence_banner,
    "</section>\n\n        <section class=\"metrics\">"
)

patch_html_block(
    "platform_agentic_enterprise_blueprint.html",
    evidence_banner,
    "</section>\n\n        <section class=\"metrics\">"
)

patch_html_block(
    "platform_ab_command_center.html",
    platform_banner,
    "</section>\n\n        <section class=\"metrics\">"
)

patch_html_block(
    "platform_route_registry_command_center.html",
    route_registry_section,
    "<div class=\"footer\">"
)

summary = {
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "new_module": False,
    "new_route": False,
    "new_records_module": False,
    "lifecycle_change": False,
    "cmc_discovery_expansion": cmc_discovery_expansion,
    "evidence_stage_enrichment": evidence_stage_enrichment
}

Path("cmc_discovery_evidence_enrichment_patch_v1_summary.json").write_text(
    json.dumps(summary, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("cmc_discovery_evidence_enrichment_patch_v1_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/blueprints",
        "http://127.0.0.1:5000/platform/blueprints/ai-enabled-cmc",
        "http://127.0.0.1:5000/platform/blueprints/agentic-enterprise",
        "http://127.0.0.1:5000/platform/lifecycle-integration",
        "http://127.0.0.1:5000/platform/routes",
        "http://127.0.0.1:5000/api/platform/blueprints/model/demo",
        "http://127.0.0.1:5000/api/platform/blueprints/ai-enabled-cmc/demo",
        "http://127.0.0.1:5000/api/platform/lifecycle-integration/model/demo"
    ]),
    encoding="utf-8"
)

print("")
print("CMC Discovery + Evidence Stage Enrichment Patch completed.")
print("Marker:")
print("  " + PATCH_MARKER)
print("No new module. No new route. No Records module. No architecture change.")
