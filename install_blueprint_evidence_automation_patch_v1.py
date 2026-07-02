from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_BLUEPRINT_EVIDENCE_AUTOMATION_PATCH_V1_ACTIVE"

patch_summary = {
    "patch_marker": PATCH_MARKER,
    "patch_type": "blueprint_evidence_automation_not_new_module",
    "architecture_change": False,
    "new_module": False,
    "new_route": False,
    "platform_rule": "No new module. No new architecture. Strengthen existing blueprints by adding evidence traceability and automation mapping.",
    "purpose": "Convert blueprint questions into evidence automation mappings that connect lifecycle stage, evidence object, owner, reviewer, monitoring signal, and trust impact.",
    "traceability_flow": [
        "Blueprint Question",
        "Lifecycle Stage",
        "Evidence Object",
        "Owner / Reviewer",
        "Monitoring Signal",
        "Trust Impact"
    ],
    "evidence_automation_principle": "A blueprint becomes operational when every question can be traced to a lifecycle stage, evidence object, responsible owner, monitoring signal, and operational trust impact."
}

cmc_evidence_traceability = [
    {
        "question": "Which AI supports formulation?",
        "lifecycle_stage": "Discovery / Visibility",
        "evidence_object": "AI-assisted formulation design record",
        "owner": "CMC process owner",
        "reviewer": "Qualified formulation reviewer",
        "monitoring_signal": "Formulation AI use-case visibility status",
        "trust_impact": "Confirms formulation AI is visible, owned, and governed."
    },
    {
        "question": "Which AI supports process development?",
        "lifecycle_stage": "Discovery / Visibility",
        "evidence_object": "AI-assisted process development record",
        "owner": "Process development owner",
        "reviewer": "Process SME / quality reviewer",
        "monitoring_signal": "Process development AI inventory status",
        "trust_impact": "Confirms process development AI activity is identified and classified."
    },
    {
        "question": "Which AI generated regulatory content?",
        "lifecycle_stage": "Operationalization / Evidence",
        "evidence_object": "AI-assisted regulatory authoring record",
        "owner": "Regulatory content owner",
        "reviewer": "Qualified regulatory reviewer",
        "monitoring_signal": "AI-generated content review status",
        "trust_impact": "Confirms generated regulatory content is reviewed, approved, and evidence-bound."
    },
    {
        "question": "Which AI influenced manufacturing decisions?",
        "lifecycle_stage": "Manufacturing Monitoring / Evidence",
        "evidence_object": "Manufacturing decision influence record",
        "owner": "Manufacturing process owner",
        "reviewer": "Quality / manufacturing reviewer",
        "monitoring_signal": "AI manufacturing recommendation log",
        "trust_impact": "Confirms manufacturing decisions influenced by AI can be reconstructed."
    },
    {
        "question": "What evidence exists?",
        "lifecycle_stage": "Evidence",
        "evidence_object": "CMC evidence package",
        "owner": "Evidence custodian",
        "reviewer": "Quality assurance reviewer",
        "monitoring_signal": "Evidence freshness status",
        "trust_impact": "Confirms AI-enabled CMC evidence is complete, current, and replayable."
    },
    {
        "question": "Were humans involved?",
        "lifecycle_stage": "Governance / Operationalization / Evidence",
        "evidence_object": "Human approval record",
        "owner": "Workflow owner",
        "reviewer": "Qualified human reviewer",
        "monitoring_signal": "Human review completion status",
        "trust_impact": "Confirms accountable human oversight occurred where required."
    },
    {
        "question": "Is change control synchronized?",
        "lifecycle_stage": "Continuous Assurance",
        "evidence_object": "Change control synchronization record",
        "owner": "Change control owner",
        "reviewer": "Quality / validation reviewer",
        "monitoring_signal": "Model, prompt, process, or intended-use change trigger",
        "trust_impact": "Confirms AI-enabled CMC changes are synchronized with governance and validation obligations."
    },
    {
        "question": "Has intended use changed?",
        "lifecycle_stage": "Continuous Assurance / Operational Trust",
        "evidence_object": "Intended-use change assessment",
        "owner": "AI system owner",
        "reviewer": "Governance owner / quality reviewer",
        "monitoring_signal": "Intended-use drift signal",
        "trust_impact": "Confirms operational trust is recalculated when intended use changes."
    }
]

agentic_evidence_traceability = [
    {
        "question": "Which agents support each business process?",
        "lifecycle_stage": "AI Discovery / Visibility",
        "evidence_object": "Agent inventory and business process map",
        "owner": "Business process owner",
        "reviewer": "AI governance owner",
        "monitoring_signal": "Agent-to-process visibility status",
        "trust_impact": "Confirms agent activity is visible before governance decisions."
    },
    {
        "question": "Which decisions are autonomous?",
        "lifecycle_stage": "Governance / Operating Model",
        "evidence_object": "Autonomous decision classification record",
        "owner": "Operating model owner",
        "reviewer": "Risk / governance reviewer",
        "monitoring_signal": "Autonomy level change signal",
        "trust_impact": "Confirms autonomous decisions are classified and controlled."
    },
    {
        "question": "Where are human approvals required?",
        "lifecycle_stage": "Governance / Operationalization",
        "evidence_object": "Human approval rule and approval record",
        "owner": "Workflow owner",
        "reviewer": "Qualified approver",
        "monitoring_signal": "Approval completion and exception status",
        "trust_impact": "Confirms consequential agent actions remain accountable."
    },
    {
        "question": "What evidence was generated?",
        "lifecycle_stage": "Evidence",
        "evidence_object": "Agent evidence package",
        "owner": "Evidence custodian",
        "reviewer": "Assurance reviewer",
        "monitoring_signal": "Evidence package completeness status",
        "trust_impact": "Confirms agent actions are evidence-bound and defensible."
    },
    {
        "question": "Which workflows changed?",
        "lifecycle_stage": "Operating Model / Operationalization",
        "evidence_object": "Workflow change record",
        "owner": "Process owner",
        "reviewer": "Operating model reviewer",
        "monitoring_signal": "Workflow drift or modification signal",
        "trust_impact": "Confirms agentic workflow changes are visible and governed."
    },
    {
        "question": "Which controls executed?",
        "lifecycle_stage": "Operationalization / Evidence",
        "evidence_object": "Control execution record",
        "owner": "Control owner",
        "reviewer": "Governance / audit reviewer",
        "monitoring_signal": "Control execution status",
        "trust_impact": "Confirms documented governance controls are actually operating."
    },
    {
        "question": "Which agent actions crossed governance boundaries?",
        "lifecycle_stage": "Governance / Continuous Assurance",
        "evidence_object": "Governance boundary event record",
        "owner": "AI governance owner",
        "reviewer": "Risk / compliance reviewer",
        "monitoring_signal": "Boundary crossing alert",
        "trust_impact": "Confirms boundary events trigger review, escalation, or revalidation."
    },
    {
        "question": "Can the action be reconstructed?",
        "lifecycle_stage": "Evidence / Continuous Assurance",
        "evidence_object": "Replay-ready agent action package",
        "owner": "Evidence custodian",
        "reviewer": "Assurance reviewer",
        "monitoring_signal": "Replay completeness status",
        "trust_impact": "Confirms agent action can be reconstructed for audit, investigation, or assurance."
    },
    {
        "question": "Is the agent still operating within its intended use?",
        "lifecycle_stage": "Continuous Assurance / Operational Trust",
        "evidence_object": "Intended-use boundary monitoring record",
        "owner": "AI system owner",
        "reviewer": "Governance owner",
        "monitoring_signal": "Intended-use boundary drift",
        "trust_impact": "Confirms agent trust is recalculated when behavior changes."
    }
]

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
    data["blueprint_evidence_automation_patch"] = patch_summary

    for bp in data.get("blueprints", []) or []:
        bp["evidence_automation_principle"] = patch_summary["evidence_automation_principle"]
        bp["traceability_flow"] = patch_summary["traceability_flow"]

        if bp.get("blueprint_id") == "ai_enabled_cmc":
            bp["evidence_traceability_matrix"] = cmc_evidence_traceability
            bp["sample_blueprint_assessment"]["evidence_automation_state"] = "CMC_BLUEPRINT_EVIDENCE_TRACEABILITY_MAPPED"
            bp["sample_blueprint_assessment"]["evidence_traceability_count"] = len(cmc_evidence_traceability)
            bp["sample_blueprint_assessment"]["evidence_automation_next_actions"] = [
                "Bind each CMC blueprint question to evidence object IDs.",
                "Connect human approval records to generated regulatory content.",
                "Connect manufacturing AI recommendation logs to decision influence records.",
                "Connect intended-use change assessment to lifecycle assurance and trust recalculation."
            ]

        if bp.get("blueprint_id") == "agentic_enterprise":
            bp["evidence_traceability_matrix"] = agentic_evidence_traceability
            bp["sample_blueprint_assessment"]["evidence_automation_state"] = "AGENTIC_ENTERPRISE_BLUEPRINT_EVIDENCE_TRACEABILITY_MAPPED"
            bp["sample_blueprint_assessment"]["evidence_traceability_count"] = len(agentic_evidence_traceability)
            bp["sample_blueprint_assessment"]["evidence_automation_next_actions"] = [
                "Bind each agent action to agent identity, tool call, prompt/context lineage, and workflow impact.",
                "Connect governance boundary events to escalation and revalidation triggers.",
                "Connect human approval rules to approval evidence.",
                "Connect replay completeness to continuous assurance and operational trust recalculation."
            ]

    save_json(path, data)
    print("PATCHED: platform_blueprint_library_seed.json")
    return True

def patch_lifecycle_seed():
    path = Path("platform_lifecycle_integration_seed.json")
    if not path.exists():
        print("SKIP: platform_lifecycle_integration_seed.json not found.")
        return False

    data = load_json(path)
    data["blueprint_evidence_automation_patch"] = patch_summary
    data["blueprint_evidence_traceability_flow"] = patch_summary["traceability_flow"]

    assessment = data.get("sample_integration_assessment", {})
    assessment["blueprint_evidence_automation"] = {
        "state": "BLUEPRINT_EVIDENCE_TRACEABILITY_CONNECTED",
        "architecture_change": False,
        "new_module": False,
        "traceability_flow": patch_summary["traceability_flow"],
        "blueprints_mapped": [
            "AI-enabled CMC Blueprint",
            "Agentic Enterprise Blueprint"
        ],
        "evidence_traceability_counts": {
            "ai_enabled_cmc": len(cmc_evidence_traceability),
            "agentic_enterprise": len(agentic_evidence_traceability)
        }
    }

    assessment["evidence_automation_targets"] = add_unique_list(
        assessment.get("evidence_automation_targets", []),
        [
            "Blueprint question-to-evidence mapper",
            "Blueprint evidence traceability matrix",
            "Owner and reviewer assignment mapping",
            "Monitoring signal linkage",
            "Trust impact mapping",
            "Blueprint replay evidence package"
        ]
    )

    data["sample_integration_assessment"] = assessment

    for stage in data.get("integration_flow", []) or []:
        if stage.get("stage_id") in ["discovery_visibility", "governance_operationalization", "evidence_contract", "monitoring_response_learning"]:
            stage["blueprint_evidence_automation"] = {
                "traceability_flow": patch_summary["traceability_flow"],
                "principle": patch_summary["evidence_automation_principle"]
            }
            stage["evidence_outputs"] = add_unique_list(
                stage.get("evidence_outputs", []),
                [
                    "Blueprint question-to-evidence mapping",
                    "Blueprint owner/reviewer mapping",
                    "Blueprint monitoring signal mapping",
                    "Blueprint trust impact record"
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

cmc_html_block = r'''
<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">CMC Evidence Traceability Matrix</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Each CMC blueprint question now maps to a lifecycle stage, evidence object, owner, reviewer, monitoring signal, and operational trust impact. This enriches the existing Evidence stage without adding a Records module.
            </div>
        </div>
        <span class="tag">Evidence automation</span>
    </div>
    <div class="grid">
        <div class="panel"><strong>Traceability Flow</strong><div>Blueprint Question -> Lifecycle Stage -> Evidence Object -> Owner / Reviewer -> Monitoring Signal -> Trust Impact</div></div>
        <div class="panel"><strong>CMC Evidence Automation</strong><div>Formulation, process development, regulatory authoring, manufacturing decision influence, human approval, change control synchronization, and intended-use change are now evidence-mapped.</div></div>
    </div>
</section>
'''

agentic_html_block = r'''
<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">Agentic Enterprise Evidence Traceability Matrix</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Each agentic enterprise blueprint question now maps to a lifecycle stage, evidence object, owner, reviewer, monitoring signal, and operational trust impact.
            </div>
        </div>
        <span class="tag">Evidence automation</span>
    </div>
    <div class="grid">
        <div class="panel"><strong>Traceability Flow</strong><div>Blueprint Question -> Lifecycle Stage -> Evidence Object -> Owner / Reviewer -> Monitoring Signal -> Trust Impact</div></div>
        <div class="panel"><strong>Agent Evidence Automation</strong><div>Agent identity, autonomous decisions, human approvals, workflow changes, control execution, governance boundary crossings, replay evidence, and intended-use monitoring are now evidence-mapped.</div></div>
    </div>
</section>
'''

platform_html_block = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>Blueprint Evidence Automation</h2>
            <p>Existing blueprint questions now map to lifecycle stages, evidence objects, owners, reviewers, monitoring signals, and operational trust impact. This strengthens evidence automation without adding a new module or architecture.</p>
        </div>
        <span class="tag">Evidence automation</span>
    </div>
    <div class="grid-4">
        <a class="card" href="/platform/blueprints/ai-enabled-cmc"><strong>CMC Evidence Traceability</strong><span>Maps formulation, process development, regulatory authoring, manufacturing decisions, human approval, change control, and intended-use questions to evidence objects.</span><small>Open CMC blueprint</small></a>
        <a class="card" href="/platform/blueprints/agentic-enterprise"><strong>Agent Evidence Traceability</strong><span>Maps agent actions, autonomous decisions, approvals, workflow changes, controls, boundary crossings, replay, and intended-use questions to evidence objects.</span><small>Open Agentic blueprint</small></a>
        <a class="card" href="/platform/lifecycle-integration"><strong>Lifecycle Evidence Integration</strong><span>Connects blueprint evidence expectations to the existing lifecycle and evidence automation targets.</span><small>Open integration</small></a>
        <a class="card" href="/platform/evidence-packages"><strong>Evidence Vault</strong><span>Stores replayable evidence packages without creating a separate Records module.</span><small>Open evidence</small></a>
    </div>
</section>
'''

route_registry_html_block = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>Blueprint Evidence Automation Routes</h2>
            <p>Blueprint evidence traceability is now visible through the existing blueprint and lifecycle routes. No new route or module was added.</p>
        </div>
        <span class="tag">Evidence traceability</span>
    </div>
    <div class="route-grid">
        <a class="route" href="/platform/blueprints/ai-enabled-cmc"><strong>CMC Evidence Traceability</strong><span>View CMC blueprint evidence mapping for formulation, process development, regulatory authoring, manufacturing decisions, change control, and intended use.</span><code>/platform/blueprints/ai-enabled-cmc</code></a>
        <a class="route" href="/platform/blueprints/agentic-enterprise"><strong>Agentic Evidence Traceability</strong><span>View agentic enterprise evidence mapping for agents, decisions, approvals, workflow changes, controls, boundary crossings, replay, and intended use.</span><code>/platform/blueprints/agentic-enterprise</code></a>
        <a class="route" href="/api/platform/blueprints/model/demo"><strong>Blueprint Evidence API</strong><span>Existing blueprint API now returns evidence traceability matrices.</span><code>/api/platform/blueprints/model/demo</code></a>
        <a class="route" href="/api/platform/lifecycle-integration/model/demo"><strong>Lifecycle Integration API</strong><span>Existing lifecycle integration API now returns blueprint evidence automation status.</span><code>/api/platform/lifecycle-integration/model/demo</code></a>
    </div>
</section>
'''

patch_blueprint_seed()
patch_lifecycle_seed()

patch_html(
    "platform_ai_enabled_cmc_blueprint.html",
    cmc_html_block,
    "<div class=\"footer\">"
)

patch_html(
    "platform_agentic_enterprise_blueprint.html",
    agentic_html_block,
    "<div class=\"footer\">"
)

patch_html(
    "platform_ab_command_center.html",
    platform_html_block,
    "<div class=\"footer\">"
)

patch_html(
    "platform_route_registry_command_center.html",
    route_registry_html_block,
    "<div class=\"footer\">"
)

summary = {
    "patch_summary": patch_summary,
    "cmc_evidence_traceability_count": len(cmc_evidence_traceability),
    "agentic_evidence_traceability_count": len(agentic_evidence_traceability),
    "cmc_evidence_traceability": cmc_evidence_traceability,
    "agentic_evidence_traceability": agentic_evidence_traceability
}

Path("blueprint_evidence_automation_patch_v1_summary.json").write_text(
    json.dumps(summary, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("blueprint_evidence_automation_patch_v1_urls.txt").write_text(
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
print("Blueprint Evidence Automation Patch completed.")
print("Marker:")
print("  " + PATCH_MARKER)
print("No new module. No new route. No architecture change.")
