from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_OPTIMIZATION_GOVERNANCE_EVIDENCE_PATCH_V1_ACTIVE"

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

operationalization_expansion = {
    "patch_marker": PATCH_MARKER,
    "patch_type": "operationalization_enrichment_not_new_module",
    "architecture_change": False,
    "new_module": False,
    "new_route": False,
    "lifecycle_change": False,
    "locked_lifecycle": locked_lifecycle,
    "platform_rule": "No new module. No new architecture. No lifecycle change. Enrich the existing Operationalization stage only.",
    "stage": "Operationalization",
    "operationalization_question": "Were these optimizations governed, approved, monitored, and evidenced?",
    "operationalization_explicitly_governs": [
        "Prompt management",
        "Prompt versioning",
        "Prompt approval",
        "Routing policies",
        "Retrieval strategies",
        "Context management",
        "Context compaction",
        "Semantic caching",
        "Prompt caching",
        "Lazy-loading strategies",
        "Agent orchestration",
        "Optimization policies"
    ],
    "operationalization_statement": "Operationalization governs the execution choices that affect AI behavior, efficiency, evidence, and trust, including prompts, routing, retrieval, context, caching, lazy-loading, orchestration, and optimization policies."
}

evidence_optimization_expansion = {
    "patch_marker": PATCH_MARKER,
    "patch_type": "evidence_enrichment_not_new_module",
    "architecture_change": False,
    "new_module": False,
    "new_route": False,
    "lifecycle_change": False,
    "locked_lifecycle": locked_lifecycle,
    "platform_rule": "No new Records module. No new architecture. Enrich the existing Evidence stage only.",
    "stage": "Evidence",
    "evidence_explicitly_includes": [
        "Prompt versions",
        "Routing decisions",
        "Retrieval evidence",
        "Context supplied",
        "Context omitted",
        "Cache usage",
        "Agent decisions",
        "Tool-call lineage",
        "Optimization policies",
        "Human approvals",
        "Runtime evidence"
    ],
    "evidence_operational_question": "Can prompt versions, routing decisions, retrieval evidence, supplied context, omitted context, cache usage, agent decisions, tool-call lineage, optimization policies, human approvals, and runtime evidence be reconstructed?",
    "evidence_outputs_to_bind": [
        "Prompt version record",
        "Routing decision record",
        "Retrieval evidence record",
        "Context supplied record",
        "Context omitted record",
        "Cache usage record",
        "Agent decision record",
        "Tool-call lineage record",
        "Optimization policy record",
        "Human approval record",
        "Runtime evidence record"
    ],
    "evidence_statement": "Evidence must show not only what the AI produced, but how the output was shaped by prompt versions, routing, retrieval, context supplied, context omitted, cache behavior, agent decisions, tool calls, optimization policies, human approvals, and runtime execution."
}

optimization_traceability = [
    {
        "optimization_area": "Prompt management",
        "governance_question": "Was the prompt managed under an approved lifecycle?",
        "required_evidence": "Prompt management record",
        "approval_expected": True,
        "monitoring_signal": "Prompt usage and change signal",
        "trust_impact": "Confirms prompts are controlled rather than informal execution artifacts."
    },
    {
        "optimization_area": "Prompt versioning",
        "governance_question": "Which prompt version influenced the AI output or recommendation?",
        "required_evidence": "Prompt version record",
        "approval_expected": True,
        "monitoring_signal": "Prompt version drift or mismatch signal",
        "trust_impact": "Confirms AI behavior can be traced to the exact prompt version used."
    },
    {
        "optimization_area": "Prompt approval",
        "governance_question": "Was the prompt approved before use in the workflow?",
        "required_evidence": "Prompt approval record",
        "approval_expected": True,
        "monitoring_signal": "Unapproved prompt use signal",
        "trust_impact": "Confirms prompt changes do not bypass governance."
    },
    {
        "optimization_area": "Routing policies",
        "governance_question": "Which model, tool, or agent route was selected and why?",
        "required_evidence": "Routing decision record",
        "approval_expected": True,
        "monitoring_signal": "Routing policy execution log",
        "trust_impact": "Confirms route selection was governed and appropriate for risk."
    },
    {
        "optimization_area": "Retrieval strategies",
        "governance_question": "Which retrieval strategy supplied evidence or context to the AI?",
        "required_evidence": "Retrieval evidence record",
        "approval_expected": True,
        "monitoring_signal": "Retrieval source and relevance signal",
        "trust_impact": "Confirms retrieved content can be reviewed and reconstructed."
    },
    {
        "optimization_area": "Context management",
        "governance_question": "What context was supplied to the AI system?",
        "required_evidence": "Context supplied record",
        "approval_expected": False,
        "monitoring_signal": "Context package completeness signal",
        "trust_impact": "Confirms the decision context can be reconstructed."
    },
    {
        "optimization_area": "Context compaction",
        "governance_question": "What information was removed, summarized, compressed, or omitted?",
        "required_evidence": "Context omitted record",
        "approval_expected": True,
        "monitoring_signal": "Context omission or compaction signal",
        "trust_impact": "Confirms compaction did not remove decision-critical information."
    },
    {
        "optimization_area": "Semantic caching",
        "governance_question": "Was a semantically similar cached response or context reused?",
        "required_evidence": "Semantic cache usage record",
        "approval_expected": True,
        "monitoring_signal": "Semantic cache hit signal",
        "trust_impact": "Confirms cache reuse did not weaken current-context validity."
    },
    {
        "optimization_area": "Prompt caching",
        "governance_question": "Was a cached prompt or prompt segment reused?",
        "required_evidence": "Prompt cache usage record",
        "approval_expected": True,
        "monitoring_signal": "Prompt cache hit signal",
        "trust_impact": "Confirms prompt reuse remains valid, approved, and traceable."
    },
    {
        "optimization_area": "Lazy-loading strategies",
        "governance_question": "Was information deferred, loaded later, or excluded to optimize execution?",
        "required_evidence": "Lazy-loading strategy record",
        "approval_expected": True,
        "monitoring_signal": "Lazy-load trigger and omission signal",
        "trust_impact": "Confirms delayed loading did not compromise decision completeness."
    },
    {
        "optimization_area": "Agent orchestration",
        "governance_question": "Which agents acted, in what sequence, with which tools and authority?",
        "required_evidence": "Agent orchestration record",
        "approval_expected": True,
        "monitoring_signal": "Agent action and tool-call lineage signal",
        "trust_impact": "Confirms agent actions are bounded, sequenced, and reconstructable."
    },
    {
        "optimization_area": "Optimization policies",
        "governance_question": "Which optimization policy changed execution behavior, cost, latency, context, retrieval, or routing?",
        "required_evidence": "Optimization policy record",
        "approval_expected": True,
        "monitoring_signal": "Optimization policy execution signal",
        "trust_impact": "Confirms efficiency improvements did not reduce operational trust."
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
    data["optimization_governance_patch"] = {
        "operationalization_expansion": operationalization_expansion,
        "evidence_optimization_expansion": evidence_optimization_expansion,
        "optimization_traceability": optimization_traceability
    }

    for bp in data.get("blueprints", []) or []:
        bp["optimization_governance_patch"] = {
            "architecture_change": False,
            "new_module": False,
            "new_route": False,
            "lifecycle_change": False,
            "locked_lifecycle": locked_lifecycle
        }

        if bp.get("blueprint_id") == "ai_enabled_cmc":
            bp["locked_lifecycle"] = locked_lifecycle
            bp["optimization_traceability"] = optimization_traceability
            bp["questions_answered"] = add_unique_list(
                bp.get("questions_answered", []),
                [
                    "Were prompt management and prompt versioning governed?",
                    "Were prompt approvals completed before operational use?",
                    "Were routing policies approved and evidenced?",
                    "Were retrieval strategies governed and reconstructable?",
                    "Was context management controlled?",
                    "Was context compaction approved and evidenced?",
                    "Was semantic caching or prompt caching used?",
                    "Were lazy-loading strategies governed?",
                    "Was agent orchestration approved and monitored?",
                    "Were optimization policies governed, approved, monitored, and evidenced?"
                ]
            )

            assessment = bp.get("sample_blueprint_assessment", {})
            assessment["optimization_governance_state"] = "CMC_OPTIMIZATION_GOVERNANCE_MAPPED_TO_EXISTING_OPERATIONALIZATION_AND_EVIDENCE_STAGES"
            assessment["optimization_governance_question"] = operationalization_expansion["operationalization_question"]
            assessment["optimization_traceability_count"] = len(optimization_traceability)
            assessment["optimization_governance_next_actions"] = [
                "Bind prompt version records to AI-assisted CMC outputs.",
                "Bind routing decision records to model, tool, and agent selection.",
                "Bind retrieval evidence to AI-assisted regulatory and manufacturing outputs.",
                "Bind context supplied and context omitted records to output clearance and evidence replay.",
                "Bind cache usage records to operational trust review.",
                "Bind agent orchestration records and tool-call lineage to manufacturing monitoring and evidence.",
                "Bind optimization policy records to approval, monitoring, and continuous assurance."
            ]
            bp["sample_blueprint_assessment"] = assessment

        for stage in bp.get("lifecycle", []) or []:
            if stage.get("stage_name") == "Operationalization":
                stage["operationalization_expansion"] = operationalization_expansion
                stage["optimization_traceability"] = optimization_traceability
                stage["stage_question"] = operationalization_expansion["operationalization_question"]
                stage["operational_focus"] = operationalization_expansion["operationalization_statement"]
                stage["operationalization_explicitly_governs"] = operationalization_expansion["operationalization_explicitly_governs"]
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    [
                        "Prompt management record",
                        "Prompt version record",
                        "Prompt approval record",
                        "Routing policy record",
                        "Retrieval strategy record",
                        "Context management record",
                        "Context compaction record",
                        "Semantic cache usage record",
                        "Prompt cache usage record",
                        "Lazy-loading strategy record",
                        "Agent orchestration record",
                        "Optimization policy record"
                    ]
                )

            if stage.get("stage_name") == "Evidence":
                stage["evidence_optimization_expansion"] = evidence_optimization_expansion
                stage["evidence_explicitly_includes"] = add_unique_list(
                    stage.get("evidence_explicitly_includes", []),
                    evidence_optimization_expansion["evidence_explicitly_includes"]
                )
                stage["stage_question"] = evidence_optimization_expansion["evidence_operational_question"]
                stage["operational_focus"] = evidence_optimization_expansion["evidence_statement"]
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    evidence_optimization_expansion["evidence_outputs_to_bind"]
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
    data["optimization_governance_patch"] = {
        "operationalization_expansion": operationalization_expansion,
        "evidence_optimization_expansion": evidence_optimization_expansion,
        "optimization_traceability": optimization_traceability
    }

    assessment = data.get("sample_integration_assessment", {})
    assessment["optimization_governance"] = {
        "state": "OPTIMIZATION_GOVERNANCE_CONNECTED_TO_EXISTING_OPERATIONALIZATION_AND_EVIDENCE_STAGES",
        "architecture_change": False,
        "new_module": False,
        "new_route": False,
        "lifecycle_change": False,
        "operationalization_question": operationalization_expansion["operationalization_question"],
        "optimization_areas": operationalization_expansion["operationalization_explicitly_governs"],
        "evidence_objects": evidence_optimization_expansion["evidence_outputs_to_bind"]
    }
    assessment["evidence_automation_targets"] = add_unique_list(
        assessment.get("evidence_automation_targets", []),
        [
            "Prompt version evidence binding",
            "Routing decision evidence binding",
            "Retrieval evidence binding",
            "Context supplied and context omitted evidence binding",
            "Cache usage evidence binding",
            "Agent decision evidence binding",
            "Tool-call lineage evidence binding",
            "Optimization policy evidence binding",
            "Runtime evidence binding"
        ]
    )
    data["sample_integration_assessment"] = assessment

    optimization_objects = [
        "PromptManagementRecord",
        "PromptVersionRecord",
        "PromptApprovalRecord",
        "RoutingPolicyRecord",
        "RoutingDecisionRecord",
        "RetrievalStrategyRecord",
        "RetrievalEvidenceRecord",
        "ContextManagementRecord",
        "ContextCompactionRecord",
        "ContextSuppliedRecord",
        "ContextOmittedRecord",
        "SemanticCacheUsageRecord",
        "PromptCacheUsageRecord",
        "LazyLoadingStrategyRecord",
        "AgentOrchestrationRecord",
        "AgentDecisionRecord",
        "ToolCallLineageRecord",
        "OptimizationPolicyRecord",
        "RuntimeEvidenceRecord"
    ]

    for stage in data.get("integration_flow", []) or []:
        stage_id = stage.get("stage_id", "")

        if stage_id in ["governance_operationalization", "output_clearance"]:
            stage["operationalization_expansion"] = operationalization_expansion
            stage["optimization_traceability"] = optimization_traceability
            stage["operational_question"] = operationalization_expansion["operationalization_question"]
            stage["expected_objects"] = add_unique_list(stage.get("expected_objects", []), optimization_objects)
            stage["evidence_outputs"] = add_unique_list(
                stage.get("evidence_outputs", []),
                [
                    "Prompt management record",
                    "Prompt version record",
                    "Prompt approval record",
                    "Routing policy record",
                    "Routing decision record",
                    "Retrieval strategy record",
                    "Retrieval evidence record",
                    "Context management record",
                    "Context compaction record",
                    "Context supplied record",
                    "Context omitted record",
                    "Semantic cache usage record",
                    "Prompt cache usage record",
                    "Lazy-loading strategy record",
                    "Agent orchestration record",
                    "Agent decision record",
                    "Tool-call lineage record",
                    "Optimization policy record",
                    "Runtime evidence record"
                ]
            )

        if stage_id in ["evidence_contract", "monitoring_response_learning"]:
            stage["evidence_optimization_expansion"] = evidence_optimization_expansion
            stage["expected_objects"] = add_unique_list(stage.get("expected_objects", []), optimization_objects)
            stage["evidence_outputs"] = add_unique_list(
                stage.get("evidence_outputs", []),
                evidence_optimization_expansion["evidence_outputs_to_bind"]
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
            <h2 style="margin:0;font-size:30px;">Operationalization Optimization Governance</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Operationalization now explicitly governs prompt management, prompt versioning, prompt approval, routing policies, retrieval strategies, context management, context compaction, semantic caching, prompt caching, lazy-loading strategies, agent orchestration, and optimization policies.
            </div>
        </div>
        <span class="tag">No new module</span>
    </div>
    <div class="grid">
        <div class="panel"><strong>Operationalization Question</strong><div>Were these optimizations governed, approved, monitored, and evidenced?</div></div>
        <div class="panel"><strong>Lifecycle Locked</strong><div>Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust</div></div>
    </div>
</section>

<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">Optimization Evidence Enriched</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Evidence now explicitly includes prompt versions, routing decisions, retrieval evidence, context supplied, context omitted, cache usage, agent decisions, tool-call lineage, optimization policies, human approvals, and runtime evidence.
            </div>
        </div>
        <span class="tag">Evidence enriched</span>
    </div>
</section>
'''

platform_html_block = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>Operationalization and Evidence Enriched</h2>
            <p>The existing lifecycle now treats AI optimization choices as governed operational variables. Prompt management, versioning, approval, routing, retrieval, context, compaction, caching, lazy-loading, orchestration, and optimization policies must be governed, approved, monitored, and evidenced. No new module or architecture change.</p>
        </div>
        <span class="tag">Optimization governance</span>
    </div>
    <div class="grid-4">
        <a class="card" href="/platform/blueprints/ai-enabled-cmc"><strong>CMC Optimization Governance</strong><span>AI-enabled CMC Operationalization now governs prompts, routing, retrieval, context, caching, lazy-loading, orchestration, and optimization policies.</span><small>Open CMC blueprint</small></a>
        <a class="card" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Lifecycle Integration now binds optimization governance to evidence objects and monitoring signals.</span><small>Open integration</small></a>
        <a class="card" href="/platform/evidence-packages"><strong>Evidence Vault</strong><span>Evidence now includes prompt versions, routing decisions, retrieval evidence, context supplied or omitted, cache usage, agent decisions, tool-call lineage, and runtime evidence.</span><small>Open evidence</small></a>
        <a class="card" href="/platform/ai-output-clearance"><strong>Output Clearance</strong><span>Output clearance can now reference optimization evidence that shaped the AI output.</span><small>Open clearance</small></a>
    </div>
</section>
'''

route_registry_html_block = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>Optimization Governance and Evidence Enrichment</h2>
            <p>Existing Operationalization and Evidence stages now explicitly cover prompt management, prompt versioning, prompt approval, routing policies, retrieval strategies, context management, context compaction, semantic caching, prompt caching, lazy-loading strategies, agent orchestration, optimization policies, prompt versions, routing decisions, retrieval evidence, supplied context, omitted context, cache usage, agent decisions, tool-call lineage, human approvals, and runtime evidence.</p>
        </div>
        <span class="tag">No new route</span>
    </div>
    <div class="route-grid">
        <a class="route" href="/platform/blueprints/ai-enabled-cmc"><strong>AI-enabled CMC Blueprint</strong><span>Operationalization and Evidence are enriched without changing the lifecycle or creating a new module.</span><code>/platform/blueprints/ai-enabled-cmc</code></a>
        <a class="route" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Optimization governance evidence is connected to the existing lifecycle integration model.</span><code>/platform/lifecycle-integration</code></a>
        <a class="route" href="/api/platform/blueprints/ai-enabled-cmc/demo"><strong>CMC Blueprint API</strong><span>Returns optimization governance and evidence enrichment fields inside the existing blueprint API.</span><code>/api/platform/blueprints/ai-enabled-cmc/demo</code></a>
        <a class="route" href="/api/platform/lifecycle-integration/model/demo"><strong>Lifecycle API</strong><span>Returns optimization governance evidence binding targets inside existing lifecycle API output.</span><code>/api/platform/lifecycle-integration/model/demo</code></a>
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
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "new_module": False,
    "new_route": False,
    "lifecycle_change": False,
    "locked_lifecycle": locked_lifecycle,
    "operationalization_expansion": operationalization_expansion,
    "evidence_optimization_expansion": evidence_optimization_expansion,
    "optimization_traceability_count": len(optimization_traceability),
    "optimization_traceability": optimization_traceability
}

Path("optimization_governance_evidence_patch_v1_summary.json").write_text(
    json.dumps(summary, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("optimization_governance_evidence_patch_v1_urls.txt").write_text(
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
print("Operationalization Optimization Governance + Evidence Enrichment Patch completed.")
print("Marker:")
print("  " + PATCH_MARKER)
print("No new module. No new route. No architecture change. Lifecycle unchanged.")
