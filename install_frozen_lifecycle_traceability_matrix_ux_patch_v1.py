from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_FROZEN_LIFECYCLE_TRACEABILITY_MATRIX_UX_PATCH_V1_ACTIVE"

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

matrix_columns = [
    "Execution Case",
    "Discovery",
    "Visibility",
    "Governance",
    "Operationalization",
    "Manufacturing Monitoring",
    "Evidence",
    "Continuous Assurance",
    "Operational Trust"
]

execution_traceability_matrix = [
    {
        "execution_case": "Agent execution",
        "discovery": "AI Agent inventory record",
        "visibility": "Agent topology and cross-agent observability",
        "governance": "Agent governance, identity governance, policy governance, risk governance",
        "operationalization": "Agent orchestration, runtime authorization, policy enforcement",
        "manufacturing_monitoring": "Agent execution monitoring and runtime telemetry",
        "evidence": "Which agent executed? Which policy approved execution? What runtime evidence was produced?",
        "continuous_assurance": "Agent behavior, runtime trust, policy compliance, evidence integrity",
        "operational_trust": "Agent action can be trusted because execution is inventoried, visible, governed, monitored, evidenced, and continuously assured."
    },
    {
        "execution_case": "MCP execution",
        "discovery": "MCP Server and MCP Tool inventory records",
        "visibility": "MCP visibility and runtime telemetry",
        "governance": "MCP governance, tool governance, identity governance, policy governance, risk governance",
        "operationalization": "MCP integration, tool authorization, runtime authorization, policy enforcement",
        "manufacturing_monitoring": "MCP call monitoring and tool execution monitoring",
        "evidence": "Which MCP server was used? Which tool was called? Which policies were evaluated?",
        "continuous_assurance": "MCP interaction integrity, tool-use compliance, runtime trust, policy compliance",
        "operational_trust": "MCP execution can be trusted because server use, tool calls, policies, and runtime evidence are reconstructable."
    },
    {
        "execution_case": "AI Gateway routing",
        "discovery": "AI Gateway inventory record",
        "visibility": "Gateway visibility, route visibility, runtime telemetry",
        "governance": "Gateway governance, API governance, identity governance, policy governance, risk governance",
        "operationalization": "AI Gateway integration, routing policy, runtime authorization, policy enforcement",
        "manufacturing_monitoring": "Gateway execution monitoring, routing events, policy enforcement events",
        "evidence": "Which gateway routed execution? Which model or service was invoked? Which policy was enforced?",
        "continuous_assurance": "Gateway control effectiveness, routing integrity, runtime trust, policy compliance",
        "operational_trust": "Gateway-mediated execution can be trusted because routing, authorization, policy evaluation, and runtime evidence are reconstructable."
    },
    {
        "execution_case": "A2A collaboration",
        "discovery": "A2A Connection and AI Agent inventory records",
        "visibility": "A2A visibility, agent topology, workflow visibility, cross-agent observability",
        "governance": "Agent governance, API governance, identity governance, policy governance, risk governance",
        "operationalization": "A2A collaboration, multi-agent execution, workflow orchestration, human approval workflow, policy enforcement",
        "manufacturing_monitoring": "A2A collaboration monitoring, workflow execution monitoring, runtime telemetry",
        "evidence": "Which A2A interaction occurred? Which agents participated? Which workflow executed? Which approvals occurred?",
        "continuous_assurance": "A2A interaction integrity, agent behavior, workflow integrity, runtime trust, policy compliance",
        "operational_trust": "A2A collaboration can be trusted because agent interaction, workflow execution, approvals, and evidence are reconstructable."
    },
    {
        "execution_case": "Multi-model execution",
        "discovery": "AI Model and AI Service inventory records",
        "visibility": "Cross-model observability, model route visibility, runtime telemetry",
        "governance": "Model governance, risk governance, compliance governance, policy governance",
        "operationalization": "Multi-model execution, model routing, runtime authorization, policy enforcement, human approval workflow",
        "manufacturing_monitoring": "Model execution monitoring, cross-model monitoring, runtime telemetry",
        "evidence": "Which model generated the output? Which model route was used? Which policy approved execution?",
        "continuous_assurance": "Model behavior, model route integrity, runtime trust, policy compliance, evidence integrity",
        "operational_trust": "Multi-model execution can be trusted because model selection, routing, output generation, and policy decisions are reconstructable."
    },
    {
        "execution_case": "Digital Twin recommendation",
        "discovery": "Digital Twin inventory record",
        "visibility": "Digital Twin visibility, simulation visibility, dependency visibility, runtime telemetry",
        "governance": "Model governance, data governance, infrastructure governance, risk governance, compliance governance, policy governance",
        "operationalization": "Digital Twin execution, simulation approval, AI-to-Twin orchestration, human approval, policy enforcement",
        "manufacturing_monitoring": "Digital Twin monitoring, simulation monitoring, process monitoring, recommendation monitoring",
        "evidence": "Which Digital Twin produced the recommendation? Which simulation influenced the decision? Was the recommendation reviewed?",
        "continuous_assurance": "Digital Twin performance, simulation integrity, workflow integrity, runtime trust, evidence integrity",
        "operational_trust": "Digital Twin recommendations can be trusted because simulations, approvals, runtime signals, and evidence are reconstructable."
    },
    {
        "execution_case": "AI-enabled CMC recommendation",
        "discovery": "AI system, AI model, AI service, data product, workflow inventory records",
        "visibility": "AI asset visibility, workflow visibility, runtime telemetry, dependency visibility",
        "governance": "Model governance, data governance, risk governance, compliance governance, policy governance",
        "operationalization": "Enterprise workflow execution, human approval workflow, runtime authorization, policy enforcement",
        "manufacturing_monitoring": "Decision monitoring, workflow monitoring, runtime telemetry, execution monitoring",
        "evidence": "Which AI recommended the formulation, CPP, CQA, regulatory content, or supply chain decision? Was it reviewed? What evidence supports the decision?",
        "continuous_assurance": "Runtime trust, evidence integrity, policy compliance, workflow integrity, trust reconstruction",
        "operational_trust": "AI-enabled CMC decisions can be trusted because recommendations are inventoried, visible, governed, monitored, evidenced, reviewed, and continuously assured."
    },
    {
        "execution_case": "AI-enabled supply chain decision",
        "discovery": "Supplier, raw material, inventory, cold chain, logistics, blood and biologics planning AI activity records",
        "visibility": "Supplier recommendation visibility, raw material visibility, inventory visibility, logistics visibility, workflow visibility, dependency visibility",
        "governance": "Supplier governance, raw material governance, inventory governance, cold chain governance, logistics governance, quality risk governance, policy governance",
        "operationalization": "Supply chain workflow execution, human approval workflow, runtime authorization, policy enforcement",
        "manufacturing_monitoring": "Supplier recommendation monitoring, shortage prediction monitoring, inventory monitoring, cold chain execution monitoring, logistics monitoring",
        "evidence": "Which AI recommended this supplier? Which AI predicted this shortage? Which AI optimized inventory? Was the recommendation reviewed?",
        "continuous_assurance": "Supply chain evidence integrity, recommendation trust, shortage prediction reliability, workflow integrity, policy compliance",
        "operational_trust": "AI-enabled supply chain decisions can be trusted because decision lineage, review, evidence, monitoring, and assurance are reconstructable."
    }
]

ux_patch = {
    "patch_marker": PATCH_MARKER,
    "patch_type": "frozen_lifecycle_traceability_matrix_ux_not_new_module",
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
    "ux_goal": "Make the execution traceability matrix visible on existing blueprint, platform, lifecycle, and route registry pages.",
    "matrix_columns": matrix_columns,
    "execution_traceability_matrix": execution_traceability_matrix,
    "evidence_question": "Can the execution be traced from discovered AI asset to visibility signal, governance decision, operational execution, monitoring event, evidence record, assurance validation, and operational trust outcome?",
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
    data["frozen_lifecycle_traceability_matrix_ux_patch"] = ux_patch

    for bp in data.get("blueprints", []) or []:
        bp["frozen_lifecycle_traceability_matrix_ux"] = {
            "architecture_status": "FROZEN",
            "architecture_change": False,
            "new_module": False,
            "new_route": False,
            "lifecycle_change": False,
            "stage_strengthening_only": True,
            "matrix_visible_on_existing_pages": True,
            "matrix_row_count": len(execution_traceability_matrix),
            "permanent_lifecycle": permanent_lifecycle,
            "operational_trust_unchanged": True
        }

        bp["questions_answered"] = add_unique_list(
            bp.get("questions_answered", []),
            [
                "Can the execution be traced from Discovery through Operational Trust?",
                "Which visibility signal supports this execution?",
                "Which governance decision allowed this execution?",
                "Which operational workflow executed?",
                "Which monitoring event confirms runtime behavior?",
                "Which evidence record reconstructs the action?",
                "Which continuous assurance validation sustains trust?"
            ]
        )

        assessment = bp.get("sample_blueprint_assessment", {})
        if not isinstance(assessment, dict):
            assessment = {}
        assessment["frozen_lifecycle_traceability_matrix_ux_state"] = "TRACEABILITY_MATRIX_VISIBLE_ON_EXISTING_PAGES_NO_NEW_MODULE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["new_route"] = False
        assessment["lifecycle_change"] = False
        assessment["stage_strengthening_only"] = True
        assessment["traceability_matrix_row_count"] = len(execution_traceability_matrix)
        assessment["permanent_lifecycle_sequence"] = ux_patch["permanent_lifecycle_sequence"]
        assessment["operational_trust_rule"] = ux_patch["operational_trust_rule"]
        bp["sample_blueprint_assessment"] = assessment

        for stage in bp.get("lifecycle", []) or []:
            stage_name = normalize_stage_name(stage.get("stage_name", ""))
            if not stage_name:
                continue

            stage["frozen_lifecycle_traceability_matrix_ux_guardrail"] = {
                "architecture_status": "FROZEN",
                "new_module_allowed": False,
                "new_route_allowed": False,
                "lifecycle_change_allowed": False,
                "stage_rename_allowed": False,
                "stage_strengthening_only": True
            }

            if stage_name == "Evidence":
                stage["traceability_matrix_visible"] = True
                stage["execution_traceability_matrix"] = execution_traceability_matrix
                stage["stage_question"] = ux_patch["evidence_question"]
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    [
                        "Visible execution traceability matrix",
                        "Traceability matrix evidence package",
                        "Traceability row evidence record",
                        "Lifecycle reconstruction evidence record"
                    ]
                )

            if stage_name == "Continuous Assurance":
                stage["traceability_matrix_assurance_use"] = "Continuous Assurance validates that each traceability row remains complete, current, policy-compliant, and reconstructable."
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    [
                        "Traceability matrix completeness validation record",
                        "Traceability row assurance validation record"
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
    data["frozen_lifecycle_traceability_matrix_ux_patch"] = ux_patch

    assessment = data.get("sample_integration_assessment", {})
    if not isinstance(assessment, dict):
        assessment = {}

    assessment["frozen_lifecycle_traceability_matrix_ux"] = {
        "state": "TRACEABILITY_MATRIX_VISIBLE_ON_EXISTING_PAGES_NO_NEW_MODULE",
        "architecture_status": "FROZEN",
        "architecture_change": False,
        "new_module": False,
        "new_route": False,
        "lifecycle_change": False,
        "stage_strengthening_only": True,
        "matrix_columns": matrix_columns,
        "execution_traceability_matrix": execution_traceability_matrix
    }

    assessment["implementation_priority"] = add_unique_list(
        assessment.get("implementation_priority", []),
        [
            "Display the frozen lifecycle execution traceability matrix on existing pages.",
            "Make agent, MCP, gateway, A2A, multi-model, digital twin, CMC, and supply chain execution traceability visible.",
            "Use existing Evidence stage to reconstruct every execution.",
            "Use existing Continuous Assurance stage to validate trace completeness.",
            "Keep Operational Trust unchanged as the lifecycle outcome."
        ]
    )

    assessment["evidence_automation_targets"] = add_unique_list(
        assessment.get("evidence_automation_targets", []),
        [
            "Visible execution traceability matrix",
            "Traceability matrix evidence package",
            "Traceability row evidence record",
            "Lifecycle reconstruction evidence record",
            "Traceability matrix completeness validation record"
        ]
    )

    data["sample_integration_assessment"] = assessment

    for stage in data.get("integration_flow", []) or []:
        stage_name = normalize_stage_name(stage.get("stage_name", "")) or normalize_stage_name(stage.get("stage_id", ""))

        stage["frozen_lifecycle_traceability_matrix_ux_guardrail"] = {
            "architecture_status": "FROZEN",
            "new_module_allowed": False,
            "new_route_allowed": False,
            "lifecycle_change_allowed": False,
            "stage_strengthening_only": True
        }

        if stage_name == "Evidence":
            stage["execution_traceability_matrix_visible"] = True
            stage["execution_traceability_matrix"] = execution_traceability_matrix
            stage["operational_question"] = ux_patch["evidence_question"]
            stage["expected_objects"] = add_unique_list(
                stage.get("expected_objects", []),
                [
                    "VisibleExecutionTraceabilityMatrix",
                    "TraceabilityMatrixEvidencePackage",
                    "TraceabilityRowEvidenceRecord",
                    "LifecycleReconstructionEvidenceRecord"
                ]
            )

        if stage_name == "Continuous Assurance":
            stage["traceability_matrix_assurance_use"] = "Validate trace completeness, evidence integrity, policy compliance, workflow integrity, runtime trust, and trust reconstruction."
            stage["expected_objects"] = add_unique_list(
                stage.get("expected_objects", []),
                [
                    "TraceabilityMatrixCompletenessValidationRecord",
                    "TraceabilityRowAssuranceValidationRecord"
                ]
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

def build_matrix_rows(rows):
    html = []
    for row in rows:
        html.append("<tr>")
        html.append(f"<td><strong>{html_escape(row['execution_case'])}</strong></td>")
        html.append(f"<td>{html_escape(row['discovery'])}</td>")
        html.append(f"<td>{html_escape(row['visibility'])}</td>")
        html.append(f"<td>{html_escape(row['governance'])}</td>")
        html.append(f"<td>{html_escape(row['operationalization'])}</td>")
        html.append(f"<td>{html_escape(row['manufacturing_monitoring'])}</td>")
        html.append(f"<td>{html_escape(row['evidence'])}</td>")
        html.append(f"<td>{html_escape(row['continuous_assurance'])}</td>")
        html.append(f"<td>{html_escape(row['operational_trust'])}</td>")
        html.append("</tr>")
    return "\n".join(html)

matrix_rows_html = build_matrix_rows(execution_traceability_matrix)

table_styles = r'''
<style>
.traceability-matrix-wrap {
    overflow-x: auto;
    border: 1px solid rgba(255,255,255,.12);
    border-radius: 18px;
    background: rgba(255,255,255,.035);
    box-shadow: 0 18px 50px rgba(0,0,0,.28);
}
.traceability-matrix {
    width: 100%;
    min-width: 1550px;
    border-collapse: collapse;
    font-size: 13px;
}
.traceability-matrix th {
    position: sticky;
    top: 0;
    background: #111827;
    color: #ffb25f;
    text-align: left;
    padding: 14px;
    border-bottom: 1px solid rgba(255,255,255,.14);
    white-space: nowrap;
}
.traceability-matrix td {
    vertical-align: top;
    padding: 14px;
    border-bottom: 1px solid rgba(255,255,255,.08);
    color: #d8dee9;
    line-height: 1.5;
}
.traceability-matrix tr:hover td {
    background: rgba(255,122,24,.06);
}
.traceability-note {
    margin-top: 14px;
    color: #aeb7c4;
    font-size: 14px;
    line-height: 1.6;
}
</style>
'''

matrix_table_block = f'''
{table_styles}
<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">Execution Traceability Matrix</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Every AI-enabled execution is traced across the frozen lifecycle: Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust.
            </div>
        </div>
        <span class="tag">Existing lifecycle</span>
    </div>
    <div class="traceability-matrix-wrap">
        <table class="traceability-matrix">
            <thead>
                <tr>
                    <th>Execution Case</th>
                    <th>Discovery</th>
                    <th>Visibility</th>
                    <th>Governance</th>
                    <th>Operationalization</th>
                    <th>Manufacturing Monitoring</th>
                    <th>Evidence</th>
                    <th>Continuous Assurance</th>
                    <th>Operational Trust</th>
                </tr>
            </thead>
            <tbody>
                {matrix_rows_html}
            </tbody>
        </table>
    </div>
    <div class="traceability-note">
        No new module, route, architecture, stage, pillar, or lifecycle phase was created. The matrix makes existing lifecycle traceability visible.
    </div>
</section>
'''

platform_block = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>Visible Execution Traceability Matrix</h2>
            <p>The existing Platform B pages now display execution traceability for agent execution, MCP execution, AI Gateway routing, A2A collaboration, multi-model execution, Digital Twin recommendations, AI-enabled CMC recommendations, and AI-enabled supply chain decisions.</p>
        </div>
        <span class="tag">No new route</span>
    </div>
    <div class="grid-4">
        <a class="card" href="/platform/blueprints/ai-enabled-cmc"><strong>AI-enabled CMC Blueprint</strong><span>View CMC, Digital Twin, and supply chain traceability across the frozen lifecycle.</span><small>Open blueprint</small></a>
        <a class="card" href="/platform/blueprints/agentic-enterprise"><strong>Agentic Enterprise Blueprint</strong><span>View agent, MCP, gateway, A2A, model, workflow, policy, and evidence traceability.</span><small>Open blueprint</small></a>
        <a class="card" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Trace execution from discovered asset to operational trust outcome.</span><small>Open lifecycle</small></a>
        <a class="card" href="/platform/evidence-packages"><strong>Evidence</strong><span>Use the matrix to reconstruct every execution.</span><small>Open evidence</small></a>
    </div>
</section>
'''

library_block = r'''
<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">Traceability Matrix UX</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Blueprint pages now make lifecycle traceability visible without adding modules, routes, stages, or architecture.
            </div>
        </div>
        <span class="tag">UX only</span>
    </div>
</section>
'''

route_registry_block = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>Traceability Matrix UX Routes</h2>
            <p>The matrix appears on existing routes only. No route was added.</p>
        </div>
        <span class="tag">Existing routes only</span>
    </div>
    <div class="route-grid">
        <a class="route" href="/platform"><strong>Platform Command Center</strong><span>Shows the traceability matrix UX summary.</span><code>/platform</code></a>
        <a class="route" href="/platform/blueprints/ai-enabled-cmc"><strong>AI-enabled CMC Blueprint</strong><span>Displays traceability matrix for CMC, Digital Twin, and supply chain decisions.</span><code>/platform/blueprints/ai-enabled-cmc</code></a>
        <a class="route" href="/platform/blueprints/agentic-enterprise"><strong>Agentic Enterprise Blueprint</strong><span>Displays traceability matrix for agentic enterprise execution.</span><code>/platform/blueprints/agentic-enterprise</code></a>
        <a class="route" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Uses existing lifecycle integration route.</span><code>/platform/lifecycle-integration</code></a>
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
    matrix_table_block,
    "<div class=\"footer\">"
)

patch_html(
    "platform_agentic_enterprise_blueprint.html",
    matrix_table_block,
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

Path("frozen_lifecycle_traceability_matrix_ux_patch_v1_summary.json").write_text(
    json.dumps(ux_patch, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("frozen_lifecycle_traceability_matrix_ux_patch_v1_urls.txt").write_text(
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
print("Frozen Lifecycle Traceability Matrix UX Patch completed.")
print("Marker:")
print("  " + PATCH_MARKER)
print("No new module. No new route. No architecture change. Lifecycle unchanged.")
