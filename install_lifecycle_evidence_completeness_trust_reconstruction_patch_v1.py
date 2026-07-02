from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_LIFECYCLE_EVIDENCE_COMPLETENESS_TRUST_RECONSTRUCTION_PATCH_V1_ACTIVE"

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

evidence_completeness_dimensions = [
    {
        "dimension": "Discovery completeness",
        "question": "Was the AI asset, agent, model, MCP server, gateway, tool, workflow, Digital Twin, data product, or supply chain AI activity discovered and inventoried?",
        "required_record": "Discovery inventory record",
        "trust_risk_if_missing": "Execution cannot be tied to an approved AI asset or intended use."
    },
    {
        "dimension": "Visibility completeness",
        "question": "Was runtime, workflow, topology, telemetry, dependency, cross-agent, or cross-model visibility captured?",
        "required_record": "Visibility and telemetry record",
        "trust_risk_if_missing": "Execution behavior cannot be observed or reconstructed."
    },
    {
        "dimension": "Governance completeness",
        "question": "Was the relevant governance decision, permission, policy, risk, compliance, identity, or executive approval recorded?",
        "required_record": "Governance decision record",
        "trust_risk_if_missing": "Execution may have occurred without demonstrable governance authorization."
    },
    {
        "dimension": "Operationalization completeness",
        "question": "Was runtime authorization, workflow execution, orchestration, human approval, and policy enforcement captured?",
        "required_record": "Operational execution record",
        "trust_risk_if_missing": "Execution cannot be tied to authorized workflow operation."
    },
    {
        "dimension": "Manufacturing Monitoring completeness",
        "question": "Was execution monitoring, runtime telemetry, agent monitoring, model monitoring, workflow monitoring, or decision monitoring captured?",
        "required_record": "Monitoring signal record",
        "trust_risk_if_missing": "Runtime behavior cannot be verified after execution."
    },
    {
        "dimension": "Evidence completeness",
        "question": "Does the evidence answer which AI, agent, model, workflow, tool, gateway, MCP server, A2A interaction, policy, approval, evidence, and outcome were involved?",
        "required_record": "Execution evidence package",
        "trust_risk_if_missing": "Execution cannot be reconstructed for audit, investigation, or trust justification."
    },
    {
        "dimension": "Continuous Assurance completeness",
        "question": "Were runtime trust, evidence integrity, policy compliance, agent behavior, workflow integrity, and trust reconstruction validated?",
        "required_record": "Continuous assurance validation record",
        "trust_risk_if_missing": "Trust may decay after operation without detection."
    },
    {
        "dimension": "Operational Trust completeness",
        "question": "Can Operational Trust be justified from the complete lifecycle evidence?",
        "required_record": "Operational Trust justification record",
        "trust_risk_if_missing": "The lifecycle cannot support a defensible trust outcome."
    }
]

trust_reconstruction_questions = [
    "What AI-enabled execution occurred?",
    "Which AI asset, agent, model, MCP server, gateway, tool, API, workflow, or Digital Twin was involved?",
    "What was the intended use and risk classification?",
    "Which visibility signals and runtime telemetry were captured?",
    "Which governance decision permitted execution?",
    "Which policies were evaluated or enforced?",
    "Which runtime authorization occurred?",
    "Which human approvals occurred?",
    "Which manufacturing or operational monitoring signals were captured?",
    "Which evidence records reconstruct the execution?",
    "Which continuous assurance checks validated the execution?",
    "Can Operational Trust be justified from the evidence?"
]

evidence_completeness_status = [
    {
        "status": "Complete",
        "meaning": "All required lifecycle records are present, linked, reviewable, and sufficient to reconstruct execution.",
        "trust_outcome": "Operational Trust can be justified."
    },
    {
        "status": "Conditionally complete",
        "meaning": "Most required records are present, but minor gaps require explanation, review, or compensating evidence.",
        "trust_outcome": "Operational Trust may be conditional until gaps are resolved."
    },
    {
        "status": "Incomplete",
        "meaning": "Critical records are missing or not linked across the lifecycle.",
        "trust_outcome": "Operational Trust cannot be fully justified."
    },
    {
        "status": "Not reconstructable",
        "meaning": "Execution cannot be reconstructed from available lifecycle evidence.",
        "trust_outcome": "Operational Trust should not be claimed."
    }
]

stage_strengthening = {
    "Evidence": {
        "stage_rule": "Strengthen Evidence by checking lifecycle evidence completeness before trust is claimed.",
        "evidence_completeness_dimensions": evidence_completeness_dimensions,
        "trust_reconstruction_questions": trust_reconstruction_questions,
        "stage_question": "Is the execution evidence complete enough to reconstruct the AI-enabled action and justify Operational Trust?",
        "evidence_outputs": [
            "Lifecycle evidence completeness record",
            "Execution evidence completeness checklist",
            "Trust reconstruction question set",
            "Evidence gap record",
            "Evidence linkage record",
            "Execution reconstruction package",
            "Operational Trust justification evidence package"
        ]
    },
    "Continuous Assurance": {
        "stage_rule": "Strengthen Continuous Assurance by repeatedly validating evidence completeness, evidence integrity, traceability, and trust reconstruction.",
        "validation_scope": [
            "Evidence completeness",
            "Evidence integrity",
            "Lifecycle traceability",
            "Policy compliance",
            "Runtime trust",
            "Workflow integrity",
            "Agent behavior",
            "Trust reconstruction"
        ],
        "stage_question": "Are evidence completeness, evidence integrity, lifecycle traceability, policy compliance, runtime trust, workflow integrity, agent behavior, and trust reconstruction continuously validated?",
        "evidence_outputs": [
            "Evidence completeness validation record",
            "Evidence integrity validation record",
            "Lifecycle traceability validation record",
            "Policy compliance validation record",
            "Runtime trust validation record",
            "Workflow integrity validation record",
            "Agent behavior validation record",
            "Trust reconstruction validation record"
        ]
    },
    "Operational Trust": {
        "stage_rule": "Operational Trust remains unchanged as the lifecycle outcome, but its justification must be supported by complete lifecycle evidence.",
        "outcome_role": "Operational Trust is the outcome of the entire lifecycle and is justified only when lifecycle evidence is complete, linked, reviewed, and continuously assured.",
        "do_not_expand_beyond_outcome_role": True,
        "stage_question": "Can Operational Trust be justified from complete Discovery, Visibility, Governance, Operationalization, Manufacturing Monitoring, Evidence, and Continuous Assurance records?",
        "evidence_outputs": [
            "Operational Trust justification record",
            "Lifecycle trust outcome record",
            "Trust decision record",
            "Trust limitation record"
        ]
    }
}

patch_model = {
    "patch_marker": PATCH_MARKER,
    "patch_type": "lifecycle_evidence_completeness_trust_reconstruction_not_new_module",
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
    "strengthened_stages": [
        "Evidence",
        "Continuous Assurance",
        "Operational Trust"
    ],
    "evidence_completeness_dimensions": evidence_completeness_dimensions,
    "trust_reconstruction_questions": trust_reconstruction_questions,
    "evidence_completeness_status": evidence_completeness_status,
    "stage_strengthening": stage_strengthening,
    "platform_question": "Can Operational Trust be justified from complete, linked, reviewable, and continuously assured lifecycle evidence?",
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
    data["lifecycle_evidence_completeness_trust_reconstruction_patch"] = patch_model

    for bp in data.get("blueprints", []) or []:
        bp["lifecycle_evidence_completeness_trust_reconstruction"] = {
            "architecture_status": "FROZEN",
            "architecture_change": False,
            "new_module": False,
            "new_route": False,
            "lifecycle_change": False,
            "stage_strengthening_only": True,
            "strengthened_stages": [
                "Evidence",
                "Continuous Assurance",
                "Operational Trust"
            ],
            "platform_question": patch_model["platform_question"],
            "evidence_completeness_dimension_count": len(evidence_completeness_dimensions),
            "trust_reconstruction_question_count": len(trust_reconstruction_questions),
            "operational_trust_unchanged": True
        }

        bp["questions_answered"] = add_unique_list(
            bp.get("questions_answered", []),
            trust_reconstruction_questions + [
                "Is the evidence complete enough to justify Operational Trust?",
                "What evidence gaps prevent trust reconstruction?",
                "What trust limitations should be disclosed?"
            ]
        )

        assessment = bp.get("sample_blueprint_assessment", {})
        if not isinstance(assessment, dict):
            assessment = {}

        assessment["lifecycle_evidence_completeness_state"] = "EVIDENCE_AND_CONTINUOUS_ASSURANCE_STRENGTHENED_NO_NEW_MODULE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["new_route"] = False
        assessment["lifecycle_change"] = False
        assessment["stage_strengthening_only"] = True
        assessment["strengthened_stages"] = [
            "Evidence",
            "Continuous Assurance",
            "Operational Trust"
        ]
        assessment["permanent_lifecycle_sequence"] = patch_model["permanent_lifecycle_sequence"]
        assessment["platform_question"] = patch_model["platform_question"]
        assessment["operational_trust_rule"] = patch_model["operational_trust_rule"]
        bp["sample_blueprint_assessment"] = assessment

        for stage in bp.get("lifecycle", []) or []:
            stage_name = normalize_stage_name(stage.get("stage_name", ""))
            if not stage_name:
                continue

            stage["lifecycle_evidence_completeness_guardrail"] = {
                "architecture_status": "FROZEN",
                "new_module_allowed": False,
                "new_route_allowed": False,
                "lifecycle_change_allowed": False,
                "stage_rename_allowed": False,
                "stage_strengthening_only": True
            }

            if stage_name in stage_strengthening:
                strengthening = stage_strengthening[stage_name]
                stage["lifecycle_evidence_completeness_trust_reconstruction"] = strengthening
                stage["stage_question"] = strengthening["stage_question"]
                stage["evidence_outputs"] = add_unique_list(
                    stage.get("evidence_outputs", []),
                    strengthening["evidence_outputs"]
                )
                stage["operational_focus"] = strengthening["stage_rule"]

            if stage_name == "Evidence":
                stage["evidence_completeness_dimensions"] = evidence_completeness_dimensions
                stage["trust_reconstruction_questions"] = trust_reconstruction_questions
                stage["evidence_completeness_status"] = evidence_completeness_status

            if stage_name == "Continuous Assurance":
                stage["evidence_completeness_validation_scope"] = stage_strengthening["Continuous Assurance"]["validation_scope"]

            if stage_name == "Operational Trust":
                stage["operational_trust_outcome_rule"] = stage_strengthening["Operational Trust"]["outcome_role"]
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
    data["lifecycle_evidence_completeness_trust_reconstruction_patch"] = patch_model

    assessment = data.get("sample_integration_assessment", {})
    if not isinstance(assessment, dict):
        assessment = {}

    assessment["lifecycle_evidence_completeness_trust_reconstruction"] = {
        "state": "EVIDENCE_AND_CONTINUOUS_ASSURANCE_STRENGTHENED_NO_NEW_MODULE",
        "architecture_status": "FROZEN",
        "architecture_change": False,
        "new_module": False,
        "new_route": False,
        "lifecycle_change": False,
        "stage_strengthening_only": True,
        "evidence_completeness_dimensions": evidence_completeness_dimensions,
        "trust_reconstruction_questions": trust_reconstruction_questions,
        "evidence_completeness_status": evidence_completeness_status
    }

    assessment["implementation_priority"] = add_unique_list(
        assessment.get("implementation_priority", []),
        [
            "Strengthen Evidence with lifecycle evidence completeness checks.",
            "Strengthen Evidence with trust reconstruction questions.",
            "Strengthen Evidence with evidence gap records and linkage records.",
            "Strengthen Continuous Assurance with evidence completeness validation.",
            "Strengthen Continuous Assurance with trust reconstruction validation.",
            "Use Operational Trust only as the lifecycle outcome justified by complete evidence.",
            "Do not create new modules, routes, stages, pillars, lifecycle phases, architectures, or foundational concepts."
        ]
    )

    assessment["evidence_automation_targets"] = add_unique_list(
        assessment.get("evidence_automation_targets", []),
        [
            "Lifecycle evidence completeness record",
            "Execution evidence completeness checklist",
            "Trust reconstruction question set",
            "Evidence gap record",
            "Evidence linkage record",
            "Operational Trust justification evidence package",
            "Evidence completeness validation record",
            "Trust reconstruction validation record"
        ]
    )

    data["sample_integration_assessment"] = assessment

    lifecycle_object_map = {
        "Evidence": [
            "LifecycleEvidenceCompletenessRecord",
            "ExecutionEvidenceCompletenessChecklist",
            "TrustReconstructionQuestionSet",
            "EvidenceGapRecord",
            "EvidenceLinkageRecord",
            "ExecutionReconstructionPackage",
            "OperationalTrustJustificationEvidencePackage"
        ],
        "Continuous Assurance": [
            "EvidenceCompletenessValidationRecord",
            "EvidenceIntegrityValidationRecord",
            "LifecycleTraceabilityValidationRecord",
            "PolicyComplianceValidationRecord",
            "RuntimeTrustValidationRecord",
            "WorkflowIntegrityValidationRecord",
            "AgentBehaviorValidationRecord",
            "TrustReconstructionValidationRecord"
        ],
        "Operational Trust": [
            "OperationalTrustJustificationRecord",
            "LifecycleTrustOutcomeRecord",
            "TrustDecisionRecord",
            "TrustLimitationRecord"
        ]
    }

    for stage in data.get("integration_flow", []) or []:
        stage_name = normalize_stage_name(stage.get("stage_name", "")) or normalize_stage_name(stage.get("stage_id", ""))

        stage["lifecycle_evidence_completeness_guardrail"] = {
            "architecture_status": "FROZEN",
            "new_module_allowed": False,
            "new_route_allowed": False,
            "lifecycle_change_allowed": False,
            "stage_strengthening_only": True
        }

        if stage_name in stage_strengthening:
            strengthening = stage_strengthening[stage_name]
            stage["lifecycle_evidence_completeness_trust_reconstruction"] = strengthening
            stage["operational_question"] = strengthening["stage_question"]
            stage["expected_objects"] = add_unique_list(
                stage.get("expected_objects", []),
                lifecycle_object_map.get(stage_name, [])
            )
            stage["evidence_outputs"] = add_unique_list(
                stage.get("evidence_outputs", []),
                strengthening["evidence_outputs"]
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

def build_dimension_rows():
    rows = []
    for item in evidence_completeness_dimensions:
        rows.append(
            "<tr>"
            f"<td><strong>{html_escape(item['dimension'])}</strong></td>"
            f"<td>{html_escape(item['question'])}</td>"
            f"<td>{html_escape(item['required_record'])}</td>"
            f"<td>{html_escape(item['trust_risk_if_missing'])}</td>"
            "</tr>"
        )
    return "\n".join(rows)

def build_status_cards():
    cards = []
    for item in evidence_completeness_status:
        cards.append(
            f"<div class='panel'><strong>{html_escape(item['status'])}</strong>"
            f"<div>{html_escape(item['meaning'])}</div>"
            f"<small>{html_escape(item['trust_outcome'])}</small></div>"
        )
    return "\n".join(cards)

def build_question_items():
    return "\n".join([f"<li>{html_escape(q)}</li>" for q in trust_reconstruction_questions])

dimension_rows = build_dimension_rows()
status_cards = build_status_cards()
question_items = build_question_items()

ux_styles = r'''
<style>
.evidence-completeness-wrap {
    overflow-x: auto;
    border: 1px solid rgba(255,255,255,.12);
    border-radius: 18px;
    background: rgba(255,255,255,.035);
    box-shadow: 0 18px 50px rgba(0,0,0,.28);
}
.evidence-completeness-table {
    width: 100%;
    min-width: 1100px;
    border-collapse: collapse;
    font-size: 13px;
}
.evidence-completeness-table th {
    background: #111827;
    color: #ffb25f;
    text-align: left;
    padding: 14px;
    border-bottom: 1px solid rgba(255,255,255,.14);
}
.evidence-completeness-table td {
    vertical-align: top;
    padding: 14px;
    border-bottom: 1px solid rgba(255,255,255,.08);
    color: #d8dee9;
    line-height: 1.5;
}
.evidence-completeness-table tr:hover td {
    background: rgba(255,122,24,.06);
}
.trust-question-list {
    columns: 2;
    column-gap: 34px;
    margin: 0;
    padding-left: 22px;
    color: #d8dee9;
    line-height: 1.7;
}
.trust-question-list li {
    break-inside: avoid;
    margin-bottom: 8px;
}
</style>
'''

blueprint_block = f'''
{ux_styles}
<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">Lifecycle Evidence Completeness and Trust Reconstruction</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Can Operational Trust be justified from complete, linked, reviewable, and continuously assured lifecycle evidence? This strengthens Evidence and Continuous Assurance only. Operational Trust remains the lifecycle outcome.
            </div>
        </div>
        <span class="tag">No new module</span>
    </div>

    <div class="evidence-completeness-wrap">
        <table class="evidence-completeness-table">
            <thead>
                <tr>
                    <th>Completeness Dimension</th>
                    <th>Question</th>
                    <th>Required Record</th>
                    <th>Trust Risk if Missing</th>
                </tr>
            </thead>
            <tbody>
                {dimension_rows}
            </tbody>
        </table>
    </div>

    <div class="topbar" style="margin-top:24px;">
        <div>
            <h3 style="margin:0;font-size:22px;">Trust Reconstruction Questions</h3>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                These questions reconstruct AI-enabled execution across the frozen lifecycle.
            </div>
        </div>
    </div>
    <ul class="trust-question-list">
        {question_items}
    </ul>

    <div class="grid" style="margin-top:24px;">
        {status_cards}
    </div>
</section>
'''

platform_block = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>Lifecycle Evidence Completeness</h2>
            <p>Evidence and Continuous Assurance now check whether lifecycle records are complete enough to reconstruct execution and justify Operational Trust. No new module or architecture change.</p>
        </div>
        <span class="tag">Trust reconstruction</span>
    </div>
    <div class="grid-4">
        <a class="card" href="/platform/blueprints/ai-enabled-cmc"><strong>AI-enabled CMC Blueprint</strong><span>Check evidence completeness for CMC, Digital Twin, and supply chain decisions.</span><small>Open blueprint</small></a>
        <a class="card" href="/platform/blueprints/agentic-enterprise"><strong>Agentic Enterprise Blueprint</strong><span>Check evidence completeness for agents, MCP, gateways, A2A, workflows, policies, and approvals.</span><small>Open blueprint</small></a>
        <a class="card" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Connect completeness records to Evidence, Continuous Assurance, and Operational Trust.</span><small>Open lifecycle</small></a>
        <a class="card" href="/platform/evidence-packages"><strong>Evidence</strong><span>Use completeness checks to build reconstructable evidence packages.</span><small>Open evidence</small></a>
    </div>
</section>
'''

library_block = r'''
<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">Evidence Completeness Across Blueprints</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Blueprints may strengthen Evidence and Continuous Assurance by checking whether execution can be reconstructed and Operational Trust can be justified from lifecycle evidence.
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
            <h2>Lifecycle Evidence Completeness Routes</h2>
            <p>Evidence completeness is shown through existing routes only. No new module or route was added.</p>
        </div>
        <span class="tag">Existing routes only</span>
    </div>
    <div class="route-grid">
        <a class="route" href="/platform"><strong>Platform Command Center</strong><span>Shows lifecycle evidence completeness and trust reconstruction.</span><code>/platform</code></a>
        <a class="route" href="/platform/blueprints/ai-enabled-cmc"><strong>AI-enabled CMC Blueprint</strong><span>Displays evidence completeness and trust reconstruction questions.</span><code>/platform/blueprints/ai-enabled-cmc</code></a>
        <a class="route" href="/platform/blueprints/agentic-enterprise"><strong>Agentic Enterprise Blueprint</strong><span>Displays evidence completeness for agentic enterprise execution.</span><code>/platform/blueprints/agentic-enterprise</code></a>
        <a class="route" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Connects completeness records to lifecycle assurance.</span><code>/platform/lifecycle-integration</code></a>
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

Path("lifecycle_evidence_completeness_trust_reconstruction_patch_v1_summary.json").write_text(
    json.dumps(patch_model, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("lifecycle_evidence_completeness_trust_reconstruction_patch_v1_urls.txt").write_text(
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
print("Lifecycle Evidence Completeness and Trust Reconstruction Patch completed.")
print("Marker:")
print("  " + PATCH_MARKER)
print("No new module. No new route. No architecture change. Lifecycle unchanged.")
