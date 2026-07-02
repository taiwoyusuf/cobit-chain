from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_ENTERPRISE_EXECUTION_ASSURANCE_CAPABILITY_PATCH_V1_ACTIVE"
ROUTE_MARKER_START = "# COBITCHAIN_ENTERPRISE_EXECUTION_ASSURANCE_CAPABILITY_ROUTES_V1_START"
ROUTE_MARKER_END = "# COBITCHAIN_ENTERPRISE_EXECUTION_ASSURANCE_CAPABILITY_ROUTES_V1_END"

updated_lifecycle = [
    "Discovery",
    "Visibility",
    "Governance",
    "Operationalization",
    "Enterprise Execution Assurance",
    "Evidence",
    "Continuous Assurance",
    "Operational Trust"
]

enterprise_execution_assurance = {
    "capability_name": "Enterprise Execution Assurance",
    "capability_type": "First-class Platform B assurance capability",
    "platform_position": "Between Operationalization and Evidence",
    "purpose": "Evaluate whether AI-generated recommendations were translated into enterprise actions safely, correctly, under policy, and with complete evidence.",
    "core_question": "Was the AI recommendation executed safely, correctly, under policy, and with complete evidence?",
    "positioning_statement": "Organizations are moving from AI that recommends to AI that acts. Enterprise Execution Assurance ensures those AI-driven actions are authorized, policy-enforced, traceable, reversible where required, monitored, evidenced, and reconstructable.",
    "difference_from_evidence": "Enterprise Execution Assurance checks the execution itself. Evidence proves the execution can be reconstructed.",
    "platform_redesign": False,
    "lifecycle_evolution": True
}

evaluation_areas = [
    "Workflow authorization",
    "Runtime policy enforcement",
    "Enterprise system interaction",
    "API invocation traceability",
    "Human approval checkpoints",
    "Rollback capability",
    "Execution evidence",
    "Outcome verification",
    "Continuous monitoring",
    "Audit reconstruction"
]

execution_assurance_modules = [
    {
        "name": "AI Runtime Assurance",
        "question": "Can this AI runtime be operationally trusted?",
        "evaluates": [
            "Runtime identity",
            "Runtime security",
            "Runtime permissions",
            "Runtime isolation",
            "Runtime policy enforcement",
            "Runtime evidence",
            "Runtime audit logs"
        ]
    },
    {
        "name": "Workflow Assurance",
        "question": "Was this AI action executed through an approved workflow?",
        "evaluates": [
            "Workflow integrity",
            "Approval routing",
            "Workflow ownership",
            "Workflow evidence",
            "Workflow traceability",
            "Workflow versioning",
            "Workflow execution logs"
        ]
    },
    {
        "name": "Enterprise Action Assurance",
        "question": "Can every enterprise action be reconstructed?",
        "evaluates": [
            "API called",
            "File modified",
            "Database updated",
            "ServiceNow ticket created",
            "Robot instructed",
            "MES command",
            "ERP update",
            "LIMS action",
            "EHR action"
        ]
    },
    {
        "name": "Runtime Policy Assurance",
        "question": "Was policy enforced during execution?",
        "evaluates": [
            "Policies applied",
            "Blocked actions",
            "Exceptions",
            "Policy overrides",
            "Escalation",
            "Approval"
        ]
    },
    {
        "name": "AI Orchestration Assurance",
        "question": "Was AI orchestration executed safely, correctly, and with recoverable evidence?",
        "evaluates": [
            "Agent routing",
            "Agent sequencing",
            "Agent dependencies",
            "Agent handoffs",
            "Runtime coordination",
            "Failure handling",
            "Rollback",
            "Retry evidence"
        ]
    },
    {
        "name": "Agent Runtime Evidence",
        "question": "Can the agent runtime decision be reconstructed?",
        "evaluates": [
            "Prompt",
            "Context",
            "Model",
            "Runtime",
            "Workflow",
            "Tools",
            "APIs",
            "Human review",
            "Decision",
            "Outcome"
        ]
    }
]

execution_control_questions = [
    "Was the workflow authorized?",
    "Was runtime policy enforced?",
    "Which enterprise system was touched?",
    "Which API was invoked?",
    "Was human approval required and captured?",
    "Was rollback available?",
    "Was execution evidence produced?",
    "Was the outcome verified?",
    "Is the action continuously monitored?",
    "Can the execution be reconstructed during audit or inspection?"
]

enterprise_action_types = [
    "API call",
    "File modification",
    "Database update",
    "ServiceNow ticket creation",
    "Robot instruction",
    "MES command",
    "ERP update",
    "LIMS action",
    "EHR action"
]

execution_assurance_records = [
    "Enterprise Execution Assurance Record",
    "Workflow authorization record",
    "Runtime policy enforcement record",
    "Enterprise system interaction record",
    "API invocation traceability record",
    "Human approval checkpoint record",
    "Rollback capability record",
    "Execution evidence record",
    "Outcome verification record",
    "Continuous monitoring record",
    "Audit reconstruction record",
    "AI runtime assurance record",
    "Workflow assurance record",
    "Enterprise action assurance record",
    "Runtime policy assurance record",
    "AI orchestration assurance record",
    "Agent runtime evidence record"
]

patch_model = {
    "patch_marker": PATCH_MARKER,
    "patch_type": "enterprise_execution_assurance_capability_layer",
    "platform_redesign": False,
    "new_capability_layer": True,
    "capability_name": "Enterprise Execution Assurance",
    "updated_lifecycle": updated_lifecycle,
    "updated_lifecycle_sequence": "Discovery -> Visibility -> Governance -> Operationalization -> Enterprise Execution Assurance -> Evidence -> Continuous Assurance -> Operational Trust",
    "enterprise_execution_assurance": enterprise_execution_assurance,
    "evaluation_areas": evaluation_areas,
    "execution_assurance_modules": execution_assurance_modules,
    "execution_control_questions": execution_control_questions,
    "enterprise_action_types": enterprise_action_types,
    "execution_assurance_records": execution_assurance_records
}

def load_json(path):
    p = Path(path)
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8-sig"))

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
    for stage in updated_lifecycle:
        if stage.lower() == low:
            return stage
    if "execution assurance" in low or "enterprise execution" in low:
        return "Enterprise Execution Assurance"
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

def enterprise_execution_stage():
    return {
        "stage_name": "Enterprise Execution Assurance",
        "stage_order": 5,
        "stage_type": "Execution-control assurance layer",
        "stage_rule": "Evaluate whether AI-generated recommendations were translated into enterprise actions safely, correctly, under policy, and with complete evidence.",
        "core_question": enterprise_execution_assurance["core_question"],
        "evaluation_areas": evaluation_areas,
        "execution_control_questions": execution_control_questions,
        "execution_assurance_modules": execution_assurance_modules,
        "enterprise_action_types": enterprise_action_types,
        "evidence_outputs": execution_assurance_records,
        "operational_focus": "Execution Assurance checks the execution itself before Evidence proves it can be reconstructed."
    }

def insert_execution_assurance_stage(lifecycle):
    if not isinstance(lifecycle, list):
        return lifecycle

    cleaned = []
    found = False
    for stage in lifecycle:
        if isinstance(stage, dict):
            if normalize_stage_name(stage.get("stage_name", "")) == "Enterprise Execution Assurance":
                found = True
                merged = stage
                merged.update(enterprise_execution_stage())
                cleaned.append(merged)
            else:
                cleaned.append(stage)
        else:
            cleaned.append(stage)

    if found:
        return cleaned

    new_lifecycle = []
    inserted = False
    for stage in cleaned:
        new_lifecycle.append(stage)
        if isinstance(stage, dict) and normalize_stage_name(stage.get("stage_name", "")) == "Operationalization":
            new_lifecycle.append(enterprise_execution_stage())
            inserted = True

    if not inserted:
        new_lifecycle.append(enterprise_execution_stage())

    return new_lifecycle

def patch_blueprint_seed():
    path = Path("platform_blueprint_library_seed.json")
    if not path.exists():
        print("SKIP: platform_blueprint_library_seed.json not found.")
        return False

    data = load_json(path)
    data["enterprise_execution_assurance_capability_patch"] = patch_model
    data["platform_b_updated_lifecycle"] = updated_lifecycle
    data["platform_b_execution_assurance_capability"] = enterprise_execution_assurance

    for bp in data.get("blueprints", []) or []:
        bp["updated_lifecycle_sequence"] = patch_model["updated_lifecycle_sequence"]
        bp["enterprise_execution_assurance"] = {
            "capability_name": "Enterprise Execution Assurance",
            "capability_type": "First-class Platform B assurance capability",
            "platform_position": "Between Operationalization and Evidence",
            "platform_redesign": False,
            "core_question": enterprise_execution_assurance["core_question"],
            "purpose": enterprise_execution_assurance["purpose"],
            "evaluation_areas": evaluation_areas,
            "execution_control_questions": execution_control_questions,
            "execution_assurance_modules": execution_assurance_modules,
            "enterprise_action_types": enterprise_action_types
        }

        bp["questions_answered"] = add_unique_list(
            bp.get("questions_answered", []),
            execution_control_questions + [
                "Can this AI runtime be operationally trusted?",
                "Was this AI action executed through an approved workflow?",
                "Can every enterprise action be reconstructed?",
                "Was policy enforced during execution?",
                "Was the AI recommendation executed safely?"
            ]
        )

        assessment = bp.get("sample_blueprint_assessment", {})
        if not isinstance(assessment, dict):
            assessment = {}

        assessment["enterprise_execution_assurance_state"] = "FIRST_CLASS_EXECUTION_ASSURANCE_CAPABILITY_ADDED"
        assessment["platform_redesign"] = False
        assessment["new_capability_layer"] = True
        assessment["capability_name"] = "Enterprise Execution Assurance"
        assessment["platform_position"] = "Between Operationalization and Evidence"
        assessment["updated_lifecycle_sequence"] = patch_model["updated_lifecycle_sequence"]
        assessment["core_question"] = enterprise_execution_assurance["core_question"]
        assessment["execution_assurance_module_count"] = len(execution_assurance_modules)
        assessment["evaluation_area_count"] = len(evaluation_areas)
        bp["sample_blueprint_assessment"] = assessment

        if "lifecycle" in bp:
            bp["lifecycle"] = insert_execution_assurance_stage(bp.get("lifecycle", []))

    save_json(path, data)
    print("PATCHED: platform_blueprint_library_seed.json")
    return True

def patch_lifecycle_seed():
    path = Path("platform_lifecycle_integration_seed.json")
    if not path.exists():
        print("SKIP: platform_lifecycle_integration_seed.json not found.")
        return False

    data = load_json(path)
    data["enterprise_execution_assurance_capability_patch"] = patch_model
    data["platform_b_updated_lifecycle"] = updated_lifecycle

    assessment = data.get("sample_integration_assessment", {})
    if not isinstance(assessment, dict):
        assessment = {}

    assessment["enterprise_execution_assurance"] = {
        "state": "FIRST_CLASS_EXECUTION_ASSURANCE_CAPABILITY_ADDED",
        "platform_redesign": False,
        "new_capability_layer": True,
        "capability_name": "Enterprise Execution Assurance",
        "platform_position": "Between Operationalization and Evidence",
        "updated_lifecycle": updated_lifecycle,
        "updated_lifecycle_sequence": patch_model["updated_lifecycle_sequence"],
        "enterprise_execution_assurance": enterprise_execution_assurance,
        "evaluation_areas": evaluation_areas,
        "execution_assurance_modules": execution_assurance_modules,
        "execution_control_questions": execution_control_questions,
        "enterprise_action_types": enterprise_action_types
    }

    assessment["implementation_priority"] = add_unique_list(
        assessment.get("implementation_priority", []),
        [
            "Add Enterprise Execution Assurance as a first-class Platform B capability layer.",
            "Place Enterprise Execution Assurance between Operationalization and Evidence.",
            "Evaluate whether AI recommendations were translated into enterprise actions safely, correctly, under policy, and with complete evidence.",
            "Build AI Runtime Assurance.",
            "Build Workflow Assurance.",
            "Build Enterprise Action Assurance.",
            "Build Runtime Policy Assurance.",
            "Build AI Orchestration Assurance.",
            "Build Agent Runtime Evidence.",
            "Ensure every enterprise action can be reconstructed."
        ]
    )

    assessment["evidence_automation_targets"] = add_unique_list(
        assessment.get("evidence_automation_targets", []),
        execution_assurance_records
    )

    data["sample_integration_assessment"] = assessment

    if "integration_flow" in data and isinstance(data["integration_flow"], list):
        data["integration_flow"] = insert_execution_assurance_stage(data["integration_flow"])

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

def build_module_cards():
    cards = []
    for item in execution_assurance_modules:
        evaluates = "".join([f"<li>{html_escape(x)}</li>" for x in item["evaluates"]])
        cards.append(
            "<div class='panel'>"
            f"<strong>{html_escape(item['name'])}</strong>"
            f"<div style='margin-top:8px;color:#d8dee9;'>{html_escape(item['question'])}</div>"
            f"<ul style='margin-top:10px;color:#b9c2ce;line-height:1.6;'>{evaluates}</ul>"
            "</div>"
        )
    return "\n".join(cards)

def build_eval_items():
    return "\n".join([f"<li>{html_escape(x)}</li>" for x in evaluation_areas])

def build_question_items():
    return "\n".join([f"<li>{html_escape(x)}</li>" for x in execution_control_questions])

def build_action_items():
    return "\n".join([f"<li>{html_escape(x)}</li>" for x in enterprise_action_types])

ux_styles = r'''
<style>
.exec-assurance-flow {
    display:flex;
    flex-wrap:wrap;
    gap:10px;
    align-items:center;
    margin-top:18px;
}
.exec-assurance-node {
    border:1px solid rgba(255,255,255,.14);
    background:rgba(255,255,255,.045);
    border-radius:999px;
    padding:10px 14px;
    color:#d8dee9;
    font-size:13px;
}
.exec-assurance-node.hot {
    border-color:rgba(255,178,95,.55);
    background:rgba(255,122,24,.12);
    color:#ffb25f;
    font-weight:700;
}
.exec-arrow {
    color:#ffb25f;
}
.exec-list {
    columns:2;
    column-gap:34px;
    margin:0;
    padding-left:22px;
    color:#d8dee9;
    line-height:1.7;
}
.exec-list li {
    break-inside:avoid;
    margin-bottom:8px;
}
</style>
'''

module_cards = build_module_cards()
eval_items = build_eval_items()
question_items = build_question_items()
action_items = build_action_items()

capability_html = f'''
{ux_styles}
<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">Enterprise Execution Assurance&trade;</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Evaluate whether AI-generated recommendations were translated into enterprise actions safely, correctly, under policy, and with complete evidence.
            </div>
        </div>
        <span class="tag">First-class capability</span>
    </div>

    <div class="exec-assurance-flow">
        <span class="exec-assurance-node">Discovery</span><span class="exec-arrow">-&gt;</span>
        <span class="exec-assurance-node">Visibility</span><span class="exec-arrow">-&gt;</span>
        <span class="exec-assurance-node">Governance</span><span class="exec-arrow">-&gt;</span>
        <span class="exec-assurance-node">Operationalization</span><span class="exec-arrow">-&gt;</span>
        <span class="exec-assurance-node hot">Enterprise Execution Assurance&trade;</span><span class="exec-arrow">-&gt;</span>
        <span class="exec-assurance-node">Evidence</span><span class="exec-arrow">-&gt;</span>
        <span class="exec-assurance-node">Continuous Assurance</span><span class="exec-arrow">-&gt;</span>
        <span class="exec-assurance-node">Operational Trust</span>
    </div>

    <div class="grid" style="margin-top:24px;">
        <div class="panel"><strong>Core question</strong><div>{html_escape(enterprise_execution_assurance["core_question"])}</div></div>
        <div class="panel"><strong>Why it matters</strong><div>Organizations are moving from AI that recommends to AI that acts. Platform B must assure execution, not only recommendation quality.</div></div>
        <div class="panel"><strong>Execution Assurance checks</strong><div>The execution itself: workflow, runtime, policy, system interaction, API call, rollback, outcome, monitoring, and audit reconstruction.</div></div>
        <div class="panel"><strong>Evidence proves</strong><div>That the execution can be reconstructed for audit, inspection, investigation, and operational trust.</div></div>
    </div>

    <div class="topbar" style="margin-top:24px;">
        <div>
            <h3 style="margin:0;font-size:22px;">Evaluation Areas</h3>
        </div>
    </div>
    <ul class="exec-list">
        {eval_items}
    </ul>

    <div class="topbar" style="margin-top:24px;">
        <div>
            <h3 style="margin:0;font-size:22px;">Execution Control Questions</h3>
        </div>
    </div>
    <ul class="exec-list">
        {question_items}
    </ul>

    <div class="topbar" style="margin-top:24px;">
        <div>
            <h3 style="margin:0;font-size:22px;">Enterprise Actions Covered</h3>
        </div>
    </div>
    <ul class="exec-list">
        {action_items}
    </ul>

    <div class="topbar" style="margin-top:24px;">
        <div>
            <h3 style="margin:0;font-size:22px;">Assurance Capabilities</h3>
        </div>
    </div>
    <div class="grid">
        {module_cards}
    </div>
</section>
'''

platform_block = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>Enterprise Execution Assurance&trade;</h2>
            <p>Platform B now includes Enterprise Execution Assurance as the layer between Operationalization and Evidence. It evaluates whether AI-generated recommendations became enterprise actions safely, correctly, under policy, and with complete evidence.</p>
        </div>
        <span class="tag">New capability layer</span>
    </div>
    <div class="grid-4">
        <a class="card" href="/platform/enterprise-execution-assurance"><strong>Enterprise Execution Assurance</strong><span>Assure AI actions across runtimes, workflows, policies, systems, APIs, rollback, monitoring, and audit reconstruction.</span><small>Open capability</small></a>
        <a class="card" href="/platform/blueprints/ai-enabled-cmc"><strong>AI-enabled CMC Blueprint</strong><span>Apply execution assurance to MES commands, EBR, batch execution, CPP/CQA changes, and inspection reconstruction.</span><small>Open blueprint</small></a>
        <a class="card" href="/platform/blueprints/agentic-enterprise"><strong>Agentic Enterprise Blueprint</strong><span>Apply execution assurance to agent routing, handoffs, dependencies, rollback, retries, and runtime evidence.</span><small>Open blueprint</small></a>
        <a class="card" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Shows the updated lifecycle with Enterprise Execution Assurance between Operationalization and Evidence.</span><small>Open lifecycle</small></a>
    </div>
</section>
'''

library_block = r'''
<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">Enterprise Execution Assurance&trade;</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Platform B now assures AI execution, not only AI recommendations. Enterprise Execution Assurance sits between Operationalization and Evidence.
            </div>
        </div>
        <span class="tag">Execution assurance</span>
    </div>
</section>
'''

route_registry_block = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>Enterprise Execution Assurance Routes</h2>
            <p>Enterprise Execution Assurance is available as a first-class Platform B capability page and API endpoint.</p>
        </div>
        <span class="tag">Capability layer</span>
    </div>
    <div class="route-grid">
        <a class="route" href="/platform/enterprise-execution-assurance"><strong>Enterprise Execution Assurance</strong><span>First-class capability page for execution assurance.</span><code>/platform/enterprise-execution-assurance</code></a>
        <a class="route" href="/platform/execution-assurance"><strong>Execution Assurance Alias</strong><span>Short alias for the same capability.</span><code>/platform/execution-assurance</code></a>
        <a class="route" href="/api/platform/enterprise-execution-assurance/demo"><strong>Enterprise Execution Assurance API</strong><span>Returns execution assurance capability model.</span><code>/api/platform/enterprise-execution-assurance/demo</code></a>
        <a class="route" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Shows Enterprise Execution Assurance between Operationalization and Evidence.</span><code>/platform/lifecycle-integration</code></a>
    </div>
</section>
'''

def remove_marker_block(text, marker=PATCH_MARKER):
    start = f"<!-- {marker} -->"
    end = f"<!-- END {marker} -->"
    return re.sub(re.escape(start) + r".*?" + re.escape(end), "", text, flags=re.DOTALL)

def patch_html(path, block, anchor):
    p = Path(path)
    if not p.exists():
        print(f"SKIP: {path} not found.")
        return False

    text = p.read_text(encoding="utf-8-sig")
    text = remove_marker_block(text)

    wrapped = f"\n<!-- {PATCH_MARKER} -->\n{block}\n<!-- END {PATCH_MARKER} -->\n"

    if anchor in text:
        text = text.replace(anchor, wrapped + "\n" + anchor, 1)
    else:
        text = text.replace("</body>", wrapped + "\n</body>", 1)

    p.write_text(text, encoding="utf-8")
    print(f"PATCHED: {path}")
    return True

def create_capability_page():
    page = f'''<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Enterprise Execution Assurance - Platform B</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{
            margin:0;
            font-family: Arial, sans-serif;
            background:#0b1020;
            color:#eef2f7;
        }}
        .shell {{
            max-width:1180px;
            margin:0 auto;
            padding:34px 22px 70px;
        }}
        .hero {{
            border:1px solid rgba(255,255,255,.12);
            background:linear-gradient(135deg, rgba(255,122,24,.16), rgba(59,130,246,.08));
            border-radius:26px;
            padding:34px;
            box-shadow:0 22px 70px rgba(0,0,0,.35);
        }}
        .eyebrow {{
            color:#ffb25f;
            font-weight:700;
            letter-spacing:.08em;
            text-transform:uppercase;
            font-size:12px;
        }}
        h1 {{
            margin:10px 0 10px;
            font-size:44px;
            line-height:1.05;
        }}
        .subtitle {{
            color:#c9d3df;
            font-size:17px;
            line-height:1.7;
            max-width:900px;
        }}
        .section {{
            margin-top:24px;
            border:1px solid rgba(255,255,255,.10);
            background:rgba(255,255,255,.04);
            border-radius:22px;
            padding:24px;
        }}
        .topbar {{
            display:flex;
            justify-content:space-between;
            gap:18px;
            align-items:flex-start;
            margin-bottom:18px;
        }}
        .tag {{
            border:1px solid rgba(255,178,95,.45);
            color:#ffb25f;
            border-radius:999px;
            padding:8px 12px;
            font-size:12px;
            white-space:nowrap;
            background:rgba(255,122,24,.08);
        }}
        .grid {{
            display:grid;
            grid-template-columns:repeat(auto-fit,minmax(250px,1fr));
            gap:16px;
        }}
        .panel {{
            border:1px solid rgba(255,255,255,.10);
            background:rgba(255,255,255,.045);
            border-radius:18px;
            padding:18px;
            color:#d8dee9;
            line-height:1.6;
        }}
        .panel strong {{
            display:block;
            color:#fff;
            margin-bottom:6px;
        }}
        a {{
            color:#ffb25f;
            text-decoration:none;
        }}
        .nav {{
            margin-top:18px;
            display:flex;
            gap:12px;
            flex-wrap:wrap;
        }}
        .nav a {{
            border:1px solid rgba(255,255,255,.12);
            border-radius:999px;
            padding:10px 14px;
            background:rgba(255,255,255,.04);
        }}
    </style>
</head>
<body>
    <main class="shell">
        <section class="hero">
            <div class="eyebrow">Platform B Capability Layer</div>
            <h1>Enterprise Execution Assurance&trade;</h1>
            <div class="subtitle">
                Evaluate whether AI-generated recommendations were translated into enterprise actions safely, correctly, under policy, and with complete evidence.
            </div>
            <div class="nav">
                <a href="/platform">Platform</a>
                <a href="/platform/blueprints/ai-enabled-cmc">AI-enabled CMC Blueprint</a>
                <a href="/platform/blueprints/agentic-enterprise">Agentic Enterprise Blueprint</a>
                <a href="/platform/lifecycle-integration">Lifecycle Integration</a>
                <a href="/api/platform/enterprise-execution-assurance/demo">API</a>
            </div>
        </section>
        {capability_html}
    </main>
</body>
</html>
'''
    Path("platform_enterprise_execution_assurance.html").write_text(page, encoding="utf-8")
    print("CREATED: platform_enterprise_execution_assurance.html")

def patch_app_routes():
    path = Path("app.py")
    text = path.read_text(encoding="utf-8")

    route_block = f'''
{ROUTE_MARKER_START}
@app.route("/platform/enterprise-execution-assurance")
@app.route("/platform/execution-assurance")
def platform_enterprise_execution_assurance():
    from pathlib import Path
    from flask import Response
    page = Path("platform_enterprise_execution_assurance.html")
    if page.exists():
        return Response(page.read_text(encoding="utf-8"), mimetype="text/html")
    return Response("<h1>Enterprise Execution Assurance</h1><p>Capability page not found.</p>", mimetype="text/html", status=404)

@app.route("/api/platform/enterprise-execution-assurance/demo")
@app.route("/api/platform/execution-assurance/demo")
def api_platform_enterprise_execution_assurance_demo():
    from flask import jsonify
    return jsonify({json.dumps(patch_model, indent=8, ensure_ascii=False)})
{ROUTE_MARKER_END}
'''

    pattern = re.escape(ROUTE_MARKER_START) + r".*?" + re.escape(ROUTE_MARKER_END)
    text = re.sub(pattern, "", text, flags=re.DOTALL)

    if 'if __name__ == "__main__"' in text:
        text = text.replace('if __name__ == "__main__"', route_block + '\n\nif __name__ == "__main__"', 1)
    elif "if __name__ == '__main__'" in text:
        text = text.replace("if __name__ == '__main__'", route_block + "\n\nif __name__ == '__main__'", 1)
    else:
        text = text.rstrip() + "\n\n" + route_block + "\n"

    path.write_text(text, encoding="utf-8")
    print("PATCHED: app.py routes")

patch_blueprint_seed()
patch_lifecycle_seed()
create_capability_page()
patch_app_routes()

patch_html(
    "platform_ai_enabled_cmc_blueprint.html",
    capability_html,
    "<div class=\"footer\">"
)

patch_html(
    "platform_agentic_enterprise_blueprint.html",
    capability_html,
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

Path("enterprise_execution_assurance_capability_patch_v1_summary.json").write_text(
    json.dumps(patch_model, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("enterprise_execution_assurance_capability_patch_v1_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform",
        "http://127.0.0.1:5000/platform/routes",
        "http://127.0.0.1:5000/platform/enterprise-execution-assurance",
        "http://127.0.0.1:5000/platform/execution-assurance",
        "http://127.0.0.1:5000/platform/blueprints",
        "http://127.0.0.1:5000/platform/blueprints/ai-enabled-cmc",
        "http://127.0.0.1:5000/platform/blueprints/agentic-enterprise",
        "http://127.0.0.1:5000/platform/lifecycle-integration",
        "http://127.0.0.1:5000/api/platform/enterprise-execution-assurance/demo",
        "http://127.0.0.1:5000/api/platform/execution-assurance/demo",
        "http://127.0.0.1:5000/api/platform/blueprints/model/demo",
        "http://127.0.0.1:5000/api/platform/blueprints/ai-enabled-cmc/demo",
        "http://127.0.0.1:5000/api/platform/blueprints/agentic-enterprise/demo",
        "http://127.0.0.1:5000/api/platform/lifecycle-integration/model/demo"
    ]),
    encoding="utf-8"
)

print("")
print("Enterprise Execution Assurance Capability Patch completed.")
print("Marker:")
print("  " + PATCH_MARKER)
print("Updated lifecycle:")
print("  " + patch_model["updated_lifecycle_sequence"])
print("No platform redesign.")

