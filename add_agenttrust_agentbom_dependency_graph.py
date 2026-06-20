from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_AGENTBOM_DEPENDENCY_GRAPH_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust AgentBOM Dependency Graph already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base module not found. Install AgentTrust module first.")

nav_old = '<a href="/agenttrust/human-oversight-workbench" class="secondary">Human Oversight</a>'
nav_new = '''<a href="/agenttrust/human-oversight-workbench" class="secondary">Human Oversight</a>
                    <a href="/agenttrust/agent-bom" class="secondary">AgentBOM</a>
                    <a href="/agenttrust/dependency-graph" class="dark">Dependency Graph</a>
                    <a href="/agenttrust/model-prompt-tool-map" class="dark">Model/Prompt/Tool</a>
                    <a href="/agenttrust/agent-supply-chain-risk" class="dark">Supply Chain Risk</a>'''

if nav_old in text and "/agenttrust/agent-bom" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# AGENTTRUST_AGENTBOM_DEPENDENCY_GRAPH_V1_ACTIVE
# AgentTrust™ AgentBOM, AI Agent Bill of Materials,
# Dependency Graph, Model-Prompt-Tool Map, Data Lineage Map,
# Downstream Workflow Map, Supply Chain Risk Register,
# Dependency Drift Watch, and AgentBOM JSON Export
# ============================================================

AGENTTRUST_AGENTBOM_COMPONENTS = [
    {
        "layer": "Agent Identity",
        "component": "ServiceNow CMDB Ownership Recommendation Agent™",
        "purpose": "Reviews CI candidates, orphan CIs, ownership gaps, support group gaps, and lifecycle readiness.",
        "risk": "Medium",
        "owner": "CMDB / Service Governance Owner",
        "control": "Registered agent record and Agent Risk Passport™ required."
    },
    {
        "layer": "Model Layer",
        "component": "Approved enterprise AI model or hosted model endpoint",
        "purpose": "Generates summaries, recommendations, and structured output.",
        "risk": "High Control",
        "owner": "AI Platform Owner",
        "control": "Model version, provider, configuration, and change gate required."
    },
    {
        "layer": "Prompt Layer",
        "component": "Governed system prompt and task instruction set",
        "purpose": "Constrains agent behavior, decision style, prohibited actions, and output format.",
        "risk": "High",
        "owner": "Agent Lifecycle Owner",
        "control": "Prompt change gate and prompt evidence required."
    },
    {
        "layer": "Tool Layer",
        "component": "ServiceNow read query, CI candidate review, evidence builder",
        "purpose": "Allows agent to read records, prepare recommendations, and generate evidence package.",
        "risk": "High",
        "owner": "ServiceNow Platform Owner",
        "control": "Tool authority, access boundary, and tool-call evidence required."
    },
    {
        "layer": "Data Source Layer",
        "component": "CMDB records, CI ownership fields, support group fields, LCM fields",
        "purpose": "Provides source information for recommendations.",
        "risk": "Medium / High",
        "owner": "CMDB Owner",
        "control": "Source lineage and data quality review required."
    },
    {
        "layer": "Access Layer",
        "component": "MyAccess groups, CyberArk / PSM context where applicable",
        "purpose": "Identifies whether access or privileged execution is involved.",
        "risk": "Critical",
        "owner": "Access / Cybersecurity Owner",
        "control": "No autonomous access approval. Cyber review required."
    },
    {
        "layer": "Workflow Layer",
        "component": "ServiceNow task, change, candidate review, ownership reconciliation workflow",
        "purpose": "Routes AI recommendations into human-governed operational workflows.",
        "risk": "High",
        "owner": "Workflow Owner",
        "control": "Human gate, change link, rollback path, and evidence capture required."
    },
    {
        "layer": "Evidence Layer",
        "component": "Tool-call evidence, source record, reviewer decision, outcome record",
        "purpose": "Preserves audit replay and decision defensibility.",
        "risk": "High Control",
        "owner": "Audit / Governance Owner",
        "control": "Evidence must be captured at the time of action."
    },
    {
        "layer": "Runtime Control Layer",
        "component": "Execution firewall, runtime sentinel, drift sentinel, kill switch, quarantine",
        "purpose": "Controls unsafe, unauthorized, or drifting AI agent behavior.",
        "risk": "Critical",
        "owner": "Platform / Risk Owner",
        "control": "Runtime controls required for operational or high-impact agents."
    }
]


AGENTTRUST_DEPENDENCY_EDGES = [
    ("Agent Identity", "Model Layer", "Agent uses model endpoint."),
    ("Agent Identity", "Prompt Layer", "Agent behavior constrained by prompt."),
    ("Agent Identity", "Tool Layer", "Agent calls approved tools."),
    ("Tool Layer", "Data Source Layer", "Tools retrieve source records."),
    ("Tool Layer", "Workflow Layer", "Tools may prepare task or workflow action."),
    ("Data Source Layer", "Evidence Layer", "Source lineage feeds evidence package."),
    ("Workflow Layer", "Human Oversight", "Human reviewer approves, rejects, or escalates."),
    ("Access Layer", "Cybersecurity Review", "Access or privileged impact escalates to cyber owner."),
    ("Runtime Control Layer", "Execution Firewall", "Controls whether action can continue."),
    ("Evidence Layer", "Decision Replay", "Evidence supports replay and audit defense.")
]


def agenttrust_agentbom_rows():
    rows = ""

    for item in AGENTTRUST_AGENTBOM_COMPONENTS:
        badge = "blue"
        if item["risk"] in ["Critical"]:
            badge = "red"
        elif item["risk"] in ["High", "High Control"]:
            badge = "orange"
        elif item["risk"] == "Medium / High":
            badge = "yellow"

        rows += f"""
        <tr>
            <td><span class="badge blue">{item["layer"]}</span></td>
            <td><strong>{item["component"]}</strong></td>
            <td>{item["purpose"]}</td>
            <td><span class="badge {badge}">{item["risk"]}</span></td>
            <td>{item["owner"]}</td>
            <td>{item["control"]}</td>
        </tr>
        """

    return rows


def agenttrust_dependency_rows():
    rows = ""

    for source, target, relationship in AGENTTRUST_DEPENDENCY_EDGES:
        rows += f"""
        <tr>
            <td><strong>{source}</strong></td>
            <td>→</td>
            <td><strong>{target}</strong></td>
            <td>{relationship}</td>
        </tr>
        """

    return rows


try:
    AGENTTRUST_EXPECTED_ROUTES.extend([
        "/agenttrust/agent-bom",
        "/agenttrust/dependency-graph",
        "/agenttrust/model-prompt-tool-map",
        "/agenttrust/data-lineage-map",
        "/agenttrust/downstream-workflow-map",
        "/agenttrust/agent-supply-chain-risk",
        "/agenttrust/dependency-drift-watch",
        "/agenttrust/agentbom-json"
    ])
except Exception:
    pass


@app.route("/agenttrust/agent-bom")
@app.route("/agenttrust/agent-bill-of-materials")
@app.route("/agenttrust/ai-agent-bom")
def agenttrust_agent_bom():
    rows = agenttrust_agentbom_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">AgentBOM</div><div class="value" style="color:var(--green);">Defined</div><div class="note">AI agent bill of materials created.</div></div>
        <div class="metric"><div class="label">Model</div><div class="value" style="color:var(--orange);">Controlled</div><div class="note">Model version and provider must be governed.</div></div>
        <div class="metric"><div class="label">Prompt</div><div class="value" style="color:var(--yellow);">Change-Gated</div><div class="note">Prompt changes can alter agent behavior.</div></div>
        <div class="metric"><div class="label">Tools</div><div class="value" style="color:var(--red);">Authority-Gated</div><div class="note">Tool calls require authority and evidence.</div></div>
        <div class="metric"><div class="label">Data</div><div class="value" style="color:var(--blue);">Lineage</div><div class="note">Source records must remain traceable.</div></div>
        <div class="metric"><div class="label">Runtime</div><div class="value" style="color:var(--purple);">Firewalled</div><div class="note">Unsafe dependencies can trigger quarantine.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ AgentBOM — AI Agent Bill of Materials</h2>
        <div class="answer">
            <strong>Purpose:</strong> make every dependency behind an AI agent visible, owned, governed, and evidence-backed.
            AgentBOM shows the model, prompt, tools, APIs, data sources, ServiceNow records, CMDB relationships,
            access routes, owners, runtime controls, workflows, and evidence stores that an AI agent depends on.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Layer</th>
                    <th>Component</th>
                    <th>Purpose</th>
                    <th>Risk</th>
                    <th>Owner</th>
                    <th>Required Control</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>AgentBOM Rule</h2>
        <div class="answer">
            An AI agent cannot be operationally trusted if its dependencies are unknown.
            AgentTrust™ requires every model, prompt, tool, API, data source, workflow, owner, and evidence store to be visible.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ AgentBOM",
        "AI Agent Bill of Materials for model, prompt, tools, APIs, data sources, ServiceNow records, access routes, owners, runtime controls, workflows, and evidence.",
        body
    )


@app.route("/agenttrust/dependency-graph")
@app.route("/agenttrust/agent-dependency-graph")
@app.route("/agenttrust/ai-agent-dependency-graph")
def agenttrust_dependency_graph():
    rows = agenttrust_dependency_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Dependency Graph</h2>
        <p>
            The dependency graph shows how AI agent components connect.
            It helps identify where operational trust can break when one dependency changes, fails, or becomes unauthorized.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Source Layer</th>
                    <th></th>
                    <th>Target Layer</th>
                    <th>Dependency Relationship</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Dependency Chain</h2>
        <div class="answer">
            Agent Identity → Model → Prompt → Tool → Data Source → Workflow → Human Review → Evidence Package → Audit Replay.
            If any link is unknown, unauthorized, stale, or unevidenced, trust decreases.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Dependency Graph",
        "Dependency graph for AI agent identity, model, prompt, tools, data sources, workflows, access routes, human review, evidence, and replay.",
        body
    )


@app.route("/agenttrust/model-prompt-tool-map")
@app.route("/agenttrust/model-tool-map")
@app.route("/agenttrust/prompt-tool-map")
def agenttrust_model_prompt_tool_map():
    body = """
    <section class="section">
        <h2>AgentTrust™ Model / Prompt / Tool Map</h2>
        <p>
            This map separates the three layers that most often change AI agent behavior:
            model, prompt, and tools. Each layer requires its own governance control.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Layer</th>
                    <th>What It Controls</th>
                    <th>Change Risk</th>
                    <th>Required AgentTrust™ Control</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Model</td><td>Reasoning capability, output behavior, provider endpoint, configuration.</td><td>Different model may behave differently under same prompt.</td><td><span class="badge orange">Model change gate</span></td></tr>
                <tr><td>System Prompt</td><td>Agent role, boundaries, prohibited actions, output discipline.</td><td>Prompt drift can silently change decision behavior.</td><td><span class="badge red">Prompt change gate</span></td></tr>
                <tr><td>Task Prompt</td><td>Specific action request and context.</td><td>Poor prompt may create misleading output.</td><td><span class="badge yellow">Input evidence capture</span></td></tr>
                <tr><td>Tool</td><td>What systems the agent can query, update, trigger, or call.</td><td>Tool expansion can increase operational risk.</td><td><span class="badge red">Tool authority gate</span></td></tr>
                <tr><td>API</td><td>External or internal system interaction.</td><td>API write or trigger access can create real-world impact.</td><td><span class="badge red">Tool-call evidence</span></td></tr>
                <tr><td>Retrieval Source</td><td>Records used to ground the agent response.</td><td>Bad or stale source creates bad recommendation.</td><td><span class="badge orange">Source lineage check</span></td></tr>
                <tr><td>Output Parser</td><td>Converts model output into structured workflow action.</td><td>Parser can convert text into action.</td><td><span class="badge red">Execution firewall</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Model / Prompt / Tool Rule</h2>
        <div class="answer">
            AgentTrust™ treats model changes, prompt changes, and tool changes as material governance events.
            A safe agent can become unsafe if any of these layers change without review.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Model Prompt Tool Map",
        "Governance map for AI agent model, system prompt, task prompt, tools, APIs, retrieval sources, and output parsers.",
        body
    )


@app.route("/agenttrust/data-lineage-map")
@app.route("/agenttrust/agent-data-lineage")
@app.route("/agenttrust/source-data-lineage")
def agenttrust_data_lineage_map():
    body = """
    <section class="section">
        <h2>AgentTrust™ Data Lineage Map</h2>
        <p>
            The Data Lineage Map shows where agent input comes from, how it is used, and whether it can be defended later.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Data Layer</th>
                    <th>Example Source</th>
                    <th>Lineage Evidence Required</th>
                    <th>Risk If Missing</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Source Record</td><td>ServiceNow CI record, change record, access request.</td><td>Record ID, timestamp, source system.</td><td><span class="badge red">Untraceable output</span></td></tr>
                <tr><td>Context Data</td><td>Owner, support group, LCM, lifecycle state, validation status.</td><td>Field values and retrieval time.</td><td><span class="badge orange">Stale or wrong recommendation</span></td></tr>
                <tr><td>Evidence Data</td><td>Tool-call log, reviewer decision, workflow outcome.</td><td>Evidence ID and storage location.</td><td><span class="badge red">Weak audit replay</span></td></tr>
                <tr><td>Access Data</td><td>MyAccess group, entitlement route, CyberArk / PSM context.</td><td>Access source and approver route.</td><td><span class="badge red">Privileged access ambiguity</span></td></tr>
                <tr><td>Regulated Data</td><td>GMP, QA, validation, QC, release, inspection evidence.</td><td>QA owner, validation owner, source record.</td><td><span class="badge red">Inspection defensibility risk</span></td></tr>
                <tr><td>Derived Output</td><td>Summary, recommendation, readiness score, risk flag.</td><td>Input-to-output trace.</td><td><span class="badge orange">Cannot explain conclusion</span></td></tr>
                <tr><td>Final Outcome</td><td>Executed, blocked, escalated, accepted, rejected, quarantined.</td><td>Decision owner and outcome timestamp.</td><td><span class="badge orange">Incomplete action loop</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Data Lineage Rule</h2>
        <div class="answer">
            AgentTrust™ does not treat AI output as evidence by itself.
            The evidence is the full input-to-output-to-human-decision-to-outcome chain.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Data Lineage Map",
        "Data lineage map for AI agent source records, context data, evidence data, access data, regulated data, derived output, and final outcome.",
        body
    )


@app.route("/agenttrust/downstream-workflow-map")
@app.route("/agenttrust/agent-workflow-map")
@app.route("/agenttrust/workflow-impact-map")
def agenttrust_downstream_workflow_map():
    body = """
    <section class="section">
        <h2>AgentTrust™ Downstream Workflow Map</h2>
        <p>
            This map identifies what can happen after an AI agent generates output.
            Downstream workflow risk often matters more than the original AI response.
        </p>

        <table>
            <thead>
                <tr>
                    <th>AI Output</th>
                    <th>Downstream Workflow</th>
                    <th>Risk</th>
                    <th>Required Control</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>CI ownership recommendation.</td><td>ServiceNow CI update request.</td><td>Wrong owner or support group.</td><td><span class="badge yellow">LCM review</span></td></tr>
                <tr><td>Cutover readiness summary.</td><td>Transition go-live discussion.</td><td>AI summary influences readiness decision.</td><td><span class="badge red">Human cutover approval</span></td></tr>
                <tr><td>Access route suggestion.</td><td>MyAccess request creation.</td><td>Incorrect entitlement routing.</td><td><span class="badge red">Access owner review</span></td></tr>
                <tr><td>Privileged route suggestion.</td><td>CyberArk / PSM workflow.</td><td>Privileged execution risk.</td><td><span class="badge red">Cybersecurity review</span></td></tr>
                <tr><td>Validation evidence summary.</td><td>QA or validation decision support.</td><td>Regulated conclusion risk.</td><td><span class="badge red">QA / validation review</span></td></tr>
                <tr><td>Risk score.</td><td>Leadership dashboard or board report.</td><td>Leadership may rely on incomplete score.</td><td><span class="badge orange">Evidence sufficiency check</span></td></tr>
                <tr><td>Workflow trigger command.</td><td>Automated task, update, or system action.</td><td>Operational execution.</td><td><span class="badge red">Execution firewall</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Workflow Map Rule</h2>
        <div class="answer">
            AgentTrust™ evaluates not only the AI output, but what the enterprise workflow does with that output.
            A harmless summary can become high-risk when it triggers action.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Downstream Workflow Map",
        "Workflow impact map showing how AI outputs can affect ServiceNow updates, cutover decisions, access requests, CyberArk workflows, validation evidence, leadership reports, and automation triggers.",
        body
    )


@app.route("/agenttrust/agent-supply-chain-risk")
@app.route("/agenttrust/ai-supply-chain-risk")
@app.route("/agenttrust/agentbom-risk-register")
def agenttrust_agent_supply_chain_risk():
    body = """
    <section class="section">
        <h2>AgentTrust™ Agent Supply Chain Risk Register</h2>
        <p>
            AI agents have a supply chain: model, prompt, tools, APIs, data, owners, workflows, and evidence stores.
            Each dependency can introduce risk.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Supply Chain Risk</th>
                    <th>Risk Signal</th>
                    <th>Impact</th>
                    <th>AgentTrust™ Control</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Unknown model version.</td><td>Model endpoint changes without review.</td><td>Behavior drift.</td><td><span class="badge orange">Model change gate</span></td></tr>
                <tr><td>Prompt drift.</td><td>System instruction changes without evidence.</td><td>Boundary or prohibited action changes.</td><td><span class="badge red">Prompt change control</span></td></tr>
                <tr><td>Tool expansion.</td><td>Agent receives new API or write capability.</td><td>Execution risk increases.</td><td><span class="badge red">Tool authority gate</span></td></tr>
                <tr><td>Data source weakness.</td><td>Agent uses stale, incomplete, or ownerless records.</td><td>Incorrect recommendation.</td><td><span class="badge orange">Source lineage review</span></td></tr>
                <tr><td>Access dependency risk.</td><td>Agent influences entitlement or privileged workflow.</td><td>Cybersecurity risk.</td><td><span class="badge red">Cyber review</span></td></tr>
                <tr><td>Regulated evidence dependency.</td><td>Agent uses GMP, QA, validation, QC, release, or inspection evidence.</td><td>Inspection or quality risk.</td><td><span class="badge red">QA / validation review</span></td></tr>
                <tr><td>Owner dependency risk.</td><td>Business, technical, risk, QA, or cyber owner missing.</td><td>Accountability failure.</td><td><span class="badge red">Owner assignment</span></td></tr>
                <tr><td>Evidence store risk.</td><td>Evidence logs are missing, mutable, incomplete, or inaccessible.</td><td>Audit replay failure.</td><td><span class="badge red">Evidence vault control</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Supply Chain Risk Rule</h2>
        <div class="answer">
            AI agent risk does not sit only inside the model.
            It also sits in prompts, tools, APIs, data, owners, workflows, evidence stores, and downstream decisions.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Agent Supply Chain Risk",
        "Supply chain risk register for AI agent model, prompt, tools, APIs, data sources, access dependencies, regulated evidence, owners, and evidence stores.",
        body
    )


@app.route("/agenttrust/dependency-drift-watch")
@app.route("/agenttrust/agent-dependency-drift")
@app.route("/agenttrust/agentbom-drift-watch")
def agenttrust_dependency_drift_watch():
    body = """
    <section class="section">
        <h2>AgentTrust™ Dependency Drift Watch</h2>
        <p>
            Dependency drift occurs when an AI agent dependency changes after approval.
            Trust must be recalculated when dependencies change.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Drift Type</th>
                    <th>Trigger</th>
                    <th>Risk Created</th>
                    <th>Required AgentTrust™ Action</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Model Drift</td><td>Model version, endpoint, provider, or configuration changes.</td><td>Output behavior may change.</td><td><span class="badge orange">Run model change gate</span></td></tr>
                <tr><td>Prompt Drift</td><td>System prompt, task instruction, or prohibited action text changes.</td><td>Agent boundary changes silently.</td><td><span class="badge red">Run prompt change gate</span></td></tr>
                <tr><td>Tool Drift</td><td>New tool, API, workflow, write access, or trigger is added.</td><td>Action capability increases.</td><td><span class="badge red">Run tool authority gate</span></td></tr>
                <tr><td>Data Drift</td><td>Source record quality, owner, schema, or field meaning changes.</td><td>Recommendations become unreliable.</td><td><span class="badge orange">Run data lineage review</span></td></tr>
                <tr><td>Access Drift</td><td>MyAccess group, CyberArk route, PSM rule, or entitlement changes.</td><td>Access governance gap.</td><td><span class="badge red">Cyber review</span></td></tr>
                <tr><td>Workflow Drift</td><td>Downstream task, change, approval, or update workflow changes.</td><td>AI output may trigger new operational behavior.</td><td><span class="badge orange">Run workflow impact review</span></td></tr>
                <tr><td>Owner Drift</td><td>Business, technical, QA, cyber, risk, or LCM owner changes.</td><td>Accountability may break.</td><td><span class="badge red">Reconfirm owner</span></td></tr>
                <tr><td>Evidence Drift</td><td>Evidence storage, logging, retention, or replay path changes.</td><td>Audit defensibility weakens.</td><td><span class="badge red">Run evidence sufficiency review</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Dependency Drift Rule</h2>
        <div class="answer">
            AgentTrust™ trust scores are not permanent.
            When dependencies drift, the agent must be re-scored, re-gated, or restricted.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Dependency Drift Watch",
        "Dependency drift watch for AI agent model, prompt, tool, data, access, workflow, owner, and evidence changes.",
        body
    )


@app.route("/agenttrust/agentbom-json")
@app.route("/agenttrust/agent-bom-json")
@app.route("/agenttrust/dependency-graph-json")
def agenttrust_agentbom_json():
    from flask import jsonify

    return jsonify({
        "module": "AgentTrust™",
        "capability": "AgentBOM + Dependency Graph",
        "primary_question": "Are this AI agent's dependencies known, owned, governed, and evidence-backed?",
        "agentbom_components": AGENTTRUST_AGENTBOM_COMPONENTS,
        "dependency_edges": [
            {
                "source": source,
                "target": target,
                "relationship": relationship
            }
            for source, target, relationship in AGENTTRUST_DEPENDENCY_EDGES
        ],
        "required_controls": [
            "Agent identity and owner must be registered",
            "Model version and provider must be known",
            "Prompt must be change-gated",
            "Tools and APIs must have authority controls",
            "Data sources must have lineage evidence",
            "Access and privileged dependencies must route to cybersecurity",
            "Regulated dependencies must route to QA / validation",
            "Downstream workflows must be mapped",
            "Runtime controls must be active for high-impact actions",
            "Evidence stores must support audit replay"
        ],
        "default_decision": "Restrict or human-gate if any critical dependency is unknown, ownerless, unauthorized, stale, or unevidenced"
    })

# ============================================================
# END AGENTTRUST_AGENTBOM_DEPENDENCY_GRAPH_V1_ACTIVE
# ============================================================

'''

targets = [
    'if __name__ == "__main__":',
    "if __name__ == '__main__':"
]

idx = -1
target_found = None

for target in targets:
    current_idx = text.rfind(target)
    if current_idx > idx:
        idx = current_idx
        target_found = target

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("AgentTrust AgentBOM Dependency Graph installed.")
print(f"Inserted before: {target_found}")
