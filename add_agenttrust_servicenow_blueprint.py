from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_SERVICENOW_INTEGRATION_BLUEPRINT_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust ServiceNow Integration Blueprint already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base module not found. Install AgentTrust module first.")

nav_old = '<a href="/agenttrust/metrics-engine" class="secondary">Metrics Engine</a>'
nav_new = '''<a href="/agenttrust/metrics-engine" class="secondary">Metrics Engine</a>
                    <a href="/agenttrust/servicenow-integration-blueprint" class="secondary">ServiceNow Blueprint</a>
                    <a href="/agenttrust/cmdb-csdm-mapping" class="dark">CMDB / CSDM</a>
                    <a href="/agenttrust/agent-ci-relationship-model" class="dark">Agent-CI Model</a>
                    <a href="/agenttrust/myaccess-cyberark-agent-routing" class="dark">Access Routing</a>'''

if nav_old in text and "/agenttrust/servicenow-integration-blueprint" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# AGENTTRUST_SERVICENOW_INTEGRATION_BLUEPRINT_V1_ACTIVE
# AgentTrust™ ServiceNow Integration Blueprint, CMDB / CSDM Mapping,
# Agent-CI Relationship Model, MyAccess / CyberArk Agent Routing,
# Change Control Bridge, LCM Ownership Bridge, and Evidence Sync Model
# ============================================================

AGENTTRUST_SERVICENOW_FIELDS = [
    ("Agent ID", "Unique identifier for the AI agent.", "AgentTrust™ Register"),
    ("Agent Name", "Business-readable name of the AI agent.", "AgentTrust™ Register"),
    ("Agent Owner", "Human accountable business owner.", "ServiceNow owner / business owner alignment"),
    ("Technical Owner", "Technical support and lifecycle owner.", "Support group / assignment group"),
    ("Linked Business Application", "Business Application the agent supports or influences.", "CMDB / CSDM"),
    ("Linked Application Service", "Application Service or mapped service touched by the agent.", "CMDB / CSDM"),
    ("Linked Infrastructure CI", "Server, VM, database, endpoint, integration, or platform component touched by the agent.", "CMDB"),
    ("Support Group", "Group responsible for support and operational accountability.", "ServiceNow assignment/support group"),
    ("LCM Owner", "Lifecycle owner responsible for CI or agent lifecycle alignment.", "ServiceNow LCM"),
    ("MyAccess Group", "Entitlement or approval group linked to AI agent use.", "MyAccess"),
    ("CyberArk Scope", "Privileged access impact or PSM-related route.", "CyberArk / privileged access"),
    ("Change Control Link", "Change record or workflow governing agent release or modification.", "ServiceNow Change"),
    ("Tool-Call Evidence", "API, workflow trigger, data access, and execution evidence.", "Evidence Ledger"),
    ("Risk Tier", "Agent operational risk tier.", "AgentTrust™ Risk Tiering"),
    ("Trust Score", "Operational trust score for AI agent readiness.", "AgentTrust™ Metrics Engine")
]


def agenttrust_servicenow_field_rows():
    rows = ""

    for field, purpose, source in AGENTTRUST_SERVICENOW_FIELDS:
        rows += f"""
        <tr>
            <td><strong>{field}</strong></td>
            <td>{purpose}</td>
            <td><span class="badge blue">{source}</span></td>
        </tr>
        """

    return rows


@app.route("/agenttrust/servicenow-integration-blueprint")
@app.route("/agenttrust/servicenow-blueprint")
@app.route("/agenttrust/servicenow-agent-blueprint")
def agenttrust_servicenow_integration_blueprint():
    rows = agenttrust_servicenow_field_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">CMDB Linkage</div><div class="value" style="color:var(--green);">Mapped</div><div class="note">AI agents linked to business apps, app services, and infrastructure CIs.</div></div>
        <div class="metric"><div class="label">CSDM Alignment</div><div class="value" style="color:var(--blue);">Ready</div><div class="note">Agent impact mapped through service relationships.</div></div>
        <div class="metric"><div class="label">Ownership</div><div class="value" style="color:var(--orange);">Required</div><div class="note">Business owner, technical owner, LCM, and support group required.</div></div>
        <div class="metric"><div class="label">Access Routing</div><div class="value" style="color:var(--red);">Controlled</div><div class="note">MyAccess and CyberArk impact must be known.</div></div>
        <div class="metric"><div class="label">Change Control</div><div class="value" style="color:var(--yellow);">Linked</div><div class="note">Agent release and change routed through change governance.</div></div>
        <div class="metric"><div class="label">Evidence Sync</div><div class="value" style="color:var(--purple);">Traceable</div><div class="note">Tool-call evidence links to agent, CI, owner, and workflow.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ ServiceNow Integration Blueprint</h2>
        <div class="answer">
            <strong>Purpose:</strong> connect AI agents to ServiceNow governance so they are not floating outside CMDB,
            CSDM, ownership, support group, LCM, MyAccess, CyberArk, change control, and evidence lineage.
        </div>

        <table>
            <thead>
                <tr>
                    <th>AgentTrust™ Field</th>
                    <th>Governance Purpose</th>
                    <th>ServiceNow / Governance Source</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Integration Principle</h2>
        <div class="answer">
            If an AI agent can touch, recommend, update, trigger, or influence an enterprise workflow,
            it should be linked to the same governance backbone as the systems it affects: CI, owner, support group,
            lifecycle owner, access route, change route, evidence route, and risk tier.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ ServiceNow Integration Blueprint",
        "Blueprint for linking AI agents to ServiceNow CMDB, CSDM, ownership, support groups, LCM, MyAccess, CyberArk, change control, and evidence.",
        body
    )


@app.route("/agenttrust/cmdb-csdm-mapping")
@app.route("/agenttrust/agent-cmdb-mapping")
@app.route("/agenttrust/csdm-agent-mapping")
def agenttrust_cmdb_csdm_mapping():
    body = """
    <section class="section">
        <h2>AgentTrust™ CMDB / CSDM Mapping</h2>
        <p>
            This page defines how AI agents should be mapped to CMDB and CSDM structures.
            The goal is to connect agent behavior to business service impact, application ownership, infrastructure dependency, and operational accountability.
        </p>

        <table>
            <thead>
                <tr>
                    <th>ServiceNow Layer</th>
                    <th>AgentTrust™ Link</th>
                    <th>Governance Question</th>
                    <th>Required Evidence</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Business Capability</td><td>Agent business purpose.</td><td>What business capability does this AI agent support?</td><td>Agent purpose and business owner.</td></tr>
                <tr><td>Business Application</td><td>Application the agent supports or influences.</td><td>Which business application can this agent affect?</td><td>Linked Business Application CI.</td></tr>
                <tr><td>Application Service</td><td>Mapped operational service touched by the agent.</td><td>Which operational service may be impacted?</td><td>Linked Application Service record.</td></tr>
                <tr><td>Infrastructure CI</td><td>Server, database, endpoint, integration, or platform touched by the agent.</td><td>Which technical components are exposed?</td><td>Linked infrastructure CI and relationship evidence.</td></tr>
                <tr><td>Support Group</td><td>Group accountable for operation and support.</td><td>Who supports the agent or the affected service?</td><td>Assignment group / support group.</td></tr>
                <tr><td>LCM</td><td>Lifecycle owner for linked CI or agent lifecycle control.</td><td>Who governs lifecycle decisions?</td><td>LCM owner and review cadence.</td></tr>
                <tr><td>Service Offering</td><td>Business-facing service potentially influenced by the agent.</td><td>What service outcome could be impacted?</td><td>Service mapping and owner confirmation.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Mapping Rule</h2>
        <div class="answer">
            An AI agent should be treated as a governed operational actor connected to the CMDB relationships of the systems,
            services, workflows, and owners it can influence.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ CMDB / CSDM Mapping",
        "Mapping model for connecting AI agents to Business Applications, Application Services, infrastructure CIs, support groups, LCM, and service impact.",
        body
    )


@app.route("/agenttrust/agent-ci-relationship-model")
@app.route("/agenttrust/ai-agent-ci-relationship")
@app.route("/agenttrust/agent-ci-model")
def agenttrust_agent_ci_relationship_model():
    body = """
    <section class="section">
        <h2>AgentTrust™ Agent-CI Relationship Model</h2>
        <p>
            This model defines the relationship types between AI agents and Configuration Items.
            It helps answer whether the agent only observes a CI, recommends actions, triggers workflows, updates records, or influences regulated operations.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Relationship Type</th>
                    <th>Description</th>
                    <th>Example</th>
                    <th>Required Control</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Observes CI</td><td>Agent reads CI data but does not recommend or act.</td><td>Reads CI lifecycle status.</td><td><span class="badge green">Data access log</span></td></tr>
                <tr><td>Summarizes CI</td><td>Agent summarizes CI risk, ownership, support group, or mapping gaps.</td><td>Summarizes orphan CI list.</td><td><span class="badge green">Source traceability</span></td></tr>
                <tr><td>Recommends CI Action</td><td>Agent recommends owner, LCM, support group, service mapping, or readiness state.</td><td>Suggests support group for an application.</td><td><span class="badge yellow">Human review</span></td></tr>
                <tr><td>Creates CI Candidate</td><td>Agent creates a draft candidate for CI review.</td><td>Creates AI-proposed CI candidate.</td><td><span class="badge orange">Workflow authority</span></td></tr>
                <tr><td>Updates CI Record</td><td>Agent updates CI field, owner, status, or relationship.</td><td>Updates lifecycle or assignment group.</td><td><span class="badge red">Approval and rollback</span></td></tr>
                <tr><td>Triggers CI Workflow</td><td>Agent initiates change, review, remediation, or access workflow.</td><td>Triggers CI ownership reconciliation task.</td><td><span class="badge red">Authority gate</span></td></tr>
                <tr><td>Influences Regulated CI</td><td>Agent affects CI linked to GxP, QA, validation, release, inspection, or GMP operation.</td><td>Summarizes validation readiness for regulated system.</td><td><span class="badge red">QA / validation review</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Relationship Rule</h2>
        <div class="answer">
            The same AI agent becomes more risky as it moves from observing a CI to recommending, creating,
            updating, triggering, or influencing regulated CI decisions.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Agent-CI Relationship Model",
        "Relationship model for AI agents that observe, summarize, recommend, create, update, trigger, or influence Configuration Items.",
        body
    )


@app.route("/agenttrust/myaccess-cyberark-agent-routing")
@app.route("/agenttrust/access-agent-routing")
@app.route("/agenttrust/cyberark-agent-routing")
def agenttrust_myaccess_cyberark_agent_routing():
    body = """
    <section class="section">
        <h2>AgentTrust™ MyAccess / CyberArk Agent Routing</h2>
        <p>
            This page defines how AI agents should be routed when they influence access, entitlement, privileged execution,
            CyberArk, PSM, admin activity, or approval workflows.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Agent Access Scenario</th>
                    <th>Risk</th>
                    <th>Required Owner</th>
                    <th>AgentTrust™ Rule</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent recommends access group.</td><td>Wrong entitlement could be suggested.</td><td>Access owner / process owner.</td><td><span class="badge yellow">Human review required</span></td></tr>
                <tr><td>Agent drafts MyAccess request text.</td><td>Request may be incomplete or misleading.</td><td>Requester / access approver.</td><td><span class="badge yellow">Human approval required</span></td></tr>
                <tr><td>Agent triggers access request workflow.</td><td>Could initiate unauthorized access path.</td><td>Access governance owner.</td><td><span class="badge orange">Restricted execution</span></td></tr>
                <tr><td>Agent approves access.</td><td>AI becomes hidden access approver.</td><td>Access owner.</td><td><span class="badge red">Prohibited by default</span></td></tr>
                <tr><td>Agent influences CyberArk / PSM route.</td><td>Privileged execution risk.</td><td>Cybersecurity / CyberArk owner.</td><td><span class="badge red">Cyber review required</span></td></tr>
                <tr><td>Agent triggers privileged workflow.</td><td>Could enable admin action.</td><td>Cybersecurity owner.</td><td><span class="badge red">Block unless explicitly approved</span></td></tr>
                <tr><td>Agent uses privileged account context.</td><td>Credential misuse or audit ambiguity.</td><td>CyberArk owner / platform owner.</td><td><span class="badge red">Strong evidence and approval required</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Access Routing Principle</h2>
        <div class="answer">
            AI agents may help prepare, summarize, or recommend access actions, but access approval and privileged execution
            must remain human-governed, evidenced, and cybersecurity-reviewed.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ MyAccess / CyberArk Agent Routing",
        "Access governance routing model for AI agents that influence MyAccess, CyberArk, PSM, privileged execution, and entitlement workflows.",
        body
    )


@app.route("/agenttrust/change-control-bridge")
@app.route("/agenttrust/agent-change-bridge")
@app.route("/agenttrust/servicenow-change-bridge")
def agenttrust_change_control_bridge():
    body = """
    <section class="section">
        <h2>AgentTrust™ ServiceNow Change Control Bridge</h2>
        <p>
            This bridge connects AI agent deployment and modification to ServiceNow-style change governance.
            It prevents material AI agent changes from bypassing change control.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Agent Change Event</th>
                    <th>Change Control Trigger</th>
                    <th>Required Evidence</th>
                    <th>Decision Rule</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>New AI agent introduced.</td><td>New service or workflow capability.</td><td>Agent passport, owner, risk tier, support model.</td><td><span class="badge yellow">Change review required</span></td></tr>
                <tr><td>Agent connected to ServiceNow workflow.</td><td>New workflow integration.</td><td>Workflow boundary, tool-call evidence rule, rollback plan.</td><td><span class="badge orange">Impact review</span></td></tr>
                <tr><td>Agent given record update ability.</td><td>Operational write capability.</td><td>Authority gate, approval, audit log, rollback.</td><td><span class="badge red">Full change gate</span></td></tr>
                <tr><td>Agent given access workflow influence.</td><td>Access governance impact.</td><td>MyAccess owner, CyberArk review, approval route.</td><td><span class="badge red">Cyber review required</span></td></tr>
                <tr><td>Agent touches regulated system or evidence.</td><td>QA / validation impact.</td><td>GxP impact assessment and QA approval.</td><td><span class="badge red">QA change review</span></td></tr>
                <tr><td>Agent model, prompt, tool, or data boundary changed.</td><td>Behavior or capability change.</td><td>Change reason, test result, approval, updated passport.</td><td><span class="badge orange">Revalidation required</span></td></tr>
                <tr><td>Agent retired.</td><td>Decommissioning event.</td><td>Access removal, workflow disablement, evidence archive.</td><td><span class="badge green">Retirement record</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Change Bridge Rule</h2>
        <div class="answer">
            If an AI agent change can affect workflow behavior, access, records, evidence, ownership, risk, or regulated operations,
            the change must be governed before the agent is trusted again.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Change Control Bridge",
        "Bridge between AI agent lifecycle changes and ServiceNow-style change control, impact review, rollback, and evidence.",
        body
    )


@app.route("/agenttrust/lcm-ownership-bridge")
@app.route("/agenttrust/agent-lcm-bridge")
@app.route("/agenttrust/ownership-support-bridge")
def agenttrust_lcm_ownership_bridge():
    body = """
    <section class="section">
        <h2>AgentTrust™ LCM / Ownership / Support Group Bridge</h2>
        <p>
            This bridge ensures that every AI agent has clear ownership and support responsibility,
            just like the Configuration Items and services it may influence.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Ownership Field</th>
                    <th>Purpose</th>
                    <th>Risk If Missing</th>
                    <th>Required Action</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Business Owner</td><td>Owns the business purpose and acceptable use.</td><td>Agent has no accountable business sponsor.</td><td><span class="badge red">Assign before use</span></td></tr>
                <tr><td>Technical Owner</td><td>Owns technical configuration, integration, and support.</td><td>Agent cannot be supported or remediated.</td><td><span class="badge red">Assign before deployment</span></td></tr>
                <tr><td>Support Group</td><td>Receives incidents, issues, and operational tasks.</td><td>No operational support path.</td><td><span class="badge orange">Define assignment group</span></td></tr>
                <tr><td>LCM Owner</td><td>Owns lifecycle decisions and periodic review.</td><td>Agent becomes stale or unmanaged.</td><td><span class="badge yellow">Assign lifecycle owner</span></td></tr>
                <tr><td>Risk Owner</td><td>Accepts residual risk and escalation decisions.</td><td>Risk has no owner.</td><td><span class="badge red">Assign risk owner</span></td></tr>
                <tr><td>QA Owner</td><td>Reviews GxP, validation, quality, and inspection impact.</td><td>Regulated reliance may be undefended.</td><td><span class="badge red">Required for regulated impact</span></td></tr>
                <tr><td>Cybersecurity Owner</td><td>Reviews access, privileged execution, and threat exposure.</td><td>Access or privilege risk may be uncontrolled.</td><td><span class="badge red">Required for access impact</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Ownership Bridge Rule</h2>
        <div class="answer">
            AgentTrust™ blocks operational reliance on AI agents that have no business owner, technical owner,
            support path, lifecycle owner, risk owner, or regulated/cyber owner where applicable.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ LCM Ownership Bridge",
        "Ownership and support model connecting AI agents to business owners, technical owners, support groups, LCM, risk, QA, and cybersecurity.",
        body
    )


@app.route("/agenttrust/servicenow-evidence-sync")
@app.route("/agenttrust/evidence-sync-model")
@app.route("/agenttrust/agent-evidence-sync")
def agenttrust_servicenow_evidence_sync():
    body = """
    <section class="section">
        <h2>AgentTrust™ ServiceNow Evidence Sync Model</h2>
        <p>
            This model defines how AI agent evidence should link to ServiceNow records, CMDB items, change records,
            access requests, incidents, tasks, and governance evidence packages.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Evidence Type</th>
                    <th>ServiceNow Link</th>
                    <th>AgentTrust™ Record</th>
                    <th>Audit Question Answered</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent Identity</td><td>Agent record / related CI / service mapping.</td><td>Agent Register and Passport.</td><td>Which AI agent was involved?</td></tr>
                <tr><td>CI Context</td><td>Business Application, Application Service, Infrastructure CI.</td><td>Agent-CI relationship model.</td><td>Which system or service was affected?</td></tr>
                <tr><td>Change Context</td><td>Change request, task, approval, implementation record.</td><td>Change Control Bridge.</td><td>Was the agent action governed by change?</td></tr>
                <tr><td>Access Context</td><td>MyAccess request, entitlement group, CyberArk approval route.</td><td>Access Routing Model.</td><td>Did access or privilege governance apply?</td></tr>
                <tr><td>Tool-Call Evidence</td><td>API, workflow, task, record update, trigger evidence.</td><td>Tool-Call Evidence Ledger.</td><td>What did the AI agent do?</td></tr>
                <tr><td>Human Review</td><td>Approver, reviewer, assignment group, owner comment.</td><td>Human Accountability Map.</td><td>Which human reviewed or approved it?</td></tr>
                <tr><td>Outcome</td><td>Closed task, blocked action, escalation, rollback, verification.</td><td>Decision Replay Package.</td><td>What was the result?</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Evidence Sync Rule</h2>
        <div class="answer">
            AgentTrust™ evidence should not sit separately from ServiceNow operations.
            It should link AI agent identity, CI context, change context, access context, tool-call evidence,
            human review, and outcome into one defensible chain.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ ServiceNow Evidence Sync",
        "Evidence synchronization model linking AI agent actions to ServiceNow records, CMDB context, change control, access routing, and decision replay.",
        body
    )

# ============================================================
# END AGENTTRUST_SERVICENOW_INTEGRATION_BLUEPRINT_V1_ACTIVE
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

print("AgentTrust ServiceNow Integration Blueprint installed.")
print(f"Inserted before: {target_found}")
