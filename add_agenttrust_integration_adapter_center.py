from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_INTEGRATION_ADAPTER_CENTER_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust Integration Adapter Center already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base module not found. Install AgentTrust module first.")

nav_old = '<a href="/agenttrust/governance-graph" class="secondary">Governance Graph</a>'
nav_new = '''<a href="/agenttrust/governance-graph" class="secondary">Governance Graph</a>
                    <a href="/agenttrust/integration-adapter-center" class="secondary">Adapters</a>
                    <a href="/agenttrust/enterprise-connector-map" class="dark">Connector Map</a>
                    <a href="/agenttrust/servicenow-adapter-spec" class="dark">ServiceNow Adapter</a>
                    <a href="/agenttrust/integration-readiness-checklist" class="dark">Integration Readiness</a>'''

if nav_old in text and "/agenttrust/integration-adapter-center" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# AGENTTRUST_INTEGRATION_ADAPTER_CENTER_V1_ACTIVE
# AgentTrust™ Integration Adapter Center, Enterprise Connector Map,
# ServiceNow Adapter Spec, MyAccess / CyberArk Adapter,
# Splunk / SIEM Adapter, Azure OpenAI Adapter, GxP Platform Adapter,
# Evidence Vault Adapter, Integration Readiness Checklist,
# and Adapter Contract JSON Export
# ============================================================

AGENTTRUST_ADAPTERS = [
    {
        "adapter_id": "AT-ADP-001",
        "adapter": "ServiceNow / CMDB Adapter",
        "system": "ServiceNow CMDB, CSDM, Change, Incident, Request, CI Candidate Review",
        "purpose": "Connect AI agent governance to CI identity, ownership, lifecycle, support group, change control, and evidence records.",
        "data_in": "CI records, change records, owner fields, support groups, lifecycle state, relationship data.",
        "data_out": "Agent recommendations, authority decisions, evidence links, readiness score, human review status.",
        "risk": "High",
        "control": "Read-only by default. Update or workflow trigger requires authority gate and human approval."
    },
    {
        "adapter_id": "AT-ADP-002",
        "adapter": "MyAccess Adapter",
        "system": "MyAccess / Enterprise Access Request",
        "purpose": "Route AI agent access-impacting recommendations to the correct access owner and approval path.",
        "data_in": "Entitlement group, requester, approver route, business justification, system boundary.",
        "data_out": "Access impact flag, required approver, evidence package, cyber review requirement.",
        "risk": "Critical",
        "control": "AI must not approve access. Access owner and cybersecurity review required where applicable."
    },
    {
        "adapter_id": "AT-ADP-003",
        "adapter": "CyberArk / PSM Adapter",
        "system": "CyberArk, PSM, privileged session, admin access pathway",
        "purpose": "Detect and route privileged or admin-impacting AI agent actions.",
        "data_in": "Privileged access context, admin route, PSM dependency, vault/session evidence.",
        "data_out": "Privileged impact decision, cyber escalation, restricted execution state.",
        "risk": "Critical",
        "control": "Privileged execution is blocked unless cybersecurity owner approves and evidence is captured."
    },
    {
        "adapter_id": "AT-ADP-004",
        "adapter": "Splunk / SIEM Adapter",
        "system": "Splunk, SIEM, security event monitoring",
        "purpose": "Send AI agent runtime alerts, trust degradation events, abnormal tool calls, and evidence tamper signals to security monitoring.",
        "data_in": "Agent event logs, tool-call logs, runtime sentinel alerts, drift alerts, breach events.",
        "data_out": "Security alert, investigation ticket, escalation evidence, monitoring correlation.",
        "risk": "High",
        "control": "Security-relevant agent events must be traceable, timestamped, and owner-routed."
    },
    {
        "adapter_id": "AT-ADP-005",
        "adapter": "Azure OpenAI / AI Platform Adapter",
        "system": "Azure OpenAI, internal AI platform, model endpoint, orchestration layer",
        "purpose": "Track model version, prompt version, endpoint, configuration, token/tool policy, and agent runtime identity.",
        "data_in": "Model endpoint, deployment name, prompt version, runtime configuration, tool policy.",
        "data_out": "Model change signal, prompt drift signal, AgentBOM update, trust recalculation trigger.",
        "risk": "High",
        "control": "Model, prompt, and tool changes must trigger lifecycle change gate and trust score recalculation."
    },
    {
        "adapter_id": "AT-ADP-006",
        "adapter": "GxP Platform Adapter",
        "system": "Veeva, MES, LIMS, QMS, validation repository, batch / QC / inspection evidence systems",
        "purpose": "Detect regulated evidence, QA impact, validation impact, inspection impact, and quality decision influence.",
        "data_in": "Regulated record reference, validation evidence, QC evidence, deviation, CAPA, release, inspection packet.",
        "data_out": "GxP impact flag, QA review route, validation owner decision, regulated reliance status.",
        "risk": "Critical",
        "control": "AI may prepare evidence but cannot make regulated conclusions or approvals."
    },
    {
        "adapter_id": "AT-ADP-007",
        "adapter": "Evidence Vault Adapter",
        "system": "Evidence ledger, document repository, audit dossier, immutable evidence store",
        "purpose": "Store and retrieve input, source, tool-call, output, human review, outcome, and replay evidence.",
        "data_in": "Agent action, evidence bundle, decision record, tool-call record, reviewer decision.",
        "data_out": "Replay package, audit dossier, assurance case evidence, inspection response packet.",
        "risk": "High Control",
        "control": "Evidence must be captured at time of action and linked to agent, authority, owner, and outcome."
    },
    {
        "adapter_id": "AT-ADP-008",
        "adapter": "Leadership Dashboard Adapter",
        "system": "Power BI, executive dashboard, governance reporting, board pack",
        "purpose": "Report trust score, risk tier, open alerts, human-gated items, exceptions, and audit readiness.",
        "data_in": "Trust index, monitoring events, risk acceptance, red-team score, assurance claims.",
        "data_out": "Executive scorecard, board summary, governance heatmap, readiness dashboard.",
        "risk": "Medium",
        "control": "Leadership reports must distinguish evidence-backed trust from incomplete or conditional trust."
    }
]


AGENTTRUST_INTEGRATION_CONTRACTS = [
    {
        "contract": "Identity Contract",
        "requirement": "Every integration must preserve agent ID, action ID, timestamp, owner, and system touched.",
        "failure": "Action cannot be traced to agent identity."
    },
    {
        "contract": "Authority Contract",
        "requirement": "Every create, update, trigger, approve, access, privileged, or regulated action must have authority decision ID.",
        "failure": "Tool call may execute without governance approval."
    },
    {
        "contract": "Evidence Contract",
        "requirement": "Every integration must return or store input, source, tool-call, output, human decision, and outcome evidence.",
        "failure": "Audit replay becomes weak or impossible."
    },
    {
        "contract": "Human Accountability Contract",
        "requirement": "Every material decision must route to a named human owner or accountable reviewer.",
        "failure": "AI becomes a hidden decision-maker."
    },
    {
        "contract": "Cyber Contract",
        "requirement": "Access, CyberArk, PSM, entitlement, admin, or privileged context must route to cyber owner.",
        "failure": "Privileged access governance may be bypassed."
    },
    {
        "contract": "GxP Contract",
        "requirement": "GMP, QA, validation, release, deviation, CAPA, or inspection context must route to QA / validation owner.",
        "failure": "Regulated conclusion may be created without proper human review."
    },
    {
        "contract": "Drift Contract",
        "requirement": "Model, prompt, tool, API, data source, workflow, owner, or evidence-store changes must trigger drift signal.",
        "failure": "Trust score becomes stale."
    },
    {
        "contract": "Replay Contract",
        "requirement": "Every completed action must be reconstructable from identity to outcome.",
        "failure": "Leadership cannot defend the AI agent action."
    }
]


def agenttrust_adapter_rows():
    rows = ""

    for item in AGENTTRUST_ADAPTERS:
        badge = "blue"
        if item["risk"] == "Critical":
            badge = "red"
        elif item["risk"] == "High":
            badge = "orange"
        elif item["risk"] == "High Control":
            badge = "yellow"

        rows += f"""
        <tr>
            <td><strong>{item["adapter_id"]}</strong></td>
            <td>{item["adapter"]}</td>
            <td>{item["system"]}</td>
            <td>{item["purpose"]}</td>
            <td>{item["data_in"]}</td>
            <td>{item["data_out"]}</td>
            <td><span class="badge {badge}">{item["risk"]}</span></td>
            <td>{item["control"]}</td>
        </tr>
        """

    return rows


def agenttrust_integration_contract_rows():
    rows = ""

    for item in AGENTTRUST_INTEGRATION_CONTRACTS:
        rows += f"""
        <tr>
            <td><strong>{item["contract"]}</strong></td>
            <td>{item["requirement"]}</td>
            <td><span class="badge red">{item["failure"]}</span></td>
        </tr>
        """

    return rows


try:
    AGENTTRUST_EXPECTED_ROUTES.extend([
        "/agenttrust/integration-adapter-center",
        "/agenttrust/enterprise-connector-map",
        "/agenttrust/servicenow-adapter-spec",
        "/agenttrust/myaccess-cyberark-adapter",
        "/agenttrust/splunk-security-adapter",
        "/agenttrust/azure-openai-adapter",
        "/agenttrust/gxp-platform-adapter",
        "/agenttrust/evidence-vault-adapter",
        "/agenttrust/integration-readiness-checklist",
        "/agenttrust/adapter-contract-json"
    ])
except Exception:
    pass


@app.route("/agenttrust/integration-adapter-center")
@app.route("/agenttrust/adapter-center")
@app.route("/agenttrust/enterprise-adapter-center")
def agenttrust_integration_adapter_center():
    rows = agenttrust_adapter_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Adapter Center</div><div class="value" style="color:var(--green);">Ready</div><div class="note">Enterprise connector model defined.</div></div>
        <div class="metric"><div class="label">ServiceNow</div><div class="value" style="color:var(--blue);">Mapped</div><div class="note">CMDB, CI, change, ticket, and evidence integration.</div></div>
        <div class="metric"><div class="label">MyAccess / CyberArk</div><div class="value" style="color:var(--red);">Gated</div><div class="note">Access and privileged impact route to cyber owner.</div></div>
        <div class="metric"><div class="label">AI Platform</div><div class="value" style="color:var(--orange);">Controlled</div><div class="note">Model, prompt, endpoint, and tool drift watched.</div></div>
        <div class="metric"><div class="label">GxP Systems</div><div class="value" style="color:var(--yellow);">QA Routed</div><div class="note">Regulated impact routes to QA / validation owner.</div></div>
        <div class="metric"><div class="label">Evidence Vault</div><div class="value" style="color:var(--purple);">Replayable</div><div class="note">Evidence must support audit dossier and replay.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Integration Adapter Center</h2>
        <div class="answer">
            <strong>Purpose:</strong> define how AgentTrust™ connects to enterprise systems without losing governance.
            The adapter center ensures every integration preserves agent identity, authority, human accountability,
            evidence, cyber routing, GxP routing, monitoring, and audit replay.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Adapter ID</th>
                    <th>Adapter</th>
                    <th>Enterprise System</th>
                    <th>Purpose</th>
                    <th>Data In</th>
                    <th>Data Out</th>
                    <th>Risk</th>
                    <th>Required Control</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Adapter Rule</h2>
        <div class="answer">
            AgentTrust™ integrations must not become blind automation.
            Every connector must preserve identity, authority, evidence, human accountability, and final outcome.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Integration Adapter Center",
        "Enterprise integration adapter center for ServiceNow, MyAccess, CyberArk, Splunk, Azure OpenAI, GxP systems, evidence vaults, and leadership dashboards.",
        body
    )


@app.route("/agenttrust/enterprise-connector-map")
@app.route("/agenttrust/connector-map")
@app.route("/agenttrust/system-connector-map")
def agenttrust_enterprise_connector_map():
    rows = agenttrust_adapter_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Enterprise Connector Map</h2>
        <p>
            The Enterprise Connector Map shows how AgentTrust™ can sit above operational systems as a governance assurance layer.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Connector</th>
                    <th>System</th>
                    <th>Governance Purpose</th>
                    <th>Output to AgentTrust™</th>
                    <th>Risk</th>
                </tr>
            </thead>
            <tbody>
                {''.join([f'<tr><td><strong>{item["adapter"]}</strong></td><td>{item["system"]}</td><td>{item["purpose"]}</td><td>{item["data_out"]}</td><td><span class="badge red">{item["risk"]}</span></td></tr>' for item in AGENTTRUST_ADAPTERS])}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Connector Map Rule</h2>
        <div class="answer">
            AgentTrust™ is not replacing ServiceNow, MyAccess, CyberArk, Splunk, Azure OpenAI, MES, LIMS, QMS, or Veeva.
            It is the governance assurance layer that makes AI agent interactions with those systems traceable and defensible.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Enterprise Connector Map",
        "Connector map showing how AgentTrust™ integrates with enterprise systems while preserving AI agent governance assurance.",
        body
    )


@app.route("/agenttrust/servicenow-adapter-spec")
@app.route("/agenttrust/servicenow-agent-adapter")
@app.route("/agenttrust/cmdb-adapter-spec")
def agenttrust_servicenow_adapter_spec():
    body = """
    <section class="section">
        <h2>AgentTrust™ ServiceNow Adapter Specification</h2>
        <p>
            This adapter links AgentTrust™ AI agent governance to ServiceNow CMDB, CSDM, change, incident,
            request, CI candidate review, and evidence workflows.
        </p>

        <table>
            <thead>
                <tr>
                    <th>ServiceNow Object</th>
                    <th>AgentTrust™ Use</th>
                    <th>Required Field / Evidence</th>
                    <th>Control Rule</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Configuration Item</td><td>Agent reviews CI ownership, lifecycle, support group, and relationship gaps.</td><td>CI ID, owner, support group, LCM, lifecycle status.</td><td><span class="badge yellow">Recommendation only unless approved</span></td></tr>
                <tr><td>Business Application</td><td>Agent maps application identity and regulated relevance.</td><td>Application owner, support group, business service, environment.</td><td><span class="badge orange">Owner validation required</span></td></tr>
                <tr><td>Application Service</td><td>Agent checks mapped service relationship.</td><td>Service mapping and dependency evidence.</td><td><span class="badge orange">Relationship evidence required</span></td></tr>
                <tr><td>Change Record</td><td>Agent drafts or summarizes change impact.</td><td>Change ID, impact, approval, evidence, rollback.</td><td><span class="badge red">No autonomous approval</span></td></tr>
                <tr><td>Incident / Task</td><td>Agent summarizes issue or prepares remediation task.</td><td>Task ID, source evidence, owner, status.</td><td><span class="badge yellow">Human-gated if operational</span></td></tr>
                <tr><td>Request Item</td><td>Agent supports access or workflow request routing.</td><td>Request ID, requester, approver, evidence.</td><td><span class="badge red">Access approval prohibited</span></td></tr>
                <tr><td>CI Candidate Review</td><td>Agent assists manual CI intake and review.</td><td>Candidate ID, source, reviewer, decision.</td><td><span class="badge yellow">LCM / CMDB owner review required</span></td></tr>
                <tr><td>Evidence Link</td><td>Agent stores evidence package reference.</td><td>Evidence ID, dossier link, replay status.</td><td><span class="badge green">Required for audit defense</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>ServiceNow Adapter Rule</h2>
        <div class="answer">
            AI may assist ServiceNow governance, but it must not become the hidden owner, approver, LCM, change approver,
            access approver, or regulated decision-maker.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ ServiceNow Adapter Specification",
        "ServiceNow adapter specification for AI agent governance across CMDB, CSDM, change, incident, request, CI candidate review, and evidence links.",
        body
    )


@app.route("/agenttrust/myaccess-cyberark-adapter")
@app.route("/agenttrust/access-cyberark-adapter")
@app.route("/agenttrust/privileged-access-adapter")
def agenttrust_myaccess_cyberark_adapter():
    body = """
    <section class="section">
        <h2>AgentTrust™ MyAccess / CyberArk Adapter</h2>
        <p>
            This adapter controls AI agent interactions with access, entitlement, CyberArk, PSM, admin, and privileged routes.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Access Scenario</th>
                    <th>AgentTrust™ Decision</th>
                    <th>Required Owner</th>
                    <th>Evidence Required</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent reads access group metadata.</td><td><span class="badge yellow">Allowed if approved boundary</span></td><td>Access owner.</td><td>Source group, requester, purpose, timestamp.</td></tr>
                <tr><td>Agent recommends entitlement group.</td><td><span class="badge orange">Human-gated</span></td><td>Access owner.</td><td>Recommendation, rationale, reviewer decision.</td></tr>
                <tr><td>Agent drafts MyAccess request.</td><td><span class="badge orange">Restricted</span></td><td>Requester / access owner.</td><td>Draft request, human review, no auto-submit evidence.</td></tr>
                <tr><td>Agent approves access.</td><td><span class="badge red">Prohibited</span></td><td>Human approver.</td><td>AI approval blocked record.</td></tr>
                <tr><td>Agent detects CyberArk / PSM route.</td><td><span class="badge red">Cyber escalation</span></td><td>Cybersecurity / CyberArk owner.</td><td>Privileged impact record and cyber decision.</td></tr>
                <tr><td>Agent triggers privileged workflow.</td><td><span class="badge red">Blocked by default</span></td><td>Cybersecurity owner.</td><td>Authority breach or approved cyber exception.</td></tr>
                <tr><td>Agent influences admin activity.</td><td><span class="badge red">Cyber-gated</span></td><td>Cybersecurity / platform owner.</td><td>Admin context, approval, session evidence.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Access Adapter Rule</h2>
        <div class="answer">
            AgentTrust™ treats access and privileged workflows as critical. AI can assist routing,
            but it must not approve access, activate entitlements, or trigger privileged execution by default.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ MyAccess CyberArk Adapter",
        "Adapter for AI agent governance across MyAccess, entitlement groups, CyberArk, PSM, admin access, privileged workflows, and cyber escalation.",
        body
    )


@app.route("/agenttrust/splunk-security-adapter")
@app.route("/agenttrust/siem-adapter")
@app.route("/agenttrust/security-monitoring-adapter")
def agenttrust_splunk_security_adapter():
    body = """
    <section class="section">
        <h2>AgentTrust™ Splunk / SIEM Security Adapter</h2>
        <p>
            This adapter sends AI agent risk signals to security monitoring and investigation workflows.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Security Signal</th>
                    <th>Meaning</th>
                    <th>SIEM / Splunk Event</th>
                    <th>AgentTrust™ Response</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Unauthorized tool call attempt.</td><td>Agent tried to act outside authority.</td><td>agenttrust.authority_breach</td><td><span class="badge red">Block and alert</span></td></tr>
                <tr><td>Privileged access context detected.</td><td>CyberArk, PSM, admin, or entitlement route involved.</td><td>agenttrust.privileged_context</td><td><span class="badge red">Escalate to cyber</span></td></tr>
                <tr><td>Prompt injection signal.</td><td>External content attempted instruction override.</td><td>agenttrust.prompt_injection</td><td><span class="badge orange">Restrict and investigate</span></td></tr>
                <tr><td>Evidence tamper signal.</td><td>Evidence missing, edited, or post-created.</td><td>agenttrust.evidence_integrity</td><td><span class="badge red">Tamper watch</span></td></tr>
                <tr><td>Dependency drift signal.</td><td>Model, prompt, tool, data, owner, or workflow changed.</td><td>agenttrust.dependency_drift</td><td><span class="badge orange">Run change gate</span></td></tr>
                <tr><td>Quarantine event.</td><td>Agent restricted due to control failure.</td><td>agenttrust.quarantine</td><td><span class="badge red">Investigation required</span></td></tr>
                <tr><td>Repeated unsafe pattern.</td><td>Agent repeatedly violates policy or triggers alert.</td><td>agenttrust.repeated_violation</td><td><span class="badge red">Suspend license</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Security Adapter Rule</h2>
        <div class="answer">
            AI agent security events must be observable.
            If an agent violates authority, touches privilege, shows prompt-injection behavior, or weakens evidence,
            the event should be visible to security monitoring.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Splunk SIEM Adapter",
        "Security monitoring adapter for AI agent authority breaches, privileged context, prompt injection, evidence tampering, dependency drift, quarantine, and repeated violations.",
        body
    )


@app.route("/agenttrust/azure-openai-adapter")
@app.route("/agenttrust/ai-platform-adapter")
@app.route("/agenttrust/model-platform-adapter")
def agenttrust_azure_openai_adapter():
    body = """
    <section class="section">
        <h2>AgentTrust™ Azure OpenAI / AI Platform Adapter</h2>
        <p>
            This adapter connects AgentTrust™ governance to the AI platform layer where model, prompt, tool policy,
            endpoint configuration, and runtime identity are controlled.
        </p>

        <table>
            <thead>
                <tr>
                    <th>AI Platform Element</th>
                    <th>Governance Risk</th>
                    <th>AgentTrust™ Evidence</th>
                    <th>Required Control</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Model deployment.</td><td>Model behavior changes if deployment changes.</td><td>Model name, version, endpoint, configuration.</td><td><span class="badge orange">Model change gate</span></td></tr>
                <tr><td>System prompt.</td><td>Boundary or prohibited actions may change.</td><td>Prompt version, owner, approval, hash/reference.</td><td><span class="badge red">Prompt change gate</span></td></tr>
                <tr><td>Tool policy.</td><td>New tool can create execution risk.</td><td>Allowed tools, denied tools, mode, target system.</td><td><span class="badge red">Tool authority gate</span></td></tr>
                <tr><td>Runtime identity.</td><td>Agent identity may be confused with user or service account.</td><td>Agent ID, service identity, owner, session ID.</td><td><span class="badge yellow">Identity control</span></td></tr>
                <tr><td>RAG / retrieval source.</td><td>Wrong source can create wrong decision.</td><td>Source documents, record IDs, retrieval timestamp.</td><td><span class="badge orange">Source lineage control</span></td></tr>
                <tr><td>Output parser.</td><td>Text may be converted into workflow action.</td><td>Parser rule, output schema, action map.</td><td><span class="badge red">Execution firewall</span></td></tr>
                <tr><td>Telemetry.</td><td>Weak logs reduce replay and monitoring.</td><td>Prompt, response, tool calls, errors, outcome.</td><td><span class="badge orange">Evidence capture</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>AI Platform Adapter Rule</h2>
        <div class="answer">
            Model governance is not enough. AgentTrust™ governs the model, prompt, tool policy, data source,
            runtime identity, output parser, telemetry, and downstream workflow together.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Azure OpenAI Adapter",
        "AI platform adapter for model deployment, prompt governance, tool policy, runtime identity, retrieval source, output parser, and telemetry evidence.",
        body
    )


@app.route("/agenttrust/gxp-platform-adapter")
@app.route("/agenttrust/regulated-platform-adapter")
@app.route("/agenttrust/mes-lims-qms-adapter")
def agenttrust_gxp_platform_adapter():
    body = """
    <section class="section">
        <h2>AgentTrust™ GxP Platform Adapter</h2>
        <p>
            This adapter protects regulated workflows where AI agent output may touch GMP, QA, validation, QC,
            release, deviation, CAPA, inspection, MES, LIMS, QMS, or Veeva-related evidence.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Regulated Context</th>
                    <th>AI Agent Risk</th>
                    <th>Required Owner</th>
                    <th>AgentTrust™ Decision</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Validation evidence summary.</td><td>AI summary may be treated as validation conclusion.</td><td>Validation Owner.</td><td><span class="badge red">Human-governed only</span></td></tr>
                <tr><td>QC / lab evidence interpretation.</td><td>AI may influence quality interpretation.</td><td>QA / QC Owner.</td><td><span class="badge red">QA review required</span></td></tr>
                <tr><td>Deviation / CAPA drafting.</td><td>AI may influence root cause or closure language.</td><td>QA Owner.</td><td><span class="badge red">Human approval required</span></td></tr>
                <tr><td>Batch or release support.</td><td>AI may influence release readiness.</td><td>QA / Release Owner.</td><td><span class="badge red">AI approval prohibited</span></td></tr>
                <tr><td>Inspection response packet.</td><td>AI may prepare response but cannot certify truth.</td><td>QA / Inspection Owner.</td><td><span class="badge orange">QA signoff required</span></td></tr>
                <tr><td>MES / LIMS / QMS record context.</td><td>AI may touch regulated operational records.</td><td>System Owner + QA.</td><td><span class="badge red">GxP impact review required</span></td></tr>
                <tr><td>Regulated evidence export.</td><td>Evidence may be incomplete or stale.</td><td>Audit / QA Owner.</td><td><span class="badge orange">Evidence sufficiency check</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>GxP Adapter Rule</h2>
        <div class="answer">
            AgentTrust™ allows AI to help prepare regulated evidence, but it blocks the AI from becoming the regulated approver,
            QA decision-maker, validation signer, batch release authority, or inspection certifier.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ GxP Platform Adapter",
        "GxP platform adapter for AI agent governance across validation evidence, QC, deviation, CAPA, batch release, inspection response, MES, LIMS, QMS, and Veeva-related records.",
        body
    )


@app.route("/agenttrust/evidence-vault-adapter")
@app.route("/agenttrust/audit-evidence-adapter")
@app.route("/agenttrust/evidence-store-adapter")
def agenttrust_evidence_vault_adapter():
    body = """
    <section class="section">
        <h2>AgentTrust™ Evidence Vault Adapter</h2>
        <p>
            The Evidence Vault Adapter stores the evidence needed to defend AI agent actions.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Evidence Type</th>
                    <th>Required Content</th>
                    <th>Replay Purpose</th>
                    <th>Missing Evidence Risk</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent identity evidence.</td><td>Agent ID, owner, purpose, lifecycle state.</td><td>Shows which agent acted.</td><td><span class="badge red">Unknown actor</span></td></tr>
                <tr><td>Input evidence.</td><td>Prompt, requester, source context, timestamp.</td><td>Shows what the agent received.</td><td><span class="badge orange">Weak input trace</span></td></tr>
                <tr><td>Source evidence.</td><td>Record ID, document, CI, change, access request, validation reference.</td><td>Shows what the agent relied on.</td><td><span class="badge red">Untraceable conclusion</span></td></tr>
                <tr><td>Authority evidence.</td><td>Decision rule, approval status, allowed action.</td><td>Shows why action was allowed or blocked.</td><td><span class="badge red">Unauthorized action risk</span></td></tr>
                <tr><td>Tool-call evidence.</td><td>Tool, API, system, mode, timestamp, result.</td><td>Shows what system was touched.</td><td><span class="badge red">No operational trace</span></td></tr>
                <tr><td>Human decision evidence.</td><td>Reviewer, approver, rejection, escalation, risk acceptance.</td><td>Shows human accountability.</td><td><span class="badge red">Hidden approval risk</span></td></tr>
                <tr><td>Outcome evidence.</td><td>Executed, blocked, escalated, rejected, rolled back, quarantined.</td><td>Shows final result.</td><td><span class="badge orange">Incomplete action loop</span></td></tr>
                <tr><td>Replay package.</td><td>Timeline, lineage, evidence links, final assurance decision.</td><td>Supports audit and inspection defense.</td><td><span class="badge red">Not defensible</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Evidence Vault Rule</h2>
        <div class="answer">
            The strongest AI governance evidence is captured at the time of action.
            AgentTrust™ treats after-the-fact reconstruction as weaker than live evidence capture.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Evidence Vault Adapter",
        "Evidence vault adapter for AI agent identity, input, source, authority, tool-call, human decision, outcome, and replay evidence.",
        body
    )


@app.route("/agenttrust/integration-readiness-checklist")
@app.route("/agenttrust/adapter-readiness-checklist")
@app.route("/agenttrust/connector-readiness")
def agenttrust_integration_readiness_checklist():
    contract_rows = agenttrust_integration_contract_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Integration Readiness Checklist</h2>
        <p>
            Before AgentTrust™ connects to any enterprise system, the integration must satisfy these contracts.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Integration Contract</th>
                    <th>Requirement</th>
                    <th>Failure If Missing</th>
                </tr>
            </thead>
            <tbody>
                {contract_rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Integration Readiness Decision</h2>
        <div class="answer">
            <strong>Ready:</strong> identity, authority, evidence, human owner, cyber routing, GxP routing, drift, and replay contracts are complete.<br>
            <strong>Human-Gated:</strong> integration is useful but still has owner, evidence, or authority gaps.<br>
            <strong>Restricted:</strong> connector can read but cannot create, update, trigger, approve, or route high-impact actions.<br>
            <strong>Blocked:</strong> integration cannot preserve identity, authority, evidence, or human accountability.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Integration Readiness Checklist",
        "Integration readiness checklist for AI agent enterprise adapters, including identity, authority, evidence, human accountability, cyber, GxP, drift, and replay contracts.",
        body
    )


@app.route("/agenttrust/adapter-contract-json")
@app.route("/agenttrust/integration-adapter-json")
@app.route("/agenttrust/connector-map-json")
def agenttrust_adapter_contract_json():
    from flask import jsonify

    return jsonify({
        "module": "AgentTrust™",
        "capability": "Integration Adapter Center + Enterprise Connector Map",
        "primary_question": "Can AgentTrust™ connect to enterprise systems without losing identity, authority, evidence, ownership, or replay?",
        "adapters": AGENTTRUST_ADAPTERS,
        "integration_contracts": AGENTTRUST_INTEGRATION_CONTRACTS,
        "critical_routing_rules": [
            "ServiceNow updates require authority and human approval",
            "MyAccess and entitlement actions require access owner approval",
            "CyberArk, PSM, admin, or privileged context requires cybersecurity review",
            "GxP, QA, validation, release, deviation, CAPA, or inspection context requires QA / validation review",
            "AI platform model, prompt, tool, or endpoint changes trigger drift and lifecycle review",
            "Security-relevant events route to SIEM / Splunk-style monitoring",
            "Evidence vault must support identity-to-outcome replay",
            "Leadership dashboards must distinguish evidence-backed trust from conditional trust"
        ],
        "default_decision": "Restrict integration to read-only or human-gated mode until identity, authority, evidence, human owner, cyber routing, GxP routing, drift, and replay contracts are complete"
    })

# ============================================================
# END AGENTTRUST_INTEGRATION_ADAPTER_CENTER_V1_ACTIVE
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

print("AgentTrust Integration Adapter Center installed.")
print(f"Inserted before: {target_found}")
