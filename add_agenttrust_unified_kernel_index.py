from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_UNIFIED_KERNEL_INDEX_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust Unified Kernel Index already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base module not found. Install AgentTrust module first.")

nav_old = '<a href="/agenttrust/servicenow-integration-blueprint" class="secondary">ServiceNow Blueprint</a>'
nav_new = '''<a href="/agenttrust/servicenow-integration-blueprint" class="secondary">ServiceNow Blueprint</a>
                    <a href="/agenttrust/unified-kernel-index" class="secondary">Kernel Index</a>
                    <a href="/agenttrust/agentic-operating-model" class="dark">Operating Model</a>
                    <a href="/agenttrust/readiness-roadmap" class="dark">Roadmap</a>
                    <a href="/agenttrust/platform-positioning" class="dark">Positioning</a>'''

if nav_old in text and "/agenttrust/unified-kernel-index" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# AGENTTRUST_UNIFIED_KERNEL_INDEX_V1_ACTIVE
# AgentTrust™ Unified Kernel Index, Agentic Operating Model,
# Readiness Roadmap, Platform Positioning, and Full Route Directory
# ============================================================

AGENTTRUST_KERNEL_ROUTES = [
    ("Core", "AgentTrust™ Home", "/agenttrust", "Main AI Agentic Governance landing page."),
    ("Core", "Integration Map", "/agenttrust/integration-map", "Tracks AgentTrust™ hooks across COBIT-Chain™ modules."),
    ("Core", "Unified Kernel Index", "/agenttrust/unified-kernel-index", "Complete master index for all AgentTrust™ capabilities."),

    ("Identity", "Agent Register", "/agenttrust/agent-register", "Registers AI agents as governed operational actors."),
    ("Identity", "Agent Risk Passport", "/agenttrust/agent-passport", "Defines agent purpose, model, data, systems, tools, risk, and evidence."),
    ("Identity", "Passport Factory", "/agenttrust/passport-factory", "Factory for creating Agent Risk Passport™ artifacts."),
    ("Identity", "Sample Agent Register", "/agenttrust/sample-agent-register", "Starter register showing sample AI agents and governance linkage."),

    ("Authority", "Authority Gate", "/agenttrust/authority-gate", "Confirms authority before execution."),
    ("Authority", "Chain of Authority", "/agenttrust/chain-of-authority", "Shows who or what allowed the agent to act."),
    ("Authority", "Operational Matrix", "/agenttrust/operational-matrix", "Defines read, recommend, draft, create, update, trigger, approve, and prohibited actions."),
    ("Authority", "Prohibited Action Sentinel", "/agenttrust/prohibited-action-sentinel", "Blocks or human-gates forbidden AI agent actions."),

    ("Evidence", "Tool-Call Evidence", "/agenttrust/tool-call-evidence", "Logs API calls, workflow triggers, data access, and decision paths."),
    ("Evidence", "Evidence Ledger", "/agenttrust/evidence-ledger", "Captures evidence at the time of action."),
    ("Evidence", "Evidence Package Builder", "/agenttrust/evidence-package-builder", "Builds audit-ready evidence packages."),
    ("Evidence", "Evidence Lineage Engine", "/agenttrust/evidence-lineage-engine", "Maps source evidence to AI output, tool call, human review, and outcome."),
    ("Evidence", "Immutable Evidence Ledger", "/agenttrust/immutable-evidence-ledger", "Preserves authority, input, tool, output, human, and outcome records."),

    ("Accountability", "Human Accountability Map", "/agenttrust/human-accountability", "Maps AI agent action back to accountable human owners."),
    ("Accountability", "Escalation Router", "/agenttrust/escalation-rules", "Routes ownership, evidence, authority, cyber, QA, and risk gaps."),

    ("Operations", "Command Center", "/agenttrust/command-center", "Operational trust command center."),
    ("Operations", "Readiness Gate", "/agenttrust/readiness-gate", "Go-live readiness gate for AI agents."),
    ("Operations", "Risk Tiering", "/agenttrust/risk-tiering", "Classifies AI agent risk by capability and impact."),
    ("Operations", "Control Library", "/agenttrust/control-library", "Core AI agent controls."),
    ("Operations", "Enterprise Control Tower", "/agenttrust/enterprise-control-tower", "Leadership view of agent risk, ownership, authority, and evidence."),

    ("Runtime", "Execution Firewall", "/agenttrust/execution-firewall", "Runtime control before agent execution."),
    ("Runtime", "Runtime Sentinel", "/agenttrust/runtime-sentinel", "Monitors authority drift, boundary violations, evidence gaps, and unsafe runtime patterns."),
    ("Runtime", "Kill Switch", "/agenttrust/agent-kill-switch", "Stop-control for unsafe AI agent execution."),
    ("Runtime", "Drift Sentinel", "/agenttrust/drift-sentinel", "Detects model, prompt, tool, data, authority, owner, and evidence drift."),
    ("Runtime", "Trust Quarantine", "/agenttrust/trust-quarantine", "Isolates unsafe or unresolved AI agents."),

    ("Replay", "Decision Replay Studio", "/agenttrust/decision-replay-studio", "Reconstructs what the AI agent did and why."),
    ("Replay", "Action Timeline", "/agenttrust/action-timeline", "Shows request, boundary, authority, risk, evidence, action, review, and outcome."),
    ("Replay", "Audit Defense Room", "/agenttrust/audit-defense-room", "Organizes AI evidence into inspection-ready Q&A."),
    ("Replay", "Incident Reconstruction", "/agenttrust/incident-reconstruction", "Reconstructs AI agent incidents from evidence."),

    ("Lifecycle", "Lifecycle Governance", "/agenttrust/lifecycle-governance", "Governs agents from proposal to retirement."),
    ("Lifecycle", "Change Control Gate", "/agenttrust/change-control-gate", "Controls changes to purpose, boundary, data, tools, authority, and risk."),
    ("Lifecycle", "Model Change Gate", "/agenttrust/model-change-gate", "Controls model version, provider, configuration, and capability changes."),
    ("Lifecycle", "Prompt & Tool Change Gate", "/agenttrust/prompt-tool-change-gate", "Controls prompt, instruction, tool, API, retrieval, and workflow changes."),
    ("Lifecycle", "Review Cadence", "/agenttrust/review-cadence", "Defines recurring ownership, authority, evidence, risk, and tool review."),
    ("Lifecycle", "Decommissioning Gate", "/agenttrust/decommissioning-gate", "Controls retirement, access removal, workflow disablement, and evidence archive."),
    ("Lifecycle", "Lifecycle Evidence Register", "/agenttrust/lifecycle-evidence-register", "Defines evidence required at each lifecycle stage."),

    ("Metrics", "Metrics Engine", "/agenttrust/metrics-engine", "Measures AI agent operational trust."),
    ("Metrics", "Agent Trust Index", "/agenttrust/agent-trust-index", "Composite trust score."),
    ("Metrics", "Control Coverage Matrix", "/agenttrust/control-coverage-matrix", "Maps controls by risk tier."),
    ("Metrics", "Evidence Sufficiency Dashboard", "/agenttrust/evidence-sufficiency-dashboard", "Scores input, authority, tool, human, outcome, and replay evidence."),
    ("Metrics", "Runtime Safety Score", "/agenttrust/runtime-safety-score", "Scores runtime firewall, sentinel, kill switch, quarantine, and rollback."),
    ("Metrics", "Audit Defensibility Score", "/agenttrust/audit-defensibility-score", "Scores replay and inspection defensibility."),
    ("Metrics", "GxP Exposure Score", "/agenttrust/gxp-exposure-score", "Scores regulated exposure."),
    ("Metrics", "Continuous Assurance Scorecard", "/agenttrust/continuous-assurance-scorecard", "Recurring assurance view."),
    ("Metrics", "Governance Debt Register", "/agenttrust/governance-debt-register", "Tracks missing owners, authority gaps, evidence gaps, drift, and expired exceptions."),
    ("Metrics", "KPI Catalog", "/agenttrust/kpi-catalog", "Catalog of AI agent governance KPIs."),

    ("Regulatory", "AI Act Readiness", "/agenttrust/ai-act-readiness", "AI Act readiness lens."),
    ("Regulatory", "Regulatory Crosswalk", "/agenttrust/regulatory-crosswalk", "Crosswalk across governance and regulatory lenses."),
    ("Regulatory", "COBIT Control Map", "/agenttrust/cobit-crosswalk", "Maps COBIT-style governance to AI agent controls."),
    ("Regulatory", "GxP Impact Router", "/agenttrust/gxp-impact-router", "Routes regulated impact to QA and validation review."),
    ("Regulatory", "AI Policy Router", "/agenttrust/ai-policy-router", "Routes AI agent action through correct governance lane."),

    ("ServiceNow", "ServiceNow Integration Blueprint", "/agenttrust/servicenow-integration-blueprint", "Connects AgentTrust™ to ServiceNow CMDB, CSDM, access, change, and evidence."),
    ("ServiceNow", "CMDB / CSDM Mapping", "/agenttrust/cmdb-csdm-mapping", "Maps agents to Business Applications, Application Services, infrastructure CIs, support groups, and LCM."),
    ("ServiceNow", "Agent-CI Relationship Model", "/agenttrust/agent-ci-relationship-model", "Defines how agents observe, summarize, recommend, create, update, trigger, or influence CIs."),
    ("ServiceNow", "MyAccess / CyberArk Routing", "/agenttrust/myaccess-cyberark-agent-routing", "Routes access and privileged-execution agent scenarios."),
    ("ServiceNow", "Change Control Bridge", "/agenttrust/change-control-bridge", "Links AI agent change events to change governance."),
    ("ServiceNow", "LCM Ownership Bridge", "/agenttrust/lcm-ownership-bridge", "Connects AI agents to ownership, support group, LCM, risk, QA, and cybersecurity."),
    ("ServiceNow", "ServiceNow Evidence Sync", "/agenttrust/servicenow-evidence-sync", "Links AI agent evidence to ServiceNow records, CMDB context, change, access, and outcome."),

    ("Executive", "Executive Assurance Dashboard", "/agenttrust/executive-assurance-dashboard", "Leadership dashboard for AI agent governance assurance."),
    ("Executive", "Master Index", "/agenttrust/master-index", "Earlier master index page."),
    ("Executive", "Trust Heatmap", "/agenttrust/trust-heatmap", "Heatmap for AI agent trust weaknesses."),
    ("Executive", "Board Report", "/agenttrust/board-report", "Board-ready AI agent governance report."),
    ("Executive", "Strategic Value Map", "/agenttrust/strategic-value-map", "Enterprise value map for AgentTrust™."),

    ("Strategy", "Agentic Operating Model", "/agenttrust/agentic-operating-model", "Operating model for governed AI agent deployment."),
    ("Strategy", "Readiness Roadmap", "/agenttrust/readiness-roadmap", "Roadmap for building AgentTrust™ maturity."),
    ("Strategy", "Platform Positioning", "/agenttrust/platform-positioning", "Market and product positioning for AgentTrust™.")
]


def agenttrust_kernel_route_rows():
    rows = ""

    for domain, page, url, purpose in AGENTTRUST_KERNEL_ROUTES:
        rows += f"""
        <tr>
            <td><span class="badge blue">{domain}</span></td>
            <td><strong>{page}</strong></td>
            <td>{purpose}</td>
            <td><a href="{url}">Open</a></td>
        </tr>
        """

    return rows


@app.route("/agenttrust/unified-kernel-index")
@app.route("/agenttrust/kernel-index")
@app.route("/agenttrust/complete-index")
@app.route("/agenttrust/full-index")
def agenttrust_unified_kernel_index():
    rows = agenttrust_kernel_route_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Kernel Status</div><div class="value" style="color:var(--green);">Unified</div><div class="note">All AgentTrust™ capabilities indexed.</div></div>
        <div class="metric"><div class="label">Governance Scope</div><div class="value" style="color:var(--blue);">End-to-End</div><div class="note">Identity, authority, evidence, runtime, lifecycle, ServiceNow, and audit defense.</div></div>
        <div class="metric"><div class="label">Operational Question</div><div class="value" style="color:var(--yellow);">Trust</div><div class="note">Can this AI agent be operationally trusted to act?</div></div>
        <div class="metric"><div class="label">Runtime Control</div><div class="value" style="color:var(--red);">Firewalled</div><div class="note">Unsafe execution is blocked, escalated, or quarantined.</div></div>
        <div class="metric"><div class="label">Audit Defense</div><div class="value" style="color:var(--purple);">Replayable</div><div class="note">Agent actions can be reconstructed from evidence.</div></div>
        <div class="metric"><div class="label">ServiceNow Link</div><div class="value" style="color:var(--orange);">Mapped</div><div class="note">CMDB, CSDM, access, change, ownership, and evidence bridge.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Unified Kernel Index</h2>
        <div class="answer">
            <strong>AgentTrust™ is now the COBIT-Chain™ AI Agentic Governance kernel.</strong>
            It brings AI agent identity, authority-before-execution, tool-call evidence, human accountability,
            runtime safety, lifecycle governance, regulatory routing, ServiceNow integration, metrics, and audit replay
            into one operational assurance model.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Domain</th>
                    <th>Capability</th>
                    <th>Purpose</th>
                    <th>Route</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Unified Kernel Index",
        "Complete master index for the AgentTrust™ AI Agentic Governance kernel across identity, authority, evidence, runtime, lifecycle, metrics, ServiceNow, and audit defense.",
        body
    )


@app.route("/agenttrust/agentic-operating-model")
@app.route("/agenttrust/operating-model")
@app.route("/agenttrust/ai-agent-operating-model")
def agenttrust_agentic_operating_model():
    body = """
    <section class="section">
        <h2>AgentTrust™ Agentic Operating Model</h2>
        <div class="answer">
            The AgentTrust™ operating model treats AI agents as governed operational actors.
            They must be known, owned, bounded, authorized, evidenced, monitored, human-accountable,
            lifecycle-governed, and audit-replayable before they can be trusted in enterprise workflows.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Operating Layer</th>
                    <th>Purpose</th>
                    <th>AgentTrust™ Capability</th>
                    <th>Output</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>1. Intake</td><td>Identify proposed AI agent and business purpose.</td><td>Agent Register</td><td>Agent intake record.</td></tr>
                <tr><td>2. Classification</td><td>Classify risk, autonomy, data, system, cyber, and GxP exposure.</td><td>Risk Tiering / GxP Exposure Score</td><td>Agent risk tier.</td></tr>
                <tr><td>3. Ownership</td><td>Assign accountable business, technical, risk, QA, and cyber owners.</td><td>Human Accountability Map</td><td>Ownership map.</td></tr>
                <tr><td>4. Passport</td><td>Document purpose, model, data, tools, authority, prohibited actions, and evidence.</td><td>Agent Risk Passport™</td><td>Approved passport.</td></tr>
                <tr><td>5. Readiness</td><td>Confirm identity, boundary, authority, evidence, accountability, risk, and rollback.</td><td>Readiness Gate</td><td>Go-live decision.</td></tr>
                <tr><td>6. Execution</td><td>Control action before execution.</td><td>Execution Firewall</td><td>Execute, human-gate, restrict, block, or quarantine.</td></tr>
                <tr><td>7. Evidence</td><td>Capture evidence at the time of action.</td><td>Tool-Call Evidence / Evidence Ledger</td><td>Evidence package.</td></tr>
                <tr><td>8. Monitoring</td><td>Monitor drift, runtime safety, exceptions, and governance debt.</td><td>Runtime Sentinel / Drift Sentinel / Governance Debt Register</td><td>Continuous assurance signal.</td></tr>
                <tr><td>9. Replay</td><td>Reconstruct what happened, why, who owned it, and what outcome occurred.</td><td>Decision Replay Studio</td><td>Audit defense package.</td></tr>
                <tr><td>10. Lifecycle</td><td>Govern changes, model updates, prompt/tool changes, and retirement.</td><td>Lifecycle Governance</td><td>Lifecycle evidence record.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Operating Model Rule</h2>
        <div class="answer">
            AgentTrust™ does not approve AI agents once and forget them.
            It continuously governs agent identity, authority, evidence, risk, ownership, runtime behavior, change, and retirement.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Agentic Operating Model",
        "Operating model for governing AI agents from intake to classification, ownership, passport, readiness, execution, evidence, monitoring, replay, and retirement.",
        body
    )


@app.route("/agenttrust/readiness-roadmap")
@app.route("/agenttrust/maturity-roadmap")
@app.route("/agenttrust/implementation-roadmap")
def agenttrust_readiness_roadmap():
    body = """
    <section class="section">
        <h2>AgentTrust™ Readiness Roadmap</h2>
        <p>
            This roadmap shows how an enterprise can move from uncontrolled AI agent experimentation
            to governed, evidence-backed, human-accountable, operationally trusted AI agents.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Phase</th>
                    <th>Readiness Focus</th>
                    <th>AgentTrust™ Build</th>
                    <th>Exit Criteria</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Phase 1 — Discover</td><td>Identify AI agents and agent-like automations.</td><td>Agent Register / Integration Map.</td><td>Known agent inventory.</td></tr>
                <tr><td>Phase 2 — Own</td><td>Assign business, technical, support, risk, QA, and cyber owners.</td><td>Human Accountability Map / LCM Bridge.</td><td>No ownerless live agents.</td></tr>
                <tr><td>Phase 3 — Bound</td><td>Define systems, data, tools, and prohibited actions.</td><td>Agent Passport / Operational Matrix.</td><td>Approved system boundary.</td></tr>
                <tr><td>Phase 4 — Authorize</td><td>Define what agents may read, recommend, draft, create, update, trigger, or never do.</td><td>Authority Gate / Chain of Authority.</td><td>Pre-execution authority model.</td></tr>
                <tr><td>Phase 5 — Evidence</td><td>Capture tool-call, input, output, owner, and outcome evidence.</td><td>Evidence Ledger / Evidence Package Builder.</td><td>Evidence at time of action.</td></tr>
                <tr><td>Phase 6 — Control Runtime</td><td>Stop unsafe agent execution.</td><td>Execution Firewall / Runtime Sentinel / Kill Switch.</td><td>Unsafe action can be blocked or quarantined.</td></tr>
                <tr><td>Phase 7 — Integrate</td><td>Link agents to ServiceNow, CMDB, CSDM, access, change, and evidence.</td><td>ServiceNow Integration Blueprint.</td><td>Agent mapped to enterprise governance backbone.</td></tr>
                <tr><td>Phase 8 — Assure</td><td>Measure trust, evidence, runtime safety, audit defensibility, and governance debt.</td><td>Metrics Engine / Continuous Assurance Scorecard.</td><td>Leadership scorecard operational.</td></tr>
                <tr><td>Phase 9 — Replay</td><td>Reconstruct AI action for audit, inspection, cyber, QA, or incident review.</td><td>Decision Replay Studio / Audit Defense Room.</td><td>Replay package available.</td></tr>
                <tr><td>Phase 10 — Improve</td><td>Govern lifecycle change, drift, retirement, and continuous improvement.</td><td>Lifecycle Governance / Drift Sentinel.</td><td>Trust remains current over time.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Roadmap Principle</h2>
        <div class="answer">
            AgentTrust™ maturity is not measured by how many AI agents are deployed.
            It is measured by how many AI agents are known, owned, bounded, authorized, evidenced, controlled, replayable, and continuously governed.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Readiness Roadmap",
        "Implementation roadmap for AI agent governance maturity, from discovery to ownership, authority, evidence, runtime control, integration, assurance, replay, and lifecycle improvement.",
        body
    )


@app.route("/agenttrust/platform-positioning")
@app.route("/agenttrust/market-positioning")
@app.route("/agenttrust/product-positioning")
def agenttrust_platform_positioning():
    body = """
    <section class="section">
        <h2>AgentTrust™ Platform Positioning</h2>
        <div class="answer">
            <strong>AgentTrust™ is the COBIT-Chain™ AI Agentic Governance Assurance module.</strong>
            It is designed for enterprises that want to scale AI agents without losing control over identity,
            authority, evidence, accountability, runtime safety, regulated impact, lifecycle governance, and audit defensibility.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Market Direction</th>
                    <th>What Enterprises Want</th>
                    <th>Governance Gap</th>
                    <th>AgentTrust™ Answer</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Autonomous AI agents</td><td>Faster workflow execution.</td><td>Who authorized the agent to act?</td><td>Authority Gate and Chain of Authority.</td></tr>
                <tr><td>AI workflow automation</td><td>AI that can trigger, update, and route work.</td><td>Can the agent act safely?</td><td>Execution Firewall and Runtime Sentinel.</td></tr>
                <tr><td>ServiceNow AI expansion</td><td>AI embedded into enterprise workflows.</td><td>How does AI link to CMDB, CSDM, access, change, and ownership?</td><td>ServiceNow Integration Blueprint.</td></tr>
                <tr><td>Regulated AI adoption</td><td>AI used in pharma, healthcare, quality, cyber, and audit workflows.</td><td>Can AI output be trusted in regulated operations?</td><td>GxP Impact Router and Regulatory Crosswalk.</td></tr>
                <tr><td>AI observability</td><td>Logs and monitoring.</td><td>Are logs enough to defend decisions?</td><td>Tool-Call Evidence, Evidence Lineage, and Decision Replay.</td></tr>
                <tr><td>AI governance programs</td><td>Policies and committees.</td><td>How does policy become operational control?</td><td>Control Library, Policy Router, and Metrics Engine.</td></tr>
                <tr><td>Executive AI assurance</td><td>Leadership confidence.</td><td>Can leadership defend AI agent reliance?</td><td>Executive Dashboard, Trust Heatmap, Board Report, and Audit Defense Room.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Final Positioning Statement</h2>
        <div class="answer">
            <strong>AgentTrust™ makes AI agents operationally defensible.</strong>
            It turns autonomous AI from an execution problem into a governed assurance model:
            known agent, known owner, known authority, known evidence, known risk, known accountability, known outcome.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Platform Positioning",
        "Product and market positioning for AgentTrust™ as the COBIT-Chain™ AI Agentic Governance Assurance module.",
        body
    )

# ============================================================
# END AGENTTRUST_UNIFIED_KERNEL_INDEX_V1_ACTIVE
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

print("AgentTrust Unified Kernel Index installed.")
print(f"Inserted before: {target_found}")
