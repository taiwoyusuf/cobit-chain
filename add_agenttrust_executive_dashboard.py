from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_EXECUTIVE_ASSURANCE_DASHBOARD_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust Executive Assurance Dashboard already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base module not found. Install AgentTrust module first.")

nav_old = '<a href="/agenttrust/lifecycle-governance" class="secondary">Lifecycle</a>'
nav_new = '''<a href="/agenttrust/lifecycle-governance" class="secondary">Lifecycle</a>
                    <a href="/agenttrust/executive-assurance-dashboard" class="secondary">Executive Dashboard</a>
                    <a href="/agenttrust/master-index" class="dark">Master Index</a>
                    <a href="/agenttrust/trust-heatmap" class="dark">Trust Heatmap</a>
                    <a href="/agenttrust/board-report" class="dark">Board Report</a>'''

if nav_old in text and "/agenttrust/executive-assurance-dashboard" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# AGENTTRUST_EXECUTIVE_ASSURANCE_DASHBOARD_V1_ACTIVE
# AgentTrust™ Executive Assurance Dashboard, Master Index,
# Trust Heatmap, Board Report, Module Sitemap, and Strategic Value Map
# ============================================================

AGENTTRUST_MASTER_INDEX = [
    ("Core Module", "AgentTrust™ Home", "/agenttrust", "Primary module landing page for AI Agentic Governance."),
    ("Core Module", "Integration Map", "/agenttrust/integration-map", "Tracks AgentTrust™ hooks across COBIT-Chain™ modules."),
    ("Identity", "Agent Register", "/agenttrust/agent-register", "Registers AI agents as governed digital assets."),
    ("Passport", "Agent Risk Passport", "/agenttrust/agent-passport", "Defines agent purpose, model, data, tools, authority, risk, and evidence."),
    ("Authority", "Authority Gate", "/agenttrust/authority-gate", "Confirms authority before AI agent execution."),
    ("Evidence", "Tool-Call Evidence", "/agenttrust/tool-call-evidence", "Logs API calls, workflow triggers, data access, and decision paths."),
    ("Accountability", "Human Accountability", "/agenttrust/human-accountability", "Maps every agent action to responsible human owners."),
    ("Regulatory", "AI Act Readiness", "/agenttrust/ai-act-readiness", "Maps AI agents to AI Act-style readiness obligations."),
    ("Evidence", "Evidence Ledger", "/agenttrust/evidence-ledger", "Captures evidence at the time of action."),
    ("Operations", "Command Center", "/agenttrust/command-center", "Operational command center for AI agent trust decisions."),
    ("Readiness", "Readiness Gate", "/agenttrust/readiness-gate", "Go-live readiness gate for AI agents."),
    ("Risk", "Risk Tiering", "/agenttrust/risk-tiering", "Classifies agent risk by capability and operational impact."),
    ("Controls", "Control Library", "/agenttrust/control-library", "Core controls for identity, authority, evidence, accountability, and rollback."),
    ("Operations", "Operational Matrix", "/agenttrust/operational-matrix", "Defines what agents may read, recommend, draft, create, update, trigger, or approve."),
    ("Passport", "Passport Factory", "/agenttrust/passport-factory", "Generates Agent Risk Passport™ structure."),
    ("Register", "Sample Agent Register", "/agenttrust/sample-agent-register", "Sample inventory of governed AI agents."),
    ("Scoring", "Trust Score Engine", "/agenttrust/trust-score-engine", "Scores operational trust from 0 to 100."),
    ("Evidence", "Evidence Package Builder", "/agenttrust/evidence-package-builder", "Builds audit-ready evidence packages."),
    ("Escalation", "Escalation Router", "/agenttrust/escalation-rules", "Routes ownership, authority, cyber, QA, and evidence gaps."),
    ("Regulatory", "Regulatory Crosswalk", "/agenttrust/regulatory-crosswalk", "Maps AI agents to governance and regulatory lenses."),
    ("COBIT", "COBIT Control Map", "/agenttrust/cobit-crosswalk", "Translates COBIT-style governance into AI agent controls."),
    ("GxP", "GxP Impact Router", "/agenttrust/gxp-impact-router", "Routes regulated-impact agents to QA and validation review."),
    ("Policy", "AI Policy Router", "/agenttrust/ai-policy-router", "Routes AI agent actions through the correct governance lane."),
    ("Control Tower", "Enterprise Control Tower", "/agenttrust/enterprise-control-tower", "Leadership view of agent ownership, authority, evidence, and risk."),
    ("Runtime", "Execution Firewall", "/agenttrust/execution-firewall", "Prevents agents from executing outside approved authority."),
    ("Runtime", "Prohibited Action Sentinel", "/agenttrust/prohibited-action-sentinel", "Blocks or human-gates forbidden AI agent actions."),
    ("Runtime", "Runtime Sentinel", "/agenttrust/runtime-sentinel", "Monitors authority drift, boundary violations, evidence gaps, and unsafe patterns."),
    ("Runtime", "Kill Switch", "/agenttrust/agent-kill-switch", "Defines stop-control for unsafe AI agent execution."),
    ("Runtime", "Drift Sentinel", "/agenttrust/drift-sentinel", "Detects model, tool, data, authority, ownership, and evidence drift."),
    ("Runtime", "Trust Quarantine", "/agenttrust/trust-quarantine", "Isolates unsafe or unresolved AI agents."),
    ("Replay", "Decision Replay Studio", "/agenttrust/decision-replay-studio", "Reconstructs what the AI agent did and why."),
    ("Replay", "Evidence Lineage Engine", "/agenttrust/evidence-lineage-engine", "Maps source data to AI action to human review to outcome."),
    ("Replay", "Action Timeline", "/agenttrust/action-timeline", "Shows request, boundary, authority, risk, evidence, action, review, and outcome."),
    ("Replay", "Chain of Authority", "/agenttrust/chain-of-authority", "Shows who allowed the AI agent to act."),
    ("Replay", "Audit Defense Room", "/agenttrust/audit-defense-room", "Organizes AI evidence into audit-ready Q&A."),
    ("Replay", "Immutable Evidence Ledger", "/agenttrust/immutable-evidence-ledger", "Preserves authority, input, tool, output, human, and outcome records."),
    ("Replay", "Incident Reconstruction", "/agenttrust/incident-reconstruction", "Reconstructs AI agent incidents from evidence."),
    ("Lifecycle", "Lifecycle Governance", "/agenttrust/lifecycle-governance", "Governs agents from proposal to retirement."),
    ("Lifecycle", "Change Control Gate", "/agenttrust/change-control-gate", "Controls changes to purpose, boundary, data, tools, authority, and risk."),
    ("Lifecycle", "Model Change Gate", "/agenttrust/model-change-gate", "Controls model version, provider, configuration, and capability changes."),
    ("Lifecycle", "Prompt & Tool Change Gate", "/agenttrust/prompt-tool-change-gate", "Controls prompt, tool, API, retrieval, and workflow changes."),
    ("Lifecycle", "Review Cadence", "/agenttrust/review-cadence", "Defines periodic review for ownership, authority, tools, evidence, risk, and GxP impact."),
    ("Lifecycle", "Decommissioning Gate", "/agenttrust/decommissioning-gate", "Controls retirement, access removal, evidence archive, and post-retirement checks."),
    ("Lifecycle", "Lifecycle Evidence Register", "/agenttrust/lifecycle-evidence-register", "Defines evidence required at each lifecycle stage.")
]


def agenttrust_master_index_rows():
    rows = ""

    for category, name, url, purpose in AGENTTRUST_MASTER_INDEX:
        rows += f"""
        <tr>
            <td><span class="badge blue">{category}</span></td>
            <td><strong>{name}</strong></td>
            <td>{purpose}</td>
            <td><a href="{url}">Open</a></td>
        </tr>
        """

    return rows


@app.route("/agenttrust/executive-assurance-dashboard")
@app.route("/agenttrust/executive-dashboard")
@app.route("/agenttrust/assurance-dashboard")
def agenttrust_executive_assurance_dashboard():
    body = """
    <section class="kpis">
        <div class="metric"><div class="label">Agent Identity</div><div class="value" style="color:var(--green);">Known</div><div class="note">AI agents must have ID, owner, role, and lifecycle status.</div></div>
        <div class="metric"><div class="label">Authority</div><div class="value" style="color:var(--yellow);">Pre-Gated</div><div class="note">No agent action without confirmed authority.</div></div>
        <div class="metric"><div class="label">Evidence</div><div class="value" style="color:var(--blue);">At Action</div><div class="note">Evidence captured when the action occurs.</div></div>
        <div class="metric"><div class="label">Human Owner</div><div class="value" style="color:var(--orange);">Mapped</div><div class="note">Every action links to accountable humans.</div></div>
        <div class="metric"><div class="label">Runtime Safety</div><div class="value" style="color:var(--red);">Firewalled</div><div class="note">Unsafe actions are blocked, restricted, escalated, or quarantined.</div></div>
        <div class="metric"><div class="label">Audit Defense</div><div class="value" style="color:var(--purple);">Replayable</div><div class="note">Agent actions can be reconstructed and defended.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Executive Assurance Dashboard</h2>
        <div class="answer">
            <strong>Executive question:</strong> Can leadership trust AI agents to operate inside enterprise, regulated,
            cyber, access, ServiceNow, CMDB, cutover, and GxP workflows without losing authority, evidence, accountability,
            risk control, and audit defensibility?
        </div>

        <div class="grid">
            <div class="card"><span class="badge green">Identity</span><h3>Known AI Agents</h3><p>Every AI agent must be registered with owner, role, purpose, boundary, and lifecycle status.</p><a href="/agenttrust/agent-register">Open Agent Register</a></div>
            <div class="card"><span class="badge yellow">Authority</span><h3>Authority Before Execution</h3><p>Agents cannot act unless action authority is confirmed before execution.</p><a href="/agenttrust/authority-gate">Open Authority Gate</a></div>
            <div class="card"><span class="badge blue">Evidence</span><h3>Tool-Call Evidence</h3><p>Every API call, workflow trigger, data access, and decision path is logged.</p><a href="/agenttrust/tool-call-evidence">Open Evidence Ledger</a></div>
            <div class="card"><span class="badge orange">Accountability</span><h3>Human Accountability</h3><p>Every autonomous or semi-autonomous action maps to a responsible human owner.</p><a href="/agenttrust/human-accountability">Open Accountability Map</a></div>
            <div class="card"><span class="badge red">Runtime</span><h3>Execution Firewall</h3><p>Agent actions are executed, human-gated, restricted, blocked, or quarantined based on governance checks.</p><a href="/agenttrust/execution-firewall">Open Execution Firewall</a></div>
            <div class="card"><span class="badge purple">Audit</span><h3>Decision Replay</h3><p>Agent action can be reconstructed from authority, evidence, tool calls, human owner, and outcome.</p><a href="/agenttrust/decision-replay-studio">Open Decision Replay</a></div>
            <div class="card"><span class="badge red">GxP</span><h3>Regulated Impact</h3><p>Agents touching GMP, QA, validation, QC, batch, release, or inspection evidence are human-governed.</p><a href="/agenttrust/gxp-impact-router">Open GxP Router</a></div>
            <div class="card"><span class="badge green">Lifecycle</span><h3>Lifecycle Governance</h3><p>Agents are governed from proposal through change, monitoring, suspension, retirement, and evidence preservation.</p><a href="/agenttrust/lifecycle-governance">Open Lifecycle</a></div>
        </div>
    </section>

    <section class="section">
        <h2>Leadership Assurance Matrix</h2>
        <table>
            <thead>
                <tr>
                    <th>Executive Concern</th>
                    <th>AgentTrust™ Assurance Layer</th>
                    <th>Evidence Produced</th>
                    <th>Trust Result</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Unknown AI agents</td><td>Agent Register</td><td>Agent ID, owner, purpose, lifecycle status.</td><td><span class="badge green">Known and owned</span></td></tr>
                <tr><td>Unauthorized action</td><td>Authority Gate and Execution Firewall</td><td>Decision rights, permitted actions, approval route.</td><td><span class="badge yellow">Pre-gated</span></td></tr>
                <tr><td>Invisible AI execution</td><td>Tool-Call Evidence Ledger</td><td>API calls, workflow triggers, data access, timestamps.</td><td><span class="badge blue">Observable</span></td></tr>
                <tr><td>No human accountability</td><td>Human Accountability Map</td><td>Business owner, technical owner, risk owner, QA/cyber owner.</td><td><span class="badge orange">Accountable</span></td></tr>
                <tr><td>Regulated impact</td><td>GxP Impact Router</td><td>QA review, validation impact, regulated evidence package.</td><td><span class="badge red">Human-governed</span></td></tr>
                <tr><td>Audit weakness</td><td>Decision Replay and Audit Defense Room</td><td>Timeline, authority, evidence, owner, outcome.</td><td><span class="badge purple">Defensible</span></td></tr>
                <tr><td>Governance drift</td><td>Drift Sentinel and Lifecycle Governance</td><td>Change record, model/tool/prompt review, monitoring cadence.</td><td><span class="badge yellow">Continuously governed</span></td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Executive Assurance Dashboard",
        "Leadership dashboard for AI agent identity, authority, evidence, accountability, runtime safety, lifecycle governance, and audit defense.",
        body
    )


@app.route("/agenttrust/master-index")
@app.route("/agenttrust/module-index")
@app.route("/agenttrust/sitemap")
def agenttrust_master_index():
    rows = agenttrust_master_index_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Master Index</h2>
        <p>
            This index gives one access point to every AgentTrust™ page, route, capability, governance artifact,
            and operating layer currently installed in COBIT-Chain™.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Domain</th>
                    <th>Page</th>
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
        "AgentTrust™ Master Index",
        "Complete sitemap and capability index for the AgentTrust™ AI Agentic Governance module.",
        body
    )


@app.route("/agenttrust/trust-heatmap")
@app.route("/agenttrust/executive-trust-heatmap")
@app.route("/agenttrust/agent-risk-heatmap")
def agenttrust_trust_heatmap():
    body = """
    <section class="section">
        <h2>AgentTrust™ Trust Heatmap</h2>
        <p>
            The Trust Heatmap shows how AI agent trust changes across identity, authority, evidence, human accountability,
            runtime safety, regulated impact, lifecycle control, and audit replay.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Trust Domain</th>
                    <th>Strong Signal</th>
                    <th>Weak Signal</th>
                    <th>Executive Risk</th>
                    <th>Heatmap Status</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Identity</td><td>Agent ID and owner complete.</td><td>Agent is unnamed or ownerless.</td><td>Unknown AI actor.</td><td><span class="badge green">Low if complete</span></td></tr>
                <tr><td>Authority</td><td>Action level and decision rights approved.</td><td>Agent can act without approval rule.</td><td>Unauthorized execution.</td><td><span class="badge red">High if missing</span></td></tr>
                <tr><td>Evidence</td><td>Tool-call and timestamp captured.</td><td>Evidence reconstructed later.</td><td>Audit replay weakness.</td><td><span class="badge orange">Medium / High</span></td></tr>
                <tr><td>Human Accountability</td><td>Business, technical, risk, QA/cyber owners mapped.</td><td>No human owner for agent action.</td><td>Accountability gap.</td><td><span class="badge red">High if missing</span></td></tr>
                <tr><td>Runtime Safety</td><td>Execution firewall, sentinel, kill switch active.</td><td>Agent acts without runtime checks.</td><td>Unsafe autonomy.</td><td><span class="badge red">High if uncontrolled</span></td></tr>
                <tr><td>GxP / QA Impact</td><td>QA and validation impact routed.</td><td>Agent influences regulated evidence without QA review.</td><td>Inspection and quality risk.</td><td><span class="badge red">Critical</span></td></tr>
                <tr><td>Lifecycle</td><td>Change, model, prompt, tool, and retirement gates defined.</td><td>Agent changes without governance review.</td><td>Governance drift.</td><td><span class="badge orange">Medium / High</span></td></tr>
                <tr><td>Replay</td><td>Action timeline and evidence lineage complete.</td><td>Action cannot be reconstructed.</td><td>Defensibility failure.</td><td><span class="badge red">High if absent</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Heatmap Rule</h2>
        <div class="answer">
            The highest-risk AI agent is not the most powerful model. It is the agent that can act without identity,
            authority, evidence, human accountability, runtime control, and replayable proof.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Trust Heatmap",
        "Executive heatmap for AI agent trust, weakness, runtime risk, regulated impact, and audit defensibility.",
        body
    )


@app.route("/agenttrust/board-report")
@app.route("/agenttrust/executive-board-report")
@app.route("/agenttrust/leadership-report")
def agenttrust_board_report():
    body = """
    <section class="section">
        <h2>AgentTrust™ Executive Board Report</h2>
        <div class="answer">
            <strong>Board-level statement:</strong> AgentTrust™ provides the governance assurance layer required to scale AI agents safely.
            It ensures AI agents are known, owned, bounded, authorized, evidenced, human-accountable, monitored, and auditable.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Board Question</th>
                    <th>AgentTrust™ Answer</th>
                    <th>Assurance Evidence</th>
                    <th>Decision Support</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Do we know which AI agents exist?</td><td>Yes, through the Agent Register.</td><td>Agent ID, owner, purpose, lifecycle status.</td><td>Approve inventory and ownership model.</td></tr>
                <tr><td>Can AI agents act without authority?</td><td>No, action must pass Authority Gate and Execution Firewall.</td><td>Decision rights, permitted actions, approval route.</td><td>Require pre-execution governance.</td></tr>
                <tr><td>Can we prove what agents did?</td><td>Yes, through tool-call evidence and decision replay.</td><td>API calls, workflow triggers, input, output, timestamp, outcome.</td><td>Support audit and investigation readiness.</td></tr>
                <tr><td>Who is accountable when AI acts?</td><td>Human owners remain accountable.</td><td>Business, technical, risk, QA, cyber, and process owner map.</td><td>Prevent hidden AI decision-making.</td></tr>
                <tr><td>What if the AI agent becomes unsafe?</td><td>Runtime Sentinel, Kill Switch, and Trust Quarantine stop unsafe autonomy.</td><td>Block, escalation, quarantine, and recovery evidence.</td><td>Support safe AI operations.</td></tr>
                <tr><td>What if the agent touches regulated operations?</td><td>GxP Impact Router escalates to QA and validation review.</td><td>Impact assessment, QA decision, validation evidence.</td><td>Prevent ungoverned regulated AI reliance.</td></tr>
                <tr><td>Can agent activity survive audit?</td><td>Yes, if replay package is complete.</td><td>Authority, evidence, owner, action timeline, outcome.</td><td>Support inspection defensibility.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Executive Recommendation</h2>
        <div class="answer">
            Leadership should treat AI agents as governed operational actors, not just software features.
            AgentTrust™ gives COBIT-Chain™ a defensible method to control agent identity, authority, execution, evidence,
            accountability, regulated impact, lifecycle change, and audit replay.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Executive Board Report",
        "Board-ready report for AI agent governance, operational trust, risk, accountability, evidence, and regulated assurance.",
        body
    )


@app.route("/agenttrust/strategic-value-map")
@app.route("/agenttrust/value-map")
@app.route("/agenttrust/business-value-map")
def agenttrust_strategic_value_map():
    body = """
    <section class="section">
        <h2>AgentTrust™ Strategic Value Map</h2>
        <p>
            This page explains the value of AgentTrust™ across enterprise governance, regulated operations,
            ServiceNow AI, cybersecurity, audit readiness, and executive decision-making.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Enterprise Problem</th>
                    <th>AgentTrust™ Capability</th>
                    <th>Business Value</th>
                    <th>Strategic Outcome</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>AI agents are hard to inventory.</td><td>Agent Register and Passport Factory.</td><td>Creates governed inventory and ownership.</td><td><span class="badge green">Known AI estate</span></td></tr>
                <tr><td>AI actions may bypass authority.</td><td>Authority Gate and Execution Firewall.</td><td>Prevents unauthorized agent execution.</td><td><span class="badge yellow">Controlled autonomy</span></td></tr>
                <tr><td>AI evidence is weak or reconstructed.</td><td>Tool-Call Evidence and Immutable Evidence Ledger.</td><td>Captures evidence at time of action.</td><td><span class="badge blue">Defensible evidence</span></td></tr>
                <tr><td>AI accountability is unclear.</td><td>Human Accountability Map.</td><td>Preserves human ownership and responsibility.</td><td><span class="badge orange">Accountable AI operations</span></td></tr>
                <tr><td>AI touches regulated workflows.</td><td>GxP Impact Router and Regulatory Crosswalk.</td><td>Routes AI impact to QA, validation, cyber, and risk owners.</td><td><span class="badge red">Regulated-safe AI adoption</span></td></tr>
                <tr><td>AI behavior changes over time.</td><td>Lifecycle Governance and Drift Sentinel.</td><td>Controls model, prompt, tool, data, owner, and boundary changes.</td><td><span class="badge purple">Continuous governance</span></td></tr>
                <tr><td>Auditors ask what the agent did.</td><td>Decision Replay Studio and Audit Defense Room.</td><td>Reconstructs action from evidence, authority, owner, and outcome.</td><td><span class="badge green">Audit-ready AI</span></td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Strategic Value Map",
        "Enterprise value map for AI agent governance, operational trust, regulated assurance, and audit defensibility.",
        body
    )

# ============================================================
# END AGENTTRUST_EXECUTIVE_ASSURANCE_DASHBOARD_V1_ACTIVE
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

print("AgentTrust Executive Assurance Dashboard installed.")
print(f"Inserted before: {target_found}")
