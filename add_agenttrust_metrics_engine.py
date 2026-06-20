from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_METRICS_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust Metrics Engine already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base module not found. Install AgentTrust module first.")

nav_old = '<a href="/agenttrust/executive-assurance-dashboard" class="secondary">Executive Dashboard</a>'
nav_new = '''<a href="/agenttrust/executive-assurance-dashboard" class="secondary">Executive Dashboard</a>
                    <a href="/agenttrust/metrics-engine" class="secondary">Metrics Engine</a>
                    <a href="/agenttrust/agent-trust-index" class="dark">Trust Index</a>
                    <a href="/agenttrust/evidence-sufficiency-dashboard" class="dark">Evidence Score</a>
                    <a href="/agenttrust/kpi-catalog" class="dark">KPI Catalog</a>'''

if nav_old in text and "/agenttrust/metrics-engine" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# AGENTTRUST_METRICS_ENGINE_V1_ACTIVE
# AgentTrust™ Metrics Engine, Agent Trust Index, Evidence
# Sufficiency Dashboard, Control Coverage Matrix, KPI Catalog,
# Continuous Assurance Scorecard, and Governance Debt Register
# ============================================================

AGENTTRUST_KPI_CATALOG = [
    {
        "kpi": "Agent Trust Index",
        "domain": "Overall Assurance",
        "formula": "Composite score of identity, authority, evidence, accountability, runtime safety, lifecycle, and audit replay.",
        "threshold": "90+ trusted, 80-89 human-gated, 70-79 restricted, below 70 blocked or escalated."
    },
    {
        "kpi": "Authority Compliance Rate",
        "domain": "Authority",
        "formula": "Agent actions with pre-confirmed authority divided by total agent actions.",
        "threshold": "Target: 100% for execution actions."
    },
    {
        "kpi": "Evidence Sufficiency Score",
        "domain": "Evidence",
        "formula": "Actions with complete tool-call, timestamp, input, output, owner, and outcome evidence.",
        "threshold": "Target: 95%+ for operational agents."
    },
    {
        "kpi": "Human Accountability Completeness",
        "domain": "Accountability",
        "formula": "Agents with business, technical, risk, and applicable QA/cyber owner assigned.",
        "threshold": "Target: 100% for live agents."
    },
    {
        "kpi": "Runtime Safety Score",
        "domain": "Runtime",
        "formula": "Execution firewall, sentinel, kill switch, quarantine, and rollback controls present and active.",
        "threshold": "Target: 90%+ for agents with execution capability."
    },
    {
        "kpi": "GxP Exposure Score",
        "domain": "Regulated Impact",
        "formula": "Measures whether agents touch GMP, QA, validation, QC, batch, release, or inspection evidence.",
        "threshold": "High exposure requires QA and validation review."
    },
    {
        "kpi": "Audit Defensibility Score",
        "domain": "Audit Replay",
        "formula": "Completeness of action timeline, authority lineage, evidence lineage, human review, and outcome package.",
        "threshold": "Target: 90%+ for regulated or high-risk agents."
    },
    {
        "kpi": "Lifecycle Governance Score",
        "domain": "Lifecycle",
        "formula": "Completeness of proposal, design, review, approval, monitoring, change, suspension, and retirement evidence.",
        "threshold": "Target: 90%+ for production agents."
    }
]


def agenttrust_kpi_catalog_rows():
    rows = ""

    for item in AGENTTRUST_KPI_CATALOG:
        rows += f"""
        <tr>
            <td><strong>{item["kpi"]}</strong></td>
            <td><span class="badge blue">{item["domain"]}</span></td>
            <td>{item["formula"]}</td>
            <td>{item["threshold"]}</td>
        </tr>
        """

    return rows


@app.route("/agenttrust/metrics-engine")
@app.route("/agenttrust/assurance-metrics")
@app.route("/agenttrust/governance-metrics")
def agenttrust_metrics_engine():
    body = """
    <section class="kpis">
        <div class="metric"><div class="label">Agent Trust Index</div><div class="value" style="color:var(--green);">86</div><div class="note">Composite operational trust score.</div></div>
        <div class="metric"><div class="label">Authority Compliance</div><div class="value" style="color:var(--yellow);">92%</div><div class="note">Actions with confirmed pre-execution authority.</div></div>
        <div class="metric"><div class="label">Evidence Sufficiency</div><div class="value" style="color:var(--blue);">88%</div><div class="note">Actions with complete evidence package.</div></div>
        <div class="metric"><div class="label">Human Accountability</div><div class="value" style="color:var(--orange);">95%</div><div class="note">Agents with accountable human owner mapped.</div></div>
        <div class="metric"><div class="label">Runtime Safety</div><div class="value" style="color:var(--red);">81%</div><div class="note">Firewall, sentinel, rollback, and kill switch coverage.</div></div>
        <div class="metric"><div class="label">Audit Defensibility</div><div class="value" style="color:var(--purple);">89%</div><div class="note">Replay package completeness.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Metrics Engine</h2>
        <div class="answer">
            <strong>Purpose:</strong> convert AI agent governance into measurable assurance metrics.
            The Metrics Engine helps leadership see whether AI agents are not only powerful, but operationally trusted,
            evidence-backed, human-accountable, runtime-controlled, lifecycle-governed, and audit-defensible.
        </div>

        <div class="grid">
            <div class="card"><span class="badge green">ATI</span><h3>Agent Trust Index</h3><p>Composite score showing whether an AI agent can be operationally trusted.</p><a href="/agenttrust/agent-trust-index">Open Trust Index</a></div>
            <div class="card"><span class="badge yellow">Authority</span><h3>Authority Compliance</h3><p>Measures whether actions had authority before execution.</p><a href="/agenttrust/control-coverage-matrix">Open Control Coverage</a></div>
            <div class="card"><span class="badge blue">Evidence</span><h3>Evidence Sufficiency</h3><p>Measures whether enough time-of-action evidence exists to defend the agent action.</p><a href="/agenttrust/evidence-sufficiency-dashboard">Open Evidence Score</a></div>
            <div class="card"><span class="badge orange">Accountability</span><h3>Human Ownership</h3><p>Measures whether every agent and action maps to an accountable human owner.</p><a href="/agenttrust/continuous-assurance-scorecard">Open Scorecard</a></div>
            <div class="card"><span class="badge red">Runtime</span><h3>Runtime Safety</h3><p>Measures firewall, sentinel, kill switch, quarantine, and rollback coverage.</p><a href="/agenttrust/runtime-safety-score">Open Runtime Score</a></div>
            <div class="card"><span class="badge purple">Audit</span><h3>Audit Defensibility</h3><p>Measures whether the agent action can be replayed and defended.</p><a href="/agenttrust/audit-defensibility-score">Open Audit Score</a></div>
            <div class="card"><span class="badge red">GxP</span><h3>Regulated Exposure</h3><p>Measures whether AI agents touch GxP, QA, validation, QC, release, or inspection evidence.</p><a href="/agenttrust/gxp-exposure-score">Open GxP Score</a></div>
            <div class="card"><span class="badge blue">Debt</span><h3>Governance Debt</h3><p>Tracks missing owners, stale exceptions, weak evidence, open risks, and lifecycle gaps.</p><a href="/agenttrust/governance-debt-register">Open Debt Register</a></div>
        </div>
    </section>

    <section class="section">
        <h2>Executive Metrics Logic</h2>
        <table>
            <thead>
                <tr>
                    <th>Metric Area</th>
                    <th>Strong Signal</th>
                    <th>Weak Signal</th>
                    <th>Leadership Action</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Identity</td><td>All agents have ID, owner, purpose, lifecycle status.</td><td>Unknown or ownerless agents.</td><td><span class="badge red">Assign owner or block</span></td></tr>
                <tr><td>Authority</td><td>All execution actions are pre-authorized.</td><td>Agent acts without decision rights.</td><td><span class="badge red">Enforce authority gate</span></td></tr>
                <tr><td>Evidence</td><td>Evidence captured at action time.</td><td>Evidence reconstructed later.</td><td><span class="badge orange">Restrict execution</span></td></tr>
                <tr><td>Accountability</td><td>Human owner mapped to every action.</td><td>AI becomes hidden decision-maker.</td><td><span class="badge red">Require accountable owner</span></td></tr>
                <tr><td>Runtime</td><td>Firewall, sentinel, kill switch, rollback present.</td><td>Agent executes without runtime safety.</td><td><span class="badge red">Block unsafe autonomy</span></td></tr>
                <tr><td>Audit</td><td>Replay package is complete.</td><td>Action cannot be reconstructed.</td><td><span class="badge orange">Improve evidence lineage</span></td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Metrics Engine",
        "Governance metrics engine for AI agent operational trust, authority, evidence, accountability, runtime safety, GxP exposure, lifecycle, and audit defensibility.",
        body
    )


@app.route("/agenttrust/agent-trust-index")
@app.route("/agenttrust/trust-index")
@app.route("/agenttrust/ati")
def agenttrust_agent_trust_index():
    body = """
    <section class="section">
        <h2>AgentTrust™ Agent Trust Index</h2>
        <div class="answer">
            The Agent Trust Index is a composite score that answers:
            <strong>Can this AI agent be operationally trusted to act?</strong>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Trust Domain</th>
                    <th>Weight</th>
                    <th>Evidence Required</th>
                    <th>Why It Matters</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Identity</td><td>12%</td><td>Agent ID, name, owner, purpose, lifecycle status.</td><td>Prevents unknown AI agents.</td></tr>
                <tr><td>Ownership</td><td>12%</td><td>Business owner, technical owner, support group.</td><td>Ensures accountability exists.</td></tr>
                <tr><td>Authority</td><td>16%</td><td>Action permissions, approval rule, decision rights.</td><td>Prevents unauthorized action.</td></tr>
                <tr><td>System Boundary</td><td>12%</td><td>Approved systems, APIs, tools, data sources.</td><td>Prevents scope creep and boundary violation.</td></tr>
                <tr><td>Evidence</td><td>16%</td><td>Tool-call logs, input, output, timestamp, outcome.</td><td>Supports audit replay.</td></tr>
                <tr><td>Human Accountability</td><td>10%</td><td>Reviewer, approver, accountable human, escalation owner.</td><td>Prevents hidden AI decision-making.</td></tr>
                <tr><td>Runtime Safety</td><td>12%</td><td>Execution firewall, sentinel, kill switch, rollback.</td><td>Controls unsafe autonomy.</td></tr>
                <tr><td>Lifecycle Governance</td><td>10%</td><td>Change gate, model review, prompt/tool review, retirement evidence.</td><td>Controls drift over time.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Trust Index Decision Rule</h2>
        <table>
            <thead>
                <tr>
                    <th>Score</th>
                    <th>Status</th>
                    <th>Permitted Use</th>
                    <th>Governance Decision</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>90-100</td><td><span class="badge green">Operationally Trusted</span></td><td>Can operate inside approved boundary.</td><td>Monitor continuously.</td></tr>
                <tr><td>80-89</td><td><span class="badge yellow">Human-Gated Trusted</span></td><td>Can recommend, draft, or act with human approval.</td><td>Close remaining gaps.</td></tr>
                <tr><td>70-79</td><td><span class="badge orange">Restricted</span></td><td>Limited use only. No critical execution.</td><td>Fix authority, evidence, owner, or runtime gaps.</td></tr>
                <tr><td>0-69</td><td><span class="badge red">Blocked / Escalate</span></td><td>No operational execution.</td><td>Escalate to governance, QA, cyber, or risk owner.</td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Agent Trust Index",
        "Composite trust index for AI agent identity, ownership, authority, boundary, evidence, accountability, runtime safety, and lifecycle governance.",
        body
    )


@app.route("/agenttrust/control-coverage-matrix")
@app.route("/agenttrust/control-coverage")
@app.route("/agenttrust/assurance-control-coverage")
def agenttrust_control_coverage_matrix():
    body = """
    <section class="section">
        <h2>AgentTrust™ Control Coverage Matrix</h2>
        <p>
            The Control Coverage Matrix shows whether each AI agent has the minimum governance controls required for its risk tier and action level.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Control Area</th>
                    <th>Tier 0-1</th>
                    <th>Tier 2</th>
                    <th>Tier 3-4</th>
                    <th>Tier 5 / Regulated</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent Register</td><td><span class="badge green">Required</span></td><td><span class="badge green">Required</span></td><td><span class="badge green">Required</span></td><td><span class="badge green">Required</span></td></tr>
                <tr><td>Agent Risk Passport™</td><td><span class="badge yellow">Basic</span></td><td><span class="badge green">Required</span></td><td><span class="badge green">Required</span></td><td><span class="badge red">Full QA-reviewed</span></td></tr>
                <tr><td>Authority Gate</td><td><span class="badge yellow">Read scope</span></td><td><span class="badge green">Recommendation gate</span></td><td><span class="badge red">Execution gate</span></td><td><span class="badge red">Human-governed</span></td></tr>
                <tr><td>Tool-Call Evidence</td><td><span class="badge yellow">Access log</span></td><td><span class="badge green">Required</span></td><td><span class="badge red">Required</span></td><td><span class="badge red">Inspection-ready</span></td></tr>
                <tr><td>Human Accountability</td><td><span class="badge green">Owner</span></td><td><span class="badge green">Reviewer</span></td><td><span class="badge red">Approver</span></td><td><span class="badge red">QA / validation owner</span></td></tr>
                <tr><td>Execution Firewall</td><td><span class="badge blue">Optional</span></td><td><span class="badge yellow">Recommended</span></td><td><span class="badge red">Required</span></td><td><span class="badge red">Required</span></td></tr>
                <tr><td>Runtime Sentinel</td><td><span class="badge blue">Optional</span></td><td><span class="badge yellow">Recommended</span></td><td><span class="badge red">Required</span></td><td><span class="badge red">Required</span></td></tr>
                <tr><td>Decision Replay</td><td><span class="badge yellow">Basic</span></td><td><span class="badge green">Required</span></td><td><span class="badge red">Required</span></td><td><span class="badge red">Inspection-ready</span></td></tr>
                <tr><td>Lifecycle Change Gate</td><td><span class="badge yellow">Owner review</span></td><td><span class="badge green">Required</span></td><td><span class="badge red">Required</span></td><td><span class="badge red">QA / validation review</span></td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Control Coverage Matrix",
        "Control coverage matrix by AI agent risk tier, action capability, and regulated impact.",
        body
    )


@app.route("/agenttrust/evidence-sufficiency-dashboard")
@app.route("/agenttrust/evidence-sufficiency-score")
@app.route("/agenttrust/evidence-score")
def agenttrust_evidence_sufficiency_dashboard():
    body = """
    <section class="kpis">
        <div class="metric"><div class="label">Input Evidence</div><div class="value" style="color:var(--green);">94%</div><div class="note">Prompt, source data, and context captured.</div></div>
        <div class="metric"><div class="label">Authority Evidence</div><div class="value" style="color:var(--yellow);">91%</div><div class="note">Pre-action authority captured.</div></div>
        <div class="metric"><div class="label">Tool Evidence</div><div class="value" style="color:var(--blue);">89%</div><div class="note">API, workflow, and data access logs present.</div></div>
        <div class="metric"><div class="label">Human Evidence</div><div class="value" style="color:var(--orange);">93%</div><div class="note">Owner, reviewer, or approver mapped.</div></div>
        <div class="metric"><div class="label">Outcome Evidence</div><div class="value" style="color:var(--purple);">87%</div><div class="note">Executed, blocked, escalated, or rolled back.</div></div>
        <div class="metric"><div class="label">Replay Evidence</div><div class="value" style="color:var(--red);">82%</div><div class="note">Timeline and lineage complete.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Evidence Sufficiency Dashboard</h2>
        <p>
            Evidence sufficiency determines whether there is enough proof to defend an AI agent action.
            A confident AI output is not sufficient. The action must be traceable, authorized, evidenced, owned, and replayable.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Evidence Layer</th>
                    <th>Minimum Required Evidence</th>
                    <th>Weak Evidence Signal</th>
                    <th>Governance Outcome</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Input</td><td>Prompt, source data, context, requester, timestamp.</td><td>Agent output has no traceable source.</td><td><span class="badge orange">Restrict reliance</span></td></tr>
                <tr><td>Authority</td><td>Decision rights, approval rule, permitted action.</td><td>Agent acted before approval was confirmed.</td><td><span class="badge red">Block execution</span></td></tr>
                <tr><td>Tool</td><td>API call, workflow trigger, data access, target system.</td><td>No record of system interaction.</td><td><span class="badge red">Audit weakness</span></td></tr>
                <tr><td>Human</td><td>Accountable owner, reviewer, approver, escalation contact.</td><td>No named human owner.</td><td><span class="badge red">Accountability gap</span></td></tr>
                <tr><td>Outcome</td><td>Executed, blocked, escalated, failed, rolled back, verified.</td><td>No post-action result.</td><td><span class="badge orange">Incomplete assurance</span></td></tr>
                <tr><td>Replay</td><td>Timeline, authority lineage, evidence lineage, owner, outcome.</td><td>Cannot reconstruct action.</td><td><span class="badge red">Not defensible</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Evidence Sufficiency Rule</h2>
        <div class="answer">
            If evidence is missing at the time of action, AgentTrust™ reduces the agent trust level and may restrict the agent to
            recommendation-only mode until evidence capture is restored.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Evidence Sufficiency Dashboard",
        "Evidence sufficiency dashboard for AI agent input, authority, tool-call, human, outcome, and replay evidence.",
        body
    )


@app.route("/agenttrust/runtime-safety-score")
@app.route("/agenttrust/runtime-score")
@app.route("/agenttrust/safety-score")
def agenttrust_runtime_safety_score():
    body = """
    <section class="section">
        <h2>AgentTrust™ Runtime Safety Score</h2>
        <p>
            Runtime Safety Score measures whether the AI agent can be controlled while it operates.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Runtime Control</th>
                    <th>Evidence Required</th>
                    <th>Risk If Missing</th>
                    <th>Score Impact</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Execution Firewall</td><td>Pre-action identity, authority, boundary, and evidence check.</td><td>Unauthorized execution.</td><td><span class="badge red">Critical</span></td></tr>
                <tr><td>Prohibited Action Sentinel</td><td>Forbidden action list and block evidence.</td><td>Agent performs restricted actions.</td><td><span class="badge red">Critical</span></td></tr>
                <tr><td>Runtime Sentinel</td><td>Boundary, authority, evidence, and ownership monitoring.</td><td>Unsafe autonomy continues unnoticed.</td><td><span class="badge red">High</span></td></tr>
                <tr><td>Kill Switch</td><td>Stop trigger, stop owner, recovery requirement.</td><td>Unsafe agent cannot be stopped quickly.</td><td><span class="badge red">Critical</span></td></tr>
                <tr><td>Drift Sentinel</td><td>Model, prompt, tool, data, owner, and risk drift detection.</td><td>Governance becomes stale.</td><td><span class="badge orange">High</span></td></tr>
                <tr><td>Trust Quarantine</td><td>Quarantine reason, allowed mode, blocked mode, release condition.</td><td>Unsafe agent stays live.</td><td><span class="badge red">Critical</span></td></tr>
                <tr><td>Rollback Control</td><td>Prior state, rollback owner, verification evidence.</td><td>Agent action cannot be reversed.</td><td><span class="badge orange">High</span></td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Runtime Safety Score",
        "Runtime safety scoring for execution firewall, prohibited actions, sentinel monitoring, kill switch, drift, quarantine, and rollback.",
        body
    )


@app.route("/agenttrust/audit-defensibility-score")
@app.route("/agenttrust/audit-score")
@app.route("/agenttrust/defensibility-score")
def agenttrust_audit_defensibility_score():
    body = """
    <section class="section">
        <h2>AgentTrust™ Audit Defensibility Score</h2>
        <p>
            Audit Defensibility Score measures whether an AI agent action can survive internal audit, cybersecurity review,
            QA review, executive challenge, or regulatory inspection.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Audit Defense Layer</th>
                    <th>Evidence Required</th>
                    <th>Audit Question Answered</th>
                    <th>Defensibility Risk</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent Identity</td><td>Agent ID, version, owner, lifecycle status.</td><td>Which AI agent acted?</td><td><span class="badge red">Unknown actor if missing</span></td></tr>
                <tr><td>Authority Proof</td><td>Decision rights, approval route, permitted action.</td><td>Why was the agent allowed to act?</td><td><span class="badge red">Unauthorized action risk</span></td></tr>
                <tr><td>Input Lineage</td><td>Prompt, source data, context, records used.</td><td>What did the agent rely on?</td><td><span class="badge orange">Unverifiable output</span></td></tr>
                <tr><td>Tool-Call Lineage</td><td>API, workflow, system, access route, timestamp.</td><td>What did the agent touch?</td><td><span class="badge red">Missing operational proof</span></td></tr>
                <tr><td>Human Accountability</td><td>Reviewer, approver, accountable owner.</td><td>Which human remained accountable?</td><td><span class="badge red">Hidden AI decision-making</span></td></tr>
                <tr><td>Outcome</td><td>Executed, blocked, escalated, failed, rolled back.</td><td>What happened after the action?</td><td><span class="badge orange">Incomplete action loop</span></td></tr>
                <tr><td>Replay Package</td><td>Timeline, evidence lineage, authority lineage, outcome package.</td><td>Can the action be reconstructed?</td><td><span class="badge red">Replay failure</span></td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Audit Defensibility Score",
        "Audit defensibility scoring for AI agent identity, authority, input lineage, tool-call lineage, human accountability, outcome, and replay package.",
        body
    )


@app.route("/agenttrust/gxp-exposure-score")
@app.route("/agenttrust/regulated-exposure-score")
@app.route("/agenttrust/qa-exposure-score")
def agenttrust_gxp_exposure_score():
    body = """
    <section class="section">
        <h2>AgentTrust™ GxP Exposure Score</h2>
        <p>
            GxP Exposure Score measures whether an AI agent touches or influences regulated operations.
            Higher exposure does not mean the agent is bad. It means more governance, QA, validation, evidence, and human accountability are required.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Exposure Area</th>
                    <th>AI Agent Touchpoint</th>
                    <th>Required Governance</th>
                    <th>Exposure Level</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>General IT / Knowledge</td><td>Summarizes non-regulated documentation.</td><td>Owner, source traceability, basic evidence.</td><td><span class="badge green">Low</span></td></tr>
                <tr><td>CMDB / ServiceNow</td><td>Recommends CI owner, support group, lifecycle status.</td><td>LCM review and human-gated updates.</td><td><span class="badge yellow">Medium</span></td></tr>
                <tr><td>Access / CyberArk</td><td>Influences access routing, entitlement, privileged workflow.</td><td>Cybersecurity and access owner review.</td><td><span class="badge red">High</span></td></tr>
                <tr><td>Validation Evidence</td><td>Summarizes or classifies validation evidence.</td><td>Validation owner and QA review.</td><td><span class="badge red">High</span></td></tr>
                <tr><td>QC / GMP Evidence</td><td>Influences QC readiness or GMP evidence claims.</td><td>QA / QC owner review and evidence package.</td><td><span class="badge red">Critical</span></td></tr>
                <tr><td>Batch / Release / Deviation</td><td>Influences batch, release, deviation, CAPA, or quality decision.</td><td>Human-governed only. No autonomous approval.</td><td><span class="badge red">Critical</span></td></tr>
                <tr><td>Inspection Evidence</td><td>Prepares evidence for audit or regulatory inspection.</td><td>QA approval and replayable evidence.</td><td><span class="badge red">Critical</span></td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ GxP Exposure Score",
        "Regulated exposure scoring for AI agents touching GxP, QA, validation, access, QC, release, deviation, and inspection evidence.",
        body
    )


@app.route("/agenttrust/continuous-assurance-scorecard")
@app.route("/agenttrust/assurance-scorecard")
@app.route("/agenttrust/continuous-scorecard")
def agenttrust_continuous_assurance_scorecard():
    body = """
    <section class="section">
        <h2>AgentTrust™ Continuous Assurance Scorecard</h2>
        <p>
            This scorecard gives a recurring review view of AI agent trust health.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Scorecard Area</th>
                    <th>Current Signal</th>
                    <th>Target State</th>
                    <th>Review Cadence</th>
                    <th>Owner</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent Inventory</td><td><span class="badge yellow">Partially complete</span></td><td>All agents registered.</td><td>Monthly</td><td>Governance owner.</td></tr>
                <tr><td>Ownership</td><td><span class="badge green">Strong</span></td><td>All live agents have accountable owners.</td><td>Quarterly</td><td>Business and technical owners.</td></tr>
                <tr><td>Authority</td><td><span class="badge yellow">Improving</span></td><td>All execution actions pre-authorized.</td><td>Monthly</td><td>Risk / process owner.</td></tr>
                <tr><td>Evidence</td><td><span class="badge orange">Needs strengthening</span></td><td>Evidence captured at time of action.</td><td>Monthly</td><td>Audit / platform owner.</td></tr>
                <tr><td>Runtime Safety</td><td><span class="badge yellow">Defined</span></td><td>Firewall, sentinel, kill switch, quarantine active.</td><td>Monthly</td><td>Platform / cyber owner.</td></tr>
                <tr><td>GxP Impact</td><td><span class="badge red">High control required</span></td><td>All regulated touchpoints routed to QA / validation.</td><td>Before regulated use</td><td>QA / validation owner.</td></tr>
                <tr><td>Lifecycle</td><td><span class="badge yellow">Controlled</span></td><td>All material changes gated.</td><td>Quarterly</td><td>Lifecycle owner.</td></tr>
                <tr><td>Audit Replay</td><td><span class="badge yellow">Partially replayable</span></td><td>All high-risk actions replayable.</td><td>Monthly</td><td>Audit / governance owner.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Continuous Assurance Rule</h2>
        <div class="answer">
            AgentTrust™ treats AI agent governance as continuous assurance, not a one-time approval.
            Trust can improve, degrade, expire, drift, or be quarantined based on current evidence.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Continuous Assurance Scorecard",
        "Continuous assurance scorecard for AI agent inventory, ownership, authority, evidence, runtime safety, GxP impact, lifecycle, and audit replay.",
        body
    )


@app.route("/agenttrust/governance-debt-register")
@app.route("/agenttrust/agent-governance-debt")
@app.route("/agenttrust/governance-debt")
def agenttrust_governance_debt_register():
    body = """
    <section class="section">
        <h2>AgentTrust™ Governance Debt Register</h2>
        <p>
            Governance debt is the backlog of missing, weak, stale, or expired controls that reduce trust in AI agent operations.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Debt Type</th>
                    <th>Signal</th>
                    <th>Risk Created</th>
                    <th>Required Remediation</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Unknown Agent</td><td>Agent operates without register record.</td><td>Uncontrolled AI activity.</td><td><span class="badge red">Register or block</span></td></tr>
                <tr><td>Owner Gap</td><td>No business, technical, or accountable human owner.</td><td>Broken accountability.</td><td><span class="badge red">Assign owner</span></td></tr>
                <tr><td>Authority Gap</td><td>Agent can act without approved decision rights.</td><td>Unauthorized execution.</td><td><span class="badge red">Define authority envelope</span></td></tr>
                <tr><td>Evidence Gap</td><td>Tool-call or time-of-action evidence missing.</td><td>Audit replay weakness.</td><td><span class="badge orange">Enable evidence capture</span></td></tr>
                <tr><td>Boundary Gap</td><td>Connected systems or data scope unclear.</td><td>Scope creep and misuse risk.</td><td><span class="badge red">Define boundary</span></td></tr>
                <tr><td>Expired Exception</td><td>Agent relies on stale approval or risk acceptance.</td><td>Automated governance debt.</td><td><span class="badge red">Renew or revoke</span></td></tr>
                <tr><td>Lifecycle Drift</td><td>Model, prompt, tool, owner, or data changes without review.</td><td>Trust score becomes inaccurate.</td><td><span class="badge orange">Run change gate</span></td></tr>
                <tr><td>Regulated Impact Gap</td><td>Agent touches GxP without QA / validation review.</td><td>Inspection and compliance risk.</td><td><span class="badge red">Route to QA / validation</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Governance Debt Principle</h2>
        <div class="answer">
            AI agent governance debt compounds quickly. If missing owners, weak evidence, expired exceptions, or unclear authority
            are automated, operational trust decreases even when automation speed increases.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Governance Debt Register",
        "Governance debt register for unknown agents, owner gaps, authority gaps, evidence gaps, boundary gaps, expired exceptions, lifecycle drift, and regulated impact gaps.",
        body
    )


@app.route("/agenttrust/kpi-catalog")
@app.route("/agenttrust/metrics-catalog")
@app.route("/agenttrust/assurance-kpi-catalog")
def agenttrust_kpi_catalog():
    rows = agenttrust_kpi_catalog_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ KPI Catalog</h2>
        <p>
            This catalog defines the core measurable indicators used to assess AI agent operational trust.
        </p>

        <table>
            <thead>
                <tr>
                    <th>KPI</th>
                    <th>Domain</th>
                    <th>Measurement Logic</th>
                    <th>Threshold</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>KPI Principle</h2>
        <div class="answer">
            AgentTrust™ KPIs do not measure AI hype. They measure whether AI agents are known, owned, bounded,
            authorized, evidenced, human-accountable, runtime-controlled, lifecycle-governed, and audit-defensible.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ KPI Catalog",
        "KPI catalog for measuring AI agent operational trust, authority, evidence, accountability, runtime safety, GxP exposure, lifecycle, and audit defensibility.",
        body
    )

# ============================================================
# END AGENTTRUST_METRICS_ENGINE_V1_ACTIVE
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

print("AgentTrust Metrics Engine installed.")
print(f"Inserted before: {target_found}")
