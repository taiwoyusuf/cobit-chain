from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_LIFECYCLE_GOVERNANCE_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust Lifecycle Governance already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base module not found. Install AgentTrust module first.")

nav_old = '<a href="/agenttrust/decision-replay-studio" class="secondary">Decision Replay</a>'
nav_new = '''<a href="/agenttrust/decision-replay-studio" class="secondary">Decision Replay</a>
                    <a href="/agenttrust/lifecycle-governance" class="secondary">Lifecycle</a>
                    <a href="/agenttrust/change-control-gate" class="dark">Change Gate</a>
                    <a href="/agenttrust/model-change-gate" class="dark">Model Change</a>
                    <a href="/agenttrust/decommissioning-gate" class="dark">Decommissioning</a>'''

if nav_old in text and "/agenttrust/lifecycle-governance" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# AGENTTRUST_LIFECYCLE_GOVERNANCE_V1_ACTIVE
# AgentTrust™ Lifecycle Governance, Change Control Gate,
# Model Change Gate, Prompt / Tool Change Gate, Monitoring Cadence,
# Decommissioning Gate, and Retirement Evidence
# ============================================================

@app.route("/agenttrust/lifecycle-governance")
@app.route("/agenttrust/agent-lifecycle")
@app.route("/agenttrust/lifecycle-command-center")
def agenttrust_lifecycle_governance():
    body = """
    <section class="kpis">
        <div class="metric"><div class="label">Lifecycle Status</div><div class="value" style="color:var(--green);">Governed</div><div class="note">Agents move through controlled states.</div></div>
        <div class="metric"><div class="label">Change Control</div><div class="value" style="color:var(--yellow);">Required</div><div class="note">Material change requires review.</div></div>
        <div class="metric"><div class="label">Model Change</div><div class="value" style="color:var(--orange);">Gated</div><div class="note">Model changes trigger impact review.</div></div>
        <div class="metric"><div class="label">Tool Change</div><div class="value" style="color:var(--red);">Controlled</div><div class="note">New tool access is never silent.</div></div>
        <div class="metric"><div class="label">Review Cadence</div><div class="value" style="color:var(--blue);">Defined</div><div class="note">Agents need periodic assurance review.</div></div>
        <div class="metric"><div class="label">Retirement</div><div class="value" style="color:var(--purple);">Evidenced</div><div class="note">Retired agents preserve audit history.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Lifecycle Governance</h2>
        <div class="answer">
            <strong>Purpose:</strong> control the full lifecycle of AI agents from proposal to retirement.
            AgentTrust™ ensures that an AI agent is not only approved once, but remains governed as its model, prompt,
            tools, data sources, owners, authority, risk tier, and connected systems change over time.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Lifecycle Stage</th>
                    <th>Governance Requirement</th>
                    <th>Required Evidence</th>
                    <th>Allowed Status</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Proposed</td><td>Business purpose and owner identified.</td><td>Use case, owner, intended boundary.</td><td><span class="badge yellow">Concept only</span></td></tr>
                <tr><td>Designed</td><td>System boundary, tools, data, and authority defined.</td><td>Draft Agent Risk Passport™.</td><td><span class="badge yellow">Design review</span></td></tr>
                <tr><td>Reviewed</td><td>Risk, cyber, QA, validation, and access impacts reviewed where applicable.</td><td>Review record and impact assessment.</td><td><span class="badge orange">Conditional</span></td></tr>
                <tr><td>Approved</td><td>Owner, authority, evidence, rollback, and escalation complete.</td><td>Approved passport and readiness gate.</td><td><span class="badge green">Ready for deployment</span></td></tr>
                <tr><td>Live</td><td>Agent operates inside approved boundary only.</td><td>Tool-call logs, evidence ledger, monitoring record.</td><td><span class="badge green">Operational</span></td></tr>
                <tr><td>Changed</td><td>Material changes routed through change control.</td><td>Change record, impact review, approval.</td><td><span class="badge yellow">Revalidated</span></td></tr>
                <tr><td>Suspended</td><td>Unsafe, ownerless, or drifted agent is paused.</td><td>Suspension reason, owner, investigation record.</td><td><span class="badge red">No execution</span></td></tr>
                <tr><td>Retired</td><td>Agent is decommissioned and evidence preserved.</td><td>Retirement record, access removal, evidence archive.</td><td><span class="badge purple">Archived</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Lifecycle Rule</h2>
        <div class="answer">
            AI agents are not static assets. Any change to model, prompt, tool, data, owner, authority, boundary,
            risk tier, or connected system can change operational trust and must be governed.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Lifecycle Governance",
        "Lifecycle governance for AI agents from proposal to approval, operation, change, suspension, retirement, and evidence preservation.",
        body
    )


@app.route("/agenttrust/change-control-gate")
@app.route("/agenttrust/agent-change-control")
@app.route("/agenttrust/ai-agent-change-gate")
def agenttrust_change_control_gate():
    body = """
    <section class="section">
        <h2>AgentTrust™ Change Control Gate</h2>
        <p>
            This gate determines whether an AI agent change can proceed without review, requires human approval,
            requires cybersecurity review, requires QA / validation review, or must be blocked.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Change Type</th>
                    <th>Risk Created</th>
                    <th>Required Review</th>
                    <th>Execution Rule</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent name or description update.</td><td>Low documentation risk.</td><td>Owner review.</td><td><span class="badge green">Allowed with record</span></td></tr>
                <tr><td>Business purpose change.</td><td>Agent may be used outside original intent.</td><td>Business owner and risk owner.</td><td><span class="badge yellow">Human approval</span></td></tr>
                <tr><td>System boundary expansion.</td><td>Agent may touch new systems or workflows.</td><td>System owner, CMDB owner, cyber if applicable.</td><td><span class="badge orange">Restricted until approved</span></td></tr>
                <tr><td>New data source.</td><td>Privacy, integrity, or GxP evidence risk.</td><td>Data owner, QA where applicable.</td><td><span class="badge orange">Impact review required</span></td></tr>
                <tr><td>New tool or API access.</td><td>Agent may perform new operational action.</td><td>Platform owner and cybersecurity.</td><td><span class="badge red">Block until approved</span></td></tr>
                <tr><td>Authority level increase.</td><td>Agent gains more execution power.</td><td>Risk owner, process owner, QA/cyber as needed.</td><td><span class="badge red">Full change gate</span></td></tr>
                <tr><td>Risk tier increase.</td><td>Agent now affects higher impact workflow.</td><td>Governance board and accountable owner.</td><td><span class="badge red">Reapprove passport</span></td></tr>
                <tr><td>GxP, QA, validation, release, or inspection impact.</td><td>Regulated decision risk.</td><td>QA and validation owner.</td><td><span class="badge red">Human-governed only</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Change Gate Principle</h2>
        <div class="answer">
            If a change can alter what the agent knows, touches, decides, triggers, or influences, it is not a cosmetic change.
            It is a governance-impacting change.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Change Control Gate",
        "Change control gate for AI agent purpose, boundary, data, tools, authority, risk, and regulated impact.",
        body
    )


@app.route("/agenttrust/model-change-gate")
@app.route("/agenttrust/model-version-gate")
@app.route("/agenttrust/model-governance-gate")
def agenttrust_model_change_gate():
    body = """
    <section class="section">
        <h2>AgentTrust™ Model Change Gate</h2>
        <p>
            This gate governs model replacement, model version change, model provider change, configuration change,
            behavior change, or model capability expansion.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Model Change</th>
                    <th>Impact Question</th>
                    <th>Evidence Required</th>
                    <th>Governance Outcome</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Model version update.</td><td>Can outputs, behavior, risk, or performance change?</td><td>Version record, test summary, owner approval.</td><td><span class="badge yellow">Review required</span></td></tr>
                <tr><td>Model provider change.</td><td>Does data handling, security, or validation posture change?</td><td>Provider review, cyber review, data review.</td><td><span class="badge orange">Impact assessment</span></td></tr>
                <tr><td>Temperature or configuration change.</td><td>Could output variability or behavior change?</td><td>Configuration record and testing evidence.</td><td><span class="badge yellow">Controlled change</span></td></tr>
                <tr><td>New reasoning or tool-use capability.</td><td>Can the agent now perform more complex actions?</td><td>Updated authority and tool matrix.</td><td><span class="badge red">Reapprove authority</span></td></tr>
                <tr><td>New multimodal input.</td><td>Can the agent process images, files, audio, or screenshots?</td><td>Data classification and evidence rule.</td><td><span class="badge orange">Data impact review</span></td></tr>
                <tr><td>Regulated process model update.</td><td>Can the model influence GxP, QA, validation, batch, release, or inspection evidence?</td><td>QA review, validation impact, test evidence.</td><td><span class="badge red">Human-governed only</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Model Change Rule</h2>
        <div class="answer">
            AgentTrust™ treats model changes as governance-relevant because the same workflow with a different model
            may produce different outputs, different risks, and different evidence expectations.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Model Change Gate",
        "Model version, provider, configuration, capability, and regulated-impact change gate for AI agents.",
        body
    )


@app.route("/agenttrust/prompt-tool-change-gate")
@app.route("/agenttrust/prompt-change-gate")
@app.route("/agenttrust/tool-change-gate")
def agenttrust_prompt_tool_change_gate():
    body = """
    <section class="section">
        <h2>AgentTrust™ Prompt & Tool Change Gate</h2>
        <p>
            AI agent behavior can change when its prompt, instruction hierarchy, tool list, API permissions,
            retrieval source, or workflow connection changes. AgentTrust™ routes these changes through governance.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Change Area</th>
                    <th>What Can Change</th>
                    <th>Risk</th>
                    <th>Control Requirement</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>System Prompt</td><td>Agent behavior, tone, refusal logic, escalation behavior.</td><td>Agent may act differently.</td><td><span class="badge yellow">Prompt version control</span></td></tr>
                <tr><td>Instruction Hierarchy</td><td>Priority of policy, user request, workflow logic.</td><td>Policy bypass risk.</td><td><span class="badge orange">Governance review</span></td></tr>
                <tr><td>Tool List</td><td>Which tools, APIs, or workflows the agent can call.</td><td>New execution capability.</td><td><span class="badge red">Tool approval required</span></td></tr>
                <tr><td>API Permission</td><td>Read, write, update, trigger, delete, approve.</td><td>Operational or privileged action risk.</td><td><span class="badge red">Authority gate update</span></td></tr>
                <tr><td>Retrieval Source</td><td>Knowledge base, CMDB, evidence repository, policy source.</td><td>Wrong or stale evidence risk.</td><td><span class="badge orange">Source validation</span></td></tr>
                <tr><td>Workflow Connection</td><td>ServiceNow, MyAccess, CyberArk, change, validation, QA workflow.</td><td>Control bypass risk.</td><td><span class="badge red">Policy router review</span></td></tr>
                <tr><td>Prohibited Action List</td><td>Agent blocklist or forbidden actions.</td><td>Unsafe action may become permitted.</td><td><span class="badge red">Governance owner approval</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Prompt and Tool Rule</h2>
        <div class="answer">
            In AgentTrust™, prompt and tool changes are not minor technical edits.
            They can change authority, evidence, risk, and operational trust.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Prompt & Tool Change Gate",
        "Governance gate for prompt, instruction, tool, API, retrieval source, workflow, and prohibited-action changes.",
        body
    )


@app.route("/agenttrust/review-cadence")
@app.route("/agenttrust/agent-review-cadence")
@app.route("/agenttrust/continuous-monitoring-cadence")
def agenttrust_review_cadence():
    body = """
    <section class="section">
        <h2>AgentTrust™ Review Cadence</h2>
        <p>
            AI agents require periodic review because owners, models, prompts, tools, data sources, risks,
            policies, and connected systems change over time.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Review Type</th>
                    <th>Frequency</th>
                    <th>Review Owner</th>
                    <th>Evidence Reviewed</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent Ownership Review</td><td>Quarterly or upon owner change.</td><td>Business owner / technical owner.</td><td>Owner, support group, lifecycle status.</td></tr>
                <tr><td>Authority Review</td><td>Quarterly or after scope change.</td><td>Process owner / risk owner.</td><td>Permitted actions, prohibited actions, approval route.</td></tr>
                <tr><td>Tool Access Review</td><td>Quarterly or after integration change.</td><td>Platform owner / cyber owner.</td><td>API access, workflow triggers, access permissions.</td></tr>
                <tr><td>Evidence Review</td><td>Monthly for high-risk agents.</td><td>Audit / governance owner.</td><td>Tool-call logs, timestamps, replay packages.</td></tr>
                <tr><td>GxP / QA Impact Review</td><td>Before regulated use and after material change.</td><td>QA / validation owner.</td><td>Validation impact, regulated evidence, QA decision record.</td></tr>
                <tr><td>Risk Tier Review</td><td>Quarterly or after incident.</td><td>Risk owner / governance board.</td><td>Risk tier, incidents, exceptions, residual risk.</td></tr>
                <tr><td>Retirement Review</td><td>At decommissioning.</td><td>Business owner / technical owner.</td><td>Access removal, evidence archive, final status.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Cadence Rule</h2>
        <div class="answer">
            AgentTrust™ keeps AI agent trust current by reviewing ownership, authority, evidence, risk, tool access,
            regulated impact, and lifecycle status on a defined cadence.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Review Cadence",
        "Periodic review cadence for AI agent ownership, authority, tool access, evidence, GxP impact, risk, and retirement.",
        body
    )


@app.route("/agenttrust/decommissioning-gate")
@app.route("/agenttrust/agent-decommissioning")
@app.route("/agenttrust/retirement-gate")
def agenttrust_decommissioning_gate():
    body = """
    <section class="section">
        <h2>AgentTrust™ Decommissioning Gate</h2>
        <p>
            Retiring an AI agent requires more than turning it off. Its access, tools, workflows, evidence, ownership,
            residual risk, exceptions, and audit records must be closed properly.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Retirement Control</th>
                    <th>Required Action</th>
                    <th>Evidence Required</th>
                    <th>Closure Rule</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Lifecycle Status</td><td>Set agent status to retired.</td><td>Retirement record and date.</td><td><span class="badge green">Required</span></td></tr>
                <tr><td>Access Removal</td><td>Remove tool, API, workflow, and system access.</td><td>Access revocation evidence.</td><td><span class="badge red">Must confirm</span></td></tr>
                <tr><td>Workflow Disablement</td><td>Disable triggers, automations, scheduled jobs, and connectors.</td><td>Workflow deactivation record.</td><td><span class="badge red">Must confirm</span></td></tr>
                <tr><td>Evidence Archive</td><td>Preserve agent passport, logs, decisions, and replay packages.</td><td>Evidence archive location.</td><td><span class="badge green">Required</span></td></tr>
                <tr><td>Open Exception Review</td><td>Close or transfer active exceptions and residual risks.</td><td>Exception closure or transfer record.</td><td><span class="badge orange">Required if open</span></td></tr>
                <tr><td>Owner Signoff</td><td>Business and technical owner confirm retirement.</td><td>Owner approval record.</td><td><span class="badge yellow">Required</span></td></tr>
                <tr><td>Post-Retirement Check</td><td>Confirm agent cannot execute after retirement.</td><td>Post-retirement verification evidence.</td><td><span class="badge red">Must pass</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Retirement Rule</h2>
        <div class="answer">
            An AI agent is not fully retired until its access is removed, workflows are disabled,
            evidence is archived, residual risk is closed, and post-retirement execution is verified as impossible.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Decommissioning Gate",
        "Retirement and decommissioning gate for AI agent access, workflows, evidence, exceptions, and closure verification.",
        body
    )


@app.route("/agenttrust/lifecycle-evidence-register")
@app.route("/agenttrust/lifecycle-evidence")
@app.route("/agenttrust/agent-lifecycle-evidence")
def agenttrust_lifecycle_evidence_register():
    body = """
    <section class="section">
        <h2>AgentTrust™ Lifecycle Evidence Register</h2>
        <p>
            This register defines the evidence required at each stage of an AI agent lifecycle.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Lifecycle Stage</th>
                    <th>Evidence Artifact</th>
                    <th>Minimum Evidence</th>
                    <th>Why It Matters</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Proposed</td><td>Agent Intake Record</td><td>Use case, owner, purpose, initial risk.</td><td>Prevents undocumented agents.</td></tr>
                <tr><td>Designed</td><td>Draft Agent Passport</td><td>Boundary, data, tools, authority, prohibited actions.</td><td>Defines trust boundary.</td></tr>
                <tr><td>Reviewed</td><td>Impact Assessment</td><td>Cyber, access, GxP, validation, privacy, operational impact.</td><td>Routes risk before deployment.</td></tr>
                <tr><td>Approved</td><td>Approval Record</td><td>Owner approval, risk decision, readiness gate.</td><td>Proves authority to deploy.</td></tr>
                <tr><td>Live</td><td>Runtime Evidence</td><td>Tool-call logs, evidence ledger, action timeline.</td><td>Supports audit replay.</td></tr>
                <tr><td>Changed</td><td>Change Record</td><td>Change reason, impact, approver, revalidation result.</td><td>Controls drift.</td></tr>
                <tr><td>Suspended</td><td>Suspension Record</td><td>Reason, owner, investigation, stop-control evidence.</td><td>Preserves safety decision.</td></tr>
                <tr><td>Retired</td><td>Retirement Evidence</td><td>Access removal, workflow disablement, evidence archive.</td><td>Proves safe decommissioning.</td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Lifecycle Evidence Register",
        "Evidence register for AI agent proposal, design, review, approval, live operation, change, suspension, and retirement.",
        body
    )

# ============================================================
# END AGENTTRUST_LIFECYCLE_GOVERNANCE_V1_ACTIVE
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

print("AgentTrust Lifecycle Governance installed.")
print(f"Inserted before: {target_found}")
