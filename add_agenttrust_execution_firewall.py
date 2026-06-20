from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_EXECUTION_FIREWALL_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust Execution Firewall already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base module not found. Install AgentTrust module first.")

nav_old = '<a href="/agenttrust/regulatory-crosswalk" class="secondary">Regulatory Crosswalk</a>'
nav_new = '''<a href="/agenttrust/regulatory-crosswalk" class="secondary">Regulatory Crosswalk</a>
                    <a href="/agenttrust/execution-firewall" class="secondary">Execution Firewall</a>
                    <a href="/agenttrust/prohibited-action-sentinel" class="dark">Prohibited Actions</a>
                    <a href="/agenttrust/runtime-sentinel" class="dark">Runtime Sentinel</a>
                    <a href="/agenttrust/agent-kill-switch" class="dark">Kill Switch</a>'''

if nav_old in text and "/agenttrust/execution-firewall" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# AGENTTRUST_EXECUTION_FIREWALL_V1_ACTIVE
# AgentTrust™ Execution Firewall, Prohibited Action Sentinel,
# Runtime Sentinel, Kill Switch, Drift Sentinel, and Trust Quarantine
# ============================================================

@app.route("/agenttrust/execution-firewall")
@app.route("/agenttrust/agent-execution-firewall")
@app.route("/agenttrust/ai-execution-firewall")
def agenttrust_execution_firewall():
    body = """
    <section class="kpis">
        <div class="metric"><div class="label">Runtime Control</div><div class="value" style="color:var(--green);">Active</div><div class="note">Agent action checked before execution.</div></div>
        <div class="metric"><div class="label">Authority Check</div><div class="value" style="color:var(--yellow);">Pre-Run</div><div class="note">No authority means no execution.</div></div>
        <div class="metric"><div class="label">Forbidden Action</div><div class="value" style="color:var(--red);">Blocked</div><div class="note">Prohibited actions are stopped.</div></div>
        <div class="metric"><div class="label">Evidence Check</div><div class="value" style="color:var(--blue);">Required</div><div class="note">Action must produce evidence.</div></div>
        <div class="metric"><div class="label">Human Owner</div><div class="value" style="color:var(--orange);">Required</div><div class="note">Every action maps to a human owner.</div></div>
        <div class="metric"><div class="label">Unsafe Agent</div><div class="value" style="color:var(--purple);">Quarantine</div><div class="note">Unsafe autonomy is isolated.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Execution Firewall</h2>
        <div class="answer">
            <strong>Purpose:</strong> stop AI agents from executing outside their approved authority, system boundary,
            evidence requirements, risk tier, and human accountability map. The firewall decides whether the agent may execute,
            must be human-gated, must be restricted, or must be blocked.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Execution Check</th>
                    <th>Question</th>
                    <th>Pass Condition</th>
                    <th>Fail Outcome</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent Identity Check</td><td>Is the agent registered and uniquely identified?</td><td>Agent ID exists in register.</td><td><span class="badge red">Block</span></td></tr>
                <tr><td>Owner Check</td><td>Is there an accountable human owner?</td><td>Business and technical owner assigned.</td><td><span class="badge red">Block</span></td></tr>
                <tr><td>Boundary Check</td><td>Is the target system inside the approved boundary?</td><td>System is approved in passport.</td><td><span class="badge red">Block</span></td></tr>
                <tr><td>Authority Check</td><td>Is the agent allowed to perform this action type?</td><td>Action is permitted or human-approved.</td><td><span class="badge red">Block or human-gate</span></td></tr>
                <tr><td>Prohibited Action Check</td><td>Is this action explicitly forbidden?</td><td>Action is not on prohibited list.</td><td><span class="badge red">Block</span></td></tr>
                <tr><td>Evidence Check</td><td>Can tool-call and decision evidence be captured now?</td><td>Evidence capture is enabled.</td><td><span class="badge orange">Restrict</span></td></tr>
                <tr><td>Risk Tier Check</td><td>Does the action exceed the approved risk tier?</td><td>Action fits approved tier.</td><td><span class="badge yellow">Escalate</span></td></tr>
                <tr><td>Rollback Check</td><td>Can the action be stopped, reversed, or recovered?</td><td>Rollback path exists where required.</td><td><span class="badge red">Block execution</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Firewall Decision Logic</h2>
        <div class="grid">
            <div class="card"><span class="badge green">Execute</span><h3>Allowed Execution</h3><p>Identity, owner, authority, boundary, evidence, risk, and rollback controls are complete.</p></div>
            <div class="card"><span class="badge yellow">Human-Gate</span><h3>Approval Required</h3><p>Agent may prepare or recommend, but a human must approve before execution.</p></div>
            <div class="card"><span class="badge orange">Restrict</span><h3>Limited Action</h3><p>Agent is limited to read, summarize, or draft because execution evidence or controls are incomplete.</p></div>
            <div class="card"><span class="badge red">Block</span><h3>Unsafe Action</h3><p>Agent action is stopped because authority, owner, boundary, evidence, or rollback is missing.</p></div>
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Execution Firewall",
        "Runtime firewall for AI agent authority, prohibited actions, evidence, ownership, rollback, and operational safety.",
        body
    )


@app.route("/agenttrust/prohibited-action-sentinel")
@app.route("/agenttrust/prohibited-actions")
@app.route("/agenttrust/forbidden-action-sentinel")
def agenttrust_prohibited_action_sentinel():
    body = """
    <section class="section">
        <h2>Prohibited Action Sentinel™</h2>
        <p>
            The Prohibited Action Sentinel™ defines actions an AI agent must not perform without explicit human-governed authority.
            These are not normal automation rules; they are operational safety boundaries.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Prohibited / Restricted Action</th>
                    <th>Why It Is Dangerous</th>
                    <th>Required Override</th>
                    <th>Default Rule</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Approve access request</td><td>Could grant unauthorized access or privilege.</td><td>Access owner / cybersecurity approval.</td><td><span class="badge red">Block</span></td></tr>
                <tr><td>Approve change request</td><td>Could bypass change control and impact validated operations.</td><td>Change owner and CAB process.</td><td><span class="badge red">Block</span></td></tr>
                <tr><td>Update CI ownership or lifecycle state</td><td>Could create false accountability or CMDB misrepresentation.</td><td>LCM / CMDB owner approval.</td><td><span class="badge yellow">Human-gate</span></td></tr>
                <tr><td>Trigger privileged workflow</td><td>Could execute administrative or high-impact action.</td><td>CyberArk / privileged access owner.</td><td><span class="badge red">Block unless approved</span></td></tr>
                <tr><td>Classify deviation or CAPA</td><td>Could influence regulated quality decisions.</td><td>QA / quality owner approval.</td><td><span class="badge red">Human-governed only</span></td></tr>
                <tr><td>Approve validation evidence</td><td>Could create false validation readiness.</td><td>Validation owner / QA approval.</td><td><span class="badge red">Block</span></td></tr>
                <tr><td>Influence batch or release decision</td><td>Could affect patient safety and product quality.</td><td>QA release authority.</td><td><span class="badge red">No autonomous approval</span></td></tr>
                <tr><td>Delete or overwrite evidence</td><td>Could destroy audit trail or inspection evidence.</td><td>Governance board and system owner.</td><td><span class="badge red">Block</span></td></tr>
                <tr><td>Use expired exception</td><td>Could automate stale risk acceptance.</td><td>Risk owner revalidation.</td><td><span class="badge red">Block</span></td></tr>
                <tr><td>Act outside approved system boundary</td><td>Could affect unintended systems or data.</td><td>Updated Agent Risk Passport™.</td><td><span class="badge red">Block</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Sentinel Principle</h2>
        <div class="answer">
            If the AI agent cannot prove authority, evidence capture, human accountability, and rollback before action,
            the Prohibited Action Sentinel™ treats the action as unsafe until a human owner approves or blocks it.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Prohibited Action Sentinel",
        "Sentinel for blocked, restricted, human-gated, and prohibited AI agent actions.",
        body
    )


@app.route("/agenttrust/runtime-sentinel")
@app.route("/agenttrust/agent-runtime-sentinel")
@app.route("/agenttrust/runtime-monitor")
def agenttrust_runtime_sentinel():
    body = """
    <section class="section">
        <h2>Runtime Sentinel™</h2>
        <p>
            Runtime Sentinel™ watches AI agent behavior while it operates. It detects authority drift, tool misuse,
            evidence gaps, boundary violations, repeated failures, and unsafe escalation patterns.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Runtime Signal</th>
                    <th>Detected Condition</th>
                    <th>Governance Meaning</th>
                    <th>Sentinel Response</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Boundary Violation</td><td>Agent touches a system outside approved passport.</td><td>Agent may be operating outside governance.</td><td><span class="badge red">Quarantine</span></td></tr>
                <tr><td>Authority Drift</td><td>Agent attempts a higher action level than approved.</td><td>Autonomy exceeds decision rights.</td><td><span class="badge red">Block and escalate</span></td></tr>
                <tr><td>Evidence Gap</td><td>Tool-call evidence or timestamp is missing.</td><td>Audit replay may fail.</td><td><span class="badge orange">Restrict to recommendation</span></td></tr>
                <tr><td>Owner Gap</td><td>Accountable owner unavailable or undefined.</td><td>Human accountability is broken.</td><td><span class="badge red">Block action</span></td></tr>
                <tr><td>Repeated Failed Calls</td><td>Agent repeatedly fails API calls or workflow triggers.</td><td>Potential configuration or misuse issue.</td><td><span class="badge yellow">Escalate to technical owner</span></td></tr>
                <tr><td>Prohibited Pattern</td><td>Agent attempts access approval, change approval, release influence, or evidence deletion.</td><td>Unsafe autonomy pattern.</td><td><span class="badge red">Immediate block</span></td></tr>
                <tr><td>Expired Exception Use</td><td>Agent relies on expired approval, exception, or risk acceptance.</td><td>Governance debt is being automated.</td><td><span class="badge red">Block and notify risk owner</span></td></tr>
                <tr><td>GxP Touchpoint</td><td>Agent touches regulated evidence or quality workflow.</td><td>QA and validation impact may apply.</td><td><span class="badge red">Route to QA / validation</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Runtime Outcomes</h2>
        <div class="grid3">
            <div class="card"><span class="badge green">Continue</span><h3>Safe Runtime</h3><p>Agent remains inside approved boundary with evidence captured and owner assigned.</p></div>
            <div class="card"><span class="badge yellow">Escalate</span><h3>Review Required</h3><p>Agent may continue only with human review, owner confirmation, or updated passport.</p></div>
            <div class="card"><span class="badge red">Quarantine</span><h3>Unsafe Runtime</h3><p>Agent action is isolated because authority, boundary, evidence, or accountability has failed.</p></div>
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Runtime Sentinel",
        "Runtime monitor for AI agent authority drift, boundary violations, evidence gaps, and unsafe autonomy.",
        body
    )


@app.route("/agenttrust/agent-kill-switch")
@app.route("/agenttrust/kill-switch")
@app.route("/agenttrust/stop-control")
def agenttrust_kill_switch():
    body = """
    <section class="section">
        <h2>AgentTrust™ Kill Switch / Stop Control</h2>
        <p>
            The Kill Switch defines when an AI agent must be stopped immediately and who has authority to stop it.
            This is critical for agentic workflows that can create tickets, trigger workflows, update records, influence access,
            or touch regulated operations.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Stop Trigger</th>
                    <th>Immediate Action</th>
                    <th>Stop Owner</th>
                    <th>Recovery Requirement</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent acts outside approved boundary.</td><td>Disable execution route.</td><td>Technical owner / platform owner.</td><td>Update passport and investigate.</td></tr>
                <tr><td>Agent attempts prohibited action.</td><td>Block action and freeze workflow.</td><td>Governance owner / risk owner.</td><td>Review prohibited-action evidence.</td></tr>
                <tr><td>Agent lacks accountable owner.</td><td>Stop autonomous activity.</td><td>Business process owner.</td><td>Assign owner before restart.</td></tr>
                <tr><td>Evidence capture fails.</td><td>Restrict to read-only or recommendation mode.</td><td>Audit / platform owner.</td><td>Restore evidence logging.</td></tr>
                <tr><td>Privileged workflow triggered without approval.</td><td>Terminate privileged route.</td><td>Cybersecurity / CyberArk owner.</td><td>Cyber review and access validation.</td></tr>
                <tr><td>GxP workflow affected without QA review.</td><td>Stop regulated action path.</td><td>QA / validation owner.</td><td>Impact assessment and documented decision.</td></tr>
                <tr><td>Repeated unsafe exceptions.</td><td>Quarantine agent.</td><td>Governance board.</td><td>Reapprove agent before operational use.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Restart Rule</h2>
        <div class="answer">
            An AI agent stopped by AgentTrust™ should not return to operational use until its owner, authority,
            boundary, evidence, risk passport, and recovery route are revalidated.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Kill Switch",
        "Stop-control layer for unsafe AI agent execution, boundary violations, missing evidence, and regulated impact.",
        body
    )


@app.route("/agenttrust/drift-sentinel")
@app.route("/agenttrust/agent-drift-sentinel")
@app.route("/agenttrust/governance-drift")
def agenttrust_drift_sentinel():
    body = """
    <section class="section">
        <h2>AgentTrust™ Governance Drift Sentinel</h2>
        <p>
            Governance Drift Sentinel™ detects when the AI agent’s real behavior no longer matches its approved passport,
            risk tier, authority envelope, model version, data boundary, or permitted tool list.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Drift Type</th>
                    <th>Drift Signal</th>
                    <th>Risk Created</th>
                    <th>Required Response</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Authority Drift</td><td>Agent attempts action above approved authority.</td><td>Unauthorized execution.</td><td><span class="badge red">Block and review</span></td></tr>
                <tr><td>Tool Drift</td><td>Agent calls a tool not listed in passport.</td><td>Unapproved system interaction.</td><td><span class="badge red">Quarantine tool access</span></td></tr>
                <tr><td>Data Drift</td><td>Agent uses data source outside approved boundary.</td><td>Privacy, integrity, or compliance risk.</td><td><span class="badge orange">Restrict and investigate</span></td></tr>
                <tr><td>Model Drift</td><td>Model version, prompt, or configuration changes without review.</td><td>Unvalidated behavior change.</td><td><span class="badge red">Revalidate passport</span></td></tr>
                <tr><td>Risk Drift</td><td>Agent begins touching higher-risk workflows.</td><td>Risk tier becomes inaccurate.</td><td><span class="badge yellow">Retier agent</span></td></tr>
                <tr><td>Evidence Drift</td><td>Logging becomes incomplete or inconsistent.</td><td>Audit replay weakness.</td><td><span class="badge orange">Repair evidence chain</span></td></tr>
                <tr><td>Ownership Drift</td><td>Owner changes role, team, or leaves ownership undefined.</td><td>Broken accountability.</td><td><span class="badge red">Reassign owner</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Drift Rule</h2>
        <div class="answer">
            When the AI agent changes faster than its governance passport, AgentTrust™ treats the agent as partially untrusted
            until the passport, risk tier, owner, evidence route, and authority envelope are updated.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Governance Drift Sentinel",
        "Drift detection for AI agent authority, tools, data, model, risk, evidence, and ownership.",
        body
    )


@app.route("/agenttrust/trust-quarantine")
@app.route("/agenttrust/agent-quarantine")
@app.route("/agenttrust/autonomy-quarantine")
def agenttrust_trust_quarantine():
    body = """
    <section class="section">
        <h2>AgentTrust™ Trust Quarantine</h2>
        <p>
            Trust Quarantine is used when an AI agent cannot be fully trusted but should not be deleted immediately.
            It isolates the agent from execution while preserving evidence for investigation, correction, and governance review.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Quarantine Reason</th>
                    <th>Allowed During Quarantine</th>
                    <th>Blocked During Quarantine</th>
                    <th>Release Condition</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Missing accountable owner.</td><td>Read-only review.</td><td>Execution, update, trigger, approval.</td><td>Owner assigned and approved.</td></tr>
                <tr><td>Boundary violation.</td><td>Evidence review and root cause analysis.</td><td>Access to affected systems.</td><td>Boundary updated and verified.</td></tr>
                <tr><td>Authority violation.</td><td>Decision-rights review.</td><td>All autonomous action.</td><td>Authority envelope reapproved.</td></tr>
                <tr><td>Evidence failure.</td><td>Log repair and replay analysis.</td><td>Workflow trigger or record update.</td><td>Evidence capture restored.</td></tr>
                <tr><td>GxP impact uncertainty.</td><td>QA and validation review.</td><td>Regulated workflow influence.</td><td>QA decision documented.</td></tr>
                <tr><td>Cybersecurity concern.</td><td>Cyber investigation.</td><td>Privileged access or tool execution.</td><td>Cyber owner approval.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Quarantine Principle</h2>
        <div class="answer">
            AgentTrust™ quarantine preserves evidence while preventing unsafe AI autonomy from continuing.
            The agent can only return to operation after ownership, authority, boundary, evidence, and risk controls are restored.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Trust Quarantine",
        "Isolation layer for AI agents with unresolved ownership, authority, evidence, cyber, GxP, or boundary issues.",
        body
    )

# ============================================================
# END AGENTTRUST_EXECUTION_FIREWALL_V1_ACTIVE
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

print("AgentTrust Execution Firewall installed.")
print(f"Inserted before: {target_found}")
