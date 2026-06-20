from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_HUMAN_OVERSIGHT_WORKBENCH_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust Human Oversight Workbench already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base module not found. Install AgentTrust module first.")

nav_old = '<a href="/agenttrust/multi-agent-governance" class="secondary">Multi-Agent</a>'
nav_new = '''<a href="/agenttrust/multi-agent-governance" class="secondary">Multi-Agent</a>
                    <a href="/agenttrust/human-oversight-workbench" class="secondary">Human Oversight</a>
                    <a href="/agenttrust/approval-queue" class="dark">Approval Queue</a>
                    <a href="/agenttrust/risk-acceptance-register" class="dark">Risk Acceptance</a>
                    <a href="/agenttrust/exception-expiry-watch" class="dark">Exception Watch</a>'''

if nav_old in text and "/agenttrust/human-oversight-workbench" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# AGENTTRUST_HUMAN_OVERSIGHT_WORKBENCH_V1_ACTIVE
# AgentTrust™ Human Oversight Workbench, Approval Queue,
# Human Signoff Matrix, Risk Acceptance Register, Exception Expiry Watch,
# Approval Evidence Vault, Review Decision Simulator, and Oversight JSON
# ============================================================

AGENTTRUST_APPROVAL_QUEUE = [
    {
        "id": "AT-REV-001",
        "agent": "ServiceNow CI Triage Agent™",
        "requested_action": "Recommend CI owner and support group",
        "risk": "Medium",
        "required_owner": "LCM / CMDB Owner",
        "decision": "Human review required",
        "status": "Pending Review"
    },
    {
        "id": "AT-REV-002",
        "agent": "Cutover Readiness Summary Agent™",
        "requested_action": "Summarize cutover readiness and blockers",
        "risk": "Medium / High",
        "required_owner": "Cutover Owner / QA where applicable",
        "decision": "Human-gated summary",
        "status": "Pending Review"
    },
    {
        "id": "AT-REV-003",
        "agent": "MyAccess / CyberArk Routing Agent™",
        "requested_action": "Recommend privileged-access route",
        "risk": "High",
        "required_owner": "Cybersecurity / CyberArk Owner",
        "decision": "Escalate to cyber owner",
        "status": "Escalated"
    },
    {
        "id": "AT-REV-004",
        "agent": "GxP Inspection Evidence Agent™",
        "requested_action": "Prepare inspection evidence summary",
        "risk": "Critical",
        "required_owner": "QA / Validation Owner",
        "decision": "Human-governed only",
        "status": "QA Review"
    },
    {
        "id": "AT-REV-005",
        "agent": "Multi-Agent Orchestration Chain",
        "requested_action": "Continue handoff from CI agent to evidence packaging agent",
        "risk": "High Control",
        "required_owner": "Governance Owner",
        "decision": "Composite evidence required",
        "status": "Evidence Check"
    }
]


AGENTTRUST_RISK_ACCEPTANCES = [
    {
        "id": "AT-RA-001",
        "risk": "Agent may recommend CI ownership but cannot update production CI records.",
        "owner": "LCM / CMDB Owner",
        "expiry": "30 days",
        "condition": "Recommendation-only mode with evidence capture.",
        "status": "Active Conditional Acceptance"
    },
    {
        "id": "AT-RA-002",
        "risk": "Cutover readiness summary may rely on incomplete evidence sources.",
        "owner": "Cutover Governance Owner",
        "expiry": "14 days",
        "condition": "Must show evidence gaps and cannot approve go-live.",
        "status": "Active Conditional Acceptance"
    },
    {
        "id": "AT-RA-003",
        "risk": "Access routing agent may suggest privileged route.",
        "owner": "Cybersecurity Owner",
        "expiry": "Review required before use",
        "condition": "No access approval or privileged execution.",
        "status": "Cyber Review Required"
    },
    {
        "id": "AT-RA-004",
        "risk": "GxP evidence summary may be used for inspection preparation.",
        "owner": "QA / Validation Owner",
        "expiry": "Before regulated reliance",
        "condition": "QA review required before use in regulated response.",
        "status": "QA Review Required"
    }
]


def agenttrust_approval_queue_rows():
    rows = ""

    for item in AGENTTRUST_APPROVAL_QUEUE:
        badge = "yellow"
        if item["status"] in ["Escalated", "QA Review"]:
            badge = "red"
        elif item["status"] == "Evidence Check":
            badge = "orange"

        rows += f"""
        <tr>
            <td><strong>{item["id"]}</strong></td>
            <td>{item["agent"]}</td>
            <td>{item["requested_action"]}</td>
            <td><span class="badge blue">{item["risk"]}</span></td>
            <td>{item["required_owner"]}</td>
            <td>{item["decision"]}</td>
            <td><span class="badge {badge}">{item["status"]}</span></td>
        </tr>
        """

    return rows


def agenttrust_risk_acceptance_rows():
    rows = ""

    for item in AGENTTRUST_RISK_ACCEPTANCES:
        badge = "green"
        if "Required" in item["status"]:
            badge = "red"
        elif "Conditional" in item["status"]:
            badge = "yellow"

        rows += f"""
        <tr>
            <td><strong>{item["id"]}</strong></td>
            <td>{item["risk"]}</td>
            <td>{item["owner"]}</td>
            <td>{item["expiry"]}</td>
            <td>{item["condition"]}</td>
            <td><span class="badge {badge}">{item["status"]}</span></td>
        </tr>
        """

    return rows


@app.route("/agenttrust/human-oversight-workbench")
@app.route("/agenttrust/human-oversight")
@app.route("/agenttrust/oversight-workbench")
def agenttrust_human_oversight_workbench():
    body = """
    <section class="kpis">
        <div class="metric"><div class="label">Human Oversight</div><div class="value" style="color:var(--green);">Active</div><div class="note">Human accountability preserved.</div></div>
        <div class="metric"><div class="label">Approval Queue</div><div class="value" style="color:var(--yellow);">Gated</div><div class="note">High-impact agent actions require review.</div></div>
        <div class="metric"><div class="label">Risk Acceptance</div><div class="value" style="color:var(--orange);">Conditional</div><div class="note">Exceptions must have owner, condition, and expiry.</div></div>
        <div class="metric"><div class="label">GxP Review</div><div class="value" style="color:var(--red);">QA Routed</div><div class="note">Regulated impact requires QA / validation owner.</div></div>
        <div class="metric"><div class="label">Cyber Review</div><div class="value" style="color:var(--purple);">Escalated</div><div class="note">Privileged impact routes to cybersecurity.</div></div>
        <div class="metric"><div class="label">Evidence Vault</div><div class="value" style="color:var(--blue);">Required</div><div class="note">Human decisions must be evidenced.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Human Oversight Workbench</h2>
        <div class="answer">
            <strong>Purpose:</strong> make human oversight operational rather than theoretical.
            AI agents may recommend, draft, summarize, or prepare evidence, but final accountability must remain visible,
            assigned, reviewable, and evidenced.
        </div>

        <div class="grid">
            <div class="card"><span class="badge yellow">Queue</span><h3>Approval Queue</h3><p>Shows AI agent actions waiting for human review, QA review, cyber escalation, or evidence check.</p><a href="/agenttrust/approval-queue">Open Approval Queue</a></div>
            <div class="card"><span class="badge blue">Signoff</span><h3>Human Signoff Matrix</h3><p>Defines which owner must approve which AI agent action.</p><a href="/agenttrust/human-signoff-matrix">Open Signoff Matrix</a></div>
            <div class="card"><span class="badge orange">Risk</span><h3>Risk Acceptance Register</h3><p>Tracks conditional acceptance, owner, expiry, evidence, and accepted residual risk.</p><a href="/agenttrust/risk-acceptance-register">Open Risk Register</a></div>
            <div class="card"><span class="badge red">Expiry</span><h3>Exception Expiry Watch</h3><p>Prevents AI agents from relying on stale exceptions and expired risk decisions.</p><a href="/agenttrust/exception-expiry-watch">Open Exception Watch</a></div>
            <div class="card"><span class="badge purple">Evidence</span><h3>Approval Evidence Vault</h3><p>Defines evidence required for approve, reject, escalate, accept risk, or block decisions.</p><a href="/agenttrust/approval-evidence-vault">Open Evidence Vault</a></div>
            <div class="card"><span class="badge green">Simulator</span><h3>Review Decision Simulator</h3><p>Test human review outcomes and evidence requirements.</p><a href="/agenttrust/review-decision-simulator">Open Simulator</a></div>
        </div>
    </section>

    <section class="section">
        <h2>Human Oversight Rule</h2>
        <div class="answer">
            Human oversight is not a label. It requires a named owner, a decision point, evidence of review,
            an outcome, and a record that can be replayed later.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Human Oversight Workbench",
        "Human oversight workbench for AI agent approval queues, signoff, risk acceptance, exception expiry, review evidence, and accountability.",
        body
    )


@app.route("/agenttrust/approval-queue")
@app.route("/agenttrust/human-approval-queue")
@app.route("/agenttrust/review-queue")
def agenttrust_approval_queue():
    rows = agenttrust_approval_queue_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Approval Queue</h2>
        <p>
            This queue shows AI agent actions that require human review, evidence check, QA review, cyber escalation,
            risk acceptance, or governance decision before operational reliance.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Review ID</th>
                    <th>Agent</th>
                    <th>Requested Action</th>
                    <th>Risk</th>
                    <th>Required Owner</th>
                    <th>Decision Rule</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Approval Queue Rule</h2>
        <div class="answer">
            If an AI agent action requires review, the queue must identify the agent, requested action, risk,
            required owner, decision rule, and current status.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Approval Queue",
        "Approval queue for AI agent actions requiring human review, QA review, cyber escalation, evidence check, or governance decision.",
        body
    )


@app.route("/agenttrust/human-signoff-matrix")
@app.route("/agenttrust/signoff-matrix")
@app.route("/agenttrust/accountability-signoff")
def agenttrust_human_signoff_matrix():
    body = """
    <section class="section">
        <h2>AgentTrust™ Human Signoff Matrix</h2>
        <p>
            This matrix defines which human owner must review or approve each type of AI agent action.
        </p>

        <table>
            <thead>
                <tr>
                    <th>AI Agent Action</th>
                    <th>Required Human Owner</th>
                    <th>Evidence Required</th>
                    <th>AgentTrust™ Decision</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Read approved evidence.</td><td>Business / technical owner.</td><td>Access log and source reference.</td><td><span class="badge green">Allowed within boundary</span></td></tr>
                <tr><td>Summarize evidence.</td><td>Process owner or reviewer.</td><td>Source traceability and output record.</td><td><span class="badge green">Allowed with evidence</span></td></tr>
                <tr><td>Recommend action.</td><td>Process owner / LCM / system owner.</td><td>Recommendation rationale and reviewer decision.</td><td><span class="badge yellow">Human-gated</span></td></tr>
                <tr><td>Draft change, access, validation, or readiness text.</td><td>Workflow owner.</td><td>Draft, source, reviewer, approval status.</td><td><span class="badge yellow">Human approval required</span></td></tr>
                <tr><td>Create task or candidate record.</td><td>System owner / process owner.</td><td>Authority proof, task record, rollback path.</td><td><span class="badge orange">Restricted</span></td></tr>
                <tr><td>Update production record.</td><td>Record owner / LCM / process owner.</td><td>Approval, change record, audit log, rollback.</td><td><span class="badge red">Blocked unless approved</span></td></tr>
                <tr><td>Trigger workflow.</td><td>Workflow owner / risk owner.</td><td>Authority, evidence, rollback, outcome.</td><td><span class="badge red">Execution firewall required</span></td></tr>
                <tr><td>Approve access or privileged execution.</td><td>Access owner / cyber owner.</td><td>Human approval and cybersecurity review.</td><td><span class="badge red">AI approval prohibited</span></td></tr>
                <tr><td>Influence GxP, QA, validation, release, or inspection conclusion.</td><td>QA / validation owner.</td><td>QA review and regulated evidence package.</td><td><span class="badge red">Human-governed only</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Signoff Rule</h2>
        <div class="answer">
            The higher the operational or regulated impact, the stronger the human signoff requirement.
            AI may assist, but accountable human approval remains visible and evidenced.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Human Signoff Matrix",
        "Human signoff matrix for AI agent read, summarize, recommend, draft, create, update, trigger, access, privileged, and regulated actions.",
        body
    )


@app.route("/agenttrust/risk-acceptance-register")
@app.route("/agenttrust/agent-risk-acceptance")
@app.route("/agenttrust/ai-risk-acceptance-register")
def agenttrust_risk_acceptance_register():
    rows = agenttrust_risk_acceptance_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Risk Acceptance Register</h2>
        <p>
            This register tracks conditional risk acceptance for AI agent use cases.
            Risk acceptance must have a named owner, condition, expiry, evidence, and review trigger.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Acceptance ID</th>
                    <th>Accepted Risk</th>
                    <th>Owner</th>
                    <th>Expiry / Review</th>
                    <th>Condition</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Risk Acceptance Rule</h2>
        <div class="answer">
            AgentTrust™ does not allow open-ended AI risk acceptance.
            Every accepted risk must be conditional, owned, time-bound, evidenced, and reviewed.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Risk Acceptance Register",
        "Risk acceptance register for AI agent conditional use, residual risk, named owner, expiry, condition, and evidence.",
        body
    )


@app.route("/agenttrust/exception-expiry-watch")
@app.route("/agenttrust/exception-watch")
@app.route("/agenttrust/expiry-watch")
def agenttrust_exception_expiry_watch():
    body = """
    <section class="section">
        <h2>AgentTrust™ Exception Expiry Watch</h2>
        <p>
            Exception Expiry Watch prevents AI agents from relying on stale approvals, expired exceptions,
            old risk acceptances, or outdated human decisions.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Exception Type</th>
                    <th>Expiry Trigger</th>
                    <th>Risk If Expired</th>
                    <th>Required Action</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Temporary recommendation-only approval.</td><td>Review period expires.</td><td>Agent continues using stale approval.</td><td><span class="badge orange">Renew or revoke</span></td></tr>
                <tr><td>Cybersecurity exception.</td><td>Access route, vendor route, or privileged context changes.</td><td>Privileged AI risk becomes uncontrolled.</td><td><span class="badge red">Cyber review required</span></td></tr>
                <tr><td>QA / validation exception.</td><td>Regulated use begins or evidence source changes.</td><td>Inspection reliance may be undefended.</td><td><span class="badge red">QA review required</span></td></tr>
                <tr><td>Change-control exception.</td><td>Agent model, prompt, tool, workflow, or boundary changes.</td><td>Behavior changes outside approval.</td><td><span class="badge orange">Run change gate</span></td></tr>
                <tr><td>Owner exception.</td><td>Owner leaves role or ownership changes.</td><td>Human accountability breaks.</td><td><span class="badge red">Reassign owner</span></td></tr>
                <tr><td>Evidence exception.</td><td>Logging, replay, or evidence capture is not restored.</td><td>Audit replay becomes weak.</td><td><span class="badge orange">Restrict execution</span></td></tr>
                <tr><td>Rollback exception.</td><td>High-impact execution remains without recovery route.</td><td>Unsafe AI action may not be reversible.</td><td><span class="badge red">Block execution</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Expiry Rule</h2>
        <div class="answer">
            AI agent exceptions must not become permanent hidden approvals.
            If an exception expires, the agent should be restricted, blocked, or revalidated.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Exception Expiry Watch",
        "Exception expiry watch for AI agent temporary approvals, cyber exceptions, QA exceptions, change exceptions, owner exceptions, evidence exceptions, and rollback exceptions.",
        body
    )


@app.route("/agenttrust/approval-evidence-vault")
@app.route("/agenttrust/human-decision-evidence")
@app.route("/agenttrust/review-evidence-vault")
def agenttrust_approval_evidence_vault():
    body = """
    <section class="section">
        <h2>AgentTrust™ Approval Evidence Vault</h2>
        <p>
            The Approval Evidence Vault defines the minimum evidence required for human decisions on AI agent actions.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Human Decision</th>
                    <th>Evidence Required</th>
                    <th>Why It Matters</th>
                    <th>Replay Outcome</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Approve</td><td>Reviewer, authority, source evidence, approval timestamp, decision reason.</td><td>Proves human approval existed.</td><td><span class="badge green">Replayable</span></td></tr>
                <tr><td>Reject</td><td>Reviewer, rejection reason, risk or evidence gap, required remediation.</td><td>Prevents repeated unsafe request.</td><td><span class="badge yellow">Remediation traceable</span></td></tr>
                <tr><td>Escalate</td><td>Escalation owner, reason, risk domain, due date, evidence package.</td><td>Routes issue to correct accountable owner.</td><td><span class="badge orange">Escalation visible</span></td></tr>
                <tr><td>Accept Risk</td><td>Risk owner, condition, expiry, residual risk, mitigation, review date.</td><td>Prevents uncontrolled risk acceptance.</td><td><span class="badge red">Conditional only</span></td></tr>
                <tr><td>Block</td><td>Block reason, control failure, owner, next action, affected agent.</td><td>Shows why action was stopped.</td><td><span class="badge red">Defensible block</span></td></tr>
                <tr><td>Quarantine</td><td>Quarantine reason, allowed mode, blocked mode, release condition.</td><td>Preserves safety while investigation runs.</td><td><span class="badge red">Controlled isolation</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Evidence Vault Rule</h2>
        <div class="answer">
            Human review is only defensible when the decision and the reason for the decision are captured.
            “Human in the loop” without evidence is not enough.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Approval Evidence Vault",
        "Evidence vault for human approve, reject, escalate, accept risk, block, and quarantine decisions on AI agent actions.",
        body
    )


@app.route("/agenttrust/review-decision-simulator", methods=["GET", "POST"])
@app.route("/agenttrust/human-review-simulator", methods=["GET", "POST"])
@app.route("/agenttrust/approval-decision-simulator", methods=["GET", "POST"])
def agenttrust_review_decision_simulator():
    from flask import request

    decision = request.form.get("decision", "approve")
    risk = request.form.get("risk", "medium")
    evidence = request.form.get("evidence", "yes")
    owner = request.form.get("owner", "yes")
    expiry = request.form.get("expiry", "yes")

    if owner != "yes":
        result = "Decision Invalid — Owner Missing"
        badge = "red"
        note = "A human decision cannot be accepted without a named accountable owner."
    elif decision == "accept_risk" and expiry != "yes":
        result = "Risk Acceptance Rejected"
        badge = "red"
        note = "Risk acceptance must have an expiry or review date."
    elif evidence != "yes":
        result = "Decision Weak — Evidence Missing"
        badge = "orange"
        note = "Human decision exists but is weak because evidence is incomplete."
    elif decision == "approve" and risk in ["high", "critical"]:
        result = "Approval Requires Escalation"
        badge = "red"
        note = "High or critical risk requires QA, cyber, risk, or governance owner escalation."
    elif decision == "block":
        result = "Action Blocked"
        badge = "red"
        note = "The AI agent action is stopped and must be remediated before retry."
    elif decision == "escalate":
        result = "Escalated"
        badge = "orange"
        note = "The decision is routed to the required accountable owner."
    elif decision == "accept_risk":
        result = "Conditional Risk Acceptance"
        badge = "yellow"
        note = "Risk is accepted only under documented conditions, expiry, owner, and evidence."
    else:
        result = "Decision Accepted"
        badge = "green"
        note = "Human decision is accepted because owner, evidence, and decision context are present."

    def selected(value, expected):
        return "selected" if value == expected else ""

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Review Decision Simulator</h2>
        <p>
            Simulate a human decision on an AI agent action and check whether the decision is defensible.
        </p>

        <form method="POST" action="/agenttrust/review-decision-simulator">
            <table>
                <tbody>
                    <tr>
                        <td><strong>Human Decision</strong></td>
                        <td>
                            <select name="decision" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;">
                                <option value="approve" {selected(decision, "approve")}>Approve</option>
                                <option value="reject" {selected(decision, "reject")}>Reject</option>
                                <option value="escalate" {selected(decision, "escalate")}>Escalate</option>
                                <option value="accept_risk" {selected(decision, "accept_risk")}>Accept Risk</option>
                                <option value="block" {selected(decision, "block")}>Block</option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <td><strong>Risk Level</strong></td>
                        <td>
                            <select name="risk" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;">
                                <option value="low" {selected(risk, "low")}>Low</option>
                                <option value="medium" {selected(risk, "medium")}>Medium</option>
                                <option value="high" {selected(risk, "high")}>High</option>
                                <option value="critical" {selected(risk, "critical")}>Critical / Regulated</option>
                            </select>
                        </td>
                    </tr>
                    <tr><td><strong>Named Owner Present?</strong></td><td><select name="owner" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(owner, "yes")}>Yes</option><option value="no" {selected(owner, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Evidence Complete?</strong></td><td><select name="evidence" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(evidence, "yes")}>Yes</option><option value="no" {selected(evidence, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Expiry / Review Date Present?</strong></td><td><select name="expiry" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(expiry, "yes")}>Yes</option><option value="no" {selected(expiry, "no")}>No</option></select></td></tr>
                </tbody>
            </table>

            <button type="submit" style="margin-top:16px;padding:12px 18px;border-radius:12px;border:0;background:#2563eb;color:white;font-weight:800;">Evaluate Human Decision</button>
        </form>
    </section>

    <section class="section">
        <h2>Decision Result</h2>
        <div class="answer">
            <strong>Result:</strong> <span class="badge {badge}">{result}</span><br>
            <strong>Reason:</strong> {note}
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Review Decision Simulator",
        "Simulator for human approve, reject, escalate, accept-risk, and block decisions with owner, evidence, risk, and expiry checks.",
        body
    )


@app.route("/agenttrust/oversight-json")
@app.route("/agenttrust/human-oversight-json")
@app.route("/agenttrust/approval-queue-json")
def agenttrust_oversight_json():
    from flask import jsonify

    return jsonify({
        "module": "AgentTrust™",
        "capability": "Human Oversight Workbench",
        "primary_question": "Which human remains accountable for this AI agent action?",
        "approval_queue": AGENTTRUST_APPROVAL_QUEUE,
        "risk_acceptance_register": AGENTTRUST_RISK_ACCEPTANCES,
        "human_oversight_rules": [
            "No human owner, no operational reliance.",
            "Human review must produce evidence.",
            "Risk acceptance must be owned, conditional, evidenced, and time-bound.",
            "AI must not approve access, change, validation, release, deviation, or quality decisions by default.",
            "Cyber-impacting AI actions escalate to cybersecurity owner.",
            "GxP-impacting AI actions escalate to QA / validation owner.",
            "Expired exceptions must be renewed, revoked, or escalated."
        ]
    })

# ============================================================
# END AGENTTRUST_HUMAN_OVERSIGHT_WORKBENCH_V1_ACTIVE
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

print("AgentTrust Human Oversight Workbench installed.")
print(f"Inserted before: {target_found}")
