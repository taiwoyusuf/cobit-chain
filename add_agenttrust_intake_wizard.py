from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_INTAKE_WIZARD_CALCULATOR_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust Intake Wizard already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base module not found. Install AgentTrust module first.")

nav_old = '<a href="/agenttrust/scenario-lab" class="secondary">Scenario Lab</a>'
nav_new = '''<a href="/agenttrust/scenario-lab" class="secondary">Scenario Lab</a>
                    <a href="/agenttrust/intake-wizard" class="secondary">Intake Wizard</a>
                    <a href="/agenttrust/readiness-calculator" class="dark">Calculator</a>
                    <a href="/agenttrust/gxp-impact-screening" class="dark">GxP Screen</a>
                    <a href="/agenttrust/intake-summary-demo" class="dark">Intake Demo</a>'''

if nav_old in text and "/agenttrust/intake-wizard" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# AGENTTRUST_INTAKE_WIZARD_CALCULATOR_V1_ACTIVE
# AgentTrust™ Intake Wizard, Live Readiness Calculator,
# Authority Readiness Form, Evidence Readiness Form,
# GxP Impact Screening, and Intake Summary Demo
# ============================================================

AGENTTRUST_READINESS_CHECKS = [
    ("identity", "Agent identity is defined: ID, name, purpose, owner, lifecycle status.", 12),
    ("ownership", "Business owner, technical owner, support group, and accountable human are assigned.", 12),
    ("boundary", "Approved systems, tools, APIs, workflows, and data sources are defined.", 12),
    ("authority", "Permitted actions, human-gated actions, and prohibited actions are documented.", 16),
    ("evidence", "Tool-call, input, output, timestamp, owner, and outcome evidence can be captured.", 16),
    ("human", "Human reviewer, approver, escalation owner, and risk owner are mapped.", 10),
    ("runtime", "Execution firewall, runtime sentinel, kill switch, quarantine, and rollback are defined.", 12),
    ("lifecycle", "Model, prompt, tool, data, owner, and lifecycle changes are gated.", 10)
]


def agenttrust_calculated_status(score):
    if score >= 90:
        return ("Operationally Trusted", "green", "Agent may operate inside approved boundary with continuous monitoring.")
    if score >= 80:
        return ("Human-Gated Trusted", "yellow", "Agent may recommend, draft, or execute only with required human approval.")
    if score >= 70:
        return ("Restricted", "orange", "Agent should be limited until ownership, evidence, authority, or runtime gaps are closed.")
    return ("Blocked / Intake Incomplete", "red", "Agent should not be relied upon operationally until core governance controls are complete.")


@app.route("/agenttrust/intake-wizard")
@app.route("/agenttrust/agent-intake-wizard")
@app.route("/agenttrust/ai-agent-intake")
def agenttrust_intake_wizard():
    body = """
    <section class="kpis">
        <div class="metric"><div class="label">Intake Status</div><div class="value" style="color:var(--green);">Active</div><div class="note">Structured intake for AI agents.</div></div>
        <div class="metric"><div class="label">Readiness Logic</div><div class="value" style="color:var(--blue);">Scored</div><div class="note">Calculates operational trust readiness.</div></div>
        <div class="metric"><div class="label">Authority</div><div class="value" style="color:var(--yellow);">Gated</div><div class="note">Confirms what the agent may and may not do.</div></div>
        <div class="metric"><div class="label">Evidence</div><div class="value" style="color:var(--purple);">Checked</div><div class="note">Tests audit evidence sufficiency.</div></div>
        <div class="metric"><div class="label">GxP Impact</div><div class="value" style="color:var(--red);">Screened</div><div class="note">Routes regulated impact to QA / validation.</div></div>
        <div class="metric"><div class="label">Output</div><div class="value" style="color:var(--orange);">Passport</div><div class="note">Feeds Agent Risk Passport™ creation.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Intake Wizard</h2>
        <div class="answer">
            <strong>Purpose:</strong> capture the minimum governance information required before an AI agent is trusted
            inside enterprise, ServiceNow, access, cutover, cyber, GxP, or audit-relevant workflows.
        </div>

        <div class="grid">
            <div class="card"><span class="badge green">1</span><h3>Agent Intake Form</h3><p>Capture agent name, purpose, owners, systems, tools, data, and intended use.</p><a href="/agenttrust/agent-intake-form">Open Intake Form</a></div>
            <div class="card"><span class="badge blue">2</span><h3>Readiness Calculator</h3><p>Score identity, ownership, boundary, authority, evidence, runtime, and lifecycle readiness.</p><a href="/agenttrust/readiness-calculator">Open Calculator</a></div>
            <div class="card"><span class="badge yellow">3</span><h3>Authority Readiness</h3><p>Check whether the agent can read, recommend, draft, create, update, trigger, or approve.</p><a href="/agenttrust/authority-readiness-form">Open Authority Form</a></div>
            <div class="card"><span class="badge purple">4</span><h3>Evidence Readiness</h3><p>Check whether the action can be defended with evidence at the time of action.</p><a href="/agenttrust/evidence-readiness-form">Open Evidence Form</a></div>
            <div class="card"><span class="badge red">5</span><h3>GxP Impact Screening</h3><p>Screen AI agent impact on GMP, QA, validation, release, deviation, access, and inspection evidence.</p><a href="/agenttrust/gxp-impact-screening">Open GxP Screen</a></div>
            <div class="card"><span class="badge orange">6</span><h3>Intake Summary Demo</h3><p>View a demo-ready sample intake packet for a governed AI agent.</p><a href="/agenttrust/intake-summary-demo">Open Demo</a></div>
        </div>
    </section>

    <section class="section">
        <h2>Intake Rule</h2>
        <div class="answer">
            AgentTrust™ should not trust an AI agent because it works technically.
            It should trust the agent only when identity, ownership, boundary, authority, evidence, human accountability,
            runtime safety, lifecycle control, and regulated impact are clear.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Intake Wizard",
        "Structured AI agent intake wizard for identity, ownership, boundary, authority, evidence, GxP impact, runtime safety, and operational trust readiness.",
        body
    )


@app.route("/agenttrust/agent-intake-form", methods=["GET", "POST"])
@app.route("/agenttrust/intake-form", methods=["GET", "POST"])
def agenttrust_agent_intake_form():
    from flask import request
    from html import escape

    submitted = request.method == "POST"

    agent_name = escape(request.form.get("agent_name", ""))
    business_owner = escape(request.form.get("business_owner", ""))
    technical_owner = escape(request.form.get("technical_owner", ""))
    agent_purpose = escape(request.form.get("agent_purpose", ""))
    systems = escape(request.form.get("systems", ""))
    tools = escape(request.form.get("tools", ""))
    data_sources = escape(request.form.get("data_sources", ""))
    intended_actions = escape(request.form.get("intended_actions", ""))
    prohibited_actions = escape(request.form.get("prohibited_actions", ""))
    evidence_required = escape(request.form.get("evidence_required", ""))

    summary = ""

    if submitted:
        summary = f"""
        <section class="section">
            <h2>Generated Intake Summary</h2>
            <table>
                <thead>
                    <tr>
                        <th>Intake Field</th>
                        <th>Captured Value</th>
                        <th>AgentTrust™ Interpretation</th>
                    </tr>
                </thead>
                <tbody>
                    <tr><td>Agent Name</td><td>{agent_name or "Not provided"}</td><td>Used for Agent Register and Passport.</td></tr>
                    <tr><td>Business Owner</td><td>{business_owner or "Not provided"}</td><td>Required for accountability.</td></tr>
                    <tr><td>Technical Owner</td><td>{technical_owner or "Not provided"}</td><td>Required for support and lifecycle governance.</td></tr>
                    <tr><td>Purpose</td><td>{agent_purpose or "Not provided"}</td><td>Defines approved business use.</td></tr>
                    <tr><td>Systems</td><td>{systems or "Not provided"}</td><td>Defines operating boundary.</td></tr>
                    <tr><td>Tools / APIs</td><td>{tools or "Not provided"}</td><td>Defines execution capability.</td></tr>
                    <tr><td>Data Sources</td><td>{data_sources or "Not provided"}</td><td>Defines evidence and data boundary.</td></tr>
                    <tr><td>Intended Actions</td><td>{intended_actions or "Not provided"}</td><td>Feeds authority matrix.</td></tr>
                    <tr><td>Prohibited Actions</td><td>{prohibited_actions or "Not provided"}</td><td>Feeds prohibited action sentinel.</td></tr>
                    <tr><td>Evidence Required</td><td>{evidence_required or "Not provided"}</td><td>Feeds evidence ledger and replay package.</td></tr>
                </tbody>
            </table>
            <div class="answer">
                <strong>Next step:</strong> run the Readiness Calculator, Authority Readiness Form, Evidence Readiness Form,
                and GxP Impact Screening before this agent is trusted.
            </div>
        </section>
        """

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Agent Intake Form</h2>
        <p>
            Use this form to capture the minimum governance profile for a proposed AI agent.
        </p>

        <form method="POST" action="/agenttrust/agent-intake-form">
            <table>
                <tbody>
                    <tr><td><strong>Agent Name</strong></td><td><input name="agent_name" value="{agent_name}" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"></td></tr>
                    <tr><td><strong>Business Owner</strong></td><td><input name="business_owner" value="{business_owner}" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"></td></tr>
                    <tr><td><strong>Technical Owner</strong></td><td><input name="technical_owner" value="{technical_owner}" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"></td></tr>
                    <tr><td><strong>Agent Purpose</strong></td><td><textarea name="agent_purpose" style="width:100%;height:70px;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;">{agent_purpose}</textarea></td></tr>
                    <tr><td><strong>Connected Systems</strong></td><td><textarea name="systems" style="width:100%;height:70px;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;">{systems}</textarea></td></tr>
                    <tr><td><strong>Tools / APIs / Workflows</strong></td><td><textarea name="tools" style="width:100%;height:70px;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;">{tools}</textarea></td></tr>
                    <tr><td><strong>Data Sources</strong></td><td><textarea name="data_sources" style="width:100%;height:70px;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;">{data_sources}</textarea></td></tr>
                    <tr><td><strong>Intended Actions</strong></td><td><textarea name="intended_actions" style="width:100%;height:70px;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;">{intended_actions}</textarea></td></tr>
                    <tr><td><strong>Prohibited Actions</strong></td><td><textarea name="prohibited_actions" style="width:100%;height:70px;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;">{prohibited_actions}</textarea></td></tr>
                    <tr><td><strong>Evidence Required</strong></td><td><textarea name="evidence_required" style="width:100%;height:70px;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;">{evidence_required}</textarea></td></tr>
                </tbody>
            </table>

            <button type="submit" style="margin-top:16px;padding:12px 18px;border-radius:12px;border:0;background:#2563eb;color:white;font-weight:800;">Generate Intake Summary</button>
        </form>
    </section>

    {summary}
    """

    return agenttrust_shell(
        "AgentTrust™ Agent Intake Form",
        "Interactive intake form for capturing AI agent identity, ownership, purpose, systems, tools, data sources, actions, prohibited actions, and evidence requirements.",
        body
    )


@app.route("/agenttrust/readiness-calculator", methods=["GET", "POST"])
@app.route("/agenttrust/live-readiness-calculator", methods=["GET", "POST"])
@app.route("/agenttrust/agent-readiness-calculator", methods=["GET", "POST"])
def agenttrust_readiness_calculator():
    from flask import request

    selected = set(request.form.getlist("checks")) if request.method == "POST" else set()
    score = sum(weight for key, label, weight in AGENTTRUST_READINESS_CHECKS if key in selected)
    status, badge, note = agenttrust_calculated_status(score)

    rows = ""
    for key, label, weight in AGENTTRUST_READINESS_CHECKS:
        checked = "checked" if key in selected else ""
        state = '<span class="badge green">Selected</span>' if key in selected else '<span class="badge red">Missing</span>'
        rows += f"""
        <tr>
            <td><input type="checkbox" name="checks" value="{key}" {checked}></td>
            <td><strong>{label}</strong></td>
            <td>{weight}</td>
            <td>{state}</td>
        </tr>
        """

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Readiness Score</div><div class="value" style="color:var(--green);">{score}</div><div class="note">Calculated from selected governance controls.</div></div>
        <div class="metric"><div class="label">Trust Status</div><div class="value" style="color:var(--yellow);">{status}</div><div class="note">{note}</div></div>
        <div class="metric"><div class="label">Required Max</div><div class="value" style="color:var(--blue);">100</div><div class="note">Full operational trust package.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Live Readiness Calculator</h2>
        <p>
            Select the controls that are complete for the AI agent. The calculator returns the operational trust status.
        </p>

        <form method="POST" action="/agenttrust/readiness-calculator">
            <table>
                <thead>
                    <tr>
                        <th>Select</th>
                        <th>Readiness Control</th>
                        <th>Weight</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>

            <button type="submit" style="margin-top:16px;padding:12px 18px;border-radius:12px;border:0;background:#2563eb;color:white;font-weight:800;">Calculate Readiness</button>
        </form>
    </section>

    <section class="section">
        <h2>Decision Result</h2>
        <div class="answer">
            <strong>Score:</strong> {score}/100<br>
            <strong>Status:</strong> <span class="badge {badge}">{status}</span><br>
            <strong>Decision:</strong> {note}
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Live Readiness Calculator",
        "Interactive readiness calculator for AI agent identity, ownership, boundary, authority, evidence, accountability, runtime safety, and lifecycle governance.",
        body
    )


@app.route("/agenttrust/authority-readiness-form", methods=["GET", "POST"])
@app.route("/agenttrust/authority-calculator", methods=["GET", "POST"])
@app.route("/agenttrust/action-authority-screen", methods=["GET", "POST"])
def agenttrust_authority_readiness_form():
    from flask import request

    action_rules = [
        ("read", "Agent may read approved records or evidence.", "Low", "Allowed if source and access are approved."),
        ("summarize", "Agent may summarize approved evidence.", "Low / Medium", "Allowed with source traceability."),
        ("recommend", "Agent may recommend an action.", "Medium", "Human review required."),
        ("draft", "Agent may draft request, change text, or evidence summary.", "Medium", "Human approval required before use."),
        ("create", "Agent may create ticket, candidate, or task.", "High", "Workflow authority and evidence required."),
        ("update", "Agent may update a record or CI field.", "High", "Human approval, rollback, and audit log required."),
        ("trigger", "Agent may trigger workflow, job, access request, or automation.", "High / Critical", "Execution firewall and approval required."),
        ("approve", "Agent may approve access, change, release, validation, or quality decision.", "Critical", "Prohibited by default."),
        ("privileged", "Agent may influence privileged or CyberArk-related execution.", "Critical", "Cybersecurity review required.")
    ]

    selected = set(request.form.getlist("actions")) if request.method == "POST" else set()

    critical = {"approve", "privileged", "trigger"}
    high = {"create", "update"}

    if selected & critical:
        decision = "Restricted / Blocked"
        badge = "red"
        note = "Selected action includes critical execution, approval, or privileged impact. Human governance and escalation required."
    elif selected & high:
        decision = "Human-Gated Execution"
        badge = "orange"
        note = "Selected action includes create or update capability. Approval, rollback, and evidence are required."
    elif selected:
        decision = "Recommendation / Draft Mode"
        badge = "yellow"
        note = "Agent may operate only within approved advisory or draft boundary."
    else:
        decision = "No Action Selected"
        badge = "red"
        note = "Authority cannot be assessed until intended actions are selected."

    rows = ""
    for key, label, risk, rule in action_rules:
        checked = "checked" if key in selected else ""
        rows += f"""
        <tr>
            <td><input type="checkbox" name="actions" value="{key}" {checked}></td>
            <td><strong>{label}</strong></td>
            <td><span class="badge blue">{risk}</span></td>
            <td>{rule}</td>
        </tr>
        """

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Authority Readiness Form</h2>
        <p>
            Select the action types the AI agent is expected to perform or influence.
        </p>

        <form method="POST" action="/agenttrust/authority-readiness-form">
            <table>
                <thead>
                    <tr>
                        <th>Select</th>
                        <th>Action Type</th>
                        <th>Risk</th>
                        <th>AgentTrust™ Rule</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>

            <button type="submit" style="margin-top:16px;padding:12px 18px;border-radius:12px;border:0;background:#2563eb;color:white;font-weight:800;">Assess Authority</button>
        </form>
    </section>

    <section class="section">
        <h2>Authority Decision</h2>
        <div class="answer">
            <strong>Decision:</strong> <span class="badge {badge}">{decision}</span><br>
            <strong>Reason:</strong> {note}
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Authority Readiness Form",
        "Interactive authority screening form for AI agent read, summarize, recommend, draft, create, update, trigger, approve, and privileged action capabilities.",
        body
    )


@app.route("/agenttrust/evidence-readiness-form", methods=["GET", "POST"])
@app.route("/agenttrust/evidence-calculator", methods=["GET", "POST"])
@app.route("/agenttrust/evidence-readiness-screen", methods=["GET", "POST"])
def agenttrust_evidence_readiness_form():
    from flask import request

    evidence_checks = [
        ("input", "Input evidence captured: prompt, source data, context, requester, timestamp."),
        ("authority", "Authority evidence captured before action."),
        ("tool", "Tool-call evidence captured: API, workflow, data access, system touched."),
        ("output", "Output evidence captured: recommendation, draft, update, trigger result."),
        ("human", "Human evidence captured: reviewer, approver, accountable owner."),
        ("outcome", "Outcome evidence captured: executed, blocked, escalated, failed, rolled back."),
        ("timeline", "Action timeline can be reconstructed."),
        ("retention", "Evidence retention and archive location are defined.")
    ]

    selected = set(request.form.getlist("evidence")) if request.method == "POST" else set()
    score = int((len(selected) / len(evidence_checks)) * 100) if evidence_checks else 0

    if score >= 90:
        decision = "Evidence Sufficient"
        badge = "green"
        note = "Evidence package is strong enough for operational reliance and audit replay."
    elif score >= 75:
        decision = "Evidence Mostly Sufficient"
        badge = "yellow"
        note = "Evidence is usable but should be strengthened before high-risk execution."
    elif score >= 50:
        decision = "Evidence Weak"
        badge = "orange"
        note = "Agent should be restricted to recommendation or draft mode until evidence gaps are closed."
    else:
        decision = "Evidence Not Sufficient"
        badge = "red"
        note = "Agent should not execute operational actions because audit replay would be weak."

    rows = ""
    for key, label in evidence_checks:
        checked = "checked" if key in selected else ""
        state = '<span class="badge green">Ready</span>' if key in selected else '<span class="badge red">Gap</span>'
        rows += f"""
        <tr>
            <td><input type="checkbox" name="evidence" value="{key}" {checked}></td>
            <td><strong>{label}</strong></td>
            <td>{state}</td>
        </tr>
        """

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Evidence Score</div><div class="value" style="color:var(--blue);">{score}%</div><div class="note">Evidence readiness based on selected controls.</div></div>
        <div class="metric"><div class="label">Decision</div><div class="value" style="color:var(--yellow);">{decision}</div><div class="note">{note}</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Evidence Readiness Form</h2>
        <p>
            Select the evidence controls that are available at the time of AI agent action.
        </p>

        <form method="POST" action="/agenttrust/evidence-readiness-form">
            <table>
                <thead>
                    <tr>
                        <th>Select</th>
                        <th>Evidence Control</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>

            <button type="submit" style="margin-top:16px;padding:12px 18px;border-radius:12px;border:0;background:#2563eb;color:white;font-weight:800;">Assess Evidence</button>
        </form>
    </section>

    <section class="section">
        <h2>Evidence Decision</h2>
        <div class="answer">
            <strong>Decision:</strong> <span class="badge {badge}">{decision}</span><br>
            <strong>Reason:</strong> {note}
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Evidence Readiness Form",
        "Interactive evidence readiness form for AI agent input, authority, tool-call, output, human, outcome, timeline, and retention evidence.",
        body
    )


@app.route("/agenttrust/gxp-impact-screening", methods=["GET", "POST"])
@app.route("/agenttrust/gxp-screening", methods=["GET", "POST"])
@app.route("/agenttrust/regulated-impact-screening", methods=["GET", "POST"])
def agenttrust_gxp_impact_screening():
    from flask import request

    impact_checks = [
        ("gmp", "Agent reads, summarizes, or influences GMP system data."),
        ("qc", "Agent touches QC readiness, QC evidence, or QC interpretation."),
        ("validation", "Agent summarizes, classifies, or influences validation evidence."),
        ("deviation", "Agent supports deviation, CAPA, root cause, or closure language."),
        ("batch", "Agent influences batch, release, disposition, or regulated claim."),
        ("inspection", "Agent prepares audit or inspection evidence."),
        ("access", "Agent influences access, CyberArk, privileged execution, or entitlement routing."),
        ("none", "No GxP, QA, validation, release, inspection, access, or privileged impact identified.")
    ]

    selected = set(request.form.getlist("impact")) if request.method == "POST" else set()

    critical = {"qc", "validation", "deviation", "batch", "inspection"}
    access = {"access"}

    if selected & critical:
        decision = "QA / Validation Review Required"
        badge = "red"
        note = "The agent touches regulated or quality-relevant evidence. Human-governed execution is required."
    elif selected & access:
        decision = "Cybersecurity Review Required"
        badge = "orange"
        note = "The agent influences access or privileged workflow. Cybersecurity and access owner review are required."
    elif "gmp" in selected:
        decision = "GMP Impact Review Required"
        badge = "yellow"
        note = "The agent touches GMP data. System owner and QA impact review may be required."
    elif "none" in selected:
        decision = "No Regulated Impact Identified"
        badge = "green"
        note = "No GxP or privileged impact was selected, but ownership and evidence controls still apply."
    else:
        decision = "Impact Not Assessed"
        badge = "red"
        note = "Select at least one impact area before trusting the agent."

    rows = ""
    for key, label in impact_checks:
        checked = "checked" if key in selected else ""
        rows += f"""
        <tr>
            <td><input type="checkbox" name="impact" value="{key}" {checked}></td>
            <td><strong>{label}</strong></td>
        </tr>
        """

    body = f"""
    <section class="section">
        <h2>AgentTrust™ GxP Impact Screening</h2>
        <p>
            Select any regulated, quality, validation, access, or privileged impact the AI agent may have.
        </p>

        <form method="POST" action="/agenttrust/gxp-impact-screening">
            <table>
                <thead>
                    <tr>
                        <th>Select</th>
                        <th>Impact Area</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>

            <button type="submit" style="margin-top:16px;padding:12px 18px;border-radius:12px;border:0;background:#2563eb;color:white;font-weight:800;">Screen Impact</button>
        </form>
    </section>

    <section class="section">
        <h2>Impact Decision</h2>
        <div class="answer">
            <strong>Decision:</strong> <span class="badge {badge}">{decision}</span><br>
            <strong>Reason:</strong> {note}
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ GxP Impact Screening",
        "Interactive screening for AI agent impact on GMP, QC, validation, deviation, batch, release, inspection, access, and privileged execution.",
        body
    )


@app.route("/agenttrust/intake-summary-demo")
@app.route("/agenttrust/sample-intake-summary")
@app.route("/agenttrust/intake-packet-demo")
def agenttrust_intake_summary_demo():
    body = """
    <section class="section">
        <h2>AgentTrust™ Sample Intake Summary</h2>
        <div class="answer">
            <strong>Sample Agent:</strong> ServiceNow CMDB Ownership Recommendation Agent<br>
            <strong>Primary Use:</strong> Reviews CI candidates, orphan CIs, support group gaps, and ownership inconsistencies.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Intake Domain</th>
                    <th>Sample Entry</th>
                    <th>AgentTrust™ Decision</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent Identity</td><td>AT-AGT-001 — ServiceNow CMDB Ownership Recommendation Agent.</td><td><span class="badge green">Registered</span></td></tr>
                <tr><td>Business Owner</td><td>CMDB / Service Governance Owner.</td><td><span class="badge green">Owner assigned</span></td></tr>
                <tr><td>Technical Owner</td><td>ServiceNow Platform Owner / Support Group.</td><td><span class="badge green">Support mapped</span></td></tr>
                <tr><td>System Boundary</td><td>ServiceNow CMDB, CITrust™ candidate review, CI ownership fields.</td><td><span class="badge yellow">Boundary defined</span></td></tr>
                <tr><td>Allowed Actions</td><td>Read, summarize, recommend, draft candidate notes.</td><td><span class="badge yellow">Human-gated</span></td></tr>
                <tr><td>Prohibited Actions</td><td>Approve CI update, change lifecycle state, assign LCM, delete evidence.</td><td><span class="badge red">Blocked</span></td></tr>
                <tr><td>Evidence</td><td>Source CI, recommendation, rationale, reviewer, timestamp, outcome.</td><td><span class="badge green">Replayable if captured</span></td></tr>
                <tr><td>GxP Impact</td><td>Possible if CI supports regulated operations.</td><td><span class="badge orange">Route to QA if regulated</span></td></tr>
                <tr><td>Runtime Control</td><td>Execution firewall blocks direct production update.</td><td><span class="badge red">Update blocked without approval</span></td></tr>
                <tr><td>Readiness Score</td><td>Estimated 84 / 100.</td><td><span class="badge yellow">Human-Gated Trusted</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Sample Intake Conclusion</h2>
        <div class="answer">
            <strong>Conclusion:</strong> This AI agent may support CI review by summarizing and recommending ownership,
            but production CI updates, LCM assignment, lifecycle changes, and regulated-impact conclusions require human approval
            and evidence capture.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Intake Summary Demo",
        "Sample AI agent intake packet showing identity, ownership, boundary, authority, prohibited actions, evidence, GxP impact, runtime control, and readiness score.",
        body
    )

# ============================================================
# END AGENTTRUST_INTAKE_WIZARD_CALCULATOR_V1_ACTIVE
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

print("AgentTrust Intake Wizard installed.")
print(f"Inserted before: {target_found}")
