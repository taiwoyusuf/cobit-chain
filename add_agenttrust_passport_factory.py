from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_PASSPORT_FACTORY_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust Passport Factory already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base module not found. Install AgentTrust module first.")

nav_old = '<a href="/agenttrust/command-center" class="secondary">Command Center</a>'
nav_new = '''<a href="/agenttrust/command-center" class="secondary">Command Center</a>
                    <a href="/agenttrust/passport-factory" class="secondary">Passport Factory</a>
                    <a href="/agenttrust/sample-agent-register" class="dark">Sample Register</a>
                    <a href="/agenttrust/trust-score-engine" class="dark">Trust Score</a>
                    <a href="/agenttrust/evidence-package-builder" class="dark">Evidence Package</a>'''

if nav_old in text and "/agenttrust/passport-factory" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# AGENTTRUST_PASSPORT_FACTORY_V1_ACTIVE
# AgentTrust™ Passport Factory, Sample Register, Trust Scoring,
# Evidence Package Builder, and Escalation Router
# ============================================================

AGENTTRUST_SAMPLE_AGENTS = [
    {
        "id": "AT-AGT-001",
        "name": "ServiceNow CI Triage Agent™",
        "owner": "CMDB / LCM Owner",
        "boundary": "ServiceNow CI candidate review, orphan CI analysis, and CI ownership recommendations.",
        "tier": "Tier 2",
        "score": 88,
        "status": "Human-Gated Trusted",
        "risk": "Medium",
        "hook": "/citrust/agenttrust-integration"
    },
    {
        "id": "AT-AGT-002",
        "name": "Cutover Readiness Summary Agent™",
        "owner": "Cutover Governance Owner",
        "boundary": "Cutover readiness summaries, evidence gaps, rollback status, and post-cutover verification prompts.",
        "tier": "Tier 2",
        "score": 84,
        "status": "Conditional Trust",
        "risk": "Medium",
        "hook": "/cutovertrust/agenttrust-integration"
    },
    {
        "id": "AT-AGT-003",
        "name": "MyAccess Routing Agent™",
        "owner": "Access Governance Owner",
        "boundary": "Access-routing recommendations, entitlement review prompts, CyberArk readiness checks, and approval routing support.",
        "tier": "Tier 3",
        "score": 76,
        "status": "Restricted Execution",
        "risk": "High",
        "hook": "/citrust/myaccess-readiness/agenttrust-integration"
    },
    {
        "id": "AT-AGT-004",
        "name": "IRLT Inspection Evidence Agent™",
        "owner": "QA / Regulated Operations Owner",
        "boundary": "Inspection evidence summaries, readiness gap review, QC evidence packaging, and regulated operations support.",
        "tier": "Tier 5",
        "score": 69,
        "status": "Human-Governed Only",
        "risk": "Regulated Critical",
        "hook": "/irlt-commercial-readiness/agenttrust-integration"
    },
    {
        "id": "AT-AGT-005",
        "name": "Governance Black Box Replay Agent™",
        "owner": "Governance Assurance Owner",
        "boundary": "Decision replay, tool-call evidence review, time-of-action evidence package creation, and audit explanation.",
        "tier": "Tier 4",
        "score": 91,
        "status": "Operationally Trusted",
        "risk": "High Control",
        "hook": "/agenttrust/governance-black-box-integration"
    }
]


def agenttrust_score_badge(score):
    if score >= 90:
        return f'<span class="badge green">{score} — Operationally Trusted</span>'
    if score >= 80:
        return f'<span class="badge yellow">{score} — Human-Gated Trusted</span>'
    if score >= 70:
        return f'<span class="badge orange">{score} — Restricted</span>'
    return f'<span class="badge red">{score} — Block / Escalate</span>'


def agenttrust_sample_agent_rows():
    rows = ""

    for agent in AGENTTRUST_SAMPLE_AGENTS:
        rows += f"""
        <tr>
            <td><strong>{agent["id"]}</strong><br>{agent["name"]}</td>
            <td>{agent["owner"]}</td>
            <td>{agent["boundary"]}</td>
            <td><span class="badge purple">{agent["tier"]}</span><br>{agent["risk"]}</td>
            <td>{agenttrust_score_badge(agent["score"])}</td>
            <td>{agent["status"]}</td>
            <td><a href="{agent["hook"]}">Open hook</a></td>
        </tr>
        """

    return rows


@app.route("/agenttrust/passport-factory")
@app.route("/agenttrust/agent-passport-factory")
def agenttrust_passport_factory():
    body = """
    <section class="kpis">
        <div class="metric"><div class="label">Passport Status</div><div class="value" style="color:var(--green);">Factory</div><div class="note">Creates governance passports for AI agents.</div></div>
        <div class="metric"><div class="label">Required Fields</div><div class="value" style="color:var(--blue);">12</div><div class="note">Identity, owner, boundary, authority, evidence, and risk.</div></div>
        <div class="metric"><div class="label">Trust Score</div><div class="value" style="color:var(--yellow);">0-100</div><div class="note">Operational trust scoring model.</div></div>
        <div class="metric"><div class="label">Execution Rule</div><div class="value" style="color:var(--orange);">Gated</div><div class="note">Agents cannot act without authority.</div></div>
        <div class="metric"><div class="label">Audit Output</div><div class="value" style="color:var(--purple);">Package</div><div class="note">Builds inspection-ready evidence packs.</div></div>
        <div class="metric"><div class="label">Escalation</div><div class="value" style="color:var(--red);">Mapped</div><div class="note">Routes unsafe action to human owners.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Passport Factory</h2>
        <div class="answer">
            <strong>Purpose:</strong> generate an Agent Risk Passport™ for every AI agent before it is trusted to read, recommend,
            draft, create, update, trigger, approve, or influence regulated operations.
        </div>

        <div class="grid">
            <div class="card"><span class="badge blue">1</span><h3>Agent Identity</h3><p>Agent ID, name, business purpose, owner, technical owner, support group, and lifecycle status.</p></div>
            <div class="card"><span class="badge yellow">2</span><h3>Operating Boundary</h3><p>Approved systems, environments, workflows, APIs, data sources, and prohibited zones.</p></div>
            <div class="card"><span class="badge purple">3</span><h3>Authority Rule</h3><p>What the agent can read, recommend, draft, create, update, trigger, or never do.</p></div>
            <div class="card"><span class="badge orange">4</span><h3>Human Accountability</h3><p>Business owner, technical owner, risk owner, QA owner, cyber owner, and approver.</p></div>
            <div class="card"><span class="badge green">5</span><h3>Evidence Rule</h3><p>What must be captured at the time of action: input, output, tool, timestamp, owner, outcome.</p></div>
            <div class="card"><span class="badge red">6</span><h3>Prohibited Actions</h3><p>Actions the agent is never allowed to perform without human-governed authorization.</p></div>
            <div class="card"><span class="badge blue">7</span><h3>Risk Classification</h3><p>AI Act, GxP, cyber, privacy, validation, operational, and business-critical risk class.</p></div>
            <div class="card"><span class="badge green">8</span><h3>Audit Package</h3><p>Replayable evidence package showing who allowed the agent to act, what it did, and why.</p></div>
        </div>
    </section>

    <section class="section">
        <h2>Passport Output</h2>
        <table>
            <thead>
                <tr>
                    <th>Passport Section</th>
                    <th>Minimum Content</th>
                    <th>Fail Condition</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Identity</td><td>Agent ID, name, purpose, lifecycle status, owner.</td><td>No owner or no unique ID.</td></tr>
                <tr><td>Boundary</td><td>Connected systems, data scope, tools, workflow permissions.</td><td>Boundary is vague or unlimited.</td></tr>
                <tr><td>Authority</td><td>Allowed actions, human-gated actions, prohibited actions.</td><td>Agent can act without pre-approved authority.</td></tr>
                <tr><td>Evidence</td><td>Tool-call log, decision path, timestamp, outcome, linked record.</td><td>Evidence is reconstructed later or missing.</td></tr>
                <tr><td>Accountability</td><td>Human accountable owner, reviewer, escalation contact.</td><td>No accountable human owner.</td></tr>
                <tr><td>Risk</td><td>Risk tier, AI Act lens, GxP/cyber/validation impact.</td><td>Risk not classified before operational use.</td></tr>
                <tr><td>Rollback</td><td>Stop rule, rollback owner, exception route, verification evidence.</td><td>No recovery route for workflow-triggering agents.</td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Passport Factory",
        "Factory for generating Agent Risk Passports, trust scores, authority rules, evidence packages, and escalation paths.",
        body
    )


@app.route("/agenttrust/sample-agent-register")
@app.route("/agenttrust/register-dashboard")
def agenttrust_sample_agent_register():
    rows = agenttrust_sample_agent_rows()

    body = f"""
    <section class="section">
        <h2>Sample Agent Register</h2>
        <p>
            This is a starter register showing how COBIT-Chain™ can classify AI agents across CITrust™,
            CutoverTrust™, MyAccess/CyberArk, IRLTTrust™, and Governance Black Box.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Agent</th>
                    <th>Owner</th>
                    <th>System Boundary</th>
                    <th>Risk Tier</th>
                    <th>Trust Score</th>
                    <th>Status</th>
                    <th>Linked Hook</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>How to Use This Register Later</h2>
        <div class="grid3">
            <div class="card"><span class="badge blue">CITrust™</span><h3>Link to CIs</h3><p>Connect each AI agent to Business Application, Application Service, infrastructure CI, owner, LCM, and support group.</p></div>
            <div class="card"><span class="badge orange">CutoverTrust™</span><h3>Link to Go-Live</h3><p>Check if an AI agent can participate in cutover, rollback, post-cutover checks, and readiness reporting.</p></div>
            <div class="card"><span class="badge red">IRLTTrust™</span><h3>Link to Regulated Operations</h3><p>Identify whether an AI agent affects GMP, QC, validation, inspection evidence, or regulated decision-making.</p></div>
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Sample Agent Register",
        "Starter register for AI agent identity, ownership, boundary, risk tier, trust score, and module linkage.",
        body
    )


@app.route("/agenttrust/trust-score-engine")
@app.route("/agenttrust/scoring-engine")
def agenttrust_trust_score_engine():
    body = """
    <section class="section">
        <h2>AgentTrust™ Operational Trust Score Engine</h2>
        <div class="answer">
            The Operational Trust Score does not measure whether an AI agent is impressive.
            It measures whether the agent is governed well enough to be trusted inside operational, regulated, or enterprise workflows.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Score Domain</th>
                    <th>Weight</th>
                    <th>Evidence Required</th>
                    <th>Trust Question</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent Identity</td><td>15</td><td>Agent ID, name, role, lifecycle status.</td><td>Can the agent be uniquely identified?</td></tr>
                <tr><td>Ownership</td><td>15</td><td>Business owner, technical owner, accountable human.</td><td>Who owns the agent and its actions?</td></tr>
                <tr><td>System Boundary</td><td>15</td><td>Approved systems, APIs, data scope, prohibited zones.</td><td>Where can the agent operate?</td></tr>
                <tr><td>Authority Before Execution</td><td>15</td><td>Decision rights, approval route, allowed/prohibited actions.</td><td>Was authority confirmed before action?</td></tr>
                <tr><td>Tool-Call Evidence</td><td>15</td><td>API log, workflow trigger, data access, timestamp, outcome.</td><td>Can we prove what the agent did?</td></tr>
                <tr><td>Human Accountability</td><td>10</td><td>Reviewer, approver, escalation owner, risk owner.</td><td>Which human remains accountable?</td></tr>
                <tr><td>Rollback / Stop Control</td><td>10</td><td>Rollback owner, prior state, recovery route, stop rule.</td><td>Can unsafe action be stopped or reversed?</td></tr>
                <tr><td>Risk Passport Completeness</td><td>5</td><td>Approved Agent Risk Passport™.</td><td>Is the governance artifact complete?</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Trust Score Interpretation</h2>
        <table>
            <thead>
                <tr>
                    <th>Score Range</th>
                    <th>Trust Status</th>
                    <th>Permitted Use</th>
                    <th>Required Action</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>90-100</td><td><span class="badge green">Operationally Trusted</span></td><td>May operate inside approved boundary.</td><td>Continue monitoring and evidence capture.</td></tr>
                <tr><td>80-89</td><td><span class="badge yellow">Human-Gated Trusted</span></td><td>May recommend, draft, or act with human approval.</td><td>Close remaining gaps before wider autonomy.</td></tr>
                <tr><td>70-79</td><td><span class="badge orange">Restricted</span></td><td>Limited use only. No critical execution.</td><td>Fix authority, evidence, owner, or rollback gaps.</td></tr>
                <tr><td>0-69</td><td><span class="badge red">Blocked / Escalate</span></td><td>No operational execution.</td><td>Escalate to owner, QA, cyber, or governance board.</td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Trust Score Engine",
        "Operational trust scoring model for AI agent governance readiness.",
        body
    )


@app.route("/agenttrust/evidence-package-builder")
@app.route("/agenttrust/audit-evidence-package")
def agenttrust_evidence_package_builder():
    body = """
    <section class="section">
        <h2>AgentTrust™ Audit Evidence Package Builder</h2>
        <p>
            This builder defines the minimum evidence required to defend an AI agent action during audit,
            inspection, deviation investigation, cybersecurity review, or executive governance review.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Evidence Layer</th>
                    <th>Captured Evidence</th>
                    <th>Reason It Matters</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Identity Evidence</td><td>Agent ID, version, owner, purpose, lifecycle status.</td><td>Proves which AI agent acted.</td></tr>
                <tr><td>Authority Evidence</td><td>Approved action type, human approval, decision rights, policy route.</td><td>Proves the agent was allowed to act.</td></tr>
                <tr><td>Input Evidence</td><td>Prompt, data source, record ID, context, retrieved evidence.</td><td>Shows what the agent relied on.</td></tr>
                <tr><td>Tool Evidence</td><td>API call, workflow trigger, system touched, access path, timestamp.</td><td>Shows what the agent actually did.</td></tr>
                <tr><td>Decision Evidence</td><td>Output, recommendation, action rationale, confidence where applicable, review status.</td><td>Explains why the output or action was produced.</td></tr>
                <tr><td>Human Evidence</td><td>Reviewer, approver, accountable owner, escalation owner.</td><td>Shows human accountability did not disappear.</td></tr>
                <tr><td>Outcome Evidence</td><td>Success, failure, blocked action, rollback, exception, post-action verification.</td><td>Shows the operational result.</td></tr>
                <tr><td>Replay Evidence</td><td>Timeline from input to action to outcome.</td><td>Supports audit replay and inspection defense.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Evidence Package Rule</h2>
        <div class="answer">
            AgentTrust™ evidence must be captured <strong>at the time of action</strong>.
            If evidence must be reconstructed later, the action should be treated as weaker, higher-risk, and less defensible.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Evidence Package Builder",
        "Audit evidence package builder for AI agent actions, decisions, tools, authority, and outcomes.",
        body
    )


@app.route("/agenttrust/escalation-rules")
@app.route("/agenttrust/escalation-router")
def agenttrust_escalation_rules():
    body = """
    <section class="section">
        <h2>AgentTrust™ Escalation Router</h2>
        <p>
            This router defines where AI agent issues go when authority, ownership, evidence, risk, or regulated impact is unclear.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Trigger</th>
                    <th>Escalation Owner</th>
                    <th>Required Action</th>
                    <th>Agent Status</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>No agent owner</td><td>Business process owner / governance owner.</td><td>Assign accountable owner before use.</td><td><span class="badge red">Blocked</span></td></tr>
                <tr><td>No technical owner</td><td>IT / platform owner.</td><td>Assign support and lifecycle owner.</td><td><span class="badge red">Blocked</span></td></tr>
                <tr><td>Unclear system boundary</td><td>System owner / CMDB owner.</td><td>Define approved systems and prohibited zones.</td><td><span class="badge orange">Restricted</span></td></tr>
                <tr><td>Missing authority rule</td><td>Risk owner / process owner.</td><td>Define decision rights and action permissions.</td><td><span class="badge red">Blocked</span></td></tr>
                <tr><td>Missing tool-call evidence</td><td>Platform owner / audit owner.</td><td>Enable logs, workflow evidence, and timestamped records.</td><td><span class="badge orange">Restricted</span></td></tr>
                <tr><td>Privileged access involved</td><td>Cybersecurity / CyberArk owner.</td><td>Review privileged execution and approval routing.</td><td><span class="badge red">High Control</span></td></tr>
                <tr><td>GxP or QA impact</td><td>QA / validation owner.</td><td>Perform validation and regulated-process impact assessment.</td><td><span class="badge red">Human-Governed Only</span></td></tr>
                <tr><td>Expired exception</td><td>Risk owner / governance board.</td><td>Renew, close, or revoke exception before agent relies on it.</td><td><span class="badge red">Blocked</span></td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Escalation Router",
        "Escalation rules for AI agent ownership gaps, authority gaps, evidence gaps, cyber risk, and regulated impact.",
        body
    )

# ============================================================
# END AGENTTRUST_PASSPORT_FACTORY_V1_ACTIVE
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

print("AgentTrust Passport Factory installed.")
print(f"Inserted before: {target_found}")
