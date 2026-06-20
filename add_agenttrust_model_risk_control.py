from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_MODEL_RISK_VALIDATION_CENTER_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust Model Risk Control Center already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base module not found. Install AgentTrust module first.")

nav_old = '<a href="/agenttrust/privacy-boundary-center" class="secondary">Privacy Boundary</a>'
nav_new = '''<a href="/agenttrust/privacy-boundary-center" class="secondary">Privacy Boundary</a>
                    <a href="/agenttrust/model-risk-control-center" class="secondary">Model Risk</a>
                    <a href="/agenttrust/model-validation-evidence-hub" class="dark">Validation Evidence</a>
                    <a href="/agenttrust/model-performance-monitor" class="dark">Performance</a>
                    <a href="/agenttrust/model-risk-simulator" class="dark">Model Risk</a>'''

if nav_old in text and "/agenttrust/model-risk-control-center" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# AGENTTRUST_MODEL_RISK_VALIDATION_CENTER_V1_ACTIVE
# AgentTrust™ Model Risk Control Center, Model Risk Register,
# Model Validation Evidence Hub, Model Performance Monitor,
# Bias / Fairness / Suitability Screen, Model Limitation Register,
# Model Change Validation Gate, Model Risk Simulator,
# and Model Risk JSON Export
# ============================================================

AGENTTRUST_MODEL_RISK_REGISTER = [
    {
        "model_id": "AT-MDL-001",
        "model": "Enterprise LLM / Foundation Model",
        "agent_dependency": "ServiceNow CMDB Ownership Recommendation Agent™",
        "model_role": "Summarization, classification, recommendation drafting, gap explanation.",
        "risk_tier": "High",
        "owner": "AI Platform Owner / Governance Owner",
        "required_control": "Model identity, prompt boundary, source evidence, human review, and monitoring."
    },
    {
        "model_id": "AT-MDL-002",
        "model": "Access Routing Reasoning Model",
        "agent_dependency": "MyAccess / CyberArk Routing Agent™",
        "model_role": "Classifies access context and recommends access-owner route.",
        "risk_tier": "Critical",
        "owner": "Cybersecurity / Access Owner",
        "required_control": "Cyber review, no autonomous access approval, privileged-action block, evidence replay."
    },
    {
        "model_id": "AT-MDL-003",
        "model": "GxP Evidence Summary Model",
        "agent_dependency": "GxP Inspection Evidence Agent™",
        "model_role": "Summarizes validation, QA, QC, inspection, and regulated evidence.",
        "risk_tier": "Critical",
        "owner": "QA / Validation Owner",
        "required_control": "QA-governed use, regulated conclusion block, source lineage, validation evidence."
    },
    {
        "model_id": "AT-MDL-004",
        "model": "Cutover Readiness Reasoning Model",
        "agent_dependency": "Cutover Readiness Summary Agent™",
        "model_role": "Summarizes readiness, blockers, rollback gaps, evidence gaps, and owner actions.",
        "risk_tier": "High",
        "owner": "Cutover / Transition Owner",
        "required_control": "Human-gated output, blocker visibility, rollback evidence, no go-live approval."
    },
    {
        "model_id": "AT-MDL-005",
        "model": "Document Intelligence Model",
        "agent_dependency": "Vendor Document Intelligence AI / Evidence Packaging Agent™",
        "model_role": "Extracts, summarizes, and structures evidence from documents.",
        "risk_tier": "High",
        "owner": "Document / Audit / Quality Owner",
        "required_control": "Source traceability, document boundary, evidence quality, reviewer signoff."
    },
    {
        "model_id": "AT-MDL-006",
        "model": "Executive Reporting Model",
        "agent_dependency": "Leadership Dashboard / Board Pack Agent™",
        "model_role": "Converts governance data into executive summaries and scorecards.",
        "risk_tier": "Medium",
        "owner": "Governance Reporting Owner",
        "required_control": "Metric lineage, evidence-backed trust distinction, no unsupported assurance claims."
    }
]


AGENTTRUST_MODEL_VALIDATION_CONTROLS = [
    {
        "control_id": "AT-MVAL-001",
        "control": "Model Identity",
        "question": "Is the model, provider, version, endpoint, deployment, owner, and hosting boundary known?",
        "evidence": "Model register, deployment record, platform owner, endpoint reference.",
        "failure_response": "Block operational reliance."
    },
    {
        "control_id": "AT-MVAL-002",
        "control": "Intended Use Validation",
        "question": "Is the model approved for the agent's intended use and action type?",
        "evidence": "Use case approval, agent passport, operating license, trust contract.",
        "failure_response": "Restrict to sandbox or advisory mode."
    },
    {
        "control_id": "AT-MVAL-003",
        "control": "Input Boundary Validation",
        "question": "Are allowed inputs, prohibited inputs, sensitive data, and regulated data boundaries defined?",
        "evidence": "Privacy boundary, data classification, GxP/cyber screen, minimization record.",
        "failure_response": "Route to privacy, cyber, QA, or data owner."
    },
    {
        "control_id": "AT-MVAL-004",
        "control": "Output Reliability Validation",
        "question": "Can the model output be checked against source evidence and human review?",
        "evidence": "Source lineage, output review, reviewer decision, evidence replay.",
        "failure_response": "Human-gate or restrict reliance."
    },
    {
        "control_id": "AT-MVAL-005",
        "control": "Hallucination / Unsupported Claim Control",
        "question": "Does the model separate evidence-backed statements from assumptions or unsupported claims?",
        "evidence": "Citation/source map, uncertainty label, unsupported-claim flag.",
        "failure_response": "Block unsupported operational conclusion."
    },
    {
        "control_id": "AT-MVAL-006",
        "control": "Performance Monitoring",
        "question": "Are model quality, error patterns, drift, false confidence, and escalation failures monitored?",
        "evidence": "Performance dashboard, exception log, monitoring event register.",
        "failure_response": "Re-score, re-gate, or quarantine."
    },
    {
        "control_id": "AT-MVAL-007",
        "control": "Bias / Fairness / Suitability Screen",
        "question": "Could the model create unfair, inappropriate, or unsuitable outcomes for people, access, work allocation, or regulated decisions?",
        "evidence": "Bias screen, reviewer route, decision limitation, human accountability.",
        "failure_response": "Restrict or require human-governed use."
    },
    {
        "control_id": "AT-MVAL-008",
        "control": "Model Change Validation",
        "question": "Does any model, prompt, endpoint, tool, data, or configuration change trigger validation review?",
        "evidence": "Change gate record, drift signal, validation test, updated trust score.",
        "failure_response": "Suspend current trust decision."
    }
]


AGENTTRUST_MODEL_LIMITATIONS = [
    {
        "limitation_id": "AT-LIM-001",
        "limitation": "Model output is not an approval.",
        "affected_agents": "All recommendation, drafting, access, GxP, and cutover agents.",
        "risk": "Hidden AI approval or over-reliance.",
        "required_guardrail": "Output must be reviewed by accountable human owner before operational reliance."
    },
    {
        "limitation_id": "AT-LIM-002",
        "limitation": "Model may summarize evidence incorrectly.",
        "affected_agents": "Document Intelligence, GxP Evidence, Cutover Readiness, Audit Dossier agents.",
        "risk": "Incorrect evidence interpretation.",
        "required_guardrail": "Source evidence and reviewer signoff required."
    },
    {
        "limitation_id": "AT-LIM-003",
        "limitation": "Model may infer ownership or responsibility incorrectly.",
        "affected_agents": "ServiceNow CMDB and CI ownership agents.",
        "risk": "Wrong CI owner, support group, or LCM recommendation.",
        "required_guardrail": "Recommendation-only mode with LCM / CMDB owner review."
    },
    {
        "limitation_id": "AT-LIM-004",
        "limitation": "Model must not approve access or privileged activity.",
        "affected_agents": "MyAccess / CyberArk / PSM agents.",
        "risk": "Unauthorized access or privileged workflow influence.",
        "required_guardrail": "Cyber-gated review and access approval prohibition."
    },
    {
        "limitation_id": "AT-LIM-005",
        "limitation": "Model must not make regulated conclusions.",
        "affected_agents": "GxP, QA, validation, QC, release, deviation, CAPA, inspection agents.",
        "risk": "Inspection and GMP defensibility failure.",
        "required_guardrail": "QA / validation owner review and regulated conclusion block."
    },
    {
        "limitation_id": "AT-LIM-006",
        "limitation": "Model may be sensitive to prompt, retrieval, or context drift.",
        "affected_agents": "All AI agents.",
        "risk": "Trust score becomes stale after change.",
        "required_guardrail": "Lifecycle change gate, drift monitoring, and revalidation."
    }
]


AGENTTRUST_MODEL_PERFORMANCE_SIGNALS = [
    {
        "signal": "Unsupported claim rate",
        "meaning": "How often the model produces statements without source evidence.",
        "threshold": "Low tolerance for regulated, cyber, access, and executive assurance use.",
        "response": "Human-gate, source-check, or restrict output."
    },
    {
        "signal": "Escalation miss rate",
        "meaning": "How often the model fails to route cyber, GxP, privacy, or owner review.",
        "threshold": "Zero tolerance for critical routes.",
        "response": "Block or quarantine until route logic is remediated."
    },
    {
        "signal": "Boundary violation rate",
        "meaning": "How often the model attempts action outside approved system, tool, data, or workflow boundary.",
        "threshold": "Zero tolerance for execution agents.",
        "response": "Execution firewall block and release gate review."
    },
    {
        "signal": "Evidence completeness score",
        "meaning": "Percentage of actions with input, source, tool-call, output, human, timestamp, and outcome evidence.",
        "threshold": "High evidence completeness required for operational reliance.",
        "response": "Restrict reliance if evidence is weak."
    },
    {
        "signal": "Reviewer correction rate",
        "meaning": "How often human reviewers correct or reject model output.",
        "threshold": "Rising trend signals trust degradation.",
        "response": "Re-score trust and run performance review."
    },
    {
        "signal": "Drift event count",
        "meaning": "Number of model, prompt, tool, data, endpoint, or configuration changes since last approval.",
        "threshold": "Material drift requires review.",
        "response": "Run model change validation gate."
    }
]


def agenttrust_model_risk_rows():
    rows = ""

    for item in AGENTTRUST_MODEL_RISK_REGISTER:
        badge = "blue"
        if item["risk_tier"] == "Critical":
            badge = "red"
        elif item["risk_tier"] == "High":
            badge = "orange"
        elif item["risk_tier"] == "Medium":
            badge = "yellow"

        rows += f"""
        <tr>
            <td><strong>{item["model_id"]}</strong></td>
            <td>{item["model"]}</td>
            <td>{item["agent_dependency"]}</td>
            <td>{item["model_role"]}</td>
            <td><span class="badge {badge}">{item["risk_tier"]}</span></td>
            <td>{item["owner"]}</td>
            <td>{item["required_control"]}</td>
        </tr>
        """

    return rows


def agenttrust_model_validation_rows():
    rows = ""

    for item in AGENTTRUST_MODEL_VALIDATION_CONTROLS:
        rows += f"""
        <tr>
            <td><strong>{item["control_id"]}</strong></td>
            <td><span class="badge blue">{item["control"]}</span></td>
            <td>{item["question"]}</td>
            <td>{item["evidence"]}</td>
            <td><span class="badge red">{item["failure_response"]}</span></td>
        </tr>
        """

    return rows


def agenttrust_model_limitation_rows():
    rows = ""

    for item in AGENTTRUST_MODEL_LIMITATIONS:
        rows += f"""
        <tr>
            <td><strong>{item["limitation_id"]}</strong></td>
            <td>{item["limitation"]}</td>
            <td>{item["affected_agents"]}</td>
            <td><span class="badge red">{item["risk"]}</span></td>
            <td>{item["required_guardrail"]}</td>
        </tr>
        """

    return rows


def agenttrust_model_performance_rows():
    rows = ""

    for item in AGENTTRUST_MODEL_PERFORMANCE_SIGNALS:
        rows += f"""
        <tr>
            <td><strong>{item["signal"]}</strong></td>
            <td>{item["meaning"]}</td>
            <td>{item["threshold"]}</td>
            <td><span class="badge orange">{item["response"]}</span></td>
        </tr>
        """

    return rows


def agenttrust_model_risk_decision(identity, intended_use, input_boundary, output_check, hallucination, monitoring, bias, change_gate):
    controls = [identity, intended_use, input_boundary, output_check, hallucination, monitoring, bias, change_gate]
    score = int((sum(1 for item in controls if item == "yes") / len(controls)) * 100)

    if identity != "yes":
        return score, "Block Model Reliance", "red", "Model identity, version, endpoint, owner, or provider is not known."
    if intended_use != "yes":
        return score, "Restrict to Sandbox", "red", "Model is not validated for the intended agent use case."
    if input_boundary != "yes":
        return score, "Input Boundary Review Required", "red", "Allowed and prohibited input boundaries are not defined."
    if output_check != "yes":
        return score, "Human-Gated Only", "orange", "Output reliability cannot be checked against source evidence and reviewer decision."
    if hallucination != "yes":
        return score, "Restrict Unsupported Claims", "orange", "Unsupported claim control is incomplete."
    if monitoring != "yes":
        return score, "No Production Release", "red", "Model performance and drift monitoring are not ready."
    if bias != "yes":
        return score, "Suitability Review Required", "orange", "Bias, fairness, or suitability review is incomplete."
    if change_gate != "yes":
        return score, "Suspend Trust on Change", "red", "Model change validation gate is not active."
    if score == 100:
        return score, "Model Approved With Controls", "green", "Model risk controls are complete for governed use inside approved AgentTrust™ boundaries."
    return score, "Conditional Model Use", "yellow", "Model may be used only with restrictions, human review, and remediation tracking."


try:
    AGENTTRUST_EXPECTED_ROUTES.extend([
        "/agenttrust/model-risk-control-center",
        "/agenttrust/model-risk-register",
        "/agenttrust/model-validation-evidence-hub",
        "/agenttrust/model-performance-monitor",
        "/agenttrust/model-bias-fairness-screen",
        "/agenttrust/model-limitation-register",
        "/agenttrust/model-change-validation-gate",
        "/agenttrust/model-risk-simulator",
        "/agenttrust/model-risk-json"
    ])
except Exception:
    pass


@app.route("/agenttrust/model-risk-control-center")
@app.route("/agenttrust/model-risk-center")
@app.route("/agenttrust/ai-model-risk-control")
def agenttrust_model_risk_control_center():
    rows = agenttrust_model_risk_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Model Risk</div><div class="value" style="color:var(--green);">Controlled</div><div class="note">Model identity and risk tier mapped.</div></div>
        <div class="metric"><div class="label">Model Register</div><div class="value" style="color:var(--blue);">Active</div><div class="note">Models linked to agent dependencies.</div></div>
        <div class="metric"><div class="label">Validation</div><div class="value" style="color:var(--yellow);">Required</div><div class="note">Intended use and output reliability checked.</div></div>
        <div class="metric"><div class="label">Critical Models</div><div class="value" style="color:var(--red);">QA / Cyber</div><div class="note">Access and GxP models require strict routing.</div></div>
        <div class="metric"><div class="label">Monitoring</div><div class="value" style="color:var(--orange);">Continuous</div><div class="note">Performance, drift, and unsupported claims watched.</div></div>
        <div class="metric"><div class="label">Change Gate</div><div class="value" style="color:var(--purple);">Mandatory</div><div class="note">Model changes trigger revalidation.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Model Risk Control Center</h2>
        <div class="answer">
            <strong>Purpose:</strong> control the AI model layer behind the agent.
            AgentTrust™ does not only govern the agent workflow. It also governs the model identity,
            intended use, input boundary, output reliability, hallucination risk, performance, bias/suitability,
            change validation, and monitoring evidence.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Model ID</th>
                    <th>Model</th>
                    <th>Agent Dependency</th>
                    <th>Model Role</th>
                    <th>Risk Tier</th>
                    <th>Owner</th>
                    <th>Required Control</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Model Risk Rule</h2>
        <div class="answer">
            An AI agent cannot be trusted if the model behind it is unknown, unvalidated, unmonitored,
            unsuitable for the use case, or changed without revalidation.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Model Risk Control Center",
        "Model risk control center for AI model identity, intended use, validation, performance, bias, limitations, monitoring, and change validation.",
        body
    )


@app.route("/agenttrust/model-risk-register")
@app.route("/agenttrust/ai-model-register")
@app.route("/agenttrust/model-register")
def agenttrust_model_risk_register():
    rows = agenttrust_model_risk_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Model Risk Register</h2>
        <p>
            The Model Risk Register links every AI model or foundation model dependency to the agent, use case, risk tier, owner, and required control.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Model ID</th>
                    <th>Model</th>
                    <th>Agent Dependency</th>
                    <th>Model Role</th>
                    <th>Risk Tier</th>
                    <th>Owner</th>
                    <th>Required Control</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Register Rule</h2>
        <div class="answer">
            No model should support an operational AI agent without a register record, owner, risk tier,
            intended use, and required control package.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Model Risk Register",
        "AI model risk register linking models to agent dependencies, roles, risk tiers, owners, and required controls.",
        body
    )


@app.route("/agenttrust/model-validation-evidence-hub")
@app.route("/agenttrust/model-validation-hub")
@app.route("/agenttrust/ai-validation-evidence")
def agenttrust_model_validation_evidence_hub():
    rows = agenttrust_model_validation_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Model Validation Evidence Hub</h2>
        <p>
            The Model Validation Evidence Hub defines what evidence is required before a model can support governed AI agent use.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Control ID</th>
                    <th>Validation Control</th>
                    <th>Question</th>
                    <th>Evidence</th>
                    <th>Failure Response</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Validation Evidence Rule</h2>
        <div class="answer">
            Model validation must be connected to the agent's actual operating context.
            A model that is acceptable for summarization may still be unacceptable for access, GxP, release, or workflow execution.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Model Validation Evidence Hub",
        "Validation evidence hub for AI model identity, intended use, input boundary, output reliability, hallucination control, performance, bias, and change validation.",
        body
    )


@app.route("/agenttrust/model-performance-monitor")
@app.route("/agenttrust/ai-model-performance-monitor")
@app.route("/agenttrust/model-monitoring")
def agenttrust_model_performance_monitor():
    rows = agenttrust_model_performance_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Model Performance Monitor</h2>
        <p>
            The Model Performance Monitor tracks whether the model remains reliable after deployment.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Performance Signal</th>
                    <th>Meaning</th>
                    <th>Threshold Position</th>
                    <th>AgentTrust™ Response</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Performance Rule</h2>
        <div class="answer">
            Model performance is not fixed at release. AgentTrust™ watches unsupported claims, escalation misses,
            boundary violations, evidence completeness, reviewer correction rate, and drift events over time.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Model Performance Monitor",
        "Model performance monitor for unsupported claims, escalation misses, boundary violations, evidence completeness, reviewer corrections, and drift events.",
        body
    )


@app.route("/agenttrust/model-bias-fairness-screen")
@app.route("/agenttrust/bias-fairness-screen")
@app.route("/agenttrust/model-suitability-screen")
def agenttrust_model_bias_fairness_screen():
    body = """
    <section class="section">
        <h2>AgentTrust™ Bias / Fairness / Suitability Screen</h2>
        <p>
            This screen checks whether model output could create unfair, unsuitable, or inappropriate operational decisions.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Screen Area</th>
                    <th>Risk Question</th>
                    <th>Required Owner</th>
                    <th>Default Control</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>People Impact</td><td>Could output affect employee, contractor, user, reviewer, or approver treatment?</td><td>Process / HR / Legal Owner where applicable.</td><td><span class="badge orange">Human review required</span></td></tr>
                <tr><td>Access Impact</td><td>Could output affect who gets access or privileged route?</td><td>Cybersecurity / Access Owner.</td><td><span class="badge red">Cyber-gated</span></td></tr>
                <tr><td>Work Allocation</td><td>Could output influence ownership, assignment, workload, or accountability?</td><td>Business / Process Owner.</td><td><span class="badge yellow">Owner review required</span></td></tr>
                <tr><td>Regulated Impact</td><td>Could output influence QA, validation, release, deviation, CAPA, QC, or inspection decisions?</td><td>QA / Validation Owner.</td><td><span class="badge red">QA-governed only</span></td></tr>
                <tr><td>Confidence Risk</td><td>Could the model present uncertain output as fact?</td><td>Governance / Audit Owner.</td><td><span class="badge orange">Uncertainty labeling required</span></td></tr>
                <tr><td>Language / Context Risk</td><td>Could the model misunderstand local terminology, abbreviations, SOP context, or system naming?</td><td>System / Process Owner.</td><td><span class="badge orange">Source validation required</span></td></tr>
                <tr><td>Automation Bias</td><td>Could users over-trust AI output because it appears authoritative?</td><td>Governance Owner.</td><td><span class="badge red">Human accountability preserved</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Suitability Rule</h2>
        <div class="answer">
            A model can be technically capable but operationally unsuitable for a specific workflow.
            AgentTrust™ requires suitability review when model output can affect people, access, ownership, regulated decisions, or accountability.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Bias Fairness Suitability Screen",
        "Bias, fairness, and suitability screen for AI model impact on people, access, work allocation, regulated decisions, confidence risk, context risk, and automation bias.",
        body
    )


@app.route("/agenttrust/model-limitation-register")
@app.route("/agenttrust/model-limitations")
@app.route("/agenttrust/ai-model-limitation-register")
def agenttrust_model_limitation_register():
    rows = agenttrust_model_limitation_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Model Limitation Register</h2>
        <p>
            The Model Limitation Register makes model limitations explicit so users do not confuse AI output with approval, evidence, or regulated truth.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Limitation ID</th>
                    <th>Model Limitation</th>
                    <th>Affected Agents</th>
                    <th>Risk</th>
                    <th>Required Guardrail</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Limitation Rule</h2>
        <div class="answer">
            AgentTrust™ makes limitations visible. If a model cannot approve, validate, release, grant access,
            close deviation, or certify evidence, that limitation must be shown before operational reliance.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Model Limitation Register",
        "Model limitation register for AI output approval limits, evidence summary risk, ownership inference risk, access approval prohibition, regulated conclusion prohibition, and drift sensitivity.",
        body
    )


@app.route("/agenttrust/model-change-validation-gate")
@app.route("/agenttrust/model-change-gate-v2")
@app.route("/agenttrust/ai-model-change-validation")
def agenttrust_model_change_validation_gate():
    body = """
    <section class="section">
        <h2>AgentTrust™ Model Change Validation Gate</h2>
        <p>
            This gate controls what happens when a model, endpoint, prompt, tool policy, retrieval source, parser, or configuration changes.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Change Type</th>
                    <th>Risk Created</th>
                    <th>Required Validation</th>
                    <th>Trust Decision</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Model version changes.</td><td>Behavior and output style may change.</td><td>Regression test, red-team test, performance review.</td><td><span class="badge orange">Re-score trust</span></td></tr>
                <tr><td>Endpoint or deployment changes.</td><td>Different runtime or configuration may be used.</td><td>Endpoint identity and platform owner review.</td><td><span class="badge orange">Revalidate deployment</span></td></tr>
                <tr><td>System prompt changes.</td><td>Authority, boundary, and prohibited action behavior may change.</td><td>Prompt change gate and injection test.</td><td><span class="badge red">Suspend until approved</span></td></tr>
                <tr><td>Tool policy changes.</td><td>Execution capability may increase.</td><td>Tool authority gate and execution firewall test.</td><td><span class="badge red">Block new tool until approved</span></td></tr>
                <tr><td>Retrieval source changes.</td><td>Model may rely on new or weaker evidence.</td><td>Source lineage and evidence sufficiency review.</td><td><span class="badge orange">Human-gated until checked</span></td></tr>
                <tr><td>Output parser changes.</td><td>Text may become action, workflow trigger, or structured update.</td><td>Parser validation and preflight simulation.</td><td><span class="badge red">Execution firewall required</span></td></tr>
                <tr><td>Risk tier changes.</td><td>Control package may no longer be sufficient.</td><td>Release gate and assurance case refresh.</td><td><span class="badge red">Re-approve operating license</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Change Gate Rule</h2>
        <div class="answer">
            A model change is a trust event. AgentTrust™ should suspend or downgrade operational trust until
            the change is validated, evidenced, monitored, and approved.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Model Change Validation Gate",
        "Model change validation gate for AI model version, endpoint, prompt, tool policy, retrieval source, output parser, and risk tier changes.",
        body
    )


@app.route("/agenttrust/model-risk-simulator", methods=["GET", "POST"])
@app.route("/agenttrust/ai-model-risk-simulator", methods=["GET", "POST"])
@app.route("/agenttrust/model-validation-simulator", methods=["GET", "POST"])
def agenttrust_model_risk_simulator():
    from flask import request

    identity = request.form.get("identity", "yes")
    intended_use = request.form.get("intended_use", "yes")
    input_boundary = request.form.get("input_boundary", "yes")
    output_check = request.form.get("output_check", "yes")
    hallucination = request.form.get("hallucination", "yes")
    monitoring = request.form.get("monitoring", "yes")
    bias = request.form.get("bias", "yes")
    change_gate = request.form.get("change_gate", "yes")

    score, decision, badge, reason = agenttrust_model_risk_decision(
        identity, intended_use, input_boundary, output_check, hallucination, monitoring, bias, change_gate
    )

    def selected(value, expected):
        return "selected" if value == expected else ""

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Model Risk Score</div><div class="value" style="color:var(--green);">{score}%</div><div class="note">Calculated from model risk controls.</div></div>
        <div class="metric"><div class="label">Model Decision</div><div class="value" style="color:var(--yellow);">{decision}</div><div class="note">{reason}</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Model Risk Simulator</h2>
        <p>
            Simulate whether a model can support a governed AI agent use case.
        </p>

        <form method="POST" action="/agenttrust/model-risk-simulator">
            <table>
                <tbody>
                    <tr><td><strong>Model Identity Known?</strong></td><td><select name="identity" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(identity, "yes")}>Yes</option><option value="no" {selected(identity, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Intended Use Validated?</strong></td><td><select name="intended_use" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(intended_use, "yes")}>Yes</option><option value="no" {selected(intended_use, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Input Boundary Defined?</strong></td><td><select name="input_boundary" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(input_boundary, "yes")}>Yes</option><option value="no" {selected(input_boundary, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Output Reliability Check Ready?</strong></td><td><select name="output_check" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(output_check, "yes")}>Yes</option><option value="no" {selected(output_check, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Unsupported Claim Control Ready?</strong></td><td><select name="hallucination" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(hallucination, "yes")}>Yes</option><option value="no" {selected(hallucination, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Performance / Drift Monitoring Ready?</strong></td><td><select name="monitoring" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(monitoring, "yes")}>Yes</option><option value="no" {selected(monitoring, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Bias / Fairness / Suitability Reviewed?</strong></td><td><select name="bias" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(bias, "yes")}>Yes</option><option value="no" {selected(bias, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Model Change Gate Active?</strong></td><td><select name="change_gate" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(change_gate, "yes")}>Yes</option><option value="no" {selected(change_gate, "no")}>No</option></select></td></tr>
                </tbody>
            </table>

            <button type="submit" style="margin-top:16px;padding:12px 18px;border-radius:12px;border:0;background:#2563eb;color:white;font-weight:800;">Run Model Risk Screen</button>
        </form>
    </section>

    <section class="section">
        <h2>Model Risk Decision</h2>
        <div class="answer">
            <strong>Score:</strong> {score}%<br>
            <strong>Decision:</strong> <span class="badge {badge}">{decision}</span><br>
            <strong>Reason:</strong> {reason}
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Model Risk Simulator",
        "Simulator for AI model risk across model identity, intended use, input boundary, output reliability, unsupported claims, monitoring, bias, and change gate readiness.",
        body
    )


@app.route("/agenttrust/model-risk-json")
@app.route("/agenttrust/model-validation-json")
@app.route("/agenttrust/ai-model-risk-json")
def agenttrust_model_risk_json():
    from flask import jsonify

    return jsonify({
        "module": "AgentTrust™",
        "capability": "Model Risk Control Center + AI Validation Evidence Hub",
        "primary_question": "Can the model behind this AI agent be trusted for this intended use?",
        "model_risk_register": AGENTTRUST_MODEL_RISK_REGISTER,
        "model_validation_controls": AGENTTRUST_MODEL_VALIDATION_CONTROLS,
        "model_limitations": AGENTTRUST_MODEL_LIMITATIONS,
        "model_performance_signals": AGENTTRUST_MODEL_PERFORMANCE_SIGNALS,
        "minimum_conditions": [
            "Model identity, version, endpoint, provider, owner, and hosting boundary are known",
            "Model is validated for intended use",
            "Input boundary and prohibited inputs are defined",
            "Output can be checked against source evidence",
            "Unsupported claims are flagged or blocked",
            "Performance and drift monitoring are active",
            "Bias, fairness, and suitability are reviewed where relevant",
            "Model, prompt, tool, endpoint, retrieval, parser, or configuration changes trigger validation gate"
        ],
        "default_decision": "Restrict or block model reliance until identity, intended use, input boundary, output reliability, monitoring, suitability, and change validation controls are complete"
    })

# ============================================================
# END AGENTTRUST_MODEL_RISK_VALIDATION_CENTER_V1_ACTIVE
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

print("AgentTrust Model Risk Control Center installed.")
print(f"Inserted before: {target_found}")
