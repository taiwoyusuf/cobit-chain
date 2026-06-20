from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_CONTROL_EFFECTIVENESS_TESTING_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust Control Effectiveness Testing Center already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base module not found. Install AgentTrust module first.")

nav_old = '<a href="/agenttrust/ai-incident-response-center" class="secondary">Incident Response</a>'
nav_new = '''<a href="/agenttrust/ai-incident-response-center" class="secondary">Incident Response</a>
                    <a href="/agenttrust/control-effectiveness-testing" class="secondary">Control Testing</a>
                    <a href="/agenttrust/control-test-library" class="dark">Test Library</a>
                    <a href="/agenttrust/evidence-sampling-workbench" class="dark">Sampling</a>
                    <a href="/agenttrust/control-effectiveness-simulator" class="dark">Effectiveness</a>'''

if nav_old in text and "/agenttrust/control-effectiveness-testing" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# AGENTTRUST_CONTROL_EFFECTIVENESS_TESTING_V1_ACTIVE
# AgentTrust™ Control Effectiveness Testing Center,
# Control Test Library, Continuous Control Testing,
# Control Sampling Plan, Evidence Sampling Workbench,
# Control Deficiency Register, Retest and Remediation Tracker,
# Control Effectiveness Simulator, and Control Testing JSON Export
# ============================================================

AGENTTRUST_CONTROL_TESTS = [
    {
        "test_id": "AT-CTL-001",
        "control": "Agent Register Control",
        "test_objective": "Confirm every AI agent has identity, owner, purpose, lifecycle status, and risk tier.",
        "sample_evidence": "Agent Register, Agent Risk Passport™, owner assignment.",
        "pass_condition": "Agent is known, owned, classified, and lifecycle-controlled.",
        "failure_response": "Block operational trust until register is complete."
    },
    {
        "test_id": "AT-CTL-002",
        "control": "Authority Gate Control",
        "test_objective": "Confirm high-impact actions have pre-action authority before execution.",
        "sample_evidence": "Authority decision, trust token, action permit, policy decision record.",
        "pass_condition": "Create, update, trigger, approve, access, privileged, and regulated actions are gated.",
        "failure_response": "Block action and open authority deficiency."
    },
    {
        "test_id": "AT-CTL-003",
        "control": "Human Oversight Control",
        "test_objective": "Confirm material AI output has a named reviewer, approver, risk owner, or escalation owner.",
        "sample_evidence": "Approval queue, signoff matrix, reviewer decision, outcome.",
        "pass_condition": "Human accountability is visible before operational reliance.",
        "failure_response": "Restrict to advisory mode and assign reviewer."
    },
    {
        "test_id": "AT-CTL-004",
        "control": "Evidence Capture Control",
        "test_objective": "Confirm input, source, tool-call, output, reviewer, timestamp, and outcome evidence are captured.",
        "sample_evidence": "Evidence ledger, tool-call evidence, replay package, audit dossier.",
        "pass_condition": "Action can be reconstructed from identity to outcome.",
        "failure_response": "Mark replay weak and open evidence remediation."
    },
    {
        "test_id": "AT-CTL-005",
        "control": "Cyber Escalation Control",
        "test_objective": "Confirm access, CyberArk, PSM, admin, and privileged-impacting actions route to cyber owner.",
        "sample_evidence": "Cyber route, access owner decision, privileged impact assessment.",
        "pass_condition": "No AI access approval or privileged action occurs without cyber review.",
        "failure_response": "Suspend cyber scope and open cyber deficiency."
    },
    {
        "test_id": "AT-CTL-006",
        "control": "GxP / QA Escalation Control",
        "test_objective": "Confirm regulated, QA, validation, release, deviation, CAPA, QC, and inspection impacts route to QA.",
        "sample_evidence": "GxP screen, QA review, validation owner decision, regulated evidence route.",
        "pass_condition": "AI does not make regulated conclusion without QA / validation review.",
        "failure_response": "Suspend regulated reliance and route to QA."
    },
    {
        "test_id": "AT-CTL-007",
        "control": "Execution Firewall Control",
        "test_objective": "Confirm prohibited or unauthorized AI actions are blocked before system execution.",
        "sample_evidence": "Firewall decision, blocked action record, preflight gate, incident record if applicable.",
        "pass_condition": "Unauthorized create, update, trigger, approve, access, or regulated conclusion is stopped.",
        "failure_response": "Quarantine agent and update enforcement rule."
    },
    {
        "test_id": "AT-CTL-008",
        "control": "Drift Monitoring Control",
        "test_objective": "Confirm model, prompt, tool, data, owner, evidence, or workflow drift triggers review.",
        "sample_evidence": "Drift alert, change gate, updated AgentBOM, recalculated trust score.",
        "pass_condition": "Material drift causes re-score, re-gate, restriction, or approval refresh.",
        "failure_response": "Suspend current trust decision until drift review is complete."
    },
    {
        "test_id": "AT-CTL-009",
        "control": "Vendor AI Boundary Control",
        "test_objective": "Confirm third-party AI use stays within data, contract, evidence, and exit boundaries.",
        "sample_evidence": "Vendor register, data boundary, contract controls, vendor evidence dossier.",
        "pass_condition": "Vendor AI has approved use case, data boundary, contract controls, and exit plan.",
        "failure_response": "Restrict or block vendor AI."
    },
    {
        "test_id": "AT-CTL-010",
        "control": "Incident Closure Control",
        "test_objective": "Confirm AI incidents are not closed without root cause, remediation, retest, and owner signoff.",
        "sample_evidence": "Incident record, root cause, CAPA/deviation route, retest evidence, closure approval.",
        "pass_condition": "Incident closure is evidence-based and owner-approved.",
        "failure_response": "Reopen incident and block release."
    }
]


AGENTTRUST_TESTING_CADENCE = [
    {
        "control_area": "Agent identity and ownership",
        "cadence": "Monthly",
        "sample": "All high-risk agents and a sample of medium-risk agents.",
        "owner": "Governance Owner"
    },
    {
        "control_area": "Authority and execution controls",
        "cadence": "Monthly and before release",
        "sample": "All create, update, trigger, approve, access, and regulated action classes.",
        "owner": "Risk / Process Owner"
    },
    {
        "control_area": "Cyber and privileged access controls",
        "cadence": "Monthly or after access route change",
        "sample": "All CyberArk, PSM, entitlement, admin, and privileged-impacting scenarios.",
        "owner": "Cybersecurity Owner"
    },
    {
        "control_area": "GxP / QA controls",
        "cadence": "Before regulated reliance and quarterly thereafter",
        "sample": "All GxP-impacting agents and regulated evidence use cases.",
        "owner": "QA / Validation Owner"
    },
    {
        "control_area": "Evidence and audit replay controls",
        "cadence": "Monthly",
        "sample": "Representative actions across advisory, human-gated, restricted, and incident scenarios.",
        "owner": "Audit / Evidence Owner"
    },
    {
        "control_area": "Drift and monitoring controls",
        "cadence": "Continuous with monthly review",
        "sample": "All model, prompt, tool, data, workflow, owner, and evidence-store changes.",
        "owner": "Lifecycle / Platform Owner"
    },
    {
        "control_area": "Vendor AI controls",
        "cadence": "Before onboarding and quarterly",
        "sample": "All vendor AI with enterprise workflow, sensitive data, cyber, or GxP touchpoint.",
        "owner": "Vendor / Security / Data Owner"
    }
]


AGENTTRUST_CONTROL_DEFICIENCIES = [
    {
        "deficiency_id": "AT-DEF-001",
        "deficiency": "Agent owner missing or outdated.",
        "risk": "No accountable human owner.",
        "severity": "High",
        "remediation": "Assign owner, update register, retest identity control."
    },
    {
        "deficiency_id": "AT-DEF-002",
        "deficiency": "Tool call not linked to authority decision.",
        "risk": "Unauthorized action may occur.",
        "severity": "Critical",
        "remediation": "Require authority decision ID before tool execution."
    },
    {
        "deficiency_id": "AT-DEF-003",
        "deficiency": "Human review not captured.",
        "risk": "AI output may become hidden approval.",
        "severity": "Critical",
        "remediation": "Route to reviewer and capture decision before reliance."
    },
    {
        "deficiency_id": "AT-DEF-004",
        "deficiency": "Evidence package incomplete.",
        "risk": "Audit replay and inspection defense are weak.",
        "severity": "High",
        "remediation": "Capture source, tool-call, reviewer, outcome, and replay evidence."
    },
    {
        "deficiency_id": "AT-DEF-005",
        "deficiency": "Cyber escalation missed.",
        "risk": "Access or privileged impact may bypass cybersecurity review.",
        "severity": "Critical",
        "remediation": "Suspend cyber scope and update routing rule."
    },
    {
        "deficiency_id": "AT-DEF-006",
        "deficiency": "GxP escalation missed.",
        "risk": "Regulated conclusion may be created without QA review.",
        "severity": "Critical",
        "remediation": "Suspend regulated reliance and route to QA / validation owner."
    },
    {
        "deficiency_id": "AT-DEF-007",
        "deficiency": "Drift alert not reviewed.",
        "risk": "Trust score becomes stale.",
        "severity": "High",
        "remediation": "Run change gate, update AgentBOM, recalculate trust score."
    }
]


def agenttrust_control_test_rows():
    rows = ""

    for item in AGENTTRUST_CONTROL_TESTS:
        rows += f"""
        <tr>
            <td><strong>{item["test_id"]}</strong></td>
            <td><span class="badge blue">{item["control"]}</span></td>
            <td>{item["test_objective"]}</td>
            <td>{item["sample_evidence"]}</td>
            <td>{item["pass_condition"]}</td>
            <td><span class="badge red">{item["failure_response"]}</span></td>
        </tr>
        """

    return rows


def agenttrust_testing_cadence_rows():
    rows = ""

    for item in AGENTTRUST_TESTING_CADENCE:
        rows += f"""
        <tr>
            <td><strong>{item["control_area"]}</strong></td>
            <td><span class="badge green">{item["cadence"]}</span></td>
            <td>{item["sample"]}</td>
            <td>{item["owner"]}</td>
        </tr>
        """

    return rows


def agenttrust_control_deficiency_rows():
    rows = ""

    for item in AGENTTRUST_CONTROL_DEFICIENCIES:
        badge = "orange"
        if item["severity"] == "Critical":
            badge = "red"
        elif item["severity"] == "High":
            badge = "yellow"

        rows += f"""
        <tr>
            <td><strong>{item["deficiency_id"]}</strong></td>
            <td>{item["deficiency"]}</td>
            <td>{item["risk"]}</td>
            <td><span class="badge {badge}">{item["severity"]}</span></td>
            <td>{item["remediation"]}</td>
        </tr>
        """

    return rows


def agenttrust_control_effectiveness_decision(design, operation, evidence, sample, deficiency, remediation, retest, signoff):
    controls = [design, operation, evidence, sample, remediation, retest, signoff]
    score = int((sum(1 for item in controls if item == "yes") / len(controls)) * 100)

    if design != "yes":
        return score, "Ineffective — Design Failure", "red", "Control is not designed clearly enough to test or enforce."
    if operation != "yes":
        return score, "Ineffective — Operating Failure", "red", "Control is designed but not operating in practice."
    if evidence != "yes":
        return score, "Not Defensible — Evidence Gap", "red", "Control operation cannot be proven with evidence."
    if sample != "yes":
        return score, "Insufficient Testing", "orange", "Control sample is not adequate to support effectiveness conclusion."
    if deficiency == "yes" and remediation != "yes":
        return score, "Deficiency Open", "red", "A control deficiency exists and remediation is not complete."
    if remediation != "yes":
        return score, "Remediation Required", "orange", "Control requires remediation before effectiveness can be confirmed."
    if retest != "yes":
        return score, "Retest Required", "orange", "Remediated control must be retested before closure."
    if signoff != "yes":
        return score, "Pending Owner Signoff", "yellow", "Control effectiveness requires accountable owner signoff."
    if score == 100 and deficiency == "no":
        return score, "Effective", "green", "Control is designed, operating, evidenced, sampled, retested, and signed off."
    return score, "Effective With Observation", "yellow", "Control is mostly effective but requires observation tracking."


try:
    AGENTTRUST_EXPECTED_ROUTES.extend([
        "/agenttrust/control-effectiveness-testing",
        "/agenttrust/control-test-library",
        "/agenttrust/continuous-control-testing",
        "/agenttrust/control-sampling-plan",
        "/agenttrust/evidence-sampling-workbench",
        "/agenttrust/control-deficiency-register",
        "/agenttrust/retest-remediation-tracker",
        "/agenttrust/control-effectiveness-simulator",
        "/agenttrust/control-testing-json"
    ])
except Exception:
    pass


@app.route("/agenttrust/control-effectiveness-testing")
@app.route("/agenttrust/control-effectiveness-center")
@app.route("/agenttrust/agent-control-testing")
def agenttrust_control_effectiveness_testing():
    rows = agenttrust_control_test_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Control Testing</div><div class="value" style="color:var(--green);">Active</div><div class="note">Control design and operating effectiveness mapped.</div></div>
        <div class="metric"><div class="label">Tests</div><div class="value" style="color:var(--blue);">10</div><div class="note">Identity, authority, human, evidence, cyber, GxP, firewall, drift, vendor, incident.</div></div>
        <div class="metric"><div class="label">Sampling</div><div class="value" style="color:var(--yellow);">Required</div><div class="note">Evidence samples prove operation.</div></div>
        <div class="metric"><div class="label">Deficiencies</div><div class="value" style="color:var(--red);">Tracked</div><div class="note">Open failures require remediation and retest.</div></div>
        <div class="metric"><div class="label">Retest</div><div class="value" style="color:var(--orange);">Mandatory</div><div class="note">No closure without retest.</div></div>
        <div class="metric"><div class="label">Signoff</div><div class="value" style="color:var(--purple);">Owner-Based</div><div class="note">Control owner signs effectiveness conclusion.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Control Effectiveness Testing Center</h2>
        <div class="answer">
            <strong>Purpose:</strong> prove that AI governance controls are working in practice.
            AgentTrust™ tests whether controls are designed, operating, evidenced, sampled, remediated, retested,
            and signed off before leadership relies on the control environment.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Test ID</th>
                    <th>Control</th>
                    <th>Test Objective</th>
                    <th>Sample Evidence</th>
                    <th>Pass Condition</th>
                    <th>Failure Response</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Control Effectiveness Rule</h2>
        <div class="answer">
            A documented control is not the same as an effective control.
            AgentTrust™ requires evidence that the control operated correctly for real or sampled AI agent actions.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Control Effectiveness Testing Center",
        "Control effectiveness testing center for AI agent governance controls, sampling, deficiencies, remediation, retest, and owner signoff.",
        body
    )


@app.route("/agenttrust/control-test-library")
@app.route("/agenttrust/agent-control-test-library")
@app.route("/agenttrust/control-testing-library")
def agenttrust_control_test_library():
    rows = agenttrust_control_test_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Control Test Library</h2>
        <p>
            The Control Test Library defines the repeatable tests used to verify that AgentTrust™ controls operate as expected.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Test ID</th>
                    <th>Control</th>
                    <th>Test Objective</th>
                    <th>Sample Evidence</th>
                    <th>Pass Condition</th>
                    <th>Failure Response</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Control Test Library",
        "Control test library for testing AgentTrust™ identity, authority, human oversight, evidence, cyber, GxP, firewall, drift, vendor, and incident closure controls.",
        body
    )


@app.route("/agenttrust/continuous-control-testing")
@app.route("/agenttrust/continuous-testing")
@app.route("/agenttrust/control-testing-cadence")
def agenttrust_continuous_control_testing():
    rows = agenttrust_testing_cadence_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Continuous Control Testing</h2>
        <p>
            Continuous testing defines when each AI governance control should be tested and who owns the result.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Control Area</th>
                    <th>Cadence</th>
                    <th>Sample</th>
                    <th>Owner</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Continuous Testing Rule</h2>
        <div class="answer">
            Control effectiveness must be refreshed. AI agents, models, prompts, tools, owners, data, vendors,
            and regulated workflows can change after initial approval.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Continuous Control Testing",
        "Continuous control testing cadence for AI agent identity, authority, cyber, GxP, evidence, drift, vendor, and incident controls.",
        body
    )


@app.route("/agenttrust/control-sampling-plan")
@app.route("/agenttrust/control-sampling")
@app.route("/agenttrust/ai-control-sampling-plan")
def agenttrust_control_sampling_plan():
    rows = agenttrust_testing_cadence_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Control Sampling Plan</h2>
        <p>
            The sampling plan defines which AI agent actions, evidence packages, and incidents should be selected for testing.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Control Area</th>
                    <th>Cadence</th>
                    <th>Sample Population</th>
                    <th>Testing Owner</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Sampling Rule</h2>
        <div class="answer">
            Sampling must focus on risk. Critical actions, cyber impacts, GxP impacts, vendor AI,
            incidents, drift events, and human-gated decisions should receive priority.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Control Sampling Plan",
        "Sampling plan for AI agent control effectiveness testing across high-risk actions, cyber, GxP, vendor, evidence, drift, and incident samples.",
        body
    )


@app.route("/agenttrust/evidence-sampling-workbench")
@app.route("/agenttrust/evidence-sampling")
@app.route("/agenttrust/control-evidence-sampling")
def agenttrust_evidence_sampling_workbench():
    body = """
    <section class="section">
        <h2>AgentTrust™ Evidence Sampling Workbench</h2>
        <p>
            The Evidence Sampling Workbench checks whether sampled AI agent actions can be defended.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Evidence Sample</th>
                    <th>Question</th>
                    <th>Pass Condition</th>
                    <th>If Missing</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent identity</td><td>Can we identify which AI agent acted?</td><td>Agent ID, owner, passport, license.</td><td><span class="badge red">Unknown actor</span></td></tr>
                <tr><td>Source evidence</td><td>Can we prove what the agent relied on?</td><td>Record ID, document, system source, timestamp.</td><td><span class="badge red">Unsupported output</span></td></tr>
                <tr><td>Authority evidence</td><td>Can we prove action was allowed before execution?</td><td>Authority decision, trust token, action permit.</td><td><span class="badge red">Unauthorized action risk</span></td></tr>
                <tr><td>Tool-call evidence</td><td>Can we prove what system or API was touched?</td><td>Tool, target, mode, timestamp, result.</td><td><span class="badge red">No execution trace</span></td></tr>
                <tr><td>Human evidence</td><td>Can we prove who reviewed or approved reliance?</td><td>Reviewer, decision, signoff, escalation.</td><td><span class="badge red">Hidden approval risk</span></td></tr>
                <tr><td>Outcome evidence</td><td>Can we prove final result?</td><td>Executed, blocked, escalated, rejected, rolled back, quarantined.</td><td><span class="badge orange">Incomplete action loop</span></td></tr>
                <tr><td>Replay evidence</td><td>Can we reconstruct the action end-to-end?</td><td>Timeline, lineage, owner, evidence package.</td><td><span class="badge red">Not audit-defensible</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Evidence Sampling Rule</h2>
        <div class="answer">
            A control test is only as strong as the evidence sample.
            AgentTrust™ requires identity, source, authority, tool-call, human, outcome, and replay evidence.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Evidence Sampling Workbench",
        "Evidence sampling workbench for AI agent identity, source, authority, tool-call, human review, outcome, and audit replay evidence.",
        body
    )


@app.route("/agenttrust/control-deficiency-register")
@app.route("/agenttrust/control-deficiencies")
@app.route("/agenttrust/ai-control-deficiency-register")
def agenttrust_control_deficiency_register():
    rows = agenttrust_control_deficiency_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Control Deficiency Register</h2>
        <p>
            The Control Deficiency Register records control failures, severity, risk, remediation, and retest requirement.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Deficiency ID</th>
                    <th>Deficiency</th>
                    <th>Risk</th>
                    <th>Severity</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Deficiency Rule</h2>
        <div class="answer">
            Control deficiencies must not remain as informal observations.
            AgentTrust™ converts deficiencies into remediation, owner route, retest, and closure evidence.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Control Deficiency Register",
        "Control deficiency register for AI governance owner gaps, authority gaps, human review gaps, evidence gaps, cyber escalation misses, GxP misses, and drift review gaps.",
        body
    )


@app.route("/agenttrust/retest-remediation-tracker")
@app.route("/agenttrust/control-retest-tracker")
@app.route("/agenttrust/remediation-tracker")
def agenttrust_retest_remediation_tracker():
    body = """
    <section class="section">
        <h2>AgentTrust™ Retest and Remediation Tracker</h2>
        <p>
            The Retest and Remediation Tracker confirms that failed controls were fixed and retested before closure.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Remediation Step</th>
                    <th>Required Action</th>
                    <th>Owner</th>
                    <th>Closure Condition</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Deficiency logged</td><td>Record issue, severity, affected agent, affected control.</td><td>Control Owner.</td><td><span class="badge yellow">Deficiency record created</span></td></tr>
                <tr><td>Impact assessed</td><td>Determine cyber, GxP, privacy, vendor, incident, or audit impact.</td><td>Risk Owner.</td><td><span class="badge orange">Impact route completed</span></td></tr>
                <tr><td>Root cause mapped</td><td>Classify as model, prompt, tool, data, authority, human, evidence, or vendor failure.</td><td>Process / Platform Owner.</td><td><span class="badge yellow">Root cause approved</span></td></tr>
                <tr><td>Remediation completed</td><td>Update control, routing, evidence capture, authority rule, or owner mapping.</td><td>Remediation Owner.</td><td><span class="badge green">Fix implemented</span></td></tr>
                <tr><td>Retest performed</td><td>Run control test with evidence sample.</td><td>Testing Owner.</td><td><span class="badge green">Retest passed</span></td></tr>
                <tr><td>Effectiveness signed off</td><td>Control owner confirms operating effectiveness.</td><td>Control Owner.</td><td><span class="badge green">Owner signoff captured</span></td></tr>
                <tr><td>Trust score refreshed</td><td>Recalculate trust, release, monitoring, or assurance score.</td><td>Governance Owner.</td><td><span class="badge purple">Score updated</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Retest Rule</h2>
        <div class="answer">
            Remediation is not closure. Closure requires retest evidence and owner signoff proving the control now works.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Retest and Remediation Tracker",
        "Retest and remediation tracker for AI control deficiencies, impact assessment, root cause, remediation, retest, signoff, and trust score refresh.",
        body
    )


@app.route("/agenttrust/control-effectiveness-simulator", methods=["GET", "POST"])
@app.route("/agenttrust/control-testing-simulator", methods=["GET", "POST"])
@app.route("/agenttrust/effectiveness-simulator", methods=["GET", "POST"])
def agenttrust_control_effectiveness_simulator():
    from flask import request

    design = request.form.get("design", "yes")
    operation = request.form.get("operation", "yes")
    evidence = request.form.get("evidence", "yes")
    sample = request.form.get("sample", "yes")
    deficiency = request.form.get("deficiency", "no")
    remediation = request.form.get("remediation", "yes")
    retest = request.form.get("retest", "yes")
    signoff = request.form.get("signoff", "yes")

    score, decision, badge, reason = agenttrust_control_effectiveness_decision(
        design, operation, evidence, sample, deficiency, remediation, retest, signoff
    )

    def selected(value, expected):
        return "selected" if value == expected else ""

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Effectiveness Score</div><div class="value" style="color:var(--green);">{score}%</div><div class="note">Calculated from control testing criteria.</div></div>
        <div class="metric"><div class="label">Effectiveness Decision</div><div class="value" style="color:var(--yellow);">{decision}</div><div class="note">{reason}</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Control Effectiveness Simulator</h2>
        <p>
            Simulate whether an AI governance control is effective, deficient, or not defensible.
        </p>

        <form method="POST" action="/agenttrust/control-effectiveness-simulator">
            <table>
                <tbody>
                    <tr><td><strong>Control Designed Clearly?</strong></td><td><select name="design" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(design, "yes")}>Yes</option><option value="no" {selected(design, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Control Operating?</strong></td><td><select name="operation" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(operation, "yes")}>Yes</option><option value="no" {selected(operation, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Evidence Available?</strong></td><td><select name="evidence" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(evidence, "yes")}>Yes</option><option value="no" {selected(evidence, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Sample Adequate?</strong></td><td><select name="sample" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(sample, "yes")}>Yes</option><option value="no" {selected(sample, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Deficiency Found?</strong></td><td><select name="deficiency" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="no" {selected(deficiency, "no")}>No</option><option value="yes" {selected(deficiency, "yes")}>Yes</option></select></td></tr>
                    <tr><td><strong>Remediation Complete?</strong></td><td><select name="remediation" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(remediation, "yes")}>Yes</option><option value="no" {selected(remediation, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Retest Passed?</strong></td><td><select name="retest" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(retest, "yes")}>Yes</option><option value="no" {selected(retest, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Owner Signoff Captured?</strong></td><td><select name="signoff" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(signoff, "yes")}>Yes</option><option value="no" {selected(signoff, "no")}>No</option></select></td></tr>
                </tbody>
            </table>

            <button type="submit" style="margin-top:16px;padding:12px 18px;border-radius:12px;border:0;background:#2563eb;color:white;font-weight:800;">Run Effectiveness Test</button>
        </form>
    </section>

    <section class="section">
        <h2>Control Effectiveness Decision</h2>
        <div class="answer">
            <strong>Score:</strong> {score}%<br>
            <strong>Decision:</strong> <span class="badge {badge}">{decision}</span><br>
            <strong>Reason:</strong> {reason}
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Control Effectiveness Simulator",
        "Simulator for AI governance control effectiveness across design, operation, evidence, sampling, deficiency, remediation, retest, and signoff.",
        body
    )


@app.route("/agenttrust/control-testing-json")
@app.route("/agenttrust/control-effectiveness-json")
@app.route("/agenttrust/control-test-json")
def agenttrust_control_testing_json():
    from flask import jsonify

    return jsonify({
        "module": "AgentTrust™",
        "capability": "Control Effectiveness Testing Center + Continuous Control Testing Lab",
        "primary_question": "Are AgentTrust™ controls designed, operating, evidenced, sampled, remediated, retested, and signed off?",
        "control_tests": AGENTTRUST_CONTROL_TESTS,
        "testing_cadence": AGENTTRUST_TESTING_CADENCE,
        "control_deficiencies": AGENTTRUST_CONTROL_DEFICIENCIES,
        "minimum_effectiveness_conditions": [
            "Control is clearly designed",
            "Control is operating in practice",
            "Evidence proves operation",
            "Sample is adequate for risk",
            "Deficiencies are recorded",
            "Remediation is completed",
            "Retest is performed",
            "Control owner signoff is captured",
            "Trust score is refreshed after remediation"
        ],
        "default_decision": "Do not conclude a control is effective unless design, operation, evidence, sampling, remediation, retest, and owner signoff are complete"
    })

# ============================================================
# END AGENTTRUST_CONTROL_EFFECTIVENESS_TESTING_V1_ACTIVE
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

print("AgentTrust Control Effectiveness Testing Center installed.")
print(f"Inserted before: {target_found}")
