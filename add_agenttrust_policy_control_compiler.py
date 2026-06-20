from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_POLICY_CONTROL_COMPILER_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust Policy-to-Control Compiler already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base module not found. Install AgentTrust module first.")

nav_old = '<a href="/agenttrust/executive-attestation-center" class="secondary">Attestation</a>'
nav_new = '''<a href="/agenttrust/executive-attestation-center" class="secondary">Attestation</a>
                    <a href="/agenttrust/policy-control-compiler" class="secondary">Policy Compiler</a>
                    <a href="/agenttrust/obligation-traceability-matrix" class="dark">Traceability</a>
                    <a href="/agenttrust/evidence-requirement-compiler" class="dark">Evidence Compiler</a>
                    <a href="/agenttrust/policy-control-simulator" class="dark">Policy Sim</a>'''

if nav_old in text and "/agenttrust/policy-control-compiler" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# AGENTTRUST_POLICY_CONTROL_COMPILER_V1_ACTIVE
# AgentTrust™ Policy-to-Control Compiler,
# Obligation Traceability Matrix, Policy Obligation Register,
# Control Obligation Mapper, Evidence Requirement Compiler,
# Control Cadence Compiler, Policy Exception Compiler,
# Policy Control Simulator, and Policy Control JSON Export
# ============================================================

AGENTTRUST_POLICY_OBLIGATIONS = [
    {
        "obligation_id": "AT-POL-001",
        "policy_obligation": "Every AI agent must be registered, owned, classified, and lifecycle-controlled.",
        "control_requirement": "Agent Register Control",
        "evidence": "Agent Register, Agent Risk Passport™, owner record, lifecycle state, risk tier.",
        "owner": "Governance / Agent Lifecycle Owner",
        "cadence": "Monthly and before release",
        "test": "Sample active agents and verify identity, owner, purpose, lifecycle, and risk tier."
    },
    {
        "obligation_id": "AT-POL-002",
        "policy_obligation": "AI agent actions must not exceed approved authority.",
        "control_requirement": "Authority Gate / Runtime Control Plane",
        "evidence": "Authority decision, trust token, action permit, policy decision record, enforcement gateway result.",
        "owner": "Risk / Process / Platform Owner",
        "cadence": "Before every high-impact action",
        "test": "Verify create, update, trigger, approve, access, privileged, and regulated actions have pre-action authority."
    },
    {
        "obligation_id": "AT-POL-003",
        "policy_obligation": "AI must not become a hidden approver.",
        "control_requirement": "Human Oversight Control",
        "evidence": "Approval queue, reviewer decision, signoff matrix, accountability ledger.",
        "owner": "Business / Process Owner",
        "cadence": "Every material reliance decision",
        "test": "Confirm human decision is captured before output is relied upon."
    },
    {
        "obligation_id": "AT-POL-004",
        "policy_obligation": "AI must not approve access, activate entitlements, trigger privileged sessions, or bypass cyber review.",
        "control_requirement": "Cyber / Access Escalation Control",
        "evidence": "MyAccess route, CyberArk / PSM impact review, cyber owner decision, blocked approval record.",
        "owner": "Cybersecurity / Access / CyberArk Owner",
        "cadence": "Every access or privileged-impacting action",
        "test": "Verify access and privileged contexts are cyber-gated and AI approval is blocked."
    },
    {
        "obligation_id": "AT-POL-005",
        "policy_obligation": "AI must not make regulated, QA, validation, release, deviation, CAPA, QC, or inspection conclusions.",
        "control_requirement": "GxP / QA Escalation Control",
        "evidence": "GxP impact screen, QA / validation review, regulated conclusion block, audit dossier.",
        "owner": "QA / Validation / Quality Owner",
        "cadence": "Every regulated-impacting use case",
        "test": "Verify regulated reliance routes to QA / validation before use."
    },
    {
        "obligation_id": "AT-POL-006",
        "policy_obligation": "AI data use must be purpose-bound, minimized, classified, retained, and replayable.",
        "control_requirement": "Privacy Boundary / AI DPIA Control",
        "evidence": "Data classification, DPIA, minimization record, retention/deletion rule, transfer screen.",
        "owner": "Privacy / Legal / Data Owner",
        "cadence": "Before processing sensitive or enterprise data",
        "test": "Verify purpose, classification, minimization, retention, access boundary, and replay evidence."
    },
    {
        "obligation_id": "AT-POL-007",
        "policy_obligation": "Third-party AI must not be used without vendor assurance, contract obligations, data boundary, and exit rights.",
        "control_requirement": "Vendor AI Governance Control",
        "evidence": "Vendor AI register, vendor evidence dossier, contract controls, data boundary, exit plan.",
        "owner": "Vendor / Security / Legal / Data Owner",
        "cadence": "Before onboarding and quarterly",
        "test": "Verify vendor identity, allowed data, contract controls, audit support, deletion, and exit rights."
    },
    {
        "obligation_id": "AT-POL-008",
        "policy_obligation": "Model, prompt, endpoint, tool, parser, data, workflow, or owner changes must trigger review.",
        "control_requirement": "Model / Lifecycle Change Gate",
        "evidence": "Change gate, AgentBOM update, drift alert, model validation evidence, recalculated trust score.",
        "owner": "AI Platform / Lifecycle / Governance Owner",
        "cadence": "Every material change",
        "test": "Verify material changes trigger revalidation, trust recalculation, and owner approval."
    },
    {
        "obligation_id": "AT-POL-009",
        "policy_obligation": "AI actions must be reconstructable from identity to outcome.",
        "control_requirement": "Evidence Lineage / Decision Replay Control",
        "evidence": "Input, source, tool-call, authority, human review, output, timestamp, outcome, replay package.",
        "owner": "Audit / Evidence Owner",
        "cadence": "Every material action and sampled monthly",
        "test": "Reconstruct sampled actions end-to-end using evidence."
    },
    {
        "obligation_id": "AT-POL-010",
        "policy_obligation": "AI incidents and control deficiencies must be contained, remediated, retested, and closed with evidence.",
        "control_requirement": "Incident Response / Control Effectiveness Control",
        "evidence": "Incident record, root cause, CAPA/deviation route, deficiency register, remediation, retest, closure signoff.",
        "owner": "Risk / QA / Cyber / Governance Owner",
        "cadence": "Every incident and recurring control review",
        "test": "Verify closure evidence includes containment, root cause, remediation, retest, and owner signoff."
    }
]


AGENTTRUST_COMPILER_OUTPUTS = [
    {
        "compiler_stage": "Policy Extraction",
        "input": "AI governance policy, SOP, standard, framework expectation, audit observation, or leadership requirement.",
        "output": "Plain-language obligation.",
        "quality_rule": "Obligation must be specific enough to test."
    },
    {
        "compiler_stage": "Control Translation",
        "input": "Plain-language obligation.",
        "output": "Operational control requirement.",
        "quality_rule": "Control must define what prevents, detects, routes, blocks, or proves compliance."
    },
    {
        "compiler_stage": "Evidence Mapping",
        "input": "Control requirement.",
        "output": "Evidence artifact list.",
        "quality_rule": "Evidence must prove control operation, not just control existence."
    },
    {
        "compiler_stage": "Owner Assignment",
        "input": "Control and evidence requirement.",
        "output": "Accountable owner and reviewer route.",
        "quality_rule": "No ownerless obligation may be considered implemented."
    },
    {
        "compiler_stage": "Cadence Assignment",
        "input": "Risk tier and action type.",
        "output": "Testing, monitoring, review, and attestation cadence.",
        "quality_rule": "Higher-risk controls require more frequent review."
    },
    {
        "compiler_stage": "Exception Handling",
        "input": "Incomplete control, missing owner, missing evidence, or open risk.",
        "output": "Exception, restriction, expiry, owner, and remediation path.",
        "quality_rule": "Exceptions must be visible, time-bound, and signed."
    },
    {
        "compiler_stage": "Assurance Packaging",
        "input": "Control, evidence, owner, testing, exception, and signoff records.",
        "output": "Audit-ready assurance package.",
        "quality_rule": "Package must support executive defense and audit replay."
    }
]


AGENTTRUST_POLICY_EXCEPTION_RULES = [
    {
        "exception_type": "Missing Owner",
        "meaning": "Policy obligation cannot be assigned to an accountable person or function.",
        "decision": "Block or restrict.",
        "required_action": "Assign owner before implementation or attestation."
    },
    {
        "exception_type": "Missing Evidence",
        "meaning": "Control exists in design but operation cannot be proven.",
        "decision": "Not defensible.",
        "required_action": "Define evidence artifact and test sample."
    },
    {
        "exception_type": "Manual Workaround",
        "meaning": "Control relies on manual tracking outside system workflow.",
        "decision": "Conditional.",
        "required_action": "Document owner, cadence, evidence location, and expiry."
    },
    {
        "exception_type": "Cyber Review Pending",
        "meaning": "Access, entitlement, CyberArk, PSM, admin, or privileged impact is not reviewed.",
        "decision": "Cyber-gated.",
        "required_action": "Route to cybersecurity owner before reliance."
    },
    {
        "exception_type": "QA Review Pending",
        "meaning": "GxP, QA, validation, release, deviation, CAPA, QC, or inspection impact is not reviewed.",
        "decision": "QA-governed only.",
        "required_action": "Route to QA / validation owner before regulated reliance."
    },
    {
        "exception_type": "Vendor Assurance Pending",
        "meaning": "Vendor AI identity, data boundary, audit support, contract controls, or exit plan is incomplete.",
        "decision": "Restrict vendor use.",
        "required_action": "Limit to synthetic or non-sensitive data until vendor controls are complete."
    },
    {
        "exception_type": "Open Incident / Deficiency",
        "meaning": "Incident or control deficiency remains unresolved.",
        "decision": "Do not fully attest.",
        "required_action": "Contain, remediate, retest, and capture owner signoff."
    }
]


def agenttrust_policy_obligation_rows():
    rows = ""

    for item in AGENTTRUST_POLICY_OBLIGATIONS:
        rows += f"""
        <tr>
            <td><strong>{item["obligation_id"]}</strong></td>
            <td>{item["policy_obligation"]}</td>
            <td><span class="badge blue">{item["control_requirement"]}</span></td>
            <td>{item["evidence"]}</td>
            <td>{item["owner"]}</td>
            <td><span class="badge green">{item["cadence"]}</span></td>
            <td>{item["test"]}</td>
        </tr>
        """

    return rows


def agenttrust_compiler_output_rows():
    rows = ""

    for item in AGENTTRUST_COMPILER_OUTPUTS:
        rows += f"""
        <tr>
            <td><strong>{item["compiler_stage"]}</strong></td>
            <td>{item["input"]}</td>
            <td>{item["output"]}</td>
            <td><span class="badge yellow">{item["quality_rule"]}</span></td>
        </tr>
        """

    return rows


def agenttrust_policy_exception_rows():
    rows = ""

    for item in AGENTTRUST_POLICY_EXCEPTION_RULES:
        badge = "orange"
        if "Block" in item["decision"] or "not" in item["decision"].lower() or "Do not" in item["decision"]:
            badge = "red"
        elif "gated" in item["decision"].lower() or "governed" in item["decision"].lower():
            badge = "yellow"

        rows += f"""
        <tr>
            <td><strong>{item["exception_type"]}</strong></td>
            <td>{item["meaning"]}</td>
            <td><span class="badge {badge}">{item["decision"]}</span></td>
            <td>{item["required_action"]}</td>
        </tr>
        """

    return rows


def agenttrust_policy_control_decision(policy, control, evidence, owner, cadence, testing, exception, attestation):
    controls = [policy, control, evidence, owner, cadence, testing, attestation]
    score = int((sum(1 for item in controls if item == "yes") / len(controls)) * 100)

    if policy != "yes":
        return score, "Cannot Compile", "red", "No clear policy obligation exists."
    if control != "yes":
        return score, "Design Gap", "red", "Policy obligation has not been translated into an operational control."
    if evidence != "yes":
        return score, "Evidence Gap", "red", "Control cannot be proven with defined evidence artifacts."
    if owner != "yes":
        return score, "Owner Gap", "red", "No accountable owner is assigned."
    if cadence != "yes":
        return score, "Cadence Gap", "orange", "Testing or monitoring cadence is not defined."
    if testing != "yes":
        return score, "Testing Gap", "orange", "Control effectiveness test is not defined."
    if exception == "yes":
        return score, "Conditional Compilation", "yellow", "Policy-to-control mapping exists but has an open exception that must be owned and time-bound."
    if attestation != "yes":
        return score, "Pending Attestation", "yellow", "Control mapping is complete but owner signoff is pending."
    if score == 100:
        return score, "Compiled and Defensible", "green", "Policy obligation is translated into control, evidence, owner, cadence, test, and attestation."
    return score, "Partially Compiled", "yellow", "Policy obligation is partially translated but needs closure before audit reliance."


try:
    AGENTTRUST_EXPECTED_ROUTES.extend([
        "/agenttrust/policy-control-compiler",
        "/agenttrust/policy-to-control-compiler",
        "/agenttrust/obligation-traceability-matrix",
        "/agenttrust/policy-obligation-register",
        "/agenttrust/control-obligation-mapper",
        "/agenttrust/evidence-requirement-compiler",
        "/agenttrust/control-cadence-compiler",
        "/agenttrust/policy-exception-compiler",
        "/agenttrust/policy-control-simulator",
        "/agenttrust/policy-control-json"
    ])
except Exception:
    pass


@app.route("/agenttrust/policy-control-compiler")
@app.route("/agenttrust/policy-to-control-compiler")
@app.route("/agenttrust/ai-policy-control-compiler")
def agenttrust_policy_control_compiler():
    rows = agenttrust_compiler_output_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Policy Compiler</div><div class="value" style="color:var(--green);">Active</div><div class="note">Policies converted into controls and evidence.</div></div>
        <div class="metric"><div class="label">Obligations</div><div class="value" style="color:var(--blue);">10</div><div class="note">Identity, authority, human, cyber, GxP, privacy, vendor, model, evidence, incident.</div></div>
        <div class="metric"><div class="label">Evidence</div><div class="value" style="color:var(--yellow);">Mapped</div><div class="note">Every control requires proof of operation.</div></div>
        <div class="metric"><div class="label">Owners</div><div class="value" style="color:var(--orange);">Required</div><div class="note">No ownerless obligation is defensible.</div></div>
        <div class="metric"><div class="label">Exceptions</div><div class="value" style="color:var(--red);">Controlled</div><div class="note">Gaps become restrictions, expiry, and remediation.</div></div>
        <div class="metric"><div class="label">Attestation</div><div class="value" style="color:var(--purple);">Linked</div><div class="note">Compiled controls feed owner signoff.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Policy-to-Control Compiler</h2>
        <div class="answer">
            <strong>Purpose:</strong> convert AI governance policy into operational controls that can be tested,
            evidenced, owned, monitored, attested, and defended. The compiler prevents policy from remaining
            high-level language with no execution path.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Compiler Stage</th>
                    <th>Input</th>
                    <th>Output</th>
                    <th>Quality Rule</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Compiler Rule</h2>
        <div class="answer">
            A policy obligation is not operational until it has a control, evidence, owner, cadence, test,
            exception route, and attestation path.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Policy-to-Control Compiler",
        "Compiler that translates AI governance policy obligations into operational controls, evidence requirements, owners, cadence, testing, exceptions, and attestation.",
        body
    )


@app.route("/agenttrust/obligation-traceability-matrix")
@app.route("/agenttrust/policy-traceability-matrix")
@app.route("/agenttrust/control-traceability-matrix")
def agenttrust_obligation_traceability_matrix():
    rows = agenttrust_policy_obligation_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Obligation Traceability Matrix</h2>
        <p>
            This matrix traces each AI governance obligation from policy wording to control requirement, evidence,
            owner, cadence, and test.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Obligation ID</th>
                    <th>Policy Obligation</th>
                    <th>Control Requirement</th>
                    <th>Evidence</th>
                    <th>Owner</th>
                    <th>Cadence</th>
                    <th>Test</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Traceability Rule</h2>
        <div class="answer">
            Every AI policy statement should be traceable to a control and every control should be traceable to evidence.
            Without traceability, audit defense becomes narrative instead of proof.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Obligation Traceability Matrix",
        "Traceability matrix connecting AI governance obligations to controls, evidence, owners, cadence, and tests.",
        body
    )


@app.route("/agenttrust/policy-obligation-register")
@app.route("/agenttrust/ai-policy-obligation-register")
@app.route("/agenttrust/obligation-register")
def agenttrust_policy_obligation_register():
    rows = agenttrust_policy_obligation_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Policy Obligation Register</h2>
        <p>
            The Policy Obligation Register captures the core AI governance expectations that must be converted into operational controls.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Obligation ID</th>
                    <th>Policy Obligation</th>
                    <th>Control Requirement</th>
                    <th>Evidence</th>
                    <th>Owner</th>
                    <th>Cadence</th>
                    <th>Test</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Policy Obligation Register",
        "Register of AI governance policy obligations mapped to controls, evidence, owners, cadence, and testing expectations.",
        body
    )


@app.route("/agenttrust/control-obligation-mapper")
@app.route("/agenttrust/obligation-control-mapper")
@app.route("/agenttrust/policy-control-mapper")
def agenttrust_control_obligation_mapper():
    body = """
    <section class="section">
        <h2>AgentTrust™ Control Obligation Mapper</h2>
        <p>
            This mapper converts policy obligations into control language that can be tested.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Policy Language</th>
                    <th>Control Translation</th>
                    <th>Control Type</th>
                    <th>Testing Question</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>AI must be accountable.</td><td>Every agent has owner, passport, lifecycle state, and signoff route.</td><td><span class="badge blue">Preventive / Detective</span></td><td>Can every active agent be tied to a human owner?</td></tr>
                <tr><td>AI must not act beyond authority.</td><td>High-impact actions require preflight gate, trust token, and action permit.</td><td><span class="badge red">Preventive</span></td><td>Can unauthorized actions execute?</td></tr>
                <tr><td>AI must remain human-governed.</td><td>Material reliance requires human reviewer and decision evidence.</td><td><span class="badge yellow">Preventive / Detective</span></td><td>Is human review captured before reliance?</td></tr>
                <tr><td>AI must protect access and privilege.</td><td>Access and CyberArk / PSM contexts route to cybersecurity and block AI approval.</td><td><span class="badge red">Preventive</span></td><td>Can AI approve or trigger privileged access?</td></tr>
                <tr><td>AI must protect regulated decisions.</td><td>GxP, QA, validation, release, deviation, CAPA, QC, and inspection contexts route to QA.</td><td><span class="badge red">Preventive</span></td><td>Can AI make regulated conclusion?</td></tr>
                <tr><td>AI must be auditable.</td><td>Every material action has evidence lineage and replay package.</td><td><span class="badge orange">Detective</span></td><td>Can the action be reconstructed identity-to-outcome?</td></tr>
                <tr><td>AI must remain controlled after release.</td><td>Drift, incidents, deficiencies, exceptions, and model changes trigger review.</td><td><span class="badge purple">Monitoring</span></td><td>Do changes or failures update trust posture?</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Mapper Rule</h2>
        <div class="answer">
            Policy language must be converted into control language.
            “AI must be accountable” becomes owner, passport, signoff, evidence, and testable ownership records.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Control Obligation Mapper",
        "Mapper converting AI governance policy language into operational control language, control type, and testing questions.",
        body
    )


@app.route("/agenttrust/evidence-requirement-compiler")
@app.route("/agenttrust/evidence-compiler")
@app.route("/agenttrust/policy-evidence-compiler")
def agenttrust_evidence_requirement_compiler():
    body = """
    <section class="section">
        <h2>AgentTrust™ Evidence Requirement Compiler</h2>
        <p>
            This compiler defines the evidence needed to prove each AI governance control.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Control Area</th>
                    <th>Minimum Evidence</th>
                    <th>Evidence Owner</th>
                    <th>Audit Failure If Missing</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent Identity</td><td>Agent ID, owner, purpose, risk tier, lifecycle state, operating license.</td><td>Governance Owner.</td><td><span class="badge red">Unknown or ownerless agent</span></td></tr>
                <tr><td>Authority</td><td>Authority decision, trust token, action permit, policy rule, outcome.</td><td>Risk / Platform Owner.</td><td><span class="badge red">Unauthorized action cannot be disproven</span></td></tr>
                <tr><td>Human Review</td><td>Reviewer, decision, timestamp, approval/rejection, reliance condition.</td><td>Process Owner.</td><td><span class="badge red">Hidden approval risk</span></td></tr>
                <tr><td>Cyber</td><td>Access context, cyber route, CyberArk / PSM assessment, cyber decision.</td><td>Cybersecurity Owner.</td><td><span class="badge red">Privileged access exposure</span></td></tr>
                <tr><td>GxP / QA</td><td>GxP impact screen, QA decision, validation review, regulated reliance status.</td><td>QA / Validation Owner.</td><td><span class="badge red">Inspection defensibility gap</span></td></tr>
                <tr><td>Privacy</td><td>Data classification, minimization, retention, transfer, DPIA, deletion status.</td><td>Privacy / Data Owner.</td><td><span class="badge orange">Data protection gap</span></td></tr>
                <tr><td>Vendor AI</td><td>Vendor register, contract controls, data boundary, evidence dossier, exit plan.</td><td>Vendor Owner.</td><td><span class="badge orange">Third-party AI exposure</span></td></tr>
                <tr><td>Incident Closure</td><td>Incident record, containment, root cause, remediation, retest, owner signoff.</td><td>Incident Owner.</td><td><span class="badge red">Incident not defensibly closed</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Evidence Compiler Rule</h2>
        <div class="answer">
            Evidence must prove what happened, who owned it, what was reviewed, what decision was made,
            and whether the control actually operated.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Evidence Requirement Compiler",
        "Compiler for AI governance control evidence requirements across identity, authority, human review, cyber, GxP, privacy, vendor AI, and incident closure.",
        body
    )


@app.route("/agenttrust/control-cadence-compiler")
@app.route("/agenttrust/cadence-compiler")
@app.route("/agenttrust/policy-cadence-compiler")
def agenttrust_control_cadence_compiler():
    body = """
    <section class="section">
        <h2>AgentTrust™ Control Cadence Compiler</h2>
        <p>
            This page converts control risk into testing, monitoring, review, and attestation cadence.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Risk / Control Type</th>
                    <th>Minimum Cadence</th>
                    <th>Trigger Events</th>
                    <th>Owner</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Critical access / privileged control</td><td>Every action and monthly review.</td><td>Access route, CyberArk, PSM, entitlement, admin context.</td><td>Cybersecurity Owner.</td></tr>
                <tr><td>Critical GxP / QA control</td><td>Every regulated use and quarterly review.</td><td>GMP, QA, validation, release, deviation, CAPA, QC, inspection.</td><td>QA / Validation Owner.</td></tr>
                <tr><td>High-risk authority control</td><td>Every high-impact action.</td><td>Create, update, trigger, approve, workflow action.</td><td>Risk / Process Owner.</td></tr>
                <tr><td>Evidence replay control</td><td>Every material action and monthly sample.</td><td>Audit pack, inspection pack, evidence gap, incident.</td><td>Audit / Evidence Owner.</td></tr>
                <tr><td>Model / prompt / tool change control</td><td>Every material change.</td><td>Model, prompt, endpoint, parser, tool, retrieval, workflow change.</td><td>AI Platform / Lifecycle Owner.</td></tr>
                <tr><td>Vendor AI control</td><td>Before onboarding and quarterly.</td><td>New vendor AI, data boundary change, contract change, incident.</td><td>Vendor / Security Owner.</td></tr>
                <tr><td>Executive attestation</td><td>Before release and periodic leadership review.</td><td>Production promotion, major incident, critical exception, control failure.</td><td>Executive Sponsor / Governance Owner.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Cadence Rule</h2>
        <div class="answer">
            Cadence follows risk. Critical controls are tested at the point of action;
            lower-risk controls may be sampled periodically, but drift and incident triggers force immediate review.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Control Cadence Compiler",
        "Compiler for AI governance control testing, monitoring, review, and attestation cadence based on risk and trigger events.",
        body
    )


@app.route("/agenttrust/policy-exception-compiler")
@app.route("/agenttrust/exception-compiler")
@app.route("/agenttrust/ai-policy-exceptions")
def agenttrust_policy_exception_compiler():
    rows = agenttrust_policy_exception_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Policy Exception Compiler</h2>
        <p>
            The exception compiler converts policy implementation gaps into visible restrictions, owner routes, expiry, and remediation.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Exception Type</th>
                    <th>Meaning</th>
                    <th>Decision</th>
                    <th>Required Action</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Exception Compiler Rule</h2>
        <div class="answer">
            A gap is not acceptable just because it is known.
            AgentTrust™ requires every exception to have an owner, condition, expiry, restriction, and closure evidence.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Policy Exception Compiler",
        "Policy exception compiler for missing owners, evidence gaps, manual workarounds, cyber review gaps, QA review gaps, vendor assurance gaps, and open incidents.",
        body
    )


@app.route("/agenttrust/policy-control-simulator", methods=["GET", "POST"])
@app.route("/agenttrust/policy-compiler-simulator", methods=["GET", "POST"])
@app.route("/agenttrust/obligation-simulator", methods=["GET", "POST"])
def agenttrust_policy_control_simulator():
    from flask import request

    policy = request.form.get("policy", "yes")
    control = request.form.get("control", "yes")
    evidence = request.form.get("evidence", "yes")
    owner = request.form.get("owner", "yes")
    cadence = request.form.get("cadence", "yes")
    testing = request.form.get("testing", "yes")
    exception = request.form.get("exception", "no")
    attestation = request.form.get("attestation", "yes")

    score, decision, badge, reason = agenttrust_policy_control_decision(
        policy, control, evidence, owner, cadence, testing, exception, attestation
    )

    def selected(value, expected):
        return "selected" if value == expected else ""

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Compilation Score</div><div class="value" style="color:var(--green);">{score}%</div><div class="note">Calculated from policy-to-control readiness.</div></div>
        <div class="metric"><div class="label">Compilation Decision</div><div class="value" style="color:var(--yellow);">{decision}</div><div class="note">{reason}</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Policy Control Simulator</h2>
        <p>
            Simulate whether a policy obligation is operationally compiled into a defensible control.
        </p>

        <form method="POST" action="/agenttrust/policy-control-simulator">
            <table>
                <tbody>
                    <tr><td><strong>Clear Policy Obligation Exists?</strong></td><td><select name="policy" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(policy, "yes")}>Yes</option><option value="no" {selected(policy, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Operational Control Defined?</strong></td><td><select name="control" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(control, "yes")}>Yes</option><option value="no" {selected(control, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Evidence Requirement Defined?</strong></td><td><select name="evidence" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(evidence, "yes")}>Yes</option><option value="no" {selected(evidence, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Accountable Owner Assigned?</strong></td><td><select name="owner" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(owner, "yes")}>Yes</option><option value="no" {selected(owner, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Cadence Defined?</strong></td><td><select name="cadence" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(cadence, "yes")}>Yes</option><option value="no" {selected(cadence, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Control Test Defined?</strong></td><td><select name="testing" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(testing, "yes")}>Yes</option><option value="no" {selected(testing, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Open Exception Exists?</strong></td><td><select name="exception" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="no" {selected(exception, "no")}>No</option><option value="yes" {selected(exception, "yes")}>Yes</option></select></td></tr>
                    <tr><td><strong>Owner Attestation Ready?</strong></td><td><select name="attestation" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(attestation, "yes")}>Yes</option><option value="no" {selected(attestation, "no")}>No</option></select></td></tr>
                </tbody>
            </table>

            <button type="submit" style="margin-top:16px;padding:12px 18px;border-radius:12px;border:0;background:#2563eb;color:white;font-weight:800;">Run Policy Compiler Check</button>
        </form>
    </section>

    <section class="section">
        <h2>Policy Compilation Decision</h2>
        <div class="answer">
            <strong>Score:</strong> {score}%<br>
            <strong>Decision:</strong> <span class="badge {badge}">{decision}</span><br>
            <strong>Reason:</strong> {reason}
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Policy Control Simulator",
        "Simulator for policy-to-control compilation readiness across obligation, control, evidence, owner, cadence, testing, exceptions, and attestation.",
        body
    )


@app.route("/agenttrust/policy-control-json")
@app.route("/agenttrust/policy-compiler-json")
@app.route("/agenttrust/obligation-traceability-json")
def agenttrust_policy_control_json():
    from flask import jsonify

    return jsonify({
        "module": "AgentTrust™",
        "capability": "Policy-to-Control Compiler + Obligation Traceability Matrix",
        "primary_question": "Has this AI policy obligation been converted into a testable, owned, evidenced, and attestable control?",
        "policy_obligations": AGENTTRUST_POLICY_OBLIGATIONS,
        "compiler_outputs": AGENTTRUST_COMPILER_OUTPUTS,
        "policy_exception_rules": AGENTTRUST_POLICY_EXCEPTION_RULES,
        "minimum_compilation_conditions": [
            "Clear policy obligation exists",
            "Operational control requirement is defined",
            "Evidence artifact is mapped",
            "Accountable owner is assigned",
            "Testing or monitoring cadence is defined",
            "Control effectiveness test is defined",
            "Exceptions are owned, restricted, time-bound, and remediated",
            "Owner attestation is linked",
            "Audit-ready assurance package can be produced"
        ],
        "default_decision": "Do not treat AI policy as implemented until it is translated into control, evidence, owner, cadence, test, exception route, and attestation"
    })

# ============================================================
# END AGENTTRUST_POLICY_CONTROL_COMPILER_V1_ACTIVE
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

print("AgentTrust Policy-to-Control Compiler installed.")
print(f"Inserted before: {target_found}")
