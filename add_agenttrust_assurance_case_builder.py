from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_ASSURANCE_CASE_BUILDER_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust Assurance Case Builder already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base module not found. Install AgentTrust module first.")

nav_old = '<a href="/agenttrust/continuous-monitoring-center" class="secondary">Monitoring</a>'
nav_new = '''<a href="/agenttrust/continuous-monitoring-center" class="secondary">Monitoring</a>
                    <a href="/agenttrust/assurance-case-builder" class="secondary">Assurance Case</a>
                    <a href="/agenttrust/audit-dossier-generator" class="dark">Audit Dossier</a>
                    <a href="/agenttrust/claim-evidence-argument-map" class="dark">Claim Map</a>
                    <a href="/agenttrust/executive-assurance-memo" class="dark">Exec Memo</a>'''

if nav_old in text and "/agenttrust/assurance-case-builder" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# AGENTTRUST_ASSURANCE_CASE_BUILDER_V1_ACTIVE
# AgentTrust™ Assurance Case Builder, Claim-Evidence-Argument Map,
# Audit Dossier Generator, Inspection Response Pack,
# Executive Assurance Memo, Evidence Gap Closure Plan,
# and Assurance Case JSON Export
# ============================================================

AGENTTRUST_ASSURANCE_CLAIMS = [
    {
        "claim_id": "AT-CLM-001",
        "claim": "The AI agent is known and registered.",
        "evidence": "Agent Register, Agent Risk Passport™, lifecycle status, business owner, technical owner.",
        "control": "Agent identity control",
        "owner": "Governance Owner",
        "defensibility": "Strong"
    },
    {
        "claim_id": "AT-CLM-002",
        "claim": "The AI agent has accountable human ownership.",
        "evidence": "Human Accountability Map, signoff matrix, approval queue, risk owner mapping.",
        "control": "Human accountability control",
        "owner": "Business Owner / Technical Owner",
        "defensibility": "Strong"
    },
    {
        "claim_id": "AT-CLM-003",
        "claim": "The AI agent can only operate inside an approved boundary.",
        "evidence": "AgentBOM, approved systems, tools, APIs, data sources, prohibited actions.",
        "control": "Boundary and dependency control",
        "owner": "Agent Lifecycle Owner",
        "defensibility": "Strong"
    },
    {
        "claim_id": "AT-CLM-004",
        "claim": "The AI agent cannot execute without authority.",
        "evidence": "Authority Gate, Policy Decision Engine, decision rules, action decision records.",
        "control": "Authority-before-execution control",
        "owner": "Process Owner / Risk Owner",
        "defensibility": "Strong"
    },
    {
        "claim_id": "AT-CLM-005",
        "claim": "The AI agent action is evidenced at the time of action.",
        "evidence": "Tool-call evidence, input evidence, output evidence, timestamp, reviewer, outcome.",
        "control": "Evidence sufficiency control",
        "owner": "Audit / Platform Owner",
        "defensibility": "Moderate"
    },
    {
        "claim_id": "AT-CLM-006",
        "claim": "High-risk actions are human-gated.",
        "evidence": "Human Oversight Workbench, Approval Queue, Human Signoff Matrix, Review Decision Simulator.",
        "control": "Human oversight control",
        "owner": "Required Human Reviewer",
        "defensibility": "Strong"
    },
    {
        "claim_id": "AT-CLM-007",
        "claim": "CyberArk, MyAccess, PSM, admin, or privileged-impacting actions are escalated.",
        "evidence": "Cyber escalation rule, MyAccess / CyberArk routing, privileged access decision record.",
        "control": "Cybersecurity escalation control",
        "owner": "Cybersecurity / CyberArk Owner",
        "defensibility": "Strong"
    },
    {
        "claim_id": "AT-CLM-008",
        "claim": "GxP, QA, validation, release, deviation, or inspection-impacting actions are human-governed.",
        "evidence": "GxP Impact Router, GxP Screening, QA review record, validation owner evidence.",
        "control": "Regulated impact control",
        "owner": "QA / Validation Owner",
        "defensibility": "Strong"
    },
    {
        "claim_id": "AT-CLM-009",
        "claim": "Runtime safety is controlled.",
        "evidence": "Execution Firewall, Runtime Sentinel, Kill Switch, Quarantine, Rollback evidence.",
        "control": "Runtime safety control",
        "owner": "Platform / Risk Owner",
        "defensibility": "Moderate"
    },
    {
        "claim_id": "AT-CLM-010",
        "claim": "The AI agent can be audited and replayed.",
        "evidence": "Decision Replay Studio, Evidence Lineage Engine, Action Timeline, Audit Defense Room.",
        "control": "Audit replay control",
        "owner": "Audit / Governance Owner",
        "defensibility": "Strong"
    }
]


AGENTTRUST_DOSSIER_ITEMS = [
    {
        "section": "1. Agent Identity",
        "artifact": "Agent Register + Agent Risk Passport™",
        "audit_question": "Which AI agent acted and who owns it?",
        "status": "Ready"
    },
    {
        "section": "2. Operating Boundary",
        "artifact": "AgentBOM + Dependency Graph + Approved Systems / Tools / APIs",
        "audit_question": "Where was the agent allowed to operate?",
        "status": "Ready"
    },
    {
        "section": "3. Authority",
        "artifact": "Authority Gate + Policy Decision Engine + Decision Record",
        "audit_question": "Why was the agent allowed or blocked?",
        "status": "Ready"
    },
    {
        "section": "4. Evidence",
        "artifact": "Tool-Call Evidence + Input / Output / Timestamp / Outcome Record",
        "audit_question": "What evidence proves what happened?",
        "status": "Review"
    },
    {
        "section": "5. Human Oversight",
        "artifact": "Approval Queue + Signoff Matrix + Human Review Evidence",
        "audit_question": "Which human remained accountable?",
        "status": "Ready"
    },
    {
        "section": "6. Cyber / Access",
        "artifact": "MyAccess / CyberArk Routing + Cyber Review Record",
        "audit_question": "Did access or privileged impact require cyber review?",
        "status": "Conditional"
    },
    {
        "section": "7. GxP / QA",
        "artifact": "GxP Impact Screening + QA / Validation Review",
        "audit_question": "Did regulated impact require QA or validation review?",
        "status": "Conditional"
    },
    {
        "section": "8. Runtime Control",
        "artifact": "Execution Firewall + Runtime Sentinel + Kill Switch + Quarantine",
        "audit_question": "How was unsafe execution controlled?",
        "status": "Review"
    },
    {
        "section": "9. Monitoring",
        "artifact": "Continuous Monitoring Center + Drift Alerts + Trust Degradation Watch",
        "audit_question": "Is the agent still trusted after deployment?",
        "status": "Ready"
    },
    {
        "section": "10. Audit Replay",
        "artifact": "Decision Replay Studio + Evidence Lineage + Action Timeline",
        "audit_question": "Can the action be reconstructed end-to-end?",
        "status": "Ready"
    }
]


def agenttrust_assurance_claim_rows():
    rows = ""

    for item in AGENTTRUST_ASSURANCE_CLAIMS:
        badge = "green"
        if item["defensibility"] == "Moderate":
            badge = "yellow"
        elif item["defensibility"] == "Weak":
            badge = "red"

        rows += f"""
        <tr>
            <td><strong>{item["claim_id"]}</strong></td>
            <td>{item["claim"]}</td>
            <td>{item["evidence"]}</td>
            <td><span class="badge blue">{item["control"]}</span></td>
            <td>{item["owner"]}</td>
            <td><span class="badge {badge}">{item["defensibility"]}</span></td>
        </tr>
        """

    return rows


def agenttrust_dossier_item_rows():
    rows = ""

    for item in AGENTTRUST_DOSSIER_ITEMS:
        badge = "green"
        if item["status"] == "Review":
            badge = "yellow"
        elif item["status"] == "Conditional":
            badge = "orange"
        elif item["status"] == "Gap":
            badge = "red"

        rows += f"""
        <tr>
            <td><strong>{item["section"]}</strong></td>
            <td>{item["artifact"]}</td>
            <td>{item["audit_question"]}</td>
            <td><span class="badge {badge}">{item["status"]}</span></td>
        </tr>
        """

    return rows


try:
    AGENTTRUST_EXPECTED_ROUTES.extend([
        "/agenttrust/assurance-case-builder",
        "/agenttrust/claim-evidence-argument-map",
        "/agenttrust/audit-dossier-generator",
        "/agenttrust/inspection-response-pack",
        "/agenttrust/executive-assurance-memo",
        "/agenttrust/evidence-gap-closure-plan",
        "/agenttrust/assurance-case-json"
    ])
except Exception:
    pass


@app.route("/agenttrust/assurance-case-builder")
@app.route("/agenttrust/agent-assurance-case")
@app.route("/agenttrust/ai-assurance-case")
def agenttrust_assurance_case_builder():
    rows = agenttrust_assurance_claim_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Assurance Case</div><div class="value" style="color:var(--green);">Built</div><div class="note">Claims, evidence, controls, owners, and decisions mapped.</div></div>
        <div class="metric"><div class="label">Claims</div><div class="value" style="color:var(--blue);">10</div><div class="note">Core operational trust claims defined.</div></div>
        <div class="metric"><div class="label">Evidence</div><div class="value" style="color:var(--yellow);">Mapped</div><div class="note">Each claim links to evidence artifacts.</div></div>
        <div class="metric"><div class="label">Owners</div><div class="value" style="color:var(--orange);">Assigned</div><div class="note">Each claim has an accountable owner.</div></div>
        <div class="metric"><div class="label">Audit Defense</div><div class="value" style="color:var(--purple);">Replayable</div><div class="note">Dossier-ready audit structure created.</div></div>
        <div class="metric"><div class="label">Decision</div><div class="value" style="color:var(--red);">Defensible</div><div class="note">Trust decision is evidence-backed.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Assurance Case Builder</h2>
        <div class="answer">
            <strong>Purpose:</strong> convert AgentTrust™ governance into a defensible assurance case.
            The assurance case proves why an AI agent can be trusted, human-gated, restricted, escalated,
            blocked, quarantined, or retired using claims, evidence, controls, owners, and replayable records.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Claim ID</th>
                    <th>Trust Claim</th>
                    <th>Evidence</th>
                    <th>Control</th>
                    <th>Owner</th>
                    <th>Defensibility</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Assurance Case Rule</h2>
        <div class="answer">
            AgentTrust™ does not rely on confidence alone. It builds a defensible case:
            what is claimed, what evidence supports it, which control enforces it, who owns it, and how it can be replayed.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Assurance Case Builder",
        "Assurance case builder for AI agent trust claims, evidence, controls, owners, decisions, and audit replay.",
        body
    )


@app.route("/agenttrust/claim-evidence-argument-map")
@app.route("/agenttrust/claim-evidence-map")
@app.route("/agenttrust/argument-map")
def agenttrust_claim_evidence_argument_map():
    rows = agenttrust_assurance_claim_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Claim-Evidence-Argument Map</h2>
        <p>
            This map connects each trust claim to the evidence and control argument that supports it.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Claim ID</th>
                    <th>Claim</th>
                    <th>Evidence</th>
                    <th>Control Argument</th>
                    <th>Owner</th>
                    <th>Strength</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Argument Map Principle</h2>
        <div class="answer">
            A dashboard can say an AI agent is trusted. An assurance case explains why.
            The claim-evidence-argument map is what makes the trust decision defendable.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Claim-Evidence-Argument Map",
        "Claim-evidence-argument map for AI agent trust, evidence sufficiency, control ownership, and defensibility.",
        body
    )


@app.route("/agenttrust/audit-dossier-generator")
@app.route("/agenttrust/agent-audit-dossier")
@app.route("/agenttrust/audit-dossier")
def agenttrust_audit_dossier_generator():
    rows = agenttrust_dossier_item_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Audit Dossier Generator</h2>
        <p>
            The Audit Dossier Generator organizes AgentTrust™ evidence into a structure that can be used for audit,
            inspection, cybersecurity review, QA review, governance board review, or executive challenge.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Dossier Section</th>
                    <th>Required Artifact</th>
                    <th>Audit Question Answered</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Dossier Output</h2>
        <div class="answer">
            <strong>Generated Dossier Logic:</strong><br>
            1. Identify the agent.<br>
            2. Confirm the owner.<br>
            3. Confirm boundary and dependencies.<br>
            4. Confirm authority.<br>
            5. Confirm evidence.<br>
            6. Confirm human oversight.<br>
            7. Confirm cyber and GxP routing where applicable.<br>
            8. Confirm runtime controls.<br>
            9. Confirm monitoring status.<br>
            10. Confirm replay package.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Audit Dossier Generator",
        "Audit dossier generator for AI agent identity, boundary, authority, evidence, human oversight, cyber, GxP, runtime, monitoring, and replay evidence.",
        body
    )


@app.route("/agenttrust/inspection-response-pack")
@app.route("/agenttrust/inspection-pack")
@app.route("/agenttrust/regulatory-response-pack")
def agenttrust_inspection_response_pack():
    body = """
    <section class="section">
        <h2>AgentTrust™ Inspection Response Pack</h2>
        <p>
            This pack prepares concise responses to the questions an auditor, QA reviewer, cybersecurity reviewer,
            or regulator may ask about AI agent use.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Inspection Question</th>
                    <th>AgentTrust™ Response Evidence</th>
                    <th>Responsible Owner</th>
                    <th>Defensible Answer</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Which AI agent acted?</td><td>Agent Register and Agent Risk Passport™.</td><td>Governance Owner.</td><td><span class="badge green">Agent identity is known.</span></td></tr>
                <tr><td>Who owns the AI agent?</td><td>Human Accountability Map and Signoff Matrix.</td><td>Business / Technical Owner.</td><td><span class="badge green">Human accountability is assigned.</span></td></tr>
                <tr><td>What was the agent allowed to do?</td><td>Authority Gate and Policy Decision Engine.</td><td>Process / Risk Owner.</td><td><span class="badge green">Authority was defined before action.</span></td></tr>
                <tr><td>What systems did it touch?</td><td>AgentBOM, Dependency Graph, Tool-Call Evidence.</td><td>Technical / Platform Owner.</td><td><span class="badge green">System boundary is traceable.</span></td></tr>
                <tr><td>Was the action evidenced?</td><td>Evidence Ledger, Tool-Call Log, Outcome Record.</td><td>Audit / Platform Owner.</td><td><span class="badge yellow">Evidence completeness must be checked.</span></td></tr>
                <tr><td>Did it affect access or privilege?</td><td>MyAccess / CyberArk Routing and Cyber Review.</td><td>Cybersecurity Owner.</td><td><span class="badge orange">Cyber review required if impacted.</span></td></tr>
                <tr><td>Did it affect GxP or QA evidence?</td><td>GxP Impact Screening and QA / Validation Review.</td><td>QA / Validation Owner.</td><td><span class="badge red">Human-governed only if regulated.</span></td></tr>
                <tr><td>Can you replay what happened?</td><td>Decision Replay Studio and Evidence Lineage Engine.</td><td>Audit / Governance Owner.</td><td><span class="badge green">Replay package required.</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Inspection Rule</h2>
        <div class="answer">
            The strongest inspection response is not “the AI was accurate.”
            It is “the AI agent was known, owned, bounded, authorized, evidenced, human-governed, monitored, and replayable.”
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Inspection Response Pack",
        "Inspection response pack for AI agent identity, ownership, authority, systems touched, evidence, cyber impact, GxP impact, and replayability.",
        body
    )


@app.route("/agenttrust/executive-assurance-memo")
@app.route("/agenttrust/leadership-assurance-memo")
@app.route("/agenttrust/board-assurance-memo")
def agenttrust_executive_assurance_memo():
    body = """
    <section class="section">
        <h2>AgentTrust™ Executive Assurance Memo</h2>
        <div class="answer">
            <strong>Executive Position:</strong><br>
            AgentTrust™ provides an operational assurance layer for AI agents. It does not simply ask whether an AI agent can produce useful output.
            It asks whether the agent can be trusted to act inside enterprise workflows with known identity, known owner,
            known authority, known boundary, known evidence, known risk, known human accountability, and known outcome.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Leadership Concern</th>
                    <th>AgentTrust™ Assurance Response</th>
                    <th>Evidence Artifact</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>AI agents may act without oversight.</td><td>Authority gates and human oversight preserve decision accountability.</td><td>Authority Gate + Human Oversight Workbench.</td></tr>
                <tr><td>AI agents may alter records or workflows.</td><td>Execution firewall controls create, update, trigger, and approve actions.</td><td>Execution Firewall + Policy Decision Engine.</td></tr>
                <tr><td>AI may influence access or privileged workflows.</td><td>Cyber-impacting actions route to cybersecurity and CyberArk owners.</td><td>MyAccess / CyberArk Routing.</td></tr>
                <tr><td>AI may influence regulated or QA decisions.</td><td>GxP-impacting actions are human-governed and QA / validation reviewed.</td><td>GxP Impact Router + QA Review.</td></tr>
                <tr><td>AI evidence may be incomplete.</td><td>Tool-call evidence, input, output, reviewer, and outcome are captured.</td><td>Evidence Ledger + Evidence Lineage Engine.</td></tr>
                <tr><td>AI behavior may drift after deployment.</td><td>Continuous monitoring and dependency drift watch reduce stale trust risk.</td><td>Continuous Monitoring Center + AgentBOM.</td></tr>
                <tr><td>Leadership may be challenged by audit.</td><td>Decision replay and audit dossier provide defensible reconstruction.</td><td>Audit Dossier + Decision Replay Studio.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Board-Level Statement</h2>
        <div class="answer">
            <strong>AgentTrust™ makes AI agent reliance defensible.</strong>
            It converts AI agent governance from policy language into an operational trust system:
            register, passport, authority, evidence, human oversight, runtime control, monitoring, replay, and assurance case.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Executive Assurance Memo",
        "Executive assurance memo explaining how AgentTrust™ makes AI agent reliance operationally defensible for leadership, audit, cyber, QA, and governance.",
        body
    )


@app.route("/agenttrust/evidence-gap-closure-plan")
@app.route("/agenttrust/gap-closure-plan")
@app.route("/agenttrust/assurance-gap-plan")
def agenttrust_evidence_gap_closure_plan():
    body = """
    <section class="section">
        <h2>AgentTrust™ Evidence Gap Closure Plan</h2>
        <p>
            This plan converts weak assurance areas into specific remediation actions.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Gap</th>
                    <th>Risk Created</th>
                    <th>Required Remediation</th>
                    <th>Owner</th>
                    <th>Target Evidence</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent owner missing.</td><td>No accountability.</td><td>Assign business and technical owner.</td><td>Governance Owner.</td><td>Updated Agent Register.</td></tr>
                <tr><td>Boundary unclear.</td><td>Agent may act outside approved scope.</td><td>Define systems, tools, APIs, data, workflows.</td><td>Lifecycle Owner.</td><td>AgentBOM and Passport.</td></tr>
                <tr><td>Authority not documented.</td><td>Unauthorized execution.</td><td>Define allowed, gated, restricted, prohibited actions.</td><td>Process Owner.</td><td>Authority Matrix.</td></tr>
                <tr><td>Tool-call evidence missing.</td><td>Audit replay weakness.</td><td>Enable tool-call evidence capture.</td><td>Platform Owner.</td><td>Evidence Ledger.</td></tr>
                <tr><td>Human review missing.</td><td>Hidden AI decision-making.</td><td>Route to reviewer and capture decision.</td><td>Human Reviewer.</td><td>Approval Evidence Vault.</td></tr>
                <tr><td>Cyber impact not reviewed.</td><td>Access or privileged workflow risk.</td><td>Route to CyberArk / cybersecurity owner.</td><td>Cybersecurity Owner.</td><td>Cyber Review Record.</td></tr>
                <tr><td>GxP impact not reviewed.</td><td>Regulated or QA defensibility risk.</td><td>Route to QA / validation owner.</td><td>QA / Validation Owner.</td><td>GxP Review Record.</td></tr>
                <tr><td>Replay package incomplete.</td><td>Leadership cannot defend action.</td><td>Build action timeline and evidence lineage.</td><td>Audit Owner.</td><td>Decision Replay Package.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Gap Closure Rule</h2>
        <div class="answer">
            A trust gap should never remain as a vague issue. AgentTrust™ converts every gap into owner, remediation,
            evidence, and closure condition.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Evidence Gap Closure Plan",
        "Gap closure plan for AI agent ownership, boundary, authority, evidence, human review, cyber impact, GxP impact, and replay package weaknesses.",
        body
    )


@app.route("/agenttrust/assurance-case-json")
@app.route("/agenttrust/audit-dossier-json")
@app.route("/agenttrust/assurance-dossier-json")
def agenttrust_assurance_case_json():
    from flask import jsonify

    return jsonify({
        "module": "AgentTrust™",
        "capability": "Assurance Case Builder + Audit Dossier Generator",
        "primary_question": "Can leadership defend why this AI agent was trusted, human-gated, restricted, escalated, blocked, or quarantined?",
        "assurance_claims": AGENTTRUST_ASSURANCE_CLAIMS,
        "audit_dossier": AGENTTRUST_DOSSIER_ITEMS,
        "assurance_case_logic": [
            "Claim is defined",
            "Evidence is linked",
            "Control is identified",
            "Owner is assigned",
            "Decision is recorded",
            "Replay package is available",
            "Gaps are converted into closure actions"
        ],
        "default_decision": "No operational trust decision is complete until claims, evidence, controls, owners, and replay package are available"
    })

# ============================================================
# END AGENTTRUST_ASSURANCE_CASE_BUILDER_V1_ACTIVE
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

print("AgentTrust Assurance Case Builder installed.")
print(f"Inserted before: {target_found}")
