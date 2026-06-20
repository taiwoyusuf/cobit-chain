from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_CONTINUOUS_MONITORING_CENTER_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust Continuous Monitoring Center already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base module not found. Install AgentTrust module first.")

nav_old = '<a href="/agenttrust/red-team-lab" class="secondary">Red-Team Lab</a>'
nav_new = '''<a href="/agenttrust/red-team-lab" class="secondary">Red-Team Lab</a>
                    <a href="/agenttrust/continuous-monitoring-center" class="secondary">Monitoring</a>
                    <a href="/agenttrust/drift-alert-console" class="dark">Drift Alerts</a>
                    <a href="/agenttrust/trust-degradation-watch" class="dark">Trust Watch</a>
                    <a href="/agenttrust/control-cadence-calendar" class="dark">Cadence</a>'''

if nav_old in text and "/agenttrust/continuous-monitoring-center" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# AGENTTRUST_CONTINUOUS_MONITORING_CENTER_V1_ACTIVE
# AgentTrust™ Continuous Monitoring Center, Runtime Alert Queue,
# Drift Alert Console, Trust Degradation Watch, Exception Breach Console,
# Monitoring Event Register, Control Cadence Calendar,
# and Continuous Assurance JSON Export
# ============================================================

AGENTTRUST_MONITORING_EVENTS = [
    {
        "event_id": "AT-MON-001",
        "agent": "ServiceNow CI Triage Agent™",
        "signal": "Ownership recommendation generated without final reviewer decision.",
        "category": "Human Oversight",
        "severity": "Medium",
        "status": "Human Review Pending",
        "required_action": "Route to LCM / CMDB owner and capture reviewer decision."
    },
    {
        "event_id": "AT-MON-002",
        "agent": "MyAccess / CyberArk Routing Agent™",
        "signal": "Privileged-access route detected in agent recommendation.",
        "category": "Cybersecurity",
        "severity": "Critical",
        "status": "Escalated",
        "required_action": "Route to Cybersecurity / CyberArk owner before reliance."
    },
    {
        "event_id": "AT-MON-003",
        "agent": "GxP Inspection Evidence Agent™",
        "signal": "Validation evidence source used in generated summary.",
        "category": "GxP / QA",
        "severity": "Critical",
        "status": "QA Review Required",
        "required_action": "Route to QA / validation owner before regulated use."
    },
    {
        "event_id": "AT-MON-004",
        "agent": "Cutover Readiness Summary Agent™",
        "signal": "Rollback evidence missing from readiness summary.",
        "category": "Cutover / Transition",
        "severity": "High",
        "status": "Restricted",
        "required_action": "Block go-live reliance until rollback owner and recovery path are evidenced."
    },
    {
        "event_id": "AT-MON-005",
        "agent": "Multi-Agent Orchestration Chain",
        "signal": "Agent-to-agent handoff occurred without complete handoff context.",
        "category": "Multi-Agent",
        "severity": "High",
        "status": "Evidence Gap",
        "required_action": "Create composite evidence bundle and validate receiving-agent authority."
    },
    {
        "event_id": "AT-MON-006",
        "agent": "ServiceNow CMDB Ownership Recommendation Agent™",
        "signal": "Prompt instruction changed after last approved passport review.",
        "category": "Drift",
        "severity": "High",
        "status": "Change Gate Required",
        "required_action": "Run prompt change gate and recalculate trust score."
    },
    {
        "event_id": "AT-MON-007",
        "agent": "Evidence Packaging Agent™",
        "signal": "Evidence package contains post-created evidence only.",
        "category": "Evidence Integrity",
        "severity": "Medium",
        "status": "Weak Replay",
        "required_action": "Mark as reconstructed evidence and restrict operational reliance."
    }
]


AGENTTRUST_CONTROL_CADENCE = [
    {
        "control": "Agent Inventory Review",
        "owner": "Governance Owner",
        "cadence": "Monthly",
        "purpose": "Confirm all AI agents are registered, owned, and lifecycle-classified.",
        "evidence": "Updated Agent Register and owner confirmation."
    },
    {
        "control": "Authority Review",
        "owner": "Process Owner / Risk Owner",
        "cadence": "Monthly for execution agents; quarterly for advisory agents",
        "purpose": "Confirm permitted, human-gated, restricted, and prohibited actions.",
        "evidence": "Updated authority matrix and approval record."
    },
    {
        "control": "Evidence Sufficiency Review",
        "owner": "Audit / Platform Owner",
        "cadence": "Monthly",
        "purpose": "Confirm input, tool-call, output, human, outcome, and replay evidence.",
        "evidence": "Evidence sufficiency dashboard and sample replay package."
    },
    {
        "control": "Cyber / Access Impact Review",
        "owner": "Cybersecurity / CyberArk Owner",
        "cadence": "Before privileged use and quarterly thereafter",
        "purpose": "Confirm access, MyAccess, CyberArk, PSM, and entitlement impacts.",
        "evidence": "Cyber review record and access routing confirmation."
    },
    {
        "control": "GxP / QA Impact Review",
        "owner": "QA / Validation Owner",
        "cadence": "Before regulated reliance and after material change",
        "purpose": "Confirm GMP, QA, validation, QC, release, deviation, and inspection impact.",
        "evidence": "QA / validation impact review and decision record."
    },
    {
        "control": "AgentBOM Dependency Review",
        "owner": "Agent Lifecycle Owner",
        "cadence": "Monthly or after dependency change",
        "purpose": "Confirm model, prompt, tool, API, data, workflow, owner, and evidence dependencies.",
        "evidence": "Updated AgentBOM and dependency drift log."
    },
    {
        "control": "Red-Team Resilience Review",
        "owner": "Risk / Security Owner",
        "cadence": "Quarterly or before high-risk deployment",
        "purpose": "Test prompt injection, authority bypass, tool abuse, evidence tampering, and hidden approval.",
        "evidence": "Red-team scorecard and failure mode remediation log."
    },
    {
        "control": "Exception Expiry Review",
        "owner": "Risk Acceptance Owner",
        "cadence": "Weekly for critical exceptions; monthly for standard exceptions",
        "purpose": "Ensure accepted risks and exceptions are still owned, conditional, and valid.",
        "evidence": "Risk acceptance register and expiry watch report."
    }
]


def agenttrust_monitoring_event_rows():
    rows = ""

    for item in AGENTTRUST_MONITORING_EVENTS:
        badge = "blue"
        if item["severity"] == "Critical":
            badge = "red"
        elif item["severity"] == "High":
            badge = "orange"
        elif item["severity"] == "Medium":
            badge = "yellow"

        rows += f"""
        <tr>
            <td><strong>{item["event_id"]}</strong></td>
            <td>{item["agent"]}</td>
            <td>{item["signal"]}</td>
            <td><span class="badge blue">{item["category"]}</span></td>
            <td><span class="badge {badge}">{item["severity"]}</span></td>
            <td>{item["status"]}</td>
            <td>{item["required_action"]}</td>
        </tr>
        """

    return rows


def agenttrust_control_cadence_rows():
    rows = ""

    for item in AGENTTRUST_CONTROL_CADENCE:
        rows += f"""
        <tr>
            <td><strong>{item["control"]}</strong></td>
            <td>{item["owner"]}</td>
            <td><span class="badge green">{item["cadence"]}</span></td>
            <td>{item["purpose"]}</td>
            <td>{item["evidence"]}</td>
        </tr>
        """

    return rows


try:
    AGENTTRUST_EXPECTED_ROUTES.extend([
        "/agenttrust/continuous-monitoring-center",
        "/agenttrust/runtime-alert-queue",
        "/agenttrust/drift-alert-console",
        "/agenttrust/trust-degradation-watch",
        "/agenttrust/exception-breach-console",
        "/agenttrust/monitoring-event-register",
        "/agenttrust/control-cadence-calendar",
        "/agenttrust/continuous-assurance-json"
    ])
except Exception:
    pass


@app.route("/agenttrust/continuous-monitoring-center")
@app.route("/agenttrust/agent-monitoring-center")
@app.route("/agenttrust/continuous-assurance-monitor")
def agenttrust_continuous_monitoring_center():
    rows = agenttrust_monitoring_event_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Monitoring Status</div><div class="value" style="color:var(--green);">Active</div><div class="note">Continuous assurance events are being tracked.</div></div>
        <div class="metric"><div class="label">Critical Alerts</div><div class="value" style="color:var(--red);">2</div><div class="note">Cyber and GxP review required.</div></div>
        <div class="metric"><div class="label">High Alerts</div><div class="value" style="color:var(--orange);">3</div><div class="note">Rollback, handoff, and prompt drift issues.</div></div>
        <div class="metric"><div class="label">Evidence Gaps</div><div class="value" style="color:var(--yellow);">2</div><div class="note">Human decision or replay evidence incomplete.</div></div>
        <div class="metric"><div class="label">Trust Watch</div><div class="value" style="color:var(--purple);">Running</div><div class="note">Trust degradation conditions are mapped.</div></div>
        <div class="metric"><div class="label">Cadence</div><div class="value" style="color:var(--blue);">Defined</div><div class="note">Reviews and owners are assigned.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Continuous Monitoring Center</h2>
        <div class="answer">
            <strong>Purpose:</strong> keep AI agent trust current after go-live.
            AgentTrust™ continuously watches for owner gaps, authority drift, evidence gaps, cyber impact,
            GxP impact, rollback gaps, dependency drift, exception expiry, and trust degradation.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Event ID</th>
                    <th>Agent</th>
                    <th>Signal</th>
                    <th>Category</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Required Action</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Continuous Monitoring Rule</h2>
        <div class="answer">
            AgentTrust™ trust is not permanent. Trust must be continuously monitored because owners change,
            prompts change, tools change, access routes change, evidence paths fail, and regulated impact can emerge later.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Continuous Monitoring Center",
        "Continuous assurance monitoring center for AI agent runtime alerts, drift, trust degradation, exception breaches, evidence gaps, cyber escalation, and GxP routing.",
        body
    )


@app.route("/agenttrust/runtime-alert-queue")
@app.route("/agenttrust/agent-alert-queue")
@app.route("/agenttrust/runtime-monitoring-alerts")
def agenttrust_runtime_alert_queue():
    rows = agenttrust_monitoring_event_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Runtime Alert Queue</h2>
        <p>
            The Runtime Alert Queue captures AI agent conditions that require review, escalation, restriction, quarantine, or remediation.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Alert ID</th>
                    <th>Agent</th>
                    <th>Runtime Signal</th>
                    <th>Category</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Required Action</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Alert Queue Rule</h2>
        <div class="answer">
            A runtime alert should always have a severity, owner route, required action, and evidence record.
            Alerts without ownership become unmanaged governance debt.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Runtime Alert Queue",
        "Runtime alert queue for AI agent monitoring signals, severity, owner routing, required action, and remediation.",
        body
    )


@app.route("/agenttrust/drift-alert-console")
@app.route("/agenttrust/agent-drift-alerts")
@app.route("/agenttrust/drift-monitoring-console")
def agenttrust_drift_alert_console():
    body = """
    <section class="section">
        <h2>AgentTrust™ Drift Alert Console</h2>
        <p>
            Drift occurs when an AI agent changes after approval. AgentTrust™ watches for drift across model,
            prompt, tool, data, access, workflow, owner, evidence, and risk conditions.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Drift Type</th>
                    <th>Signal</th>
                    <th>Trust Impact</th>
                    <th>Required Response</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Model Drift</td><td>Model version, endpoint, provider, or configuration changed.</td><td>Output behavior may change.</td><td><span class="badge orange">Run model change gate</span></td></tr>
                <tr><td>Prompt Drift</td><td>System prompt, role instruction, or prohibited action text changed.</td><td>Authority boundary may change silently.</td><td><span class="badge red">Run prompt change gate</span></td></tr>
                <tr><td>Tool Drift</td><td>New API, workflow, trigger, or write capability added.</td><td>Execution capability increased.</td><td><span class="badge red">Run tool authority gate</span></td></tr>
                <tr><td>Data Drift</td><td>Source schema, field meaning, ownership, or quality changed.</td><td>Recommendation reliability decreases.</td><td><span class="badge orange">Run data lineage review</span></td></tr>
                <tr><td>Access Drift</td><td>MyAccess group, CyberArk route, PSM route, or entitlement changed.</td><td>Cyber risk changed.</td><td><span class="badge red">Cyber review required</span></td></tr>
                <tr><td>GxP Drift</td><td>Agent begins touching regulated, QA, validation, or inspection evidence.</td><td>Regulated impact increased.</td><td><span class="badge red">QA / validation review</span></td></tr>
                <tr><td>Owner Drift</td><td>Business, technical, QA, cyber, risk, or lifecycle owner changes.</td><td>Accountability may break.</td><td><span class="badge red">Reconfirm owner</span></td></tr>
                <tr><td>Evidence Drift</td><td>Logging, replay, retention, or vault location changed.</td><td>Audit defensibility decreases.</td><td><span class="badge orange">Run evidence sufficiency review</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Drift Console Rule</h2>
        <div class="answer">
            Any material drift must trigger re-scoring, re-gating, or restriction.
            A previously trusted AI agent can become untrusted after dependency or behavior drift.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Drift Alert Console",
        "Drift alert console for AI agent model, prompt, tool, data, access, GxP, owner, evidence, and risk changes.",
        body
    )


@app.route("/agenttrust/trust-degradation-watch")
@app.route("/agenttrust/trust-degradation")
@app.route("/agenttrust/agent-trust-watch")
def agenttrust_trust_degradation_watch():
    body = """
    <section class="section">
        <h2>AgentTrust™ Trust Degradation Watch</h2>
        <p>
            Trust degradation occurs when an AI agent's operational trust score drops because controls weaken,
            evidence becomes incomplete, ownership becomes unclear, or risk increases.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Degradation Signal</th>
                    <th>Why Trust Drops</th>
                    <th>Trust Impact</th>
                    <th>AgentTrust™ Action</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Owner removed or unclear.</td><td>No accountable human remains visible.</td><td><span class="badge red">Critical drop</span></td><td>Block operational reliance until owner reassigned.</td></tr>
                <tr><td>Authority envelope outdated.</td><td>Agent actions no longer match approved authority.</td><td><span class="badge red">Critical drop</span></td><td>Run authority review and restrict execution.</td></tr>
                <tr><td>Evidence capture failure.</td><td>Action cannot be replayed or defended.</td><td><span class="badge orange">High drop</span></td><td>Restrict to draft / recommendation mode.</td></tr>
                <tr><td>Cyber impact detected.</td><td>Agent touches access or privileged route.</td><td><span class="badge red">Critical escalation</span></td><td>Escalate to cybersecurity owner.</td></tr>
                <tr><td>GxP impact detected.</td><td>Agent touches regulated evidence or quality workflow.</td><td><span class="badge red">Critical escalation</span></td><td>Route to QA / validation owner.</td></tr>
                <tr><td>Rollback path missing.</td><td>High-impact execution cannot be safely recovered.</td><td><span class="badge red">Execution blocked</span></td><td>Block create, update, or trigger action.</td></tr>
                <tr><td>Exception expired.</td><td>Agent relies on stale risk acceptance.</td><td><span class="badge orange">Trust reduced</span></td><td>Renew, revoke, or escalate exception.</td></tr>
                <tr><td>Red-team failure found.</td><td>Prompt injection, tool abuse, or evidence tampering risk detected.</td><td><span class="badge red">Trust reduced</span></td><td>Quarantine or remediate before reliance.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Trust Degradation Rule</h2>
        <div class="answer">
            Trust must go down automatically when controls weaken.
            AgentTrust™ treats degradation as a signal to restrict, human-gate, escalate, quarantine, or revalidate.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Trust Degradation Watch",
        "Trust degradation watch for AI agent owner gaps, authority drift, evidence gaps, cyber impact, GxP impact, rollback gaps, expired exceptions, and red-team failures.",
        body
    )


@app.route("/agenttrust/exception-breach-console")
@app.route("/agenttrust/exception-breach")
@app.route("/agenttrust/expired-exception-console")
def agenttrust_exception_breach_console():
    body = """
    <section class="section">
        <h2>AgentTrust™ Exception Breach Console</h2>
        <p>
            Exception breaches occur when AI agents rely on expired, exceeded, ownerless, or conditionally approved exceptions.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Exception Breach</th>
                    <th>Signal</th>
                    <th>Risk</th>
                    <th>Required Action</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Expired risk acceptance.</td><td>Review date passed with no renewal.</td><td>AI relies on stale acceptance.</td><td><span class="badge red">Revoke or renew</span></td></tr>
                <tr><td>Condition violated.</td><td>Agent acts outside accepted-risk condition.</td><td>Exception no longer valid.</td><td><span class="badge red">Block action</span></td></tr>
                <tr><td>Owner missing.</td><td>Risk acceptance owner changed or left role.</td><td>No accountable human.</td><td><span class="badge red">Reassign owner</span></td></tr>
                <tr><td>Scope exceeded.</td><td>Agent uses exception for a different system, tool, or workflow.</td><td>Approval misuse.</td><td><span class="badge orange">Run scope review</span></td></tr>
                <tr><td>Evidence missing.</td><td>No evidence showing why exception was accepted.</td><td>Weak audit defense.</td><td><span class="badge orange">Rebuild evidence package</span></td></tr>
                <tr><td>Regulated impact emerged.</td><td>Exception now touches GMP, QA, validation, release, or inspection evidence.</td><td>QA risk.</td><td><span class="badge red">QA review required</span></td></tr>
                <tr><td>Cyber impact emerged.</td><td>Exception now touches access, CyberArk, PSM, or privileged route.</td><td>Cyber risk.</td><td><span class="badge red">Cyber review required</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Exception Breach Rule</h2>
        <div class="answer">
            Exceptions must be narrow, owned, evidenced, conditional, and time-bound.
            An expired or exceeded exception should reduce trust immediately.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Exception Breach Console",
        "Exception breach console for expired risk acceptance, violated conditions, owner gaps, exceeded scope, missing evidence, regulated impact, and cyber impact.",
        body
    )


@app.route("/agenttrust/monitoring-event-register")
@app.route("/agenttrust/monitoring-register")
@app.route("/agenttrust/agent-event-register")
def agenttrust_monitoring_event_register():
    rows = agenttrust_monitoring_event_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Monitoring Event Register</h2>
        <p>
            This register records continuous monitoring signals that require review, remediation, escalation, restriction, or evidence capture.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Event ID</th>
                    <th>Agent</th>
                    <th>Signal</th>
                    <th>Category</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Required Action</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Monitoring Register Rule</h2>
        <div class="answer">
            Every meaningful monitoring signal should become a governed event with owner, severity,
            status, required action, and evidence location.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Monitoring Event Register",
        "Monitoring event register for AI agent runtime signals, drift, evidence gaps, cyber escalation, GxP routing, and required actions.",
        body
    )


@app.route("/agenttrust/control-cadence-calendar")
@app.route("/agenttrust/monitoring-cadence")
@app.route("/agenttrust/control-review-calendar")
def agenttrust_control_cadence_calendar():
    rows = agenttrust_control_cadence_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Control Cadence Calendar</h2>
        <p>
            The Control Cadence Calendar defines how often each AgentTrust™ control should be reviewed and what evidence is expected.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Control</th>
                    <th>Owner</th>
                    <th>Cadence</th>
                    <th>Purpose</th>
                    <th>Evidence</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Cadence Rule</h2>
        <div class="answer">
            Continuous assurance requires cadence. Without scheduled review, AI agent trust becomes stale and governance debt grows.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Control Cadence Calendar",
        "Control cadence calendar for AI agent inventory, authority, evidence, cyber impact, GxP impact, AgentBOM dependencies, red-team resilience, and exception expiry.",
        body
    )


@app.route("/agenttrust/continuous-assurance-json")
@app.route("/agenttrust/monitoring-json")
@app.route("/agenttrust/agent-monitoring-json")
def agenttrust_continuous_assurance_json():
    from flask import jsonify

    return jsonify({
        "module": "AgentTrust™",
        "capability": "Continuous Monitoring Center",
        "primary_question": "Is this AI agent still operationally trusted after deployment?",
        "monitoring_events": AGENTTRUST_MONITORING_EVENTS,
        "control_cadence": AGENTTRUST_CONTROL_CADENCE,
        "trust_degradation_triggers": [
            "Owner gap",
            "Authority drift",
            "Evidence capture failure",
            "CyberArk / privileged access impact",
            "GxP / QA / validation impact",
            "Rollback path missing",
            "Exception expiry",
            "Red-team failure",
            "Dependency drift",
            "Audit replay weakness"
        ],
        "default_response": "Restrict, human-gate, escalate, quarantine, or revalidate when trust degradation is detected"
    })

# ============================================================
# END AGENTTRUST_CONTINUOUS_MONITORING_CENTER_V1_ACTIVE
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

print("AgentTrust Continuous Monitoring Center installed.")
print(f"Inserted before: {target_found}")
