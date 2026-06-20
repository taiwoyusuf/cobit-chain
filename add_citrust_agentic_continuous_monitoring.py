from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_AGENTIC_CONTINUOUS_MONITORING_DRIFT_SENTINEL_V1_ACTIVE"

if MARKER in text:
    print("CITrust Agentic Continuous Monitoring already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base shell not found. Install AgentTrust base module first.")

nav_old = '<a href="/citrust/agentic-control-effectiveness-testing" class="secondary">Control Testing</a>'
nav_new = '''<a href="/citrust/agentic-control-effectiveness-testing" class="secondary">Control Testing</a>
                    <a href="/citrust/agentic-continuous-monitoring-center" class="secondary">Monitoring</a>
                    <a href="/citrust/agentic-drift-signal-register" class="dark">Drift Signals</a>
                    <a href="/citrust/agentic-threshold-alert-catalog" class="dark">Thresholds</a>
                    <a href="/citrust/agentic-monitoring-simulator" class="dark">Monitoring Sim</a>'''

if nav_old in text and "/citrust/agentic-continuous-monitoring-center" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# CITRUST_AGENTIC_CONTINUOUS_MONITORING_DRIFT_SENTINEL_V1_ACTIVE
# CITrust™ Agentic Continuous Monitoring Center + Drift Sentinel
# Control Health Dashboard, Runtime KPI Scorecard,
# Drift Signal Register, Threshold Alert Catalog,
# Exception Aging Monitor, Monitoring Escalation Router,
# Monitoring Simulator, and JSON Export
# ============================================================

CITRUST_AGENTIC_MONITORING_DOMAINS = [
    {
        "domain": "Agent Inventory Health",
        "monitoring_question": "Are all AI agents still registered, owned, approved, and operating inside their approved scope?",
        "signal": "New agent, unknown agent, inactive owner, expired operating license, scope expansion.",
        "owner": "AI Agent Owner / Governance Owner",
        "alert_response": "Block unknown agent and require registration or recertification."
    },
    {
        "domain": "CI Trust Health",
        "monitoring_question": "Are CIs touched by AI still owner-complete, support-complete, LCM-assigned, relationship-valid, and non-orphaned?",
        "signal": "Owner removed, support group missing, LCM missing, orphan status, weak relationship confidence.",
        "owner": "CMDB / LCM Owner",
        "alert_response": "Restrict AI reliance and open CI remediation task."
    },
    {
        "domain": "GxP / Validation Health",
        "monitoring_question": "Has any AI workflow touched GMP, validation, QA, release, deviation, CAPA, or inspection-sensitive context?",
        "signal": "GxP flag changed, validation status changed, QA evidence missing, regulated output generated.",
        "owner": "QA / Validation Owner",
        "alert_response": "Route to QA and prevent regulated reliance until reviewed."
    },
    {
        "domain": "Cyber / Access Health",
        "monitoring_question": "Has any AI workflow touched MyAccess, CyberArk, PSM, privileged, admin, entitlement, or access route?",
        "signal": "Access route change, privileged signal, new entitlement, CyberArk / PSM context, admin workflow.",
        "owner": "Cybersecurity / Access Owner",
        "alert_response": "Cyber-gated review and no autonomous approval."
    },
    {
        "domain": "Prompt Chain Health",
        "monitoring_question": "Are prompt chains captured for AI outputs that influence CI, GxP, cyber, access, or change decisions?",
        "signal": "Final output without chain, missing intermediate step, missing evaluator score, missing reviewer decision.",
        "owner": "AI Agent Owner / Governance Owner",
        "alert_response": "Restrict reliance until prompt chain evidence is restored."
    },
    {
        "domain": "Memory / Context Health",
        "monitoring_question": "Is the agent using current, source-traceable, approved, bounded, and correctable context?",
        "signal": "Stale owner, stale support group, stale validation status, stale access route, outdated relationship.",
        "owner": "Data Owner / AI Agent Owner",
        "alert_response": "Suppress stale memory and refresh from approved source."
    },
    {
        "domain": "Observability Health",
        "monitoring_question": "Can runtime, ServiceNow, Azure, CyberArk, CMDB, QA, change, and human review evidence be correlated?",
        "signal": "Missing correlation ID, missing telemetry, missing tool-call evidence, missing ServiceNow log.",
        "owner": "Observability / Governance Owner",
        "alert_response": "Do not close as audit-defensible until evidence is correlated."
    },
    {
        "domain": "Change Integration Health",
        "monitoring_question": "Are material AI-assisted actions routed to task, change, access, QA, deviation, exception, rollback, and post-check where required?",
        "signal": "Material CI action without change, missing rollback, missing post-check, missing closure dossier.",
        "owner": "Change Owner / System Owner",
        "alert_response": "Create change/task route and block closure until evidence is complete."
    },
    {
        "domain": "Exception Aging Health",
        "monitoring_question": "Are agentic exceptions time-bound, owned, remediated, retested, and closed?",
        "signal": "Expired exception, owner missing, remediation overdue, repeated extension, no retest.",
        "owner": "Governance / Risk Owner",
        "alert_response": "Escalate overdue exception and restrict AI workflow."
    }
]


CITRUST_AGENTIC_DRIFT_SIGNALS = [
    {
        "signal_id": "DRF-001",
        "drift_signal": "New AI agent appears in logs but not in registry",
        "risk": "Unknown AI actor influencing ServiceNow or CMDB workflow.",
        "severity": "Critical",
        "required_action": "Block and register agent before further use."
    },
    {
        "signal_id": "DRF-002",
        "drift_signal": "Agent begins touching new CI class or new workflow type",
        "risk": "Agent scope expanded without governance review.",
        "severity": "High",
        "required_action": "Run operating license and impact map review."
    },
    {
        "signal_id": "DRF-003",
        "drift_signal": "CI owner, support group, LCM, or CMDB contact becomes blank",
        "risk": "AI may rely on ownerless or unsupported CI.",
        "severity": "Critical",
        "required_action": "Open CI remediation and restrict AI reliance."
    },
    {
        "signal_id": "DRF-004",
        "drift_signal": "GxP or validation metadata changes after AI context retrieval",
        "risk": "AI output may rely on outdated regulated state.",
        "severity": "Critical",
        "required_action": "Refresh context and route to QA."
    },
    {
        "signal_id": "DRF-005",
        "drift_signal": "Access route, MyAccess group, CyberArk, or PSM requirement changes",
        "risk": "AI may recommend stale or unsafe access path.",
        "severity": "Critical",
        "required_action": "Suppress access memory and route to cyber owner."
    },
    {
        "signal_id": "DRF-006",
        "drift_signal": "Prompt chain capture rate drops",
        "risk": "AI reasoning becomes unreplayable.",
        "severity": "High",
        "required_action": "Restrict reliance and restore prompt chain logging."
    },
    {
        "signal_id": "DRF-007",
        "drift_signal": "Telemetry correlation breaks",
        "risk": "Audit replay cannot prove what happened.",
        "severity": "High",
        "required_action": "Fix correlation ID and evidence linkage."
    },
    {
        "signal_id": "DRF-008",
        "drift_signal": "Repeated AI recommendation rejected by human owner",
        "risk": "Agent accuracy, context, or policy alignment may be degrading.",
        "severity": "Medium",
        "required_action": "Run evaluator review and memory/context correction."
    },
    {
        "signal_id": "DRF-009",
        "drift_signal": "Exception remains open beyond expiry",
        "risk": "Temporary risk acceptance becomes permanent control weakness.",
        "severity": "High",
        "required_action": "Escalate to risk owner and restrict workflow."
    },
    {
        "signal_id": "DRF-010",
        "drift_signal": "Material AI action closes without rollback or post-check",
        "risk": "Operational state may be changed without recovery or verification.",
        "severity": "Critical",
        "required_action": "Reopen closure, require rollback/post-check evidence."
    }
]


CITRUST_AGENTIC_THRESHOLD_ALERTS = [
    {
        "threshold": "Agent registration coverage below 100%",
        "alert_level": "Critical",
        "meaning": "One or more agents are operating without registration.",
        "owner": "Governance Owner",
        "response": "Block unknown agent operation."
    },
    {
        "threshold": "CI ownership completeness below 95%",
        "alert_level": "High",
        "meaning": "AI may rely on CIs without owner/support/LCM completeness.",
        "owner": "CMDB / LCM Owner",
        "response": "Open remediation and restrict AI reliance for affected CIs."
    },
    {
        "threshold": "GxP route coverage below 100% for regulated outputs",
        "alert_level": "Critical",
        "meaning": "Regulated AI output may not have QA review.",
        "owner": "QA / Validation Owner",
        "response": "Block regulated reliance until QA route is complete."
    },
    {
        "threshold": "Cyber route coverage below 100% for access-impacting outputs",
        "alert_level": "Critical",
        "meaning": "Access, CyberArk, PSM, or privileged context may bypass cyber review.",
        "owner": "Cybersecurity / Access Owner",
        "response": "Block access reliance until cyber route is complete."
    },
    {
        "threshold": "Prompt chain capture below 98%",
        "alert_level": "High",
        "meaning": "AI reasoning is not consistently replayable.",
        "owner": "AI Agent Owner",
        "response": "Investigate logging gap and restrict high-risk reliance."
    },
    {
        "threshold": "Telemetry correlation below 98%",
        "alert_level": "High",
        "meaning": "Evidence fabric may not support audit replay.",
        "owner": "Observability Owner",
        "response": "Repair correlation and evidence linkage."
    },
    {
        "threshold": "Open critical findings older than 7 days",
        "alert_level": "Critical",
        "meaning": "High-risk agentic control failure remains unresolved.",
        "owner": "Governance / Risk Owner",
        "response": "Escalate to executive owner and restrict workflow."
    },
    {
        "threshold": "Expired exceptions above 0",
        "alert_level": "High",
        "meaning": "Temporary exception has become uncontrolled.",
        "owner": "Risk Owner",
        "response": "Close, extend with approval, or block workflow."
    }
]


CITRUST_AGENTIC_RUNTIME_KPIS = [
    {
        "kpi": "Agent Registration Coverage",
        "target": "100%",
        "calculation": "Registered agents divided by observed agents in runtime logs.",
        "owner": "Governance Owner"
    },
    {
        "kpi": "Agent-to-CI Mapping Coverage",
        "target": "100% for high-risk actions",
        "calculation": "AI actions with CI impact map divided by AI actions touching CI context.",
        "owner": "CMDB / CI Owner"
    },
    {
        "kpi": "Prompt Chain Capture Rate",
        "target": ">= 98%",
        "calculation": "AI outputs with prompt chain evidence divided by total AI outputs in scope.",
        "owner": "AI Agent Owner"
    },
    {
        "kpi": "GxP Route Coverage",
        "target": "100%",
        "calculation": "Regulated AI outputs with QA route divided by regulated AI outputs.",
        "owner": "QA / Validation Owner"
    },
    {
        "kpi": "Cyber Route Coverage",
        "target": "100%",
        "calculation": "Access-impacting AI outputs with cyber route divided by access-impacting AI outputs.",
        "owner": "Cybersecurity / Access Owner"
    },
    {
        "kpi": "Telemetry Correlation Rate",
        "target": ">= 98%",
        "calculation": "AI actions with unified correlation ID divided by AI actions in scope.",
        "owner": "Observability Owner"
    },
    {
        "kpi": "Change Integration Coverage",
        "target": "100% for material CI actions",
        "calculation": "Material AI actions with task/change/rollback/post-check divided by material AI actions.",
        "owner": "Change Owner"
    },
    {
        "kpi": "Exception Aging Compliance",
        "target": "0 expired exceptions",
        "calculation": "Expired open exceptions count.",
        "owner": "Governance / Risk Owner"
    }
]


CITRUST_AGENTIC_EXCEPTION_AGING_MONITOR = [
    {
        "aging_bucket": "0-7 days",
        "status": "Active monitoring",
        "required_action": "Owner must confirm remediation path and expiry.",
        "risk_position": "Acceptable if evidence is complete."
    },
    {
        "aging_bucket": "8-14 days",
        "status": "Warning",
        "required_action": "Escalate to governance owner and confirm compensating control.",
        "risk_position": "Restricted AI reliance."
    },
    {
        "aging_bucket": "15-30 days",
        "status": "High risk",
        "required_action": "Risk owner review, executive awareness, remediation deadline.",
        "risk_position": "No high-risk AI action until remediated."
    },
    {
        "aging_bucket": "Over 30 days",
        "status": "Critical",
        "required_action": "Block affected workflow unless formally reapproved.",
        "risk_position": "Not audit-defensible without escalation."
    },
    {
        "aging_bucket": "Expired",
        "status": "Breach",
        "required_action": "Close, extend with approval, or block workflow.",
        "risk_position": "Uncontrolled exception."
    }
]


CITRUST_AGENTIC_MONITORING_ESCALATION = [
    {
        "alert": "Critical drift signal",
        "route_to": "Governance Owner + Domain Owner",
        "response_time": "Same business day",
        "evidence": "Alert record, owner route, containment decision."
    },
    {
        "alert": "GxP alert",
        "route_to": "QA / Validation Owner",
        "response_time": "Before regulated reliance",
        "evidence": "QA decision and validation evidence."
    },
    {
        "alert": "Cyber / access alert",
        "route_to": "Cybersecurity / Access Owner",
        "response_time": "Before access reliance",
        "evidence": "Cyber decision, MyAccess / CyberArk / PSM evidence."
    },
    {
        "alert": "Change-control alert",
        "route_to": "Change Owner / System Owner",
        "response_time": "Before material execution or closure",
        "evidence": "Change/task, rollback, post-check, closure."
    },
    {
        "alert": "Telemetry alert",
        "route_to": "Observability Owner / AI Agent Owner",
        "response_time": "Before audit-defensible closure",
        "evidence": "Correlation ID and runtime evidence."
    },
    {
        "alert": "Expired exception",
        "route_to": "Risk Owner / Executive Owner where material",
        "response_time": "Immediate escalation",
        "evidence": "Exception decision, extension/closure/block."
    }
]


def citrust_monitoring_domain_rows():
    rows = ""
    for item in CITRUST_AGENTIC_MONITORING_DOMAINS:
        rows += f"""
        <tr>
            <td><strong>{item["domain"]}</strong></td>
            <td>{item["monitoring_question"]}</td>
            <td>{item["signal"]}</td>
            <td>{item["owner"]}</td>
            <td><span class="badge orange">{item["alert_response"]}</span></td>
        </tr>
        """
    return rows


def citrust_drift_signal_rows():
    rows = ""
    for item in CITRUST_AGENTIC_DRIFT_SIGNALS:
        badge = "orange"
        if item["severity"] == "Critical":
            badge = "red"
        elif item["severity"] == "High":
            badge = "orange"
        else:
            badge = "yellow"

        rows += f"""
        <tr>
            <td><strong>{item["signal_id"]}</strong></td>
            <td>{item["drift_signal"]}</td>
            <td><span class="badge red">{item["risk"]}</span></td>
            <td><span class="badge {badge}">{item["severity"]}</span></td>
            <td>{item["required_action"]}</td>
        </tr>
        """
    return rows


def citrust_threshold_alert_rows():
    rows = ""
    for item in CITRUST_AGENTIC_THRESHOLD_ALERTS:
        badge = "red" if item["alert_level"] == "Critical" else "orange"
        rows += f"""
        <tr>
            <td><strong>{item["threshold"]}</strong></td>
            <td><span class="badge {badge}">{item["alert_level"]}</span></td>
            <td>{item["meaning"]}</td>
            <td>{item["owner"]}</td>
            <td>{item["response"]}</td>
        </tr>
        """
    return rows


def citrust_runtime_kpi_rows():
    rows = ""
    for item in CITRUST_AGENTIC_RUNTIME_KPIS:
        rows += f"""
        <tr>
            <td><strong>{item["kpi"]}</strong></td>
            <td><span class="badge green">{item["target"]}</span></td>
            <td>{item["calculation"]}</td>
            <td>{item["owner"]}</td>
        </tr>
        """
    return rows


def citrust_exception_aging_rows():
    rows = ""
    for item in CITRUST_AGENTIC_EXCEPTION_AGING_MONITOR:
        badge = "green"
        if item["status"] in ["Critical", "Breach"]:
            badge = "red"
        elif item["status"] in ["High risk", "Warning"]:
            badge = "orange"
        rows += f"""
        <tr>
            <td><strong>{item["aging_bucket"]}</strong></td>
            <td><span class="badge {badge}">{item["status"]}</span></td>
            <td>{item["required_action"]}</td>
            <td>{item["risk_position"]}</td>
        </tr>
        """
    return rows


def citrust_monitoring_escalation_rows():
    rows = ""
    for item in CITRUST_AGENTIC_MONITORING_ESCALATION:
        rows += f"""
        <tr>
            <td><strong>{item["alert"]}</strong></td>
            <td>{item["route_to"]}</td>
            <td><span class="badge yellow">{item["response_time"]}</span></td>
            <td>{item["evidence"]}</td>
        </tr>
        """
    return rows


def citrust_monitoring_decision(registry, ci, gxp, cyber, prompt, memory, telemetry, change, exceptions):
    checks = [registry, ci, gxp, cyber, prompt, memory, telemetry, change, exceptions]
    score = int((sum(1 for item in checks if item == "yes") / len(checks)) * 100)

    if registry != "yes":
        return score, "Block Unknown Agent", "red", "Agent inventory health is not trusted."
    if ci != "yes":
        return score, "Restrict AI Reliance", "red", "CI trust health is degraded."
    if gxp != "yes":
        return score, "QA Escalation Required", "red", "GxP or validation monitoring route is incomplete."
    if cyber != "yes":
        return score, "Cyber Escalation Required", "red", "Access, CyberArk, PSM, or privileged monitoring route is incomplete."
    if telemetry != "yes":
        return score, "Audit Replay Monitoring Gap", "red", "Observability health is not sufficient."
    if change != "yes":
        return score, "Change Monitoring Gap", "orange", "Material AI actions may not be routed to change evidence."
    if prompt != "yes":
        return score, "Prompt Chain Monitoring Gap", "orange", "Prompt chain capture is not continuously monitored."
    if memory != "yes":
        return score, "Memory Drift Monitoring Gap", "orange", "Stale memory or context drift may not be detected."
    if exceptions != "yes":
        return score, "Exception Aging Gap", "orange", "Exception aging and expiry are not controlled."
    if score == 100:
        return score, "Continuous Monitoring Trusted", "green", "Agentic monitoring is active across registry, CI, GxP, cyber, prompt, memory, telemetry, change, and exceptions."
    return score, "Conditional Monitoring", "yellow", "Monitoring has gaps and requires remediation tracking."


try:
    AGENTTRUST_EXPECTED_ROUTES.extend([
        "/citrust/agentic-continuous-monitoring-center",
        "/citrust/agentic-control-health-dashboard",
        "/citrust/agentic-drift-signal-register",
        "/citrust/agentic-threshold-alert-catalog",
        "/citrust/agentic-runtime-kpi-scorecard",
        "/citrust/agentic-exception-aging-monitor",
        "/citrust/agentic-monitoring-escalation-router",
        "/citrust/agentic-monitoring-simulator",
        "/citrust/agentic-monitoring-json"
    ])
except Exception:
    pass


@app.route("/citrust/agentic-continuous-monitoring-center")
@app.route("/citrust/agentic-monitoring-center")
@app.route("/citrust/ci-agentic-continuous-monitoring")
def citrust_agentic_continuous_monitoring_center():
    rows = citrust_monitoring_domain_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Monitoring Center</div><div class="value" style="color:var(--green);">Active</div><div class="note">Post-go-live agentic assurance monitoring installed.</div></div>
        <div class="metric"><div class="label">Monitoring Domains</div><div class="value" style="color:var(--blue);">9</div><div class="note">Registry, CI, GxP, cyber, prompt, memory, observability, change, exceptions.</div></div>
        <div class="metric"><div class="label">Drift Sentinel</div><div class="value" style="color:var(--yellow);">Watching</div><div class="note">Detects scope, CI, memory, access, GxP, telemetry, and change drift.</div></div>
        <div class="metric"><div class="label">Threshold Alerts</div><div class="value" style="color:var(--red);">Defined</div><div class="note">Critical thresholds escalate to owners.</div></div>
        <div class="metric"><div class="label">Exception Aging</div><div class="value" style="color:var(--orange);">Controlled</div><div class="note">Expired exceptions trigger escalation.</div></div>
        <div class="metric"><div class="label">Trust Status</div><div class="value" style="color:var(--purple);">Continuous</div><div class="note">Trust is monitored after launch, not only at release.</div></div>
    </section>

    <section class="section">
        <h2>CITrust™ Agentic Continuous Monitoring Center</h2>
        <div class="answer">
            <strong>Purpose:</strong> continuously monitor whether AI-agent governance remains trusted after go-live.
            CITrust™ watches for drift in agent inventory, CI ownership, GxP metadata, access routes, prompt chain evidence,
            memory provenance, observability, change-control routing, and exception aging.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Monitoring Domain</th>
                    <th>Monitoring Question</th>
                    <th>Signal</th>
                    <th>Owner</th>
                    <th>Alert Response</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Monitoring Rule</h2>
        <div class="answer">
            AI governance cannot be a one-time release checklist. CITrust™ continuously monitors drift, threshold breaches,
            expired exceptions, missing evidence, and degraded trust signals after AI workflows go live.
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Continuous Monitoring Center",
        "Continuous monitoring center for AI agentic ServiceNow / CMDB assurance across registry, CI trust, GxP, cyber, prompt chain, memory, observability, change, and exceptions.",
        body
    )


@app.route("/citrust/agentic-control-health-dashboard")
@app.route("/citrust/agentic-health-dashboard")
@app.route("/citrust/ci-agentic-control-health")
def citrust_agentic_control_health_dashboard():
    rows = citrust_monitoring_domain_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agentic Control Health Dashboard</h2>
        <p>
            The control health dashboard shows which agentic governance domains must remain healthy after deployment.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Domain</th>
                    <th>Question</th>
                    <th>Runtime Signal</th>
                    <th>Owner</th>
                    <th>Response</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Control Health Dashboard",
        "Control health dashboard for agent inventory, CI trust, GxP, cyber, prompt chain, memory, observability, change integration, and exception aging.",
        body
    )


@app.route("/citrust/agentic-drift-signal-register")
@app.route("/citrust/agentic-drift-register")
@app.route("/citrust/ci-agentic-drift-signals")
def citrust_agentic_drift_signal_register():
    rows = citrust_drift_signal_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agentic Drift Signal Register</h2>
        <p>
            Drift signals indicate that an AI agent, CI context, access route, GxP state, memory, telemetry, or change-control state has moved away from approved governance.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Signal ID</th>
                    <th>Drift Signal</th>
                    <th>Risk</th>
                    <th>Severity</th>
                    <th>Required Action</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Drift Signal Register",
        "Drift signal register for unknown agents, scope expansion, ownerless CIs, GxP changes, access route changes, prompt chain gaps, telemetry breaks, rejected outputs, expired exceptions, and missing rollback.",
        body
    )


@app.route("/citrust/agentic-threshold-alert-catalog")
@app.route("/citrust/agentic-alert-thresholds")
@app.route("/citrust/ci-agentic-threshold-alerts")
def citrust_agentic_threshold_alert_catalog():
    rows = citrust_threshold_alert_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agentic Threshold Alert Catalog</h2>
        <p>
            Threshold alerts convert monitoring signals into escalation triggers.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Threshold</th>
                    <th>Alert Level</th>
                    <th>Meaning</th>
                    <th>Owner</th>
                    <th>Response</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Threshold Alert Catalog",
        "Threshold alert catalog for agent registration coverage, CI ownership completeness, GxP route coverage, cyber route coverage, prompt chain capture, telemetry correlation, critical findings, and expired exceptions.",
        body
    )


@app.route("/citrust/agentic-runtime-kpi-scorecard")
@app.route("/citrust/agentic-kpi-scorecard")
@app.route("/citrust/ci-agentic-runtime-kpis")
def citrust_agentic_runtime_kpi_scorecard():
    rows = citrust_runtime_kpi_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agentic Runtime KPI Scorecard</h2>
        <p>
            Runtime KPIs show whether AI-agent governance remains healthy while workflows operate.
        </p>

        <table>
            <thead>
                <tr>
                    <th>KPI</th>
                    <th>Target</th>
                    <th>Calculation</th>
                    <th>Owner</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Runtime KPI Scorecard",
        "Runtime KPI scorecard for agent registration, agent-to-CI mapping, prompt chain capture, GxP route, cyber route, telemetry correlation, change integration, and exception aging.",
        body
    )


@app.route("/citrust/agentic-exception-aging-monitor")
@app.route("/citrust/agentic-exception-aging")
@app.route("/citrust/ci-agentic-exception-aging")
def citrust_agentic_exception_aging_monitor():
    rows = citrust_exception_aging_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agentic Exception Aging Monitor</h2>
        <p>
            Exception aging ensures temporary AI governance gaps do not become permanent control weaknesses.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Aging Bucket</th>
                    <th>Status</th>
                    <th>Required Action</th>
                    <th>Risk Position</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Exception Aging Monitor",
        "Exception aging monitor for agentic governance exceptions across active monitoring, warning, high risk, critical, and breach states.",
        body
    )


@app.route("/citrust/agentic-monitoring-escalation-router")
@app.route("/citrust/agentic-monitoring-escalation")
@app.route("/citrust/ci-agentic-monitoring-escalation")
def citrust_agentic_monitoring_escalation_router():
    rows = citrust_monitoring_escalation_rows()

    body = f"""
    <section class="section">
        <h2>CITrust™ Agentic Monitoring Escalation Router</h2>
        <p>
            Monitoring alerts route to the accountable domain owner before unsafe AI reliance continues.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Alert</th>
                    <th>Route To</th>
                    <th>Response Time</th>
                    <th>Evidence</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Monitoring Escalation Router",
        "Monitoring escalation router for critical drift, GxP alerts, cyber alerts, change-control alerts, telemetry alerts, and expired exceptions.",
        body
    )


@app.route("/citrust/agentic-monitoring-simulator", methods=["GET", "POST"])
@app.route("/citrust/agentic-continuous-monitoring-simulator", methods=["GET", "POST"])
@app.route("/citrust/ci-agentic-monitoring-simulator", methods=["GET", "POST"])
def citrust_agentic_monitoring_simulator():
    from flask import request

    registry = request.form.get("registry", "yes")
    ci = request.form.get("ci", "yes")
    gxp = request.form.get("gxp", "yes")
    cyber = request.form.get("cyber", "yes")
    prompt = request.form.get("prompt", "yes")
    memory = request.form.get("memory", "yes")
    telemetry = request.form.get("telemetry", "yes")
    change = request.form.get("change", "yes")
    exceptions = request.form.get("exceptions", "yes")

    score, decision, badge, reason = citrust_monitoring_decision(
        registry, ci, gxp, cyber, prompt, memory, telemetry, change, exceptions
    )

    def selected(value, expected):
        return "selected" if value == expected else ""

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Monitoring Trust Score</div><div class="value" style="color:var(--green);">{score}%</div><div class="note">Calculated from continuous monitoring domains.</div></div>
        <div class="metric"><div class="label">Monitoring Decision</div><div class="value" style="color:var(--yellow);">{decision}</div><div class="note">{reason}</div></div>
    </section>

    <section class="section">
        <h2>CITrust™ Agentic Monitoring Simulator</h2>
        <p>
            Simulate whether post-go-live monitoring is strong enough to maintain AI-agent trust across ServiceNow / CMDB / GxP / cyber / change workflows.
        </p>

        <form method="POST" action="/citrust/agentic-monitoring-simulator">
            <table>
                <tbody>
                    <tr><td><strong>Agent Inventory Monitoring Healthy?</strong></td><td><select name="registry" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(registry, "yes")}>Yes</option><option value="no" {selected(registry, "no")}>No</option></select></td></tr>
                    <tr><td><strong>CI Trust Monitoring Healthy?</strong></td><td><select name="ci" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(ci, "yes")}>Yes</option><option value="no" {selected(ci, "no")}>No</option></select></td></tr>
                    <tr><td><strong>GxP / Validation Monitoring Healthy?</strong></td><td><select name="gxp" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(gxp, "yes")}>Yes</option><option value="no" {selected(gxp, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Cyber / Access Monitoring Healthy?</strong></td><td><select name="cyber" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(cyber, "yes")}>Yes</option><option value="no" {selected(cyber, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Prompt Chain Monitoring Healthy?</strong></td><td><select name="prompt" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(prompt, "yes")}>Yes</option><option value="no" {selected(prompt, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Memory / Context Drift Monitoring Healthy?</strong></td><td><select name="memory" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(memory, "yes")}>Yes</option><option value="no" {selected(memory, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Telemetry / Observability Monitoring Healthy?</strong></td><td><select name="telemetry" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(telemetry, "yes")}>Yes</option><option value="no" {selected(telemetry, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Change Integration Monitoring Healthy?</strong></td><td><select name="change" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(change, "yes")}>Yes</option><option value="no" {selected(change, "no")}>No</option></select></td></tr>
                    <tr><td><strong>Exception Aging Monitoring Healthy?</strong></td><td><select name="exceptions" style="width:100%;padding:10px;border-radius:10px;border:1px solid #334155;background:#020617;color:#e5e7eb;"><option value="yes" {selected(exceptions, "yes")}>Yes</option><option value="no" {selected(exceptions, "no")}>No</option></select></td></tr>
                </tbody>
            </table>

            <button type="submit" style="margin-top:16px;padding:12px 18px;border-radius:12px;border:0;background:#2563eb;color:white;font-weight:800;">Run Monitoring Trust Check</button>
        </form>
    </section>

    <section class="section">
        <h2>Continuous Monitoring Decision</h2>
        <div class="answer">
            <strong>Score:</strong> {score}%<br>
            <strong>Decision:</strong> <span class="badge {badge}">{decision}</span><br>
            <strong>Reason:</strong> {reason}
        </div>
    </section>
    """

    return agenttrust_shell(
        "CITrust™ Agentic Monitoring Simulator",
        "Simulator for continuous monitoring readiness across agent inventory, CI trust, GxP, cyber, prompt chain, memory, telemetry, change integration, and exception aging.",
        body
    )


@app.route("/citrust/agentic-monitoring-json")
@app.route("/citrust/agentic-continuous-monitoring-json")
@app.route("/citrust/ci-agentic-monitoring-json")
def citrust_agentic_monitoring_json():
    from flask import jsonify

    return jsonify({
        "module": "CITrust™",
        "capability": "Agentic Continuous Monitoring Center + Drift Sentinel",
        "primary_question": "Does CITrust™ continuously monitor whether AI-agent governance remains trusted after go-live?",
        "monitoring_domains": CITRUST_AGENTIC_MONITORING_DOMAINS,
        "drift_signals": CITRUST_AGENTIC_DRIFT_SIGNALS,
        "threshold_alerts": CITRUST_AGENTIC_THRESHOLD_ALERTS,
        "runtime_kpis": CITRUST_AGENTIC_RUNTIME_KPIS,
        "exception_aging_monitor": CITRUST_AGENTIC_EXCEPTION_AGING_MONITOR,
        "monitoring_escalation": CITRUST_AGENTIC_MONITORING_ESCALATION,
        "minimum_conditions": [
            "Agent inventory monitoring is active",
            "CI trust monitoring is active",
            "GxP / validation monitoring is active",
            "Cyber / access monitoring is active",
            "Prompt chain monitoring is active",
            "Memory / context drift monitoring is active",
            "Observability / telemetry monitoring is active",
            "Change integration monitoring is active",
            "Exception aging monitoring is active",
            "Threshold alerts route to accountable owners"
        ],
        "default_decision": "Do not treat agentic governance as continuously trusted unless monitoring, drift detection, threshold alerts, exception aging, escalation, and remediation routes are active"
    })

# ============================================================
# END CITRUST_AGENTIC_CONTINUOUS_MONITORING_DRIFT_SENTINEL_V1_ACTIVE
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

print("CITrust Agentic Continuous Monitoring Center installed.")
print(f"Inserted before: {target_found}")
