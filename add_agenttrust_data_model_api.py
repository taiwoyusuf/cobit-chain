from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_DATA_MODEL_API_EXPORT_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust Data Model API Export layer already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base module not found. Install AgentTrust module first.")

nav_old = '<a href="/agenttrust/intake-wizard" class="secondary">Intake Wizard</a>'
nav_new = '''<a href="/agenttrust/intake-wizard" class="secondary">Intake Wizard</a>
                    <a href="/agenttrust/data-model" class="secondary">Data Model</a>
                    <a href="/agenttrust/export-center" class="dark">Export Center</a>
                    <a href="/agenttrust/api-blueprint" class="dark">API Blueprint</a>
                    <a href="/agenttrust/readiness-report-json" class="dark">JSON Report</a>'''

if nav_old in text and "/agenttrust/data-model" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# AGENTTRUST_DATA_MODEL_API_EXPORT_V1_ACTIVE
# AgentTrust™ Data Model, API Blueprint, Export Center,
# Agent Record Schema, Passport Schema, Evidence Schema,
# Authority Decision Schema, and Readiness Report JSON
# ============================================================

AGENTTRUST_SAMPLE_AGENT_RECORD = {
    "agent_id": "AT-AGT-001",
    "agent_name": "ServiceNow CMDB Ownership Recommendation Agent",
    "agent_type": "Governed AI Agent",
    "business_purpose": "Review CI candidates, orphan CIs, ownership gaps, support group gaps, and lifecycle readiness.",
    "business_owner": "CMDB / Service Governance Owner",
    "technical_owner": "ServiceNow Platform Owner",
    "support_group": "ServiceNow Support Group",
    "lifecycle_owner": "LCM Owner",
    "risk_owner": "Governance Risk Owner",
    "qa_owner_required": False,
    "cyber_owner_required": True,
    "lifecycle_status": "Proposed / Human-Gated",
    "risk_tier": "Tier 2",
    "trust_score": 84,
    "trust_status": "Human-Gated Trusted",
    "connected_systems": [
        "ServiceNow CMDB",
        "CITrust™ Candidate Review",
        "ServiceNow Change",
        "MyAccess metadata where applicable"
    ],
    "permitted_actions": [
        "Read approved CI records",
        "Summarize ownership gaps",
        "Recommend support group or LCM review",
        "Draft CI candidate notes"
    ],
    "prohibited_actions": [
        "Approve CI update",
        "Change CI lifecycle state",
        "Assign LCM without human approval",
        "Delete evidence",
        "Approve access or privileged execution"
    ],
    "evidence_required": [
        "Source CI",
        "Recommendation rationale",
        "Timestamp",
        "Reviewer",
        "Final human decision",
        "Outcome"
    ]
}


AGENTTRUST_SAMPLE_PASSPORT_RECORD = {
    "passport_id": "AT-PASS-001",
    "agent_id": "AT-AGT-001",
    "passport_status": "Draft / Human-Gated",
    "operating_boundary": {
        "approved_systems": ["ServiceNow CMDB", "CITrust™"],
        "approved_data_sources": ["CI records", "ownership metadata", "support group fields"],
        "approved_tools": ["Read-only CMDB query", "Candidate review workflow"],
        "prohibited_zones": ["Production record update", "Access approval", "Privileged execution"]
    },
    "authority_model": {
        "read": "Allowed within approved boundary",
        "summarize": "Allowed with source traceability",
        "recommend": "Allowed with human review",
        "draft": "Allowed with human approval before use",
        "create": "Restricted",
        "update": "Blocked unless human-approved",
        "trigger": "Blocked unless explicitly approved",
        "approve": "Prohibited"
    },
    "runtime_controls": {
        "execution_firewall": True,
        "runtime_sentinel": True,
        "kill_switch": True,
        "trust_quarantine": True,
        "rollback_required": True
    },
    "review_cadence": {
        "ownership_review": "Quarterly",
        "authority_review": "Quarterly",
        "evidence_review": "Monthly for high-risk actions",
        "risk_review": "After material change or incident"
    }
}


AGENTTRUST_SAMPLE_EVIDENCE_RECORD = {
    "evidence_id": "AT-EVD-001",
    "agent_id": "AT-AGT-001",
    "action_id": "AT-ACT-001",
    "timestamp": "2026-06-20T00:00:00Z",
    "action_type": "Recommend CI ownership review",
    "authority_status": "Human-gated recommendation allowed",
    "source_records": [
        "CI candidate record",
        "CMDB ownership field",
        "Support group field",
        "LCM field"
    ],
    "tool_call": {
        "tool_name": "ServiceNow CMDB read query",
        "tool_mode": "Read-only",
        "target_system": "ServiceNow CMDB",
        "result": "Recommendation generated"
    },
    "human_accountability": {
        "reviewer": "LCM / CMDB Owner",
        "approver_required": True,
        "final_approval_status": "Pending human review"
    },
    "outcome": {
        "status": "Draft recommendation only",
        "production_update_executed": False,
        "rollback_required": False,
        "replay_status": "Replayable if reviewer decision is captured"
    }
}


AGENTTRUST_SAMPLE_AUTHORITY_DECISION = {
    "decision_id": "AT-DEC-001",
    "agent_id": "AT-AGT-001",
    "requested_action": "Update CI owner field",
    "authority_result": "Blocked / Human approval required",
    "reason": "Agent may recommend ownership but may not update production CI ownership without LCM approval.",
    "required_owner": "LCM / CMDB Owner",
    "required_evidence": [
        "Source CI",
        "Recommended owner",
        "Rationale",
        "Reviewer approval",
        "Change or update record",
        "Outcome"
    ],
    "final_decision": "Human-gated"
}


def agenttrust_json_pretty(data):
    import json
    return json.dumps(data, indent=2, ensure_ascii=False)


def agenttrust_schema_table_rows(schema):
    rows = ""

    for key, value in schema.items():
        if isinstance(value, dict):
            value_display = "Nested object"
        elif isinstance(value, list):
            value_display = ", ".join([str(v) for v in value])
        else:
            value_display = str(value)

        rows += f"""
        <tr>
            <td><strong>{key}</strong></td>
            <td>{value_display}</td>
        </tr>
        """

    return rows


@app.route("/agenttrust/data-model")
@app.route("/agenttrust/agenttrust-data-model")
@app.route("/agenttrust/data-architecture")
def agenttrust_data_model():
    body = """
    <section class="kpis">
        <div class="metric"><div class="label">Data Model</div><div class="value" style="color:var(--green);">Defined</div><div class="note">Agent, passport, evidence, authority, and readiness records.</div></div>
        <div class="metric"><div class="label">Agent Record</div><div class="value" style="color:var(--blue);">Core</div><div class="note">Identity, ownership, boundary, lifecycle, risk.</div></div>
        <div class="metric"><div class="label">Passport Record</div><div class="value" style="color:var(--yellow);">Control</div><div class="note">Authority, tools, evidence, prohibited actions.</div></div>
        <div class="metric"><div class="label">Evidence Record</div><div class="value" style="color:var(--purple);">Replay</div><div class="note">Tool call, input, output, owner, outcome.</div></div>
        <div class="metric"><div class="label">Decision Record</div><div class="value" style="color:var(--orange);">Authority</div><div class="note">Execute, human-gate, restrict, block, quarantine.</div></div>
        <div class="metric"><div class="label">API Ready</div><div class="value" style="color:var(--red);">Exportable</div><div class="note">Sample JSON endpoints created.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Data Model</h2>
        <div class="answer">
            <strong>Purpose:</strong> define the core records needed to govern AI agents as operational actors.
            AgentTrust™ data is structured around identity, ownership, boundary, authority, evidence, human accountability,
            runtime safety, regulated impact, lifecycle state, and audit replay.
        </div>

        <div class="grid">
            <div class="card"><span class="badge green">Agent</span><h3>Agent Record</h3><p>Captures agent identity, owner, purpose, systems, lifecycle, risk, and trust score.</p><a href="/agenttrust/agent-record-schema">Open Schema</a></div>
            <div class="card"><span class="badge yellow">Passport</span><h3>Risk Passport</h3><p>Defines boundary, authority, tools, data, evidence, prohibited actions, and runtime controls.</p><a href="/agenttrust/passport-schema">Open Schema</a></div>
            <div class="card"><span class="badge purple">Evidence</span><h3>Evidence Record</h3><p>Captures input, tool-call, authority, human review, action outcome, and replay status.</p><a href="/agenttrust/evidence-record-schema">Open Schema</a></div>
            <div class="card"><span class="badge orange">Decision</span><h3>Authority Decision</h3><p>Records why an action was executed, human-gated, restricted, blocked, or quarantined.</p><a href="/agenttrust/authority-decision-schema">Open Schema</a></div>
            <div class="card"><span class="badge blue">API</span><h3>API Blueprint</h3><p>Shows how AgentTrust™ can become an API-backed assurance layer.</p><a href="/agenttrust/api-blueprint">Open Blueprint</a></div>
            <div class="card"><span class="badge red">Export</span><h3>Export Center</h3><p>Provides sample JSON outputs for agent, passport, evidence, decision, and readiness reports.</p><a href="/agenttrust/export-center">Open Exports</a></div>
        </div>
    </section>

    <section class="section">
        <h2>Data Model Rule</h2>
        <div class="answer">
            AgentTrust™ should not depend only on dashboard text. Every AI agent governance decision should be represented
            as structured data that can be searched, scored, exported, replayed, audited, and integrated with enterprise systems.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Data Model",
        "Data architecture for AI agent identity, ownership, passport, authority, evidence, readiness, lifecycle, and audit replay records.",
        body
    )


@app.route("/agenttrust/agent-record-schema")
@app.route("/agenttrust/agent-schema")
def agenttrust_agent_record_schema():
    rows = agenttrust_schema_table_rows(AGENTTRUST_SAMPLE_AGENT_RECORD)
    json_block = agenttrust_json_pretty(AGENTTRUST_SAMPLE_AGENT_RECORD)

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Agent Record Schema</h2>
        <p>
            The Agent Record is the master identity and ownership record for an AI agent.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Field</th>
                    <th>Sample Value</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Sample Agent Record JSON</h2>
        <pre style="white-space:pre-wrap;background:#020617;border:1px solid #1e293b;border-radius:16px;padding:18px;color:#e5e7eb;">{json_block}</pre>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Agent Record Schema",
        "Schema for AI agent identity, ownership, systems, actions, prohibited actions, risk tier, trust score, and evidence requirements.",
        body
    )


@app.route("/agenttrust/passport-schema")
@app.route("/agenttrust/agent-passport-schema")
@app.route("/agenttrust/risk-passport-schema")
def agenttrust_passport_schema():
    json_block = agenttrust_json_pretty(AGENTTRUST_SAMPLE_PASSPORT_RECORD)

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Agent Risk Passport Schema</h2>
        <p>
            The Agent Risk Passport™ defines the governance boundary for the AI agent.
            It answers what the agent is, where it may operate, what it may do, what it must never do,
            what evidence is required, and how it is controlled at runtime.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Passport Domain</th>
                    <th>Governance Meaning</th>
                    <th>Why It Matters</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Passport ID</td><td>Unique passport record.</td><td>Links agent governance to evidence and lifecycle.</td></tr>
                <tr><td>Operating Boundary</td><td>Approved systems, data, tools, and prohibited zones.</td><td>Prevents uncontrolled scope expansion.</td></tr>
                <tr><td>Authority Model</td><td>Read, summarize, recommend, draft, create, update, trigger, approve rules.</td><td>Prevents unauthorized action.</td></tr>
                <tr><td>Runtime Controls</td><td>Firewall, sentinel, kill switch, quarantine, rollback.</td><td>Stops unsafe autonomy.</td></tr>
                <tr><td>Review Cadence</td><td>Ownership, authority, evidence, and risk review periods.</td><td>Keeps trust current over time.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Sample Passport JSON</h2>
        <pre style="white-space:pre-wrap;background:#020617;border:1px solid #1e293b;border-radius:16px;padding:18px;color:#e5e7eb;">{json_block}</pre>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Passport Schema",
        "Schema for AI agent operating boundary, authority model, runtime controls, prohibited zones, and review cadence.",
        body
    )


@app.route("/agenttrust/evidence-record-schema")
@app.route("/agenttrust/tool-call-evidence-schema")
@app.route("/agenttrust/evidence-schema")
def agenttrust_evidence_record_schema():
    json_block = agenttrust_json_pretty(AGENTTRUST_SAMPLE_EVIDENCE_RECORD)

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Evidence Record Schema</h2>
        <p>
            The Evidence Record captures what happened at the time of AI agent action.
            It is the basis for decision replay, audit defense, and incident reconstruction.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Evidence Domain</th>
                    <th>Evidence Captured</th>
                    <th>Audit Question Answered</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent Identity</td><td>Agent ID and action ID.</td><td>Which AI agent acted?</td></tr>
                <tr><td>Authority</td><td>Authority status and action permission.</td><td>Why was the action allowed or blocked?</td></tr>
                <tr><td>Source Records</td><td>Records used by the agent.</td><td>What did the agent rely on?</td></tr>
                <tr><td>Tool Call</td><td>Tool, target system, mode, and result.</td><td>What did the agent touch?</td></tr>
                <tr><td>Human Accountability</td><td>Reviewer, approver requirement, final status.</td><td>Which human remained accountable?</td></tr>
                <tr><td>Outcome</td><td>Status, update execution, rollback, replay status.</td><td>What was the final result?</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Sample Evidence JSON</h2>
        <pre style="white-space:pre-wrap;background:#020617;border:1px solid #1e293b;border-radius:16px;padding:18px;color:#e5e7eb;">{json_block}</pre>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Evidence Record Schema",
        "Schema for AI agent evidence records, including source records, tool call, authority, human accountability, outcome, and replay status.",
        body
    )


@app.route("/agenttrust/authority-decision-schema")
@app.route("/agenttrust/decision-schema")
@app.route("/agenttrust/authority-record-schema")
def agenttrust_authority_decision_schema():
    json_block = agenttrust_json_pretty(AGENTTRUST_SAMPLE_AUTHORITY_DECISION)

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Authority Decision Schema</h2>
        <p>
            The Authority Decision record captures the decision made before an AI agent action is executed,
            human-gated, restricted, blocked, escalated, or quarantined.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Decision Field</th>
                    <th>Governance Meaning</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Decision ID</td><td>Unique decision record for traceability.</td></tr>
                <tr><td>Agent ID</td><td>Links the decision to the acting AI agent.</td></tr>
                <tr><td>Requested Action</td><td>Defines what the agent wanted to do.</td></tr>
                <tr><td>Authority Result</td><td>Execute, human-gate, restrict, block, escalate, quarantine, or retire.</td></tr>
                <tr><td>Reason</td><td>Explains why the decision was made.</td></tr>
                <tr><td>Required Owner</td><td>Identifies who must approve or review.</td></tr>
                <tr><td>Required Evidence</td><td>Defines proof needed for defensibility.</td></tr>
                <tr><td>Final Decision</td><td>Final operational trust outcome.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Sample Authority Decision JSON</h2>
        <pre style="white-space:pre-wrap;background:#020617;border:1px solid #1e293b;border-radius:16px;padding:18px;color:#e5e7eb;">{json_block}</pre>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Authority Decision Schema",
        "Schema for AI agent authority decision records, including requested action, decision result, owner, evidence, and final trust outcome.",
        body
    )


@app.route("/agenttrust/api-blueprint")
@app.route("/agenttrust/api-architecture")
@app.route("/agenttrust/api-model")
def agenttrust_api_blueprint():
    body = """
    <section class="section">
        <h2>AgentTrust™ API Blueprint</h2>
        <p>
            This blueprint shows how AgentTrust™ can evolve from a static demo module into an API-backed governance assurance layer.
        </p>

        <table>
            <thead>
                <tr>
                    <th>API Endpoint Concept</th>
                    <th>Purpose</th>
                    <th>Sample Route</th>
                    <th>Output</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent Record API</td><td>Return the governed AI agent record.</td><td>/agenttrust/sample-agent-json</td><td>Agent identity, owner, risk, systems, actions.</td></tr>
                <tr><td>Passport API</td><td>Return Agent Risk Passport™ structure.</td><td>/agenttrust/sample-passport-json</td><td>Boundary, authority, runtime controls, review cadence.</td></tr>
                <tr><td>Evidence API</td><td>Return tool-call evidence record.</td><td>/agenttrust/sample-evidence-json</td><td>Action, source records, tool call, human owner, outcome.</td></tr>
                <tr><td>Authority API</td><td>Return authority decision outcome.</td><td>/agenttrust/sample-authority-decision-json</td><td>Requested action, decision, owner, reason, evidence.</td></tr>
                <tr><td>Readiness Report API</td><td>Return sample operational readiness report.</td><td>/agenttrust/readiness-report-json</td><td>Score, status, gaps, required actions.</td></tr>
                <tr><td>Manifest API</td><td>Return active route manifest.</td><td>/agenttrust/route-manifest-json</td><td>Expected routes, installed routes, missing routes.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>API Architecture Rule</h2>
        <div class="answer">
            AgentTrust™ can become a real governance assurance API by exposing structured agent identity,
            authority, evidence, readiness, risk, and replay records that enterprise tools can consume.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ API Blueprint",
        "API architecture blueprint for AgentTrust™ agent records, passports, evidence, authority decisions, readiness reports, and route manifests.",
        body
    )


@app.route("/agenttrust/export-center")
@app.route("/agenttrust/json-export-center")
@app.route("/agenttrust/api-export-center")
def agenttrust_export_center():
    body = """
    <section class="section">
        <h2>AgentTrust™ Export Center</h2>
        <p>
            The Export Center gives demo-ready JSON endpoints for AgentTrust™ structured records.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Export</th>
                    <th>Purpose</th>
                    <th>Open JSON</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent Record JSON</td><td>Agent identity, owner, boundary, risk, trust score, permitted and prohibited actions.</td><td><a href="/agenttrust/sample-agent-json">Open</a></td></tr>
                <tr><td>Passport JSON</td><td>Agent Risk Passport™ with boundary, authority, runtime controls, and review cadence.</td><td><a href="/agenttrust/sample-passport-json">Open</a></td></tr>
                <tr><td>Evidence Record JSON</td><td>Evidence record for tool call, source, owner, outcome, and replay status.</td><td><a href="/agenttrust/sample-evidence-json">Open</a></td></tr>
                <tr><td>Authority Decision JSON</td><td>Decision record for execute, human-gate, restrict, block, or quarantine.</td><td><a href="/agenttrust/sample-authority-decision-json">Open</a></td></tr>
                <tr><td>Readiness Report JSON</td><td>Sample readiness report with score, status, gaps, and required actions.</td><td><a href="/agenttrust/readiness-report-json">Open</a></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Export Rule</h2>
        <div class="answer">
            AgentTrust™ data should be exportable because governance evidence must travel across dashboards,
            ServiceNow records, audit packages, risk reviews, QA reviews, cybersecurity reviews, and leadership reports.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Export Center",
        "JSON export center for AgentTrust™ agent records, risk passports, evidence records, authority decisions, and readiness reports.",
        body
    )


@app.route("/agenttrust/sample-agent-json")
def agenttrust_sample_agent_json():
    from flask import jsonify
    return jsonify(AGENTTRUST_SAMPLE_AGENT_RECORD)


@app.route("/agenttrust/sample-passport-json")
def agenttrust_sample_passport_json():
    from flask import jsonify
    return jsonify(AGENTTRUST_SAMPLE_PASSPORT_RECORD)


@app.route("/agenttrust/sample-evidence-json")
def agenttrust_sample_evidence_json():
    from flask import jsonify
    return jsonify(AGENTTRUST_SAMPLE_EVIDENCE_RECORD)


@app.route("/agenttrust/sample-authority-decision-json")
def agenttrust_sample_authority_decision_json():
    from flask import jsonify
    return jsonify(AGENTTRUST_SAMPLE_AUTHORITY_DECISION)


@app.route("/agenttrust/readiness-report-json")
@app.route("/agenttrust/sample-readiness-report-json")
def agenttrust_readiness_report_json():
    from flask import jsonify

    report = {
        "report_id": "AT-RPT-001",
        "module": "AgentTrust™",
        "question": "Can this AI agent be operationally trusted to act?",
        "agent_id": AGENTTRUST_SAMPLE_AGENT_RECORD["agent_id"],
        "agent_name": AGENTTRUST_SAMPLE_AGENT_RECORD["agent_name"],
        "trust_score": AGENTTRUST_SAMPLE_AGENT_RECORD["trust_score"],
        "trust_status": AGENTTRUST_SAMPLE_AGENT_RECORD["trust_status"],
        "decision": "Human-gated recommendation only. Production CI update requires LCM / CMDB human approval.",
        "strengths": [
            "Agent identity defined",
            "Business and technical owners assigned",
            "Permitted and prohibited actions documented",
            "ServiceNow boundary identified",
            "Evidence requirements defined"
        ],
        "gaps": [
            "Production update authority not approved",
            "Cybersecurity review required if access or privileged workflow is involved",
            "QA / validation review required if CI supports regulated operations",
            "Final human review evidence must be captured"
        ],
        "required_actions": [
            "Confirm LCM / CMDB reviewer",
            "Link recommendation to source CI",
            "Capture reviewer approval or rejection",
            "Block direct update unless authority is explicitly approved",
            "Store decision replay package"
        ],
        "runtime_decision": {
            "read": "Allowed",
            "summarize": "Allowed",
            "recommend": "Human-gated",
            "draft": "Human-gated",
            "create": "Restricted",
            "update": "Blocked unless approved",
            "trigger": "Blocked unless approved",
            "approve": "Prohibited"
        }
    }

    return jsonify(report)

# ============================================================
# END AGENTTRUST_DATA_MODEL_API_EXPORT_V1_ACTIVE
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

print("AgentTrust Data Model API Export layer installed.")
print(f"Inserted before: {target_found}")
