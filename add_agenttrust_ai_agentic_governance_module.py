from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_AI_AGENTIC_GOVERNANCE_MODULE_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust AI Agentic Governance module already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# AGENTTRUST_AI_AGENTIC_GOVERNANCE_MODULE_V1_ACTIVE
# ============================================================

AGENTTRUST_HOOKS = [
    {
        "key": "citrust",
        "module": "CITrust™",
        "url": "/citrust/agenttrust-integration",
        "context": "AI agents linked to CIs, CMDB records, MyAccess, CyberArk, ServiceNow workflows, ownership, support groups, and lifecycle accountability."
    },
    {
        "key": "cutovertrust",
        "module": "CutoverTrust™",
        "url": "/cutovertrust/agenttrust-integration",
        "context": "AI agents involved in cutover readiness, transition execution, rollback, validation impact, go-live authority, and post-cutover verification."
    },
    {
        "key": "irlttrust",
        "module": "IRLTTrust™ / RLTTrust™",
        "url": "/irlt-commercial-readiness/agenttrust-integration",
        "context": "AI agents affecting GMP operations, QC readiness, inspection evidence, validation, release defensibility, and regulated radiopharma operations."
    },
    {
        "key": "aigovernance",
        "module": "AI Governance",
        "url": "/ai-governance/agenttrust-integration",
        "context": "AI system governance, AI Act readiness, AI literacy, high-risk classification, transparency, human oversight, logging, and accountability."
    },
    {
        "key": "servicenow",
        "module": "ServiceNow / CMDB Readiness",
        "url": "/servicenow-ci-readiness/agenttrust-integration",
        "context": "Agent linkage to Business Applications, Application Services, infrastructure CIs, support groups, LCM, ownership, and operational readiness."
    },
    {
        "key": "myaccess",
        "module": "MyAccess / CyberArk Readiness",
        "url": "/citrust/myaccess-readiness/agenttrust-integration",
        "context": "Agent access authority, entitlement governance, privileged execution, CyberArk routing, human approval, and pre-execution control."
    },
    {
        "key": "blackbox",
        "module": "Governance Black Box",
        "url": "/agenttrust/governance-black-box-integration",
        "context": "Time-of-action evidence, tool-call logs, authority confirmation, decision traceability, human accountability, rollback, and audit defensibility."
    }
]


def agenttrust_shell(title, subtitle, body):
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>{title}</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            :root{{
                --bg:#040b14;
                --panel:rgba(14,27,44,.94);
                --panel2:rgba(255,255,255,.055);
                --line:rgba(255,255,255,.13);
                --text:#eef5ff;
                --muted:#a8bbd4;
                --green:#31d07d;
                --yellow:#f7c948;
                --red:#ff5c70;
                --blue:#5cc8ff;
                --purple:#b49cff;
                --orange:#ffb86b;
                --cyan:#7efcff;
            }}
            *{{box-sizing:border-box}}
            body{{
                margin:0;
                font-family:Arial,Helvetica,sans-serif;
                background:
                    radial-gradient(circle at top left,rgba(92,200,255,.22),transparent 30%),
                    radial-gradient(circle at top right,rgba(49,208,125,.18),transparent 28%),
                    radial-gradient(circle at bottom right,rgba(180,156,255,.16),transparent 30%),
                    var(--bg);
                color:var(--text);
            }}
            .page{{max-width:1500px;margin:0 auto;padding:28px}}
            .hero{{
                border:1px solid var(--line);
                background:linear-gradient(135deg,rgba(16,29,47,.98),rgba(20,40,66,.92));
                border-radius:28px;
                padding:34px;
                box-shadow:0 24px 80px rgba(0,0,0,.42);
            }}
            .eyebrow{{
                color:var(--cyan);
                font-size:13px;
                text-transform:uppercase;
                letter-spacing:1.9px;
                font-weight:900;
                margin-bottom:10px;
            }}
            h1{{margin:0;font-size:44px;line-height:1.08}}
            .subtitle{{color:var(--muted);font-size:16px;line-height:1.65;max-width:1250px;margin-top:14px}}
            .question{{
                margin-top:18px;
                padding:19px 21px;
                border:1px solid rgba(49,208,125,.38);
                background:rgba(49,208,125,.10);
                border-radius:18px;
                color:#dfffea;
                line-height:1.6;
                font-size:18px;
                font-weight:900;
            }}
            .nav{{
                display:flex;
                flex-wrap:wrap;
                gap:10px;
                margin-top:18px;
            }}
            .nav a{{
                color:#04111f;
                background:var(--cyan);
                text-decoration:none;
                font-weight:900;
                border-radius:999px;
                padding:9px 12px;
                font-size:12px;
            }}
            .nav a.secondary{{background:var(--orange)}}
            .nav a.dark{{background:rgba(255,255,255,.14);color:var(--text);border:1px solid var(--line)}}
            .kpis{{display:grid;grid-template-columns:repeat(6,1fr);gap:14px;margin-top:20px}}
            .metric{{border:1px solid var(--line);background:var(--panel);border-radius:18px;padding:18px}}
            .metric .label{{color:var(--muted);font-size:13px;margin-bottom:8px}}
            .metric .value{{font-size:27px;font-weight:900}}
            .metric .note{{margin-top:8px;color:var(--muted);font-size:12px;line-height:1.4}}
            .section{{margin-top:24px;border:1px solid var(--line);background:var(--panel);border-radius:24px;padding:23px}}
            .section h2{{margin:0 0 8px 0;font-size:23px}}
            .section p{{color:var(--muted);line-height:1.56;margin-top:0}}
            .grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-top:16px}}
            .grid3{{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-top:16px}}
            .card{{
                border:1px solid var(--line);
                background:linear-gradient(135deg,rgba(255,255,255,.055),rgba(92,200,255,.055));
                border-radius:20px;
                padding:18px;
                min-height:155px;
            }}
            .card h3{{margin:0 0 8px 0;font-size:17px}}
            .card p{{margin:0;color:var(--muted);font-size:14px;line-height:1.55}}
            .card a{{display:inline-block;margin-top:12px;color:#7efcff;text-decoration:none;font-weight:900;font-size:13px}}
            .badge{{display:inline-block;padding:6px 9px;border-radius:999px;font-size:12px;font-weight:900;white-space:nowrap;margin-bottom:10px}}
            .green{{color:#04140b;background:var(--green)}}
            .yellow{{color:#1d1600;background:var(--yellow)}}
            .red{{color:#fff;background:var(--red)}}
            .blue{{color:#06101d;background:var(--blue)}}
            .purple{{color:#120b24;background:var(--purple)}}
            .orange{{color:#211100;background:var(--orange)}}
            table{{width:100%;border-collapse:collapse;overflow:hidden;border-radius:16px;margin-top:16px}}
            th{{text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.8px;color:#c9dbef;background:rgba(255,255,255,.07);padding:13px 12px;border-bottom:1px solid var(--line)}}
            td{{padding:13px 12px;border-bottom:1px solid rgba(255,255,255,.08);color:#e9f2ff;vertical-align:top;font-size:14px;line-height:1.48}}
            tr:hover td{{background:rgba(92,200,255,.05)}}
            .answer{{border:1px solid rgba(49,208,125,.38);background:rgba(49,208,125,.10);color:#dfffea;border-radius:18px;padding:20px;margin-top:16px;line-height:1.65;font-size:15px}}
            .warning{{border:1px solid rgba(247,201,72,.38);background:rgba(247,201,72,.11);color:#fff8d7;border-radius:18px;padding:18px;margin-top:16px;line-height:1.6}}
            .footer{{color:var(--muted);font-size:12px;margin-top:22px;line-height:1.6}}
            @media(max-width:1180px){{
                .kpis,.grid,.grid3{{grid-template-columns:1fr}}
                h1{{font-size:30px}}
                table{{display:block;overflow-x:auto;white-space:nowrap}}
            }}
        </style>
    </head>
    <body>
        <div class="page">
            <section class="hero">
                <div class="eyebrow">COBIT-Chain™ / AgentTrust™ / AI Agentic Governance</div>
                <h1>{title}</h1>
                <div class="subtitle">{subtitle}</div>
                <div class="question">Primary question: Can this AI agent be operationally trusted to act?</div>
                <div class="nav">
                    <a href="/">COBIT-Chain™ Home</a>
                    <a href="/agenttrust">AgentTrust™</a>
                    <a href="/agenttrust/integration-map" class="secondary">Integration Map</a>
                    <a href="/agenttrust/agent-register" class="dark">Agent Register</a>
                    <a href="/agenttrust/agent-passport" class="dark">Agent Passport</a>
                    <a href="/agenttrust/authority-gate" class="dark">Authority Gate</a>
                    <a href="/agenttrust/tool-call-evidence" class="dark">Tool-Call Evidence</a>
                    <a href="/agenttrust/human-accountability" class="dark">Human Accountability</a>
                    <a href="/agenttrust/ai-act-readiness" class="dark">AI Act Readiness</a>
                    <a href="/agenttrust/evidence-ledger" class="dark">Evidence Ledger</a>
                </div>
            </section>

            {body}

            <div class="footer">
                AgentTrust™ does not replace ServiceNow, CMDB, CSDM, ITSM, ITOM, Change, IRM/GRC, CyberArk, MyAccess, validation systems, QA systems, or accountable human decision-making. It is a COBIT-Chain™ governance assurance layer for AI agents, autonomous workflows, and regulated AI-enabled operations.
            </div>
        </div>
    </body>
    </html>
    """


def agenttrust_integration_card(module_name, module_context):
    return f"""
    <div class="card">
        <span class="badge blue">AgentTrust™ Hook</span>
        <h3>{module_name}</h3>
        <p>
            This module is connected to AgentTrust™ for AI agent identity, authority-before-execution,
            tool-call evidence, human accountability, time-of-action evidence, and Agent Risk Passport governance.
        </p>
        <p><strong>Context:</strong> {module_context}</p>
        <a href="/agenttrust/integration-map">View Integration Map</a>
    </div>
    """


def agenttrust_hook_page(hook_key):
    hook = next((item for item in AGENTTRUST_HOOKS if item["key"] == hook_key), None)

    if hook is None:
        return agenttrust_shell(
            "AgentTrust™ Integration Hook Not Found",
            "The requested AgentTrust™ integration hook has not been defined.",
            """
            <section class="section">
                <h2>Hook Not Found</h2>
                <p>This AgentTrust™ hook is not currently registered in the integration map.</p>
                <a href="/agenttrust/integration-map">Return to AgentTrust™ Integration Map</a>
            </section>
            """
        )

    body = f"""
    <section class="section">
        <h2>{hook["module"]} + AgentTrust™</h2>
        <div class="warning">
            <strong>Status:</strong> Integration hook created. This is the placeholder connection point that prevents
            AgentTrust™ from being forgotten when {hook["module"]} is expanded later.
        </div>

        <div class="grid3">
            {agenttrust_integration_card(hook["module"], hook["context"])}

            <div class="card">
                <span class="badge yellow">Future Control</span>
                <h3>What this hook will govern</h3>
                <p>
                    Agent ID, owner, human accountability, permitted actions, prohibited actions,
                    authority gate, tool/API access, evidence capture, escalation rules, and audit defensibility.
                </p>
            </div>

            <div class="card">
                <span class="badge purple">Future Data Link</span>
                <h3>Shared fields</h3>
                <p>
                    linked_ci_id, linked_business_application, linked_application_service,
                    linked_cutover_activity, linked_regulated_process, linked_owner, and linked_support_group.
                </p>
            </div>
        </div>
    </section>
    """

    return agenttrust_shell(
        f"{hook['module']} + AgentTrust™",
        "AI Agentic Governance integration hook for this COBIT-Chain™ module.",
        body
    )


@app.route("/agenttrust")
@app.route("/agenttrust/ai-agentic-governance")
@app.route("/agenttrust/ai-agent-governance")
def agenttrust_home():
    body = """
    <section class="kpis">
        <div class="metric"><div class="label">Module Status</div><div class="value" style="color:var(--green);">Active</div><div class="note">Standalone COBIT-Chain™ module created.</div></div>
        <div class="metric"><div class="label">Governance Scope</div><div class="value" style="color:var(--blue);">Agentic</div><div class="note">Identity, authority, tools, evidence, and accountability.</div></div>
        <div class="metric"><div class="label">Execution Control</div><div class="value" style="color:var(--yellow);">Pre-Gated</div><div class="note">Authority must exist before action.</div></div>
        <div class="metric"><div class="label">Evidence Model</div><div class="value" style="color:var(--green);">Real-Time</div><div class="note">Captured at the time of action.</div></div>
        <div class="metric"><div class="label">Human Ownership</div><div class="value" style="color:var(--orange);">Mapped</div><div class="note">Every agent action links to a human owner.</div></div>
        <div class="metric"><div class="label">Integration Map</div><div class="value" style="color:var(--purple);">Ready</div><div class="note">Hooks created for other COBIT-Chain™ modules.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Executive Positioning</h2>
        <div class="answer">
            <strong>AgentTrust™ is the COBIT-Chain™ governance assurance module for AI agents and autonomous workflows.</strong>
            It governs whether an AI agent has identity, ownership, system boundary, permitted actions, prohibited actions,
            authority before execution, tool-call evidence, human accountability, time-of-action evidence, and an Agent Risk Passport.
        </div>
    </section>

    <section class="section">
        <h2>Core AgentTrust™ Capabilities</h2>
        <div class="grid">
            <div class="card"><span class="badge blue">Identity</span><h3>AI Agent Identity</h3><p>Every AI agent has an ID, owner, role, system boundary, connected systems, permitted actions, and lifecycle status.</p><a href="/agenttrust/agent-register">Open Agent Register</a></div>
            <div class="card"><span class="badge yellow">Authority</span><h3>Authority Before Execution</h3><p>The agent cannot act unless execution authority is confirmed before the action happens.</p><a href="/agenttrust/authority-gate">Open Authority Gate</a></div>
            <div class="card"><span class="badge purple">Evidence</span><h3>Tool-Call Evidence</h3><p>Every API call, workflow trigger, data access, and decision path is logged as governance evidence.</p><a href="/agenttrust/tool-call-evidence">Open Evidence Ledger</a></div>
            <div class="card"><span class="badge orange">Accountability</span><h3>Human Accountability Map</h3><p>Every autonomous or semi-autonomous action links back to a responsible human owner.</p><a href="/agenttrust/human-accountability">Open Accountability Map</a></div>
            <div class="card"><span class="badge green">Time-of-Action</span><h3>Real-Time Evidence Capture</h3><p>Evidence is captured when the decision or action happens, not reconstructed later.</p><a href="/agenttrust/evidence-ledger">Open Evidence Ledger</a></div>
            <div class="card"><span class="badge red">Risk Passport</span><h3>Agent Risk Passport™</h3><p>Purpose, model, data, systems, tools, prohibited actions, escalation rules, risk status, and audit evidence.</p><a href="/agenttrust/agent-passport">Open Agent Passport</a></div>
            <div class="card"><span class="badge blue">Regulatory</span><h3>AI Act Readiness Lens™</h3><p>Maps AI agents against prohibited practices, high-risk classification, transparency, AI literacy, logging, and human oversight.</p><a href="/agenttrust/ai-act-readiness">Open AI Act Lens</a></div>
            <div class="card"><span class="badge purple">Platform</span><h3>Integration Map</h3><p>Tracks AgentTrust™ hooks across CITrust™, CutoverTrust™, IRLTTrust™, ServiceNow, MyAccess, CyberArk, and Governance Black Box.</p><a href="/agenttrust/integration-map">Open Integration Map</a></div>
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ — AI Agentic Governance",
        "AI Agent Identity, Authority Before Execution, Tool-Call Evidence, Human Accountability, Evidence at the Time of Action, and Agent Risk Passport Assurance.",
        body
    )


@app.route("/agenttrust/integration-map")
def agenttrust_integration_map():
    rows = ""

    for hook in AGENTTRUST_HOOKS:
        rows += f"""
        <tr>
            <td><strong>{hook["module"]}</strong></td>
            <td><span class="badge green">Hook Created</span></td>
            <td>{hook["context"]}</td>
            <td><a href="{hook["url"]}">Open hook</a></td>
        </tr>
        """

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Integration Map</h2>
        <div class="warning">
            <strong>Purpose:</strong> This page prevents AgentTrust™ from being forgotten.
            It tracks every COBIT-Chain™ module that needs an AI Agentic Governance hook.
        </div>

        <table>
            <thead>
                <tr>
                    <th>COBIT-Chain™ Module</th>
                    <th>Status</th>
                    <th>AgentTrust™ Integration Context</th>
                    <th>Hook Page</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Master Build Checklist</h2>
        <table>
            <thead>
                <tr>
                    <th>Build Item</th>
                    <th>Status</th>
                    <th>Purpose</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>AgentTrust™ landing page</td><td><span class="badge green">Done</span></td><td>Standalone module entry point.</td></tr>
                <tr><td>AgentTrust™ Integration Map</td><td><span class="badge green">Done</span></td><td>Prevents integration from being forgotten.</td></tr>
                <tr><td>CITrust™ hook</td><td><span class="badge green">Done</span></td><td>Links AI agents to CIs, CMDB, access, and ServiceNow workflows.</td></tr>
                <tr><td>CutoverTrust™ hook</td><td><span class="badge green">Done</span></td><td>Links AI agents to cutover readiness and go-live control.</td></tr>
                <tr><td>IRLTTrust™ / RLTTrust™ hook</td><td><span class="badge green">Done</span></td><td>Links AI agents to GMP and regulated radiopharma readiness.</td></tr>
                <tr><td>AI Governance hook</td><td><span class="badge green">Done</span></td><td>Links AgentTrust™ to broader AI governance and AI Act readiness.</td></tr>
                <tr><td>ServiceNow / CMDB hook</td><td><span class="badge green">Done</span></td><td>Links agents to app/service/infra ownership and relationships.</td></tr>
                <tr><td>MyAccess / CyberArk hook</td><td><span class="badge green">Done</span></td><td>Links agents to access authority and privileged execution.</td></tr>
                <tr><td>Governance Black Box hook</td><td><span class="badge green">Done</span></td><td>Links agents to time-of-action evidence and replayability.</td></tr>
                <tr><td>Live Agent Register records</td><td><span class="badge yellow">Future Build</span></td><td>Connect live agent records and source data.</td></tr>
                <tr><td>Live Tool-Call Evidence Ledger</td><td><span class="badge yellow">Future Build</span></td><td>Connect logs, API calls, workflow triggers, and decision paths.</td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Integration Map",
        "Platform-level tracker for AI Agentic Governance integration across COBIT-Chain™ modules.",
        body
    )


@app.route("/agenttrust/agent-register")
def agenttrust_agent_register():
    body = """
    <section class="section">
        <h2>Agent Identity Register</h2>
        <p>This register inventories every AI agent as a governed digital asset.</p>

        <table>
            <thead>
                <tr>
                    <th>Field</th>
                    <th>Governance Purpose</th>
                    <th>Control Question</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Agent ID</td><td>Unique identity for the AI agent.</td><td>Can the agent be uniquely identified?</td></tr>
                <tr><td>Agent Name</td><td>Business-readable name of the agent.</td><td>Can business users recognize what this agent is?</td></tr>
                <tr><td>Business Owner</td><td>Human owner accountable for business use.</td><td>Who owns the business purpose?</td></tr>
                <tr><td>Technical Owner</td><td>Owner responsible for technical operation.</td><td>Who owns configuration and support?</td></tr>
                <tr><td>Human Accountable Owner</td><td>Named human accountable for autonomous or semi-autonomous action.</td><td>Who remains accountable when the agent acts?</td></tr>
                <tr><td>System Boundary</td><td>Defines where the agent is allowed to operate.</td><td>Where can the agent act, and where must it not act?</td></tr>
                <tr><td>Connected Systems</td><td>Applications, APIs, workflows, and platforms the agent can touch.</td><td>Which systems can the agent influence?</td></tr>
                <tr><td>Lifecycle Status</td><td>Proposed, review, approved, live, suspended, retired.</td><td>Is this agent approved for current use?</td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Agent Register",
        "Inventory of governed AI agents, owners, boundaries, connected systems, roles, and lifecycle status.",
        body
    )


@app.route("/agenttrust/agent-passport")
def agenttrust_agent_passport():
    body = """
    <section class="section">
        <h2>Agent Risk Passport™</h2>
        <div class="answer">
            The Agent Risk Passport™ is the core governance artifact for each AI agent.
            It records identity, purpose, model, data, connected systems, permitted tools, prohibited actions,
            escalation rules, human oversight, risk classification, validation impact, cybersecurity review, and audit evidence.
        </div>

        <div class="grid3">
            <div class="card"><span class="badge blue">Identity</span><h3>Who is the agent?</h3><p>Agent ID, name, owner, role, purpose, support group, and lifecycle status.</p></div>
            <div class="card"><span class="badge yellow">Boundary</span><h3>Where can it act?</h3><p>Connected systems, APIs, workflows, environments, data domains, and system limits.</p></div>
            <div class="card"><span class="badge purple">Risk</span><h3>How risky is it?</h3><p>AI Act class, GxP impact, cyber impact, validation impact, and business criticality.</p></div>
            <div class="card"><span class="badge orange">Execution</span><h3>What can it do?</h3><p>Permitted actions, prohibited actions, required authority, escalation rules, and oversight.</p></div>
            <div class="card"><span class="badge green">Evidence</span><h3>What proves control?</h3><p>Tool-call evidence, audit logs, decision path, timestamps, approvals, and exception handling.</p></div>
            <div class="card"><span class="badge red">Change</span><h3>What changed?</h3><p>Model changes, prompt changes, tool changes, data changes, access changes, and retirement plan.</p></div>
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Agent Risk Passport",
        "Governance passport for AI agent purpose, risk, authority, evidence, oversight, and accountability.",
        body
    )


@app.route("/agenttrust/authority-gate")
def agenttrust_authority_gate():
    body = """
    <section class="section">
        <h2>Authority Gate™</h2>
        <p>
            Authority Gate™ confirms whether an AI agent has permission before execution.
            It separates reading, recommending, drafting, creating tickets, updating records,
            triggering workflows, approving actions, and regulated execution.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Action Level</th>
                    <th>Authority Requirement</th>
                    <th>Governance Decision</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Read only</td><td>Approved data-access scope and logged retrieval.</td><td>Allowed only inside data boundary.</td></tr>
                <tr><td>Recommend</td><td>Human review required before operational action.</td><td>Agent may advise, not execute.</td></tr>
                <tr><td>Draft</td><td>Human owner must review before submission.</td><td>Drafting is not approval.</td></tr>
                <tr><td>Create ticket</td><td>Workflow authority and accountable owner required.</td><td>Allowed if ticketing boundary is approved.</td></tr>
                <tr><td>Update record</td><td>Role-based authority, evidence logging, and approval trail required.</td><td>Human-gated unless pre-approved.</td></tr>
                <tr><td>Trigger workflow</td><td>Pre-approved workflow boundary and rollback route required.</td><td>Blocked if rollback is absent.</td></tr>
                <tr><td>Regulated execution</td><td>Human authorization, validation review, QA impact, and audit evidence required.</td><td>Never fully autonomous without governed approval.</td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Authority Gate",
        "Pre-execution authority control for AI agent action.",
        body
    )


@app.route("/agenttrust/tool-call-evidence")
def agenttrust_tool_call_evidence():
    body = """
    <section class="section">
        <h2>Tool-Call Evidence Ledger™</h2>
        <p>
            Every API call, workflow trigger, data access, decision path, exception,
            escalation, and approval event must be captured as evidence.
        </p>

        <div class="grid3">
            <div class="card"><span class="badge blue">API</span><h3>API Call</h3><p>Endpoint, timestamp, requester context, payload class, and result.</p></div>
            <div class="card"><span class="badge yellow">Workflow</span><h3>Workflow Trigger</h3><p>Workflow name, trigger reason, approval status, control route, and outcome.</p></div>
            <div class="card"><span class="badge purple">Data</span><h3>Data Access</h3><p>Data source, sensitivity, scope, retrieval reason, and access evidence.</p></div>
            <div class="card"><span class="badge orange">Decision</span><h3>Decision Path</h3><p>Prompt, model, input, output, decision summary, confidence where applicable, and review status.</p></div>
            <div class="card"><span class="badge red">Exception</span><h3>Blocked Action</h3><p>Failed action, unauthorized attempt, missing authority, expired exception, and escalation path.</p></div>
            <div class="card"><span class="badge green">Audit</span><h3>Evidence Package</h3><p>Timestamp, owner, linked record, authority proof, outcome, and inspection-ready explanation.</p></div>
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Tool-Call Evidence",
        "Evidence ledger for AI agent API calls, workflow triggers, data access, and decision paths.",
        body
    )


@app.route("/agenttrust/human-accountability")
def agenttrust_human_accountability():
    body = """
    <section class="section">
        <h2>Human Accountability Map™</h2>
        <p>
            Every autonomous or semi-autonomous AI agent action must link back to a responsible human owner.
            The agent may act inside a governed boundary, but accountability remains assigned to humans and governance roles.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Accountability Role</th>
                    <th>Responsibility</th>
                    <th>Why It Matters</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Business Owner</td><td>Owns business purpose and acceptable use.</td><td>Prevents ownerless AI activity.</td></tr>
                <tr><td>Technical Owner</td><td>Owns configuration, integration, and operational support.</td><td>Ensures supportability and lifecycle control.</td></tr>
                <tr><td>Model Owner</td><td>Owns model selection, model change, and performance governance.</td><td>Prevents unmanaged model drift.</td></tr>
                <tr><td>Process Owner</td><td>Owns workflow or process affected by the agent.</td><td>Connects AI action to business process accountability.</td></tr>
                <tr><td>Risk Owner</td><td>Owns risk acceptance, mitigation, and escalation.</td><td>Ensures residual risk is visible and accepted.</td></tr>
                <tr><td>QA / Compliance Owner</td><td>Owns regulated-process impact and evidence quality.</td><td>Protects audit and inspection defensibility.</td></tr>
                <tr><td>Cybersecurity Owner</td><td>Owns access control, privileged execution, and threat review.</td><td>Prevents unauthorized or unsafe agent execution.</td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Human Accountability",
        "Human ownership and accountability map for AI agent action.",
        body
    )


@app.route("/agenttrust/ai-act-readiness")
def agenttrust_ai_act_readiness():
    body = """
    <section class="section">
        <h2>AI Act Readiness Lens™</h2>
        <p>
            This lens maps AI agents and AI-enabled workflows against regulatory expectations,
            including prohibited practices, high-risk classification, transparency, AI literacy,
            human oversight, logging, registration, and evidence readiness.
        </p>

        <div class="grid3">
            <div class="card"><span class="badge red">Prohibited</span><h3>Prohibited Practice Check</h3><p>Determines whether the agent uses forbidden, manipulative, or restricted AI behavior.</p></div>
            <div class="card"><span class="badge yellow">High Risk</span><h3>High-Risk Classification</h3><p>Checks whether the agent supports high-risk domains, regulated operations, or critical workflows.</p></div>
            <div class="card"><span class="badge blue">Transparency</span><h3>Transparency Obligation</h3><p>Checks whether AI-generated output, interaction, or decision support must be disclosed.</p></div>
            <div class="card"><span class="badge purple">Literacy</span><h3>AI Literacy</h3><p>Maps training and competency expectations for providers, deployers, owners, and users.</p></div>
            <div class="card"><span class="badge orange">Oversight</span><h3>Human Oversight</h3><p>Confirms human review, intervention, override, escalation, and stop-control routes.</p></div>
            <div class="card"><span class="badge green">Evidence</span><h3>Evidence Readiness</h3><p>Confirms logging, traceability, risk controls, testing, and audit-defensible records.</p></div>
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ AI Act Readiness",
        "Regulatory readiness lens for AI agents, AI systems, and agentic workflows.",
        body
    )


@app.route("/agenttrust/evidence-ledger")
def agenttrust_evidence_ledger():
    body = """
    <section class="section">
        <h2>Evidence at the Time of Action™</h2>
        <div class="answer">
            AgentTrust™ captures evidence when an AI agent acts, not after the fact.
            This supports audit defensibility, deviation investigation, inspection readiness,
            root-cause analysis, rollback review, and operational trust.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Evidence Type</th>
                    <th>Captured Detail</th>
                    <th>Audit Question Answered</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Timestamp</td><td>Exact time the agent accessed data, made a recommendation, or triggered an action.</td><td>When did the action happen?</td></tr>
                <tr><td>Authority Evidence</td><td>Proof that authority was confirmed before execution.</td><td>Who or what allowed the agent to act?</td></tr>
                <tr><td>Tool Evidence</td><td>API, workflow, application, or system touched by the agent.</td><td>What system did the agent affect?</td></tr>
                <tr><td>Decision Evidence</td><td>Input, output, decision path summary, confidence where applicable, and review status.</td><td>Why did the agent produce that output?</td></tr>
                <tr><td>Human Evidence</td><td>Responsible owner, approver, reviewer, or escalation contact.</td><td>Which human remains accountable?</td></tr>
                <tr><td>Outcome Evidence</td><td>Success, failure, blocked action, exception, escalation, or rollback.</td><td>What happened after the action?</td></tr>
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Evidence Ledger",
        "Time-of-action evidence capture for AI agent decisions and actions.",
        body
    )


@app.route("/citrust/agenttrust-integration")
def citrust_agenttrust_integration():
    return agenttrust_hook_page("citrust")


@app.route("/cutovertrust/agenttrust-integration")
def cutovertrust_agenttrust_integration():
    return agenttrust_hook_page("cutovertrust")


@app.route("/irlt-commercial-readiness/agenttrust-integration")
@app.route("/irlttrust/agenttrust-integration")
@app.route("/rlttrust/agenttrust-integration")
def irlttrust_agenttrust_integration():
    return agenttrust_hook_page("irlttrust")


@app.route("/ai-governance/agenttrust-integration")
def ai_governance_agenttrust_integration():
    return agenttrust_hook_page("aigovernance")


@app.route("/servicenow-ci-readiness/agenttrust-integration")
def servicenow_agenttrust_integration():
    return agenttrust_hook_page("servicenow")


@app.route("/citrust/myaccess-readiness/agenttrust-integration")
@app.route("/citrust/access-readiness/agenttrust-integration")
def myaccess_agenttrust_integration():
    return agenttrust_hook_page("myaccess")


@app.route("/agenttrust/governance-black-box-integration")
def governance_black_box_agenttrust_integration():
    return agenttrust_hook_page("blackbox")

# ============================================================
# END AGENTTRUST_AI_AGENTIC_GOVERNANCE_MODULE_V1_ACTIVE
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

print("AgentTrust AI Agentic Governance module installed.")
print(f"Inserted before: {target_found}")
