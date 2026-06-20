from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_GOVERNANCE_GRAPH_LINEAGE_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust Governance Graph already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base module not found. Install AgentTrust module first.")

nav_old = '<a href="/agenttrust/trust-contract-registry" class="secondary">Trust Contract</a>'
nav_new = '''<a href="/agenttrust/trust-contract-registry" class="secondary">Trust Contract</a>
                    <a href="/agenttrust/governance-graph" class="secondary">Governance Graph</a>
                    <a href="/agenttrust/trust-lineage-explorer" class="dark">Trust Lineage</a>
                    <a href="/agenttrust/control-ontology" class="dark">Control Ontology</a>
                    <a href="/agenttrust/lineage-break-register" class="dark">Lineage Breaks</a>'''

if nav_old in text and "/agenttrust/governance-graph" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# AGENTTRUST_GOVERNANCE_GRAPH_LINEAGE_V1_ACTIVE
# AgentTrust™ Governance Graph, Trust Lineage Explorer,
# Control Ontology, Agent-to-Control Map, Trust Chain Explorer,
# Lineage Break Register, and Trust Graph JSON Export
# ============================================================

AGENTTRUST_GOVERNANCE_NODES = [
    {
        "node_id": "AT-NODE-001",
        "node": "Agent Identity",
        "description": "Defines the AI agent name, purpose, owner, lifecycle state, and risk tier.",
        "evidence": "Agent Register / Agent Risk Passport™",
        "owner": "Governance Owner",
        "trust_role": "Establishes who or what the agent is."
    },
    {
        "node_id": "AT-NODE-002",
        "node": "Trust Contract",
        "description": "Defines what the agent is licensed to do, prohibited from doing, and what revokes trust.",
        "evidence": "Trust Contract Registry / Operating License",
        "owner": "Risk Owner",
        "trust_role": "Defines operating terms and breach rules."
    },
    {
        "node_id": "AT-NODE-003",
        "node": "AgentBOM",
        "description": "Defines model, prompt, tools, APIs, data sources, workflows, owners, and evidence stores.",
        "evidence": "AgentBOM / Dependency Graph",
        "owner": "Agent Lifecycle Owner",
        "trust_role": "Exposes dependencies that can affect trust."
    },
    {
        "node_id": "AT-NODE-004",
        "node": "Authority Decision",
        "description": "Determines whether an action may execute, be human-gated, restricted, escalated, blocked, or quarantined.",
        "evidence": "Authority Gate / Policy Decision Engine",
        "owner": "Process Owner / Risk Owner",
        "trust_role": "Prevents unauthorized AI agent action."
    },
    {
        "node_id": "AT-NODE-005",
        "node": "Tool Call",
        "description": "Captures the system, API, workflow, record, or tool touched by the agent.",
        "evidence": "Tool-Call Evidence / Evidence Ledger",
        "owner": "Platform Owner",
        "trust_role": "Shows what the agent actually did."
    },
    {
        "node_id": "AT-NODE-006",
        "node": "Human Oversight",
        "description": "Maps the decision to a human reviewer, approver, risk owner, QA owner, or cyber owner.",
        "evidence": "Human Oversight Workbench / Approval Evidence Vault",
        "owner": "Required Human Owner",
        "trust_role": "Preserves accountability."
    },
    {
        "node_id": "AT-NODE-007",
        "node": "Evidence Package",
        "description": "Captures input, source, output, tool-call, authority, human decision, outcome, and timestamp.",
        "evidence": "Evidence Lineage Engine / Audit Dossier",
        "owner": "Audit / Governance Owner",
        "trust_role": "Makes the decision defendable."
    },
    {
        "node_id": "AT-NODE-008",
        "node": "Monitoring Signal",
        "description": "Tracks drift, exception expiry, evidence weakness, cyber impact, GxP impact, and trust degradation.",
        "evidence": "Continuous Monitoring Center / Drift Alert Console",
        "owner": "Control Owner",
        "trust_role": "Keeps trust current after deployment."
    },
    {
        "node_id": "AT-NODE-009",
        "node": "Audit Replay",
        "description": "Reconstructs what happened, why it happened, who owned it, what evidence existed, and what outcome occurred.",
        "evidence": "Decision Replay Studio / Assurance Case Builder",
        "owner": "Audit / Governance Owner",
        "trust_role": "Defends the AI agent action under challenge."
    }
]


AGENTTRUST_GOVERNANCE_EDGES = [
    ("Agent Identity", "Trust Contract", "Agent must operate under a defined contract."),
    ("Trust Contract", "AgentBOM", "Contract scope depends on known dependencies."),
    ("AgentBOM", "Authority Decision", "Dependencies and tools affect whether action is allowed."),
    ("Authority Decision", "Tool Call", "Only authorized actions may call tools or workflows."),
    ("Tool Call", "Human Oversight", "Material actions must preserve human accountability."),
    ("Human Oversight", "Evidence Package", "Human decision must be evidenced."),
    ("Evidence Package", "Monitoring Signal", "Evidence gaps and drift feed monitoring."),
    ("Monitoring Signal", "Audit Replay", "Monitoring events become part of replay defense."),
    ("Audit Replay", "Assurance Case", "Replay supports leadership and audit defensibility.")
]


AGENTTRUST_CONTROL_ONTOLOGY = [
    {
        "control_family": "Identity Controls",
        "controls": "Agent Register, Agent Risk Passport™, lifecycle status, owner map.",
        "question": "Do we know which AI agent acted and who owns it?",
        "failure": "Unknown or ownerless agent."
    },
    {
        "control_family": "Boundary Controls",
        "controls": "AgentBOM, dependency graph, approved systems, tools, APIs, data sources.",
        "question": "Was the agent operating inside its approved boundary?",
        "failure": "Scope creep, tool expansion, or dependency drift."
    },
    {
        "control_family": "Authority Controls",
        "controls": "Authority Gate, Policy Decision Engine, Operating License, Trust Contract.",
        "question": "Was the action permitted before execution?",
        "failure": "Unauthorized create, update, trigger, approve, or access action."
    },
    {
        "control_family": "Evidence Controls",
        "controls": "Tool-call evidence, evidence ledger, evidence lineage, evidence vault.",
        "question": "Can the action be proven with time-of-action evidence?",
        "failure": "Weak audit replay or post-created evidence reliance."
    },
    {
        "control_family": "Human Accountability Controls",
        "controls": "Human Oversight Workbench, Approval Queue, Signoff Matrix, Risk Acceptance Register.",
        "question": "Which human remained accountable?",
        "failure": "Hidden AI approval or ownerless reliance."
    },
    {
        "control_family": "Cyber Controls",
        "controls": "MyAccess / CyberArk routing, cyber escalation, privileged action block.",
        "question": "Did access or privileged impact receive cyber review?",
        "failure": "Unauthorized entitlement or privileged route influence."
    },
    {
        "control_family": "GxP / QA Controls",
        "controls": "GxP impact router, QA review, validation review, regulated conclusion block.",
        "question": "Did regulated impact receive QA / validation review?",
        "failure": "AI-generated regulated conclusion or inspection defensibility gap."
    },
    {
        "control_family": "Runtime Controls",
        "controls": "Execution Firewall, Runtime Sentinel, Kill Switch, Quarantine, Rollback.",
        "question": "Could unsafe execution be stopped or recovered?",
        "failure": "Unsafe AI action continues or cannot be reversed."
    },
    {
        "control_family": "Monitoring Controls",
        "controls": "Continuous Monitoring Center, Drift Alert Console, Trust Degradation Watch.",
        "question": "Is the agent still trusted after deployment?",
        "failure": "Trust becomes stale after model, prompt, tool, data, owner, or evidence drift."
    },
    {
        "control_family": "Replay Controls",
        "controls": "Decision Replay Studio, Audit Dossier, Assurance Case Builder.",
        "question": "Can leadership defend what happened?",
        "failure": "Action cannot be reconstructed under audit or inspection challenge."
    }
]


AGENTTRUST_LINEAGE_BREAKS = [
    {
        "break_id": "AT-LB-001",
        "break": "Agent identity not linked to operating license.",
        "risk": "Agent action cannot be tied to approved trust contract.",
        "severity": "High",
        "required_fix": "Link Agent Register record to Trust Contract and Operating License."
    },
    {
        "break_id": "AT-LB-002",
        "break": "Tool call not linked to authority decision.",
        "risk": "Cannot prove tool use was authorized before execution.",
        "severity": "Critical",
        "required_fix": "Require authority decision ID before tool execution."
    },
    {
        "break_id": "AT-LB-003",
        "break": "Human reviewer missing from evidence package.",
        "risk": "AI output may become hidden approval.",
        "severity": "Critical",
        "required_fix": "Route to required human owner and capture decision."
    },
    {
        "break_id": "AT-LB-004",
        "break": "GxP impact not linked to QA / validation owner.",
        "risk": "Regulated reliance may be undefended.",
        "severity": "Critical",
        "required_fix": "Run GxP impact router and capture QA / validation review."
    },
    {
        "break_id": "AT-LB-005",
        "break": "CyberArk or privileged impact not linked to cyber review.",
        "risk": "Privileged or access route may be influenced without approval.",
        "severity": "Critical",
        "required_fix": "Route to cybersecurity / CyberArk owner."
    },
    {
        "break_id": "AT-LB-006",
        "break": "Monitoring alert not linked to remediation evidence.",
        "risk": "Control weakness remains open and trust becomes stale.",
        "severity": "High",
        "required_fix": "Create remediation owner, due date, closure evidence, and updated trust score."
    },
    {
        "break_id": "AT-LB-007",
        "break": "Audit replay missing final outcome.",
        "risk": "Action loop cannot be closed.",
        "severity": "High",
        "required_fix": "Capture executed, blocked, escalated, rejected, rolled back, or quarantined outcome."
    }
]


def agenttrust_governance_node_rows():
    rows = ""

    for item in AGENTTRUST_GOVERNANCE_NODES:
        rows += f"""
        <tr>
            <td><strong>{item["node_id"]}</strong></td>
            <td><span class="badge blue">{item["node"]}</span></td>
            <td>{item["description"]}</td>
            <td>{item["evidence"]}</td>
            <td>{item["owner"]}</td>
            <td>{item["trust_role"]}</td>
        </tr>
        """

    return rows


def agenttrust_governance_edge_rows():
    rows = ""

    for source, target, relationship in AGENTTRUST_GOVERNANCE_EDGES:
        rows += f"""
        <tr>
            <td><strong>{source}</strong></td>
            <td>→</td>
            <td><strong>{target}</strong></td>
            <td>{relationship}</td>
        </tr>
        """

    return rows


def agenttrust_control_ontology_rows():
    rows = ""

    for item in AGENTTRUST_CONTROL_ONTOLOGY:
        rows += f"""
        <tr>
            <td><strong>{item["control_family"]}</strong></td>
            <td>{item["controls"]}</td>
            <td>{item["question"]}</td>
            <td><span class="badge red">{item["failure"]}</span></td>
        </tr>
        """

    return rows


def agenttrust_lineage_break_rows():
    rows = ""

    for item in AGENTTRUST_LINEAGE_BREAKS:
        badge = "orange"
        if item["severity"] == "Critical":
            badge = "red"
        elif item["severity"] == "High":
            badge = "yellow"

        rows += f"""
        <tr>
            <td><strong>{item["break_id"]}</strong></td>
            <td>{item["break"]}</td>
            <td>{item["risk"]}</td>
            <td><span class="badge {badge}">{item["severity"]}</span></td>
            <td>{item["required_fix"]}</td>
        </tr>
        """

    return rows


try:
    AGENTTRUST_EXPECTED_ROUTES.extend([
        "/agenttrust/governance-graph",
        "/agenttrust/trust-lineage-explorer",
        "/agenttrust/control-ontology",
        "/agenttrust/agent-to-control-map",
        "/agenttrust/trust-chain-explorer",
        "/agenttrust/lineage-break-register",
        "/agenttrust/trust-graph-json"
    ])
except Exception:
    pass


@app.route("/agenttrust/governance-graph")
@app.route("/agenttrust/trust-governance-graph")
@app.route("/agenttrust/agent-governance-graph")
def agenttrust_governance_graph():
    node_rows = agenttrust_governance_node_rows()
    edge_rows = agenttrust_governance_edge_rows()

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Governance Graph</div><div class="value" style="color:var(--green);">Active</div><div class="note">Trust nodes and lineage edges mapped.</div></div>
        <div class="metric"><div class="label">Nodes</div><div class="value" style="color:var(--blue);">9</div><div class="note">Identity, contract, BOM, authority, tool, human, evidence, monitoring, replay.</div></div>
        <div class="metric"><div class="label">Lineage</div><div class="value" style="color:var(--yellow);">Traceable</div><div class="note">Agent action can be followed end-to-end.</div></div>
        <div class="metric"><div class="label">Breaks</div><div class="value" style="color:var(--red);">Watched</div><div class="note">Lineage breaks reduce trust immediately.</div></div>
        <div class="metric"><div class="label">Controls</div><div class="value" style="color:var(--orange);">Ontologized</div><div class="note">Control families mapped to trust questions.</div></div>
        <div class="metric"><div class="label">Replay</div><div class="value" style="color:var(--purple);">Supported</div><div class="note">Graph supports audit and assurance case defense.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Governance Graph</h2>
        <div class="answer">
            <strong>Purpose:</strong> connect every AI agent trust element into a single governance graph.
            The graph shows how agent identity, trust contract, AgentBOM, authority, tool calls, human oversight,
            evidence, monitoring, and audit replay connect into one operational trust chain.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Node ID</th>
                    <th>Trust Node</th>
                    <th>Description</th>
                    <th>Evidence Artifact</th>
                    <th>Owner</th>
                    <th>Trust Role</th>
                </tr>
            </thead>
            <tbody>
                {node_rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Governance Graph Edges</h2>
        <table>
            <thead>
                <tr>
                    <th>Source</th>
                    <th></th>
                    <th>Target</th>
                    <th>Relationship</th>
                </tr>
            </thead>
            <tbody>
                {edge_rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Governance Graph Rule</h2>
        <div class="answer">
            AgentTrust™ trust is strongest when every node is connected.
            If identity, authority, tool use, human decision, evidence, monitoring, or replay is disconnected,
            the agent action becomes harder to defend.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Governance Graph",
        "Governance graph for AI agent identity, trust contract, AgentBOM, authority decision, tool call, human oversight, evidence, monitoring, and audit replay.",
        body
    )


@app.route("/agenttrust/trust-lineage-explorer")
@app.route("/agenttrust/trust-lineage")
@app.route("/agenttrust/agent-trust-lineage")
def agenttrust_trust_lineage_explorer():
    edge_rows = agenttrust_governance_edge_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Trust Lineage Explorer</h2>
        <p>
            The Trust Lineage Explorer follows an AI agent action from initial identity to final audit replay.
            It helps prove whether a trust decision can be reconstructed end-to-end.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Lineage Start</th>
                    <th></th>
                    <th>Lineage Target</th>
                    <th>Trust Relationship</th>
                </tr>
            </thead>
            <tbody>
                {edge_rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Trust Lineage Chain</h2>
        <div class="answer">
            <strong>Complete Lineage:</strong><br>
            Agent Identity → Trust Contract → AgentBOM → Authority Decision → Tool Call → Human Oversight → Evidence Package → Monitoring Signal → Audit Replay → Assurance Case.
        </div>
    </section>

    <section class="section">
        <h2>Lineage Rule</h2>
        <div class="answer">
            If any link in the lineage is missing, AgentTrust™ should downgrade the action from trusted to human-gated,
            restricted, escalated, blocked, or quarantined depending on risk.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Trust Lineage Explorer",
        "Trust lineage explorer for tracing AI agent action from identity through contract, dependencies, authority, tool use, human review, evidence, monitoring, and replay.",
        body
    )


@app.route("/agenttrust/control-ontology")
@app.route("/agenttrust/agent-control-ontology")
@app.route("/agenttrust/trust-control-ontology")
def agenttrust_control_ontology():
    rows = agenttrust_control_ontology_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Control Ontology</h2>
        <p>
            The Control Ontology organizes AgentTrust™ controls into families and connects each family to the trust question it answers.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Control Family</th>
                    <th>Controls</th>
                    <th>Trust Question</th>
                    <th>Failure Mode</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Ontology Rule</h2>
        <div class="answer">
            AgentTrust™ controls are not isolated pages.
            They form a control ontology that answers recurring trust questions:
            who acted, who owns it, what was allowed, what was touched, what evidence exists, and can it be replayed?
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Control Ontology",
        "Control ontology mapping AgentTrust™ control families to trust questions, evidence requirements, and failure modes.",
        body
    )


@app.route("/agenttrust/agent-to-control-map")
@app.route("/agenttrust/agent-control-map")
@app.route("/agenttrust/control-mapping")
def agenttrust_agent_to_control_map():
    body = """
    <section class="section">
        <h2>AgentTrust™ Agent-to-Control Map</h2>
        <p>
            This map shows which controls are required based on the kind of AI agent capability.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Agent Capability</th>
                    <th>Required Controls</th>
                    <th>Required Owner</th>
                    <th>Default Trust Decision</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Read-only agent.</td><td>Register, owner, boundary, access log, source traceability.</td><td>Business / technical owner.</td><td><span class="badge green">Allowed within boundary</span></td></tr>
                <tr><td>Summarization agent.</td><td>Source lineage, evidence capture, reviewer route for material use.</td><td>Process owner.</td><td><span class="badge green">Allowed with evidence</span></td></tr>
                <tr><td>Recommendation agent.</td><td>Authority gate, human reviewer, evidence package, prohibited-action sentinel.</td><td>Process / LCM / system owner.</td><td><span class="badge yellow">Human-gated</span></td></tr>
                <tr><td>Drafting agent.</td><td>Human signoff, source evidence, no auto-submission rule.</td><td>Workflow owner.</td><td><span class="badge yellow">Human approval required</span></td></tr>
                <tr><td>Create / update agent.</td><td>Authority gate, execution firewall, rollback, evidence, change link.</td><td>Technical / process owner.</td><td><span class="badge red">Restricted execution</span></td></tr>
                <tr><td>Workflow trigger agent.</td><td>Policy decision engine, execution firewall, rollback, monitoring, outcome record.</td><td>Workflow / risk owner.</td><td><span class="badge red">Human-gated execution</span></td></tr>
                <tr><td>Access-influencing agent.</td><td>MyAccess / CyberArk routing, cyber owner review, no autonomous approval.</td><td>Cybersecurity / access owner.</td><td><span class="badge red">Cyber-gated</span></td></tr>
                <tr><td>GxP / QA-influencing agent.</td><td>GxP screening, QA / validation review, regulated conclusion block.</td><td>QA / validation owner.</td><td><span class="badge red">Human-governed only</span></td></tr>
                <tr><td>Multi-agent chain.</td><td>Delegation map, handoff control, orchestration firewall, composite evidence.</td><td>Governance owner.</td><td><span class="badge orange">Chain-controlled</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Control Mapping Rule</h2>
        <div class="answer">
            Controls must scale with capability. The more an agent can act, trigger, approve, access, or influence regulated operations,
            the stronger the control package must be.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Agent-to-Control Map",
        "Mapping AI agent capabilities to required controls, owners, and default trust decisions.",
        body
    )


@app.route("/agenttrust/trust-chain-explorer")
@app.route("/agenttrust/trust-chain")
@app.route("/agenttrust/agent-trust-chain")
def agenttrust_trust_chain_explorer():
    body = """
    <section class="section">
        <h2>AgentTrust™ Trust Chain Explorer</h2>
        <p>
            The Trust Chain Explorer presents the minimum chain that must exist before an AI agent action can be defended.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Trust Chain Step</th>
                    <th>Required Proof</th>
                    <th>Owner</th>
                    <th>If Missing</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>1. Agent Known</td><td>Agent ID, owner, purpose, lifecycle state.</td><td>Governance Owner.</td><td><span class="badge red">Block</span></td></tr>
                <tr><td>2. Contract Active</td><td>Operating license, permitted scope, prohibited scope.</td><td>Risk Owner.</td><td><span class="badge red">Restrict</span></td></tr>
                <tr><td>3. Dependencies Known</td><td>Model, prompt, tools, APIs, data, workflows.</td><td>Lifecycle Owner.</td><td><span class="badge orange">Human-gate</span></td></tr>
                <tr><td>4. Authority Present</td><td>Decision rule and action permission.</td><td>Process Owner.</td><td><span class="badge red">Block</span></td></tr>
                <tr><td>5. Tool Evidence Captured</td><td>Tool, target system, mode, timestamp, result.</td><td>Platform Owner.</td><td><span class="badge orange">Restrict reliance</span></td></tr>
                <tr><td>6. Human Accountability Captured</td><td>Reviewer, approver, escalation owner, decision.</td><td>Required Human Owner.</td><td><span class="badge red">Hidden approval risk</span></td></tr>
                <tr><td>7. Monitoring Active</td><td>Drift, exception, degradation, alert signals.</td><td>Control Owner.</td><td><span class="badge orange">Trust becomes stale</span></td></tr>
                <tr><td>8. Replay Ready</td><td>Timeline, evidence lineage, authority lineage, outcome.</td><td>Audit Owner.</td><td><span class="badge red">Not defensible</span></td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Trust Chain Rule</h2>
        <div class="answer">
            AgentTrust™ trust is chain-based. A strong model cannot compensate for a broken owner, missing authority,
            weak evidence, missing human review, or failed replay.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Trust Chain Explorer",
        "Trust chain explorer showing the minimum evidence chain required to defend an AI agent action.",
        body
    )


@app.route("/agenttrust/lineage-break-register")
@app.route("/agenttrust/trust-lineage-breaks")
@app.route("/agenttrust/lineage-breaks")
def agenttrust_lineage_break_register():
    rows = agenttrust_lineage_break_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Lineage Break Register</h2>
        <p>
            This register tracks missing links in the AI agent trust chain.
            Lineage breaks are serious because they prevent audit replay and weaken operational trust.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Break ID</th>
                    <th>Lineage Break</th>
                    <th>Risk</th>
                    <th>Severity</th>
                    <th>Required Fix</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Lineage Break Rule</h2>
        <div class="answer">
            If the chain breaks, trust breaks. AgentTrust™ treats missing identity, authority, evidence,
            human review, cyber review, QA review, monitoring closure, or final outcome as trust degradation signals.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Lineage Break Register",
        "Register for AI agent trust lineage breaks, including missing contract links, missing authority, missing human review, missing QA or cyber review, and replay gaps.",
        body
    )


@app.route("/agenttrust/trust-graph-json")
@app.route("/agenttrust/governance-graph-json")
@app.route("/agenttrust/trust-lineage-json")
def agenttrust_trust_graph_json():
    from flask import jsonify

    return jsonify({
        "module": "AgentTrust™",
        "capability": "Governance Graph + Trust Lineage Explorer",
        "primary_question": "Can the AI agent action be traced from identity to audit replay?",
        "governance_nodes": AGENTTRUST_GOVERNANCE_NODES,
        "governance_edges": [
            {
                "source": source,
                "target": target,
                "relationship": relationship
            }
            for source, target, relationship in AGENTTRUST_GOVERNANCE_EDGES
        ],
        "control_ontology": AGENTTRUST_CONTROL_ONTOLOGY,
        "lineage_breaks": AGENTTRUST_LINEAGE_BREAKS,
        "minimum_trust_chain": [
            "Agent identity",
            "Trust contract",
            "Known dependencies",
            "Authority decision",
            "Tool-call evidence",
            "Human accountability",
            "Evidence package",
            "Monitoring signal",
            "Audit replay"
        ],
        "default_rule": "If any critical trust lineage link is missing, downgrade the agent action to human-gated, restricted, blocked, escalated, or quarantined"
    })

# ============================================================
# END AGENTTRUST_GOVERNANCE_GRAPH_LINEAGE_V1_ACTIVE
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

print("AgentTrust Governance Graph installed.")
print(f"Inserted before: {target_found}")
