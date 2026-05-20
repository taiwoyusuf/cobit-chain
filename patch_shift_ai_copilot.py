from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_AI_COPILOT_ACTIVE"

if MARKER in text:
    print("Shift AI Copilot already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_EXECUTIVE_STABILITY_FABRIC_ACTIVE",
    "SHIFT_EXECUTIVE_EQUILIBRIUM_ENGINE_ACTIVE",
    "SHIFT_EXECUTIVE_GOVERNANCE_PULSE_ACTIVE",
    "SHIFT_EXECUTIVE_CONTINUITY_MESH_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'

if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_AI_COPILOT_ACTIVE
# ShiftTrust™ Executive AI Copilot
# ============================================================

@app.route("/shift-ai-copilot")
def shift_ai_copilot():

    prompts = [
        {
            "scenario": "Peer unavailable during critical treatment window",
            "response": "Recommend backup activation and survivability escalation."
        },
        {
            "scenario": "Governance drift increasing across handoff chain",
            "response": "Recommend continuity stabilization review and escalation alignment."
        },
        {
            "scenario": "Human dependency concentration detected",
            "response": "Recommend resilience redistribution and operational balancing."
        },
        {
            "scenario": "Continuity pressure increasing",
            "response": "Recommend intervention simulation and equilibrium analysis."
        }
    ]

    rows = ''.join([
        f"""
        <tr>
            <td>{x["scenario"]}</td>
            <td>{x["response"]}</td>
        </tr>
        """
        for x in prompts
    ])

    body = f"""
    <div class="hero">
        <h1>ShiftTrust™ Executive AI Copilot</h1>

        <div class="sub">
            Conversational executive operational intelligence layer providing governance reasoning,
            survivability recommendations,
            continuity intervention simulation, and resilience decision assistance.
        </div>

        <div class="nav">
            <a href="/shift-executive-command-center">Executive Command Center</a>
            <a href="/shift-executive-stability-fabric">Stability Fabric</a>
            <a href="/shift-executive-equilibrium-engine">Equilibrium Engine</a>
            <a href="/shift-executive-governance-pulse">Governance Pulse</a>
            <a href="/shift-advanced">Advanced Launcher</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">AI Governance Reasoning</div><div class="value">ACTIVE</div></div>
        <div class="card"><div class="label">Continuity Intelligence</div><div class="value">LIVE</div></div>
        <div class="card"><div class="label">Operational Recommendations</div><div class="value">ENABLED</div></div>
        <div class="card"><div class="label">Executive Guidance</div><div class="value">STABLE</div></div>
    </div>

    <div class="section">
        <h2>Executive AI Decision Layer</h2>

        <div class="decision">
            SHIFTTRUST™ CAN PROVIDE EXECUTIVE GOVERNANCE REASONING ACROSS ENTERPRISE CONTINUITY DOMAINS
        </div>

        <p>
            ShiftTrust™ Executive AI Copilot transforms the executive ecosystem into an interactive
            operational intelligence platform capable of survivability reasoning,
            continuity simulation, governance stabilization recommendations,
            escalation interpretation, and resilience guidance generation.
        </p>
    </div>

    <div class="section">
        <h2>Executive AI Recommendation Matrix</h2>

        <table>
            <tr>
                <th>Operational Scenario</th>
                <th>AI Governance Recommendation</th>
            </tr>

            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>

        <div class="decision">
            SHIFTTRUST™ EVOLVES INTO AN INTERACTIVE EXECUTIVE OPERATIONAL INTELLIGENCE SYSTEM
        </div>

        <p>
            Traditional governance systems present static dashboards.
            ShiftTrust™ Executive AI Copilot introduces interactive governance reasoning,
            survivability simulation, continuity intervention guidance,
            operational equilibrium recommendations, and enterprise resilience intelligence assistance.
        </p>
    </div>
    """

    return rlt_page("ShiftTrust Executive AI Copilot", body)

'''

text = text.replace(insert_before, code + insert_before)

APP.write_text(text, encoding="utf-8")

print("Shift AI Copilot patch applied.")
