from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_SURVIVABILITY_INDEX_ACTIVE"

if MARKER in text:
    print("Shift Survivability Index already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_HUMAN_DEPENDENCY_CONCENTRATION_ENGINE_ACTIVE",
    "SHIFT_GOVERNANCE_DRIFT_INTELLIGENCE_ACTIVE",
    "SHIFT_ESCALATION_LINEAGE_ENGINE_ACTIVE",
    "SHIFT_OPERATIONAL_MEMORY_ENGINE_ACTIVE",
    "SHIFT_PEER_BACKUP_COVERAGE_RESILIENCE_ACTIVE",
    "SHIFT_OPERATIONAL_GRAVITY_ENGINE_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_SURVIVABILITY_INDEX_ACTIVE
# ShiftTrust™ Operational Survivability Index
# ============================================================

@app.route("/shift-survivability-index")
def shift_survivability_index():

    domains = [
        {"domain": "Treatment Continuity", "score": "91%", "state": "STABLE"},
        {"domain": "Peer Backup Resilience", "score": "94%", "state": "STRONG"},
        {"domain": "Operational Memory", "score": "92%", "state": "STABLE"},
        {"domain": "Escalation Lineage", "score": "89%", "state": "WATCH"},
        {"domain": "Governance Drift", "score": "82%", "state": "WATCH"},
        {"domain": "Human Dependency", "score": "76%", "state": "RISK"},
        {"domain": "Operational Gravity", "score": "88%", "state": "CONTROLLED"},
        {"domain": "Shift Topology Stability", "score": "93%", "state": "STRONG"},
    ]

    executive_actions = [
        {
            "action": "Reduce hidden dependency concentration",
            "effect": "Improves operational survivability stability"
        },
        {
            "action": "Strengthen escalation inheritance acknowledgement",
            "effect": "Prevents continuity drift"
        },
        {
            "action": "Monitor governance drift normalization signals",
            "effect": "Detects erosion before deviation exposure"
        },
        {
            "action": "Maintain two-person survivability coverage",
            "effect": "Protects operational continuity during absence"
        }
    ]

    rows = ''.join([
        f"""
        <tr>
            <td>{x["domain"]}</td>
            <td>{x["score"]}</td>
            <td><span class="pill">{x["state"]}</span></td>
        </tr>
        """
        for x in domains
    ])

    action_rows = ''.join([
        f"""
        <tr>
            <td>{x["action"]}</td>
            <td>{x["effect"]}</td>
        </tr>
        """
        for x in executive_actions
    ])

    body = f"""
    <div class="hero">
        <h1>ShiftTrust™ Operational Survivability Index</h1>

        <div class="sub">
            Executive-level survivability score for time-critical manufacturing support.
            Aggregates governance continuity, treatment timing confidence, escalation inheritance,
            operational memory, peer resilience, drift pressure, and human dependency concentration.
        </div>

        <div class="nav">
            <a href="/shift-mission-control">Mission Control</a>
            <a href="/shift-executive-summary">Executive Summary</a>
            <a href="/shift-governance-drift-intelligence">Governance Drift</a>
            <a href="/shift-human-dependency">Human Dependency</a>
            <a href="/shift-advanced">Advanced Launcher</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Operational Survivability</div><div class="value">88%</div></div>
        <div class="card"><div class="label">Governance Stability</div><div class="value">STABLE</div></div>
        <div class="card"><div class="label">Continuity Confidence</div><div class="value">91%</div></div>
        <div class="card"><div class="label">Executive Risk</div><div class="value">WATCH</div></div>
    </div>

    <div class="section">
        <h2>Executive Survivability Decision</h2>

        <div class="decision">
            SHIFTTRUST™ OPERATIONAL SURVIVABILITY REMAINS STABLE — HUMAN DEPENDENCY CONCENTRATION REQUIRES REDUCTION
        </div>

        <p>
            ShiftTrust™ Operational Survivability Index provides a single executive trust layer
            that summarizes whether the shift structure can sustain operational continuity under pressure.
        </p>
    </div>

    <div class="section">
        <h2>Operational Survivability Domains</h2>

        <table>
            <tr>
                <th>Governance Domain</th>
                <th>Confidence Score</th>
                <th>Operational State</th>
            </tr>

            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Stabilization Actions</h2>

        <table>
            <tr>
                <th>Leadership Action</th>
                <th>Expected Governance Effect</th>
            </tr>

            {action_rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>

        <div class="decision">
            SHIFTTRUST™ MEASURES WHETHER THE OPERATION CAN SURVIVE STRESS WITHOUT LOSING GOVERNANCE CONTROL
        </div>

        <p>
            Traditional shift systems measure staffing. ShiftTrust™ Operational Survivability Index
            measures whether operations remain governable, resilient, auditable, and continuity-safe
            during real-world manufacturing pressure.
        </p>
    </div>
    """

    return rlt_page("ShiftTrust Operational Survivability Index", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("Shift Operational Survivability Index patch applied.")
