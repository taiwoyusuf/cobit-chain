from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_MISSION_CONTROL_ACTIVE"

if MARKER in text:
    print("Shift Mission Control already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_AUTONOMOUS_CONTINUITY_INTELLIGENCE_ACTIVE",
    "SHIFT_TREATMENT_CONTINUITY_RISK_ENGINE_ACTIVE",
    "SHIFT_PEER_BACKUP_COVERAGE_RESILIENCE_ACTIVE",
    "SHIFT_TOPOLOGY_INTELLIGENCE_ACTIVE",
    "SHIFT_ROTATION_DIGITAL_TWIN_ACTIVE",
    "SHIFT_GOVERNANCE_FATIGUE_HEATMAP_ACTIVE",
    "SHIFT_TREATMENT_WINDOW_COMPRESSION_ACTIVE",
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
# SHIFT_MISSION_CONTROL_ACTIVE
# ShiftTrust™ Mission Control
# Consolidated executive command page for advanced ShiftTrust™
# ============================================================

@app.route("/shift-mission-control")
def shift_mission_control():
    body = """
    <div class="hero">
        <h1>ShiftTrust™ Mission Control</h1>
        <div class="sub">
            Executive command surface for time-critical manufacturing support continuity, peer backup resilience,
            treatment-window protection, operational gravity, governance fatigue, and workforce continuity simulation.
        </div>
        <div class="nav">
            <a href="/shift-advanced">Advanced Launcher</a>
            <a href="/shift-treatment-continuity">Treatment Continuity</a>
            <a href="/shift-operational-gravity">Operational Gravity</a>
            <a href="/shift-treatment-window-compression">Window Compression</a>
            <a href="/command-center">Enterprise Command Center</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Operational Trust Pulse</div><div class="value">90%</div></div>
        <div class="card"><div class="label">Treatment Continuity</div><div class="value">84%</div></div>
        <div class="card"><div class="label">Coverage Resilience</div><div class="value">92%</div></div>
        <div class="card"><div class="label">Topology Stability</div><div class="value">93%</div></div>
        <div class="card"><div class="label">Governance Fatigue</div><div class="value" style="font-size:24px;">MED-HIGH</div></div>
        <div class="card"><div class="label">Operational Gravity Pull</div><div class="value">31%</div></div>
        <div class="card"><div class="label">Window Compression</div><div class="value">18%</div></div>
        <div class="card"><div class="label">Rotation Readiness</div><div class="value">86%</div></div>
    </div>

    <div class="section">
        <h2>Mission Decision</h2>
        <div class="decision">SHIFT MODEL IS GOVERNABLE — CLOSE OWNERSHIP, WALKAROUND, AND LABELER WATCH ITEMS BEFORE PRESSURE SPREADS</div>
        <p>
            ShiftTrust™ Mission Control does not manage HR scheduling. It evaluates whether the operating shift
            structure can preserve manufacturing support, peer backup, handoff inheritance, treatment-window timing,
            and operational trust during real-world pressure.
        </p>
    </div>

    <div class="section">
        <h2>Advanced ShiftTrust™ Capability Map</h2>
        <table>
            <tr><th>Capability</th><th>What It Proves</th><th>Open</th></tr>
            <tr><td>Autonomous Continuity Intelligence™</td><td>Whether operational memory, evidence, escalation, and readiness survive shift handoff.</td><td><a href="/shift-autonomous-continuity">Open</a></td></tr>
            <tr><td>Treatment Continuity Risk Engine™</td><td>Whether shift-support issues could threaten downstream treatment timing.</td><td><a href="/shift-treatment-continuity">Open</a></td></tr>
            <tr><td>Peer Backup & Coverage Resilience™</td><td>Whether two-person minimum coverage and backup survivability remain intact.</td><td><a href="/shift-peer-backup">Open</a></td></tr>
            <tr><td>Shift Topology Intelligence™</td><td>Whether the permanent A/B/C/D shift structure is governable long-term.</td><td><a href="/shift-topology">Open</a></td></tr>
            <tr><td>Workforce Continuity Digital Twin™</td><td>Whether future rotation can happen without breaking coverage, memory, or continuity.</td><td><a href="/shift-rotation-digital-twin">Open</a></td></tr>
            <tr><td>Governance Fatigue Heatmap™</td><td>Where operational pressure is accumulating before continuity weakens.</td><td><a href="/shift-governance-fatigue">Open</a></td></tr>
            <tr><td>Treatment Window Compression Simulator™</td><td>How unresolved support issues consume the timing buffer for release, courier, and treatment readiness.</td><td><a href="/shift-treatment-window-compression">Open</a></td></tr>
            <tr><td>Operational Gravity Engine™</td><td>Which unresolved issue is pulling the whole operation toward instability.</td><td><a href="/shift-operational-gravity">Open</a></td></tr>
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>
        <p>
            Most shift tools answer: who is working? ShiftTrust™ answers a more important Pharma IT question:
            can the operation remain governable if a shift is missed, handoff pressure increases, unresolved issues
            carry forward, night coverage becomes strained, or treatment-window timing starts compressing?
        </p>
    </div>
    """

    return rlt_page("ShiftTrust Mission Control", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("Shift Mission Control patch applied.")
