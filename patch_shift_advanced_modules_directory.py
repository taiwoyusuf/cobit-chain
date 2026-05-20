from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_ADVANCED_MODULES_DIRECTORY_ACTIVE"

if MARKER in text:
    print("ShiftTrust advanced modules already registered.")
    raise SystemExit(0)

required = [
    "SHIFT_AUTONOMOUS_CONTINUITY_INTELLIGENCE_ACTIVE",
    "SHIFT_TREATMENT_CONTINUITY_RISK_ENGINE_ACTIVE",
    "SHIFT_PEER_BACKUP_COVERAGE_RESILIENCE_ACTIVE",
    "SHIFT_TOPOLOGY_INTELLIGENCE_ACTIVE",
    "SHIFT_ROTATION_DIGITAL_TWIN_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

anchor = '<!-- RLT_OPERATIONS_MODULES_DIRECTORY_ACTIVE -->'
if anchor not in text:
    raise RuntimeError("Could not find Modules Directory RLT anchor.")

section = '''
<!-- SHIFT_ADVANCED_MODULES_DIRECTORY_ACTIVE -->
<div class="section">
<h2>ShiftTrust™ Advanced Operational Continuity Intelligence</h2>
<p style="color:#a8c7dc;line-height:1.6;max-width:980px;">
Advanced ShiftTrust™ modules for time-critical manufacturing support, treatment-continuity risk,
peer backup resilience, permanent shift topology, workforce continuity simulation, and autonomous
operational trust intelligence.
</p>
<div class="grid">
<div class="module-card"><span class="badge strategy">CONTINUITY AI</span><h3>Autonomous Continuity Intelligence™</h3><p>Converts daily production IT checks, handover notes, backup verification, walkaround findings, training, and triage into live operational trust signals.</p><a href="/shift-autonomous-continuity">Open Continuity Engine</a></div>
<div class="module-card"><span class="badge flagship">PATIENT-AWARE</span><h3>Treatment Continuity Risk Engine™</h3><p>Links shift operations, manufacturing support, shelf-life pressure, peer coverage, and treatment-window confidence into one patient-aware operational trust model.</p><a href="/shift-treatment-continuity">Open Treatment Continuity</a></div>
<div class="module-card"><span class="badge assurance">PEER RESILIENCE</span><h3>Peer Backup & Coverage Resilience Engine™</h3><p>Models two-person minimum coverage, backup peer activation, missed-shift recovery, continuity inheritance, and operational survivability.</p><a href="/shift-peer-backup">Open Peer Backup</a></div>
<div class="module-card"><span class="badge recovery">SHIFT TOPOLOGY</span><h3>Shift Topology Intelligence™</h3><p>Models permanent A1/B1/C1/D1 and A2/B2/C2/D2 shift structure as an operational continuity architecture, not only a schedule.</p><a href="/shift-topology">Open Shift Topology</a></div>
<div class="module-card"><span class="badge twin">DIGITAL TWIN</span><h3>Workforce Continuity Digital Twin™</h3><p>Simulates future rotation impact on peer redundancy, night-shift burden, backup survivability, operational memory, and treatment-continuity support.</p><a href="/shift-rotation-digital-twin">Open Workforce Twin</a></div>
</div>
</div>

'''

text = text.replace(anchor, section + anchor, 1)
APP.write_text(text, encoding="utf-8")

print("ShiftTrust advanced modules added to Modules Directory.")
