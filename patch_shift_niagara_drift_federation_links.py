from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_NIAGARA_DRIFT_FEDERATION_LINKS_ACTIVE"

if MARKER in text:
    print("Niagara Drift Federation links already exist.")
    raise SystemExit(0)

if "SHIFT_NIAGARA_DRIFT_FEDERATION_ACTIVE" not in text:
    raise RuntimeError("Niagara Drift Federation marker missing.")

# ------------------------------------------------------------
# Executive Command Center nav
# ------------------------------------------------------------

target1 = '<a href="/shift-niagara-operational-trust-fabric">Operational Trust Fabric</a>'

insert1 = '''<!-- SHIFT_NIAGARA_DRIFT_FEDERATION_LINKS_ACTIVE -->
            <a href="/shift-niagara-operational-trust-fabric">Operational Trust Fabric</a>
            <a href="/shift-niagara-drift-federation">Niagara Drift Federation</a>'''

if target1 not in text:
    raise RuntimeError("Executive Command Center insertion point not found.")

text = text.replace(target1, insert1, 1)

# ------------------------------------------------------------
# Operational Trust Fabric nav
# ------------------------------------------------------------

target2 = '<a href="/shift-niagara-governance-decision-intelligence">Governance Decision Intelligence</a>'

insert2 = '''<a href="/shift-niagara-governance-decision-intelligence">Governance Decision Intelligence</a>
            <a href="/shift-niagara-drift-federation">Niagara Drift Federation</a>'''

if target2 not in text:
    raise RuntimeError("Operational Trust Fabric insertion point not found.")

text = text.replace(target2, insert2, 1)

# ------------------------------------------------------------
# Mission Control capability table
# ------------------------------------------------------------

target3 = '<tr><td>Operational Trust Fabric™</td><td>Provides governance trust propagation, survivability confidence telemetry, operational defensibility correlation, and resilience orchestration.</td><td><a href="/shift-niagara-operational-trust-fabric">Open</a></td></tr>'

insert3 = '''
            <tr><td>Niagara Drift Federation™</td><td>Provides governance drift federation, anomaly propagation analytics, survivability reasoning, and resilience telemetry orchestration.</td><td><a href="/shift-niagara-drift-federation">Open</a></td></tr>'''

if target3 not in text:
    raise RuntimeError("Mission Control insertion point not found.")

text = text.replace(target3, target3 + insert3, 1)

# ------------------------------------------------------------
# Executive Summary flow
# ------------------------------------------------------------

target4 = '<tr><td>38</td><td><a href="/shift-niagara-operational-trust-fabric">Operational Trust Fabric</a></td><td>This transforms fragmented governance telemetry into continuously federated operational trust intelligence.</td></tr>'

insert4 = '''
            <tr><td>39</td><td><a href="/shift-niagara-drift-federation">Niagara Drift Federation</a></td><td>This federates governance drift telemetry into continuously correlated enterprise resilience intelligence.</td></tr>'''

if target4 not in text:
    raise RuntimeError("Executive Summary insertion point not found.")

text = text.replace(target4, target4 + insert4, 1)

# ------------------------------------------------------------
# Advanced Launcher nav
# ------------------------------------------------------------

target5 = '<a href="/shift-niagara-operational-trust-fabric">Operational Trust Fabric</a>'

insert5 = '''<a href="/shift-niagara-operational-trust-fabric">Operational Trust Fabric</a>
            <a href="/shift-niagara-drift-federation">Niagara Drift Federation</a>'''

if target5 not in text:
    raise RuntimeError("Advanced Launcher insertion point not found.")

text = text.replace(target5, insert5, 1)

APP.write_text(text, encoding="utf-8")

print("Niagara Drift Federation links added.")
