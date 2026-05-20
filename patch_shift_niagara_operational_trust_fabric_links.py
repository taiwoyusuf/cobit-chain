from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_NIAGARA_OPERATIONAL_TRUST_FABRIC_LINKS_ACTIVE"

if MARKER in text:
    print("Operational Trust Fabric links already exist.")
    raise SystemExit(0)

if "SHIFT_NIAGARA_OPERATIONAL_TRUST_FABRIC_ACTIVE" not in text:
    raise RuntimeError("Operational Trust Fabric marker missing.")

# ------------------------------------------------------------
# Executive Command Center nav
# ------------------------------------------------------------

target1 = '<a href="/shift-niagara-governance-decision-intelligence">Governance Decision Intelligence</a>'

insert1 = '''<!-- SHIFT_NIAGARA_OPERATIONAL_TRUST_FABRIC_LINKS_ACTIVE -->
            <a href="/shift-niagara-governance-decision-intelligence">Governance Decision Intelligence</a>
            <a href="/shift-niagara-operational-trust-fabric">Operational Trust Fabric</a>'''

if target1 not in text:
    raise RuntimeError("Executive Command Center insertion point not found.")

text = text.replace(target1, insert1, 1)

# ------------------------------------------------------------
# Governance Decision Intelligence nav
# ------------------------------------------------------------

target2 = '<a href="/shift-niagara-evidence-lineage">Evidence Lineage</a>'

insert2 = '''<a href="/shift-niagara-evidence-lineage">Evidence Lineage</a>
            <a href="/shift-niagara-operational-trust-fabric">Operational Trust Fabric</a>'''

if target2 not in text:
    raise RuntimeError("Governance Decision Intelligence insertion point not found.")

text = text.replace(target2, insert2, 1)

# ------------------------------------------------------------
# Mission Control capability table
# ------------------------------------------------------------

target3 = '<tr><td>Governance Decision Intelligence™</td><td>Provides escalation analytics, governance intervention reasoning, approval defensibility telemetry, and operational trust orchestration.</td><td><a href="/shift-niagara-governance-decision-intelligence">Open</a></td></tr>'

insert3 = '''
            <tr><td>Operational Trust Fabric™</td><td>Provides governance trust propagation, survivability confidence telemetry, operational defensibility correlation, and resilience orchestration.</td><td><a href="/shift-niagara-operational-trust-fabric">Open</a></td></tr>'''

if target3 not in text:
    raise RuntimeError("Mission Control insertion point not found.")

text = text.replace(target3, target3 + insert3, 1)

# ------------------------------------------------------------
# Executive Summary flow
# ------------------------------------------------------------

target4 = '<tr><td>37</td><td><a href="/shift-niagara-governance-decision-intelligence">Governance Decision Intelligence</a></td><td>This transforms governance approvals into continuously correlated operational reasoning intelligence.</td></tr>'

insert4 = '''
            <tr><td>38</td><td><a href="/shift-niagara-operational-trust-fabric">Operational Trust Fabric</a></td><td>This transforms fragmented governance telemetry into continuously federated operational trust intelligence.</td></tr>'''

if target4 not in text:
    raise RuntimeError("Executive Summary insertion point not found.")

text = text.replace(target4, target4 + insert4, 1)

# ------------------------------------------------------------
# Advanced Launcher nav
# ------------------------------------------------------------

target5 = '<a href="/shift-niagara-governance-decision-intelligence">Governance Decision Intelligence</a>'

insert5 = '''<a href="/shift-niagara-governance-decision-intelligence">Governance Decision Intelligence</a>
            <a href="/shift-niagara-operational-trust-fabric">Operational Trust Fabric</a>'''

if target5 not in text:
    raise RuntimeError("Advanced Launcher insertion point not found.")

text = text.replace(target5, insert5, 1)

APP.write_text(text, encoding="utf-8")

print("Operational Trust Fabric links added.")
