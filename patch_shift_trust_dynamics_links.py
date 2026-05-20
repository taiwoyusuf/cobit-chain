from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_EXECUTIVE_TRUST_DYNAMICS_LINKS_ACTIVE"

if MARKER in text:
    print("Executive Trust Dynamics links already exist.")
    raise SystemExit(0)

if "SHIFT_EXECUTIVE_TRUST_DYNAMICS_ACTIVE" not in text:
    raise RuntimeError("Executive Trust Dynamics marker missing.")

# ------------------------------------------------------------
# Executive Command Center nav
# ------------------------------------------------------------

target1 = '<a href="/shift-executive-recovery-intelligence">Executive Recovery Intelligence</a>'

insert1 = '''<!-- SHIFT_EXECUTIVE_TRUST_DYNAMICS_LINKS_ACTIVE -->
            <a href="/shift-executive-recovery-intelligence">Executive Recovery Intelligence</a>
            <a href="/shift-executive-trust-dynamics">Executive Trust Dynamics</a>'''

if target1 not in text:
    raise RuntimeError("Executive Command Center insertion point not found.")

text = text.replace(target1, insert1, 1)

# ------------------------------------------------------------
# Recovery Intelligence nav
# ------------------------------------------------------------

target2 = '<a href="/shift-executive-stability-engine">Stability Engine</a>'

insert2 = '''<a href="/shift-executive-stability-engine">Stability Engine</a>
            <a href="/shift-executive-trust-dynamics">Executive Trust Dynamics</a>'''

if target2 not in text:
    raise RuntimeError("Recovery Intelligence insertion point not found.")

text = text.replace(target2, insert2, 1)

# ------------------------------------------------------------
# Mission Control capability table
# ------------------------------------------------------------

target3 = '<tr><td>Executive Recovery Intelligence™</td><td>Forecasts governance rebound, survivability restoration, escalation recovery, and enterprise operational recovery confidence.</td><td><a href="/shift-executive-recovery-intelligence">Open</a></td></tr>'

insert3 = '''
            <tr><td>Executive Trust Dynamics™</td><td>Forecasts operational trust propagation, governance trust resilience, survivability trust equilibrium, and continuity trust stability.</td><td><a href="/shift-executive-trust-dynamics">Open</a></td></tr>'''

if target3 not in text:
    raise RuntimeError("Mission Control insertion point not found.")

text = text.replace(target3, target3 + insert3, 1)

# ------------------------------------------------------------
# Executive Summary flow
# ------------------------------------------------------------

target4 = '<tr><td>23</td><td><a href="/shift-executive-recovery-intelligence">Executive Recovery Intelligence</a></td><td>This forecasts continuity restoration and governance recovery confidence.</td></tr>'

insert4 = '''
            <tr><td>24</td><td><a href="/shift-executive-trust-dynamics">Executive Trust Dynamics</a></td><td>This forecasts operational trust propagation and governance trust equilibrium.</td></tr>'''

if target4 not in text:
    raise RuntimeError("Executive Summary insertion point not found.")

text = text.replace(target4, target4 + insert4, 1)

# ------------------------------------------------------------
# Advanced Launcher nav
# ------------------------------------------------------------

target5 = '<a href="/shift-executive-recovery-intelligence">Executive Recovery Intelligence</a>'

insert5 = '''<a href="/shift-executive-recovery-intelligence">Executive Recovery Intelligence</a>
            <a href="/shift-executive-trust-dynamics">Executive Trust Dynamics</a>'''

if target5 not in text:
    raise RuntimeError("Advanced Launcher insertion point not found.")

text = text.replace(target5, insert5, 1)

APP.write_text(text, encoding="utf-8")

print("Executive Trust Dynamics links added.")
