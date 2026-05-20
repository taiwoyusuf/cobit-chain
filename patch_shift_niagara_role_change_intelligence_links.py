from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_NIAGARA_ROLE_CHANGE_INTELLIGENCE_LINKS_ACTIVE"

if MARKER in text:
    print("Niagara Role Change Intelligence links already exist.")
    raise SystemExit(0)

if "SHIFT_NIAGARA_ROLE_CHANGE_INTELLIGENCE_ACTIVE" not in text:
    raise RuntimeError("Niagara Role Change Intelligence marker missing.")

# ------------------------------------------------------------
# Executive Command Center nav
# ------------------------------------------------------------

target1 = '<a href="/shift-niagara-backup-resilience">Niagara Backup Resilience</a>'

insert1 = '''<!-- SHIFT_NIAGARA_ROLE_CHANGE_INTELLIGENCE_LINKS_ACTIVE -->
            <a href="/shift-niagara-backup-resilience">Niagara Backup Resilience</a>
            <a href="/shift-niagara-role-change-intelligence">Niagara Role Change Intelligence</a>'''

if target1 not in text:
    raise RuntimeError("Executive Command Center insertion point not found.")

text = text.replace(target1, insert1, 1)

# ------------------------------------------------------------
# Niagara Backup Resilience nav
# ------------------------------------------------------------

target2 = '<a href="/shift-niagara-access-intelligence">Niagara Access Intelligence</a>'

insert2 = '''<a href="/shift-niagara-access-intelligence">Niagara Access Intelligence</a>
            <a href="/shift-niagara-role-change-intelligence">Niagara Role Change Intelligence</a>'''

if target2 not in text:
    raise RuntimeError("Niagara Backup Resilience insertion point not found.")

text = text.replace(target2, insert2, 1)

# ------------------------------------------------------------
# Mission Control capability table
# ------------------------------------------------------------

target3 = '<tr><td>Niagara Backup Resilience™</td><td>Provides recovery defensibility analytics, restoration confidence scoring, survivability telemetry, and continuity readiness intelligence.</td><td><a href="/shift-niagara-backup-resilience">Open</a></td></tr>'

insert3 = '''
            <tr><td>Niagara Role Change Intelligence™</td><td>Provides privilege escalation analytics, approval lineage telemetry, segregation-of-duty defensibility, and operational trust orchestration.</td><td><a href="/shift-niagara-role-change-intelligence">Open</a></td></tr>'''

if target3 not in text:
    raise RuntimeError("Mission Control insertion point not found.")

text = text.replace(target3, target3 + insert3, 1)

# ------------------------------------------------------------
# Executive Summary flow
# ------------------------------------------------------------

target4 = '<tr><td>34</td><td><a href="/shift-niagara-backup-resilience">Niagara Backup Resilience</a></td><td>This transforms backup governance into operational recovery intelligence and survivability analytics.</td></tr>'

insert4 = '''
            <tr><td>35</td><td><a href="/shift-niagara-role-change-intelligence">Niagara Role Change Intelligence</a></td><td>This transforms role governance into privilege escalation analytics and approval lineage intelligence.</td></tr>'''

if target4 not in text:
    raise RuntimeError("Executive Summary insertion point not found.")

text = text.replace(target4, target4 + insert4, 1)

# ------------------------------------------------------------
# Advanced Launcher nav
# ------------------------------------------------------------

target5 = '<a href="/shift-niagara-backup-resilience">Niagara Backup Resilience</a>'

insert5 = '''<a href="/shift-niagara-backup-resilience">Niagara Backup Resilience</a>
            <a href="/shift-niagara-role-change-intelligence">Niagara Role Change Intelligence</a>'''

if target5 not in text:
    raise RuntimeError("Advanced Launcher insertion point not found.")

text = text.replace(target5, insert5, 1)

APP.write_text(text, encoding="utf-8")

print("Niagara Role Change Intelligence links added.")
