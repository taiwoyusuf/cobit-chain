from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "SHIFT_EXECUTIVE_NARRATIVE_GENERATOR_LINKS_ACTIVE"

if MARKER in text:
    print("Executive Narrative Generator links already exist.")
    raise SystemExit(0)

if "SHIFT_EXECUTIVE_NARRATIVE_GENERATOR_ACTIVE" not in text:
    raise RuntimeError("Executive Narrative Generator marker missing.")

# ------------------------------------------------------------
# Executive Command Center nav
# ------------------------------------------------------------

target1 = '<a href="/shift-operational-collapse-forecast">Operational Collapse Forecast</a>'

insert1 = '''<!-- SHIFT_EXECUTIVE_NARRATIVE_GENERATOR_LINKS_ACTIVE -->
            <a href="/shift-operational-collapse-forecast">Operational Collapse Forecast</a>
            <a href="/shift-executive-narrative-generator">Executive Narrative Generator</a>'''

if target1 not in text:
    raise RuntimeError("Executive Command Center nav insertion point not found.")

text = text.replace(target1, insert1, 1)

# ------------------------------------------------------------
# Operational Collapse nav
# ------------------------------------------------------------

target2 = '<a href="/shift-executive-intervention-simulator">Executive Intervention</a>'

insert2 = '''<a href="/shift-executive-intervention-simulator">Executive Intervention</a>
            <a href="/shift-executive-narrative-generator">Executive Narrative Generator</a>'''

if target2 not in text:
    raise RuntimeError("Operational Collapse nav insertion point not found.")

text = text.replace(target2, insert2, 1)

# ------------------------------------------------------------
# Mission Control capability table
# ------------------------------------------------------------

target3 = '<tr><td>Operational Collapse Forecast™</td><td>Predicts which governance weakness collapses first during survivability degradation and continuity instability.</td><td><a href="/shift-operational-collapse-forecast">Open</a></td></tr>'

insert3 = '''
            <tr><td>Executive Narrative Generator™</td><td>Automatically converts survivability intelligence into leadership-ready governance narratives and executive talking points.</td><td><a href="/shift-executive-narrative-generator">Open</a></td></tr>'''

if target3 not in text:
    raise RuntimeError("Mission Control insertion point not found.")

text = text.replace(target3, target3 + insert3, 1)

# ------------------------------------------------------------
# Executive Summary flow
# ------------------------------------------------------------

target4 = '<tr><td>14</td><td><a href="/shift-operational-collapse-forecast">Operational Collapse Forecast</a></td><td>This predicts which governance weakness collapses first during operational pressure.</td></tr>'

insert4 = '''
            <tr><td>15</td><td><a href="/shift-executive-narrative-generator">Executive Narrative Generator</a></td><td>This automatically creates leadership-ready continuity and governance narratives.</td></tr>'''

if target4 not in text:
    raise RuntimeError("Executive Summary insertion point not found.")

text = text.replace(target4, target4 + insert4, 1)

# ------------------------------------------------------------
# Advanced Launcher nav
# ------------------------------------------------------------

target5 = '<a href="/shift-operational-collapse-forecast">Operational Collapse Forecast</a>'

insert5 = '''<a href="/shift-operational-collapse-forecast">Operational Collapse Forecast</a>
            <a href="/shift-executive-narrative-generator">Executive Narrative Generator</a>'''

if target5 not in text:
    raise RuntimeError("Advanced Launcher nav insertion point not found.")

text = text.replace(target5, insert5, 1)

APP.write_text(text, encoding="utf-8")

print("Executive Narrative Generator links added.")
