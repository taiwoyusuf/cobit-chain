from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

ACTIVE_MARKER = "RLT_OPERATIONS_MODULES_DIRECTORY_ACTIVE"

if ACTIVE_MARKER in text:
    print("RLT Modules Directory registration already exists. No duplicate patch applied.")
    raise SystemExit(0)

required = [
    "RLT_OPERATIONS_VERTICAL_ACTIVE",
    'href="/rlt-operations"',
    "DR_BRANCH_MODULES_DIRECTORY_ACTIVE",
    "ROAT_MODULES_DIRECTORY_REGISTRATION_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required existing marker/link not found: {item}")

target = '''
<div class="section">
<h2>Tier 1 Life Sciences Modules</h2>
<div class="grid">
'''

if target not in text:
    raise RuntimeError("Could not find Tier 1 Life Sciences Modules insertion point.")

rlt_section = '''
<!-- RLT_OPERATIONS_MODULES_DIRECTORY_ACTIVE -->
<div class="section">
<h2>RLT Operations AssuranceLayer™</h2>
<p style="color:#a8c7dc;line-height:1.6;max-width:980px;">
Operational Trust & Governance Intelligence for Radioligand Manufacturing. This vertical focuses on production readiness,
manufacturing trust, deviation blast-radius visibility, and operational risk intelligence for time-sensitive RLT operations.
</p>
<div class="grid">
<div class="module-card"><span class="badge twin">RLT MISSION CONTROL</span><h3>RLT Operations Mission Control™</h3><p>Executive command surface for radioligand manufacturing readiness, operational trust, governance integrity, deviation probability, environmental stability, and audit readiness.</p><a href="/rlt-operations">Open Mission Control</a></div>
<div class="module-card"><span class="badge assurance">READINESS ENGINE</span><h3>Operational Readiness Assurance Engine™</h3><p>Determines whether RLT manufacturing operations are trustworthy enough to proceed by evaluating SOP currency, CAPA exposure, training validity, backup verification, audit trail review, and shift handoff integrity.</p><a href="/rlt-operations/readiness">Open Readiness Engine</a></div>
<div class="module-card"><span class="badge assurance">TRUST SCORE</span><h3>Manufacturing Trust Score™</h3><p>Calculates operational trustworthiness using evidence integrity, documentation completeness, governance stability, audit readiness, and unresolved operational risk indicators.</p><a href="/rlt-operations/trust-score">Open Trust Score</a></div>
<div class="module-card"><span class="badge recovery">BLAST RADIUS</span><h3>Deviation Blast Radius Intelligence™</h3><p>Maps how an RLT deviation or operational issue may affect equipment, batches, shifts, SOPs, operators, reviewers, and release exposure.</p><a href="/rlt-operations/blast-radius">Open Blast Radius</a></div>
<div class="module-card"><span class="badge recovery">RISK HEAT MAP</span><h3>Operational Risk Heat Map</h3><p>Displays executive-level governance risk across isolator readiness, environmental monitoring, shift handoff governance, audit trail review, SOP alignment, and CAPA exposure.</p><a href="/rlt-operations/risk-heatmap">Open Risk Heat Map</a></div>
</div>
</div>

'''

text = text.replace(target, rlt_section + target)

APP.write_text(text, encoding="utf-8")

print("RLT Modules Directory registration patch applied successfully.")
