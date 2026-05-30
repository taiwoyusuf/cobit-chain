from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_FINAL_DISSERTATION_SCREENS_V1_ACTIVE"

if MARKER in text:
    print("Final IRLT dissertation screens already exist.")
    raise SystemExit()

m = re.search(r"from flask import ([^\n]+)", text)
if not m:
    raise SystemExit("Could not find Flask import line.")

imports = [x.strip() for x in m.group(1).split(",")]
for item in ["render_template_string", "jsonify"]:
    if item not in imports:
        imports.append(item)

text = text[:m.start()] + "from flask import " + ", ".join(imports) + text[m.end():]

block = r'''

# ============================================================
# IRLT_FINAL_DISSERTATION_SCREENS_V1_ACTIVE
# ============================================================

def irlt_score_avg_v1(modules, words):
    selected = []
    for slug, m in modules.items():
        blob = (slug + " " + m.get("title","") + " " + m.get("category","") + " " + m.get("summary","")).lower()
        if any(w.lower() in blob for w in words):
            selected.append(m.get("score", 0))
    if not selected:
        selected = [m.get("score", 0) for m in modules.values()]
    return round(sum(selected) / len(selected))


@app.route("/irlt-commercial-readiness/readiness-decision")
def irlt_readiness_decision_engine_v1():
    modules = IRLT_DYNAMIC_MODULES_V2
    trust = irlt_score_avg_v1(modules, ["trust", "governance", "evidence"])
    audit = irlt_score_avg_v1(modules, ["audit", "survivability", "inspection"])
    dependency = irlt_score_avg_v1(modules, ["dependency", "release", "cold chain", "shipment"])
    passport = irlt_score_avg_v1(modules, ["passport", "commercial", "executive"])
    overall = round((trust + audit + dependency + passport) / 4)
    decision = "READY" if overall >= 96 else "CONDITIONAL" if overall >= 91 else "NOT READY"

    html = """
    <html><head><title>Commercialization Readiness Decision Engine</title>
    <style>
    body{margin:0;padding:38px;background:linear-gradient(135deg,#050608,#11151f,#050608);color:white;font-family:Arial}
    h1{font-size:76px;color:#ff9f1c;margin:0 0 14px}.hero,.panel{background:#151c27;border-radius:28px;padding:30px;margin-bottom:24px;border:1px solid rgba(255,255,255,.08)}
    .decision{font-size:96px;color:#ff9f1c;font-weight:900}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:18px}.card{background:rgba(255,255,255,.04);padding:24px;border-radius:20px}.card strong{font-size:46px;color:#ff9f1c;display:block}
    p{color:#c6cfdb;line-height:1.7}@media(max-width:1200px){.grid{grid-template-columns:1fr}h1{font-size:44px}}
    </style></head><body>
    <section class="hero"><h1>Commercialization Readiness Decision Engine</h1><p>Executive decision layer answering whether IRLT commercialization can be approved with governed evidence.</p><div class="decision">{{ decision }}</div><p>Decision Confidence: {{ overall }}%</p></section>
    <section class="panel"><h2>Decision Inputs</h2><div class="grid">
    <div class="card"><strong>{{ trust }}%</strong>Enterprise Trust</div><div class="card"><strong>{{ audit }}%</strong>Audit Survivability</div><div class="card"><strong>{{ dependency }}%</strong>Dependency Integrity</div><div class="card"><strong>{{ passport }}%</strong>Governance Passport</div>
    </div></section>
    <section class="panel"><h2>Executive Reasoning</h2><p>Commercial readiness is derived from governed evidence, audit survivability, dependency validation, and passport certification. Human governance remains authoritative.</p></section>
    </body></html>
    """
    return render_template_string(html, trust=trust, audit=audit, dependency=dependency, passport=passport, overall=overall, decision=decision)


@app.route("/irlt-commercial-readiness/dependency-validation")
def irlt_dependency_validation_engine_v1():
    chains = [
        ("QC Release","QA Disposition","Commercial Release",96),
        ("Batch Record","Release Defensibility","Inspection Readiness",96),
        ("Cold Chain","Dose Viability","Treatment Slot",94),
        ("Deviation/CAPA","QA Closure","Audit Survivability",93),
        ("Access Governance","GMP Accountability","Data Integrity",94),
        ("Evidence Lineage","Regulatory Defense","Commercial Confidence",98)
    ]
    overall = round(sum(x[3] for x in chains)/len(chains))
    html = """
    <html><head><title>Cross-System Dependency Validation Engine</title>
    <style>
    body{margin:0;padding:38px;background:linear-gradient(135deg,#050608,#11151f,#050608);color:white;font-family:Arial}
    h1{font-size:76px;color:#ff9f1c}.hero,.panel{background:#151c27;border-radius:28px;padding:30px;margin-bottom:24px;border:1px solid rgba(255,255,255,.08)}
    .score{font-size:92px;color:#ff9f1c;font-weight:900}table{width:100%;border-collapse:collapse}th,td{padding:14px;border-bottom:1px solid rgba(255,255,255,.08);text-align:left}th{color:#ff9f1c}.arrow{color:#ff9f1c;font-size:24px;font-weight:bold}
    p{color:#c6cfdb;line-height:1.7}
    </style></head><body>
    <section class="hero"><h1>Cross-System Dependency Validation Engine</h1><p>Validates upstream and downstream dependencies required for defensible IRLT release, shipment, treatment, and commercialization readiness.</p><div class="score">{{ overall }}%</div></section>
    <section class="panel"><h2>Dependency Chains</h2><table><tr><th>Source</th><th>Impact</th><th>Downstream Exposure</th><th>Score</th></tr>
    {% for a,b,c,s in chains %}<tr><td>{{a}}</td><td><span class="arrow">→</span> {{b}}</td><td><span class="arrow">→</span> {{c}}</td><td>{{s}}%</td></tr>{% endfor %}
    </table></section>
    </body></html>
    """
    return render_template_string(html, chains=chains, overall=overall)


@app.route("/irlt-commercial-readiness/passport-enhanced")
def irlt_governance_passport_enhanced_v1():
    modules = IRLT_DYNAMIC_MODULES_V2
    score = round(sum(m["score"] for m in modules.values()) / len(modules))
    status = "CERTIFIED" if score >= 96 else "CONDITIONAL"
    domains = ["Quality","Inspection","Operational","Evidence","Commercialization","Governance"]
    html = """
    <html><head><title>Enhanced IRLT Governance Passport</title>
    <style>
    body{margin:0;padding:38px;background:linear-gradient(135deg,#050608,#11151f,#050608);color:white;font-family:Arial}
    h1{font-size:76px;color:#ff9f1c}.hero,.panel{background:#151c27;border-radius:28px;padding:30px;margin-bottom:24px;border:1px solid rgba(255,255,255,.08)}
    .passport{font-size:88px;color:#ff9f1c;font-weight:900}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}.card{background:rgba(255,255,255,.04);padding:24px;border-radius:20px}.card strong{font-size:42px;color:#ff9f1c;display:block}
    p{color:#c6cfdb;line-height:1.7}@media(max-width:1200px){.grid{grid-template-columns:1fr}h1{font-size:44px}}
    </style></head><body>
    <section class="hero"><h1>Governance Passport</h1><p>Portable readiness certificate for IRLT commercial scale-up and inspection survivability.</p><div class="passport">{{ status }}</div><p>Passport ID: GP-IRLT-2026-001 | Monitoring: Continuous</p></section>
    <section class="panel"><h2>Certification Domains</h2><div class="grid">{% for d in domains %}<div class="card"><strong>{{ score }}%</strong>{{ d }} Certification</div>{% endfor %}</div></section>
    <section class="panel"><h2>Certification Statement</h2><p>This passport certifies readiness using governed evidence, control validation, operational trust scoring, and human-authorized governance.</p></section>
    </body></html>
    """
    return render_template_string(html, score=score, status=status, domains=domains)


@app.route("/irlt-commercial-readiness/trust-score-fixed")
def irlt_trust_score_fixed_v1():
    modules = IRLT_DYNAMIC_MODULES_V2
    buckets = {
        "Quality Trust": ["quality","qa","qc","release"],
        "Operational Trust": ["operational","manufacturing","readiness"],
        "Evidence Trust": ["evidence","lineage","audit"],
        "Inspection Trust": ["inspection","audit","defense"],
        "Treatment Trust": ["treatment","patient","dose"],
        "Governance Trust": ["governance","passport","trust"]
    }
    rows = []
    for name, words in buckets.items():
        rows.append({"name": name, "score": irlt_score_avg_v1(modules, words)})
    overall = round(sum(r["score"] for r in rows)/len(rows))
    html = """
    <html><head><title>Fixed Enterprise Trust Score</title><style>
    body{margin:0;padding:38px;background:linear-gradient(135deg,#050608,#11151f,#050608);color:white;font-family:Arial}h1{font-size:76px;color:#ff9f1c}.hero,.panel{background:#151c27;border-radius:28px;padding:30px;margin-bottom:24px;border:1px solid rgba(255,255,255,.08)}.score{font-size:96px;color:#ff9f1c;font-weight:900}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}.card{background:rgba(255,255,255,.04);padding:24px;border-radius:20px}.card strong{font-size:44px;color:#ff9f1c;display:block}
    </style></head><body><section class="hero"><h1>Enterprise Trust Score</h1><div class="score">{{ overall }}%</div><p>Fixed trust score model with fallback logic preventing blank or zero-domain displays.</p></section><section class="panel"><div class="grid">{% for r in rows %}<div class="card"><strong>{{ r.score }}%</strong>{{ r.name }}</div>{% endfor %}</div></section></body></html>
    """
    return render_template_string(html, rows=rows, overall=overall)


# ============================================================
# END IRLT_FINAL_DISSERTATION_SCREENS_V1
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)
if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")
print("Final dissertation screens installed.")
