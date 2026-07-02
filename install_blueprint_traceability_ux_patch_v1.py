from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_BLUEPRINT_TRACEABILITY_UX_PATCH_V1_ACTIVE"

patch_summary = {
    "patch_marker": PATCH_MARKER,
    "patch_type": "blueprint_traceability_ux_patch_not_new_module",
    "architecture_change": False,
    "new_module": False,
    "new_route": False,
    "purpose": "Render existing blueprint evidence traceability matrices directly on the AI-enabled CMC and Agentic Enterprise blueprint pages.",
    "traceability_flow": [
        "Blueprint Question",
        "Lifecycle Stage",
        "Evidence Object",
        "Owner / Reviewer",
        "Monitoring Signal",
        "Trust Impact"
    ],
    "platform_rule": "No new module. No new route. No architecture change. This patch only improves UX and evidence automation visibility."
}

def remove_marker_block(text):
    start = f"<!-- {PATCH_MARKER} -->"
    end = f"<!-- END {PATCH_MARKER} -->"
    return re.sub(re.escape(start) + r".*?" + re.escape(end), "", text, flags=re.DOTALL)

def patch_file(path, block, anchor):
    p = Path(path)
    if not p.exists():
        print(f"SKIP: {path} not found.")
        return False

    text = p.read_text(encoding="utf-8")
    text = remove_marker_block(text)

    wrapped = f"\n<!-- {PATCH_MARKER} -->\n{block}\n<!-- END {PATCH_MARKER} -->\n"

    if anchor in text:
        text = text.replace(anchor, wrapped + "\n" + anchor, 1)
    else:
        text = text.replace("</body>", wrapped + "\n</body>", 1)

    p.write_text(text, encoding="utf-8")
    print(f"PATCHED: {path}")
    return True

def patch_seed_marker():
    p = Path("platform_blueprint_library_seed.json")
    if not p.exists():
        print("SKIP: platform_blueprint_library_seed.json not found.")
        return False

    data = json.loads(p.read_text(encoding="utf-8"))
    data["blueprint_traceability_ux_patch"] = patch_summary

    for bp in data.get("blueprints", []) or []:
        bp["traceability_ux_status"] = {
            "visible_on_blueprint_page": True,
            "architecture_change": False,
            "new_module": False,
            "new_route": False,
            "traceability_flow": patch_summary["traceability_flow"]
        }

    p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    print("PATCHED: platform_blueprint_library_seed.json")
    return True

cmc_traceability_block = r'''
<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">Live CMC Evidence Traceability</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                This table connects each AI-enabled CMC blueprint question to the existing lifecycle stage, evidence object, owner, reviewer, monitoring signal, and operational trust impact.
            </div>
        </div>
        <span class="tag">Question -> Evidence -> Trust</span>
    </div>

    <div class="grid" id="cmcTraceabilityMatrix">
        <div class="panel"><strong>Loading traceability matrix...</strong><div>Calling existing AI-enabled CMC blueprint API.</div></div>
    </div>
</section>

<script>
(function(){
    function esc(value){
        if(value === null || value === undefined){ return ""; }
        return String(value).replace(/[&<>"']/g, function(c){
            return {"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c];
        });
    }

    function card(row, index){
        return `<div class="panel">
            <strong>${index + 1}. ${esc(row.question)}</strong>
            <div>
                <b>Lifecycle Stage:</b> ${esc(row.lifecycle_stage)}<br>
                <b>Evidence Object:</b> ${esc(row.evidence_object)}<br>
                <b>Owner:</b> ${esc(row.owner)}<br>
                <b>Reviewer:</b> ${esc(row.reviewer)}<br>
                <b>Monitoring Signal:</b> ${esc(row.monitoring_signal)}<br>
                <b>Trust Impact:</b> ${esc(row.trust_impact)}
            </div>
        </div>`;
    }

    async function loadCmcTraceability(){
        const target = document.getElementById("cmcTraceabilityMatrix");
        if(!target){ return; }

        try{
            const response = await fetch('/api/platform/blueprints/ai-enabled-cmc/demo');
            const data = await response.json();
            const rows = data.evidence_traceability_matrix || [];

            if(!rows.length){
                target.innerHTML = '<div class="panel"><strong>No traceability matrix found</strong><div>The API did not return evidence_traceability_matrix. Run the Blueprint Evidence Automation patch first.</div></div>';
                return;
            }

            target.innerHTML = rows.map(card).join("");
        }catch(error){
            target.innerHTML = '<div class="panel"><strong>Traceability API error</strong><div>' + esc(error.message) + '</div></div>';
        }
    }

    loadCmcTraceability();
})();
</script>
'''

agentic_traceability_block = r'''
<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">Live Agentic Enterprise Evidence Traceability</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                This table connects each agentic enterprise blueprint question to the existing lifecycle stage, evidence object, owner, reviewer, monitoring signal, and operational trust impact.
            </div>
        </div>
        <span class="tag">Agent Action -> Evidence -> Trust</span>
    </div>

    <div class="grid" id="agenticTraceabilityMatrix">
        <div class="panel"><strong>Loading traceability matrix...</strong><div>Calling existing Agentic Enterprise blueprint API.</div></div>
    </div>
</section>

<script>
(function(){
    function esc(value){
        if(value === null || value === undefined){ return ""; }
        return String(value).replace(/[&<>"']/g, function(c){
            return {"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c];
        });
    }

    function card(row, index){
        return `<div class="panel">
            <strong>${index + 1}. ${esc(row.question)}</strong>
            <div>
                <b>Lifecycle Stage:</b> ${esc(row.lifecycle_stage)}<br>
                <b>Evidence Object:</b> ${esc(row.evidence_object)}<br>
                <b>Owner:</b> ${esc(row.owner)}<br>
                <b>Reviewer:</b> ${esc(row.reviewer)}<br>
                <b>Monitoring Signal:</b> ${esc(row.monitoring_signal)}<br>
                <b>Trust Impact:</b> ${esc(row.trust_impact)}
            </div>
        </div>`;
    }

    async function loadAgenticTraceability(){
        const target = document.getElementById("agenticTraceabilityMatrix");
        if(!target){ return; }

        try{
            const response = await fetch('/api/platform/blueprints/agentic-enterprise/demo');
            const data = await response.json();
            const rows = data.evidence_traceability_matrix || [];

            if(!rows.length){
                target.innerHTML = '<div class="panel"><strong>No traceability matrix found</strong><div>The API did not return evidence_traceability_matrix. Run the Blueprint Evidence Automation patch first.</div></div>';
                return;
            }

            target.innerHTML = rows.map(card).join("");
        }catch(error){
            target.innerHTML = '<div class="panel"><strong>Traceability API error</strong><div>' + esc(error.message) + '</div></div>';
        }
    }

    loadAgenticTraceability();
})();
</script>
'''

library_block = r'''
<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">Blueprint Evidence Traceability UX</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                The blueprint pages now display live evidence traceability matrices from the existing blueprint APIs. No new module, no new route, and no architecture change.
            </div>
        </div>
        <span class="tag">Evidence UX</span>
    </div>

    <div class="grid">
        <a class="card" href="/platform/blueprints/ai-enabled-cmc">
            <strong>CMC Traceability Matrix</strong>
            <span>View question-to-evidence mapping for formulation, process development, regulatory authoring, manufacturing decision influence, human approval, change control, and intended use.</span>
            <code>/platform/blueprints/ai-enabled-cmc</code>
        </a>
        <a class="card" href="/platform/blueprints/agentic-enterprise">
            <strong>Agentic Traceability Matrix</strong>
            <span>View question-to-evidence mapping for agents, autonomous decisions, approvals, workflow changes, controls, boundary crossings, replay, and intended use.</span>
            <code>/platform/blueprints/agentic-enterprise</code>
        </a>
    </div>
</section>
'''

patch_seed_marker()

patch_file(
    "platform_ai_enabled_cmc_blueprint.html",
    cmc_traceability_block,
    "<div class=\"footer\">"
)

patch_file(
    "platform_agentic_enterprise_blueprint.html",
    agentic_traceability_block,
    "<div class=\"footer\">"
)

patch_file(
    "platform_blueprint_library.html",
    library_block,
    "<div class=\"footer\">"
)

Path("blueprint_traceability_ux_patch_v1_summary.json").write_text(
    json.dumps(patch_summary, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("blueprint_traceability_ux_patch_v1_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform/blueprints",
        "http://127.0.0.1:5000/platform/blueprints/ai-enabled-cmc",
        "http://127.0.0.1:5000/platform/blueprints/agentic-enterprise",
        "http://127.0.0.1:5000/api/platform/blueprints/ai-enabled-cmc/demo",
        "http://127.0.0.1:5000/api/platform/blueprints/agentic-enterprise/demo",
        "http://127.0.0.1:5000/api/platform/blueprints/model/demo"
    ]),
    encoding="utf-8"
)

print("")
print("Blueprint Evidence Traceability UX Patch completed.")
print("Marker:")
print("  " + PATCH_MARKER)
print("No new module. No new route. No architecture change.")
