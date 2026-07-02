from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_OPTIMIZATION_TRACEABILITY_UX_PATCH_V1_ACTIVE"

patch_summary = {
    "patch_marker": PATCH_MARKER,
    "patch_type": "optimization_traceability_ux_not_new_module",
    "architecture_change": False,
    "new_module": False,
    "new_route": False,
    "lifecycle_change": False,
    "platform_rule": "No new module. No new route. No architecture change. No lifecycle change. This patch only improves UX visibility for existing Operationalization and Evidence enrichments.",
    "purpose": "Display optimization governance and evidence traceability on the existing AI-enabled CMC Blueprint page.",
    "ux_flow": [
        "Optimization Area",
        "Governance Question",
        "Required Evidence",
        "Approval Expected",
        "Monitoring Signal",
        "Trust Impact"
    ],
    "operationalization_question": "Were these optimizations governed, approved, monitored, and evidenced?",
    "evidence_question": "Can prompt versions, routing decisions, retrieval evidence, supplied context, omitted context, cache usage, agent decisions, tool-call lineage, optimization policies, human approvals, and runtime evidence be reconstructed?"
}

def load_json(path):
    p = Path(path)
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))

def save_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

def patch_seed(path):
    p = Path(path)
    if not p.exists():
        print(f"SKIP: {path} not found.")
        return False

    data = load_json(path)
    data["optimization_traceability_ux_patch"] = patch_summary

    if path == "platform_blueprint_library_seed.json":
        for bp in data.get("blueprints", []) or []:
            if bp.get("blueprint_id") == "ai_enabled_cmc":
                bp["optimization_traceability_ux_status"] = {
                    "visible_on_blueprint_page": True,
                    "architecture_change": False,
                    "new_module": False,
                    "new_route": False,
                    "lifecycle_change": False,
                    "ux_flow": patch_summary["ux_flow"]
                }

    if path == "platform_lifecycle_integration_seed.json":
        assessment = data.get("sample_integration_assessment", {})
        assessment["optimization_traceability_ux_status"] = {
            "visible_from_ai_enabled_cmc_blueprint": True,
            "architecture_change": False,
            "new_module": False,
            "new_route": False,
            "lifecycle_change": False,
            "ux_flow": patch_summary["ux_flow"]
        }
        data["sample_integration_assessment"] = assessment

    save_json(path, data)
    print(f"PATCHED: {path}")
    return True

def remove_marker_block(text):
    start = f"<!-- {PATCH_MARKER} -->"
    end = f"<!-- END {PATCH_MARKER} -->"
    return re.sub(re.escape(start) + r".*?" + re.escape(end), "", text, flags=re.DOTALL)

def patch_html(path, block, anchor):
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

cmc_traceability_ux = r'''
<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">Live Operationalization Optimization Governance Matrix</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                This matrix shows how each AI optimization area is governed, approved, monitored, and evidenced inside the existing Operationalization and Evidence stages. No new module, route, architecture, or lifecycle stage was added.
            </div>
        </div>
        <span class="tag">Optimization -> Evidence -> Trust</span>
    </div>

    <div class="grid" id="optimizationTraceabilityMatrix">
        <div class="panel"><strong>Loading optimization traceability...</strong><div>Calling existing AI-enabled CMC blueprint API.</div></div>
    </div>
</section>

<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">Live Optimization Evidence Checklist</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Evidence now makes optimization reconstructable by showing prompt versions, routing decisions, retrieval evidence, context supplied, context omitted, cache usage, agent decisions, tool-call lineage, optimization policies, human approvals, and runtime evidence.
            </div>
        </div>
        <span class="tag">Evidence enriched</span>
    </div>

    <div class="grid" id="optimizationEvidenceChecklist">
        <div class="panel"><strong>Loading evidence checklist...</strong><div>Calling existing AI-enabled CMC blueprint API.</div></div>
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

    function traceabilityCard(row, index){
        return `<div class="panel">
            <strong>${index + 1}. ${esc(row.optimization_area)}</strong>
            <div>
                <b>Governance Question:</b> ${esc(row.governance_question)}<br>
                <b>Required Evidence:</b> ${esc(row.required_evidence)}<br>
                <b>Approval Expected:</b> ${esc(row.approval_expected)}<br>
                <b>Monitoring Signal:</b> ${esc(row.monitoring_signal)}<br>
                <b>Trust Impact:</b> ${esc(row.trust_impact)}
            </div>
        </div>`;
    }

    function evidenceCard(item, index){
        return `<div class="panel">
            <strong>${index + 1}. ${esc(item)}</strong>
            <div>
                This evidence object supports reconstruction of AI optimization behavior, execution context, human oversight, and operational trust.
            </div>
        </div>`;
    }

    function findStage(data, stageName){
        const lifecycle = data.lifecycle || [];
        for(let i = 0; i < lifecycle.length; i++){
            if(lifecycle[i].stage_name === stageName){
                return lifecycle[i];
            }
        }
        return {};
    }

    async function loadOptimizationTraceability(){
        const matrixTarget = document.getElementById("optimizationTraceabilityMatrix");
        const evidenceTarget = document.getElementById("optimizationEvidenceChecklist");

        try{
            const response = await fetch('/api/platform/blueprints/ai-enabled-cmc/demo');
            const data = await response.json();

            const rows = data.optimization_traceability || [];
            if(matrixTarget){
                if(!rows.length){
                    matrixTarget.innerHTML = '<div class="panel"><strong>No optimization traceability found</strong><div>Run the Operationalization Optimization Governance patch first.</div></div>';
                } else {
                    matrixTarget.innerHTML = rows.map(traceabilityCard).join("");
                }
            }

            const evidenceStage = findStage(data, "Evidence");
            const evidenceItems = (evidenceStage.evidence_optimization_expansion && evidenceStage.evidence_optimization_expansion.evidence_explicitly_includes) || [];
            if(evidenceTarget){
                if(!evidenceItems.length){
                    evidenceTarget.innerHTML = '<div class="panel"><strong>No optimization evidence checklist found</strong><div>The Evidence stage did not return optimization evidence items.</div></div>';
                } else {
                    evidenceTarget.innerHTML = evidenceItems.map(evidenceCard).join("");
                }
            }
        }catch(error){
            if(matrixTarget){
                matrixTarget.innerHTML = '<div class="panel"><strong>Optimization traceability API error</strong><div>' + esc(error.message) + '</div></div>';
            }
            if(evidenceTarget){
                evidenceTarget.innerHTML = '<div class="panel"><strong>Evidence checklist API error</strong><div>' + esc(error.message) + '</div></div>';
            }
        }
    }

    loadOptimizationTraceability();
})();
</script>
'''

library_ux = r'''
<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">Optimization Governance UX</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                The AI-enabled CMC Blueprint now displays a live optimization governance matrix showing how prompt, routing, retrieval, context, cache, lazy-loading, agent orchestration, and optimization policy decisions are governed and evidenced.
            </div>
        </div>
        <span class="tag">No new module</span>
    </div>

    <div class="grid">
        <a class="card" href="/platform/blueprints/ai-enabled-cmc">
            <strong>Open CMC Optimization Matrix</strong>
            <span>View live optimization governance traceability for prompt management, prompt versioning, prompt approval, routing, retrieval, context, compaction, caching, lazy-loading, agent orchestration, and optimization policies.</span>
            <code>/platform/blueprints/ai-enabled-cmc</code>
        </a>
        <a class="card" href="/api/platform/blueprints/ai-enabled-cmc/demo">
            <strong>CMC Blueprint API</strong>
            <span>Existing API returns optimization_traceability, operationalization_expansion, and evidence_optimization_expansion without adding a new route.</span>
            <code>/api/platform/blueprints/ai-enabled-cmc/demo</code>
        </a>
    </div>
</section>
'''

platform_ux = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>Optimization Traceability UX</h2>
            <p>The AI-enabled CMC Blueprint now renders live optimization governance traceability from the existing blueprint API. This makes prompt, routing, retrieval, context, cache, lazy-loading, agent orchestration, and optimization policy evidence visible without adding a new module.</p>
        </div>
        <span class="tag">UX hardening</span>
    </div>
    <div class="grid-4">
        <a class="card" href="/platform/blueprints/ai-enabled-cmc"><strong>CMC Optimization Matrix</strong><span>Displays optimization area, governance question, required evidence, approval expectation, monitoring signal, and trust impact.</span><small>Open blueprint</small></a>
        <a class="card" href="/api/platform/blueprints/ai-enabled-cmc/demo"><strong>CMC Blueprint API</strong><span>Returns the optimization governance data used by the UX matrix.</span><small>Open API</small></a>
        <a class="card" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Shows how optimization governance connects to existing Operationalization and Evidence stages.</span><small>Open integration</small></a>
        <a class="card" href="/platform/evidence-packages"><strong>Evidence Vault</strong><span>Supports prompt, routing, retrieval, context, cache, agent, tool-call, approval, and runtime evidence.</span><small>Open evidence</small></a>
    </div>
</section>
'''

route_registry_ux = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>Optimization Traceability UX Routes</h2>
            <p>The optimization governance matrix is displayed through existing blueprint and lifecycle routes. No new route was added.</p>
        </div>
        <span class="tag">Existing routes only</span>
    </div>
    <div class="route-grid">
        <a class="route" href="/platform/blueprints/ai-enabled-cmc"><strong>CMC Optimization Governance Matrix</strong><span>Displays prompt, routing, retrieval, context, cache, lazy-loading, orchestration, and optimization policy traceability.</span><code>/platform/blueprints/ai-enabled-cmc</code></a>
        <a class="route" href="/api/platform/blueprints/ai-enabled-cmc/demo"><strong>CMC Blueprint API</strong><span>Existing API supplies optimization traceability rows and Evidence enrichment fields.</span><code>/api/platform/blueprints/ai-enabled-cmc/demo</code></a>
        <a class="route" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Optimization governance remains connected to the existing lifecycle.</span><code>/platform/lifecycle-integration</code></a>
        <a class="route" href="/platform/evidence-packages"><strong>Evidence Vault</strong><span>Evidence remains the existing layer for reconstruction, auditability, and operational trust defense.</span><code>/platform/evidence-packages</code></a>
    </div>
</section>
'''

patch_seed("platform_blueprint_library_seed.json")
patch_seed("platform_lifecycle_integration_seed.json")

patch_html(
    "platform_ai_enabled_cmc_blueprint.html",
    cmc_traceability_ux,
    "<div class=\"footer\">"
)

patch_html(
    "platform_blueprint_library.html",
    library_ux,
    "<div class=\"footer\">"
)

patch_html(
    "platform_ab_command_center.html",
    platform_ux,
    "<div class=\"footer\">"
)

patch_html(
    "platform_route_registry_command_center.html",
    route_registry_ux,
    "<div class=\"footer\">"
)

Path("optimization_traceability_ux_patch_v1_summary.json").write_text(
    json.dumps(patch_summary, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("optimization_traceability_ux_patch_v1_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform",
        "http://127.0.0.1:5000/platform/routes",
        "http://127.0.0.1:5000/platform/blueprints",
        "http://127.0.0.1:5000/platform/blueprints/ai-enabled-cmc",
        "http://127.0.0.1:5000/platform/lifecycle-integration",
        "http://127.0.0.1:5000/api/platform/blueprints/ai-enabled-cmc/demo",
        "http://127.0.0.1:5000/api/platform/lifecycle-integration/model/demo"
    ]),
    encoding="utf-8"
)

print("")
print("Optimization Traceability UX Patch completed.")
print("Marker:")
print("  " + PATCH_MARKER)
print("No new module. No new route. No architecture change. Lifecycle unchanged.")
