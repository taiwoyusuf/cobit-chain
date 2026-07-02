from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_GOVERNANCE_MULTIFRAMEWORK_UX_PATCH_V1_ACTIVE"

patch_summary = {
    "patch_marker": PATCH_MARKER,
    "patch_type": "governance_multiframework_ux_not_new_module",
    "architecture_change": False,
    "new_module": False,
    "new_route": False,
    "lifecycle_change": False,
    "platform_rule": "No new module. No new route. No architecture change. No lifecycle change. This patch only improves UX visibility for existing Governance multi-framework mapping.",
    "purpose": "Display multi-framework control mapping and multi-framework evidence mapping on existing blueprint pages.",
    "ux_flow_control": [
        "AI Control",
        "Frameworks Supported",
        "Evidence Expected",
        "Unified Implementation"
    ],
    "ux_flow_evidence": [
        "Evidence Item",
        "Frameworks Supported",
        "Reuse Rule",
        "Governance Value"
    ],
    "principle": "One AI control can satisfy many frameworks. One evidence item can support many regulations."
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
    data["governance_multiframework_ux_patch"] = patch_summary

    if path == "platform_blueprint_library_seed.json":
        for bp in data.get("blueprints", []) or []:
            bp["governance_multiframework_ux_status"] = {
                "visible_on_blueprint_page": True,
                "architecture_change": False,
                "new_module": False,
                "new_route": False,
                "lifecycle_change": False,
                "control_ux_flow": patch_summary["ux_flow_control"],
                "evidence_ux_flow": patch_summary["ux_flow_evidence"],
                "principle": patch_summary["principle"]
            }

    if path == "platform_lifecycle_integration_seed.json":
        assessment = data.get("sample_integration_assessment", {})
        assessment["governance_multiframework_ux_status"] = {
            "visible_from_blueprint_pages": True,
            "architecture_change": False,
            "new_module": False,
            "new_route": False,
            "lifecycle_change": False,
            "control_ux_flow": patch_summary["ux_flow_control"],
            "evidence_ux_flow": patch_summary["ux_flow_evidence"],
            "principle": patch_summary["principle"]
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

blueprint_multiframework_ux = r'''
<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">Live Governance Multi-Framework Control Mapping</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                This matrix shows how one AI control can satisfy multiple frameworks through one unified governance implementation. No framework module was added.
            </div>
        </div>
        <span class="tag">One control -> many frameworks</span>
    </div>

    <div class="grid" id="multiFrameworkControlMatrix">
        <div class="panel"><strong>Loading control mapping...</strong><div>Calling existing blueprint API.</div></div>
    </div>
</section>

<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">Live Governance Multi-Framework Evidence Mapping</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                This matrix shows how one evidence item can support multiple regulatory, quality, security, privacy, and internal governance obligations.
            </div>
        </div>
        <span class="tag">One evidence -> many regulations</span>
    </div>

    <div class="grid" id="multiFrameworkEvidenceMatrix">
        <div class="panel"><strong>Loading evidence mapping...</strong><div>Calling existing blueprint API.</div></div>
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

    function list(items){
        if(!items || !items.length){ return "None listed."; }
        return items.map(function(x){ return esc(x); }).join("<br>");
    }

    function getBlueprintApi(){
        const path = window.location.pathname || "";
        if(path.indexOf("agentic-enterprise") >= 0){
            return "/api/platform/blueprints/agentic-enterprise/demo";
        }
        return "/api/platform/blueprints/ai-enabled-cmc/demo";
    }

    function controlCard(row, index){
        return `<div class="panel">
            <strong>${index + 1}. ${esc(row.control_name)}</strong>
            <div>
                <b>Purpose:</b> ${esc(row.control_purpose)}<br><br>
                <b>Frameworks Supported:</b><br>${list(row.supports_frameworks)}<br><br>
                <b>Evidence Expected:</b><br>${list(row.evidence_expected)}<br><br>
                <b>Unified Implementation:</b> ${esc(row.implementation_model)}
            </div>
        </div>`;
    }

    function evidenceCard(row, index){
        return `<div class="panel">
            <strong>${index + 1}. ${esc(row.evidence_item)}</strong>
            <div>
                <b>Frameworks Supported:</b><br>${list(row.supports_frameworks)}<br><br>
                <b>Reuse Rule:</b> ${esc(row.reuse_rule)}<br><br>
                <b>Governance Value:</b> ${esc(row.why_it_matters)}
            </div>
        </div>`;
    }

    async function loadMultiFrameworkMapping(){
        const controlTarget = document.getElementById("multiFrameworkControlMatrix");
        const evidenceTarget = document.getElementById("multiFrameworkEvidenceMatrix");

        try{
            const response = await fetch(getBlueprintApi());
            const data = await response.json();

            const mapping = data.governance_multiframework_mapping || {};
            const controlRows = mapping.multi_framework_control_mapping || [];
            const evidenceRows = mapping.multi_framework_evidence_mapping || [];

            if(controlTarget){
                if(!controlRows.length){
                    controlTarget.innerHTML = '<div class="panel"><strong>No multi-framework control mapping found</strong><div>Run the Governance Multi-Framework Mapping patch first.</div></div>';
                } else {
                    controlTarget.innerHTML = controlRows.map(controlCard).join("");
                }
            }

            if(evidenceTarget){
                if(!evidenceRows.length){
                    evidenceTarget.innerHTML = '<div class="panel"><strong>No multi-framework evidence mapping found</strong><div>Run the Governance Multi-Framework Mapping patch first.</div></div>';
                } else {
                    evidenceTarget.innerHTML = evidenceRows.map(evidenceCard).join("");
                }
            }
        }catch(error){
            if(controlTarget){
                controlTarget.innerHTML = '<div class="panel"><strong>Control mapping API error</strong><div>' + esc(error.message) + '</div></div>';
            }
            if(evidenceTarget){
                evidenceTarget.innerHTML = '<div class="panel"><strong>Evidence mapping API error</strong><div>' + esc(error.message) + '</div></div>';
            }
        }
    }

    loadMultiFrameworkMapping();
})();
</script>
'''

library_ux = r'''
<section class="section">
    <div class="topbar">
        <div>
            <h2 style="margin:0;font-size:30px;">Governance Multi-Framework Mapping UX</h2>
            <div style="margin-top:8px;color:#b9c2ce;line-height:1.6;">
                Blueprint pages now display live multi-framework control and evidence mapping from the existing blueprint APIs. One control can support many frameworks. One evidence item can support many regulations.
            </div>
        </div>
        <span class="tag">Unified governance</span>
    </div>

    <div class="grid">
        <a class="card" href="/platform/blueprints/ai-enabled-cmc">
            <strong>CMC Multi-Framework Governance</strong>
            <span>View control and evidence reuse across ISO 42001, ISO 27001, EU AI Act, GDPR, NIS2, GAMP 5, GxP, FDA, ICH, and Internal SOPs.</span>
            <code>/platform/blueprints/ai-enabled-cmc</code>
        </a>
        <a class="card" href="/platform/blueprints/agentic-enterprise">
            <strong>Agentic Multi-Framework Governance</strong>
            <span>View unified governance implementation for agentic enterprise controls and evidence reuse.</span>
            <code>/platform/blueprints/agentic-enterprise</code>
        </a>
    </div>
</section>
'''

platform_ux = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>Multi-Framework Governance UX</h2>
            <p>Existing blueprint pages now render live multi-framework control and evidence mapping. This makes unified governance implementation visible without adding a framework module, route, architecture, or lifecycle stage.</p>
        </div>
        <span class="tag">Governance UX</span>
    </div>
    <div class="grid-4">
        <a class="card" href="/platform/blueprints/ai-enabled-cmc"><strong>CMC Framework Mapping</strong><span>Displays controls and evidence mapped across ISO 42001, ISO 27001, EU AI Act, GDPR, NIS2, GAMP 5, GxP, FDA, ICH, and Internal SOPs.</span><small>Open CMC blueprint</small></a>
        <a class="card" href="/platform/blueprints/agentic-enterprise"><strong>Agentic Framework Mapping</strong><span>Displays unified control and evidence reuse for agentic enterprise governance.</span><small>Open Agentic blueprint</small></a>
        <a class="card" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Shows how multi-framework governance connects to the existing lifecycle.</span><small>Open lifecycle</small></a>
        <a class="card" href="/platform/evidence-packages"><strong>Evidence Reuse</strong><span>One evidence object can support multiple frameworks and regulatory obligations.</span><small>Open evidence</small></a>
    </div>
</section>
'''

route_registry_ux = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>Multi-Framework Governance UX Routes</h2>
            <p>Multi-framework control and evidence mapping are displayed through existing blueprint routes. No new route was added.</p>
        </div>
        <span class="tag">Existing routes only</span>
    </div>
    <div class="route-grid">
        <a class="route" href="/platform/blueprints/ai-enabled-cmc"><strong>CMC Multi-Framework Mapping</strong><span>Displays unified control and evidence mapping for AI-enabled CMC governance.</span><code>/platform/blueprints/ai-enabled-cmc</code></a>
        <a class="route" href="/platform/blueprints/agentic-enterprise"><strong>Agentic Multi-Framework Mapping</strong><span>Displays unified control and evidence mapping for agentic enterprise governance.</span><code>/platform/blueprints/agentic-enterprise</code></a>
        <a class="route" href="/api/platform/blueprints/model/demo"><strong>Blueprint API</strong><span>Existing API supplies governance_multiframework_mapping data.</span><code>/api/platform/blueprints/model/demo</code></a>
        <a class="route" href="/api/platform/lifecycle-integration/model/demo"><strong>Lifecycle API</strong><span>Existing API supplies multi-framework governance status inside the lifecycle model.</span><code>/api/platform/lifecycle-integration/model/demo</code></a>
    </div>
</section>
'''

patch_seed("platform_blueprint_library_seed.json")
patch_seed("platform_lifecycle_integration_seed.json")

patch_html(
    "platform_ai_enabled_cmc_blueprint.html",
    blueprint_multiframework_ux,
    "<div class=\"footer\">"
)

patch_html(
    "platform_agentic_enterprise_blueprint.html",
    blueprint_multiframework_ux,
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

Path("governance_multiframework_ux_patch_v1_summary.json").write_text(
    json.dumps(patch_summary, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("governance_multiframework_ux_patch_v1_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform",
        "http://127.0.0.1:5000/platform/routes",
        "http://127.0.0.1:5000/platform/blueprints",
        "http://127.0.0.1:5000/platform/blueprints/ai-enabled-cmc",
        "http://127.0.0.1:5000/platform/blueprints/agentic-enterprise",
        "http://127.0.0.1:5000/platform/lifecycle-integration",
        "http://127.0.0.1:5000/api/platform/blueprints/model/demo",
        "http://127.0.0.1:5000/api/platform/blueprints/ai-enabled-cmc/demo",
        "http://127.0.0.1:5000/api/platform/blueprints/agentic-enterprise/demo",
        "http://127.0.0.1:5000/api/platform/lifecycle-integration/model/demo"
    ]),
    encoding="utf-8"
)

print("")
print("Governance Multi-Framework Mapping UX Patch completed.")
print("Marker:")
print("  " + PATCH_MARKER)
print("No new module. No new route. No architecture change. Lifecycle unchanged.")
