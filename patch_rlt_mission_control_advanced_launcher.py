from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# RLT_MISSION_CONTROL_ADVANCED_LAUNCHER_ACTIVE"

if MARKER in text:
    print("RLT Mission Control advanced launcher already exists.")
    raise SystemExit(0)

required = [
    "RLT_OPERATIONS_VERTICAL_ACTIVE",
    "RLT_DEMO_GUIDE_ACTIVE",
    "RLT_EXECUTIVE_WAR_ROOM_ACTIVE",
    "RLT_REAL_TIME_MANUFACTURING_CONFIDENCE_ACTIVE",
    "RLT_BATCH_TRUST_PASSPORT_ACTIVE",
    "RLT_PRODUCTION_RELEASE_CONFIDENCE_ACTIVE",
    "RLT_OPERATIONAL_DIGITAL_TWIN_ACTIVE",
    "RLT_CAPA_EFFECTIVENESS_INTELLIGENCE_ACTIVE",
    "RLT_AUTONOMOUS_DEVIATION_PREVENTION_ACTIVE",
    "RLT_ENTERPRISE_GOVERNANCE_MESH_ACTIVE",
    "RLT_ENTERPRISE_SYSTEM_FEDERATION_ACTIVE",
    "RLT_DSCSA_CHAIN_OF_CUSTODY_TRUST_ACTIVE",
    "RLT_SUPPLIER_MANUFACTURING_TRUST_EXCHANGE_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# RLT_MISSION_CONTROL_ADVANCED_LAUNCHER_ACTIVE
# Safe bridge: adds advanced RLT module launcher to /rlt-operations
# ============================================================

@app.after_request
def rlt_mission_control_advanced_launcher(response):
    try:
        if request.path != "/rlt-operations":
            return response

        if response.status_code != 200:
            return response

        content_type = response.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            return response

        html = response.get_data(as_text=True)

        if 'id="rlt-advanced-module-launcher"' in html:
            return response

        panel = """
        <section id="rlt-advanced-module-launcher" class="section">
            <h2>Advanced RLT Intelligence Modules™</h2>
            <p>
                Launch the expanded RLT Operations AssuranceLayer™ capabilities from one place. These modules extend
                Mission Control into executive intervention, real-time manufacturing confidence, batch trust,
                release confidence, digital twin logic, CAPA effectiveness, deviation prevention, enterprise
                federation, custody trust, and supplier/manufacturing trust exchange.
            </p>

            <div class="grid">
                <div class="card"><div class="label">Demo Control</div><div class="value" style="font-size:22px;">Presentation Flow</div><p><a href="/rlt-demo">Open Demo Guide</a></p></div>
                <div class="card"><div class="label">Executive Layer</div><div class="value" style="font-size:22px;">War Room</div><p><a href="/rlt-operations/executive-war-room">Open Executive War Room</a></p></div>
                <div class="card"><div class="label">Live Confidence</div><div class="value" style="font-size:22px;">Manufacturing Confidence</div><p><a href="/rlt-operations/manufacturing-confidence">Open Confidence Layer</a></p></div>
                <div class="card"><div class="label">Batch Assurance</div><div class="value" style="font-size:22px;">Batch Trust Passport</div><p><a href="/rlt-operations/batch-trust-passport">Open Passport</a></p></div>
                <div class="card"><div class="label">Release Logic</div><div class="value" style="font-size:22px;">Release Confidence</div><p><a href="/rlt-operations/release-confidence">Open Release Engine</a></p></div>
                <div class="card"><div class="label">Simulation</div><div class="value" style="font-size:22px;">Operational Digital Twin</div><p><a href="/rlt-operations/digital-twin">Open Digital Twin</a></p></div>
                <div class="card"><div class="label">Prevention</div><div class="value" style="font-size:22px;">Deviation Prevention</div><p><a href="/rlt-operations/deviation-prevention">Open Prevention Engine</a></p></div>
                <div class="card"><div class="label">CAPA Intelligence</div><div class="value" style="font-size:22px;">CAPA Effectiveness</div><p><a href="/rlt-operations/capa-effectiveness">Open CAPA Engine</a></p></div>
                <div class="card"><div class="label">Enterprise Mesh</div><div class="value" style="font-size:22px;">Governance Mesh</div><p><a href="/rlt-operations/governance-mesh">Open Mesh</a></p></div>
                <div class="card"><div class="label">System Federation</div><div class="value" style="font-size:22px;">Veeva / Blue Mountain / myAccess</div><p><a href="/rlt-operations/enterprise-system-federation">Open Federation</a></p></div>
                <div class="card"><div class="label">Custody Trust</div><div class="value" style="font-size:22px;">DSCSA Chain-of-Custody</div><p><a href="/rlt-operations/dscsa-chain-of-custody">Open Custody Layer</a></p></div>
                <div class="card"><div class="label">External Trust</div><div class="value" style="font-size:22px;">Supplier Trust Exchange</div><p><a href="/rlt-operations/supplier-trust-exchange">Open Trust Exchange</a></p></div>
            </div>
        </section>
        """

        lower_html = html.lower()
        if "</body>" in lower_html:
            index = lower_html.rfind("</body>")
            html = html[:index] + panel + html[index:]
        else:
            html = html + panel

        response.set_data(html)
        response.headers["Content-Length"] = str(len(response.get_data()))
        return response

    except Exception as exc:
        print(f"RLT Mission Control advanced launcher skipped safely: {exc}")
        return response

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("RLT Mission Control advanced launcher patch applied.")
