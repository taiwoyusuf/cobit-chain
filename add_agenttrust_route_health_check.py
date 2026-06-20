from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_ROUTE_HEALTH_CHECK_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust Route Health Check already exists.")
    raise SystemExit()

if "def agenttrust_shell" not in text:
    raise SystemExit("AgentTrust base module not found. Install AgentTrust module first.")

nav_old = '<a href="/agenttrust/unified-kernel-index" class="secondary">Kernel Index</a>'
nav_new = '''<a href="/agenttrust/unified-kernel-index" class="secondary">Kernel Index</a>
                    <a href="/agenttrust/route-health-check" class="secondary">Health Check</a>
                    <a href="/agenttrust/route-audit" class="dark">Route Audit</a>
                    <a href="/agenttrust/manifest-validator" class="dark">Manifest</a>'''

if nav_old in text and "/agenttrust/route-health-check" not in text:
    text = text.replace(nav_old, nav_new)

block = r'''

# ============================================================
# AGENTTRUST_ROUTE_HEALTH_CHECK_V1_ACTIVE
# AgentTrust™ Route Health Check, Route Audit, Manifest Validator,
# Route Manifest JSON, and Link Integrity Dashboard
# ============================================================

AGENTTRUST_EXPECTED_ROUTES = [
    "/agenttrust",
    "/agenttrust/integration-map",
    "/agenttrust/agent-register",
    "/agenttrust/agent-passport",
    "/agenttrust/authority-gate",
    "/agenttrust/tool-call-evidence",
    "/agenttrust/human-accountability",
    "/agenttrust/ai-act-readiness",
    "/agenttrust/evidence-ledger",

    "/agenttrust/command-center",
    "/agenttrust/readiness-gate",
    "/agenttrust/risk-tiering",
    "/agenttrust/control-library",
    "/agenttrust/operational-matrix",

    "/agenttrust/passport-factory",
    "/agenttrust/sample-agent-register",
    "/agenttrust/trust-score-engine",
    "/agenttrust/evidence-package-builder",
    "/agenttrust/escalation-rules",

    "/agenttrust/regulatory-crosswalk",
    "/agenttrust/cobit-crosswalk",
    "/agenttrust/gxp-impact-router",
    "/agenttrust/ai-policy-router",
    "/agenttrust/enterprise-control-tower",

    "/agenttrust/execution-firewall",
    "/agenttrust/prohibited-action-sentinel",
    "/agenttrust/runtime-sentinel",
    "/agenttrust/agent-kill-switch",
    "/agenttrust/drift-sentinel",
    "/agenttrust/trust-quarantine",

    "/agenttrust/decision-replay-studio",
    "/agenttrust/evidence-lineage-engine",
    "/agenttrust/action-timeline",
    "/agenttrust/chain-of-authority",
    "/agenttrust/audit-defense-room",
    "/agenttrust/immutable-evidence-ledger",
    "/agenttrust/incident-reconstruction",

    "/agenttrust/lifecycle-governance",
    "/agenttrust/change-control-gate",
    "/agenttrust/model-change-gate",
    "/agenttrust/prompt-tool-change-gate",
    "/agenttrust/review-cadence",
    "/agenttrust/decommissioning-gate",
    "/agenttrust/lifecycle-evidence-register",

    "/agenttrust/executive-assurance-dashboard",
    "/agenttrust/master-index",
    "/agenttrust/trust-heatmap",
    "/agenttrust/board-report",
    "/agenttrust/strategic-value-map",

    "/agenttrust/metrics-engine",
    "/agenttrust/agent-trust-index",
    "/agenttrust/control-coverage-matrix",
    "/agenttrust/evidence-sufficiency-dashboard",
    "/agenttrust/runtime-safety-score",
    "/agenttrust/audit-defensibility-score",
    "/agenttrust/gxp-exposure-score",
    "/agenttrust/continuous-assurance-scorecard",
    "/agenttrust/governance-debt-register",
    "/agenttrust/kpi-catalog",

    "/agenttrust/servicenow-integration-blueprint",
    "/agenttrust/cmdb-csdm-mapping",
    "/agenttrust/agent-ci-relationship-model",
    "/agenttrust/myaccess-cyberark-agent-routing",
    "/agenttrust/change-control-bridge",
    "/agenttrust/lcm-ownership-bridge",
    "/agenttrust/servicenow-evidence-sync",

    "/agenttrust/unified-kernel-index",
    "/agenttrust/agentic-operating-model",
    "/agenttrust/readiness-roadmap",
    "/agenttrust/platform-positioning",

    "/citrust/agenttrust-integration",
    "/cutovertrust/agenttrust-integration",
    "/irlt-commercial-readiness/agenttrust-integration",
    "/ai-governance/agenttrust-integration",
    "/servicenow-ci-readiness/agenttrust-integration",
    "/citrust/myaccess-readiness/agenttrust-integration",
    "/agenttrust/governance-black-box-integration"
]


def agenttrust_get_registered_routes():
    try:
        from flask import current_app
        return sorted([str(rule.rule) for rule in current_app.url_map.iter_rules()])
    except Exception:
        return []


def agenttrust_route_health_rows():
    registered = set(agenttrust_get_registered_routes())
    rows = ""
    installed_count = 0
    missing_count = 0

    for route in AGENTTRUST_EXPECTED_ROUTES:
        if route in registered:
            installed_count += 1
            rows += f"""
            <tr>
                <td><strong>{route}</strong></td>
                <td><span class="badge green">Installed</span></td>
                <td><a href="{route}">Open</a></td>
                <td>Route exists in Flask URL map.</td>
            </tr>
            """
        else:
            missing_count += 1
            rows += f"""
            <tr>
                <td><strong>{route}</strong></td>
                <td><span class="badge red">Missing</span></td>
                <td>Not available</td>
                <td>Route was expected but was not found in Flask URL map.</td>
            </tr>
            """

    return rows, installed_count, missing_count, len(AGENTTRUST_EXPECTED_ROUTES)


def agenttrust_installed_only_rows():
    registered = agenttrust_get_registered_routes()
    rows = ""

    for route in registered:
        if route.startswith("/agenttrust") or "agenttrust-integration" in route:
            rows += f"""
            <tr>
                <td><strong>{route}</strong></td>
                <td><span class="badge green">Registered</span></td>
                <td><a href="{route}">Open</a></td>
            </tr>
            """

    return rows


@app.route("/agenttrust/route-health-check")
@app.route("/agenttrust/health-check")
@app.route("/agenttrust/link-health-check")
def agenttrust_route_health_check():
    rows, installed_count, missing_count, total_count = agenttrust_route_health_rows()

    if missing_count == 0:
        health_status = "Healthy"
        health_color = "var(--green)"
        health_note = "All expected AgentTrust™ routes are installed."
    else:
        health_status = "Review"
        health_color = "var(--red)"
        health_note = "Some expected AgentTrust™ routes are missing and should be reviewed."

    body = f"""
    <section class="kpis">
        <div class="metric"><div class="label">Route Health</div><div class="value" style="color:{health_color};">{health_status}</div><div class="note">{health_note}</div></div>
        <div class="metric"><div class="label">Expected Routes</div><div class="value" style="color:var(--blue);">{total_count}</div><div class="note">Core AgentTrust™ and integration routes expected.</div></div>
        <div class="metric"><div class="label">Installed Routes</div><div class="value" style="color:var(--green);">{installed_count}</div><div class="note">Routes found in Flask URL map.</div></div>
        <div class="metric"><div class="label">Missing Routes</div><div class="value" style="color:var(--red);">{missing_count}</div><div class="note">Expected routes not found.</div></div>
        <div class="metric"><div class="label">Manifest</div><div class="value" style="color:var(--purple);">Active</div><div class="note">Route manifest validator installed.</div></div>
        <div class="metric"><div class="label">Audit Mode</div><div class="value" style="color:var(--orange);">Ready</div><div class="note">Use this after each new build.</div></div>
    </section>

    <section class="section">
        <h2>AgentTrust™ Route Health Check</h2>
        <div class="answer">
            <strong>Purpose:</strong> confirm that the AgentTrust™ module routes are installed and visible in Flask.
            This prevents missing pages after multiple code injections and helps validate the module before deployment.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Expected Route</th>
                    <th>Status</th>
                    <th>Open</th>
                    <th>Validation Note</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Route Health Check",
        "Route validation dashboard for AgentTrust™ pages, integration hooks, and Flask URL map registration.",
        body
    )


@app.route("/agenttrust/route-audit")
@app.route("/agenttrust/installed-routes")
@app.route("/agenttrust/agenttrust-routes")
def agenttrust_route_audit():
    rows = agenttrust_installed_only_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Installed Route Audit</h2>
        <p>
            This page shows AgentTrust™ routes currently registered in the Flask application.
            It is useful for checking what is actually live after each module build.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Registered Route</th>
                    <th>Status</th>
                    <th>Open</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Route Audit",
        "Audit page showing AgentTrust™ routes currently registered in the Flask URL map.",
        body
    )


@app.route("/agenttrust/manifest-validator")
@app.route("/agenttrust/route-manifest")
@app.route("/agenttrust/link-validator")
def agenttrust_manifest_validator():
    rows, installed_count, missing_count, total_count = agenttrust_route_health_rows()

    body = f"""
    <section class="section">
        <h2>AgentTrust™ Manifest Validator</h2>
        <div class="answer">
            <strong>Manifest result:</strong> {installed_count} of {total_count} expected routes are installed.
            Missing routes: {missing_count}.
        </div>

        <table>
            <thead>
                <tr>
                    <th>Manifest Route</th>
                    <th>Status</th>
                    <th>Open</th>
                    <th>Note</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Validator Rule</h2>
        <div class="answer">
            After every AgentTrust™ build, open this validator before deployment.
            If all expected routes are installed locally, then commit and push to Azure.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Manifest Validator",
        "Manifest validator for checking expected AgentTrust™ routes against the active Flask URL map.",
        body
    )


@app.route("/agenttrust/route-manifest-json")
@app.route("/agenttrust/manifest-json")
def agenttrust_route_manifest_json():
    try:
        from flask import jsonify
        registered = set(agenttrust_get_registered_routes())

        manifest = []
        installed_count = 0
        missing_count = 0

        for route in AGENTTRUST_EXPECTED_ROUTES:
            installed = route in registered

            if installed:
                installed_count += 1
            else:
                missing_count += 1

            manifest.append({
                "route": route,
                "installed": installed
            })

        return jsonify({
            "module": "AgentTrust™",
            "manifest": "Route Health Check",
            "expected_route_count": len(AGENTTRUST_EXPECTED_ROUTES),
            "installed_count": installed_count,
            "missing_count": missing_count,
            "routes": manifest
        })

    except Exception as exc:
        return {
            "module": "AgentTrust™",
            "manifest": "Route Health Check",
            "error": str(exc)
        }, 500


@app.route("/agenttrust/post-build-checklist")
@app.route("/agenttrust/deployment-checklist")
@app.route("/agenttrust/agenttrust-build-checklist")
def agenttrust_post_build_checklist():
    body = """
    <section class="section">
        <h2>AgentTrust™ Post-Build Checklist</h2>
        <p>
            Use this checklist after every AgentTrust™ code block before committing and pushing to Azure.
        </p>

        <table>
            <thead>
                <tr>
                    <th>Check</th>
                    <th>Command / Route</th>
                    <th>Pass Criteria</th>
                    <th>Action If Failed</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Compile Check</td><td>python -m py_compile app.py</td><td>No syntax errors.</td><td>Restore backup or fix syntax.</td></tr>
                <tr><td>Marker Check</td><td>Select-String marker check.</td><td>New module marker appears once.</td><td>Review duplicate or failed injection.</td></tr>
                <tr><td>Route Check</td><td>/agenttrust/route-health-check</td><td>Expected routes show installed.</td><td>Review missing route.</td></tr>
                <tr><td>Local Open Check</td><td>http://127.0.0.1:5000/agenttrust/route-health-check</td><td>Page opens locally.</td><td>Check Flask startup error.</td></tr>
                <tr><td>Manifest JSON Check</td><td>/agenttrust/route-manifest-json</td><td>JSON returns installed routes.</td><td>Review Flask route map.</td></tr>
                <tr><td>Commit Check</td><td>git status</td><td>Only intended files changed.</td><td>Review unexpected files.</td></tr>
                <tr><td>Deployment Check</td><td>Azure website route test.</td><td>Route opens after GitHub Action completes.</td><td>Check deployment logs.</td></tr>
            </tbody>
        </table>
    </section>

    <section class="section">
        <h2>Post-Build Rule</h2>
        <div class="answer">
            Do not rely only on the route opening once. Validate compile, marker, local route, manifest, commit status,
            and Azure deployment after every build.
        </div>
    </section>
    """

    return agenttrust_shell(
        "AgentTrust™ Post-Build Checklist",
        "Checklist for validating AgentTrust™ code injection, route health, local testing, commit readiness, and Azure deployment.",
        body
    )

# ============================================================
# END AGENTTRUST_ROUTE_HEALTH_CHECK_V1_ACTIVE
# ============================================================

'''

targets = [
    'if __name__ == "__main__":',
    "if __name__ == '__main__':"
]

idx = -1
target_found = None

for target in targets:
    current_idx = text.rfind(target)
    if current_idx > idx:
        idx = current_idx
        target_found = target

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("AgentTrust Route Health Check installed.")
print(f"Inserted before: {target_found}")
