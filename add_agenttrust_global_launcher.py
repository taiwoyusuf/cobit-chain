from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "AGENTTRUST_GLOBAL_LAUNCHER_V1_ACTIVE"

if MARKER in text:
    print("AgentTrust global launcher already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# AGENTTRUST_GLOBAL_LAUNCHER_V1_ACTIVE
# Adds AgentTrust™ floating integration launcher across COBIT-Chain™
# ============================================================

def agenttrust_global_launcher_target(path):
    """
    Route-aware AgentTrust™ hook selector.
    This makes AgentTrust™ visible across COBIT-Chain™ without manually
    editing every existing module page.
    """

    if path.startswith("/agenttrust"):
        return None

    if path.startswith("/citrust/myaccess-readiness") or path.startswith("/citrust/access-readiness"):
        return {
            "label": "MyAccess / CyberArk + AgentTrust™",
            "url": "/citrust/myaccess-readiness/agenttrust-integration",
            "context": "AI agent access authority, entitlement governance, privileged execution, and human approval routing."
        }

    if path.startswith("/citrust"):
        return {
            "label": "CITrust™ + AgentTrust™",
            "url": "/citrust/agenttrust-integration",
            "context": "AI agents linked to CIs, CMDB records, ownership, support groups, MyAccess, CyberArk, and ServiceNow workflows."
        }

    if path.startswith("/cutovertrust"):
        return {
            "label": "CutoverTrust™ + AgentTrust™",
            "url": "/cutovertrust/agenttrust-integration",
            "context": "AI agents involved in cutover readiness, transition execution, rollback, validation impact, and go-live control."
        }

    if path.startswith("/irlt-commercial-readiness") or path.startswith("/irlttrust") or path.startswith("/rlttrust"):
        return {
            "label": "IRLTTrust™ + AgentTrust™",
            "url": "/irlt-commercial-readiness/agenttrust-integration",
            "context": "AI agents affecting GMP operations, QC readiness, inspection evidence, validation, and regulated radiopharma readiness."
        }

    if path.startswith("/ai-governance"):
        return {
            "label": "AI Governance + AgentTrust™",
            "url": "/ai-governance/agenttrust-integration",
            "context": "AI Act readiness, AI literacy, transparency, high-risk classification, logging, and human oversight."
        }

    if path.startswith("/servicenow-ci-readiness"):
        return {
            "label": "ServiceNow / CMDB + AgentTrust™",
            "url": "/servicenow-ci-readiness/agenttrust-integration",
            "context": "Agent linkage to Business Applications, Application Services, infrastructure CIs, support groups, LCM, and ownership."
        }

    return {
        "label": "AgentTrust™",
        "url": "/agenttrust",
        "context": "AI Agentic Governance, Identity, Authority, Tool-Call Evidence, Human Accountability, and Agent Risk Passport Assurance."
    }


def agenttrust_global_launcher_html(target):
    return f"""
    <!-- AGENTTRUST_GLOBAL_NAV_INJECTED -->
    <style>
        .agenttrust-global-launcher {{
            position: fixed;
            right: 22px;
            bottom: 22px;
            z-index: 99999;
            width: 320px;
            max-width: calc(100vw - 44px);
            border: 1px solid rgba(126,252,255,.45);
            background: linear-gradient(135deg, rgba(4,11,20,.96), rgba(20,40,66,.96));
            color: #eef5ff;
            border-radius: 20px;
            box-shadow: 0 24px 80px rgba(0,0,0,.42);
            font-family: Arial, Helvetica, sans-serif;
            overflow: hidden;
        }}

        .agenttrust-global-launcher-header {{
            padding: 13px 15px;
            background: rgba(126,252,255,.12);
            border-bottom: 1px solid rgba(255,255,255,.12);
            font-size: 13px;
            font-weight: 900;
            color: #7efcff;
            letter-spacing: .3px;
        }}

        .agenttrust-global-launcher-body {{
            padding: 14px 15px 15px 15px;
        }}

        .agenttrust-global-launcher-title {{
            font-size: 15px;
            font-weight: 900;
            margin-bottom: 7px;
            color: #ffffff;
        }}

        .agenttrust-global-launcher-text {{
            font-size: 12px;
            line-height: 1.45;
            color: #a8bbd4;
            margin-bottom: 12px;
        }}

        .agenttrust-global-launcher-actions {{
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }}

        .agenttrust-global-launcher-actions a {{
            text-decoration: none;
            font-size: 12px;
            font-weight: 900;
            border-radius: 999px;
            padding: 8px 10px;
            display: inline-block;
        }}

        .agenttrust-global-launcher-primary {{
            background: #7efcff;
            color: #04111f;
        }}

        .agenttrust-global-launcher-secondary {{
            background: rgba(255,255,255,.12);
            color: #eef5ff;
            border: 1px solid rgba(255,255,255,.16);
        }}

        @media(max-width:700px) {{
            .agenttrust-global-launcher {{
                right: 12px;
                bottom: 12px;
                width: 292px;
            }}
        }}
    </style>

    <div class="agenttrust-global-launcher">
        <div class="agenttrust-global-launcher-header">
            AgentTrust™ Integration Active
        </div>
        <div class="agenttrust-global-launcher-body">
            <div class="agenttrust-global-launcher-title">{target["label"]}</div>
            <div class="agenttrust-global-launcher-text">{target["context"]}</div>
            <div class="agenttrust-global-launcher-actions">
                <a class="agenttrust-global-launcher-primary" href="{target["url"]}">Open Hook</a>
                <a class="agenttrust-global-launcher-secondary" href="/agenttrust/integration-map">Integration Map</a>
            </div>
        </div>
    </div>
    """


@app.after_request
def agenttrust_global_launcher_injector(response):
    try:
        from flask import request

        path = request.path or ""

        if path.startswith("/static"):
            return response

        content_type = response.headers.get("Content-Type", "")

        if "text/html" not in content_type:
            return response

        if response.direct_passthrough:
            return response

        target = agenttrust_global_launcher_target(path)

        if target is None:
            return response

        html = response.get_data(as_text=True)

        if "AGENTTRUST_GLOBAL_NAV_INJECTED" in html:
            return response

        if "</body>" not in html:
            return response

        launcher = agenttrust_global_launcher_html(target)
        html = html.replace("</body>", launcher + "\n</body>")

        response.set_data(html)
        response.headers["Content-Length"] = str(len(response.get_data()))

        return response

    except Exception:
        return response

# ============================================================
# END AGENTTRUST_GLOBAL_LAUNCHER_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    target = "if __name__ == '__main__':"
    idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("AgentTrust global launcher installed.")
