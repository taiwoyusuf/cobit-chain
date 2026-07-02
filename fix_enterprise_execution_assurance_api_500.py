from pathlib import Path
import re

path = Path("app.py")
text = path.read_text(encoding="utf-8")

start = "# COBITCHAIN_ENTERPRISE_EXECUTION_ASSURANCE_CAPABILITY_ROUTES_V1_START"
end = "# COBITCHAIN_ENTERPRISE_EXECUTION_ASSURANCE_CAPABILITY_ROUTES_V1_END"

new_block = r'''
# COBITCHAIN_ENTERPRISE_EXECUTION_ASSURANCE_CAPABILITY_ROUTES_V1_START
@app.route("/platform/enterprise-execution-assurance")
@app.route("/platform/execution-assurance")
def platform_enterprise_execution_assurance():
    from pathlib import Path
    from flask import Response

    page = Path("platform_enterprise_execution_assurance.html")
    if page.exists():
        return Response(page.read_text(encoding="utf-8-sig"), mimetype="text/html")

    fallback = """
    <!doctype html>
    <html>
    <head><title>Enterprise Execution Assurance</title></head>
    <body>
        <h1>Enterprise Execution Assurance</h1>
        <p>Capability page not found.</p>
    </body>
    </html>
    """
    return Response(fallback, mimetype="text/html", status=404)


@app.route("/api/platform/enterprise-execution-assurance/demo")
@app.route("/api/platform/execution-assurance/demo")
def api_platform_enterprise_execution_assurance_demo():
    from pathlib import Path
    from flask import jsonify

    summary = Path("enterprise_execution_assurance_capability_patch_v1_summary.json")

    fallback = {
        "patch_marker": "COBITCHAIN_ENTERPRISE_EXECUTION_ASSURANCE_CAPABILITY_PATCH_V1_ACTIVE",
        "patch_type": "enterprise_execution_assurance_capability_layer",
        "platform_redesign": False,
        "new_capability_layer": True,
        "capability_name": "Enterprise Execution Assurance",
        "updated_lifecycle_sequence": "Discovery -> Visibility -> Governance -> Operationalization -> Enterprise Execution Assurance -> Evidence -> Continuous Assurance -> Operational Trust",
        "core_question": "Was the AI recommendation executed safely, correctly, under policy, and with complete evidence?",
        "purpose": "Evaluate whether AI-generated recommendations were translated into enterprise actions safely, correctly, under policy, and with complete evidence.",
        "platform_position": "Between Operationalization and Evidence",
        "evaluation_areas": [
            "Workflow authorization",
            "Runtime policy enforcement",
            "Enterprise system interaction",
            "API invocation traceability",
            "Human approval checkpoints",
            "Rollback capability",
            "Execution evidence",
            "Outcome verification",
            "Continuous monitoring",
            "Audit reconstruction"
        ],
        "execution_assurance_modules": [
            "AI Runtime Assurance",
            "Workflow Assurance",
            "Enterprise Action Assurance",
            "Runtime Policy Assurance",
            "AI Orchestration Assurance",
            "Agent Runtime Evidence"
        ]
    }

    if not summary.exists():
        return jsonify(fallback)

    try:
        import json
        data = json.loads(summary.read_text(encoding="utf-8-sig"))
        return jsonify(data)
    except Exception as exc:
        fallback["summary_read_error"] = str(exc)
        return jsonify(fallback)
# COBITCHAIN_ENTERPRISE_EXECUTION_ASSURANCE_CAPABILITY_ROUTES_V1_END
'''

pattern = re.escape(start) + r".*?" + re.escape(end)

if re.search(pattern, text, flags=re.DOTALL):
    text = re.sub(pattern, new_block.strip(), text, flags=re.DOTALL)
else:
    if 'if __name__ == "__main__"' in text:
        text = text.replace('if __name__ == "__main__"', new_block.strip() + "\n\nif __name__ == \"__main__\"", 1)
    elif "if __name__ == '__main__'" in text:
        text = text.replace("if __name__ == '__main__'", new_block.strip() + "\n\nif __name__ == '__main__'", 1)
    else:
        text = text.rstrip() + "\n\n" + new_block.strip() + "\n"

path.write_text(text, encoding="utf-8")

print("PATCHED: app.py Enterprise Execution Assurance API route repaired.")
