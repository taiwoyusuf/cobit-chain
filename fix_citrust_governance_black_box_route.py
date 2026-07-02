from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_GOVERNANCE_BLACK_BOX_ROUTE_FIX_V1_ACTIVE"

if MARKER in text:
    print("CITrust Governance Black Box route fix already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_GOVERNANCE_BLACK_BOX_ROUTE_FIX_V1_ACTIVE
# ============================================================

@app.route("/citrust/governance-black-box")
@app.route("/citrust/ai-action-flight-recorder")
def citrust_governance_black_box_route_fix():
    return redirect("/irlt-commercial-readiness/governance-black-box")

# ============================================================
# END CITRUST_GOVERNANCE_BLACK_BOX_ROUTE_FIX_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Governance Black Box route fix installed.")
