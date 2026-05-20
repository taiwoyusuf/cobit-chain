from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

start = text.find("# ============================================================\n# IRLT_GOVERNANCE_SINGULARITY_LAYER_V1_ACTIVE")

end = text.find("# END IRLT_GOVERNANCE_SINGULARITY_LAYER\n# ============================================================")

if start == -1 or end == -1:
    print("Could not locate inserted block.")
    raise SystemExit()

end = end + len("# END IRLT_GOVERNANCE_SINGULARITY_LAYER\n# ============================================================")

text = text[:start] + "\n\n" + text[end:]

APP.write_text(text, encoding="utf-8")

print("Broken block removed successfully.")
