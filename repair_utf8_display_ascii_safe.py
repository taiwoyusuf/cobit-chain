from pathlib import Path
import re

ROOT = Path(".")
REPORT = ROOT / "utf8_display_repair_report.txt"

files = [ROOT / "app.py"]
files += sorted(ROOT.glob("*.html"))

def mojibake_pair(utf8_hex):
    raw = bytes.fromhex(utf8_hex)
    bad = raw.decode("cp1252")
    good = raw.decode("utf-8")
    return bad, good

# ASCII-only definitions. These generate replacements for mojibake like TM, arrows, quotes, dashes, bullets.
utf8_hex_values = [
    "e284a2",      # trademark
    "e28692",      # right arrow
    "e28690",      # left arrow
    "e28691",      # up arrow
    "e28693",      # down arrow
    "e28792",      # double right arrow
    "e280a2",      # bullet
    "e280a6",      # ellipsis
    "e28093",      # en dash
    "e28094",      # em dash
    "e28098",      # left single quote
    "e28099",      # right single quote
    "e2809c",      # left double quote
    "e2809d",      # right double quote
    "e280a1",      # dagger
    "e280ba",      # single right angle
    "e280b9",      # single left angle
    "c2a9",        # copyright
    "c2ae",        # registered
    "c2b1",        # plus-minus
    "c2b7",        # middle dot
    "c397",        # multiplication
    "c3b7",        # division
    "c3a9",        # e acute
    "c3a8",        # e grave
    "c3a1",        # a acute
    "c3ad",        # i acute
    "c3b3",        # o acute
    "c3ba",        # u acute
    "c3b1",        # n tilde
    "c3bc",        # u umlaut
    "c3b6",        # o umlaut
    "c3a4",        # a umlaut
    "e29c85",      # check mark emoji
    "e29d8c",      # cross mark emoji
    "e29aa0",      # warning sign
    "f09f9a80",    # rocket
    "f09f9492",    # lock
    "f09f938c",    # pushpin
    "f09f938a",    # chart
    "f09fa7a0",    # brain
    "f09fa7ad",    # compass
    "f09f9ba1",    # shield
]

replacements = []
for value in utf8_hex_values:
    try:
        replacements.append(mojibake_pair(value))
    except Exception:
        pass

manual_replacements = [
    ("CITrust" + mojibake_pair("e284a2")[0], "CITrust" + mojibake_pair("e284a2")[1]),
    ("AgentTrust" + mojibake_pair("e284a2")[0], "AgentTrust" + mojibake_pair("e284a2")[1]),
    ("COBIT-Chain" + mojibake_pair("e284a2")[0], "COBIT-Chain" + mojibake_pair("e284a2")[1]),
    ("Assurance Engineering" + mojibake_pair("e284a2")[0], "Assurance Engineering" + mojibake_pair("e284a2")[1]),
    ("Governance Vision" + mojibake_pair("e284a2")[0], "Governance Vision" + mojibake_pair("e284a2")[1]),
    ("Operational Trust" + mojibake_pair("e284a2")[0], "Operational Trust" + mojibake_pair("e284a2")[1]),
    ("AEBOK" + mojibake_pair("e284a2")[0], "AEBOK" + mojibake_pair("e284a2")[1]),
]

replacements = manual_replacements + replacements

def repair_text(text):
    original = text

    for _ in range(4):
        changed = False
        for bad, good in replacements:
            if bad in text:
                text = text.replace(bad, good)
                changed = True
        if not changed:
            break

    # Clean common leftover fragments around trademark and arrows.
    tm = mojibake_pair("e284a2")[1]
    arrow = mojibake_pair("e28692")[1]

    text = text.replace(tm + ",¢", tm)
    text = text.replace(tm + "¢", tm)
    text = text.replace(tm + ",", tm)
    text = text.replace(tm + "‚", tm)
    text = text.replace(tm + "‚¢", tm)

    text = text.replace("CITrust,,¢", "CITrust" + tm)
    text = text.replace("CITrust,¢", "CITrust" + tm)
    text = text.replace("CITrust¢", "CITrust" + tm)
    text = text.replace("AgentTrust,,¢", "AgentTrust" + tm)
    text = text.replace("AgentTrust,¢", "AgentTrust" + tm)
    text = text.replace("AgentTrust¢", "AgentTrust" + tm)

    # Fix common chain text after generic replacement.
    text = text.replace("Ticket " + arrow, "Ticket " + arrow)
    text = text.replace("CI " + arrow, "CI " + arrow)
    text = text.replace("Owner " + arrow, "Owner " + arrow)
    text = text.replace("Support Group " + arrow, "Support Group " + arrow)
    text = text.replace("MyAccess " + arrow, "MyAccess " + arrow)
    text = text.replace("SOP " + arrow, "SOP " + arrow)
    text = text.replace("Evidence " + arrow, "Evidence " + arrow)

    return text, text != original

report = []
report.append("COBIT-Chain UTF8 Display Repair Report")
report.append("============================================================")
report.append("")

changed_files = []

for path in files:
    if not path.exists() or not path.is_file():
        continue

    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        report.append("SKIPPED non-UTF8 file: " + str(path))
        continue

    repaired, changed = repair_text(text)

    if changed:
        backup = path.with_name(path.name + ".backup_before_utf8_display_repair")
        if not backup.exists():
            backup.write_text(text, encoding="utf-8")
        path.write_text(repaired, encoding="utf-8")
        changed_files.append(str(path))
        report.append("REPAIRED: " + str(path))
    else:
        report.append("OK: " + str(path))

report.append("")
report.append("Changed files:")
if changed_files:
    for item in changed_files:
        report.append("  - " + item)
else:
    report.append("  None")

report.append("")
report.append("This repair cleans display corruption in stored app.py and local html files.")
report.append("It does not remove the floating AgentTrust box.")

REPORT.write_text("\n".join(report), encoding="utf-8")
print("\n".join(report))
