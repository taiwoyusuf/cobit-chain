from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

if "SHIFT_OPERATIONAL_GRAVITY_ENGINE_ACTIVE" not in text:
    raise RuntimeError("Operational Gravity marker missing.")

launcher_marker = "SHIFT_OPERATIONAL_GRAVITY_LAUNCHER_LINK_ACTIVE"
command_marker = "SHIFT_OPERATIONAL_GRAVITY_COMMAND_LINK_ACTIVE"

if launcher_marker not in text:
    target = '<div class="card"><div class="label">Window Compression</div><div class="value">82%</div><p><a href="/shift-treatment-window-compression">Open Compression Simulator</a></p></div>'
    replacement = target + '''
<!-- SHIFT_OPERATIONAL_GRAVITY_LAUNCHER_LINK_ACTIVE -->
<div class="card"><div class="label">Operational Gravity</div><div class="value">31%</div><p><a href="/shift-operational-gravity">Open Gravity Engine</a></p></div>'''
    if target not in text:
        raise RuntimeError("Could not find Shift Advanced Launcher insertion point.")
    text = text.replace(target, replacement, 1)
else:
    print("Launcher link already exists.")

if command_marker not in text:
    target = '<a href="/shift-treatment-window-compression" style="display:inline-block;padding:12px 16px;border-radius:14px;'
    insert = '''<!-- SHIFT_OPERATIONAL_GRAVITY_COMMAND_LINK_ACTIVE -->
            <div style="margin-top:10px;">
                <a href="/shift-operational-gravity" style="display:inline-block;padding:12px 16px;border-radius:14px;
                background:#f59e0b;color:#06111f;text-decoration:none;font-weight:900;">
                    Open Operational Gravity Engine
                </a>
            </div>

            '''
    if target not in text:
        raise RuntimeError("Could not find Command Center treatment-window link insertion point.")
    text = text.replace(target, insert + target, 1)
else:
    print("Command link already exists.")

APP.write_text(text, encoding="utf-8")

print("Operational Gravity links added.")
