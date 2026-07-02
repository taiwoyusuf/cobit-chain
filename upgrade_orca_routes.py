from pathlib import Path

app = Path("app.py")

text = app.read_text(encoding="utf-8")

old = '''
@app.route("/orca/command-center")
@app.route("/orca/operational-trust-command-center")
@app.route("/cobitchain/orca-command-center")
'''

new = '''
@app.route("/orca")
@app.route("/orca/")
@app.route("/orca/dashboard")
@app.route("/orca/command-center")
@app.route("/orca/executive")
@app.route("/orca/executive-dashboard")
@app.route("/orca/operational-trust")
@app.route("/orca/operational-trust-engine")
@app.route("/orca/operational-trust-command-center")
@app.route("/cobitchain/orca")
@app.route("/cobitchain/orca-command-center")
'''

text = text.replace(old,new)

app.write_text(text,encoding="utf-8")

print("Routes upgraded.")
