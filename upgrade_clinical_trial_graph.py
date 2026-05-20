from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "Protocol & Governance Flow"

if MARKER in text:
    print("Enterprise graph upgrade already applied.")
    raise SystemExit(0)

old = '''
    <div class="graph">

        <div class="node blue" style="top:60px;left:70px;">
            <h3>Protocol</h3>
            <p>CT-PROT-4421</p>
        </div>

        <div class="node green" style="top:190px;left:320px;">
            <h3>eConsent</h3>
            <p>Immutable verified</p>
        </div>

        <div class="node green" style="top:360px;left:140px;">
            <h3>Patient Cohort</h3>
            <p>24 active participants</p>
        </div>

        <div class="node yellow" style="top:170px;left:620px;">
            <h3>AI Anomaly</h3>
            <p>Dosage variance</p>
        </div>

        <div class="node blue" style="top:360px;left:560px;">
            <h3>Purview</h3>
            <p>DLP retention enforced</p>
        </div>

        <div class="node green" style="top:560px;left:330px;">
            <h3>Evidence Ledger</h3>
            <p>Hash verified</p>
        </div>

        <div class="node red" style="top:540px;left:760px;">
            <h3>Deviation</h3>
            <p>CAPA unresolved</p>
        </div>

        <div class="node yellow" style="top:120px;left:960px;">
            <h3>Release Gate</h3>
            <p>Conditional hold</p>
        </div>

        <div class="line" style="top:130px;left:210px;width:190px;transform:rotate(28deg);"></div>
        <div class="line" style="top:280px;left:260px;width:160px;transform:rotate(65deg);"></div>
        <div class="line" style="top:250px;left:470px;width:180px;transform:rotate(-10deg);"></div>
        <div class="line" style="top:430px;left:420px;width:170px;transform:rotate(20deg);"></div>
        <div class="line" style="top:430px;left:710px;width:140px;transform:rotate(15deg);"></div>

    </div>
'''

new = r'''
    <div class="graph">

        <svg width="100%" height="100%" style="position:absolute;top:0;left:0;">

            <defs>

                <marker id="blueArrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto">
                    <polygon points="0 0, 10 3, 0 6" fill="#38bdf8"/>
                </marker>

                <marker id="greenArrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto">
                    <polygon points="0 0, 10 3, 0 6" fill="#22c55e"/>
                </marker>

                <marker id="yellowArrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto">
                    <polygon points="0 0, 10 3, 0 6" fill="#f59e0b"/>
                </marker>

                <marker id="redArrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto">
                    <polygon points="0 0, 10 3, 0 6" fill="#ef4444"/>
                </marker>

            </defs>

            <line x1="190" y1="145" x2="320" y2="145" stroke="#38bdf8" stroke-width="4" marker-end="url(#blueArrow)"/>
            <line x1="150" y1="210" x2="150" y2="360" stroke="#38bdf8" stroke-width="4" marker-end="url(#blueArrow)"/>

            <line x1="270" y1="390" x2="390" y2="390" stroke="#22c55e" stroke-width="4" marker-end="url(#greenArrow)"/>
            <line x1="510" y1="160" x2="620" y2="160" stroke="#22c55e" stroke-width="4" marker-end="url(#greenArrow)"/>

            <line x1="810" y1="160" x2="960" y2="160" stroke="#f59e0b" stroke-width="4" marker-end="url(#yellowArrow)"/>

            <line x1="700" y1="420" x2="820" y2="420" stroke="#ef4444" stroke-width="4" stroke-dasharray="10,10" marker-end="url(#redArrow)"/>
            <line x1="980" y1="420" x2="980" y2="220" stroke="#ef4444" stroke-width="4" stroke-dasharray="10,10" marker-end="url(#redArrow)"/>

            <line x1="500" y1="260" x2="560" y2="360" stroke="#38bdf8" stroke-width="4" marker-end="url(#blueArrow)"/>
            <line x1="660" y1="420" x2="760" y2="540" stroke="#38bdf8" stroke-width="4" marker-end="url(#blueArrow)"/>

            <line x1="270" y1="510" x2="330" y2="560" stroke="#22c55e" stroke-width="4" marker-end="url(#greenArrow)"/>
            <line x1="510" y1="610" x2="760" y2="610" stroke="#22c55e" stroke-width="4" marker-end="url(#greenArrow)"/>

        </svg>

        <div class="node blue" style="top:50px;left:60px;">
            <h3>Protocol</h3>
            <p>CT-PROT-4421</p>
        </div>

        <div class="node green" style="top:160px;left:320px;">
            <h3>eConsent</h3>
            <p>Immutable verified</p>
        </div>

        <div class="node green" style="top:360px;left:90px;">
            <h3>Patient Cohort</h3>
            <p>24 active participants</p>
        </div>

        <div class="node yellow" style="top:150px;left:620px;">
            <h3>AI Anomaly</h3>
            <p>Dosage variance</p>
        </div>

        <div class="node blue" style="top:360px;left:520px;">
            <h3>Purview</h3>
            <p>DLP retention enforced</p>
        </div>

        <div class="node green" style="top:560px;left:330px;">
            <h3>Evidence Ledger</h3>
            <p>Hash verified</p>
        </div>

        <div class="node red" style="top:540px;left:760px;">
            <h3>Deviation</h3>
            <p>CAPA unresolved</p>
        </div>

        <div class="node yellow" style="top:140px;left:930px;">
            <h3>Release Gate</h3>
            <p>Conditional hold</p>
        </div>

        <div style="position:absolute;bottom:18px;left:40px;display:flex;gap:35px;font-size:14px;">

            <div style="display:flex;align-items:center;gap:10px;">
                <div style="width:40px;height:4px;background:#38bdf8;"></div>
                <span>Protocol & Governance Flow</span>
            </div>

            <div style="display:flex;align-items:center;gap:10px;">
                <div style="width:40px;height:4px;background:#22c55e;"></div>
                <span>Evidence Integrity Flow</span>
            </div>

            <div style="display:flex;align-items:center;gap:10px;">
                <div style="width:40px;height:4px;background:#f59e0b;"></div>
                <span>Risk & Anomaly Flow</span>
            </div>

            <div style="display:flex;align-items:center;gap:10px;">
                <div style="width:40px;height:4px;background:#ef4444;"></div>
                <span>Deviation & Blocker Flow</span>
            </div>

        </div>

    </div>
'''

if old not in text:
    raise RuntimeError("Could not locate original graph block.")

text = text.replace(old, new)

APP.write_text(text, encoding="utf-8")

print("Enterprise connected graph upgrade applied successfully.")
