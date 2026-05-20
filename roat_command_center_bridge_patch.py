from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

ACTIVE_MARKER = "# ROAT_COMMAND_CENTER_BRIDGE_ACTIVE"

if ACTIVE_MARKER in text:
    print("ROAT Command Center bridge already exists. No duplicate patch applied.")
    raise SystemExit(0)

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError('Could not find if __name__ == "__main__": insertion point.')

code = r'''

# ROAT_COMMAND_CENTER_BRIDGE_ACTIVE
# Safe after_request bridge: adds ROAT panel to protected Command Center without overwriting route.

@app.after_request
def roat_command_center_bridge(response):
    try:
        if request.path != "/command-center":
            return response

        if response.content_type and "text/html" not in response.content_type:
            return response

        html = response.get_data(as_text=True)

        if "ROAT Command Center Bridge Active" in html:
            return response

        panel = """
        <section style="margin:28px auto;max-width:1180px;padding:24px;border-radius:22px;
            background:linear-gradient(135deg,#071827,#0b253d,#102f4f);
            border:1px solid rgba(125,255,212,.35);
            box-shadow:0 0 28px rgba(0,255,220,.12);color:#e8f7ff;">
            <div style="font-size:12px;letter-spacing:1.5px;text-transform:uppercase;color:#7fffd4;
                font-weight:700;margin-bottom:8px;">
                ROAT Command Center Bridge Active
            </div>

            <h2 style="margin:0 0 10px 0;font-size:28px;color:#ffffff;">
                Regulated Operations Assurance Twin™
            </h2>

            <p style="font-size:15px;line-height:1.65;color:#bddff5;max-width:980px;">
                The Regulated Operations Assurance Twin™ acts as COBIT-Chain’s flagship live governance mirror:
                it senses evidence, verifies integrity, reconciles cross-system truth, exposes operational blockers,
                gates decisions, and issues portable assurance only when the chain is defensible.
            </p>

            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px;margin-top:20px;">
                <div style="padding:16px;border-radius:16px;background:#081f33;border:1px solid rgba(125,255,212,.22);">
                    <div style="font-size:12px;color:#9ed8ff;text-transform:uppercase;">Evidence Sensing</div>
                    <div style="font-size:22px;font-weight:800;color:#7fffd4;margin-top:6px;">LIVE</div>
                </div>
                <div style="padding:16px;border-radius:16px;background:#081f33;border:1px solid rgba(125,255,212,.22);">
                    <div style="font-size:12px;color:#9ed8ff;text-transform:uppercase;">Integrity Verification</div>
                    <div style="font-size:22px;font-weight:800;color:#7fffd4;margin-top:6px;">ACTIVE</div>
                </div>
                <div style="padding:16px;border-radius:16px;background:#081f33;border:1px solid rgba(125,255,212,.22);">
                    <div style="font-size:12px;color:#9ed8ff;text-transform:uppercase;">Decision Gates</div>
                    <div style="font-size:22px;font-weight:800;color:#7fffd4;margin-top:6px;">CONTROLLED</div>
                </div>
                <div style="padding:16px;border-radius:16px;background:#081f33;border:1px solid rgba(125,255,212,.22);">
                    <div style="font-size:12px;color:#9ed8ff;text-transform:uppercase;">Assurance Output</div>
                    <div style="font-size:22px;font-weight:800;color:#7fffd4;margin-top:6px;">DEFENSIBLE</div>
                </div>
            </div>

            <div style="display:flex;flex-wrap:wrap;gap:12px;margin-top:22px;">
                <a href="/regulated-operations-assurance-twin" style="color:#071827;background:#7fffd4;
                    padding:10px 14px;border-radius:12px;font-weight:800;text-decoration:none;">Open ROAT</a>
                <a href="/cobit-chain-maturity-scorecard" style="color:#dff7ff;border:1px solid #3b8fb8;
                    padding:10px 14px;border-radius:12px;text-decoration:none;">Maturity Scorecard</a>
                <a href="/enterprise-assurance-passport-factory" style="color:#dff7ff;border:1px solid #3b8fb8;
                    padding:10px 14px;border-radius:12px;text-decoration:none;">Passport Factory</a>
                <a href="/governance-assurance-passport/BATCH-2026-041" style="color:#dff7ff;border:1px solid #3b8fb8;
                    padding:10px 14px;border-radius:12px;text-decoration:none;">Sample Assurance Passport</a>
                <a href="/recovery-governance-command-center" style="color:#dff7ff;border:1px solid #3b8fb8;
                    padding:10px 14px;border-radius:12px;text-decoration:none;">Recovery Governance</a>
            </div>
        </section>
        """

        if "</body>" in html:
            html = html.replace("</body>", panel + "</body>")
        else:
            html = html + panel

        response.set_data(html)
        response.headers["Content-Length"] = str(len(response.get_data()))
        return response

    except Exception:
        return response

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("ROAT Command Center bridge patch applied successfully.")
