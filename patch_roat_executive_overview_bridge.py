from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

ACTIVE_MARKER = "# ROAT_EXECUTIVE_OVERVIEW_BRIDGE_ACTIVE"

if ACTIVE_MARKER in text:
    print("ROAT Executive Overview bridge already exists. No duplicate patch applied.")
    raise SystemExit(0)

required_existing = [
    "# DR_BRANCH_EXECUTIVE_OVERVIEW_BRIDGE_ACTIVE",
    "# ASSURANCE_PRODUCT_STACK_EXECUTIVE_OVERVIEW_BRIDGE_ACTIVE",
]

for marker in required_existing:
    if marker not in text:
        print(f"WARNING: Existing expected bridge marker not found: {marker}")
        print("Patch will still continue, but verify executive overview carefully after local test.")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError('Could not find if __name__ == "__main__": insertion point.')

code = r'''

# ROAT_EXECUTIVE_OVERVIEW_BRIDGE_ACTIVE
# Safe after_request bridge: adds ROAT panel to protected Executive Overview without overwriting route.

@app.after_request
def roat_executive_overview_injection(response):
    try:
        if request.path != "/executive-overview":
            return response

        if response.content_type and "text/html" not in response.content_type:
            return response

        html = response.get_data(as_text=True)

        if 'id="roat-executive-overview-panel"' in html:
            return response

        panel = """
        <section id="roat-executive-overview-panel" style="margin:28px auto;max-width:1180px;
            padding:26px;border-radius:24px;
            background:linear-gradient(135deg,#071827,#0c2742,#12395d);
            border:1px solid rgba(127,255,212,.38);
            box-shadow:0 0 30px rgba(0,255,220,.13);
            color:#eaf8ff;">

            <div style="font-size:12px;letter-spacing:1.5px;text-transform:uppercase;
                color:#7fffd4;font-weight:800;margin-bottom:8px;">
                Executive Assurance Layer
            </div>

            <h2 style="margin:0 0 10px 0;font-size:29px;color:#ffffff;">
                Regulated Operations Assurance Twin™
            </h2>

            <p style="font-size:15px;line-height:1.7;color:#c5e6f8;max-width:1000px;">
                ROAT is the flagship governance mirror for regulated operations. It continuously connects evidence,
                system truth, operational blockers, decision gates, maturity signals, and portable assurance into one
                defensible executive view. Instead of only reporting what happened, it helps leadership understand
                whether the operating state is trustworthy enough to proceed.
            </p>

            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
                gap:14px;margin-top:20px;">

                <div style="padding:17px;border-radius:17px;background:#081f33;
                    border:1px solid rgba(127,255,212,.24);">
                    <div style="font-size:12px;color:#a8d8ff;text-transform:uppercase;">Live Governance Mirror</div>
                    <div style="font-size:24px;font-weight:900;color:#7fffd4;margin-top:7px;">ACTIVE</div>
                    <div style="font-size:13px;color:#b8d8ec;margin-top:8px;">Senses evidence and operational state.</div>
                </div>

                <div style="padding:17px;border-radius:17px;background:#081f33;
                    border:1px solid rgba(127,255,212,.24);">
                    <div style="font-size:12px;color:#a8d8ff;text-transform:uppercase;">Cross-System Truth</div>
                    <div style="font-size:24px;font-weight:900;color:#7fffd4;margin-top:7px;">RECONCILED</div>
                    <div style="font-size:13px;color:#b8d8ec;margin-top:8px;">Compares process, evidence, and system records.</div>
                </div>

                <div style="padding:17px;border-radius:17px;background:#081f33;
                    border:1px solid rgba(127,255,212,.24);">
                    <div style="font-size:12px;color:#a8d8ff;text-transform:uppercase;">Decision Gates</div>
                    <div style="font-size:24px;font-weight:900;color:#7fffd4;margin-top:7px;">CONTROLLED</div>
                    <div style="font-size:13px;color:#b8d8ec;margin-top:8px;">Escalates blockers before assurance is issued.</div>
                </div>

                <div style="padding:17px;border-radius:17px;background:#081f33;
                    border:1px solid rgba(127,255,212,.24);">
                    <div style="font-size:12px;color:#a8d8ff;text-transform:uppercase;">Portable Assurance</div>
                    <div style="font-size:24px;font-weight:900;color:#7fffd4;margin-top:7px;">DEFENSIBLE</div>
                    <div style="font-size:13px;color:#b8d8ec;margin-top:8px;">Issues assurance only when the chain is complete.</div>
                </div>
            </div>

            <div style="margin-top:22px;padding:18px;border-radius:18px;
                background:rgba(4,18,32,.72);border:1px solid rgba(90,180,220,.30);">
                <div style="font-weight:900;color:#ffffff;margin-bottom:8px;">
                    Executive Value
                </div>
                <div style="font-size:14px;line-height:1.7;color:#c7e8fa;">
                    ROAT turns fragmented governance activity into an executive operating picture: readiness,
                    blockers, maturity, assurance passports, recovery governance, and evidence confidence. This
                    positions COBIT-Chain™ as a trust orchestration layer above systems of record, not a replacement
                    for them.
                </div>
            </div>

            <div style="display:flex;flex-wrap:wrap;gap:12px;margin-top:22px;">
                <a href="/regulated-operations-assurance-twin" style="color:#071827;background:#7fffd4;
                    padding:10px 14px;border-radius:12px;font-weight:900;text-decoration:none;">Open ROAT</a>
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

print("ROAT Executive Overview bridge patch applied successfully.")
