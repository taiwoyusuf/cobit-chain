from pathlib import Path

APP_PATH = Path("app.py")
text = APP_PATH.read_text(encoding="utf-8")

MODULE_MARKER = "RLTTRUST_IRLT_COMMERCIAL_READINESS_COMMAND_CENTER_V1_ACTIVE"
VISUAL_MARKER = "RLTTRUST_IRLT_WORLD_CLASS_VISUAL_V2_ACTIVE"

if MODULE_MARKER not in text:
    raise RuntimeError("RLTTrust command center module was not found. Open /irlt-commercial-readiness first or confirm the previous patch exists.")

if VISUAL_MARKER in text:
    print("RLTTrust world-class visual v2 already installed. No duplicate insertion made.")
else:
    start = text.index(MODULE_MARKER)
    end_marker = "# End RLTTrust™ / IRLT Commercial Readiness Command Center"
    end = text.find(end_marker, start)
    if end == -1:
        end = len(text)

    module = text[start:end]

    visual_css = r'''
        <style id="RLTTRUST_IRLT_WORLD_CLASS_VISUAL_V2_ACTIVE">
            :root {
                --rlt-orange: #ff7a18;
                --rlt-orange2: #ff9f1c;
                --rlt-amber: #ffd166;
                --rlt-charcoal: #0b0d12;
                --rlt-graphite: #151922;
                --rlt-steel: #8d96a8;
                --rlt-silver: #d8dde8;
                --rlt-panel: rgba(18, 22, 31, 0.86);
                --rlt-panel2: rgba(30, 34, 45, 0.72);
                --rlt-border: rgba(255, 255, 255, 0.115);
                --rlt-orange-border: rgba(255, 122, 24, 0.40);
                --rlt-orange-glow: rgba(255, 122, 24, 0.30);
            }

            body {
                background:
                    radial-gradient(circle at 8% 0%, rgba(255, 122, 24, 0.22), transparent 30%),
                    radial-gradient(circle at 92% 8%, rgba(255, 159, 28, 0.16), transparent 34%),
                    radial-gradient(circle at 45% 22%, rgba(255, 255, 255, 0.06), transparent 28%),
                    linear-gradient(135deg, #050608 0%, #0b0d12 34%, #111722 67%, #06070a 100%) !important;
            }

            .wrap {
                max-width: 1880px !important;
                padding: 34px 46px !important;
            }

            .hero {
                position: relative;
                overflow: hidden;
                min-height: 360px;
                border: 1px solid rgba(255, 122, 24, 0.28) !important;
                background:
                    linear-gradient(135deg, rgba(255,122,24,0.20), rgba(38,43,55,0.90) 35%, rgba(12,14,20,0.94)),
                    repeating-linear-gradient(90deg, rgba(255,255,255,0.025) 0 1px, transparent 1px 68px) !important;
                box-shadow:
                    0 34px 110px rgba(0,0,0,0.58),
                    0 0 90px rgba(255,122,24,0.10) !important;
            }

            .hero:before {
                content: "";
                position: absolute;
                inset: -2px;
                background:
                    radial-gradient(circle at 70% 30%, rgba(255,122,24,0.18), transparent 18%),
                    radial-gradient(circle at 78% 64%, rgba(255,209,102,0.10), transparent 16%),
                    linear-gradient(120deg, transparent 0%, rgba(255,255,255,0.05) 48%, transparent 52%);
                pointer-events: none;
            }

            .hero:after {
                content: "";
                position: absolute;
                right: -120px;
                top: -180px;
                width: 520px;
                height: 520px;
                border-radius: 50%;
                border: 1px solid rgba(255,122,24,0.25);
                box-shadow:
                    inset 0 0 70px rgba(255,122,24,0.10),
                    0 0 90px rgba(255,122,24,0.12);
                pointer-events: none;
            }

            .hero-grid {
                position: relative;
                z-index: 2;
                grid-template-columns: minmax(0, 1.72fr) minmax(360px, 0.72fr) !important;
                gap: 28px !important;
            }

            h1 {
                max-width: 1120px;
                font-size: clamp(42px, 4.4vw, 76px) !important;
                letter-spacing: -0.055em;
                line-height: 0.94 !important;
            }

            h2 {
                letter-spacing: -0.025em;
                font-size: clamp(24px, 1.8vw, 34px) !important;
            }

            h3 {
                letter-spacing: -0.015em;
            }

            .eyebrow {
                color: var(--rlt-orange2) !important;
                text-shadow: 0 0 18px rgba(255,122,24,0.34);
            }

            .score-card {
                background:
                    linear-gradient(180deg, rgba(255,122,24,0.11), rgba(15,18,26,0.90)) !important;
                border: 1px solid rgba(255,122,24,0.30) !important;
                box-shadow:
                    inset 0 1px 0 rgba(255,255,255,0.08),
                    0 22px 70px rgba(0,0,0,0.42) !important;
            }

            .score {
                color: var(--rlt-orange2) !important;
                text-shadow: 0 0 34px rgba(255,122,24,0.35);
                font-size: clamp(72px, 6vw, 116px) !important;
            }

            .label-pill {
                background: rgba(255,122,24,0.12) !important;
                border: 1px solid rgba(255,122,24,0.38) !important;
                color: #ffd7ad !important;
                box-shadow: 0 0 20px rgba(255,122,24,0.08);
            }

            .nav a {
                background: rgba(255,255,255,0.055) !important;
                border: 1px solid rgba(255,122,24,0.22) !important;
                color: #f2f4f8 !important;
                transition: transform .18s ease, border-color .18s ease, background .18s ease;
            }

            .nav a:hover {
                transform: translateY(-2px);
                border-color: rgba(255,122,24,0.72) !important;
                background: rgba(255,122,24,0.13) !important;
            }

            .section {
                margin-top: 34px !important;
            }

            .card, .warning-panel, .critical-panel, .ai-box, table {
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.055), rgba(255,255,255,0.025)),
                    rgba(17, 20, 28, 0.86) !important;
                border: 1px solid rgba(255,255,255,0.115) !important;
                box-shadow:
                    0 24px 70px rgba(0,0,0,0.34),
                    inset 0 1px 0 rgba(255,255,255,0.055) !important;
                backdrop-filter: blur(14px);
            }

            .card:hover {
                border-color: rgba(255,122,24,0.35) !important;
                transform: translateY(-2px);
                transition: transform .18s ease, border-color .18s ease;
            }

            .grid-4 {
                grid-template-columns: repeat(4, minmax(0, 1fr)) !important;
            }

            .grid-3 {
                grid-template-columns: repeat(3, minmax(0, 1fr)) !important;
            }

            .grid-2 {
                grid-template-columns: repeat(2, minmax(0, 1fr)) !important;
            }

            .bar {
                height: 11px !important;
                background: rgba(255,255,255,0.075) !important;
                border: 1px solid rgba(255,255,255,0.06);
            }

            .bar span {
                background: linear-gradient(90deg, #ff4d4d, #ff7a18, #ffd166, #37d67a) !important;
                box-shadow: 0 0 18px rgba(255,122,24,0.30);
            }

            .tag {
                background: rgba(255,122,24,0.12) !important;
                border: 1px solid rgba(255,122,24,0.30) !important;
                color: #ffd7ad !important;
            }

            .tag.green {
                color: #b9ffd0 !important;
                border-color: rgba(55,214,122,0.38) !important;
                background: rgba(55,214,122,0.10) !important;
            }

            .tag.yellow {
                color: #ffe6a8 !important;
                border-color: rgba(255,209,102,0.38) !important;
                background: rgba(255,209,102,0.10) !important;
            }

            .tag.red {
                color: #ffc2c2 !important;
                border-color: rgba(255,92,122,0.38) !important;
                background: rgba(255,92,122,0.10) !important;
            }

            .visual-v2 {
                position: relative;
            }

            .executive-strip {
                display: grid;
                grid-template-columns: repeat(5, minmax(0, 1fr));
                gap: 16px;
                margin-bottom: 18px;
            }

            .executive-kpi {
                position: relative;
                overflow: hidden;
                min-height: 128px;
                border-radius: 24px;
                padding: 18px;
                background:
                    linear-gradient(135deg, rgba(255,122,24,0.15), rgba(255,255,255,0.04)),
                    rgba(17,20,28,0.88);
                border: 1px solid rgba(255,122,24,0.25);
                box-shadow:
                    0 20px 60px rgba(0,0,0,0.34),
                    inset 0 1px 0 rgba(255,255,255,0.075);
            }

            .executive-kpi:after {
                content: "";
                position: absolute;
                width: 112px;
                height: 112px;
                border-radius: 50%;
                right: -38px;
                top: -42px;
                background: radial-gradient(circle, rgba(255,122,24,0.26), transparent 68%);
            }

            .executive-kpi small {
                display: block;
                color: #aeb6c6;
                text-transform: uppercase;
                letter-spacing: .11em;
                font-size: 10px;
                font-weight: 900;
                margin-bottom: 10px;
            }

            .executive-kpi strong {
                display: block;
                font-size: 25px;
                color: #fff2e6;
                letter-spacing: -0.035em;
                margin-bottom: 8px;
            }

            .executive-kpi span {
                color: #a8b0bf;
                font-size: 13px;
                line-height: 1.45;
            }

            .mission-panel {
                display: grid;
                grid-template-columns: minmax(540px, 0.85fr) minmax(0, 1.15fr);
                gap: 18px;
                align-items: stretch;
            }

            .mission-orbit {
                position: relative;
                min-height: 500px;
                border-radius: 32px;
                overflow: hidden;
                border: 1px solid rgba(255,122,24,0.28);
                background:
                    radial-gradient(circle at 50% 50%, rgba(255,122,24,0.20), transparent 17%),
                    radial-gradient(circle at 50% 50%, rgba(255,255,255,0.05), transparent 30%),
                    linear-gradient(135deg, rgba(32,35,44,0.88), rgba(8,9,13,0.92));
                box-shadow: 0 28px 90px rgba(0,0,0,0.42);
            }

            .orbit-ring {
                position: absolute;
                border-radius: 50%;
                border: 1px solid rgba(255,122,24,0.24);
                inset: 52px;
                box-shadow: inset 0 0 42px rgba(255,122,24,0.055);
            }

            .orbit-ring.r2 { inset: 105px; border-color: rgba(255,255,255,0.13); }
            .orbit-ring.r3 { inset: 160px; border-color: rgba(255,122,24,0.30); }

            .orbit-core {
                position: absolute;
                left: 50%;
                top: 50%;
                width: 172px;
                height: 172px;
                transform: translate(-50%, -50%);
                border-radius: 50%;
                display: grid;
                place-items: center;
                text-align: center;
                background:
                    radial-gradient(circle, rgba(255,122,24,0.32), rgba(22,24,31,0.92) 62%);
                border: 1px solid rgba(255,122,24,0.50);
                box-shadow:
                    0 0 90px rgba(255,122,24,0.24),
                    inset 0 0 32px rgba(255,255,255,0.08);
            }

            .orbit-core b {
                display: block;
                color: white;
                font-size: 22px;
                letter-spacing: -0.04em;
            }

            .orbit-core small {
                color: #ffd7ad;
                font-weight: 800;
                letter-spacing: .08em;
                text-transform: uppercase;
                font-size: 10px;
            }

            .node {
                position: absolute;
                width: 154px;
                min-height: 58px;
                border-radius: 18px;
                padding: 12px;
                background: rgba(10,12,17,0.78);
                border: 1px solid rgba(255,122,24,0.32);
                color: #f4f7fb;
                box-shadow: 0 18px 45px rgba(0,0,0,0.32);
                font-size: 12px;
            }

            .node b { display: block; color: #ffd7ad; font-size: 12px; margin-bottom: 3px; }
            .node span { color: #aeb6c6; line-height: 1.35; }

            .n1 { left: 42px; top: 70px; }
            .n2 { right: 42px; top: 70px; }
            .n3 { left: 26px; top: 220px; }
            .n4 { right: 26px; top: 220px; }
            .n5 { left: 105px; bottom: 46px; }
            .n6 { right: 105px; bottom: 46px; }

            .mission-copy {
                border-radius: 32px;
                padding: 28px;
                background:
                    linear-gradient(135deg, rgba(255,122,24,0.13), rgba(255,255,255,0.035)),
                    rgba(17,20,28,0.88);
                border: 1px solid rgba(255,255,255,0.12);
                box-shadow: 0 28px 90px rgba(0,0,0,0.34);
            }

            .mission-copy h2 {
                font-size: clamp(30px, 3vw, 54px) !important;
                line-height: .98;
                margin-bottom: 14px;
            }

            .mission-copy p {
                font-size: 16px;
            }

            .mission-bullets {
                display: grid;
                grid-template-columns: repeat(2, minmax(0, 1fr));
                gap: 12px;
                margin-top: 20px;
            }

            .mission-bullet {
                border-radius: 18px;
                padding: 14px;
                background: rgba(255,255,255,0.045);
                border: 1px solid rgba(255,255,255,0.09);
                color: #d8dde8;
                font-size: 13px;
                line-height: 1.45;
            }

            .mission-bullet b {
                color: #ffd7ad;
                display: block;
                margin-bottom: 4px;
            }

            th {
                background: rgba(255,122,24,0.10) !important;
                color: #fff2e6 !important;
            }

            td strong {
                color: #fff2e6 !important;
            }

            .passport {
                border: 1px solid rgba(255,122,24,0.32) !important;
                background: rgba(255,122,24,0.10) !important;
                color: #ffd7ad !important;
                box-shadow: 0 0 22px rgba(255,122,24,0.08);
            }

            .footer {
                color: #8d96a8 !important;
                border-top: 1px solid rgba(255,122,24,0.20) !important;
            }

            @media (min-width: 1500px) {
                .grid-4 {
                    grid-template-columns: repeat(4, minmax(0, 1fr)) !important;
                }
                .feature {
                    min-height: 270px !important;
                }
            }

            @media (max-width: 1250px) {
                .hero-grid,
                .mission-panel,
                .grid-4,
                .grid-3,
                .grid-2,
                .executive-strip,
                .timeline {
                    grid-template-columns: 1fr !important;
                }
                .wrap {
                    padding: 24px !important;
                }
                .mission-orbit {
                    min-height: 560px;
                }
                .node {
                    width: 138px;
                }
            }

            @media (max-width: 720px) {
                .mission-bullets {
                    grid-template-columns: 1fr;
                }
                .node {
                    position: relative;
                    left: auto !important;
                    right: auto !important;
                    top: auto !important;
                    bottom: auto !important;
                    width: auto;
                    margin: 10px;
                }
                .orbit-ring, .orbit-core {
                    display: none;
                }
                .mission-orbit {
                    min-height: auto;
                    padding: 12px;
                }
            }
        </style>
'''

    if "        </style>\n    </head>" not in module:
        raise RuntimeError("Could not find command-center style closing block to enhance.")

    module = module.replace(
        "        </style>\n    </head>",
        "        </style>\n" + visual_css + "\n    </head>",
        1
    )

    visual_section = r'''
            <section class="section visual-v2" id="RLTTRUST_IRLT_WORLD_CLASS_VISUAL_V2_ACTIVE">
                <div class="executive-strip">
                    <div class="executive-kpi">
                        <small>Readiness Mode</small>
                        <strong>Can We Treat Tomorrow?</strong>
                        <span>Executive answer powered by release, custody, QC, treatment-window, and evidence readiness.</span>
                    </div>
                    <div class="executive-kpi">
                        <small>Physics-Aware Signal</small>
                        <strong>Readiness Decays</strong>
                        <span>Isotope timing, QC delay, courier latency, and patient slot risk are treated as live governance signals.</span>
                    </div>
                    <div class="executive-kpi">
                        <small>Inspection Posture</small>
                        <strong>Survive Tomorrow</strong>
                        <span>Evidence gaps, stale records, weak approvals, and custody breaks are surfaced before inspection pressure.</span>
                    </div>
                    <div class="executive-kpi">
                        <small>Release Confidence</small>
                        <strong>Defensible Release</strong>
                        <span>QA release is scored against evidence completeness, CAPA, EM, SOP, training, access, and custody.</span>
                    </div>
                    <div class="executive-kpi">
                        <small>Network Scale</small>
                        <strong>Commercial Mesh</strong>
                        <span>Designed for multi-site IRLT scale-up across manufacturing, QC, logistics, and treatment coordination.</span>
                    </div>
                </div>

                <div class="mission-panel">
                    <div class="mission-orbit">
                        <div class="orbit-ring"></div>
                        <div class="orbit-ring r2"></div>
                        <div class="orbit-ring r3"></div>

                        <div class="orbit-core">
                            <div>
                                <small>RLTTrust™</small>
                                <b>IRLT Readiness Core</b>
                            </div>
                        </div>

                        <div class="node n1"><b>Isotope</b><span>Source, activity, timing, radioactive material accountability.</span></div>
                        <div class="node n2"><b>QC / QA</b><span>Testing, release, deviation impact, defensibility.</span></div>
                        <div class="node n3"><b>Evidence</b><span>AuditVault™, hashes, lineage, stale-record detection.</span></div>
                        <div class="node n4"><b>Custody</b><span>Shipment, cold-chain, receipt, treatment-site readiness.</span></div>
                        <div class="node n5"><b>People</b><span>Training, SOP alignment, access, operator accountability.</span></div>
                        <div class="node n6"><b>Inspection</b><span>Auditor questions mapped to governed evidence packets.</span></div>
                    </div>

                    <div class="mission-copy">
                        <div class="eyebrow">World-Class IRLT Operating Intelligence</div>
                        <h2>One command center for commercial radiopharma readiness.</h2>
                        <p>
                            RLTTrust™ turns IRLT commercialization from scattered departmental status into a live,
                            governed, physics-aware readiness model. It understands that in radiopharma, readiness is not static:
                            it can decay with isotope activity, QC delays, courier timing, patient slot exposure, and stale evidence.
                        </p>
                        <p>
                            The goal is simple: help leadership defend whether the operation can manufacture, release, ship,
                            receive, and support treatment with governed evidence.
                        </p>

                        <div class="mission-bullets">
                            <div class="mission-bullet">
                                <b>Decay-Aware Readiness</b>
                                Readiness is measured against isotope timing, not just document status.
                            </div>
                            <div class="mission-bullet">
                                <b>Patient Slot Protection</b>
                                Treatment coordination becomes part of operational governance.
                            </div>
                            <div class="mission-bullet">
                                <b>Release Defensibility</b>
                                QA release is backed by evidence, dependencies, and approval lineage.
                            </div>
                            <div class="mission-bullet">
                                <b>Inspection Survivability</b>
                                Auditor questions are mapped to evidence packets and governance passports.
                            </div>
                            <div class="mission-bullet">
                                <b>Commercial Scale-Up Mesh</b>
                                Designed for multi-site IRLT manufacturing and logistics readiness.
                            </div>
                            <div class="mission-bullet">
                                <b>Human-Controlled AI</b>
                                AI explains risk, but people remain the authoritative control layer.
                            </div>
                        </div>
                    </div>
                </div>
            </section>

'''

    needle = '            </section>\n\n            <section class="section" id="decay">'
    if needle not in module:
        raise RuntimeError("Could not find hero-to-decay insertion point.")

    module = module.replace(
        needle,
        '            </section>\n\n' + visual_section + '            <section class="section" id="decay">',
        1
    )

    text = text[:start] + module + text[end:]
    APP_PATH.write_text(text, encoding="utf-8")
    print("Installed RLTTrust world-class orange/grey visual v2 successfully.")

