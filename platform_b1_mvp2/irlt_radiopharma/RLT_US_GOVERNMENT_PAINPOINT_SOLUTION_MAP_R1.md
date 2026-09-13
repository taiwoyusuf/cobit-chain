# U.S. RLT Government Pain-Point and Solution Map R1

**Status:** PUBLIC PROVENANCE-SAFE RESEARCH / COMMERCIALIZATION MAP  
**Workstream:** IRLT / Radiopharma Operations  
**Date frozen:** 2026-09-13  
**Repository role:** public evidence that the IRLT/Radiopharma program is being developed against concrete U.S. government-identified problems in isotope supply, radiopharmaceutical manufacturing, metrology, medical-use regulation, patient administration, radiation safety, post-treatment release, and cancer-care access.

## Scope and claim boundary

This document is a high-level public problem-to-solution map. It intentionally does **not** disclose confidential algorithms, detailed test fixtures, proprietary implementation logic, unpublished candidate claims, or any patentability conclusion.

Government reports, enforcement actions, standards work, event reports, proposed rules, and public-health materials validate or illuminate the **problem space**. They do not constitute U.S. Government endorsement, certification, validation, procurement, or acceptance of COBIT-Chain, RAMAT Vision, IRLT, RPA-ASTC, or any related product.

The architecture remains bounded by the following separation:

**Existing regulated systems execute -> RAMAT Vision observes physical/contextual reality -> COBIT-Chain establishes evidence/provenance/standing -> authorized humans retain consequential authority.**

The program does not replace a dose calibrator, qualified analytical instrument, authorized user physician, nuclear pharmacist, RSO, medical physicist, quality unit, EHR, LIMS, MES, QMS, BMS/EMS, or regulator.

---

# 1. Core national problem

Radiopharma is a **time-decaying, patient-bound, regulator-crossing evidence chain**.

The controlled mission does not end when a radiopharmaceutical batch is released. It extends through isotope availability, manufacturing capacity, release, shipment, receiving assay, patient-specific written directive, clinical readiness, administration configuration, actual delivered activity, localization/outcome evidence, patient release, residual material, waste, and reconstruction.

A central research/commercial thesis of the IRLT program is therefore:

> **One governed evidence continuum from isotope source to patient consequence and radioactive end-of-life.**

The recurring U.S. federal signal is fragmentation: DOE/GAO see isotope supply and demand; FDA sees manufacturing and CGMP; NIST sees measurement traceability; NRC/Agreement States see licensed medical use and medical events; hospitals see patient execution; CMS sees payment/provenance incentives; public-health agencies see care-access constraints. The program is designed to preserve the governed relationship among those consequence-bearing stages without pretending one system owns every source record.

---

# 2. U.S. Government pain-point -> architecture response map

## US-RLT-P01 — Critical isotope demand, shortage, foreign dependency, and weak systematic forecasting

**Government signal.** GAO-26-108053 found that DOE's Isotope Research and Development and Production program produced/sold/distributed 265 isotopes in FY2020-FY2025 and made more than 7,700 shipments, most for medical purposes. GAO found that market needs were assessed case-by-case and industry/customer interactions were manually tracked rather than systematically assessed. GAO recommended a systematic mechanism for proactive demand assessment and supply-risk mitigation.

**Primary source:** https://www.gao.gov/products/gao-26-108053

**Problem abstraction:**

`ISOTOPE INVENTORY PRESENT != TREATMENT CAPACITY SUPPORTABLE`

A treatment mission depends on more than quantity. It depends on radionuclide, activity, reference time, half-life, production route, manufacturing capacity, geography, transport, patient slot, receiving readiness, and authority.

**IRLT response:**

- RLT Supply & Decay Control Tower
- patient-pipeline-to-isotope-demand forecasting
- source/production/manufacturing network standing
- decay-adjusted inventory and arrival forecasting
- shortage and supplier-risk visibility
- mission viability horizon
- Assurance-Supportable Treatment Capacity (ASTC) research lane

**Commercial value:** isotope suppliers, radiopharma manufacturers, CDMOs, health systems, treatment networks, and planners can distinguish raw isotope availability from actual patient-treatment supportability.

**National-interest relevance:** stronger domestic supply visibility, earlier shortage detection, and evidence-backed alignment between isotope production and medical demand.

---

## US-RLT-P02 — Emerging alpha/beta therapy demand is growing faster than static supply models

**Government signal.** DOE's FY2026 isotope program materials anticipate continued growth in isotope demand, including alpha and beta emitters for cancer therapy and diagnostics, while U.S. policy continues to emphasize domestic supply resilience.

**Primary source:** https://www.energy.gov/documents/fy-2026-isotope-rd-and-production-budget-request

**Problem abstraction:**

`SUPPLY AGREEMENT != CURRENT ISOTOPE AVAILABILITY != MANUFACTURING SLOT != RELEASED CLINICAL LOT != PATIENT DOSE != ADMINISTRATION`

**IRLT response:** model these as separate time-stamped standing transitions rather than one inventory field.

---

## US-RLT-P03 — Human-error prevention at the medical-use boundary

**Government signal.** NRC Information Notice 2026-02, *Using Generic Process Checklists in Medical Care to Prevent Human Error* (Feb. 6, 2026), is listed in NRC's Medical Uses Licensee Toolkit. The broader NRC medical-event corpus shows why correct patient, product, written directive, route, equipment, and treatment conditions must be verified before and during medical use.

**Primary source:** https://www.nrc.gov/materials/miau/med-use-toolkit/info-notices

**Problem abstraction:**

`CHECKLIST COMPLETE != ALL PHYSICAL CONDITIONS ESTABLISHED`

A checklist can preserve a recorded assertion without independently establishing that the actual vial, activity, tubing, patient, target, equipment state, or physical setup corresponded to the assertion at the point of consequence.

**IRLT response:**

- Clinical Administration Assurance
- patient/order/directive/dose binding
- RAMAT Vision physical/contextual witness lane
- dose/vial/package identity evidence
- administration setup evidence
- role/authority separation
- pre-action HOLD/NO-BIND when critical evidence is absent or contradictory

---

## US-RLT-P04 — Correct released product can still fail during administration

**Government signal.** NRC/Agreement-State event reports document radiopharmaceutical administrations in which a prepared treatment did not translate into the intended delivered activity because of disconnection, air in lines, catheter/tubing residual, catheter kink, spill, or other execution-stage conditions.

Representative primary sources:

- Pluvicto IV disconnection, 120 mCi of prescribed 200 mCi delivered: https://www.nrc.gov/documents-reports/document-collections/events-reports-associated-with/event-notification-reports/2026/20260209en
- Y-90 air noted in delivery lines / significant residual in tubing: https://www.nrc.gov/documents-reports/document-collections/events-reports-associated-with/event-notification-reports/2026/20260811en
- Y-90 residual/tubing cases: https://www.nrc.gov/documents-reports/document-collections/events-reports-associated-with/event-notification-reports/2026/20260812en
- Y-90 catheter kink, 15.96% of intended dose delivered: https://www.nrc.gov/documents-reports/document-collections/events-reports-associated-with/event-notification-reports/2026/20260813en

**Problem abstraction:**

`DOSE PREPARED != DOSE DELIVERED != DOSE REACHING INTENDED TARGET`

and

`AUTHORIZED AT START != AUTHORIZED TO CONTINUE AFTER MATERIAL CHANGE`

**IRLT response:**

- Administration Continuation Assurance
- administration-kit/configuration evidence
- pre/post administration assay linkage
- residual-activity reconstruction
- material-change detection and reassessment
- spill/contamination context evidence
- consequence reconstruction rather than binary "administered = yes"

---

## US-RLT-P05 — Decay state and supplier communication can turn a traceable vial into the wrong therapeutic state

**Government signal.** NRC's Sept. 4, 2026 event report describes a Y-90 case in which the treatment calculation required 0.379 GBq, a 3.0 GBq vial was ordered, and the vial had decayed to about 1.824 GBq at administration. NRC reported the licensee's then-current assessment as approximately 457.9% of the prescribed dose after accounting for lung shunt fraction. The preliminary review suggested a requested two-week decay interval may have been supplied at about one week.

**Primary source:** https://www.nrc.gov/reading-rm/doc-collections/event-status/event/2026/20260904en

**Problem abstraction:**

`RIGHT RADIONUCLIDE != RIGHT PHYSICAL PRODUCT STATE`

`TRACEABLE SHIPMENT != VIABLE THERAPEUTIC MISSION`

**IRLT response:**

- decay as a first-class data primitive
- reference activity + reference time + trusted current time
- required decay interval
- projected activity at arrival and administration
- patient/target/directive binding
- supplier-to-hospital acceptance criteria
- mission viability horizon

---

## US-RLT-P06 — Current written directive can be overridden by historical routine

**Government signal.** NRC/Agreement-State reports include Lu-177 therapy cases in which the current written directive called for a reduced 160 mCi dose after earlier cycles had used approximately 200 mCi, but approximately 200 mCi was administered.

Representative primary source: https://www.nrc.gov/reading-rm/doc-collections/event-status/event/2026/20260414en

**Problem abstraction:**

`HISTORICAL STANDARD DOSE != CURRENT AUTHORIZED DOSE`

`PATIENT HISTORY != CURRENT CYCLE AUTHORITY`

**IRLT response:**

- cycle-specific directive binding
- exact directive/version/dose/time binding to the treatment event
- explicit invalidation after material change
- artifact/version-specific approval rather than session-level approval
- no silent inheritance from previous cycles

---

## US-RLT-P07 — Patient can be present and scheduled while biologically not treatment-ready

**Government signal.** NRC reported a Lutathera case in which treatment had started before staff learned the patient had received an octreotide injection; the physician stopped the infusion because octreotide could prevent Lu-177 uptake, after only 19 mCi of the planned 200 mCi had been administered.

**Primary source:** https://www.nrc.gov/reading-rm/doc-collections/event-status/event/2026/20260311en

**Problem abstraction:**

`PATIENT PRESENT != PATIENT TREATMENT-READY`

`APPOINTMENT CONFIRMED != BIOLOGICAL READINESS ESTABLISHED`

**IRLT response:**

- bounded concomitant-treatment/readiness evidence
- medication/timing/protocol dependency checks
- patient attestation + authorized clinical-source evidence where applicable
- HOLD and human re-resolution when a clinically material dependency changes

The architecture does not make the medical decision; it preserves the evidence and standing boundary for the authorized clinical team.

---

## US-RLT-P08 — Short-expiry radiopharmaceuticals create unusual CGMP timing and environmental-monitoring pressure

**Government signal.** FDA's April 13, 2026 warning letter to the UCSF Radiopharmaceutical Facility describes inadequate investigations, adverse environmental-monitoring trends not investigated as required, long-open investigations, inadequate monitoring practices, and the need for representative environmental monitoring and a continuing state of control.

**Primary source:** https://www.fda.gov/inspections-compliance-enforcement-and-criminal-investigations/warning-letters/ucsf-radiopharmaceutical-facility-719568-04132026

**Problem abstraction:**

`BATCH RELEASE RECORD != CONTINUING PROCESS/ENVIRONMENT STANDING`

`GREEN BMS/EMS VALUE != REPRESENTATIVE STERILE-PROCESS EVIDENCE`

**IRLT response:**

- Continuous Quality / Environmental Standing
- EM/BMS/particle/pressure/temperature/humidity evidence synchronization
- cleanroom/process-exposure representativeness
- deviation/CAPA lineage and investigation clocks
- post-event reconstruction when microbiological evidence arrives after administration
- RAMAT Vision contextual evidence without claiming that vision proves sterility

---

## US-RLT-P09 — Ac-225 and other therapeutic radionuclides require national measurement traceability

**Government signal.** NIST established the first U.S. standard for measuring Ac-225 radioactivity and opened a calibration service, emphasizing that underdosing may expose a patient to radiation without effective treatment while overdosing can cause harm.

**Primary source:** https://www.nist.gov/news-events/news/2025/06/new-nist-standard-helps-deliver-right-dosage-cancer-fighting-drugs

**Problem abstraction:**

`ACTIVITY NUMBER PRESENT != TRACEABLE DECISION-GRADE ACTIVITY`

**IRLT response:**

- instrument identity and calibration traceability
- radionuclide-specific measurement context
- reference time and decay correction
- uncertainty preservation
- activity at planned and actual administration time
- instrument standing linked to the exact consequential measurement

---

## US-RLT-P10 — Calibrated instrument does not automatically mean calibration is applicable to the clinical geometry/use

**Government signal.** NIST states that manufacturer-recommended radionuclide calibrator settings are often based on a 5 mL flame-sealed ampoule geometry not found in clinical settings, and NIST develops geometry-specific calibration settings tied to national standards.

**Primary source:** https://www.nist.gov/programs-projects/medical-standards-clinical-radionuclide-calibrators

**Problem abstraction:**

`CALIBRATED != APPLICABLE_TO_CURRENT_MEASUREMENT_CONTEXT`

**IRLT response:**

- Measurement Context Standing
- instrument + radionuclide + geometry/container + volume/position + time + uncertainty binding
- no automatic promotion from valid calibration certificate to valid current measurement proposition

---

## US-RLT-P11 — Emerging production/distribution and impurity issues need dedicated regulatory attention

**Government signal.** NRC ACMUI maintains an active **Subcommittee on Radiopharmaceutical Production and Distribution Safety** charged with reviewing emerging radiation-safety concerns related to radiopharmaceutical production, distribution, and associated impurities.

**Primary source:** https://www.nrc.gov/about-nrc/regulatory/advisory/acmui/subcommittee

**Problem abstraction:**

`RADIONUCLIDE LABEL != COMPLETE PRODUCTION/PURITY PROVENANCE`

**IRLT response:**

- radionuclide genealogy from feedstock/production route through patient dose
- production-site, purification, impurity, measurement-method and custody provenance
- lot-specific evidence rather than name-only identity
- downstream propagation when impurity/production evidence changes

---

## US-RLT-P12 — Medical-use regulation is changing to accommodate emerging technology, workforce, and waste realities

**Government signal.** NRC's July 27, 2026 proposed rule, *Reducing Barriers to Medical Use Licensing* (NRC-2025-1237), proposes more flexible training/experience pathways, changes for emerging medical technologies, and expansion of decay-in-storage eligibility from a 120-day to a 275-day half-life, explicitly including materials such as Lu-177m. This is a **proposed rule**, not a current final requirement.

**Primary source:** https://www.federalregister.gov/documents/2026/07/27/2026-15080/reducing-barriers-to-medical-use-licensing

**Problem abstraction:**

`PROPOSED REGULATION != CURRENT APPLICABLE REQUIREMENT`

`RADIOACTIVE RESIDUAL PRESENT != SAME DISPOSITION PATH FOR EVERY NUCLIDE/IMPURITY/JURISDICTION/VERSION`

**IRLT response:**

- Regulatory Obligation Graph with rule/version/effective-date standing
- Waste/Residual Standing
- authorized-user/site/license standing
- nuclide-specific disposition logic
- preservation of proposal/current/final status boundaries

---

## US-RLT-P13 — Patient release is part of the radiological mission, not an administrative afterthought

**Government signal.** NRC/ACMUI continues work on Regulatory Guide 8.39, *Release of Patients Administered Radioactive Material*, including patient instructions and dosimetry methodology.

**Primary sources:**

- https://www.nrc.gov/about-nrc/regulatory/advisory/acmui/subcommittee
- https://www.nrc.gov/reading-rm/doc-collections/acmui/reports/index

**Problem abstraction:**

`TREATMENT COMPLETE != RADIOLOGICAL MISSION COMPLETE`

**IRLT response:**

- post-treatment radiation-safety evidence package
- administered activity/time + applicable release basis
- patient instruction/version/acknowledgement evidence
- bounded follow-up and exception documentation
- residual/waste linkage

---

## US-RLT-P14 — Growing cancer-treatment indications increase pressure on supply, site capacity, treatment readiness, and theranostic selection

**Government signal.** FDA approved Pluvicto on July 31, 2026 in combination with androgen receptor pathway inhibitor therapy for an earlier metastatic prostate-cancer population, with patient selection using an approved PSMA PET product based on PSMA expression.

**Primary source:** https://www.fda.gov/drugs/resources-information-approved-drugs/fda-approves-lutetium-lu-177-vipivotide-tetraxetan-androgen-receptor-pathway-inhibitor-therapy

**Problem abstraction:**

`DRUG APPROVED != PATIENT ELIGIBLE != TREATMENT SLOT AVAILABLE != MISSION SUPPORTABLE`

**IRLT response:**

- theranostic/eligibility evidence binding
- imaging/applicability standing
- patient pipeline -> isotope demand linkage
- treatment-center readiness and capacity
- ASTC rather than vial-count capacity

---

## US-RLT-P15 — Domestic isotope provenance can influence reimbursement

**Government signal.** CMS implemented a $10 per-dose add-on payment effective Jan. 1, 2026 for Tc-99m derived from domestically produced Mo-99, with at least 50% of the Mo-99 used in the generator required to be domestically produced for qualification.

**Primary source:** https://www.cms.gov/newsroom/fact-sheets/calendar-year-2026-hospital-outpatient-prospective-payment-system-opps-ambulatory-surgical-center

**Problem abstraction:**

`PRODUCT IDENTITY != PAYMENT/PROVENANCE ELIGIBILITY`

**IRLT response:**

- source-isotope provenance
- production-origin evidence
- transformation/generator lineage
- dose-level link to reimbursement evidence

This is an adjacent commercialization capability, not the core RLT safety proposition.

---

## US-RLT-P16 — Rural cancer patients face specialist-access and care-navigation constraints

**Government signal.** CDC reports that rural populations have higher cancer mortality despite lower overall incidence, often have limited access to cancer specialists, and can benefit from telementoring and patient navigation.

**Primary source:** https://cdc.gov/cancer-survivors/hcp/rural/index.html

**Problem abstraction:**

`CLINICAL NEED PRESENT != SPECIALIST/SITE/TREATMENT PATH AVAILABLE`

**IRLT response / research direction:**

- Distributed RLT Readiness Mesh
- hub-and-spoke site readiness evidence
- local equipment/staff/license/room/waste/transport standing
- remote specialist evidence access without transferring clinical authority
- patient-navigation and mission-state visibility

This is a future deployment/commercialization direction; it is not a claim that RAMAT Vision or COBIT-Chain presently solves rural cancer access.

---

# 3. Product architecture derived from the problem map

The public commercial architecture remains an **integration and assurance layer**, not a replacement for regulated source systems.

1. **RLT Digital Dose Passport** — isotope -> batch -> vial -> shipment -> hospital -> patient administration -> residual/waste.
2. **COBIT-Chain RLT Evidence Ledger** — identity, timestamps, hashes/signatures, instrument standing, operator standing, custody, release, deviations and CAPA.
3. **RAMAT Vision RLT Witness Layer** — bounded physical/contextual evidence around identity, setup, environment, handling, administration and changed conditions.
4. **RLT Instrument Standing Registry** — dose calibrators, survey meters, contamination monitors, analytical instruments and environmental instruments.
5. **RLT Supply & Decay Control Tower** — demand, isotope availability, production/manufacturing capacity, allocation, shipment and decay forecasting.
6. **Clinical Administration Assurance** — directive -> receiving assay -> setup -> administration -> delivered activity -> residual/reconstruction.
7. **Radiation & Environmental Assurance** — ALARA, exposure, contamination, cleanroom/process context, waste, decay-in-storage and discharge.
8. **Regulatory Obligation Graph** — site/isotope/activity/jurisdiction-specific obligations and authority with version/effective-date standing.
9. **Investigation/CAPA Reconstruction Engine** — reconstruction of the evidence state surrounding a deviation, OOS, contamination event, medical event or complaint.
10. **RLT Network Layer** — governed exchange among isotope producer, manufacturer/CDMO, logistics provider, treatment center and other authorized participants.
11. **Mission Viability / TCA-GCR-ASTC research lane** — determine which future patient-treatment paths remain supportable and when supportability will disappear.

---

# 4. Cross-cutting invariants preserved by the program

- `TRACEABLE ISOTOPE != VIABLE THERAPEUTIC MISSION`
- `ISOTOPE AVAILABLE != MANUFACTURING CAPACITY AVAILABLE != TREATMENT MISSION VIABLE`
- `CHECKLIST COMPLETE != PHYSICAL CONDITIONS ESTABLISHED`
- `DOSE PREPARED != DOSE DELIVERED != DOSE REACHING INTENDED TARGET`
- `AUTHORIZED AT START != AUTHORIZED TO CONTINUE AFTER MATERIAL CHANGE`
- `HISTORICAL STANDARD DOSE != CURRENT AUTHORIZED DOSE`
- `PATIENT PRESENT != PATIENT TREATMENT-READY`
- `CALIBRATED != APPLICABLE_TO_CURRENT_MEASUREMENT_CONTEXT`
- `ACTIVITY MEASUREMENT PRESENT != DECISION-GRADE ACTIVITY STANDING`
- `BATCH RELEASE != PHYSICAL HANDLING/TRANSFER STANDING`
- `GREEN BMS/EMS != REPRESENTATIVE PROCESS-EXPOSURE STANDING`
- `PROPOSED REGULATION != CURRENT APPLICABLE REQUIREMENT`
- `TREATMENT COMPLETE != RADIOLOGICAL MISSION COMPLETE`
- `HASH/IMMUTABILITY != PHYSICAL TRUTH != REGULATORY AUTHORITY`

---

# 5. USCIS / national-importance evidence use

This map may support a future immigration evidence package as documentation that the research program is directed toward identifiable U.S. problems involving:

- domestic critical-isotope supply resilience;
- cancer-treatment availability and capacity;
- radiopharmaceutical manufacturing quality;
- radiation-safety and medical-event prevention;
- national measurement traceability and dose accuracy;
- modernization of medical-use radioactive-material regulation;
- patient-specific treatment reliability;
- rural/specialist-access constraints; and
- evidence continuity across a fragmented regulated ecosystem.

This file does **not** state that USCIS has endorsed the endeavor or that any particular immigration standard is satisfied. Petition-level legal conclusions require separate counsel/legal analysis and evidence.

For evidentiary use, the strongest presentation is:

`U.S. GOVERNMENT-IDENTIFIED PROBLEM -> USER'S EXISTING TECHNICAL WORK -> DEMONSTRATION/EVIDENCE -> PUBLICATION/EXTERNAL REVIEW -> FUTURE U.S. IMPLEMENTATION PLAN`

rather than claiming the government asked for or adopted the user's product.

---

# 6. Commercialization use

The pain-point map supports different buyer/value stories without changing the underlying assurance kernel:

- **Isotope producers / suppliers:** demand visibility, genealogy, decay-aware mission commitments.
- **Radiopharma manufacturers / CDMOs:** release defensibility, environmental/measurement standing, downstream mission visibility.
- **Logistics providers:** chain-of-custody plus time/decay mission viability.
- **Hospitals / nuclear medicine / oncology:** patient/directive/dose/setup/continuation assurance and delivered-activity reconstruction.
- **QA / compliance / validation:** proposition-specific standing and one-click evidence reconstruction.
- **Radiation safety / RSO:** instrument, contamination, exposure, residual and patient-release evidence.
- **Executives / network planners:** ASTC, shortage/bottleneck visibility, site readiness, capacity risk.
- **Payers / reimbursement operations:** bounded provenance evidence where payment depends on source/production origin.

---

# 7. Government evidence watch scope

Maintain continuing watch for material changes in:

### NRC
- medical event reports involving Lu-177, Y-90, Ac-225, Pb-212 and related therapeutic uses;
- Medical Uses Licensee Toolkit / information notices;
- ACMUI Medical Events Subcommittee;
- ACMUI Radiopharmaceutical Production and Distribution Safety Subcommittee;
- alpha-therapy licensing/guidance;
- 10 CFR Part 35 rulemaking and implementation;
- patient release / Regulatory Guide 8.39;
- waste, decay-in-storage, authorized-user, survey-instrument and emerging-medical-technology changes.

### FDA
- radiopharmaceutical CGMP warning letters and enforcement;
- sterile/aseptic/environmental-monitoring findings;
- radiopharmaceutical approvals and expanded indications;
- theranostic/imaging companion-selection requirements;
- manufacturing/quality guidance that materially changes the RLT evidence model.

### DOE / GAO
- isotope supply/demand assessments;
- shortage and foreign-dependency findings;
- Ac-225/Lu-177/Pb-212/At-211 and related production-capacity developments;
- domestic infrastructure and risk-mitigation actions;
- recommendations/implementation status for GAO-26-108053.

### NIST
- Ac-225 and other therapeutic radionuclide primary/secondary standards;
- radionuclide calibrator geometry/applicability;
- impurity metrology;
- imaging/quantitation and measurement-uncertainty developments.

### Cancer treatment / access
- NCI/FDA/CDC/CMS developments that materially affect patient eligibility, treatment demand, rural/specialist access, reimbursement provenance, or RLT capacity.

**Alert threshold:** notify only when a new event changes or strongly validates a product requirement, falsifier, standing predicate, mission path, national-importance argument, or commercialization opportunity. Do not alert for routine restatements.

---

# 8. Relationship to existing IRLT / RPA-ASTC work

This map is a problem/evidence layer above existing IRLT/Radiopharma implementation and experimental work. It does not retroactively redefine earlier artifacts.

Existing architecture/demonstration lineage should remain separately date-bound. New public government evidence may validate, challenge, or extend the problem map, but it does not manufacture earlier implementation or novelty.

**Public evidence of a government problem != proof of novelty of our solution.**

**Later government event != retroactive origin date of an earlier architecture.**

**Government convergence != government endorsement.**

---

## Summary proposition

> **A cancer-treatment mission should proceed only while the physical material, patient state, measurement basis, evidence, treatment configuration, logistics, facility, authority and consequence pathway remain jointly supportable through the intended treatment consequence.**

When one of those changes, the architecture should preserve historical truth, re-resolve current standing, and identify which bounded mission paths remain supportable rather than silently carrying forward stale approval or blindly invalidating unrelated evidence.
