# IRLT / Radiopharma Master Program State R1

**Status:** PUBLIC-SAFE MASTER PROGRAM INDEX  
**Primary focus:** Radiopharmaceutical / Radioligand Therapy Mission Assurance  
**Date frozen:** 2026-09-13  
**Purpose:** preserve program focus, architecture boundaries, build order, commercialization direction, publication strategy, and public/private disclosure discipline.

> This file is intentionally high level. Patent-sensitive mechanism detail, unpublished claim language, challenge fixtures, equations, and implementation specifics remain outside this public file pending IP review.

---

## 1. Fixed program direction

The flagship project is **IRLT / Radiopharma Mission Assurance**.

IRLT is being developed as a consequence-assurance architecture for time-varying radioactive therapeutic missions. It asks whether the physical, evidentiary, measurement, environmental, patient, authority, dependency, logistics, and regulatory conditions required for a particular treatment consequence remain sufficiently established from isotope origin through patient administration and radioactive end-of-life.

The project is **not** positioned as:

- generic blockchain for radiopharma;
- generic digital twin software;
- another MES/LIMS/QMS/BMS/EHR;
- an AI system that independently releases product or authorizes treatment;
- a replacement for the Authorized User, Quality Unit, RSO, nuclear pharmacist, medical physicist, or treating physician.

The governing separation remains:

**Regulated source systems execute and retain authoritative records -> RAMAT Vision supplies bounded physical/contextual observations -> COBIT-Chain/VSA establishes evidence, provenance, standing, and dependency -> IRLT evaluates mission supportability -> authorized humans retain consequential authority.**

---

## 2. Core problem being solved

A scientifically valid radiopharmaceutical does not by itself establish a supportable patient-treatment mission.

A mission may fail even when individual source systems appear correct because radioactive activity, logistics windows, patient readiness, measurement applicability, environmental state, personnel authority, written directives, evidence completeness, or physical conditions can change independently.

The program therefore treats the full treatment mission as the object of assurance:

`PATIENT NEED -> ISOTOPE DEMAND / AVAILABILITY -> RADIONUCLIDE PRODUCTION / PRODUCTION ROUTE -> ISOTOPIC COMPOSITION / IMPURITIES -> PRECURSOR / LIGAND -> RADIOLABELING / SYNTHESIS -> ASEPTIC PROCESSING -> QC + ENVIRONMENTAL / PROCESS EVIDENCE -> RELEASE / CONDITIONAL EVIDENCE OBLIGATIONS -> PATIENT-SPECIFIC DOSE -> ACTIVITY + REFERENCE-TIME STATE -> PACKAGING / TRANSPORT / CUSTODY -> HOSPITAL RECEIPT -> RECEIVING ASSAY -> PATIENT + TARGET + WRITTEN DIRECTIVE -> ADMINISTRATION READINESS -> DELIVERY PATH -> PHYSICAL ADMINISTRATION -> ACTUAL DELIVERED ACTIVITY / LOCALIZATION -> RESIDUAL ACTIVITY -> DOSIMETRY / FOLLOW-UP -> CONTAMINATION / OCCUPATIONAL EXPOSURE -> WASTE / EFFLUENT / DECAY-IN-STORAGE -> INVESTIGATION / CAPA / RECONCILIATION -> MISSION CLOSURE`

---

## 3. Common assurance kernel and retained domain families

### COBIT-Chain / VSA
Common assurance kernel for identity, evidence provenance, present standing, dependency, applicability, authority, admissibility, re-evaluation, reconstruction, and bounded claim support.

### RAMAT Vision
Independent physical/contextual witness and human-interface layer. It may observe, preserve, display, and challenge physical/digital correspondence, but it does not acquire QA, clinical, or radiological authority merely by sensing a condition.

### Supporting domain assurance families retained in the architecture

- **CompoundSafe / Compounding Pharmacy Assurance:** formulation identity/version, components/lots, weighing/measurement, cleanroom/process, personnel, sterility/endotoxin, BUD, deviation/CAPA, quarantine, pharmacist authority and release readiness.
- **ALARA / Radiological Operations Assurance:** worker qualification, work authorization, source/material identity, survey/dose instrumentation, contamination, dose rate, shielding/containment, stop-work, RSO/AU/HP authority, post-work survey, waste/disposition, recovery and re-entry.
- **LabTrust / Regulated Laboratory Assurance:** sample identity, chain of custody, method/specification version, instrument qualification/calibration, standards, analyst qualification, raw data/audit trail, calculations, OOS/OOT, review and corrected-result reconstruction.
- **Clinical Trial Assurance:** protocol/site/patient/investigational-product applicability, evidence lineage, trial authority, investigational radiopharma treatment context and reconstruction.

These families remain reusable, but the **primary build, commercialization, research, publication, and USCIS focus is radiopharma/RLT**.

---

## 4. Public product architecture

The current product stack is organized around six engineering objects rather than dozens of disconnected modules:

1. **RLT Mission Object** — persistent governed representation of the patient-treatment mission.
2. **Mission Standing Engine** — evaluates whether required mission conditions remain sufficiently established now.
3. **Evidence & Dependency Graph** — binds evidence to propositions and propositions to downstream reliance.
4. **RAMAT Witness Gateway** — admits bounded physical/contextual evidence from approved devices and sensors.
5. **RLT Simulation / Challenge Harness** — synthetic, falsifiable testing of mission and assurance behavior.
6. **Mission Assurance Console** — human-readable mission readiness, HOLD, uncertainty, dependency and reconstruction view.

Commercial capability families may include:

- RLT Digital Dose / Mission Passport;
- RLT Supply & Decay Control Tower;
- Instrument / Measurement Standing Registry;
- Manufacturing & Environmental Standing;
- Clinical Administration Assurance;
- Radiation / ALARA Assurance;
- Regulatory Obligation Graph;
- Investigation / CAPA Reconstruction;
- mission-viability research metrics and simulations.

---

## 5. Physical hardware program

Physical hardware is now available and should be commissioned against explicit evidence propositions rather than used as general-purpose gadgets.

Initial roles:

- **Smart glasses:** first-person contextual/visual witness around object presentation, zone, workflow step and physical configuration.
- **T-WATCH-S3:** authenticated wearer interaction, alert/acknowledgement and bounded field evidence interaction.
- **MR60FDA2 mmWave sensor:** presence/motion/context signal within its supported scope.
- **SCD41:** CO2 / temperature / humidity contextual evidence.
- **Edge compute:** local acquisition, inference and evidence buffering where appropriate.
- **QR / RFID / NFC / future UWB:** physical-object / location identity binding where independently verified.

Controlling rule:

`SENSOR PRESENT != SENSOR QUALIFIED_FOR_THE_CLAIM`

and:

`RAMAT OBSERVATION != QA RELEASE != CLINICAL DECISION`

No real radioactive work is authorized by this public program file. Early demonstrations remain synthetic / non-radioactive unless performed under properly licensed and approved controls.

---

## 6. First build target

Build a safe synthetic end-to-end RLT mission and deliberately inject failures.

Representative mission:

`SYNTHETIC SOURCE / LOT -> MOCK VIAL -> GOVERNED IDENTITY -> SIMULATED ACTIVITY + REFERENCE TIME -> MOCK TRANSPORT -> RECEIVING EVIDENCE -> MOCK DIRECTIVE -> PATIENT TOKEN -> ADMINISTRATION CONFIGURATION -> RAMAT OBSERVATION -> SIMULATED ADMINISTRATION -> SIMULATED RESIDUAL -> MISSION CLOSURE`

Representative challenge classes:

- wrong vial / wrong identity;
- stale activity or time-state;
- wrong directive version;
- missing or stale instrument standing;
- measurement-context mismatch;
- wrong location / downstream semantic misbinding;
- patient / target / cycle mismatch;
- environmental evidence stale or incomplete;
- evidence missing or not retrievable;
- material change after prior approval;
- unauthorized reviewer or expired authority;
- administration-path mismatch;
- evidence arriving after consequence;
- incomplete mission closure.

The experiment must preserve falsifiers and claim ceilings. A passing challenge does not imply clinical safety, regulatory approval, or production readiness.

---

## 7. Build roadmap

### Phase 0 — scope / provenance / IP gate
Freeze the program state, disclosure register, external-exposure provenance, candidate invention families, and public/private boundaries.

### Phase 1 — hardware commissioning
Establish device identities, software/firmware baselines, clock/time handling, sensor claim boundaries, evidence schemas and reproducible acquisition.

### Phase 2 — RLT mission engine
Implement the synthetic mission object, time-varying mission state, evidence/dependency model and bounded mission determinations.

### Phase 3 — RAMAT witness integration
Connect glasses, watch, selected sensors and edge acquisition to the evidence plane without transferring authority.

### Phase 4 — synthetic challenge lab
Create a frozen adversarial RLT challenge corpus and publish bounded results only after disclosure/IP review.

### Phase 5 — supply / mission viability research
Model patient pipeline, isotope / manufacturing availability, transport and treatment-site capacity while preserving the distinction between raw inventory and treatment supportability.

### Phase 6 — independent review / reproduction
Seek blinded or independently bounded examination of selected experiments.

### Phase 7 — commercial shadow pilot
Use synthetic, historical, de-identified or otherwise lawfully controlled evidence in a read-only / shadow mode. Source systems remain authoritative.

### Phase 8 — regulated integrations
Only after contractual, regulatory, validation, privacy, cyber and institutional controls are defined.

---

## 8. Commercialization direction

Commercialization should begin with evidence/reconstruction and shadow-mode assurance, not autonomous clinical control.

### Stage 1 — RLT Mission Assurance Assessment
For radiopharma manufacturers, CDMOs, treatment centers, RSO/quality teams and RLT networks.

Value:

- evidence-gap discovery;
- readiness and dependency visibility;
- investigation/CAPA reconstruction;
- time/decay consistency review;
- measurement/instrument context review;
- cross-organization handoff analysis;
- audit/inspection evidence packaging.

### Stage 2 — IRLT Shadow-Mode Platform + RAMAT Witness Kit
Read-only / nonbinding assurance operating beside the existing source systems.

### Stage 3 — Enterprise RLT Mission Assurance Network
Validated, role-specific interfaces across manufacturer, logistics and treatment-network boundaries where justified.

Initial commercial success metrics should include reconstruction time, evidence gaps found, handoff defects surfaced, manual-review burden, investigation duration, time-to-evidence package, and mission-readiness visibility.

---

## 9. Publication and book strategy

Publication follows the IP gate:

`INVENTION CAPTURE -> PRIOR-ART / PATENT REVIEW -> FILE / WITHHOLD DECISION -> PUBLICATION`

Candidate publication themes:

- treatment-mission assurance in RLT;
- assurance engineering for time-varying radioactive missions;
- measurement / multi-clock integrity;
- bounded physical witnessing in regulated radiopharma operations;
- conditional post-release evidence obligations and reconstruction;
- assurance-supportable treatment-capacity research;
- RLT evidence completeness / retrieval / challenge methodology.

Priority communities include SNMMI, ISPE Radiopharmaceuticals, AAPM radiopharmaceutical therapy / dosimetry groups, PDA, RAPS, Health Physics Society, EANM, and selected engineering / health-informatics venues.

### Book direction

Working title:

**Radiopharmaceutical Mission Assurance: From Isotope Origin to Patient Consequence**

The book should explain the field, public pain points, operating model, evidence principles, measurement/time issues, manufacturing, clinical handoffs, radiation safety, waste, investigations and the assurance discipline at a level safe for publication after IP review.

The book is a thought-leadership / field-definition instrument; it is not a substitute for patent protection or peer-reviewed scientific validation.

---

## 10. IP / disclosure boundary

Potentially patent-sensitive mechanism detail is deliberately **not disclosed here**.

Candidate private invention-review families include combinations involving:

- time-varying RLT mission supportability;
- consequence-bound physical witnessing with governed evidence separation;
- dynamic consequence-path / mission-viability methods;
- unresolved / later-arriving evidence dependency handling;
- retrospective reliance / dependency reconstruction;
- exact patient/directive/dose/physical consequence binding;
- treatment-supportability capacity metrics.

These are **candidate invention families only**, not patentability or novelty conclusions.

Do not publish detailed algorithms, equations, challenge fixtures, claim language or implementation internals until IP review determines what is safe.

---

## 11. Novelty / prior-art posture

The project must not claim novelty merely because an idea has a new name.

Known crowded / established areas include:

- generic radiopharmaceutical blockchain / distributed-ledger tracking;
- decay-aware inventory and logistics;
- patient-specific dosimetry;
- digital twins for RPT personalization;
- written-directive workflow software;
- dose / patient / barcode verification;
- nuclear-medicine inventory / health-physics software;
- radiopharmaceutical manufacturing MES/QMS/LIMS;
- generic digital dose passports;
- treatment scheduling and capacity planning.

The current research hypothesis is that the strongest differentiation may lie in the **combination and causal architecture** connecting time-varying radioactive mission state, proposition-bounded evidence standing, independently governed physical witnessing, dependency propagation, exact authority/action/consequence binding, changed-condition re-evaluation, and end-to-end mission closure.

That hypothesis requires formal patent / prior-art analysis before any novelty representation is made.

---

## 12. External R&D / assurance-watch rule

External AI-governance, building, environmental, agent, digital-twin or assurance work is relevant only when it materially improves the RLT product, experiments, patent analysis, USCIS evidence or commercialization.

If an external idea is incorporated:

- preserve the source and date;
- preserve the pre-exposure IRLT state;
- identify what changed and what did not;
- independently specify the RLT implementation;
- do not copy proprietary method expression;
- preserve `SIMILARITY != DERIVATION` and `EXPOSURE != ADOPTION`.

---

## 13. U.S. national-importance / USCIS positioning

The public-facing national-interest story should connect:

`U.S. GOVERNMENT-IDENTIFIED RLT / ISOTOPE / METROLOGY / SAFETY / ACCESS PROBLEM -> EXISTING TECHNICAL WORK -> DATED DEMONSTRATION / EVIDENCE -> INDEPENDENT REVIEW / PUBLICATION -> FUTURE U.S. RESEARCH / COMMERCIALIZATION PLAN`

Do not claim U.S. Government endorsement or deployment where none exists.

---

## 14. Focus rule

**PRIMARY DOMAIN = RADIOPHARMA / RLT.**

COBIT-Chain, VSA, RAMAT Vision, CompoundSafe, ALARA, LabTrust, Clinical Trial Assurance, Platform B1/AEBOK, and relevant TCA/GCR/ASTC research remain because they support the radiopharma mission.

No new unrelated product family should be added unless it directly advances:

1. the RLT product;
2. the RLT science;
3. the RLT patent estate;
4. the USCIS / national-importance evidence package; or
5. commercialization.

Everything else stays outside this program thread.

---

## 15. Next action

Create and maintain a **private, patent-sensitive IRLT Master Product Specification** outside the public repository, then begin Phase 1 hardware commissioning against explicit evidence propositions.

Public GitHub remains the provenance-safe, publication-safe, bounded evidence layer. Private IP records remain the source for undisclosed mechanism detail until patent counsel / filing decisions permit broader disclosure.
