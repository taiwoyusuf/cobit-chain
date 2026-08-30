# Domain Profile Application — Watch-Derived Refinements R1

These are shared-core contracts. Domain profiles consume them; they must not rebuild them.

| Shared refinement | Clinical Trial | CompoundSafe | Radiopharma | ALARA | DSCSA | LabTrust | RAMAT / Niagara |
|---|---|---|---|---|---|---|---|
| Non-Compensatory Standing | eligibility/safety/consent hard gates | sterile/release hard gates | product/activity/sterile hard gates | work authorization/radiological hard gates | suspect/quarantine/ATP hard gates | method/result/review hard gates | prevents green dashboard laundering |
| Oversight Queue Standing | SAE/eligibility review queues | deviation/release queues | release/radiation/quality queues | alarm/stop-work queues | exception/investigation queues | OOS/OOT/review queues | alarm sensitivity must not destroy useful human review |
| Claim Identity/Discharge | consent, eligibility, protocol claims separate | BUD, sterility, environment separate | activity, sterility, identity, dose separate | calibration, survey, work authorization separate | identity, custody, ATP, VRS separate | method, sample, result, review separate | observation cannot discharge qualification/materiality/authority claims |
| Independent Evidence Plane | sponsor/site/CRO records vs independent evidence | pharmacy system vs independent evidence | facility/instrument vs independent evidence | work-control system vs independent witness | EPCIS/trading partner vs independent evidence | CDS/LIMS/instrument vs independent evidence | camera/sensor may witness without becoming authority |
| Recovery Path Noninterference | containment after harmful agent action | quarantine/stop use | isolate product/source/process | stop work/isolate source | quarantine/recall | stop analysis/quarantine result | safety classifier/control layer must not block authorized containment |
| Revocation Propagation | consent/delegation/site authority | personnel/pharmacist delegation | AU/QA/vendor authority | RSO/HP/work authority | trading partner/ATP authority | analyst/reviewer authority | device/service credential changes must reach action boundary |
| Residual Obligation Liveness | SAE/CAPA/site remediation | deviation/CAPA | investigation/CAPA | corrective action/re-entry | suspect-product investigation | OOS/OOT/CAPA | detected condition remains open until closure evidence |
| Interoperability Seam | sponsor-CRO-site-lab interfaces | pharmacy-vendor-lab | manufacturer-lab-hospital | instrument/BMS/work-control | EPCIS/VRS interfaces | LIMS/CDS/instrument | Niagara/RAMAT/agent interfaces version/mapping bound |
| Retrospective Reliance Exposure | earlier enrollments/uses depending on changed basis | prior batches | prior releases/administrations | prior work packages | prior transactions | prior reported results | historical digital/physical decisions selectively reopened |
| Common-Cause Exposure | shared CRO/model/provider | shared HVAC/supplier | shared isotope/facility/provider | shared instrument/service | shared VRS/provider | shared method/instrument/vendor | common controller/network/model condition triggers scoped reassessment |
| Document Parse Fidelity | protocol/eConsent/CSR | SOP/MFR/BUD docs | batch/CoA/label/regulatory docs | RWP/procedures | EPCIS/verification docs | method/spec/raw-report PDFs | labels/screens/documents read by vision/OCR |
| Tool Sequence / Info Flow | subject data -> external tool | formulation/patient data -> external tool | patient/product/radiation data -> external tool | worker/dose data -> external tool | serialization data -> external tool | sample/result data -> external tool | MCP/agent/tool composition cannot inherit authorization |

## Authority boundary

All outputs remain non-binding assurance states. Final regulated decisions remain with the authorized sponsor/site/investigator/IRB/IEC/regulator, pharmacist/quality authority, authorized user/RSO/HP, trading-partner/regulatory authority, laboratory analyst/reviewer/quality authority, or other applicable institution.
