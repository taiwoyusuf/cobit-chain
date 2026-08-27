# Step 180 Revalidation Matrix

| Condition between evaluation and commit | Expected state |
|---|---|
| No relevant change; decision fresh; authority current | `SUPPORTABLE / ADMISSIBLE` |
| Prior decision already not admissible | `REASSESSMENT_REQUIRED / NOT_ADMISSIBLE` |
| Decision age exceeds declared maximum | `REASSESSMENT_REQUIRED / NOT_ADMISSIBLE` |
| Authority withdrawn or no longer current | `REASSESSMENT_REQUIRED / NOT_ADMISSIBLE` |
| Object hash changes | `REASSESSMENT_REQUIRED / NOT_ADMISSIBLE` |
| Evidence/criteria/configuration/environment change classified `MATERIAL` | `REASSESSMENT_REQUIRED / NOT_ADMISSIBLE` |
| Changed dimension lacks materiality classification | `REASSESSMENT_REQUIRED / NOT_ADMISSIBLE` |
| Changed dimension classified `IMMATERIAL` and all other requirements remain current | `SUPPORTABLE / ADMISSIBLE` |

The prior admissibility result remains historical evidence and is not rewritten when current execution standing is withdrawn.
