# Step 166 - First-Tier Triad Commercial Demonstration Console

This implementation is local, synthetic, non-production, and read-only.

Equal first-tier tracks:

- IRLT and radiopharmaceutical assurance
- Compounding pharmacy assurance
- DSCSA and pharmaceutical supply-chain assurance

The console displays only prebuilt Step 164 evidence:

- Baseline success
- Evidence-tamper failure
- Domain-specific dependency failure
- Verified recovery success
- Inspection passports
- RAMAT display-only feeds
- Governance reconstruction evidence

The console does not approve, release, override, execute, dispense,
administer, ship, transfer product, resolve No-Bind states, or write
to any source system.

Manual local console command:

py -3 .\src\demonstration_console.py --project-root . serve --host 127.0.0.1 --port 8766

Open this address in the browser:

http://127.0.0.1:8766

Boundaries:

- Platform B v1 is not modified.
- Thread D v1 is not modified.
- Thread D2 and RAMAT Vision remain DISPLAY / WITNESS ONLY.
- No production integration or write-back is supported.
- No PHI or company production data is used.
- Qualified human authority remains required.
- Official source-system execution remains required.