# Daily Update #1 - Thursday 29 Oct 2026

**Project:** Blockchain-enabled Secure Access Control Framework for IoT Healthcare
**Reporting:** <name(s)>     **Hours spent:** <h>

## Done today (with evidence)
| Item | Evidence |
|---|---|
| Repo and Hardhat environment set up | <repo link / commit hash> |
| Baseline contract (paper's design) implemented | `contracts/HealthcareBaseline.sol`, commit <hash> |
| Baseline unit tests passing | <screenshot of `npx hardhat test`> |
| Baseline gas measured | `results/baseline_gas.json` (table below) |
| Gap analysis of base paper drafted | `docs/gap-analysis.md` |
| IDS dataset downloaded and inspected | <notes / notebook link> |

## Metrics
| Function | Gas (baseline) |
|---|---|
| registerEntity | <from results/baseline_gas.json> |
| issueCertificate | |
| grantAccess | |
| requestAccess | |
| revokeAccess | |

## Planned contributions (frozen scope)
C1 gas-optimized contract; C2 consent-based ABAC with revocation and break-glass; C3 corrected NIZKP; C4 IDS with feature reduction and suspension hook.

## Blockers / decisions needed
- <none / list>

## Next 24 hours
- Optimized contract + ABAC with tests; baseline-vs-optimized gas table
- IDS training and metrics
