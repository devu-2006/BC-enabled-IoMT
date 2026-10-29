# Blockchain-enabled Secure Access Control for IoT Healthcare (extension project)

Extension of: H. Nandanwar and R. Katarya, "Privacy-preserving data sharing in blockchain-enabled
IoT healthcare management system", The Computer Journal, 68(11), 2025, 1657-1681.

## Setup (Node.js 20 LTS recommended)
```bash
git init
npm install
npx hardhat test            # runs tests, writes results/baseline_gas.json
npm run gas                 # same, with hardhat-gas-reporter table
```

## Layout
- `contracts/HealthcareBaseline.sol`  baseline following the paper's design (reference point)
- `contracts/HealthcareOptimized.sol` optimized + ABAC/consent/break-glass (Day 2)
- `test/`                             unit tests; `helpers.js` records gasUsed to `results/*.json`
- `ids/`                              IDS notebook (Day 1-2)
- `docs/`                             gap analysis, daily updates (`docs/daily/dayN.md`)
- `results/`                          measured numbers used in the paper

## Rules for fair comparison
Baseline and optimized contracts use the SAME compiler version and optimizer settings
(see `hardhat.config.js`). Report only numbers produced by `npx hardhat test`.
