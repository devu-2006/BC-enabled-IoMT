// Usage (with `npx hardhat node` running in another window):
//   npx hardhat run scripts/deploy_local.js --network localhost
// Deploys HealthcareOptimized, sets the IDS oracle, and writes gateway/deployment.json.
const fs = require("fs");
const path = require("path");
const { ethers, artifacts } = require("hardhat");

async function main() {
    const signers = await ethers.getSigners();
    const c = await (await ethers.getContractFactory("HealthcareOptimized")).deploy();
    await c.waitForDeployment();

    const names = ["authority", "oracle", "hospital", "patient", "doctor",
        "device-A", "device-B", "device-C", "device-D"];
    const accounts = {};
    names.forEach((n, i) => (accounts[n] = signers[i].address));
    await (await c.setOracle(accounts.oracle)).wait();

    const art = await artifacts.readArtifact("HealthcareOptimized");
    const net = await ethers.provider.getNetwork();
    const out = { chainId: Number(net.chainId), contract: await c.getAddress(), accounts, abi: art.abi };
    const file = path.join(__dirname, "..", "gateway", "deployment.json");
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify(out, null, 2));
    console.log("contract:", out.contract);
    console.log("wrote", file);
}
main().catch((e) => { console.error(e); process.exit(1); });