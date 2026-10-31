// Usage: npx hardhat run scripts/export_vectors.js
// Writes proofs + on-chain-computed messages so the Python service can be cross-checked.
const fs = require("fs");
const path = require("path");
const { ethers } = require("hardhat");
const { prove, randomScalar } = require("./schnorr");

async function main() {
    const c = await (await ethers.getContractFactory("HealthcareOptimized")).deploy();
    await c.waitForDeployment();
    const net = await ethers.provider.getNetwork();
    const rnd32 = () => ethers.hexlify(ethers.randomBytes(32));
    const rndAddr = () => ethers.getAddress(ethers.hexlify(ethers.randomBytes(20)));

    const cases = [];
    for (let i = 0; i < 10; i++) {
        const issuer = rndAddr(), patient = rndAddr();
        const uniqueID = rnd32(), dataRef = rnd32(), sigHash = rnd32();
        const certMessage = await c.certificateProofMessage(issuer, patient, uniqueID, dataRef, sigHash);
        const keyRegMessage = await c.keyRegistrationMessage(issuer);
        cases.push({
            issuer, patient, uniqueID, dataRef, sigHash, certMessage, keyRegMessage,
            proof: prove(randomScalar(), certMessage),
        });
    }
    const out = { chainId: Number(net.chainId), contract: await c.getAddress(), cases };
    const file = path.join(__dirname, "..", "nizk_service", "vectors", "js_vectors.json");
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify(out, null, 2));
    console.log("wrote", file, "with", cases.length, "cases");
}
main().catch((e) => { console.error(e); process.exit(1); });