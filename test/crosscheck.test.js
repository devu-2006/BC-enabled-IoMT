// Verifies, on-chain, proofs produced by the Python service (nizk_service/vectors/py_proofs.json).
const { expect } = require("chai");
const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

const file = path.join(__dirname, "..", "nizk_service", "vectors", "py_proofs.json");

describe("Python prover -> Solidity verifier", function () {
    before(function () {
        if (!fs.existsSync(file)) this.skip(); // run scripts/export_vectors.js and pytest first
    });

    it("the contract accepts every proof produced by the Python service", async () => {
        const v = await (await ethers.getContractFactory("SchnorrNIZK")).deploy();
        const proofs = JSON.parse(fs.readFileSync(file, "utf8"));
        expect(proofs.length).to.be.greaterThan(0);
        for (const p of proofs) {
            expect(await v.verifyProof(p.px, p.parity, p.message, p.e, p.s)).to.equal(true);
        }
        // sanity: a modified proof is rejected
        const p = proofs[0];
        expect(await v.verifyProof(p.px, p.parity, ethers.keccak256("0x1234"), p.e, p.s)).to.equal(false);
    });
});