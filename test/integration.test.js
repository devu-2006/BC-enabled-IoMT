const { expect } = require("chai");
const { ethers } = require("hardhat");
const { prove, randomScalar, publicKey } = require("../scripts/schnorr");
const { GasRecorder } = require("./helpers");

const Role = { Hospital: 1, Doctor: 2, Patient: 3 };

describe("NIZKP-gated certificate issuance", function () {
    let c, authority, hospital, hospital2, patient;
    let x1, x2; // hospital proof secrets (separate from Ethereum keys)
    const gas = new GasRecorder("integration");
    const h = (s) => ethers.keccak256(ethers.toUtf8Bytes(s));
    const dataRef = h("ipfs-cid"), sigHash = h("sig");

    async function certProof(secret, issuer, uniqueID) {
        const msg = await c.certificateProofMessage(issuer.address, patient.address, uniqueID, dataRef, sigHash);
        return prove(secret, msg);
    }

    before(async () => {
        [authority, hospital, hospital2, patient] = await ethers.getSigners();
        c = await (await ethers.getContractFactory("HealthcareOptimized")).deploy();
        await c.waitForDeployment();
        await c.registerEntity(hospital.address, Role.Hospital, h("h1"));
        await c.registerEntity(hospital2.address, Role.Hospital, h("h2"));
        await c.registerEntity(patient.address, Role.Patient, h("p"));
        x1 = randomScalar();
        x2 = randomScalar();
    });

    it("message helpers match an off-chain computation", async () => {
        const id = h("c-x");
        const net = await ethers.provider.getNetwork();
        const off = ethers.solidityPackedKeccak256(
            ["uint256", "address", "address", "address", "bytes32", "bytes32", "bytes32"],
            [net.chainId, await c.getAddress(), hospital.address, patient.address, id, dataRef, sigHash]);
        expect(await c.certificateProofMessage(hospital.address, patient.address, id, dataRef, sigHash)).to.equal(off);
    });

    it("issuing with a proof fails before a proof key is registered", async () => {
        const p = await certProof(x1, hospital, h("c0"));
        await expect(c.connect(hospital).issueCertificateWithProof(patient.address, h("c0"), dataRef, sigHash, p.e, p.s))
            .to.be.revertedWithCustomError(c, "NoProofKey");
    });

    it("key registration needs a valid proof of possession from an active hospital", async () => {
        const k = publicKey(x1);
        const good = prove(x1, await c.keyRegistrationMessage(hospital.address));
        const stolen = prove(randomScalar(), await c.keyRegistrationMessage(hospital.address)); // other secret, claims k
        await expect(c.connect(hospital).setProofKey(k.px, k.parity, stolen.e, stolen.s))
            .to.be.revertedWithCustomError(c, "BadProof");
        await expect(c.connect(patient).setProofKey(k.px, k.parity, good.e, good.s))
            .to.be.revertedWithCustomError(c, "NotAuthorized");
        await gas.rec("setProofKey", c.connect(hospital).setProofKey(k.px, k.parity, good.e, good.s));
        const k2 = publicKey(x2);
        const good2 = prove(x2, await c.keyRegistrationMessage(hospital2.address));
        await c.connect(hospital2).setProofKey(k2.px, k2.parity, good2.e, good2.s);
        expect((await c.proofKeys(hospital.address)).px).to.equal(k.px);
    });

    it("issues a certificate with a valid proof", async () => {
        const id = h("c1");
        const p = await certProof(x1, hospital, id);
        await gas.rec("issueCertificateWithProof", c.connect(hospital).issueCertificateWithProof(patient.address, id, dataRef, sigHash, p.e, p.s));
        expect(await c.verifyCertificate(id, sigHash)).to.equal(true);
    });

    it("rejects: wrong secret, proof for another certificate, proof from another hospital", async () => {
        const id = h("c2");
        const wrong = await certProof(randomScalar(), hospital, id);
        await expect(c.connect(hospital).issueCertificateWithProof(patient.address, id, dataRef, sigHash, wrong.e, wrong.s))
            .to.be.revertedWithCustomError(c, "BadProof");

        const forOther = await certProof(x1, hospital, h("c-other"));
        await expect(c.connect(hospital).issueCertificateWithProof(patient.address, id, dataRef, sigHash, forOther.e, forOther.s))
            .to.be.revertedWithCustomError(c, "BadProof");

        const byH2 = await certProof(x2, hospital2, id); // valid for hospital2 only
        await expect(c.connect(hospital).issueCertificateWithProof(patient.address, id, dataRef, sigHash, byH2.e, byH2.s))
            .to.be.revertedWithCustomError(c, "BadProof");
        await expect(c.connect(hospital2).issueCertificateWithProof(patient.address, id, dataRef, sigHash, byH2.e, byH2.s))
            .to.emit(c, "CertificateIssued");
    });

    it("a replayed proof cannot create a duplicate certificate", async () => {
        const id = h("c1");
        const p = await certProof(x1, hospital, id);
        await expect(c.connect(hospital).issueCertificateWithProof(patient.address, id, dataRef, sigHash, p.e, p.s))
            .to.be.revertedWithCustomError(c, "IdExists");
    });

    it("measures the extra cost of the proof against plain issuance", async () => {
        const c2 = await (await ethers.getContractFactory("HealthcareOptimized")).deploy();
        await c2.registerEntity(hospital.address, Role.Hospital, h("h1"));
        await c2.registerEntity(patient.address, Role.Patient, h("p"));
        await gas.rec("issueCertificate (no proof, same contract)", c2.connect(hospital).issueCertificate(patient.address, h("m1"), dataRef, sigHash));
    });

    after(() => gas.save());
});