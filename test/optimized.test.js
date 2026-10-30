const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");
const { GasRecorder } = require("./helpers");

const Role = { Hospital: 1, Doctor: 2, Patient: 3, Device: 4 };

describe("HealthcareOptimized", function () {
    let c, authority, hospital, doctor, patient, device, oracle;
    const gas = new GasRecorder("optimized");
    const h = (s) => ethers.keccak256(ethers.toUtf8Bytes(s));
    const certId = h("cert-1");
    const dataRef = h("ipfs-cid-of-encrypted-record");
    const sigHash = h("signature");

    before(async () => {
        [authority, hospital, doctor, patient, device, oracle] = await ethers.getSigners();
        c = await (await ethers.getContractFactory("HealthcareOptimized")).deploy();
        await c.waitForDeployment();
    });

    it("registers hospital, doctor, patient, device", async () => {
        await gas.rec("registerEntity(hospital)", c.registerEntity(hospital.address, Role.Hospital, h("h")));
        await gas.rec("registerEntity(doctor)", c.registerEntity(doctor.address, Role.Doctor, h("d")));
        await gas.rec("registerEntity(patient)", c.registerEntity(patient.address, Role.Patient, h("p")));
        await gas.rec("registerEntity(device)", c.registerEntity(device.address, Role.Device, h("w")));
        expect((await c.entities(patient.address)).active).to.equal(true);
    });

    it("rejects non-authority and duplicate registration", async () => {
        await expect(c.connect(doctor).registerEntity(doctor.address, Role.Doctor, h("x")))
            .to.be.revertedWithCustomError(c, "NotAuthority");
        await expect(c.registerEntity(doctor.address, Role.Doctor, h("x")))
            .to.be.revertedWithCustomError(c, "AlreadyRegistered");
    });

    it("issues and verifies a certificate; only hospitals; no duplicate ids", async () => {
        await gas.rec("issueCertificate", c.connect(hospital).issueCertificate(patient.address, certId, dataRef, sigHash));
        expect(await c.verifyCertificate(certId, sigHash)).to.equal(true);
        expect(await c.verifyCertificate(certId, h("wrong"))).to.equal(false);
        await expect(c.connect(doctor).issueCertificate(patient.address, h("c2"), dataRef, sigHash))
            .to.be.revertedWithCustomError(c, "NotAuthorized");
        await expect(c.connect(hospital).issueCertificate(patient.address, certId, dataRef, sigHash))
            .to.be.revertedWithCustomError(c, "IdExists");
    });

    it("patient grants access; doctor reads; unauthorized party blocked", async () => {
        await gas.rec("grantAccess", c.connect(patient).grantAccess(doctor.address, 0));
        expect(await c.hasAccess(patient.address, doctor.address)).to.equal(true);
        expect(await c.connect(doctor).requestAccess.staticCall(patient.address, certId)).to.equal(dataRef);
        await gas.rec("requestAccess", c.connect(doctor).requestAccess(patient.address, certId));
        await expect(c.connect(device).requestAccess(patient.address, certId))
            .to.be.revertedWithCustomError(c, "NoAccess");
    });

    it("revocation blocks access", async () => {
        await gas.rec("revokeAccess", c.connect(patient).revokeAccess(doctor.address));
        await expect(c.connect(doctor).requestAccess(patient.address, certId))
            .to.be.revertedWithCustomError(c, "NoAccess");
        await expect(c.connect(patient).revokeAccess(doctor.address))
            .to.be.revertedWithCustomError(c, "NoAccess");
    });

    it("time-bound consent expires", async () => {
        await gas.rec("grantAccess(1h)", c.connect(patient).grantAccess(doctor.address, 3600));
        expect(await c.hasAccess(patient.address, doctor.address)).to.equal(true);
        await time.increase(3601);
        expect(await c.hasAccess(patient.address, doctor.address)).to.equal(false);
    });

    it("IDS oracle can suspend an entity; access is cut immediately", async () => {
        await c.connect(patient).grantAccess(doctor.address, 0);
        await expect(c.connect(oracle).suspendEntity(doctor.address))
            .to.be.revertedWithCustomError(c, "NotAuthorized");
        await c.setOracle(oracle.address);
        await gas.rec("suspendEntity", c.connect(oracle).suspendEntity(doctor.address));
        expect(await c.hasAccess(patient.address, doctor.address)).to.equal(false);
        await c.reactivateEntity(doctor.address);
        expect(await c.hasAccess(patient.address, doctor.address)).to.equal(true);
        await c.connect(patient).revokeAccess(doctor.address);
    });

    it("break-glass: blocked by default, allowed by patient policy, expires, doctors only", async () => {
        const reason = h("cardiac arrest, patient unconscious");
        await expect(c.connect(doctor).emergencyAccess(patient.address, certId, reason))
            .to.be.revertedWithCustomError(c, "EmergencyNotAllowed");
        await gas.rec("setEmergencyPolicy", c.connect(patient).setEmergencyPolicy(true));
        await expect(c.connect(device).emergencyAccess(patient.address, certId, reason))
            .to.be.revertedWithCustomError(c, "NotAuthorized");
        await expect(c.connect(doctor).emergencyAccess(patient.address, certId, reason))
            .to.emit(c, "EmergencyAccess");
        await gas.rec("emergencyAccess", c.connect(doctor).emergencyAccess(patient.address, certId, reason));
        expect(await c.hasAccess(patient.address, doctor.address)).to.equal(true);
        await time.increase(3601);
        expect(await c.hasAccess(patient.address, doctor.address)).to.equal(false);
    });

    it("batch registration of 4 entities", async () => {
        const c2 = await (await ethers.getContractFactory("HealthcareOptimized")).deploy();
        const addrs = [hospital.address, doctor.address, patient.address, device.address];
        const roles = [Role.Hospital, Role.Doctor, Role.Patient, Role.Device];
        const hashes = [h("h"), h("d"), h("p"), h("w")];
        await gas.rec("registerEntities(4 batch)", c2.registerEntities(addrs, roles, hashes));
    });

    after(() => gas.save());
});