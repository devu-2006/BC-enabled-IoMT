const { expect } = require("chai");
const { ethers } = require("hardhat");
const { GasRecorder } = require("./helpers");

describe("HealthcareBaseline", function () {
  let c, authority, hospital, doctor, patient, device;
  const gas = new GasRecorder("baseline");
  const credHash = (s) => ethers.keccak256(ethers.toUtf8Bytes(s));
  const certId = ethers.keccak256(ethers.toUtf8Bytes("cert-1"));
  const encData = ethers.hexlify(new Uint8Array(128).fill(7)); // fixed bytes -> reproducible gas
  const sig = ethers.hexlify(new Uint8Array(65).fill(9));

  before(async () => {
    [authority, hospital, doctor, patient, device] = await ethers.getSigners();
    c = await (await ethers.getContractFactory("HealthcareBaseline")).deploy();
    await c.waitForDeployment();
  });

  it("registers hospital, doctor, patient, device", async () => {
    await gas.rec("registerEntity(hospital)", c.registerEntity(hospital.address, "hospital", "City Hospital", credHash("h")));
    await gas.rec("registerEntity(doctor)", c.registerEntity(doctor.address, "doctor", "Dr A", credHash("d")));
    await gas.rec("registerEntity(patient)", c.registerEntity(patient.address, "patient", "P1", credHash("p")));
    await gas.rec("registerEntity(device)", c.registerEntity(device.address, "device", "Watch", credHash("w")));
    expect((await c.entities(patient.address)).registered).to.equal(true);
  });

  it("rejects registration by non-authority", async () => {
    await expect(c.connect(doctor).registerEntity(doctor.address, "doctor", "x", credHash("x")))
      .to.be.revertedWith("not authority");
  });

  it("issues and verifies a certificate", async () => {
    await gas.rec("issueCertificate", c.connect(hospital).issueCertificate(patient.address, certId, encData, sig));
    expect(await c.verifyCertificate(certId)).to.equal(true);
  });

  it("only hospitals can issue certificates", async () => {
    const id2 = ethers.keccak256(ethers.toUtf8Bytes("cert-2"));
    await expect(c.connect(doctor).issueCertificate(patient.address, id2, encData, sig))
      .to.be.revertedWith("issuer not hospital");
  });

  it("patient grants access; doctor requests access; audit grows", async () => {
    await gas.rec("grantAccess", c.connect(patient).grantAccess(doctor.address));
    expect(await c.hasAccess(patient.address, doctor.address)).to.equal(true);
    await gas.rec("requestAccess", c.connect(doctor).requestAccess(patient.address, certId));
    expect(await c.auditLength()).to.be.greaterThan(0n);
  });

  it("blocks access for unauthorized doctor and after revocation", async () => {
    await expect(c.connect(device).requestAccess(patient.address, certId)).to.be.revertedWith("no access");
    await gas.rec("revokeAccess", c.connect(patient).revokeAccess(doctor.address));
    await expect(c.connect(doctor).requestAccess(patient.address, certId)).to.be.revertedWith("no access");
  });

  after(() => gas.save());
});
