// IDS -> contract hook: applies the decisions produced by ids/05_score_telemetry.py.
const { expect } = require("chai");
const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

const file = path.join(__dirname, "..", "results", "ids_decisions.json");
const Role = { Hospital: 1, Doctor: 2, Patient: 3, Device: 4 };

describe("IDS oracle -> access control", function () {
    let c, authority, oracle, hospital, patient, doctor, devices, data;
    const h = (s) => ethers.keccak256(ethers.toUtf8Bytes(s));
    const certId = h("cert-ids");

    before(async function () {
        if (!fs.existsSync(file)) this.skip(); // run python ids/05_score_telemetry.py first
        data = JSON.parse(fs.readFileSync(file, "utf8"));
        const signers = await ethers.getSigners();
        [authority, oracle, hospital, patient, doctor] = signers;
        devices = {};
        data.decisions.forEach((d, i) => (devices[d.device] = signers[5 + i]));

        c = await (await ethers.getContractFactory("HealthcareOptimized")).deploy();
        await c.waitForDeployment();
        await c.registerEntity(hospital.address, Role.Hospital, h("h"));
        await c.registerEntity(patient.address, Role.Patient, h("p"));
        await c.registerEntity(doctor.address, Role.Doctor, h("d"));
        for (const [name, s] of Object.entries(devices)) {
            await c.registerEntity(s.address, Role.Device, h(name));
            await c.connect(patient).grantAccess(s.address, 0);
        }
        await c.connect(hospital).issueCertificate(patient.address, certId, h("ref"), h("sig"));
        await c.setOracle(oracle.address);
    });

    it("only the oracle or the authority can suspend", async () => {
        const any = Object.values(devices)[0];
        await expect(c.connect(doctor).suspendEntity(any.address)).to.be.revertedWithCustomError(c, "NotAuthorized");
    });

    it("applies each IDS decision and shows its effect on access", async () => {
        const table = [];
        for (const d of data.decisions) {
            const dev = devices[d.device];
            const before = await c.hasAccess(patient.address, dev.address);
            if (d.decision === "suspend") await c.connect(oracle).suspendEntity(dev.address);
            const after = await c.hasAccess(patient.address, dev.address);
            table.push({ device: d.device, true_traffic: d.true_category, max_score: d.max_score,
                decision: d.decision, access_before: before, access_after: after });

            expect(before).to.equal(true);
            expect(after).to.equal(d.decision !== "suspend"); // only "suspend" cuts access
            if (d.decision === "suspend") {
                await expect(c.connect(dev).requestAccess(patient.address, certId))
                    .to.be.revertedWithCustomError(c, "NoAccess");
            } else {
                await c.connect(dev).requestAccess(patient.address, certId); // still works
            }
        }
        console.table(table);
    });

    it("the authority can reactivate a suspended device", async () => {
        const suspended = data.decisions.find((d) => d.decision === "suspend");
        if (!suspended) return; // nothing was suspended in this run
        const dev = devices[suspended.device];
        await c.reactivateEntity(dev.address);
        expect(await c.hasAccess(patient.address, dev.address)).to.equal(true);
    });
});