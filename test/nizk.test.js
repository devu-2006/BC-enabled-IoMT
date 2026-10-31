const { expect } = require("chai");
const { ethers } = require("hardhat");
const crypto = require("crypto");
const { prove, randomScalar, publicKey, hex32, Q } = require("../scripts/schnorr");
const { GasRecorder } = require("./helpers");

describe("Corrected NIZKP (Schnorr over secp256k1)", function () {
    let v;
    const gas = new GasRecorder("nizk");
    const msg = ethers.keccak256(ethers.toUtf8Bytes("certificate-1"));
    const secret = randomScalar();

    before(async () => {
        v = await (await ethers.getContractFactory("SchnorrNIZK")).deploy();
        await v.waitForDeployment();
    });

    it("accepts an honest proof", async () => {
        const p = prove(secret, msg);
        expect(await v.verifyProof(p.px, p.parity, p.message, p.e, p.s)).to.equal(true);
    });

    it("accepts honest proofs for many random secrets and messages", async () => {
        for (let i = 0; i < 25; i++) {
            const p = prove(randomScalar(), ethers.hexlify(ethers.randomBytes(32)));
            expect(await v.verifyProof(p.px, p.parity, p.message, p.e, p.s)).to.equal(true);
        }
    });

    it("rejects a proof replayed for another message", async () => {
        const p = prove(secret, msg);
        const other = ethers.keccak256(ethers.toUtf8Bytes("certificate-2"));
        expect(await v.verifyProof(p.px, p.parity, other, p.e, p.s)).to.equal(false);
    });

    it("rejects tampered e or s", async () => {
        const p = prove(secret, msg);
        const badE = hex32((BigInt(p.e) + 1n) % (1n << 256n));
        const badS = hex32((BigInt(p.s) + 1n) % Q);
        expect(await v.verifyProof(p.px, p.parity, p.message, badE, p.s)).to.equal(false);
        expect(await v.verifyProof(p.px, p.parity, p.message, p.e, badS)).to.equal(false);
    });

    it("rejects a proof under a different public key or wrong parity", async () => {
        const p = prove(secret, msg);
        const other = publicKey(randomScalar());
        expect(await v.verifyProof(other.px, other.parity, p.message, p.e, p.s)).to.equal(false);
        expect(await v.verifyProof(p.px, 1 - p.parity, p.message, p.e, p.s)).to.equal(false);
    });

    it("rejects malformed inputs", async () => {
        const p = prove(secret, msg);
        expect(await v.verifyProof(ethers.ZeroHash, p.parity, p.message, p.e, p.s)).to.equal(false);
        expect(await v.verifyProof(p.px, 2, p.message, p.e, p.s)).to.equal(false);
        expect(await v.verifyProof(p.px, p.parity, p.message, ethers.ZeroHash, p.s)).to.equal(false);
    });

    it("records a verified proof as an event and measures gas", async () => {
        const p = prove(secret, msg);
        const est = await v.verifyProof.estimateGas(p.px, p.parity, p.message, p.e, p.s);
        gas.rows["verifyProof (estimateGas, incl. 21000 base)"] = Number(est);
        await gas.rec("verifyAndRecord (tx)", v.verifyAndRecord(p.px, p.parity, p.message, p.e, p.s));
        await expect(v.verifyAndRecord(p.px, p.parity, p.message, p.e, p.s)).to.emit(v, "ProofVerified");
    });

    describe("limitations of the paper's verifier", function () {
        // Toy Schnorr group exactly as in the paper: S = g^s, C = g^r, c = SHA-256(S,C), z = r + c*s mod (p-1)
        const modpow = (b, e, m) => { let r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; };
        const p = 2039n, g = 4n, s = 123n, r = 77n;
        const S = modpow(g, s, p), C = modpow(g, r, p);
        const c = BigInt("0x" + crypto.createHash("sha256").update(String(S) + String(C)).digest("hex"));
        const z = (r + c * s) % (p - 1n);

        it("the mathematically correct equation g^z = C*S^c holds, the text's g^r = C*S^c does not", () => {
            const lhsCorrect = modpow(g, z, p);
            const rhs = (C * modpow(S, c, p)) % p;
            expect(lhsCorrect).to.equal(rhs);                  // correct Schnorr check
            expect(modpow(g, r, p)).to.not.equal(rhs);         // equation as printed in Sec. 3.4 Step 4
        });

        it("the paper's on-chain verifyProof reverts (uint256 overflow) with the paper's own challenge", async () => {
            const pv = await (await ethers.getContractFactory("PaperNIZKPVerifier")).deploy(g, p);
            await expect(pv.verifyProof(z, C, S, c)).to.be.revertedWithPanic(0x11);
        });
    });

    describe("cost of a 2048-bit modular exponentiation (paper-style group)", function () {
        it("measures one modexp precompile call", async () => {
            const bm = await (await ethers.getContractFactory("ModexpBenchmark")).deploy();
            const rnd = (n) => "0x" + crypto.randomBytes(n).toString("hex");
            const mod = "0xff" + crypto.randomBytes(254).toString("hex") + "01"; // odd 2048-bit modulus
            const base = rnd(256), exp = rnd(32);                                // 256-bit exponent
            const est = await bm.modexp.estimateGas(base, exp, mod);
            gas.rows["one 2048-bit modexp (estimateGas, incl. 21000 base)"] = Number(est);
        });
    });

    after(() => gas.save());
});