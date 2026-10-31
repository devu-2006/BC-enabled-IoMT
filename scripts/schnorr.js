// Reference prover for the corrected NIZKP (secp256k1 Schnorr, Fiat-Shamir).
// Used by the tests now, and as the test-vector source for the Python/FastAPI service later.
const { secp256k1 } = require("@noble/curves/secp256k1");
const { ethers } = require("ethers");

const Q = secp256k1.CURVE.n;
const G = secp256k1.ProjectivePoint.BASE;

const hex32 = (n) => "0x" + n.toString(16).padStart(64, "0");

function pointToAddress(point) {
    const a = point.toAffine();
    const xy = ethers.getBytes(hex32(a.x) + hex32(a.y).slice(2));
    return ethers.getAddress("0x" + ethers.keccak256(xy).slice(26));
}

function randomScalar() {
    let k = 0n;
    while (k === 0n || k >= Q) k = BigInt(ethers.hexlify(ethers.randomBytes(32)));
    return k;
}

/** Public key of secret x (bigint): returns { px, parity } as the contract expects. */
function publicKey(x) {
    const a = G.multiply(x).toAffine();
    return { px: hex32(a.x), parity: Number(a.y & 1n) };
}

/** Prove knowledge of x, bound to `message` (bytes32 hex). Returns { px, parity, message, e, s }. */
function prove(x, message) {
    const { px, parity } = publicKey(x);
    const k = randomScalar();
    const R = G.multiply(k);
    const e = BigInt(
        ethers.keccak256(ethers.solidityPacked(["address", "uint8", "bytes32", "bytes32"],
            [pointToAddress(R), parity, px, message]))
    );
    const s = (k + (e % Q) * x) % Q;
    return { px, parity, message, e: hex32(e), s: hex32(s) };
}

module.exports = { Q, randomScalar, publicKey, prove, hex32 };