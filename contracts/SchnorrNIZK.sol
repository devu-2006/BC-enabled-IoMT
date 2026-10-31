// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * Corrected, practical NIZKP verifier (Contribution C3).
 *
 * Scheme: non-interactive Schnorr proof of knowledge (Fiat-Shamir) over secp256k1.
 *   Public key  P = x*G          (x is the prover's secret)
 *   Proof       (e, s) with  R = k*G,  e = H(addr(R) || parity(P) || P.x || message),  s = k + e*x  (mod n)
 *   Verify      R' = s*G - e*P  and check  e == H(addr(R') || parity(P) || P.x || message)
 * The elliptic-curve arithmetic is done by the ecrecover precompile (technique of Chronos / noot),
 * so on-chain verification costs a few thousand gas instead of 2048-bit modular exponentiation.
 * The `message` binds the proof to a specific certificate, preventing replay for another one.
 */
library SchnorrLib {
    // order of the secp256k1 group
    uint256 internal constant Q =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    /// @param px     x-coordinate of the public key
    /// @param parity 0 if the y-coordinate of the public key is even, 1 if odd
    function verify(
        bytes32 px,
        uint8 parity,
        bytes32 message,
        bytes32 e,
        bytes32 s
    ) internal pure returns (bool) {
        if (parity > 1 || px == bytes32(0) || e == bytes32(0) || s == bytes32(0)) return false;
        if (uint256(px) >= Q || uint256(s) >= Q) return false;
        uint256 sp = Q - mulmod(uint256(s), uint256(px), Q);
        uint256 ep = Q - mulmod(uint256(e), uint256(px), Q);
        if (sp == Q || ep == Q) return false; // ecrecover needs scalars in [1, Q-1]
        address R = ecrecover(bytes32(sp), 27 + parity, px, bytes32(ep));
        if (R == address(0)) return false;
        return e == keccak256(abi.encodePacked(R, parity, px, message));
    }
}

contract SchnorrNIZK {
    event ProofVerified(address indexed prover, bytes32 indexed message);

    /// Stateless check (view): anyone can verify a proof without the prover being online.
    function verifyProof(
        bytes32 px,
        uint8 parity,
        bytes32 message,
        bytes32 e,
        bytes32 s
    ) external pure returns (bool) {
        return SchnorrLib.verify(px, parity, message, e, s);
    }

    /// Same check, recorded on-chain as an audit event (for certificate verification flows).
    function verifyAndRecord(
        bytes32 px,
        uint8 parity,
        bytes32 message,
        bytes32 e,
        bytes32 s
    ) external returns (bool ok) {
        ok = SchnorrLib.verify(px, parity, message, e, s);
        if (ok) emit ProofVerified(msg.sender, message);
    }
}

/// Measures the cost of one 2048-bit modular exponentiation (the paper-style group operation).
contract ModexpBenchmark {
    function modexp(bytes calldata base, bytes calldata exp, bytes calldata mod)
        external
        view
        returns (bytes memory out)
    {
        bytes memory input = abi.encodePacked(
            uint256(base.length), uint256(exp.length), uint256(mod.length), base, exp, mod
        );
        out = new bytes(mod.length);
        bool ok;
        assembly {
            ok := staticcall(gas(), 0x05, add(input, 0x20), mload(input), add(out, 0x20), mload(out))
        }
        require(ok, "modexp failed");
    }
}