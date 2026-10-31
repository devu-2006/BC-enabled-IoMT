// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * Reproduction of the on-chain verifier printed in the base paper (Sec. 3.4.1), kept ONLY to
 * demonstrate its limitation: checked exponentiation (`**`) overflows uint256 for realistic
 * exponents, so the call reverts. Do not use in the system.
 */
contract PaperNIZKPVerifier {
    uint256 public g;
    uint256 public p;

    constructor(uint256 _g, uint256 _p) {
        g = _g;
        p = _p;
    }

    function verifyProof(uint256 z, uint256 C, uint256 S, uint256 c) public view returns (bool) {
        return g ** z % p == C * S ** c % p;
    }
}