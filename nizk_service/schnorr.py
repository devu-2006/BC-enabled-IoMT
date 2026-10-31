"""Pure-Python secp256k1 Schnorr NIZK (Fiat-Shamir), compatible with contracts/SchnorrNIZK.sol.

Proof for secret x, public key P = x*G, message m:
    k random, R = k*G
    e = keccak256(addr(R) || parity(P) || P.x || m)
    s = k + e*x  (mod n)
Verifier: R' = s*G - e*P, accept iff e == keccak256(addr(R') || parity(P) || P.x || m)

NOTE: pure-Python big-integer arithmetic is not constant-time. This is acceptable for a prototype;
a production service should use libsecp256k1 or an HSM.
"""
import secrets
from Crypto.Hash import keccak

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def keccak256(data: bytes) -> bytes:
    return keccak.new(digest_bits=256, data=data).digest()


# ----------------------------------------------------------------------------- curve arithmetic
def _add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = (3 * a[0] * a[0]) * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)


def _mul(k, pt):
    k %= N
    r, addend = None, pt
    while k:
        if k & 1:
            r = _add(r, addend)
        addend = _add(addend, addend)
        k >>= 1
    return r


def _decompress(px: int, parity: int):
    y2 = (pow(px, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if (y * y) % P != y2:
        raise ValueError("x is not on the curve")
    return (px, y if (y & 1) == parity else P - y)


def _address(pt) -> bytes:
    return keccak256(pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big"))[12:]


# ----------------------------------------------------------------------------- hex helpers
def _hex_bytes(value: str, n: int, name: str) -> bytes:
    v = value[2:] if value.startswith(("0x", "0X")) else value
    if len(v) != 2 * n:
        raise ValueError(f"{name} must be {n} bytes")
    return bytes.fromhex(v)


def _hex32(n: int) -> str:
    return "0x" + n.to_bytes(32, "big").hex()


# ----------------------------------------------------------------------------- public API
def random_secret() -> int:
    return secrets.randbelow(N - 1) + 1


def public_key(x: int):
    """Returns (px_hex, parity)."""
    px, py = _mul(x, G)
    return _hex32(px), py & 1


def prove(x: int, message: str) -> dict:
    px_hex, parity = public_key(x)
    msg = _hex_bytes(message, 32, "message")
    k = random_secret()
    R = _mul(k, G)
    e = int.from_bytes(
        keccak256(_address(R) + bytes([parity]) + _hex_bytes(px_hex, 32, "px") + msg), "big")
    s = (k + (e % N) * x) % N
    return {"px": px_hex, "parity": parity, "message": message, "e": _hex32(e), "s": _hex32(s)}


def verify(px: str, parity: int, message: str, e: str, s: str) -> bool:
    try:
        if parity not in (0, 1):
            return False
        px_i = int.from_bytes(_hex_bytes(px, 32, "px"), "big")
        e_b = _hex_bytes(e, 32, "e")
        e_i = int.from_bytes(e_b, "big")
        s_i = int.from_bytes(_hex_bytes(s, 32, "s"), "big")
        if px_i == 0 or px_i >= N or e_i == 0 or s_i == 0 or s_i >= N:
            return False
        pub = _decompress(px_i, parity)
        R = _add(_mul(s_i, G), _mul(N - (e_i % N), pub))
        if R is None:
            return False
        digest = keccak256(_address(R) + bytes([parity]) + _hex_bytes(px, 32, "px")
                           + _hex_bytes(message, 32, "message"))
        return digest == e_b
    except ValueError:
        return False


# ----------------------------------------------------------------------------- message builders
def certificate_message(chain_id: int, contract: str, issuer: str, patient: str,
                        unique_id: str, data_ref: str, sig_hash: str) -> str:
    """Equals HealthcareOptimized.certificateProofMessage(...)."""
    data = (chain_id.to_bytes(32, "big") + _hex_bytes(contract, 20, "contract")
            + _hex_bytes(issuer, 20, "issuer") + _hex_bytes(patient, 20, "patient")
            + _hex_bytes(unique_id, 32, "unique_id") + _hex_bytes(data_ref, 32, "data_ref")
            + _hex_bytes(sig_hash, 32, "sig_hash"))
    return "0x" + keccak256(data).hex()


def key_registration_message(chain_id: int, contract: str, hospital: str) -> str:
    """Equals HealthcareOptimized.keyRegistrationMessage(hospital)."""
    data = (b"KEYREG" + chain_id.to_bytes(32, "big")
            + _hex_bytes(contract, 20, "contract") + _hex_bytes(hospital, 20, "hospital"))
    return "0x" + keccak256(data).hex()