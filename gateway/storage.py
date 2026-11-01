"""Encrypted off-chain record store (content-addressed, IPFS-compatible design).

  * every record gets its own random AES-256-GCM data key
  * ciphertext is stored under its SHA-256 digest (the value kept on-chain as `dataRef`)
  * the data key is wrapped with a master key (Fernet) and kept in keys.json
  * get() re-hashes the ciphertext and compares it with the on-chain reference (integrity check),
    then decrypts. The caller (gateway) releases a record only after the contract authorises the read.
A real IPFS node can replace put()/get() of the blob; the encryption and key flow stay the same.
"""
import hashlib
import json
import os
import threading
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class EncryptedStore:
    def __init__(self, root: Path, master_key: str):
        self.root = Path(root)
        (self.root / "blobs").mkdir(parents=True, exist_ok=True)
        self.keys_path = self.root / "keys.json"
        self.fernet = Fernet(master_key.encode())
        self.lock = threading.Lock()

    def _keys(self) -> dict:
        return json.loads(self.keys_path.read_text()) if self.keys_path.exists() else {}

    def put(self, unique_id: str, plaintext: bytes) -> str:
        uid = bytes.fromhex(unique_id[2:])
        key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        blob = nonce + AESGCM(key).encrypt(nonce, plaintext, uid)   # unique_id is authenticated data
        ref = hashlib.sha256(blob).hexdigest()
        (self.root / "blobs" / f"{ref}.bin").write_bytes(blob)
        with self.lock:
            keys = self._keys()
            keys[unique_id] = self.fernet.encrypt(key).decode()
            self.keys_path.write_text(json.dumps(keys))
        return "0x" + ref

    def get(self, unique_id: str, data_ref: str) -> bytes:
        blob = (self.root / "blobs" / f"{data_ref[2:]}.bin").read_bytes()
        if hashlib.sha256(blob).hexdigest() != data_ref[2:]:
            raise ValueError("stored ciphertext does not match its on-chain reference")
        key = self.fernet.decrypt(self._keys()[unique_id].encode())
        return AESGCM(key).decrypt(blob[:12], blob[12:], bytes.fromhex(unique_id[2:]))