"""Off-chain NIZKP service (FastAPI).

Design (security):
  * Hospital proof secrets are generated and kept INSIDE the service; no endpoint ever returns one.
  * Secrets are encrypted at rest (Fernet, key from NIZK_MASTER_KEY).
  * Callers must send the X-API-Key header (value from NIZK_API_KEY).
  * The service only signs the two message types the contract expects (certificate issuance and
    key registration), never an arbitrary message, so it cannot be used as a signing oracle.
Environment: NIZK_API_KEY, NIZK_MASTER_KEY, NIZK_KEYSTORE (optional path, default keystore.enc.json)
"""
import hmac
import json
import os
import threading
from pathlib import Path

from cryptography.fernet import Fernet
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

import schnorr

ADDR = r"^0x[0-9a-fA-F]{40}$"
B32 = r"^0x[0-9a-fA-F]{64}$"


def _env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise HTTPException(status_code=500, detail=f"server misconfigured: {name} is not set")
    return value


class KeyStore:
    """Fernet-encrypted JSON file: hospital_id -> encrypted secret."""

    def __init__(self):
        self._lock = threading.Lock()

    def _path(self) -> Path:
        return Path(os.environ.get("NIZK_KEYSTORE", "keystore.enc.json"))

    def _fernet(self) -> Fernet:
        return Fernet(_env("NIZK_MASTER_KEY").encode())

    def _load(self) -> dict:
        p = self._path()
        return json.loads(p.read_text()) if p.exists() else {}

    def create(self, hospital_id: str) -> int:
        with self._lock:
            data = self._load()
            if hospital_id in data:
                raise KeyError(hospital_id)
            secret = schnorr.random_secret()
            data[hospital_id] = self._fernet().encrypt(secret.to_bytes(32, "big")).decode()
            self._path().write_text(json.dumps(data))
            return secret

    def get_secret(self, hospital_id: str) -> int:
        with self._lock:
            token = self._load().get(hospital_id)
        if token is None:
            raise KeyError(hospital_id)
        return int.from_bytes(self._fernet().decrypt(token.encode()), "big")


store = KeyStore()
app = FastAPI(title="NIZKP service", version="0.1.0")


def require_key(x_api_key: str = Header(default="")):
    if not hmac.compare_digest(x_api_key.encode(), _env("NIZK_API_KEY").encode()):
        raise HTTPException(status_code=401, detail="invalid API key")


class KeyRequest(BaseModel):
    hospital_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")


class KeyResponse(BaseModel):
    hospital_id: str
    px: str
    parity: int


class KeyRegProofRequest(BaseModel):
    hospital_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    chain_id: int = Field(ge=1)
    contract: str = Field(pattern=ADDR)
    hospital_address: str = Field(pattern=ADDR)


class CertProofRequest(BaseModel):
    hospital_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    chain_id: int = Field(ge=1)
    contract: str = Field(pattern=ADDR)
    issuer: str = Field(pattern=ADDR)
    patient: str = Field(pattern=ADDR)
    unique_id: str = Field(pattern=B32)
    data_ref: str = Field(pattern=B32)
    sig_hash: str = Field(pattern=B32)


class ProofResponse(BaseModel):
    hospital_id: str
    px: str
    parity: int
    message: str
    e: str
    s: str


class VerifyRequest(BaseModel):
    px: str = Field(pattern=B32)
    parity: int = Field(ge=0, le=1)
    message: str = Field(pattern=B32)
    e: str = Field(pattern=B32)
    s: str = Field(pattern=B32)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/keys", response_model=KeyResponse, dependencies=[Depends(require_key)])
def create_key(req: KeyRequest):
    try:
        secret = store.create(req.hospital_id)
    except KeyError:
        raise HTTPException(status_code=409, detail="key already exists for this hospital_id")
    px, parity = schnorr.public_key(secret)
    return KeyResponse(hospital_id=req.hospital_id, px=px, parity=parity)


@app.get("/keys/{hospital_id}", response_model=KeyResponse, dependencies=[Depends(require_key)])
def get_public_key(hospital_id: str):
    try:
        secret = store.get_secret(hospital_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="unknown hospital_id")
    px, parity = schnorr.public_key(secret)
    return KeyResponse(hospital_id=hospital_id, px=px, parity=parity)


def _prove(hospital_id: str, message: str) -> ProofResponse:
    try:
        secret = store.get_secret(hospital_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="unknown hospital_id")
    proof = schnorr.prove(secret, message)
    return ProofResponse(hospital_id=hospital_id, **proof)


@app.post("/proofs/key-registration", response_model=ProofResponse, dependencies=[Depends(require_key)])
def key_registration_proof(req: KeyRegProofRequest):
    msg = schnorr.key_registration_message(req.chain_id, req.contract, req.hospital_address)
    return _prove(req.hospital_id, msg)


@app.post("/proofs/certificate", response_model=ProofResponse, dependencies=[Depends(require_key)])
def certificate_proof(req: CertProofRequest):
    msg = schnorr.certificate_message(req.chain_id, req.contract, req.issuer, req.patient,
                                      req.unique_id, req.data_ref, req.sig_hash)
    return _prove(req.hospital_id, msg)


@app.post("/verify", dependencies=[Depends(require_key)])
def verify_proof(req: VerifyRequest):
    return {"valid": schnorr.verify(req.px, req.parity, req.message, req.e, req.s)}