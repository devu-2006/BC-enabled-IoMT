"""Application gateway (FastAPI) that connects the blockchain, NIZKP service, encrypted storage and IDS.

Prototype simplification: the gateway sends transactions from the node's unlocked demo accounts on
behalf of each role (authority, hospital, patient, doctor, devices). In production every party would
sign with its own wallet.

Environment
  GATEWAY_API_KEY      required, callers send it as X-API-Key
  GATEWAY_MASTER_KEY   required, Fernet key that wraps the record data keys
  NIZK_API_KEY         required, API key of the NIZKP service
  NIZK_URL             default http://127.0.0.1:8001
  RPC_URL              default http://127.0.0.1:8545
  IDS_DATA_CSV         optional path of the IDS dataset (enables /ids/ingest), relative to the repo root
  IDS_MODEL            default ids/models/ids_xgb_fsC.joblib (relative to the repo root)
"""
import hmac
import json
import os
import re
import secrets
from pathlib import Path

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from web3 import Web3

from storage import EncryptedStore

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = json.loads(Path(os.environ.get("DEPLOYMENT", ROOT / "gateway" / "deployment.json")).read_text())
RPC_URL = os.environ.get("RPC_URL", "http://127.0.0.1:8545")
NIZK_URL = os.environ.get("NIZK_URL", "http://127.0.0.1:8001")

w3 = Web3(Web3.HTTPProvider(RPC_URL))
contract = w3.eth.contract(address=Web3.to_checksum_address(DEPLOY["contract"]), abi=DEPLOY["abi"])
ACCOUNTS = {k: Web3.to_checksum_address(v) for k, v in DEPLOY["accounts"].items()}
NAME_OF = {v: k for k, v in ACCOUNTS.items()}
ROLES = {"hospital": 1, "doctor": 2, "patient": 3, "device": 4}

# custom error selectors from the ABI, used to turn reverts into readable HTTP errors
ERRORS = {}
for item in DEPLOY["abi"]:
    if item.get("type") == "error":
        sig = f"{item['name']}({','.join(i['type'] for i in item.get('inputs', []))})"
        ERRORS[Web3.keccak(text=sig)[:4].hex().removeprefix("0x")] = item["name"]
FORBIDDEN = {"NoAccess", "NotAuthorized", "NotAuthority", "EmergencyNotAllowed"}

store = None
ids = None


def _store() -> EncryptedStore:
    global store
    if store is None:
        store = EncryptedStore(ROOT / "gateway" / "store", os.environ["GATEWAY_MASTER_KEY"])
    return store


def _ids():
    global ids
    if ids is None:
        csv = os.environ.get("IDS_DATA_CSV")
        if not csv:
            raise HTTPException(status_code=503, detail="IDS_DATA_CSV is not set")
        from ids_service import IdsService
        csv_path = Path(csv) if Path(csv).is_absolute() else ROOT / csv      # relative paths are from the repo root
        model = Path(os.environ.get("IDS_MODEL", "ids/models/ids_xgb_fsC.joblib"))
        model_path = model if model.is_absolute() else ROOT / model
        for label, f in (("IDS_DATA_CSV", csv_path), ("IDS model", model_path)):
            if not f.exists():
                raise HTTPException(status_code=503, detail=f"{label} not found: {f}")
        ids = IdsService(model_path, csv_path)
    return ids


app = FastAPI(title="Healthcare access-control gateway", version="0.1.0")


def require_key(x_api_key: str = Header(default="")):
    expected = os.environ.get("GATEWAY_API_KEY", "")
    if not expected or not hmac.compare_digest(x_api_key.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="invalid API key")


def account(name: str) -> str:
    if name not in ACCOUNTS:
        raise HTTPException(status_code=404, detail=f"unknown account '{name}'")
    return ACCOUNTS[name]


def revert_name(exc: Exception) -> str:
    text = " ".join(str(a) for a in getattr(exc, "args", [])) + " " + str(exc)
    m = re.search(r"custom error '(\w+)\(", text) or re.search(r"\b([A-Z]\w+)\(\)", text)
    if m and m.group(1) in ERRORS.values():
        return m.group(1)
    for sel in re.findall(r"0x([0-9a-fA-F]{8})", text):
        if sel.lower() in ERRORS:
            return ERRORS[sel.lower()]
    return "ContractError"


def send(fn, sender: str):
    """Send a transaction, translating contract reverts into HTTP errors."""
    try:
        tx = fn.transact({"from": sender})
        rc = w3.eth.wait_for_transaction_receipt(tx)
    except HTTPException:
        raise
    except Exception as exc:                      # revert during gas estimation / execution
        name = revert_name(exc)
        code = 403 if name in FORBIDDEN else 404 if name == "NotFound" else 400
        raise HTTPException(status_code=code, detail=f"contract reverted: {name}")
    return {"tx_hash": tx.hex() if hasattr(tx, "hex") else str(tx), "gas_used": rc["gasUsed"]}


def nizk(path: str, payload: dict) -> dict:
    try:
        r = httpx.post(f"{NIZK_URL}{path}", json=payload, timeout=30,
                       headers={"X-API-Key": os.environ.get("NIZK_API_KEY", "")})
    except httpx.HTTPError:
        raise HTTPException(status_code=502, detail="NIZKP service unreachable")
    if r.status_code != 200:
        raise HTTPException(status_code=502, detail=f"NIZKP service error {r.status_code}: {r.text}")
    return r.json()


def b32(hexstr: str) -> bytes:
    return bytes.fromhex(hexstr[2:])


# ----------------------------------------------------------------------------- models
class EntityReq(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    role: str = Field(pattern="^(hospital|doctor|patient|device)$")


class CertReq(BaseModel):
    hospital: str
    patient: str
    record: str = Field(min_length=1, max_length=100_000)


class GrantReq(BaseModel):
    patient: str
    grantee: str
    duration_seconds: int = Field(default=0, ge=0)


class ReadReq(BaseModel):
    requester: str


class IngestReq(BaseModel):
    device: str
    rows: list[dict] = Field(min_length=1)


# ----------------------------------------------------------------------------- endpoints
@app.get("/health")
def health():
    return {"status": "ok", "chain_id": w3.eth.chain_id, "block": w3.eth.block_number,
            "contract": contract.address}


@app.post("/entities", dependencies=[Depends(require_key)])
def register_entity(req: EntityReq):
    addr = account(req.name)
    cred = Web3.keccak(text=req.name)
    r = send(contract.functions.registerEntity(addr, ROLES[req.role], cred), account("authority"))
    return {"name": req.name, "role": req.role, "address": addr, **r}


@app.post("/hospitals/{name}/proof-key", dependencies=[Depends(require_key)])
def register_proof_key(name: str):
    addr = account(name)
    hid = name.replace(" ", "_")
    key = httpx.post(f"{NIZK_URL}/keys", json={"hospital_id": hid}, timeout=30,
                     headers={"X-API-Key": os.environ.get("NIZK_API_KEY", "")})
    if key.status_code == 200:
        pub = key.json()
    elif key.status_code == 409:
        pub = httpx.get(f"{NIZK_URL}/keys/{hid}", timeout=30,
                        headers={"X-API-Key": os.environ.get("NIZK_API_KEY", "")}).json()
    else:
        raise HTTPException(status_code=502, detail=f"NIZKP service error {key.status_code}")
    proof = nizk("/proofs/key-registration", {"hospital_id": hid, "chain_id": w3.eth.chain_id,
                                              "contract": contract.address, "hospital_address": addr})
    r = send(contract.functions.setProofKey(b32(pub["px"]), pub["parity"], b32(proof["e"]), b32(proof["s"])), addr)
    return {"hospital": name, "px": pub["px"], "parity": pub["parity"], **r}


@app.post("/certificates", dependencies=[Depends(require_key)])
def issue_certificate(req: CertReq):
    hospital, patient = account(req.hospital), account(req.patient)
    unique_id = "0x" + secrets.token_hex(32)
    data_ref = _store().put(unique_id, req.record.encode())           # encrypted off-chain
    # the hospital signs the ciphertext reference; only the hash of that signature goes on-chain
    sig = w3.eth.sign(hospital, data=bytes.fromhex(data_ref[2:]))
    sig_hash = Web3.keccak(sig).hex()
    sig_hash = sig_hash if sig_hash.startswith("0x") else "0x" + sig_hash
    proof = nizk("/proofs/certificate", {
        "hospital_id": req.hospital.replace(" ", "_"), "chain_id": w3.eth.chain_id,
        "contract": contract.address, "issuer": hospital, "patient": patient,
        "unique_id": unique_id, "data_ref": data_ref, "sig_hash": sig_hash})
    r = send(contract.functions.issueCertificateWithProof(
        patient, b32(unique_id), b32(data_ref), b32(sig_hash), b32(proof["e"]), b32(proof["s"])), hospital)
    return {"unique_id": unique_id, "data_ref": data_ref, "sig_hash": sig_hash, **r}


@app.post("/access/grant", dependencies=[Depends(require_key)])
def grant(req: GrantReq):
    return send(contract.functions.grantAccess(account(req.grantee), req.duration_seconds), account(req.patient))


@app.post("/access/revoke", dependencies=[Depends(require_key)])
def revoke(req: GrantReq):
    return send(contract.functions.revokeAccess(account(req.grantee)), account(req.patient))


@app.post("/records/{unique_id}/read", dependencies=[Depends(require_key)])
def read_record(unique_id: str, req: ReadReq):
    if not re.fullmatch(r"0x[0-9a-fA-F]{64}", unique_id):
        raise HTTPException(status_code=422, detail="unique_id must be 0x + 64 hex characters")
    requester = account(req.requester)
    cert = contract.functions.certificates(b32(unique_id)).call()   # (patient, issuedAt, valid, dataRef, commitment)
    patient, valid, data_ref = cert[0], cert[2], "0x" + bytes(cert[3]).hex()
    if not valid:
        raise HTTPException(status_code=404, detail="unknown certificate")
    send(contract.functions.requestAccess(patient, b32(unique_id)), requester)   # on-chain check + audit event
    try:
        plaintext = _store().get(unique_id, data_ref)
    except ValueError as e:
        raise HTTPException(status_code=500, detail=str(e))
    return {"unique_id": unique_id, "patient": NAME_OF.get(patient, patient), "record": plaintext.decode()}


@app.post("/ids/ingest", dependencies=[Depends(require_key)])
def ids_ingest(req: IngestReq):
    device = account(req.device)
    try:
        result = _ids().decide(req.rows)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    result["device"] = req.device
    if result["decision"] == "suspend":
        result["suspension"] = send(contract.functions.suspendEntity(device), account("oracle"))
    return result


@app.get("/audit", dependencies=[Depends(require_key)])
def audit():
    names = ["EntityRegistered", "ProofKeySet", "CertificateIssued", "AccessGranted", "AccessRevoked",
             "AccessUsed", "EntitySuspended", "EntityReactivated", "EmergencyAccess"]
    out = []
    for n in names:
        for ev in getattr(contract.events, n)().get_logs(from_block=0):
            args = {}
            for k, v in ev["args"].items():
                if isinstance(v, (bytes, bytearray)):
                    v = "0x" + bytes(v).hex()
                elif isinstance(v, str) and v in NAME_OF:
                    v = NAME_OF[v]
                args[k] = v if isinstance(v, (str, int, bool)) else str(v)
            out.append({"block": ev["blockNumber"], "event": n, **args})
    return sorted(out, key=lambda e: e["block"])