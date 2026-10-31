import json
import os
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

import schnorr

HEADERS = {"X-API-Key": "test-key"}
CONTRACT = "0x" + "ab" * 20
ISSUER = "0x" + "cd" * 20
PATIENT = "0x" + "ef" * 20
B = lambda c: "0x" + c * 64


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("NIZK_API_KEY", "test-key")
    monkeypatch.setenv("NIZK_MASTER_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("NIZK_KEYSTORE", str(tmp_path / "ks.json"))
    import app
    return TestClient(app.app), app


def test_rejects_missing_or_wrong_api_key(client):
    c, _ = client
    assert c.post("/keys", json={"hospital_id": "h1"}).status_code == 401
    assert c.post("/keys", json={"hospital_id": "h1"}, headers={"X-API-Key": "bad"}).status_code == 401


def test_key_lifecycle(client):
    c, _ = client
    r = c.post("/keys", json={"hospital_id": "h1"}, headers=HEADERS)
    assert r.status_code == 200
    pub = r.json()
    assert set(pub) == {"hospital_id", "px", "parity"}            # no secret in the response
    assert c.post("/keys", json={"hospital_id": "h1"}, headers=HEADERS).status_code == 409
    assert c.get("/keys/h1", headers=HEADERS).json() == pub
    assert c.get("/keys/nobody", headers=HEADERS).status_code == 404


def test_certificate_proof_is_valid_and_bound_to_message(client):
    c, _ = client
    pub = c.post("/keys", json={"hospital_id": "h1"}, headers=HEADERS).json()
    body = {"hospital_id": "h1", "chain_id": 31337, "contract": CONTRACT, "issuer": ISSUER,
            "patient": PATIENT, "unique_id": B("1"), "data_ref": B("2"), "sig_hash": B("3")}
    r = c.post("/proofs/certificate", json=body, headers=HEADERS)
    assert r.status_code == 200
    p = r.json()
    assert p["px"] == pub["px"] and p["parity"] == pub["parity"]
    expected = schnorr.certificate_message(31337, CONTRACT, ISSUER, PATIENT, B("1"), B("2"), B("3"))
    assert p["message"] == expected
    assert schnorr.verify(p["px"], p["parity"], p["message"], p["e"], p["s"])
    assert not schnorr.verify(p["px"], p["parity"], B("9"), p["e"], p["s"])
    v = c.post("/verify", json={k: p[k] for k in ("px", "parity", "message", "e", "s")}, headers=HEADERS)
    assert v.json() == {"valid": True}


def test_key_registration_proof(client):
    c, _ = client
    c.post("/keys", json={"hospital_id": "h1"}, headers=HEADERS)
    r = c.post("/proofs/key-registration", headers=HEADERS,
               json={"hospital_id": "h1", "chain_id": 31337, "contract": CONTRACT, "hospital_address": ISSUER})
    p = r.json()
    assert p["message"] == schnorr.key_registration_message(31337, CONTRACT, ISSUER)
    assert schnorr.verify(p["px"], p["parity"], p["message"], p["e"], p["s"])


def test_input_validation_and_unknown_hospital(client):
    c, _ = client
    bad = {"hospital_id": "h1", "chain_id": 1, "contract": "0x12", "issuer": ISSUER,
           "patient": PATIENT, "unique_id": B("1"), "data_ref": B("2"), "sig_hash": B("3")}
    assert c.post("/proofs/certificate", json=bad, headers=HEADERS).status_code == 422
    ok = dict(bad, contract=CONTRACT)
    assert c.post("/proofs/certificate", json=ok, headers=HEADERS).status_code == 404


def test_secret_is_encrypted_at_rest(client, tmp_path):
    c, app = client
    c.post("/keys", json={"hospital_id": "h1"}, headers=HEADERS)
    secret = app.store.get_secret("h1")
    raw = (tmp_path / "ks.json").read_text()
    assert secret.to_bytes(32, "big").hex() not in raw
    assert str(secret) not in raw


def test_tampered_proofs_are_rejected():
    x = schnorr.random_secret()
    m = B("7")
    p = schnorr.prove(x, m)
    bad_e = "0x" + format((int(p["e"], 16) + 1) % (1 << 256), "064x")
    assert not schnorr.verify(p["px"], p["parity"], m, bad_e, p["s"])
    assert not schnorr.verify(p["px"], 1 - p["parity"], m, p["e"], p["s"])