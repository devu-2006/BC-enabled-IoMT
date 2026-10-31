"""Cross-check with the JavaScript prover / Solidity contract.
Step 1 (JS):     npx hardhat run scripts/export_vectors.js      -> vectors/js_vectors.json
Step 2 (Python): pytest test_crosscheck.py                      -> verifies JS proofs, writes vectors/py_proofs.json
Step 3 (JS):     npx hardhat test test/crosscheck.test.js       -> contract verifies Python proofs
"""
import json
from pathlib import Path

import pytest

import schnorr

VEC = Path(__file__).parent / "vectors"
JS = VEC / "js_vectors.json"
pytestmark = pytest.mark.skipif(not JS.exists(), reason="run scripts/export_vectors.js first")


def test_python_matches_contract_messages_and_accepts_js_proofs():
    data = json.loads(JS.read_text())
    for c in data["cases"]:
        cert = schnorr.certificate_message(data["chainId"], data["contract"], c["issuer"],
                                           c["patient"], c["uniqueID"], c["dataRef"], c["sigHash"])
        assert cert == c["certMessage"]
        assert schnorr.key_registration_message(data["chainId"], data["contract"], c["issuer"]) == c["keyRegMessage"]
        p = c["proof"]
        assert schnorr.verify(p["px"], p["parity"], p["message"], p["e"], p["s"])


def test_write_python_proofs_for_the_contract_to_verify():
    data = json.loads(JS.read_text())
    proofs = []
    for c in data["cases"]:
        for msg in (c["certMessage"], c["keyRegMessage"]):
            p = schnorr.prove(schnorr.random_secret(), msg)
            assert schnorr.verify(p["px"], p["parity"], p["message"], p["e"], p["s"])
            proofs.append(p)
    (VEC / "py_proofs.json").write_text(json.dumps(proofs, indent=2))
    assert len(proofs) == 2 * len(data["cases"])