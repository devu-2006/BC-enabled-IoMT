"""End-to-end demo: registration -> NIZKP key -> certificate -> consent -> read -> revoke -> IDS suspension -> audit.

Usage (all services running):  python gateway/demo_e2e.py ids/data/<file>.csv
Environment: GATEWAY_API_KEY, optional GATEWAY_URL (default http://127.0.0.1:8002)
"""
import json
import os
import sys

import httpx
import pandas as pd

URL = os.environ.get("GATEWAY_URL", "http://127.0.0.1:8002")
H = {"X-API-Key": os.environ["GATEWAY_API_KEY"]}
ok_all = True


def call(method, path, expect=200, **kw):
    r = httpx.request(method, URL + path, headers=H, timeout=120, **kw)
    global ok_all
    flag = "OK  " if r.status_code == expect else "FAIL"
    ok_all &= r.status_code == expect
    body = r.json()
    brief = json.dumps(body)[:150]
    print(f"[{flag}] {method:4} {path:34} -> {r.status_code}  {brief}")
    return body


print("== 1. entities")
call("GET", "/health")
for name, role in [("hospital", "hospital"), ("patient", "patient"), ("doctor", "doctor"),
                   ("device-A", "device"), ("device-B", "device")]:
    call("POST", "/entities", json={"name": name, "role": role})

print("\n== 2. hospital registers its NIZKP key (proof of possession)")
call("POST", "/hospitals/hospital/proof-key")

print("\n== 3. issue an encrypted certificate (NIZKP-gated)")
record = "Patient P1: BP 120/80, SpO2 97%, discharge summary: stable."
cert = call("POST", "/certificates", json={"hospital": "hospital", "patient": "patient", "record": record})
uid = cert["unique_id"]

print("\n== 4. consent-controlled reading")
call("POST", f"/records/{uid}/read", expect=403, json={"requester": "doctor"})        # no consent yet
call("POST", "/access/grant", json={"patient": "patient", "grantee": "doctor"})
got = call("POST", f"/records/{uid}/read", json={"requester": "doctor"})
assert got["record"] == record, "decrypted record differs"
call("POST", "/access/revoke", json={"patient": "patient", "grantee": "doctor"})
call("POST", f"/records/{uid}/read", expect=403, json={"requester": "doctor"})        # revoked

print("\n== 5. IDS-triggered suspension")
if len(sys.argv) > 1:
    df = pd.read_csv(sys.argv[1])
    cat = df["Attack Category"].astype(str)

    def rows(category, n=100, start_after=-1):
        idx = [i for i in range(start_after + 1, len(df)) if cat.iloc[i] == category][:n]
        return json.loads(df.iloc[idx].to_json(orient="records"))

    call("POST", "/access/grant", json={"patient": "patient", "grantee": "device-A"})
    call("POST", "/access/grant", json={"patient": "patient", "grantee": "device-B"})
    call("POST", "/ids/ingest", json={"device": "device-A", "rows": rows("normal")})
    call("POST", "/ids/ingest", json={"device": "device-B", "rows": rows("Data Alteration")})
    call("POST", f"/records/{uid}/read", json={"requester": "device-A"})                 # still allowed
    call("POST", f"/records/{uid}/read", expect=403, json={"requester": "device-B"})     # suspended
else:
    print("(skipped: pass the IDS csv path as an argument)")

print("\n== 6. audit trail (events)")
for e in call("GET", "/audit"):
    print("   ", e)

print("\nRESULT:", "ALL STEPS AS EXPECTED" if ok_all else "SOME STEPS FAILED")
sys.exit(0 if ok_all else 1)