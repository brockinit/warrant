"""End-to-end POC demo: delegated hotel booking, then the attack cases.

Run:
  1. uvicorn issuer.main:app  --port 8001   (terminal 1)
  2. uvicorn hotel.main:app   --port 8002   (terminal 2, from hotel/ or repo root
     with hotel/ on the path — see README)
  3. python demo/run_demo.py [--auto-approve]

The --auto-approve flag simulates the human clicking Approve (for headless
runs / the demo video). Without it, open the printed approval URL yourself.
"""
import argparse
import json
import sys
import time

import httpx

sys.path.insert(0, "sdk")
from delegated import DelegatedAgent  # noqa: E402

ISSUER = "http://127.0.0.1:8001"
HOTEL = "http://127.0.0.1:8002"
AUD = "hotel-api"

SCOPE = {
    "action": "book_lodging",
    "max_total_usd": 500,
    "area": "Sonoma County",
    "dates": ["2026-10-10", "2026-10-11"],
    "guests": 2,
    "non_refundable_ok": False,
}


def step(n: str):
    print(f"\n{'=' * 60}\n{n}\n{'=' * 60}")


def main(auto_approve: bool):
    agent = DelegatedAgent(ISSUER, user_id="brock", name="brockinit")
    http = httpx.Client(timeout=10, trust_env=False)

    step("1. Agent requests a scoped delegation")
    print('Human instruction: "book me a hotel in Sonoma tonight under $500"')
    cred = agent.request_scope(SCOPE, AUD, auto_approve=auto_approve)
    print(f"[ok] credential issued ({len(cred)} chars)")

    step("2. Agent browses rooms (public) and books within scope")
    rooms = http.get(f"{HOTEL}/v1/rooms").json()["rooms"]
    choice = next(r for r in rooms if r["total_usd"] <= 500 and r["left"] > 0)
    print(f"[agent] choosing {choice['name']} at ${choice['total_usd']}")
    body = json.dumps({"room_id": choice["id"]}).encode()
    r = http.post(f"{HOTEL}/v1/book", content=body,
                  headers={**agent.signed_headers("POST", "/v1/book", body, cred),
                           "Content-Type": "application/json"})
    print(f"[hotel] {r.status_code} {r.json()}")
    assert r.status_code == 200, "happy path failed"

    step("3. ATTACK: book a $620 suite (outside $500 scope)")
    body = json.dumps({"room_id": "suite"}).encode()
    r = http.post(f"{HOTEL}/v1/book", content=body,
                  headers={**agent.signed_headers("POST", "/v1/book", body, cred),
                           "Content-Type": "application/json"})
    print(f"[hotel] {r.status_code} {r.json().get('detail')}")
    assert r.status_code == 403, "scope check failed!"

    step("4. ATTACK: present the credential to the wrong audience")
    # Mint a second agent and try to reuse this credential elsewhere is
    # equivalent to audience mismatch; simpler demo: tamper the path check
    # by replaying a signed request with a different body.
    evil_body = json.dumps({"room_id": "suite", "total_usd": 1}).encode()
    headers = agent.signed_headers("POST", "/v1/book", body, cred)  # signed for old body
    r = http.post(f"{HOTEL}/v1/book", content=evil_body,
                  headers={**headers, "Content-Type": "application/json"})
    print(f"[hotel] {r.status_code} {r.json().get('detail')}")
    assert r.status_code == 401, "signature check failed!"

    step("5. ATTACK: no credential at all")
    r = http.post(f"{HOTEL}/v1/book", content=body,
                  headers={"Content-Type": "application/json"})
    print(f"[hotel] {r.status_code} {r.json().get('detail')}")
    assert r.status_code == 401, "auth gate failed!"

    step("6. User revokes mid-run -> next request fails")
    import jwt as pyjwt
    jti = pyjwt.decode(cred, options={"verify_signature": False})["jti"]
    http.post(f"{ISSUER}/v1/revoke", json={"jti": jti})
    print("[user] revoked the credential")
    body = json.dumps({"room_id": "garden"}).encode()
    r = http.post(f"{HOTEL}/v1/book", content=body,
                  headers={**agent.signed_headers("POST", "/v1/book", body, cred),
                           "Content-Type": "application/json"})
    print(f"[hotel] {r.status_code} {r.json().get('detail')}")
    assert r.status_code == 401, "revocation check failed!"

    step("7. Sub-agent with narrowed scope")
    agent2 = DelegatedAgent(ISSUER, user_id="brock", name="brockinit")
    cred2 = agent2.request_scope(SCOPE, AUD, auto_approve=auto_approve)
    child = agent2.spawn_child(
        {"action": "book_lodging", "max_total_usd": 400,
         "area": "Sonoma County", "dates": ["2026-10-10", "2026-10-11"]},
        AUD, auto_approve=auto_approve)
    child_cred = child.request_child_scope(cred2)
    chain = pyjwt.decode(child_cred, options={"verify_signature": False})["chain"]
    print(f"[ok] child credential issued, chain length {len(chain)} "
          f"(scope can only narrow)")
    # child trying to widen back up must fail at issuance
    try:
        bad_child = agent2.spawn_child(
            {"action": "book_lodging", "max_total_usd": 900,
             "area": "Sonoma County"}, AUD, auto_approve=True)
        bad_child.request_child_scope(cred2)
        print("[FAIL] widened child scope was issued!")
    except Exception as e:
        print(f"[ok] widened child scope refused: {e}")

    print("\nAll POC checks passed. Audit: http://127.0.0.1:8001/audit")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--auto-approve", action="store_true")
    args = ap.parse_args()
    main(args.auto_approve)
