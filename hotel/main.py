"""Demo hotel booking API protected by the delegation verifier.

  GET  /v1/rooms          public room list (browsing needs no credential)
  POST /v1/book           requires a valid delegation credential w/ scope
"""
import os
import sys

from fastapi import FastAPI, Request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verifier import install  # noqa: E402

ISSUER_URL = os.getenv("ISSUER_URL", "http://127.0.0.1:8001")
AUDIENCE = "hotel-api"

app = FastAPI(title="Demo Hotel API (delegation-protected)")
verifier = install(app, ISSUER_URL, AUDIENCE)

ROOMS = [
    {"id": "plaza-view", "name": "Plaza View King", "area": "Sonoma County",
     "total_usd": 468, "refundable": True, "left": 2},
    {"id": "garden", "name": "Garden Queen", "area": "Sonoma County",
     "total_usd": 389, "refundable": True, "left": 1},
    {"id": "suite", "name": "Vineyard Suite", "area": "Sonoma County",
     "total_usd": 620, "refundable": False, "left": 1},
]
BOOKINGS: list[dict] = []


@app.get("/v1/rooms")
async def rooms():
    return {"rooms": ROOMS}


@app.post("/v1/book")
async def book(request: Request):
    body = await request.body()
    import json
    try:
        params = json.loads(body or b"{}")
    except Exception:
        from fastapi import HTTPException
        raise HTTPException(400, "invalid JSON")
    room = next((r for r in ROOMS if r["id"] == params.get("room_id")), None)
    if not room:
        from fastapi import HTTPException
        raise HTTPException(404, "unknown room")
    if room["left"] <= 0:
        from fastapi import HTTPException
        raise HTTPException(409, "sold out")

    # The verifier enforces: valid credential, bound key, fresh signature,
    # audience match, revocation, and scope coverage.
    claims = verifier.verify(
        request, body, "book_lodging",
        {"total_usd": room["total_usd"], "area": room["area"]},
    )
    room["left"] -= 1
    booking = {
        "confirmation": f"HTL-{room['id']}-{len(BOOKINGS) + 1:03d}",
        "room": room["name"],
        "total_usd": room["total_usd"],
        "delegation_receipt": {
            "jti": claims["jti"],
            "delegated_by": claims["sub"][:12] + "...",
            "scope": claims["scope"],
            "chain_len": len(claims.get("chain", [])),
        },
    }
    BOOKINGS.append(booking)
    return booking


@app.get("/health")
async def health():
    return {"ok": True}
