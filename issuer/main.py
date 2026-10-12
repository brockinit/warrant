"""Delegation issuer: mints short-lived, scoped credentials bound to agent keys.

Endpoints:
  POST /v1/grants          request a delegation (agent -> human approval)
  GET  /v1/grants/{id}     poll grant status (agent)
  GET  /approve/{id}       approval page (human, browser)
  POST /approve/{id}       approve / deny (human)
  POST /v1/revoke          revoke a credential by jti
  GET  /.well-known/jwks.json
  GET  /v1/policies        standing policies (auto-approve rules)
  POST /v1/policies        create standing policy
  GET  /audit              audit log (JSON + simple HTML dashboard)

Auth model (POC): DEMO_MODE=true uses a demo user id. Set DEMO_MODE=false
and GOOGLE_CLIENT_ID/SECRET to wire real Google OAuth (flow stubbed in
`maybe_require_login`).
"""
import os
import time
import uuid
from html import escape

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from .crypto import (
    ISSUER_ID,
    IssuerKeys,
    new_agent_keypair,
    now,
    pairwise_sub,
    pubkey_from_hex,
    verify_credential,
)
from .scope import covers, describe, narrows, scope_class

DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() == "true"
DEMO_USER = "demo-user-brock"
CRED_TTL = int(os.getenv("CRED_TTL", "900"))  # 15 minutes

app = FastAPI(title="Delegation Issuer (POC)")
keys = IssuerKeys()

GRANTS: dict[str, dict] = {}      # grant_id -> grant
REVOKED: set[str] = set()         # revoked jtis
POLICIES: list[dict] = []         # standing auto-approve policies
AUDIT: list[dict] = []            # audit events


def audit(event: str, detail: dict) -> None:
    AUDIT.append({"t": now(), "event": event, **detail})


def current_user(request: Request) -> str:
    # Production: validate session cookie from Google OAuth here.
    if DEMO_MODE:
        return DEMO_USER
    raise HTTPException(401, "login required (wire Google OAuth)")


def auto_approved(user_id: str, scope: dict) -> bool:
    for p in POLICIES:
        if p["user_id"] == user_id and p["scope_class"] == scope_class(scope):
            cond = p.get("condition", {})
            mt = scope.get("max_total_usd")
            if mt is None or mt <= cond.get("max_total_usd", 0):
                return True
    return False


def mint_credential(user_id: str, agent_key_hex: str, agent_meta: dict,
                   scope: dict, audience: str, chain: list) -> tuple[str, dict]:
    jti = uuid.uuid4().hex
    claims = {
        "iss": ISSUER_ID,
        "sub": pairwise_sub(user_id, audience),
        "aud": audience,
        "exp": now() + CRED_TTL,
        "iat": now(),
        "jti": jti,
        "agent_key": agent_key_hex,
        "agent_meta": agent_meta,
        "scope": scope,
        "chain": chain,
    }
    return keys.mint(claims), claims


@app.post("/v1/grants")
async def create_grant(body: dict):
    """Agent requests a delegation. Returns approval URL for the human."""
    user_id = body.get("user_id") or DEMO_USER
    agent_key = body.get("agent_key")
    scope = body.get("scope") or {}
    audience = body.get("aud")
    agent_meta = body.get("agent_meta", {})
    parent_cred = body.get("parent_credential")
    if not agent_key or not audience or not scope:
        raise HTTPException(400, "agent_key, aud and scope required")

    chain: list = []
    if parent_cred:
        try:
            pclaims = verify_credential(parent_cred, keys.public_pem(), audience)
        except Exception as e:
            raise HTTPException(401, f"invalid parent credential: {e}")
        ok, reason = narrows(scope, pclaims["scope"])
        if not ok:
            raise HTTPException(403, f"child scope not narrower: {reason}")
        chain = pclaims.get("chain", []) + [
            {"jti": pclaims["jti"], "scope": pclaims["scope"]}
        ]

    grant_id = uuid.uuid4().hex[:12]
    grant = {
        "id": grant_id,
        "user_id": user_id,
        "agent_key": agent_key,
        "agent_meta": agent_meta,
        "scope": scope,
        "audience": audience,
        "chain": chain,
        "status": "pending",
        "created": now(),
        "credential": None,
    }
    GRANTS[grant_id] = grant
    audit("grant.requested", {"grant_id": grant_id, "user": user_id,
                              "scope": describe(scope), "aud": audience})

    if auto_approved(user_id, scope):
        token, claims = mint_credential(user_id, agent_key, agent_meta,
                                        scope, audience, chain)
        grant.update(status="approved", credential=token)
        audit("grant.auto_approved", {"grant_id": grant_id, "jti": claims["jti"]})
    return {
        "grant_id": grant_id,
        "status": grant["status"],
        "approval_url": f"/approve/{grant_id}",
        "scope_human": describe(scope),
    }


@app.get("/v1/grants/{grant_id}")
async def grant_status(grant_id: str):
    g = GRANTS.get(grant_id)
    if not g:
        raise HTTPException(404, "unknown grant")
    out = {"grant_id": grant_id, "status": g["status"]}
    if g["status"] == "approved":
        out["credential"] = g["credential"]
    return out


APPROVE_HTML = """<!doctype html><html><body style="font-family:sans-serif;max-width:520px;margin:40px auto">
<h2>Agent authorization request</h2>
<p>An AI agent is asking to act on your behalf:</p>
<blockquote style="background:#f4f4f4;padding:12px;border-radius:8px">{scope}</blockquote>
<p style="color:#555">Agent: {agent}<br>Audience: {aud}<br>
Credential expires 15 minutes after approval. You can revoke anytime.</p>
<form method="post"><button name="decision" value="approve"
 style="background:#16a34a;color:#fff;padding:10px 24px;border:0;border-radius:8px;font-size:16px">Approve</button>
<button name="decision" value="deny"
 style="background:#dc2626;color:#fff;padding:10px 24px;border:0;border-radius:8px;font-size:16px;margin-left:8px">Deny</button></form>
</body></html>"""


@app.get("/approve/{grant_id}", response_class=HTMLResponse)
async def approve_page(grant_id: str):
    g = GRANTS.get(grant_id)
    if not g:
        raise HTTPException(404, "unknown grant")
    return APPROVE_HTML.format(
        scope=escape(describe(g["scope"])),
        agent=escape(g["agent_meta"].get("name", g["agent_key"][:12] + "...")),
        aud=escape(g["audience"]),
    )


@app.post("/approve/{grant_id}")
async def approve_decision(grant_id: str, decision: str = Form(...)):
    g = GRANTS.get(grant_id)
    if not g:
        raise HTTPException(404, "unknown grant")
    if g["status"] != "pending":
        return {"status": g["status"]}
    if decision == "approve":
        token, claims = mint_credential(g["user_id"], g["agent_key"],
                                        g["agent_meta"], g["scope"],
                                        g["audience"], g["chain"])
        g.update(status="approved", credential=token)
        audit("grant.approved", {"grant_id": grant_id, "jti": claims["jti"],
                                 "scope": describe(g["scope"])})
    else:
        g["status"] = "denied"
        audit("grant.denied", {"grant_id": grant_id})
    return {"status": g["status"]}


@app.post("/v1/revoke")
async def revoke(body: dict):
    jti = body.get("jti")
    if not jti:
        raise HTTPException(400, "jti required")
    REVOKED.add(jti)
    audit("credential.revoked", {"jti": jti})
    return {"revoked": jti}


@app.get("/v1/revoked")
async def revoked_list():
    return {"revoked": sorted(REVOKED)}


@app.get("/.well-known/jwks.json")
async def jwks():
    return JSONResponse(keys.jwks())


@app.get("/v1/policies")
async def list_policies():
    return {"policies": POLICIES}


@app.post("/v1/policies")
async def add_policy(body: dict):
    """Standing policy: auto-approve a scope class under a cap. POC-grade."""
    p = {
        "id": uuid.uuid4().hex[:8],
        "user_id": body.get("user_id") or DEMO_USER,
        "scope_class": body["scope_class"],
        "condition": body.get("condition", {}),
    }
    POLICIES.append(p)
    audit("policy.created", p)
    return p


@app.get("/audit")
async def audit_log():
    rows = "".join(
        f"<tr><td>{e['t']}</td><td>{escape(e['event'])}</td>"
        f"<td>{escape(str({k: v for k, v in e.items() if k not in ('t', 'event')}))}</td></tr>"
        for e in reversed(AUDIT[-100:])
    )
    return HTMLResponse(
        "<!doctype html><html><body style='font-family:sans-serif;max-width:900px;margin:20px auto'>"
        "<h2>Audit log</h2><table border=1 cellpadding=6>"
        "<tr><th>time</th><th>event</th><th>detail</th></tr>" + rows +
        "</table></body></html>"
    )


@app.get("/health")
async def health():
    return {"ok": True, "demo_mode": DEMO_MODE}
