# Warrant

Delegated authority for AI agents: a human grants a **scoped, short-lived,
cryptographically verifiable credential** — a warrant for the agent to act;
the agent acts within it; the service verifies it. No superuser API keys in
system prompts.

This is a proof of concept for a neutral agent-delegation layer. It composes
existing primitives — Ed25519 JWTs, OAuth-anchored human identity,
structured (RAR-inspired) scopes, HTTP request signing — instead of
inventing new cryptography.

## Architecture

```
human --(approves scope)--> [issuer] --(JWT: sub, agent_key, scope, exp, aud, chain)--> agent
agent --(Bearer JWT + Ed25519 request signature)--> [verifier middleware] --> service
```

| Dir | What it is |
|---|---|
| `issuer/` | Issues Ed25519-signed delegation credentials. Approval ceremony (plain-English scope page), standing auto-approve policies, revocation, JWKS, audit log. |
| `sdk/` | `DelegatedAgent`: request scopes, sign requests, spawn scope-narrowed sub-agents. |
| `hotel/` | Demo booking API + reusable verifier middleware (the site side). |
| `demo/` | End-to-end script: happy path + five attack cases. |

## Quickstart

```bash
pip install -r requirements.txt

# terminal 1 — issuer (port 8001)
uvicorn issuer.main:app --port 8001

# terminal 2 — demo hotel API (port 8002)
cd hotel && uvicorn main:app --port 8002

# terminal 3 — run the demo
cd ~/workspace/agent-delegation-poc
python demo/run_demo.py --auto-approve
```

Without `--auto-approve`, the script prints an approval URL — open it in a
browser and click Approve to complete the human-in-the-loop ceremony.

Then visit:
- `http://127.0.0.1:8001/audit` — every grant, approval, revocation
- `http://127.0.0.1:8001/.well-known/jwks.json` — issuer public keys

## What the demo proves

1. **Happy path** — agent requests scope `book_lodging ≤ $500, Sonoma
   County`; human approves; agent books the $468 room. The verifier checks
   JWT signature, expiry, audience, revocation, agent-key binding, request
   signature, and scope coverage.
2. **Scope exceeded** — $620 suite on a $500 credential → 403.
3. **Tampered request** — signature computed over a different body → 401.
4. **No credential** → 401.
5. **Revocation** — user revokes mid-run → next request → 401 (the kill
   switch that works).
6. **Sub-agent narrowing** — child credential chains to the parent; a child
   attempting to *widen* scope is refused at issuance.

## Configuration

| env | default | meaning |
|---|---|---|
| `DEMO_MODE` | `true` | skip real Google OAuth; use a demo user id |
| `CRED_TTL` | `900` | credential lifetime, seconds (15 min) |
| `ISSUER_URL` | `http://127.0.0.1:8001` | where the verifier finds the issuer |

Set `DEMO_MODE=false` with `GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET` to wire
real human authentication (stubbed in `issuer/main.py`).

## Deliberately out of scope (phase 2+)

W3C Verifiable Credentials profile, TEE/runtime attestation, agent
reputation, cross-issuer federation, full policy engine, RFC 9421 HTTP
Message Signatures (the POC uses a simplified Ed25519 scheme — see
`sdk/delegated.py`).

## License

TBD — intended: Apache-2.0 for SDK/verifier/spec, BSL for hosted components.
