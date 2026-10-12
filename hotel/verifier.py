"""Verifier middleware: the site side of delegation credentials.

Drop-in usage (FastAPI):
    from verifier import install
    install(app, issuer_url="http://127.0.0.1:8001", audience="hotel-api")

Every protected request must carry:
  Authorization: Bearer <delegation JWT>
  X-Agent-Key: <ed25519 pubkey hex>            (must match JWT agent_key)
  X-Agent-Timestamp: <unix>                     (5-min skew window)
  X-Agent-Signature: <hex>                      (over method\\npath\\nts\\nbody-sha256)

Checks, in order: JWT signature/expiry/audience -> revocation ->
agent-key binding -> request signature -> scope coverage.
"""
import base64
import hashlib
import time

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import HTTPException, Request

import sys
sys.path.insert(0, "../issuer")
from scope import covers  # noqa: E402


class Verifier:
    def __init__(self, issuer_url: str, audience: str):
        self.issuer_url = issuer_url.rstrip("/")
        self.audience = audience
        self._jwks = None
        self._http = httpx.Client(timeout=10, trust_env=False)

    def _issuer_pubkey_pem(self) -> bytes:
        if self._jwks is None:
            self._jwks = self._http.get(
                f"{self.issuer_url}/.well-known/jwks.json").json()
        key = self._jwks["keys"][0]
        raw = base64.urlsafe_b64decode(key["x"] + "=" * (-len(key["x"]) % 4))
        pub = Ed25519PublicKey.from_public_bytes(raw)
        from cryptography.hazmat.primitives import serialization
        return pub.public_bytes(serialization.Encoding.PEM,
                                serialization.PublicFormat.SubjectPublicKeyInfo)

    def _revoked(self, jti: str) -> bool:
        data = self._http.get(f"{self.issuer_url}/v1/revoked").json()
        return jti in data.get("revoked", [])

    def verify(self, request: Request, body: bytes,
               action: str, action_params: dict) -> dict:
        """Full verification. Returns JWT claims or raises HTTPException(401/403)."""
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            raise HTTPException(401, "missing delegation credential "
                                     "(Authorization: Bearer <jwt>)")
        token = auth[len("Bearer "):].strip()
        try:
            claims = jwt.decode(
                token, self._issuer_pubkey_pem(), algorithms=["EdDSA"],
                audience=self.audience,
                options={"require": ["exp", "iat", "iss", "aud", "sub", "jti"]},
            )
        except jwt.ExpiredSignatureError:
            raise HTTPException(401, "delegation credential expired")
        except jwt.InvalidAudienceError:
            raise HTTPException(403, "credential audience mismatch")
        except Exception as e:
            raise HTTPException(401, f"invalid credential: {e}")

        if self._revoked(claims["jti"]):
            raise HTTPException(401, "credential revoked by user")

        # Agent-key binding: the request must be signed by the key in the JWT.
        agent_key_hex = request.headers.get("x-agent-key", "")
        if agent_key_hex != claims.get("agent_key"):
            raise HTTPException(401, "request key != credential agent_key")
        ts = request.headers.get("x-agent-timestamp", "")
        sig_hex = request.headers.get("x-agent-signature", "")
        try:
            if abs(time.time() - int(ts)) > 300:
                raise HTTPException(401, "stale request timestamp")
            message = (f"{request.method}\n{request.url.path}\n{ts}\n"
                       f"{hashlib.sha256(body).hexdigest()}").encode()
            Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(agent_key_hex)).verify(bytes.fromhex(sig_hex),
                                                     message)
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(401, "bad request signature")

        ok, reason = covers(claims.get("scope", {}), action, action_params)
        if not ok:
            raise HTTPException(403, f"action outside granted scope: {reason}")
        return claims


def install(app, issuer_url: str, audience: str) -> Verifier:
    verifier = Verifier(issuer_url, audience)
    app.state.verifier = verifier
    return verifier
