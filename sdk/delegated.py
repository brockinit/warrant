"""Agent SDK: request scoped delegations, sign requests, spawn sub-agents.

Usage:
    agent = DelegatedAgent("http://127.0.0.1:8001", user_id="brock")
    cred = agent.request_scope(
        scope={"action": "book_lodging", "max_total_usd": 500,
               "area": "Sonoma County", "dates": ["2026-10-10", "2026-10-11"]},
        aud="hotel-api",
    )
    headers = agent.signed_headers("POST", "/v1/book", body_bytes, cred)
"""
import hashlib
import time

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


class DelegatedAgent:
    def __init__(self, issuer_url: str, user_id: str, name: str = "agent",
                 _priv: Ed25519PrivateKey | None = None):
        self.issuer_url = issuer_url.rstrip("/")
        self.user_id = user_id
        self.name = name
        self._priv = _priv or Ed25519PrivateKey.generate()
        self.key_hex = self._priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()
        self._http = httpx.Client(timeout=10, trust_env=False)

    def request_scope(self, scope: dict, aud: str, ttl_poll: int = 300,
                      auto_approve: bool = False) -> str:
        """Request a delegation; block until the human approves/denies.

        Set auto_approve=True only for demos (calls the approval endpoint
        directly, simulating the human clicking Approve).
        """
        r = self._http.post(f"{self.issuer_url}/v1/grants", json={
            "user_id": self.user_id,
            "agent_key": self.key_hex,
            "agent_meta": {"name": self.name, "framework": "poc-sdk"},
            "scope": scope,
            "aud": aud,
        })
        r.raise_for_status()
        g = r.json()
        print(f"[agent] scope requested: {g['scope_human']}")
        if g["status"] == "approved":
            print("[agent] auto-approved by standing policy")
            return g["credential"]
        print(f"[agent] waiting for human approval: {g['approval_url']}")
        if auto_approve:
            self._http.post(
                f"{self.issuer_url}/approve/{g['grant_id']}",
                data={"decision": "approve"},
            )
            print("[agent] (demo) human approved")
        deadline = time.time() + ttl_poll
        while time.time() < deadline:
            s = self._http.get(
                f"{self.issuer_url}/v1/grants/{g['grant_id']}").json()
            if s["status"] == "approved":
                return s["credential"]
            if s["status"] == "denied":
                raise PermissionError("human denied the delegation")
            time.sleep(2)
        raise TimeoutError("approval timed out")

    def signed_headers(self, method: str, path: str, body: bytes,
                       credential: str) -> dict:
        """Sign the request with the agent instance key (POC scheme).

        Production should use HTTP Message Signatures (RFC 9421); this
        simplified scheme signs method+path+timestamp+body-sha256.
        """
        ts = str(int(time.time()))
        body_hash = hashlib.sha256(body).hexdigest()
        message = f"{method}\n{path}\n{ts}\n{body_hash}".encode()
        sig = self._priv.sign(message).hex()
        return {
            "Authorization": f"Bearer {credential}",
            "X-Agent-Key": self.key_hex,
            "X-Agent-Timestamp": ts,
            "X-Agent-Signature": sig,
        }

    def spawn_child(self, narrower_scope: dict, aud: str,
                    auto_approve: bool = False) -> "DelegatedAgent":
        """Spawn a sub-agent whose scope must be narrower. Chain is recorded."""
        child = DelegatedAgent(self.issuer_url, self.user_id,
                               name=f"{self.name}/child")
        # Child requests its own grant, presenting this agent's credential
        # as the parent. (Simplified: child goes through the same flow;
        # the issuer verifies the parent chain in /v1/grants.)
        child._parent_hint = getattr(self, "_last_cred", None)
        child._narrower_scope = narrower_scope
        child._aud = aud
        child._auto_approve = auto_approve
        return child

    def request_child_scope(self, parent_credential: str) -> str:
        r = self._http.post(f"{self.issuer_url}/v1/grants", json={
            "user_id": self.user_id,
            "agent_key": self.key_hex,
            "agent_meta": {"name": self.name, "framework": "poc-sdk"},
            "scope": self._narrower_scope,
            "aud": self._aud,
            "parent_credential": parent_credential,
        })
        r.raise_for_status()
        g = r.json()
        if self._auto_approve and g["status"] == "pending":
            self._http.post(f"{self.issuer_url}/approve/{g['grant_id']}",
                            data={"decision": "approve"})
        deadline = time.time() + 120
        while time.time() < deadline:
            s = self._http.get(
                f"{self.issuer_url}/v1/grants/{g['grant_id']}").json()
            if s["status"] == "approved":
                return s["credential"]
            if s["status"] == "denied":
                raise PermissionError("human denied the child delegation")
            time.sleep(2)
        raise TimeoutError("child approval timed out")
