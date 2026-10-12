"""Ed25519 keys + JWT mint/verify for delegation credentials.

POC-grade: keys live in memory, pairwise subject derivation is a plain
SHA-256 (production should use a proper KDF + stored pairwise IDs).
"""
import base64
import hashlib
import time
import uuid

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

ISSUER_ID = "https://delegation-poc.local"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


class IssuerKeys:
    """The issuer's long-lived signing key."""

    def __init__(self) -> None:
        self._private = Ed25519PrivateKey.generate()
        self.kid = uuid.uuid4().hex[:8]

    def _private_pem(self) -> bytes:
        return self._private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def public_pem(self) -> bytes:
        return self._private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def jwks(self) -> dict:
        raw = self._private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return {
            "keys": [
                {"kty": "OKP", "crv": "Ed25519", "kid": self.kid, "x": b64url(raw)}
            ]
        }

    def mint(self, claims: dict) -> str:
        return jwt.encode(
            claims, self._private_pem(), algorithm="EdDSA", headers={"kid": self.kid}
        )


def verify_credential(token: str, public_pem: bytes, audience: str) -> dict:
    """Verify a delegation credential. Returns claims or raises."""
    return jwt.decode(
        token,
        public_pem,
        algorithms=["EdDSA"],
        audience=audience,
        issuer=ISSUER_ID,
        options={"require": ["exp", "iat", "iss", "aud", "sub", "jti"]},
    )


def pairwise_sub(user_id: str, audience: str) -> str:
    """Pseudonymous subject per audience so sites can't correlate users."""
    return hashlib.sha256(f"{user_id}|{audience}".encode()).hexdigest()[:32]


def new_agent_keypair() -> tuple[str, Ed25519PrivateKey]:
    """Generate a per-run agent instance keypair. Returns (pubkey_hex, private)."""
    priv = Ed25519PrivateKey.generate()
    pub_hex = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return pub_hex, priv


def pubkey_from_hex(pub_hex: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))


def now() -> int:
    return int(time.time())
