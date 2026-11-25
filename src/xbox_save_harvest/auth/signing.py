"""ECDSA P-256 Proof-of-Possession signing for Xbox Live authentication endpoints."""

from __future__ import annotations

import base64
import struct
import time
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

WINDOWS_EPOCH_OFFSET_SECONDS = 11644473600
WINDOWS_TICKS_PER_SECOND = 10_000_000
POLICY_VERSION = 1


def _b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def windows_filetime(unix_seconds: int | float | None = None) -> int:
    """Return current UTC time as a Windows FILETIME (100ns ticks since 1601-01-01)."""
    ts = int(time.time() if unix_seconds is None else unix_seconds)
    return (ts + WINDOWS_EPOCH_OFFSET_SECONDS) * WINDOWS_TICKS_PER_SECOND


class XboxRequestSigner:
    """Holds an ECDSA P-256 keypair and generates Xbox Live PoP `Signature` headers."""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey | None = None) -> None:
        self._private_key = private_key or ec.generate_private_key(ec.SECP256R1())

    @classmethod
    def from_pem(cls, pem_text: str) -> "XboxRequestSigner":
        key = serialization.load_pem_private_key(pem_text.encode("utf-8"), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise TypeError("Expected an ECDSA P-256 private key")
        return cls(key)

    def to_pem(self) -> str:
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

    @property
    def proof_key(self) -> dict[str, str]:
        """Return the JWK ProofKey dictionary expected by Xbox Live auth endpoints."""
        numbers = self._private_key.public_key().public_numbers()
        x_bytes = numbers.x.to_bytes(32, "big")
        y_bytes = numbers.y.to_bytes(32, "big")
        return {
            "crv": "P-256",
            "alg": "ES256",
            "use": "sig",
            "kty": "EC",
            "x": _b64url_nopad(x_bytes),
            "y": _b64url_nopad(y_bytes),
        }

    def build_signing_payload(
        self,
        *,
        method: str,
        url: str,
        body: bytes,
        authorization: str = "",
        timestamp: int,
    ) -> bytes:
        """Build the canonical byte payload signed for Xbox Live PoP requests."""
        parsed = urlsplit(url)
        path_and_query = parsed.path or "/"
        if parsed.query:
            path_and_query = f"{path_and_query}?{parsed.query}"

        parts = [
            struct.pack(">I", POLICY_VERSION),
            b"\x00",
            struct.pack(">Q", timestamp),
            b"\x00",
            method.upper().encode("ascii"),
            b"\x00",
            path_and_query.encode("utf-8"),
            b"\x00",
            authorization.encode("utf-8"),
            b"\x00",
            body,
            b"\x00",
        ]
        return b"".join(parts)

    def sign_request(
        self,
        *,
        method: str,
        url: str,
        body: bytes | str,
        authorization: str = "",
        unix_seconds: int | float | None = None,
    ) -> str:
        """Return the base64-encoded Xbox Live `Signature` header value."""
        body_bytes = body.encode("utf-8") if isinstance(body, str) else body
        ts = windows_filetime(unix_seconds)
        payload = self.build_signing_payload(
            method=method,
            url=url,
            body=body_bytes,
            authorization=authorization,
            timestamp=ts,
        )
        der_sig = self._private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_sig)
        raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        header_bytes = struct.pack(">IQ", POLICY_VERSION, ts) + raw_sig
        return base64.b64encode(header_bytes).decode("ascii")
