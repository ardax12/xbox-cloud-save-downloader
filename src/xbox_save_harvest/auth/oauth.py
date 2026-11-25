"""Microsoft Account OAuth 2.0 Device Code Flow (interactive, passwordless)."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable

import httpx

MSA_CONNECT_URL = "https://login.live.com/oauth20_connect.srf"
MSA_TOKEN_URL = "https://login.live.com/oauth20_token.srf"

# Public Xbox/Minecraft client ID supporting OAuth 2.0 Device Code Flow with Xbox Live scope.
DEFAULT_CLIENT_ID = "0000000048183522"
XBOX_LIVE_SCOPE = "service::user.auth.xboxlive.com::MBI_SSL"

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/133.0.0.0 Safari/537.36"
)


def redact_token(token: str | None) -> str:
    """Return a safe, non-sensitive summary of a token for logs and display."""
    if not token:
        return "<empty>"
    return f"<redacted len={len(token)}>"


class OAuthError(RuntimeError):
    """Raised when Microsoft OAuth authentication fails."""

    def __init__(self, message: str, *, error_code: str | None = None, status_code: int | None = None) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.status_code = status_code


@dataclass(frozen=True)
class DeviceCodePrompt:
    user_code: str
    device_code: str
    verification_uri: str
    expires_in: int
    interval: int

    def __repr__(self) -> str:
        return (
            f"DeviceCodePrompt(user_code={self.user_code!r}, "
            f"verification_uri={self.verification_uri!r}, "
            f"expires_in={self.expires_in}, interval={self.interval}, "
            f"device_code={redact_token(self.device_code)})"
        )


@dataclass(frozen=True)
class MsaToken:
    access_token: str
    refresh_token: str | None
    expires_at: datetime
    scope: str
    user_id: str | None = None

    def is_expired(self, leeway_seconds: int = 120) -> bool:
        return datetime.now(timezone.utc) >= (self.expires_at - timedelta(seconds=leeway_seconds))

    def to_dict(self) -> dict[str, str | None]:
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "expires_at": self.expires_at.isoformat(),
            "scope": self.scope,
            "user_id": self.user_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, str | None]) -> "MsaToken":
        expires_raw = data.get("expires_at")
        if not expires_raw:
            raise ValueError("Missing expires_at in cached MSA token")
        expires_at = datetime.fromisoformat(expires_raw)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        access_token = data.get("access_token")
        if not access_token:
            raise ValueError("Missing access_token in cached MSA token")
        return cls(
            access_token=access_token,
            refresh_token=data.get("refresh_token"),
            expires_at=expires_at,
            scope=data.get("scope") or XBOX_LIVE_SCOPE,
            user_id=data.get("user_id"),
        )

    def __repr__(self) -> str:
        return (
            f"MsaToken(access_token={redact_token(self.access_token)}, "
            f"refresh_token={redact_token(self.refresh_token)}, "
            f"expires_at={self.expires_at.isoformat()!r}, scope={self.scope!r})"
        )


def resolve_client_id(client_id: str | None = None) -> str:
    return client_id or os.environ.get("XBOX_CLIENT_ID") or DEFAULT_CLIENT_ID


def request_device_code(
    client: httpx.Client,
    *,
    client_id: str | None = None,
    scope: str = XBOX_LIVE_SCOPE,
) -> DeviceCodePrompt:
    """Start Microsoft OAuth 2.0 Device Code flow and return user verification instructions."""
    cid = resolve_client_id(client_id)
    response = client.post(
        MSA_CONNECT_URL,
        data={
            "client_id": cid,
            "scope": scope,
            "response_type": "device_code",
        },
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": DEFAULT_USER_AGENT,
        },
    )
    payload = _safe_json(response)
    if response.status_code != 200:
        err = payload.get("error") or f"HTTP {response.status_code}"
        desc = payload.get("error_description") or response.reason_phrase
        raise OAuthError(
            f"Failed to start Microsoft device-code login ({err}): {desc}",
            error_code=payload.get("error"),
            status_code=response.status_code,
        )

    return DeviceCodePrompt(
        user_code=payload["user_code"],
        device_code=payload["device_code"],
        verification_uri=payload.get("verification_uri") or "https://www.microsoft.com/link",
        expires_in=int(payload.get("expires_in", 900)),
        interval=max(1, int(payload.get("interval", 5))),
    )


def poll_for_token(
    client: httpx.Client,
    prompt: DeviceCodePrompt,
    *,
    client_id: str | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    monotonic_fn: Callable[[], float] = time.monotonic,
) -> MsaToken:
    """Poll Microsoft's token endpoint until the user completes browser verification."""
    cid = resolve_client_id(client_id)
    interval = prompt.interval
    deadline = monotonic_fn() + prompt.expires_in

    while True:
        if monotonic_fn() >= deadline:
            raise OAuthError("Device code expired before sign-in completed.", error_code="expired_token")

        sleep_fn(interval)

        response = client.post(
            MSA_TOKEN_URL,
            data={
                "client_id": cid,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": prompt.device_code,
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": DEFAULT_USER_AGENT,
            },
        )
        payload = _safe_json(response)

        if response.status_code == 200:
            return _parse_msa_token(payload)

        error_code = payload.get("error")
        if error_code == "authorization_pending":
            continue
        if error_code == "slow_down":
            interval += 5
            continue
        if error_code in {"expired_token", "access_denied", "bad_verification_code", "declined"}:
            desc = payload.get("error_description") or error_code
            raise OAuthError(
                f"Microsoft sign-in failed ({error_code}): {desc}",
                error_code=error_code,
                status_code=response.status_code,
            )

        desc = payload.get("error_description") or response.reason_phrase
        raise OAuthError(
            f"Unexpected Microsoft OAuth response ({response.status_code}, {error_code}): {desc}",
            error_code=error_code,
            status_code=response.status_code,
        )


def refresh_access_token(
    client: httpx.Client,
    refresh_token: str,
    *,
    client_id: str | None = None,
    scope: str = XBOX_LIVE_SCOPE,
) -> MsaToken:
    """Refresh an expired MSA access token using a cached refresh token."""
    cid = resolve_client_id(client_id)
    response = client.post(
        MSA_TOKEN_URL,
        data={
            "client_id": cid,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": scope,
        },
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": DEFAULT_USER_AGENT,
        },
    )
    payload = _safe_json(response)
    if response.status_code != 200:
        error_code = payload.get("error")
        desc = payload.get("error_description") or response.reason_phrase
        raise OAuthError(
            f"Microsoft token refresh failed ({error_code or response.status_code}): {desc}",
            error_code=error_code,
            status_code=response.status_code,
        )

    token = _parse_msa_token(payload)
    if not token.refresh_token:
        return MsaToken(
            access_token=token.access_token,
            refresh_token=refresh_token,
            expires_at=token.expires_at,
            scope=token.scope,
            user_id=token.user_id,
        )
    return token


def _parse_msa_token(payload: dict) -> MsaToken:
    expires_in = int(payload.get("expires_in", 3600))
    return MsaToken(
        access_token=payload["access_token"],
        refresh_token=payload.get("refresh_token"),
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=expires_in),
        scope=payload.get("scope") or XBOX_LIVE_SCOPE,
        user_id=payload.get("user_id"),
    )


def _safe_json(response: httpx.Response) -> dict:
    try:
        data = response.json()
        return data if isinstance(data, dict) else {}
    except ValueError:
        return {}
